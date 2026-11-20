# Pondhawk WAF design

## Goal

An embeddable WAF for ASP.NET Core with the semantics of OWASP Coraza v3, so that the OWASP CRS runs unchanged and
behaves as it does under Coraza. Decided 2026-11-18: SecLang + CRS (not a C# rule DSL), request-side protection
first.

## Architecture

```
HTTP request ─► WafMiddleware ──► Transaction ──► rules (phase 1..5) ──► Interruption? ─► 403/400/413/redirect/drop
                  │                  │
                  │ byte strings     ├─ TransactionVariables (ARGS, REQUEST_HEADERS, TX, ...)
                  │                  ├─ BodyProcessors (URLENCODED, MULTIPART, JSON, XML)
                  │                  └─ MatchedRules ─► error log callback, audit log
                  ▼
             WafEngine (singleton) ◄── WafBuilder ◄── SecLangParser ◄── pondhawk-waf.conf + crs-setup + CRS rules
```

| Component | File | Coraza equivalent |
|---|---|---|
| Engine and config | `WafEngine.cs` | `internal/corazawaf/waf.go` |
| Transaction, phase loop | `Transaction.cs` | `internal/corazawaf/transaction.go`, `rulegroup.go` |
| Rule evaluation, chains | `Rules/Rule.cs` | `internal/corazawaf/rule.go` |
| Macros (`%{tx.score}`) | `Rules/Macro.cs` | `experimental/plugins/macro` |
| Collections | `Collections/*` | `internal/collections` |
| Operators | `Operators/Operators.cs` | `internal/operators` |
| Transformations | `Transformations/Transforms.cs` | `internal/transformations` |
| Actions, ctl | `Actions/Actions.cs` | `internal/actions` |
| Body processors | `BodyProcessors/*` | `internal/bodyprocessors` |
| SecLang parser | `SecLang/SecLangParser.cs` | `internal/seclang` |
| libinjection | `Pondhawk.Waf.LibInjection` | `libinjection-go` |

### Decisions

- **Byte strings.** All request data is held as .NET strings with one char per byte (Latin-1 mapping of the raw
  bytes). Transformations (`urlDecodeUni`, `utf8toUnicode`, `jsDecode`, ...), `@validateUtf8Encoding` and
  byte-oriented regexes (`\x{e2}[\x80-\x{bf}]`) then behave as in Coraza and ModSecurity. Text from ASP.NET Core
  (headers, path) is converted to its UTF-8 bytes. Logs decode back to UTF-8.
- **Linear-time regexes.** Patterns compile with `RegexOptions.NonBacktracking` (no ReDoS). All CRS patterns are
  RE2-compatible and compile this way; a test enforces it. The largest (932235, 10 KB) exceed .NET's default
  automaton limit, so `RegexCache` raises `REGEX_NONBACKTRACKING_MAX_AUTOMATA_SIZE` to 200,000 unless the host set
  it. A pattern that needs backtracking (user rules with lookarounds) uses the backtracking engine with a 250 ms
  timeout.
- **RE2 → .NET translation** (`RegexCache.TranslatePattern`): `\x{HH}`, `(?P<name>`, escaped punctuation as a range
  start inside a class (`[\--9]`, which .NET silently misreads; before the fix 11 CRS RCE regression tests failed),
  and a bare `[` inside a class (.NET class subtraction). `\w`, `\W`, `\d`, `\D`, `\s`, `\S` become explicit
  ASCII classes, as in RE2: .NET's Unicode classes would count byte-string chars 0x80-0xFF as letters and spaces, so
  `%C2%AAeval(` hid `eval` from CRS. .NET has no ASCII-only `\b`, so patterns with `\b`/`\B` match input whose bytes
  0x80-0xFF are moved to U+E080-U+E0FF (private use, not word characters); the pattern's byte escapes move with them.
- **Default `(?sm)`** on `@rx`, as Coraza's default build.
- **XML** uses `XmlReader` with DTD processing ignored and no resolver (no XXE, no entity expansion). A parse error
  sets `REQBODY_ERROR`; the base configuration rejects it (rule 200002).
- **Request body** is buffered in memory up to 128 KiB, then in a temporary file deleted on dispose. A declared
  `Content-Length` over the limit is rejected before reading. Bodies are detected with
  `IHttpRequestBodyDetectionFeature`, so HTTP/2 and HTTP/3 bodies without `Content-Length` are inspected.
- **Embedded CRS**, unmodified, as resources; `Include` paths resolve against an in-memory file system, rooted paths
  against the disk (`CompositeConfigFileSystem`).

### Known differences from Coraza

| Area | Coraza | Pondhawk |
|---|---|---|
| Regex on UTF-8, pattern with a non-ASCII literal (none in CRS) | one rune per `.` or class | one byte: `.{1,10}` matches fewer characters of non-ASCII text. Pure-ASCII patterns match runes and patterns with byte escapes 0x80-0xFF match bytes, as in Coraza |
| Multipart | Go `mime/multipart`: delimiters after a bare LF | strict error (400) wherever Go and ASP.NET Core's `MultipartReader` would split the body differently |
| JSON | flattens any document | rejects key paths totalling more than 4 × the body size, and invalid strings (lone surrogates, invalid UTF-8) |
| Response MIME types | exact match | `*/json`, `*+json`, `*/xml`, `*+xml` and missing `Content-Type` match the listed families; UTF-16/32 transcoded |
| Malformed XML | Go decoder continues non-strictly | parsing stops at the first error, `REQBODY_ERROR` set |
| Malformed JSON | partial flattening, then error | no flattening, error |
| Multiphase evaluation | optional build tag | not implemented |
| `@rbl`, `@geoLookup`, `@inspectFile`, `@validateNid`, `@validateSchema`, `@restpath`, `@pmFromDataset` | supported | not implemented (parser error) |
| Persistent collections (`initcol`, `IP`, `SESSION`) | not supported | accepted and ignored, as in Coraza |
| Audit log formats | Native, JSON, OCSF; serial/concurrent/HTTPS | JSON through `ILogger` or `IAuditLogWriter` |
| `FILES`, `FILES_NAMES`, `FILES_SIZES` keys | empty key | the part's field name, as in ModSecurity, so `FILES:avatar` selects and excludes one upload field |
| `SecRuleUpdateTargetByTag "tag" "!VAR"` (both fields quoted) | outer quotes stripped from the whole argument | both fields parsed |

Two Coraza behaviors differ from ModSecurity and are kept, because they inspect more of the request. The CRS plugins
are tested on ModSecurity, so eight Nextcloud plugin tests have overrides in
`tests/Pondhawk.Waf.CrsRegression/plugin-overrides.yaml`:

- **Unknown content types.** CRS rule 901340 sets `ctl:forceRequestBodyVariable=On` when no body processor is chosen
  (for example, `text/plain` or `text/calendar`). ModSecurity then only fills `REQUEST_BODY`. Pondhawk, like Coraza,
  also parses the body as URL-encoded, so its lines become `ARGS` that rules inspect. CRS rule 920420 rejects these
  content types unless they are allowed.
- **XML namespace declarations.** libxml2 does not return `xmlns` attributes for the XPath `//@*`. Pondhawk, like
  Coraza, includes them in `XML://@*`.

Server-level differences from Apache (the CRS reference) are listed with reasons in
`tests/Pondhawk.Waf.CrsRegression/kestrel-overrides.yaml`.

### Response inspection

`ResponseInspector` replaces `IHttpResponseBodyFeature` for the request.

- Phase 3 runs when the application starts the response (first write, `StartAsync`, `CompleteAsync`, or return).
- Inspected bodies (MIME type listed, no `Content-Encoding`, not HEAD/204/304) are held in memory. Phase 4 runs
  when the application returns; held bytes are sent only if no rule interrupts.
- Over `SecResponseBodyLimit`: `ProcessPartial` runs phase 4 on the first bytes, then streams the rest;
  `Reject` answers 500.
- Other bodies run phase 4 without a body before the first byte is sent, then stream through.
- A block clears status, headers and body, and sends an empty response with the rule's status.
- No bypass on request headers: a client can send `Connection: Upgrade`, so upgrade requests are wrapped too.
  Real upgrades (WebSocket) do not use the body feature.
- JSON is inspected by default (Coraza and CRS list only text types), because ASP.NET Core applications mostly
  answer in JSON.

## Limits

- Inspected responses are buffered: a streamed text or JSON response (e.g. flushed progressively) reaches the
  client only when the application returns, or after the first 512 KiB. Server-sent events (`text/event-stream`)
  are not inspected and stream normally.
- Headers added by `Response.OnStarting` callbacks run after phase 3 and are not inspected.
- Responses compressed by the application are not inspected; put response compression outside the WAF.
- Response bodies over 512 KiB are inspected on their first 512 KiB only.
- One `WafEngine` per application; rule changes need a restart.
- Startup takes about 3.5 s with the full CRS. The first request after startup is warmed up.
- Per-request cost is about 1.2 ms for a typical request with the full CRS at paranoia level 1, about 1.6 ms with
  a 10 KB HTML response inspected.

## Roadmap

Ordered by protection value.

### Milestone 1 (done): request-side core

- SecLang engine: phases, chains, anomaly scoring, `skipAfter`/`SecMarker`, `ctl`, `setvar`, `capture`, macros,
  default actions, `SecRuleRemove*`, `SecRuleUpdateTargetBy*`.
- Operators used by CRS, plus `@containsWord`, `@strmatch`, `@noMatch`, `@ipMatchFromFile`.
- All CRS transformations; HTML5 entity table.
- Body processors: URLENCODED, MULTIPART (strict checks), JSON, XML, RAW.
- libinjection port; body limits; argument limits; audit and rule logs; middleware; CRS regression runner.

### Milestone 2 (done): response protection

- Phases 3-4 run before the response reaches the client and can block (`ResponseInspector`).
- Response limit actions (Reject → 500, ProcessPartial), `ctl:forceResponseBodyVariable`, JSON and XML response
  processors (`RESPONSE_ARGS`, `RESPONSE_XML`).
- Response inspection on by default, with JSON added; `InspectResponses` and `OutboundAnomalyScoreThreshold` options.
- All 105 response-side CRS regression tests enabled and passing.

### Profiles (done)

- `WafProfile` (Performance, Balanced, Strict, Paranoid) with `WafSettings`; nullable options override single values.
- Guard rule 900002 keeps the detection paranoia level at or above the blocking level (CRS 901500 would otherwise
  deny every request with 500).

### Security hardening (done)

An adversarial review (four reviewers: middleware, body parsing, rule engine, configuration and logging) found
3 critical, 4 high and 11 medium issues. All are fixed, each with a regression test in `SecurityHardeningTests`:

- A body filling the limit exactly let the tail through uninspected; DetectionOnly rejected oversized bodies.
- Four multipart differentials with ASP.NET Core's `MultipartReader`; quadratic part-header search; unbounded parts.
- JSON key-path amplification (a 32 KB body cost 2 GB); invalid JSON strings threw instead of setting `REQBODY_ERROR`.
- Unicode `\w`/`\b`/`\s`/`\d` in translated CRS regexes (a Latin-1 byte before a keyword hid it).
- Inspection cost: `SecRequestBodyNoFilesLimit` (1 MiB default) and a bounded transformation cache.
- Response formats the client chooses (`text/json`, `+json`, XML, UTF-16, no `Content-Type`) were not inspected;
  unflushed `BodyWriter` bytes were lost; streaming responses were held until complete.
- Logs: unbounded matched data, credentials in logdata and URIs, 4xx-only audit entries, C1/Unicode line breaks,
  log sink failures failing requests; a startup warning when the engine does not block; MIME type values could inject
  directives; `UseCoreRuleSet = false` dropped body inspection.

### Milestone 3 (done): operations

1. Configuration from `appsettings.json` (`AddPondhawkWaf(IConfiguration)`) with reload without restart:
   `WafEngineProvider` builds a new engine in the background and swaps it; requests in flight finish on the old one;
   a configuration that does not build keeps the current engine.
2. Metrics on the `Pondhawk.Waf` meter: requests by result, blocks and DetectionOnly would-blocks by rule, matches per
   rule, time per phase (measured in `Transaction`, network waits excluded), log failures, reloads.
3. The eight official CRS exclusion plugins, embedded and selected with `WafOptions.Plugins`; their regression tests
   run with the CRS suite.
4. Exclusion helpers (`Exclude`, `ExcludeByTag`, `RemoveRule`, `RemoveRules`, `RemoveRulesByTag`) and
   `WafOptions.Exclusions` for configuration. A path exclusion matches the raw request target, by path segment, and
   does not apply to targets a server could normalize to another path (dot segments, encoded `/` or `.`,
   backslashes).

### Milestone 4 (done): performance

1. Regex prefilters (`RegexPrefilter`), as Coraza's `SecRxPreFilter`: the minimum match length and ASCII literals
   that every match contains, read from the pattern. A value without them skips the regex. Only constructs the
   analyzer fully understands produce a prefilter; anything else (lookarounds, backreferences, `\Q..\E`) runs the
   regex as before. The CRS regression runner checks every rejected value against the regex.
2. Fewer allocations: pooled evaluation scratch (value lists, transformation cache) per engine; transformations
   return their input when they change nothing; long values are cached per transformation step, so chains that share
   steps copy a large argument once; one byte string per body; `@pm` searches with `SearchValues`; RULE is filled
   only when a rule reads it (CRS never does).
3. Startup: patterns are syntax-checked while the rules load; the NonBacktracking automata, which took most of the
   startup time, build in parallel in the background (`WafEngine.Compiled`). A rule that needs a regex before then
   builds it or waits for it. A reload swaps in its engine only when the automata are built. The automata cannot be
   cached on disk (.NET does not serialize them).
4. Response bodies: held once, in the transaction's buffer, sized from `Content-Length`. DetectionOnly streams
   responses and inspects a copy.

### Milestone 5 (done): security review findings

1. `@rx` counts UTF-8 characters, as Go's regexp does in Coraza (#13). A pattern without non-ASCII characters or
   byte escapes 0x80-0xFF sees each UTF-8 character, and each invalid byte, as one private-use char
   (`RegexCache.CollapseUtf8`); captures map back to the original bytes. Patterns with byte escapes match bytes, as
   Coraza's binary regexes do (10 CRS patterns).
2. Relative paths in `Directives`, `DirectivesAfterRules` and `RuleFiles` resolve against the content root
   (`IHostEnvironment.ContentRootPath`), not the working directory (#14).
3. A response JSON document over the arguments limit no longer sets the request variable `ARGUMENTS_LIMIT_REACHED`
   (#17).
4. `InspectedResponseFeature` makes a held response behave as started from phase 3 on (#19, #20): the application's
   `OnStarting` callbacks run before phase 3; afterwards the status and headers are read-only and `HasStarted` is
   true. When the application throws after it started a response that has not reached the server, the middleware
   aborts the connection, so an exception handler outside the WAF cannot replace it with an uninspected page.

### Later

- `@rbl`, `@geoLookup` (MaxMind), `@validateSchema` (JSON schema).
- Multiphase evaluation.
- Native ModSecurity audit log format.
