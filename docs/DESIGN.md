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
  and a bare `[` inside a class (.NET class subtraction).
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
| Regex `\w`, `\b`, `\s`, `\d` | ASCII (RE2) | .NET classes; with byte strings this adds Latin-1 letters (0xC0-0xFF) to `\w`, `\v` to `\s` |
| Regex `.` on UTF-8 | one rune | one byte |
| Malformed XML | Go decoder continues non-strictly | parsing stops at the first error, `REQBODY_ERROR` set |
| Malformed JSON | partial flattening, then error | no flattening, error |
| Multiphase evaluation | optional build tag | not implemented |
| `@rbl`, `@geoLookup`, `@inspectFile`, `@validateNid`, `@validateSchema`, `@restpath`, `@pmFromDataset` | supported | not implemented (parser error) |
| Persistent collections (`initcol`, `IP`, `SESSION`) | not supported | accepted and ignored, as in Coraza |
| Audit log formats | Native, JSON, OCSF; serial/concurrent/HTTPS | JSON through `ILogger` or `IAuditLogWriter` |

Server-level differences from Apache (the CRS reference) are listed with reasons in
`tests/Pondhawk.Waf.CrsRegression/kestrel-overrides.yaml`.

## Limits

- Response inspection (phases 3-4) runs after the application has written the response: it records matches and
  feeds the audit log, but cannot block. CRS RESPONSE-95x data-leakage rules do not run (response body access is off).
- One `WafEngine` per application; rule changes need a restart.
- Startup takes about 3.5 s with the full CRS. The first request after startup is warmed up.
- Per-request cost is about 1.2 ms for a typical request with the full CRS at paranoia level 1.

## Roadmap

Ordered by protection value.

### Milestone 1 (done): request-side core

- SecLang engine: phases, chains, anomaly scoring, `skipAfter`/`SecMarker`, `ctl`, `setvar`, `capture`, macros,
  default actions, `SecRuleRemove*`, `SecRuleUpdateTargetBy*`.
- Operators used by CRS, plus `@containsWord`, `@strmatch`, `@noMatch`, `@ipMatchFromFile`.
- All CRS transformations; HTML5 entity table.
- Body processors: URLENCODED, MULTIPART (strict checks), JSON, XML, RAW.
- libinjection port; body limits; argument limits; audit and rule logs; middleware; CRS regression runner.

### Milestone 2: response protection

1. Buffer the response body (allowed MIME types, size limit) and run phases 3-4 before the response starts, so
   `RESPONSE-95x` rules (SQL errors, stack traces, web shells, data leakage) can block.
2. Response header phase with enforcement.
3. Enable the 105 response-side CRS regression tests.

### Milestone 3: operations

1. Configuration from `appsettings.json` (rule engine, paranoia level, exclusions) and reload without restart.
2. Metrics (`System.Diagnostics.Metrics`): requests, blocks, matches per rule, latency.
3. CRS plugin support (WordPress, Drupal, Nextcloud exclusion plugins) from the embedded file system.
4. Rule exclusion helpers in C# (`options.Exclude(ruleId, "ARGS:password", path: "/login")`).

### Milestone 4: performance

1. Regex prefilters (literal and minimum-length checks before `@rx`, as Coraza's `SecRxPreFilter`).
2. Fewer allocations in `GetField` and collections (pooled lists).
3. Compiled-rule cache to cut startup time.

### Later

- `@rbl`, `@geoLookup` (MaxMind), `@validateSchema` (JSON schema).
- Multiphase evaluation.
- Native ModSecurity audit log format.
