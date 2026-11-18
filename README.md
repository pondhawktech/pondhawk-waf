# Pondhawk WAF

A web application firewall for ASP.NET Core, modeled after [OWASP Coraza](https://coraza.io). It runs SecLang rules
and ships the [OWASP Core Rule Set](https://coreruleset.org) (CRS) v4.30.0.

Status: milestone 2, request and response protection. All 5,193 CRS regression tests pass (see
[Testing](#testing)). Roadmap: [docs/DESIGN.md](docs/DESIGN.md).

## What it protects against

CRS at paranoia level 1, on the query string, path, headers, cookies, and form, multipart, JSON and XML bodies:

| Attack | CRS rules |
|---|---|
| SQL injection (regex + libinjection `@detectSQLi`) | 942xxx |
| Cross-site scripting (regex + libinjection `@detectXSS`) | 941xxx |
| Remote command execution (Unix, Windows, PowerShell) | 932xxx |
| Local / remote file inclusion, path traversal | 930xxx, 931xxx |
| PHP, Java, Node.js and generic injection, SSRF | 933xxx, 944xxx, 934xxx |
| Protocol violations, request smuggling, header injection | 920xxx, 921xxx |
| Multipart evasion, session fixation, scanners | 922xxx, 943xxx, 913xxx |
| Data leakage in responses: SQL errors, stack traces, PHP/Java/IIS/Ruby errors, directory listings | 950xxx-956xxx |
| Web shells in responses | 955xxx |

The base configuration also rejects bodies that cannot be parsed, multipart bodies that other parsers (ASP.NET Core's
`MultipartReader`) would split differently, more than 1,000 arguments or parts, bodies without files over 1 MiB and
bodies with files over 13 MiB (413).

Responses of type `text/html`, `text/plain`, `text/xml`, `application/json` and `application/problem+json` are held
in memory (up to 512 KiB) and inspected before the client receives any byte. Equivalent types are inspected too: every
`*/json` and `*+json` type (`text/json`, `application/vnd.api+json`), every `*/xml` and `*+xml` type, and responses
without `Content-Type`. UTF-16 and UTF-32 bodies are transcoded to UTF-8 for inspection. A match replaces the response
with an empty 403. Other responses stream through unchanged; larger responses are inspected on their first 512 KiB.

### What is not inspected

- **The rest of a large body.** Responses are inspected on their first `ResponseBodyLimit` bytes.
- **Streaming responses.** A response that calls `DisableBuffering()` (server-sent events, streamed JSON) is
  inspected on what it wrote before that call, then streams through.
- **Compressed responses.** Place response compression outside (before) the WAF.
- **Upgraded connections.** WebSocket data after the 101 response is not inspected.
- **File content in multipart uploads**, as in CRS. File names and sizes are inspected.

## Quick start

```csharp
using Pondhawk.Waf;
using Pondhawk.Waf.AspNetCore;

builder.Services.AddPondhawkWaf(options =>
{
    options.Profile = WafProfile.Balanced;    // Performance, Balanced (default), Strict, Paranoid
    options.RuleEngine = RuleEngineMode.On;   // default: DetectionOnly
});

var app = builder.Build();
app.UsePondhawkWaf();                         // early: before routing, auth and body readers
```

Middleware order: place `UseResponseCompression()` **before** `UsePondhawkWaf()`, so the WAF sees uncompressed
responses. Compressed responses (`Content-Encoding` set by the application) are not inspected.

Run the sample:

```sh
dotnet run --project samples/Pondhawk.Waf.Sample
curl -i "http://localhost:5000/search?q=1'%20OR%20'1'='1"   # 403: SQL injection
curl -i "http://localhost:5000/leaky"                          # 403: SQL error leaked in the response
```

## Rollout

1. Deploy with `RuleEngine = DetectionOnly` (the default). Nothing is blocked.
2. Review the `Pondhawk.Waf.Rules` log for false positives.
3. Add exclusions (below).
4. Set `RuleEngine = RuleEngineMode.On`.

## Profiles

A profile pre-selects the security/performance settings. Any option set explicitly overrides the profile value.
`RuleEngine` (block or only log) is not part of a profile.

| Setting | `Performance` | `Balanced` (default) | `Strict` | `Paranoid` |
|---|---|---|---|---|
| Blocking paranoia level | 1 | 1 | 2 | 3 |
| Detection paranoia level (log only) | 1 | 2 | 3 | 4 |
| Inbound / outbound anomaly threshold | 5 / 4 | 5 / 4 | 5 / 4 | 3 / 3 |
| Response inspection | off | text, JSON | text, JSON, XML | text, JSON, XML |
| Response bytes inspected | — | 512 KiB | 1 MiB | 1 MiB |
| Request body limit | 13 MiB | 13 MiB | 8 MiB | 4 MiB |
| Request body limit without files | 1 MiB | 1 MiB | 512 KiB | 128 KiB |
| Arguments limit | 1000 | 1000 | 500 | 255 |
| Over-limit request body | 413 | 413 | 413 | 413 |
| Time per request (see below) | 0.6 ms | 1.2 ms | 1.5 ms | 1.4 ms |
| False positives / tuning effort | low | low | medium | high |

- `Performance` has the same request-side protection as `Balanced`. It drops response inspection and the log-only
  level 2 rules.
- Rules between the blocking and the detection level run and log (`Pondhawk.Waf.Rules`) but never block. Use the
  log to see what the next profile would block before you move to it.
- `Paranoid` blocks on a single warning-level match (threshold 3). Example: a POST without `Content-Length`
  (920180), or a parameter named `id` (932350, Unix command `id`). Expect exclusions.
- Time per request: in-process, Release build, one form POST plus a 10 KB HTML response, full CRS, single run on the
  development machine. Strict and Paranoid differ by less than the run-to-run noise.

```csharp
options.Profile = WafProfile.Strict;
options.InspectResponses = false;   // override: keep Strict rules, skip response buffering
options.ParanoiaLevel = 1;          // override: block at level 1; detection stays at 3
```

`options.Resolve()` returns the effective settings (`WafSettings`) and validates them. Startup fails on an invalid
combination, e.g. a detection level lower than the blocking level.

## Configuration

| Option | Default | Purpose |
|---|---|---|
| `Profile` | `Balanced` | Pre-selected settings (above) |
| `RuleEngine` | from config (`DetectionOnly`) | `On`, `DetectionOnly` or `Off` |
| `ParanoiaLevel` | profile | CRS blocking paranoia level 1-4 |
| `DetectionParanoiaLevel` | profile | CRS log-only paranoia level; not lower than `ParanoiaLevel` |
| `InboundAnomalyScoreThreshold` | profile | Request score that blocks; critical = 5, error = 4, warning = 3 |
| `OutboundAnomalyScoreThreshold` | profile | Response score that blocks |
| `InspectResponses` | profile | Hold and inspect response bodies (phases 3-4) |
| `ResponseMimeTypes` | profile | Response MIME types held and inspected |
| `ResponseBodyLimit` | profile | Response bytes held and inspected |
| `RequestBodyLimit` | profile | Largest request body (413 above) |
| `RequestBodyNoFilesLimit` | profile | Largest body without files: URL-encoded, JSON, XML, multipart form fields (413 above). Bounds the CPU time of one request |
| `ArgumentsLimit` | profile | Most arguments per request (400 above) |
| `Directives` | none | SecLang loaded after the profile settings, before the CRS rules |
| `DirectivesAfterRules` | none | SecLang loaded after the CRS rules |
| `RuleFiles` | none | SecLang files from disk, loaded last |
| `Bypass` | none | Predicate for requests that skip the WAF |
| `UseCoreRuleSet` | true | Load the embedded CRS. The base configuration (body processing, limits) loads either way |
| `WarmUp` | true | Pre-build regex automata at startup |

Load order: base configuration → CRS setup → profile settings → `Directives` → CRS rules → `DirectivesAfterRules`
→ `RuleFiles`. Later settings win, so per-path `ctl` rules in `Directives` override the profile. If `Directives`
raises `tx.blocking_paranoia_level`, the detection level is raised with it (otherwise CRS rule 901500 would answer
every request with 500).

### Exclusions

Runtime exclusion, before the rules (`Directives`):

```
SecRule REQUEST_FILENAME "@streq /login" \
    "id:10001,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:password"
```

Configure-time exclusion, after the rules (`DirectivesAfterRules`):

```
SecRuleRemoveById 920350
SecRuleUpdateTargetById 942100 "!ARGS:search"
```

Use ids 10000-99999 for your own rules.

### Logs

| Category | Level | Content |
|---|---|---|
| `Pondhawk.Waf.Rules` | Warning | One ModSecurity-style line per matched rule |
| `Pondhawk.Waf.Audit` | Information | One JSON entry per relevant transaction: a rule matched, the WAF blocked, or a 5xx |
| `Pondhawk.Waf.AspNetCore.WafMiddleware` | Warning | One line per blocked request |
| `Pondhawk.Waf` | Information, Warning | Effective settings at startup; a warning when the rule engine is not `On` |

What the logs contain:

- **Matched data, truncated.** Rule log lines and audit entries hold the matched data (logdata), cut at 512 bytes.
  An audit entry holds at most 200 messages.
- **No credentials.** Values are redacted (`[redacted]`) for cookies, credential headers (`Authorization`, `Cookie`,
  `Set-Cookie`, `X-Api-Key` and any name containing `token`, `secret`, `auth`, `session`, `api-key`...), and arguments
  whose names contain `pass`, `pwd`, `secret`, `token`, `auth` and similar (`LogRedaction.SensitiveNameParts`). Query
  parameters with such names are redacted in logged URIs. Other matched values are logged: they are the attack.
- **Control characters escaped**, including C1 controls and Unicode line breaks, so a request cannot forge log lines.

A log provider that throws does not fail requests; `WafEngine.LogFailures` counts the failures.

### Failure behavior

- **Configuration errors** (invalid profile values, bad directives, missing rule files) fail startup.
- **Engine errors** during a request propagate as exceptions: the request fails (500) instead of reaching the
  application uninspected.
- **Unparsable bodies** are rejected with 400 (`REQBODY_ERROR`, rule 200002), including invalid JSON strings.

## Projects

| Project | Content |
|---|---|
| `src/Pondhawk.Waf` | Engine: SecLang parser, transactions, operators, transformations, actions, body processors |
| `src/Pondhawk.Waf.LibInjection` | C# port of libinjection (SQLi and XSS detection) |
| `src/Pondhawk.Waf.CoreRuleSet` | Embedded CRS v4.30.0 and the base configuration |
| `src/Pondhawk.Waf.AspNetCore` | Middleware and DI registration |
| `tests/Pondhawk.Waf.Tests` | Engine, parser and middleware tests |
| `tests/Pondhawk.Waf.LibInjection.Tests` | All libinjection test vectors |
| `tests/Pondhawk.Waf.CrsRegression` | CRS regression suite runner (Kestrel, raw TCP) |
| `samples/Pondhawk.Waf.Sample` | Minimal API sample |

## Testing

```sh
dotnet test                                                     # unit, middleware and libinjection tests
dotnet run --project tests/Pondhawk.Waf.CrsRegression -c Release # CRS regression suite
```

The regression runner sends each CRS test as raw bytes to Kestrel with the configuration Coraza uses for the same
suite (paranoia level 4, DetectionOnly), and compares the logged rule ids. Results for CRS v4.30.0:

- 5,193 / 5,193 tests pass (5,088 request-side, 105 response-side). The backend implements albedo's `/reflect`.
- 21 tests use expectations from `kestrel-overrides.yaml`: requests that Kestrel rejects (400/505) or normalizes
  before the middleware runs. Each has a reason.

Options: `--filter <rule-id or text>`, `--filter '942100-3$'` (exact), `--verbose`, `--debug`, `--report <file>`.

## Performance

Measured in-process on the development machine (Release, full CRS, paranoia level 1):

- Startup: about 3.5 s to load and compile CRS (668 rules), plus warm-up.
- Per request: about 1.2 ms for a typical form POST; about 1.6 ms with a 10 KB HTML response inspected.
- Worst case: a body without files at the 1 MiB limit costs about 0.5-0.8 s of CPU and 150-250 MiB of allocation
  (every rule runs over every byte). Lower `RequestBodyNoFilesLimit` if your API does not need large bodies, and
  rate-limit clients in front of the WAF.

## License

Third-party licenses and attributions: [NOTICE](NOTICE).
