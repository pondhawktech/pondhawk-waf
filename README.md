# Pondhawk WAF

A web application firewall for ASP.NET Core, modeled after [OWASP Coraza](https://coraza.io). It runs SecLang rules
and ships the [OWASP Core Rule Set](https://coreruleset.org) (CRS) v4.30.0.

Status: milestone 1, request-side protection. All 5,088 request-side CRS regression tests pass (see
[Testing](#testing)). Response inspection is planned for milestone 2 ([docs/DESIGN.md](docs/DESIGN.md)).

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

The base configuration also rejects bodies that cannot be parsed, strict multipart errors, more than 1,000
arguments, and bodies over 13 MiB (413).

## Quick start

```csharp
using Pondhawk.Waf;
using Pondhawk.Waf.AspNetCore;

builder.Services.AddPondhawkWaf(options =>
{
    options.RuleEngine = RuleEngineMode.On;   // default: DetectionOnly
    options.ParanoiaLevel = 1;                // 1-4
});

var app = builder.Build();
app.UsePondhawkWaf();                         // early: before routing, auth and body readers
```

Run the sample:

```sh
dotnet run --project samples/Pondhawk.Waf.Sample
curl -i "http://localhost:5000/search?q=1'%20OR%20'1'='1"   # 403
```

## Rollout

1. Deploy with `RuleEngine = DetectionOnly` (the default). Nothing is blocked.
2. Review the `Pondhawk.Waf.Rules` log for false positives.
3. Add exclusions (below).
4. Set `RuleEngine = RuleEngineMode.On`.

## Configuration

| Option | Default | Purpose |
|---|---|---|
| `RuleEngine` | from config (`DetectionOnly`) | `On`, `DetectionOnly` or `Off` |
| `ParanoiaLevel` | 1 | CRS paranoia level 1-4 |
| `InboundAnomalyScoreThreshold` | 5 | CRS blocking threshold; one critical match = 5 |
| `Directives` | none | SecLang loaded after CRS setup, before the CRS rules |
| `DirectivesAfterRules` | none | SecLang loaded after the CRS rules |
| `RuleFiles` | none | SecLang files from disk, loaded last |
| `Bypass` | none | Predicate for requests that skip the WAF |
| `UseCoreRuleSet` | true | Load the embedded CRS |
| `WarmUp` | true | Pre-build regex automata at startup |

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
| `Pondhawk.Waf.Audit` | Information | One JSON entry per relevant transaction (blocked or 4xx/5xx) |
| `Pondhawk.Waf.AspNetCore.WafMiddleware` | Warning | One line per blocked request |

The audit log redacts `Authorization`, `Cookie` and other credential headers. Rule log lines contain the matched
data, which can include parts of the request.

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

- 5,088 / 5,088 request-side tests pass.
- 105 response-side tests are skipped (milestone 2).
- 21 tests use expectations from `kestrel-overrides.yaml`: requests that Kestrel rejects (400/505) or normalizes
  before the middleware runs. Each has a reason.

Options: `--filter <rule-id or text>`, `--filter '942100-3$'` (exact), `--verbose`, `--debug`, `--report <file>`.

## Performance

Measured in-process on the development machine (Release, full CRS, paranoia level 1):

- Startup: about 3.5 s to load and compile CRS (668 rules), plus warm-up.
- Per request: about 1.2 ms for a typical form POST (all phases).

## License

Third-party licenses and attributions: [NOTICE](NOTICE).
