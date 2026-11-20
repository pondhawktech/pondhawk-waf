<p align="center">
  <img src="https://raw.githubusercontent.com/pondhawktech/pondhawk-waf/main/pht-small-logo.png" alt="Pondhawk.Waf" width="120" />
</p>

<h1 align="center">Pondhawk.Waf</h1>

<p align="center">
  A web application firewall for ASP.NET Core. Middleware that runs the OWASP Core Rule Set (CRS) unchanged, on a
  SecLang engine modeled after OWASP Coraza: SQL injection, XSS, command injection, path traversal, protocol attacks,
  and data leaks in responses, blocked before they reach your application or your users.
</p>

<p align="center">
  <a href="https://github.com/pondhawktech/pondhawk-waf/actions/workflows/build.yml"><img src="https://github.com/pondhawktech/pondhawk-waf/actions/workflows/build.yml/badge.svg" alt="Build" /></a>
  <img src="https://img.shields.io/badge/.NET-10.0-512bd4" alt=".NET 10" />
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0 License" />
  <img src="https://img.shields.io/badge/OWASP%20CRS-4.30.0-green" alt="OWASP CRS 4.30.0" />
  <a href="https://www.nuget.org/packages/Pondhawk.Waf.AspNetCore"><img src="https://img.shields.io/nuget/v/Pondhawk.Waf.AspNetCore?label=Waf.AspNetCore" alt="Pondhawk.Waf.AspNetCore on NuGet" /></a>
  <a href="https://www.nuget.org/packages/Pondhawk.Waf"><img src="https://img.shields.io/nuget/v/Pondhawk.Waf?label=Waf" alt="Pondhawk.Waf on NuGet" /></a>
</p>

| Package | Description |
|---------|-------------|
| **Pondhawk.Waf.AspNetCore** | The middleware, options and profiles. **Install this one**; it brings the others. |
| **Pondhawk.Waf** | The engine: SecLang parser, rule evaluation, operators, transformations, body processors, audit log. Use it directly to inspect traffic outside ASP.NET Core. |
| **Pondhawk.Waf.CoreRuleSet** | OWASP CRS v4.30.0 and the official CRS application plugins, embedded unmodified, and the Pondhawk base configuration. |
| **Pondhawk.Waf.LibInjection** | C# port of libinjection (SQLi and XSS fingerprinting), used by CRS `@detectSQLi` and `@detectXSS`. |

- [Quick start](#quick-start)
- [Rolling out](#rolling-out)
- [Profiles](#profiles)
- [Configuration examples](#configuration-examples)
- [Options](#options)
- [Logs](#logs)
- [Metrics](#metrics)
- [What it protects against](#what-it-protects-against)
- [Limits and failure behavior](#limits-and-failure-behavior)

## Quick start

```sh
dotnet add package Pondhawk.Waf.AspNetCore
```

```csharp
using Pondhawk.Waf;
using Pondhawk.Waf.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPondhawkWaf(options =>
{
    options.Profile = WafProfile.Balanced;   // Performance, Balanced (default), Strict, Paranoid
    options.RuleEngine = RuleEngineMode.On;  // the default is DetectionOnly: log, do not block
});

var app = builder.Build();

app.UsePondhawkWaf();                        // early: before routing, authentication and body readers

app.MapGet("/search", (string q) => $"results for {q}");
app.Run();
```

```sh
curl -i "http://localhost:5000/search?q=1'%20OR%20'1'='1"   # 403
```

A blocked request gets an empty response with the rule's status: 403 for attacks, 400 for unparsable bodies, 413 for
bodies over the limit. The response carries no rule ids or messages; those go to the [logs](#logs).

## Rolling out

Start without blocking, then tune, then block.

1. Deploy with `RuleEngine = RuleEngineMode.DetectionOnly` (the default). Requests are inspected and logged, never
   blocked. Startup logs a warning to remind you.
2. Read the `Pondhawk.Waf.Rules` log. Each line is a rule that matched: a real attack or a false positive.
3. Add an [exclusion](#exclusions) for each false positive, or the [plugin](#application-plugins) of a known
   application.
4. Set `RuleEngine = RuleEngineMode.On`.

To move to a higher profile later (for example Balanced to Strict), repeat the cycle. The rules of the next level
already run and log in the current profile (the *detection paranoia level* below), so the log shows what Strict would
block before you switch.

## Profiles

A profile pre-selects the security and performance settings. Any option you set explicitly overrides the profile
value. `RuleEngine` (block or only log) is not part of a profile.

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
| Time per request | 0.25 ms | 0.5 ms | 0.56 ms | 0.59 ms |
| False positives / tuning effort | low | low | medium | high |

- **Paranoia level** selects how many CRS rules run. Level 1 catches common attacks with few false positives. Each
  higher level adds rules that catch more evasions and flag more legitimate traffic.
- **Detection paranoia level:** rules above the blocking level, up to this level, run and log but never block.
- **Anomaly threshold:** each match adds to a score (critical 5, error 4, warning 3). A request or response that
  reaches the threshold is blocked. `Paranoid` blocks on a single warning, for example a parameter named `id` (rule
  932350 reads it as the Unix `id` command). Expect exclusions.
- **Performance** has the same request protection as Balanced. It drops response inspection and the log-only rules.
- **Time per request:** one form POST plus a 10 KB HTML response, in-process, Release build.

## Configuration examples

### Profile with overrides

```csharp
builder.Services.AddPondhawkWaf(options =>
{
    options.Profile = WafProfile.Strict;
    options.RuleEngine = RuleEngineMode.On;

    options.RequestBodyLimit = 50 * 1024 * 1024;        // file uploads up to 50 MiB (Strict: 8 MiB)
    options.RequestBodyNoFilesLimit = 2 * 1024 * 1024;  // JSON bodies up to 2 MiB (Strict: 512 KiB)
    options.ArgumentsLimit = 2000;                      // large forms (Strict: 500)
    options.InspectResponses = false;                   // keep the Strict rules, skip response buffering
});
```

`options.Resolve()` returns the effective settings (`WafSettings`). Invalid combinations fail at startup, not on the
first request.

### Settings from appsettings.json

Bind the options to a configuration section:

```csharp
builder.Services.AddPondhawkWaf(builder.Configuration.GetSection("Pondhawk:Waf"), options =>
{
    // Values that configuration cannot hold.
    options.Bypass = ctx => ctx.Request.Path == "/healthz";
});
```

```json
{
  "Pondhawk": {
    "Waf": {
      "RuleEngine": "On",
      "Profile": "Strict",
      "RequestBodyLimit": 52428800,
      "Plugins": [ "WordPress" ],
      "Exclusions": [
        { "Rule": "942100", "Target": "ARGS:password", "Path": "/login" },
        { "Tag": "attack-xss", "Target": "ARGS:json.body", "Path": "/api/posts" },
        { "Rule": "920350" }
      ]
    }
  }
}
```

Every option in the [table](#options) binds by name. Keep `"RuleEngine": "DetectionOnly"` in `appsettings.json` and
set `"On"` in `appsettings.Production.json` when tuning is done.

**Reload without a restart.** When the section changes (for example, `appsettings.json` is saved), the WAF builds a
new engine in the background and swaps it in:

- Requests in flight finish on the old engine.
- A configuration that does not build (invalid value, bad directive) logs an error (event 15) and the current rules
  stay in force. Startup still fails on an invalid configuration.
- A successful reload logs the new settings (event 14).
- Changes to `RuleFiles` on disk are not watched. Set `ReloadOnChange` to `false` to turn reload off.

### Middleware order

```csharp
var app = builder.Build();

app.UseForwardedHeaders();       // first: the WAF logs and matches the real client address
app.UseExceptionHandler("/error");
app.UseResponseCompression();    // before the WAF: the WAF must see uncompressed responses
app.UsePondhawkWaf();
app.UseStaticFiles();            // after the WAF, so static file requests are inspected too
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
```

The WAF must run before anything that reads the request body (MVC, minimal API binding, `ReadFormAsync`). It
buffers the body, inspects it, and rewinds it for the application.

### Skip health checks

```csharp
options.Bypass = ctx => ctx.Request.Path == "/healthz";
```

A bypassed request is not inspected at all. Keep the predicate narrow. Never base it on a header the client controls.

### Exclusions

Fix false positives with exclusions, not by lowering the profile. The rule id is in the `Pondhawk.Waf.Rules` log line
(`[id "942100"]`).

```csharp
builder.Services.AddPondhawkWaf(options =>
{
    // The password field of /login may contain anything: rule 942100 does not inspect it.
    options.Exclude(942100, "ARGS:password", path: "/login");

    // Rich-text editor: no XSS rules on the body field of /api/posts and the paths below it.
    options.ExcludeByTag("attack-xss", "ARGS:json.body", path: "/api/posts");

    // A rule, a range or a tag off for one path, or everywhere.
    options.RemoveRule(920350);
    options.RemoveRules(942100, 942199, path: "/admin/sql-console");
    options.RemoveRulesByTag("attack-sqli", path: "/admin/sql-console");

    // SQLi rules do not inspect the tracking cookie, everywhere.
    options.ExcludeByTag("attack-sqli", "REQUEST_COOKIES:tracking");
});
```

- **Target:** a variable with an optional key: `ARGS:name`, `REQUEST_COOKIES:name`, `REQUEST_HEADERS:User-Agent`,
  `FILES:avatar`, or a key regex such as `ARGS:/^json\.items\./`. JSON fields are named `json.<path>`:
  `{"post":{"body":"..."}}` gives `ARGS:json.post.body`.
- **Path:** a prefix that matches the path and the paths below it, ignoring case: `/login` matches `/login` and
  `/login/step2`, not `/login2`. It is the path as the client sends it, before `PathBase` is removed.
- **Safe paths:** a path exclusion does not apply when the server could route the request target to another path: dot
  segments (`/login/../admin`), encoded slashes or dots, backslashes, or an absolute-form target. Those requests get
  the full rules.
- **Errors:** an invalid exclusion fails at startup. So does an `Exclude` without a path for a rule id that does not
  exist.

The helpers generate SecLang. To write it yourself, use `Directives` for runtime (`ctl`) exclusions and
`DirectivesAfterRules` for `SecRuleRemoveById` and `SecRuleUpdateTargetBy*`:

```csharp
options.Directives = """
    SecRule REQUEST_HEADERS:X-Tenant "@streq legacy" \
        "id:10001,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:filter"
    """;
options.DirectivesAfterRules = """
    SecRuleUpdateTargetById 942100 "!ARGS:search"
    """;
```

Use ids 10000-99999 for your own rules. The WAF generates ids 900000, 900001, 900002, 900110 and 10000000 and up:
set the paranoia level and thresholds with options, not with `SecAction`.

### Application plugins

The official CRS rule exclusion plugins remove the known false positives of popular applications, on those
applications' paths only:

```csharp
options.Plugins.Add(CrsPlugin.WordPress);   // using Pondhawk.Waf.CoreRuleSet;
```

Available: `WordPress`, `Drupal`, `Nextcloud`, `DokuWiki`, `CPanel`, `PhpBB`, `PhpMyAdmin`, `XenForo`. Use them when
the WAF protects one of these applications behind a reverse proxy built on ASP.NET Core (for example YARP). A plugin
setting can be changed with a `SecAction` in `Directives`, which loads after the plugin configuration.

### Your own rules

```csharp
options.DirectivesAfterRules = """
    # Admin pages only from the internal network.
    SecRule REQUEST_FILENAME "@beginsWith /admin" \
        "id:10100,phase:1,deny,status:403,log,msg:'Admin from outside',chain"
        SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8,192.168.0.0/16"

    # Never send a .NET stack trace to the client.
    SecRule RESPONSE_BODY "@contains at System." \
        "id:10101,phase:4,deny,status:500,log,msg:'.NET stack trace in response'"
    """;
```

Rules from files on disk:

```csharp
options.RuleFiles.Add("waf/custom-rules.conf"); // Relative to the content root.
```

### Response inspection

```csharp
options.InspectResponses = true;
options.ResponseMimeTypes = ["text/html", "application/json", "application/xml"];
options.ResponseBodyLimit = 1024 * 1024;   // hold and inspect the first 1 MiB
```

A listed type also covers its family:

- `application/json` covers `text/json` and every `+json` type.
- `application/xml` or `text/xml` covers every `+xml` type.
- `text/plain` covers responses without `Content-Type`.

A response that leaks a SQL error, a stack trace or a web shell is replaced with an empty 403 before the client
receives any byte.

With `RuleEngine = On`, an inspected response is held until it is complete (or reaches `ResponseBodyLimit`), so it
reaches the client later. Memory peaks at about three times the held size while phase 4 runs: the bytes, plus the
text the rules read. DetectionOnly cannot replace a
response, so it does not hold it: the response streams to the client as the application writes it, and a copy is
inspected. Set `HoldResponsesInDetectionOnly = true` to measure the latency that switching to `On` will add.

Phase 3 inspects the status and headers when the response starts: at the first write, `StartAsync`, or when the
application returns. From then on the response behaves as started, even while it is held:

- `OnStarting` callbacks registered by the application run before phase 3, so the headers they add are inspected.
- Changing the status or a header afterwards throws `InvalidOperationException`, as on a started response.
- If the application throws after it started a response, the connection is aborted, as it would be without the WAF.
  An exception handler outside the WAF cannot send an uninspected error page in its place. An error page for an
  exception thrown before the response started is written outside the WAF and is not inspected.

### Audit log to a file

By default the audit log goes through `ILogger`, category `Pondhawk.Waf.Audit`. To write JSON lines to a file:

```csharp
using Pondhawk.Waf.AuditLog;

var auditFile = new StreamWriter("/var/log/myapp/waf-audit.jsonl", append: true);
options.Configure = waf => waf.Config.AuditLogWriter = new JsonLinesAuditLogWriter(auditFile);
```

Implement `IAuditLogWriter` to send entries anywhere else.

### Read the WAF result in the application

```csharp
app.MapPost("/comments", (HttpContext ctx) =>
{
    var tx = (Transaction)ctx.Items[WafMiddleware.TransactionKey]!;
    if (tx.DetectionOnlyInterruption is not null)
    {
        // DetectionOnly: the WAF would have blocked this request.
    }

    var ruleIds = tx.MatchedRules.Select(m => m.Rule.Id);
    // ...
});
```

### Your own rule set instead of CRS

```csharp
options.UseCoreRuleSet = false;               // body processing and limits still apply
options.RuleFiles.Add("/etc/myapp/rules.conf");
```

## Options

| Option | Default | Purpose |
|---|---|---|
| `Profile` | `Balanced` | Pre-selected settings ([Profiles](#profiles)) |
| `RuleEngine` | `DetectionOnly` | `On` blocks, `DetectionOnly` only logs, `Off` skips inspection |
| `ParanoiaLevel` | profile | CRS blocking paranoia level 1-4 |
| `DetectionParanoiaLevel` | profile | CRS log-only paranoia level; never lower than `ParanoiaLevel` |
| `InboundAnomalyScoreThreshold` | profile | Request score that blocks |
| `OutboundAnomalyScoreThreshold` | profile | Response score that blocks |
| `InspectResponses` | profile | Hold and inspect response bodies |
| `ResponseMimeTypes` | profile | Response MIME types held and inspected |
| `ResponseBodyLimit` | profile | Response bytes held and inspected |
| `RequestBodyLimit` | profile | Largest request body, files included (413 above) |
| `RequestBodyNoFilesLimit` | profile | Largest body without files: URL-encoded, JSON, XML, multipart form fields (413 above). Bounds the CPU time of one request |
| `ArgumentsLimit` | profile | Most arguments or multipart parts per request (400 above) |
| `Exclusions` | none | Rule exclusions ([Exclusions](#exclusions)); in code, use the helpers |
| `Plugins` | none | CRS application plugins ([Application plugins](#application-plugins)) |
| `Directives` | none | SecLang loaded after the profile settings, before the CRS rules: runtime (`ctl`) exclusions, your rules |
| `DirectivesAfterRules` | none | SecLang loaded after the CRS rules: `SecRuleRemoveById`, `SecRuleUpdateTargetBy*` |
| `RuleFiles` | none | SecLang files from disk, loaded last. Relative paths (also in `Include` and `@pmFromFile`) resolve against the content root |
| `Bypass` | none | Predicate for requests that skip the WAF |
| `UseCoreRuleSet` | `true` | Load the embedded CRS. The base configuration (body processing, limits) loads either way |
| `WarmUp` | `true` | After the regexes are built, run synthetic requests in the background, so the first real requests do not pay for building DFA states |
| `HoldResponsesInDetectionOnly` | `false` | In DetectionOnly, hold inspected responses as `On` does, instead of streaming them and inspecting a copy |
| `ReloadOnChange` | `true` | Rebuild the engine when bound configuration changes ([reload](#settings-from-appsettingsjson)) |
| `Configure` | none | Access to the engine builder (`WafBuilder`) after the options are applied |

Load order: base configuration → CRS setup → profile settings → plugin configuration → `Directives` → path
exclusions → plugins (before) → CRS rules → plugins (after) → `DirectivesAfterRules` → `RuleFiles` → global
exclusions. Later settings win.

## Logs

| Category | Level | Content |
|---|---|---|
| `Pondhawk.Waf.Rules` | Warning | One ModSecurity-style line per matched rule |
| `Pondhawk.Waf.Audit` | Information | One JSON entry per relevant request: a rule matched, the WAF blocked, or a 5xx |
| `Pondhawk.Waf.AspNetCore.WafMiddleware` | Warning | One line per blocked request |
| `Pondhawk.Waf` | Information, Warning, Error | Effective settings at startup and after a reload; a warning when the rule engine does not block, when warm-up fails, or when the services are registered without `UsePondhawkWaf()`; an error when a changed configuration does not build |

```json
{
  "Logging": {
    "LogLevel": {
      "Pondhawk.Waf.Rules": "Warning",
      "Pondhawk.Waf.Audit": "Information"
    }
  }
}
```

What the logs contain:

- **Matched data, truncated.** Rule lines and audit entries hold the matched data, cut at 512 bytes. An audit entry
  holds at most 200 messages.
- **No credentials.** These values are redacted (`[redacted]`):
  - cookies;
  - credential headers: `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, and any header whose name contains
    `token`, `secret`, `auth` or `session`;
  - arguments and query parameters whose names contain `pass`, `pwd`, `secret`, `token`, `auth` and similar.

  Add names with `LogRedaction.SensitiveNameParts` and `LogRedaction.SensitiveHeaders`. Other matched values are
  logged: they are the attack.
- **Escaped control characters**, including Unicode line breaks, so a request cannot forge log lines.

A log provider that throws does not fail requests. `WafEngine.LogFailures` and the `pondhawk.waf.log_failures` metric
count the failures.

## Metrics

The WAF publishes metrics on the `Pondhawk.Waf` meter. With OpenTelemetry:

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics => metrics
        .AddMeter("Pondhawk.Waf")
        .AddPrometheusExporter());
```

Or live, without code: `dotnet-counters monitor -n MyApp --counters Pondhawk.Waf`.

| Instrument | Type | Tags | Use |
|---|---|---|---|
| `pondhawk.waf.requests` | counter | `waf.result`: `allowed`, `blocked`, `detected`, `bypassed`, `off` | Traffic and block rate |
| `pondhawk.waf.blocks` | counter | `waf.rule.id`, `waf.action`, `http.response.status_code` | What blocks, and why |
| `pondhawk.waf.would_block` | counter | same as `blocks` | DetectionOnly: what On would block |
| `pondhawk.waf.rule.matches` | counter | `waf.rule.id` | Matches of rules that log: find false positives |
| `pondhawk.waf.phase.duration` | histogram, s | `waf.phase`: `request_headers`, `request_body`, `response_headers`, `response_body`, `logging` | WAF latency; network waits excluded |
| `pondhawk.waf.log_failures` | counter | none | Log or audit sink failures |
| `pondhawk.waf.reloads` | counter | `waf.result`: `success`, `failure` | Configuration reloads |

To tune a higher profile, run it in DetectionOnly. Then read `would_block` and `rule.matches` by rule id: each rule
with many matches on normal traffic needs an exclusion.

## What it protects against

CRS at paranoia level 1, on the path, query string, headers, cookies, and URL-encoded, multipart, JSON and XML bodies:

| Attack | CRS rules |
|---|---|
| SQL injection (regex and libinjection) | 942xxx |
| Cross-site scripting (regex and libinjection) | 941xxx |
| Remote command execution (Unix, Windows, PowerShell) | 932xxx |
| Local and remote file inclusion, path traversal | 930xxx, 931xxx |
| PHP, Java, Node.js and generic injection, SSRF | 933xxx, 944xxx, 934xxx |
| Protocol violations, request smuggling, header injection | 920xxx, 921xxx |
| Multipart evasion, session fixation, scanners | 922xxx, 943xxx, 913xxx |
| Data leaks in responses: SQL errors, stack traces, PHP/Java/IIS/Ruby errors, directory listings | 950xxx-956xxx |
| Web shells in responses | 955xxx |

The base configuration also rejects:

- bodies that cannot be parsed;
- multipart bodies that ASP.NET Core would parse differently from the WAF;
- requests with too many arguments;
- oversized bodies.

The engine passes all 5,193 tests of the CRS v4.30.0 regression suite, and the 459 regression tests of the bundled
application plugins.

## Limits and failure behavior

Not inspected:

- **The rest of a large response.** Responses are inspected on their first `ResponseBodyLimit` bytes.
- **Streaming responses.** A response that calls `DisableBuffering()` (server-sent events, streamed JSON) is
  inspected on what it wrote before that call. The rest streams through.
- **Compressed responses.** Put `UseResponseCompression()` before `UsePondhawkWaf()`.
- **WebSocket data** after the upgrade.
- **File content** in multipart uploads, as in CRS. File names and sizes are inspected.

Failure behavior:

- **Configuration errors** (invalid option values, bad directives, missing rule files) fail startup. After startup,
  a reload with errors keeps the current rules.
- **Engine errors** during a request fail the request (500). The request never reaches the application uninspected.
- **Cost:** every rule runs over every byte of a body without files. At the 1 MiB default, a worst-case body costs
  about 0.2-0.4 s of CPU. Lower `RequestBodyNoFilesLimit` if your API does not need large bodies, and rate-limit
  clients in front of the application.

## More

- [Sample application](https://github.com/pondhawktech/pondhawk-waf/blob/main/samples/Pondhawk.Waf.Sample/Program.cs)
- [Design and roadmap](https://github.com/pondhawktech/pondhawk-waf/blob/main/docs/DESIGN.md), including the known differences from Coraza
- [Developing and releasing](https://github.com/pondhawktech/pondhawk-waf/blob/main/docs/DEVELOPMENT.md)
- [Security policy](https://github.com/pondhawktech/pondhawk-waf/blob/main/SECURITY.md): how to report a vulnerability or a bypass

## License

Apache-2.0. Pondhawk.Waf.LibInjection is BSD-3-Clause. Third-party attributions (OWASP Coraza, OWASP CRS,
libinjection): [NOTICE](https://github.com/pondhawktech/pondhawk-waf/blob/main/NOTICE).
