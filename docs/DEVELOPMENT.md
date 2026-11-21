# Developing Pondhawk WAF

Design and roadmap: [DESIGN.md](DESIGN.md). Usage: [README](../README.md).

## Projects

| Project | Content |
|---|---|
| `src/Pondhawk.Waf` | Engine: SecLang parser, transactions, operators, transformations, actions, body processors |
| `src/Pondhawk.Waf.LibInjection` | C# port of libinjection (SQLi and XSS detection) |
| `src/Pondhawk.Waf.CoreRuleSet` | Embedded CRS v4.30.0, the CRS exclusion plugins (`plugins/`) and the base configuration (`pondhawk/pondhawk-waf.conf`) |
| `src/Pondhawk.Waf.AspNetCore` | Middleware, options, profiles and DI registration |
| `tests/Pondhawk.Waf.Tests` | Engine, parser, middleware, profile and security regression tests |
| `tests/Pondhawk.Waf.LibInjection.Tests` | All libinjection test vectors |
| `tests/Pondhawk.Waf.LibInjection.Fuzz` | Differential fuzzer: the libinjection port against libinjection-go |
| `tests/Pondhawk.Waf.Pentest` | GoTestWAF target host, scan script and bypass triage |
| `tests/Pondhawk.Waf.CrsRegression` | CRS and plugin regression suite runner (Kestrel, raw TCP) |
| `samples/Pondhawk.Waf.Sample` | Minimal API sample |
| `benchmarks/Pondhawk.Waf.Benchmarks` | Startup, per-request, large-body and response measurements |

## Build and test

Requires the .NET 10 SDK.

```sh
dotnet build
dotnet test                                                       # unit, middleware, compatibility and libinjection tests
dotnet run --project tests/Pondhawk.Waf.CrsRegression -c Release  # CRS regression suite (about 40 s)
```

### Compatibility suite

`tests/Pondhawk.Waf.Compatibility` runs a realistic application on Kestrel, with the middleware Pond Hawk apps put
around the WAF. Outside: forwarded headers, response compression, security headers (NetEscapades), exception handler,
status code pages. Inside: WebSockets, static files, routing, CORS, rate limiting, authentication, antiforgery, output
cache, minimal APIs and a YARP route to a second Kestrel app.

The differential test sends each clean request to the app without the WAF and to the app with the WAF in `Off`,
`DetectionOnly`, `DetectionOnly` with held responses, and `On`. Status, headers and body must be the same. A
difference is a WAF bug until shown otherwise (#30, #31). To add a case, add an endpoint to `CompatibilityApp` and an
entry to `DifferentialTests.Cases`. To see the servers' warnings and errors, set `COMPAT_LOG=1`
(`COMPAT_LOG_LEVEL=Debug` for more).

### CRS regression suite

The regression runner sends each CRS test as raw bytes to Kestrel with the configuration Coraza uses for the same
suite (paranoia level 4, DetectionOnly), and compares the logged rule ids. Results for CRS v4.30.0:

- 5,193 / 5,193 tests pass (5,088 request-side, 105 response-side). The backend implements albedo's `/reflect`.
- 21 tests use expectations from `kestrel-overrides.yaml`: requests that Kestrel rejects (400/505) or normalizes
  before the middleware runs. Each has a reason.
- The plugin tests (`plugin-tests/`, 459) run on a second server with every plugin loaded. 8 Nextcloud tests use
  expectations from `plugin-overrides.yaml` (differences from ModSecurity, see DESIGN.md).
- A regex timeout fails the run (`REGEX TIMEOUT`). Run with `--regex-engine backtracking` too.
- Every value the regex prefilter rejects is checked against the regex. A prefilter that hides a match fails the
  run (`PREFILTER MISSED A MATCH`).

To update a plugin, copy `plugins/*.conf` and `LICENSE` from its release into
`src/Pondhawk.Waf.CoreRuleSet/plugins/<name>/`, its `tests/regression/*/*.yaml` into `plugin-tests/<name>/`, and
update `plugins/VERSIONS`.

Options: `--filter <rule-id or text>`, `--filter '942100-3$'` (exact), `--regex-engine backtracking`, `--verbose`,
`--debug`, `--report <file>`.

`SecurityHardeningTests` holds one regression test per finding of the adversarial security review. A change that
re-opens a bypass fails there.

## libinjection differential fuzzer

`src/Pondhawk.Waf.LibInjection` is a port of libinjection-go; `oracle/go.mod` pins the version it must match. The
fuzzer sends the same bytes to both and compares `IsSQLi`, the fingerprint and `IsXSS`. It needs Go, podman or
docker (for a `golang` container) to build the oracle.

```sh
tests/Pondhawk.Waf.LibInjection.Fuzz/run.sh                              # 1,000,000 inputs, random seed
tests/Pondhawk.Waf.LibInjection.Fuzz/run.sh --count 25000000 --seed 7    # reproducible
tests/Pondhawk.Waf.LibInjection.Fuzz/run.sh --max-len 8192 --report fuzz.txt
```

1. A sweep tries every SQLi keyword, XSS tag, event and attribute from the port's tables in fixed templates, every
   byte, and every pair of special bytes.
2. The fuzz phase mutates the test vectors, joins dictionary tokens, and adds random and long inputs (up to
   `--max-len`, 512 by default; one input in ten is not cut).
3. A Unicode phase (a tenth of `--count`, plus every keyword with I or S written as U+0131 or U+017F) checks .NET
   strings with chars above U+00FF. The port encodes them as UTF-8; the harness computes Go's bytes on its own.

Each difference is minimized and printed with both results; the exit code is 1. A C# exception and a Go panic are
differences too. To port a new libinjection-go release: update the version in `oracle/go.mod`, run the fuzzer, and
fix each difference in the port or in its tests.

## GoTestWAF scan

`tests/Pondhawk.Waf.Pentest/run.sh` scans the WAF with GoTestWAF (in a docker or podman container, pinned by digest),
once per profile, with `RuleEngine = On`. The target host accepts every method and path and reads the input. It
takes about a minute for all four profiles. The `GoTestWAF scan` workflow runs the same script by hand and uploads
the reports.

```sh
tests/Pondhawk.Waf.Pentest/run.sh                                  # all profiles, reports in ./pentest-reports
tests/Pondhawk.Waf.Pentest/run.sh --profiles Balanced --triage     # also triage the bypasses
```

With `--triage`, the attack test sets run once more on Balanced; each request that passes is captured and replayed
with paranoia level 4 detection. `triage-Balanced.md` groups the bypasses: first match at PL2-4 (a CRS paranoia
trade-off), no CRS rule matches (payload encoded as Base64, or in a place CRS does not inspect for that attack), and
"PL1 score >= 5", which must stay empty: a request there passed the blocking scan but scores as an attack.

A bypass is a Pondhawk bug when a CRS rule that inspects that place should match the payload and does not. Check it
with the rule's targets and pattern before opening an issue.

## Performance

Measure with the benchmark project, in Release, on an idle machine:

```sh
dotnet run -c Release --project benchmarks/Pondhawk.Waf.Benchmarks                 # all scenarios
dotnet run -c Release --project benchmarks/Pondhawk.Waf.Benchmarks -- request alloc # selected ones
```

Wall times vary with machine load; CPU time and allocation are steadier. Set `DOTNET_gcServer=1` to match ASP.NET Core
hosts. Milestone 4 results (full CRS, Balanced unless noted; CPU time per request; 4-core machine under load):

| Scenario | 0.1.0 | Now |
|---|---|---|
| Form POST with a 10 KB HTML response | 1.37 ms, 878 KiB allocated | 0.52 ms, 250 KiB |
| GET | 0.65 ms, 611 KiB | 0.31 ms, 151 KiB |
| Profiles Performance / Strict / Paranoid | 0.49 / 1.42 / 1.48 ms | 0.25 / 0.56 / 0.59 ms |
| 1 MiB URL-encoded body, 1000 arguments | 358 ms, 234 MiB | 186 ms, 82 MiB |
| 1 MiB single argument | 404 ms, 214 MiB | 169 ms, 85 MiB |
| 512 KiB HTML response (wall, through the middleware) | 31 ms, 9.7 MiB | 14 ms, 7.9 MiB |
| Startup until the engine serves requests (cold process) | 2.6-4.0 s | 0.6 s |

After startup the regex automata build in the background (`WafEngine.Compiled`, about 1.5-3 s here); a request that
needs one before then builds it or waits for it.

## Releasing

Packages: `Pondhawk.Waf`, `Pondhawk.Waf.LibInjection`, `Pondhawk.Waf.CoreRuleSet`, `Pondhawk.Waf.AspNetCore`, all
with the version in `Directory.Build.props` (`VersionPrefix`).

1. Merge to `main`. The `Build` workflow tests every push and pull request, runs the CRS regression suite, and packs.
2. Run the `Publish to NuGet.org` workflow by hand (Actions tab). Choose a bump (`none` publishes the version in the
   file as-is), or tick `dry_run` to build, test and pack without publishing.
3. The workflow pushes to nuget.org with Trusted Publishing (no API key), mirrors to GitHub Packages, commits the
   bump, tags `vX.Y.Z` and creates a GitHub release.

A nuget.org version is permanent: it can be unlisted, never replaced or deleted.
