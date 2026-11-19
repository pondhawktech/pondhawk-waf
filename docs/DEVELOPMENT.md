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
| `tests/Pondhawk.Waf.CrsRegression` | CRS and plugin regression suite runner (Kestrel, raw TCP) |
| `samples/Pondhawk.Waf.Sample` | Minimal API sample |
| `benchmarks/Pondhawk.Waf.Benchmarks` | Startup, per-request, large-body and response measurements |

## Build and test

Requires the .NET 10 SDK.

```sh
dotnet build
dotnet test                                                       # unit, middleware and libinjection tests
dotnet run --project tests/Pondhawk.Waf.CrsRegression -c Release  # CRS regression suite (about 40 s)
```

The regression runner sends each CRS test as raw bytes to Kestrel with the configuration Coraza uses for the same
suite (paranoia level 4, DetectionOnly), and compares the logged rule ids. Results for CRS v4.30.0:

- 5,193 / 5,193 tests pass (5,088 request-side, 105 response-side). The backend implements albedo's `/reflect`.
- 21 tests use expectations from `kestrel-overrides.yaml`: requests that Kestrel rejects (400/505) or normalizes
  before the middleware runs. Each has a reason.
- The plugin tests (`plugin-tests/`, 459) run on a second server with every plugin loaded. 8 Nextcloud tests use
  expectations from `plugin-overrides.yaml` (differences from ModSecurity, see DESIGN.md).
- Every value the regex prefilter rejects is checked against the regex. A prefilter that hides a match fails the
  run (`PREFILTER MISSED A MATCH`).

To update a plugin, copy `plugins/*.conf` and `LICENSE` from its release into
`src/Pondhawk.Waf.CoreRuleSet/plugins/<name>/`, its `tests/regression/*/*.yaml` into `plugin-tests/<name>/`, and
update `plugins/VERSIONS`.

Options: `--filter <rule-id or text>`, `--filter '942100-3$'` (exact), `--verbose`, `--debug`, `--report <file>`.

`SecurityHardeningTests` holds one regression test per finding of the adversarial security review. A change that
re-opens a bypass fails there.

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
