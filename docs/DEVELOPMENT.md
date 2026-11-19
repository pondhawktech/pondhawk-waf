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

To update a plugin, copy `plugins/*.conf` and `LICENSE` from its release into
`src/Pondhawk.Waf.CoreRuleSet/plugins/<name>/`, its `tests/regression/*/*.yaml` into `plugin-tests/<name>/`, and
update `plugins/VERSIONS`.

Options: `--filter <rule-id or text>`, `--filter '942100-3$'` (exact), `--verbose`, `--debug`, `--report <file>`.

`SecurityHardeningTests` holds one regression test per finding of the adversarial security review. A change that
re-opens a bypass fails there.

## Performance

Measured in-process on the development machine (Release, full CRS):

- Startup: about 3.5 s to load and compile CRS (668 rules), plus warm-up.
- Per request: about 1.2 ms for a typical form POST; about 1.6 ms with a 10 KB HTML response inspected.
- Per profile: Performance 0.6 ms, Balanced 1.2 ms, Strict 1.5 ms, Paranoid 1.4 ms (`ProfilePerfProbe`, skipped by
  default; remove the `Skip` to run it).
- Worst case: a body without files at the 1 MiB limit costs about 0.5-0.8 s of CPU and 150-250 MiB of allocation.

## Releasing

Packages: `Pondhawk.Waf`, `Pondhawk.Waf.LibInjection`, `Pondhawk.Waf.CoreRuleSet`, `Pondhawk.Waf.AspNetCore`, all
with the version in `Directory.Build.props` (`VersionPrefix`).

1. Merge to `main`. The `Build` workflow tests every push and pull request, runs the CRS regression suite, and packs.
2. Run the `Publish to NuGet.org` workflow by hand (Actions tab). Choose a bump (`none` publishes the version in the
   file as-is), or tick `dry_run` to build, test and pack without publishing.
3. The workflow pushes to nuget.org with Trusted Publishing (no API key), mirrors to GitHub Packages, commits the
   bump, tags `vX.Y.Z` and creates a GitHub release.

A nuget.org version is permanent: it can be unlisted, never replaced or deleted.
