// Measures engine startup, per-request cost and allocation. Run in Release on an idle machine:
//   dotnet run -c Release --project benchmarks/Pondhawk.Waf.Benchmarks [scenario ...]
// Scenarios: startup, request, profiles, largebody, largearg, response, all (default: all).
// Diagnostics (not in all): alloc (allocation types per request), prefilter (which @rx get a prefilter),
// regexes (construction time per pattern), chains (transformation chains of ARGS rules).
// Wall times vary with machine load; CPU time and allocation are steadier. Server GC: DOTNET_gcServer=1.
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Pondhawk.Waf;
using Pondhawk.Waf.AspNetCore;

var scenarios = args.Length == 0 ? ["all"] : args;
bool Run(string name) => scenarios.Contains("all") || scenarios.Contains(name);

var formBody = Encoding.ASCII.GetBytes("username=alice&password=secret123&remember=on&comment=Hello+there%2C+this+is+a+normal+comment.");
var html = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("<div class=\"item\"><a href=\"/p/1\">Garden hose 25 m</a><span>19.99</span></div>\n", 130)));

if (scenarios.Contains("chains"))
{
    // Transformation chains of the rules that read ARGS in phase 2, by use count.
    var waf = Engine(WafProfile.Balanced, RuleEngineMode.On, warmUp: false);
    var chains = new Dictionary<string, int>();
    foreach (var rule in waf.Rules)
    {
        for (var r = rule; r is not null; r = r.Chain)
        {
            if (r.Phase == 2 && r.Variables.Any(v => v.Variable == Pondhawk.Waf.Collections.Variable.Args))
            {
                var key = string.Join(",", r.Transformations.Select(t => t.Name)) + (r.MultiMatch ? " [multiMatch]" : "");
                chains[key] = chains.GetValueOrDefault(key) + 1;
            }
        }
    }

    foreach (var (k, n) in chains.OrderByDescending(x => x.Value))
    {
        Console.WriteLine($"{n,4} {k}");
    }
}

if (scenarios.Contains("prefilter"))
{
    // Which @rx patterns get a prefilter, and what it requires.
    var waf = Engine(WafProfile.Paranoid, RuleEngineMode.On, warmUp: false);
    int total = 0, with = 0;
    foreach (var rule in waf.Rules)
    {
        for (var r = rule; r is not null; r = r.Chain)
        {
            if (r.Operator is Pondhawk.Waf.Operators.RxOperator rx)
            {
                total++;
                if (rx.Prefilter is { } p)
                {
                    with++;
                    Console.WriteLine($"{r.LogId,8} min {p.MinLength,3}  {string.Join(" AND ", p.Literals.Select(set => "[" + string.Join("|", set.Take(6)) + (set.Count > 6 ? $"|...{set.Count}" : "") + "]"))}");
                }
                else
                {
                    Console.WriteLine($"{r.LogId,8} none     {(r.OperatorData.Length > 80 ? r.OperatorData[..80] + "..." : r.OperatorData)}");
                }
            }
        }
    }

    Console.WriteLine($"{with} of {total} @rx operators have a prefilter");
}

if (scenarios.Contains("alloc"))
{
    // Allocation types sampled by the runtime (one event per ~100 KB allocated).
    var waf = Engine(WafProfile.Balanced, RuleEngineMode.On);
    for (var i = 0; i < 500; i++)
    {
        Request(waf, formBody, html);
    }

    using var listener = new AllocationListener();
    for (var i = 0; i < 3000; i++)
    {
        Request(waf, formBody, html);
    }

    foreach (var (type, bytes) in listener.Bytes.OrderByDescending(x => x.Value).Take(25))
    {
        Console.WriteLine($"{Size(bytes / 3000),10} per request  {type}");
    }
}

if (scenarios.Contains("regexes"))
{
    // Construction time of each CRS @rx pattern, serially, slowest first.
    var waf = Engine(WafProfile.Paranoid, RuleEngineMode.On, warmUp: false);
    var patterns = waf.Rules.SelectMany(r => { var l = new List<string>(); for (var x = r; x is not null; x = x.Chain) { if (x.Operator is Pondhawk.Waf.Operators.RxOperator) { l.Add(x.OperatorData); } } return l; }).Distinct().ToList();
    var times = new List<(double Ms, string Pattern)>();
    var total = Stopwatch.StartNew();
    foreach (var p in patterns)
    {
        var sw = Stopwatch.StartNew();
        new Pondhawk.Waf.Operators.RegexCache().Get(p);
        times.Add((sw.Elapsed.TotalMilliseconds, p));
    }

    Console.WriteLine($"{patterns.Count} patterns, serial {total.ElapsedMilliseconds} ms");
    foreach (var (ms, p) in times.OrderByDescending(t => t.Ms).Take(12))
    {
        Console.WriteLine($"{ms,8:F0} ms  {p.Length,6} chars  {(p.Length > 70 ? p[..70] : p)}");
    }

    var validate = Stopwatch.StartNew();
    foreach (var p in patterns)
    {
        _ = new System.Text.RegularExpressions.Regex(Pondhawk.Waf.Operators.RegexCache.TranslatePattern(p), System.Text.RegularExpressions.RegexOptions.Singleline | System.Text.RegularExpressions.RegexOptions.Multiline | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    }

    Console.WriteLine($"syntax check (interpreter construction) {validate.ElapsedMilliseconds} ms");
    var par = Stopwatch.StartNew();
    Parallel.ForEach(patterns, p => new Pondhawk.Waf.Operators.RegexCache().Get(p));
    Console.WriteLine($"parallel {par.ElapsedMilliseconds} ms");
}

if (Run("startup"))
{
    // The first build in a process pays JIT and static initialization; later builds show the steady cost of a reload.
    for (var i = 0; i < 3; i++)
    {
        var cpu = Process.GetCurrentProcess().TotalProcessorTime;
        var sw = Stopwatch.StartNew();
        var waf = Engine(WafProfile.Balanced, RuleEngineMode.On, warmUp: false);
        var load = sw.Elapsed.TotalMilliseconds;
        var loadCpu = (Process.GetCurrentProcess().TotalProcessorTime - cpu).TotalMilliseconds;
        waf.Compiled.Wait();
        var compiled = sw.Elapsed.TotalMilliseconds;
        sw.Restart();
        waf.WarmUp();
        var warm = sw.Elapsed.TotalMilliseconds;
        sw.Restart();
        Request(waf, formBody, html);
        Report($"startup #{i + 1}", $"usable {load,6:F0} ms (cpu {loadCpu,5:F0})   compiled {compiled,6:F0} ms   warm-up {warm,6:F0} ms   first request {sw.Elapsed.TotalMilliseconds,6:F1} ms   rules {waf.Rules.Count}");
    }
}

if (Run("request"))
{
    var waf = Engine(WafProfile.Balanced, RuleEngineMode.On);
    Measure("request form+html", 2000, 3000, () => Request(waf, formBody, html));
    Measure("request GET", 1000, 3000, () => Request(waf, null, null));
}

if (Run("profiles"))
{
    foreach (var profile in Enum.GetValues<WafProfile>())
    {
        var waf = Engine(profile, RuleEngineMode.On);
        Measure($"profile {profile}", 1000, 3000, () => Request(waf, formBody, html));
    }
}

if (Run("largebody"))
{
    // 1000 arguments (the default ArgumentsLimit) filling the 1 MiB RequestBodyNoFilesLimit with ordinary text.
    var waf = Engine(WafProfile.Balanced, RuleEngineMode.DetectionOnly);
    var sb = new StringBuilder();
    for (var i = 0; sb.Length < 1_040_000 && i < 1000; i++)
    {
        sb.Append(CultureInfo.InvariantCulture, $"{(i == 0 ? "" : "&")}field{i}=");
        for (var j = 0; sb.Length < (i + 1) * 1040; j++)
        {
            sb.Append(CultureInfo.InvariantCulture, $"The+quick+brown+fox+{i}+jumps+over+the+lazy+dog+{j}%2C+then+rests.+");
        }
    }

    var body = Encoding.ASCII.GetBytes(sb.ToString());
    Measure($"large body {body.Length / 1024} KiB, 1000 args", 2, 10, () => Request(waf, body, null));
}

if (Run("largearg"))
{
    // One argument at the 1 MiB limit.
    var waf = Engine(WafProfile.Balanced, RuleEngineMode.DetectionOnly);
    var sb = new StringBuilder("comment=");
    while (sb.Length < 1_048_000)
    {
        sb.Append("The+quick+brown+fox+jumps+over+the+lazy+dog%2C+then+rests+in+the+shade.+");
    }

    var body = Encoding.ASCII.GetBytes(sb.ToString());
    Measure($"large arg {body.Length / 1024} KiB", 2, 10, () => Request(waf, body, null));
}

if (Run("response"))
{
    // A 512 KiB HTML response (the Balanced ResponseBodyLimit) through the middleware.
    var page = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("<div class=\"item\"><a href=\"/p/1\">Garden hose 25 m</a><span>19.99</span></div>\n", 7000)))[..524_288];
    foreach (var mode in new[] { RuleEngineMode.On, RuleEngineMode.DetectionOnly })
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureLogging(l => l.ClearProviders())
                .ConfigureServices(s => s.AddPondhawkWaf(o =>
                {
                    o.Profile = WafProfile.Balanced;
                    o.RuleEngine = mode;
                }))
                .Configure(app =>
                {
                    app.UsePondhawkWaf();
                    app.Run(async ctx =>
                    {
                        ctx.Response.ContentType = "text/html; charset=utf-8";
                        for (var i = 0; i < page.Length; i += 16384)
                        {
                            await ctx.Response.Body.WriteAsync(page.AsMemory(i, Math.Min(16384, page.Length - i)));
                        }
                    });
                }))
            .StartAsync();
        var client = host.GetTestClient();
        await MeasureAsync($"response 512 KiB {mode}", 5, 40, async () =>
        {
            using var response = await client.GetAsync("/");
            if (response.StatusCode != HttpStatusCode.OK || (await response.Content.ReadAsByteArrayAsync()).Length != page.Length)
            {
                throw new InvalidOperationException("Unexpected response");
            }
        });
        await host.StopAsync();
    }
}

// Builds an engine and, unless asked not to, waits for its regexes and warms it up (CreateEngine does that in the background).
static WafEngine Engine(WafProfile profile, RuleEngineMode mode, bool warmUp = true)
{
    var waf = WafServiceCollectionExtensions.CreateEngine(new WafOptions { Profile = profile, RuleEngine = mode, WarmUp = false }, NullLoggerFactory.Instance);
    if (warmUp)
    {
        waf.WarmUp();
    }

    return waf;
}

static void Request(WafEngine waf, byte[]? body, byte[]? responseBody)
{
    using var tx = waf.NewTransaction();
    tx.ProcessConnection("10.0.0.1", 5555, "10.0.0.2", 443);
    tx.ProcessUri(body is null ? "/catalog/items?page=2&sort=price&q=garden+hose" : "/api/login?next=%2Fhome&lang=en", body is null ? "GET" : "POST", "HTTP/1.1");
    tx.AddRequestHeader("Host", "app.example.com");
    tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36");
    tx.AddRequestHeader("Accept", "text/html,application/xhtml+xml");
    tx.AddRequestHeader("Accept-Language", "en-US,en;q=0.9");
    tx.AddRequestHeader("Cookie", "session=abc123; theme=dark");
    if (body is not null)
    {
        tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        tx.AddRequestHeader("Content-Length", body.Length.ToString(CultureInfo.InvariantCulture));
    }

    tx.ProcessRequestHeaders();
    if (body is not null)
    {
        tx.WriteRequestBody(body);
    }

    tx.ProcessRequestBody();
    tx.AddResponseHeader("Content-Type", "text/html; charset=utf-8");
    tx.ProcessResponseHeaders(200, "HTTP/1.1");
    if (responseBody is not null)
    {
        tx.WriteResponseBody(responseBody);
    }

    tx.ProcessResponseBody();
    tx.ProcessLogging();
    if (tx.Interruption is not null)
    {
        throw new InvalidOperationException($"Blocked by {tx.Interruption.RuleId}");
    }
}

static void Measure(string name, int warmup, int n, Action action)
{
    for (var i = 0; i < warmup; i++)
    {
        action();
    }

    GC.Collect();
    var alloc = GC.GetTotalAllocatedBytes(precise: true);
    var cpu = Process.GetCurrentProcess().TotalProcessorTime;
    var sw = Stopwatch.StartNew();
    for (var i = 0; i < n; i++)
    {
        action();
    }

    var elapsed = sw.Elapsed;
    var cpuUsed = Process.GetCurrentProcess().TotalProcessorTime - cpu;
    var bytes = (GC.GetTotalAllocatedBytes(precise: true) - alloc) / n;
    Report(name, $"{Time(elapsed / n),10}   cpu {Time(cpuUsed / n),10}   alloc {Size(bytes),10}");
}

static async Task MeasureAsync(string name, int warmup, int n, Func<Task> action)
{
    for (var i = 0; i < warmup; i++)
    {
        await action();
    }

    GC.Collect();
    var alloc = GC.GetTotalAllocatedBytes(precise: true);
    var sw = Stopwatch.StartNew();
    for (var i = 0; i < n; i++)
    {
        await action();
    }

    var elapsed = sw.Elapsed;
    var bytes = (GC.GetTotalAllocatedBytes(precise: true) - alloc) / n;
    Report(name, $"{Time(elapsed / n),10}   alloc {Size(bytes),10}");
}

static string Time(TimeSpan t) => t.TotalMilliseconds >= 10 ? $"{t.TotalMilliseconds:F0} ms" : $"{t.TotalMicroseconds:F0} us";

static string Size(long b) => b >= 1 << 20 ? $"{b / 1048576.0:F1} MiB" : $"{b / 1024.0:F1} KiB";

static void Report(string name, string value) => Console.WriteLine($"{name,-36} {value}");

internal sealed class AllocationListener : System.Diagnostics.Tracing.EventListener
{
    public Dictionary<string, long> Bytes { get; } = [];

    protected override void OnEventSourceCreated(System.Diagnostics.Tracing.EventSource source)
    {
        if (source.Name == "Microsoft-Windows-DotNETRuntime")
        {
            EnableEvents(source, System.Diagnostics.Tracing.EventLevel.Verbose, (System.Diagnostics.Tracing.EventKeywords)0x1);
        }
    }

    protected override void OnEventWritten(System.Diagnostics.Tracing.EventWrittenEventArgs e)
    {
        if (e.EventName?.StartsWith("GCAllocationTick", StringComparison.Ordinal) == true && e.Payload is { } payload)
        {
            var type = payload[e.PayloadNames!.IndexOf("TypeName")]?.ToString() ?? "?";
            var amount = Convert.ToInt64(payload[e.PayloadNames.IndexOf("AllocationAmount64")], CultureInfo.InvariantCulture);
            lock (Bytes)
            {
                Bytes[type] = Bytes.GetValueOrDefault(type) + amount;
            }
        }
    }
}
