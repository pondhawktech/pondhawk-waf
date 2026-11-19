using System.Diagnostics.Metrics;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.Metrics.Testing;
using Microsoft.Extensions.Hosting;
using Pondhawk.Waf.AspNetCore;

namespace Pondhawk.Waf.Tests;

public class MetricsTests
{
    private const string Rules = """
        SecRule ARGS "@contains attack" "id:1,phase:1,deny,status:403,log"
        SecRule ARGS "@contains watch" "id:2,phase:1,pass,log"
        SecRule ARGS "@contains quiet" "id:3,phase:1,pass,nolog"
        """;

    private static async Task<IHost> StartAsync(RuleEngineMode mode, Action<WafOptions>? configure = null) =>
        await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(s => s.AddPondhawkWaf(o =>
                {
                    o.UseCoreRuleSet = false;
                    o.WarmUp = false;
                    o.RuleEngine = mode;
                    o.Directives = Rules;
                    o.Bypass = ctx => ctx.Request.Path == "/health";
                    configure?.Invoke(o);
                }))
                .Configure(app =>
                {
                    app.UsePondhawkWaf();
                    app.Run(ctx => ctx.Response.WriteAsync("ok"));
                }))
            .StartAsync();

    private static MetricCollector<T> Collect<T>(IHost host, string instrument)
        where T : struct =>
        new(host.Services.GetRequiredService<IMeterFactory>(), WafMetrics.MeterName, instrument);

    private static Dictionary<string, long> ByTag(MetricCollector<long> collector, string tag) =>
        collector.GetMeasurementSnapshot()
            .GroupBy(m => m.Tags.TryGetValue(tag, out var v) ? v?.ToString() ?? string.Empty : string.Empty)
            .ToDictionary(g => g.Key, g => g.Sum(m => m.Value));

    [Fact]
    public async Task CountsRequestsBlocksAndMatches()
    {
        using var host = await StartAsync(RuleEngineMode.On);
        using var requests = Collect<long>(host, "pondhawk.waf.requests");
        using var blocks = Collect<long>(host, "pondhawk.waf.blocks");
        using var matches = Collect<long>(host, "pondhawk.waf.rule.matches");
        using var durations = Collect<double>(host, "pondhawk.waf.phase.duration");
        var client = host.GetTestClient();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/?q=fine")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/?q=watch")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/?q=quiet")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/?q=attack")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health?q=attack")).StatusCode);

        Assert.Equal(new Dictionary<string, long> { ["allowed"] = 3, ["blocked"] = 1, ["bypassed"] = 1 }, ByTag(requests, "waf.result"));

        var block = Assert.Single(blocks.GetMeasurementSnapshot());
        Assert.Equal(1, block.Value);
        Assert.Equal(1, block.Tags["waf.rule.id"]);
        Assert.Equal("deny", block.Tags["waf.action"]);
        Assert.Equal(403, block.Tags["http.response.status_code"]);

        // Only rules that log are counted (rule 3 is nolog).
        Assert.Equal(new Dictionary<string, long> { ["1"] = 1, ["2"] = 1 }, ByTag(matches, "waf.rule.id"));

        var phases = durations.GetMeasurementSnapshot().Select(m => m.Tags["waf.phase"]?.ToString()).ToHashSet();
        Assert.Contains("request_headers", phases);
        Assert.Contains("request_body", phases);
        Assert.Contains("response_headers", phases);
        Assert.Contains("logging", phases);
        Assert.All(durations.GetMeasurementSnapshot(), m => Assert.InRange(m.Value, 0, 5));
        await host.StopAsync();
    }

    [Fact]
    public async Task DetectionOnlyCountsWouldBlock()
    {
        using var host = await StartAsync(RuleEngineMode.DetectionOnly);
        using var requests = Collect<long>(host, "pondhawk.waf.requests");
        using var blocks = Collect<long>(host, "pondhawk.waf.blocks");
        using var wouldBlock = Collect<long>(host, "pondhawk.waf.would_block");
        var client = host.GetTestClient();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/?q=attack")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/?q=fine")).StatusCode);

        Assert.Equal(new Dictionary<string, long> { ["detected"] = 1, ["allowed"] = 1 }, ByTag(requests, "waf.result"));
        Assert.Empty(blocks.GetMeasurementSnapshot());
        var would = Assert.Single(wouldBlock.GetMeasurementSnapshot());
        Assert.Equal(1, would.Tags["waf.rule.id"]);
        await host.StopAsync();
    }

    [Fact]
    public async Task RuleEngineOffIsCounted()
    {
        using var host = await StartAsync(RuleEngineMode.Off);
        using var requests = Collect<long>(host, "pondhawk.waf.requests");
        await host.GetTestClient().GetAsync("/?q=attack");
        Assert.Equal(new Dictionary<string, long> { ["off"] = 1 }, ByTag(requests, "waf.result"));
        await host.StopAsync();
    }

    [Fact]
    public async Task CountsLogFailures()
    {
        using var host = await StartAsync(RuleEngineMode.On, o => o.Configure = b =>
        {
            b.Config.ErrorCallback = _ => throw new InvalidOperationException("sink down");
            b.Config.AuditLogWriter = new ThrowingAuditWriter();
        });
        using var failures = Collect<long>(host, "pondhawk.waf.log_failures");
        var response = await host.GetTestClient().GetAsync("/?q=watch");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // One for the rule log (rule 2), one for the audit log entry of the transaction.
        Assert.Equal(2, failures.GetMeasurementSnapshot().Sum(m => m.Value));
        await host.StopAsync();
    }

    [Fact]
    public async Task CountsReloads()
    {
        var source = new Dictionary<string, string?>
        {
            ["Waf:UseCoreRuleSet"] = "false",
            ["Waf:WarmUp"] = "false",
            ["Waf:Directives"] = Rules,
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(source).Build();
        using var sp = new ServiceCollection().AddLogging().AddPondhawkWaf(config.GetSection("Waf")).BuildServiceProvider();
        var provider = sp.GetRequiredService<WafEngineProvider>();
        provider.ReloadDelay = TimeSpan.FromMilliseconds(10);
        using var reloads = new MetricCollector<long>(sp.GetRequiredService<IMeterFactory>(), WafMetrics.MeterName, "pondhawk.waf.reloads");

        var failed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        provider.ReloadFailed += (_, _) => failed.TrySetResult();
        config["Waf:Directives"] = "SecRule ARGS \"@bogus\" \"id:1\"";
        config.Reload();
        await failed.Task.WaitAsync(TimeSpan.FromSeconds(10));

        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        provider.Reloaded += (_, _) => done.TrySetResult();
        config["Waf:Directives"] = Rules;
        config.Reload();
        await done.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(new Dictionary<string, long> { ["failure"] = 1, ["success"] = 1 }, ByTag(reloads, "waf.result"));
    }

    private sealed class ThrowingAuditWriter : AuditLog.IAuditLogWriter
    {
        public void Write(AuditLog.AuditLogEntry entry) => throw new IOException("disk full");
    }
}
