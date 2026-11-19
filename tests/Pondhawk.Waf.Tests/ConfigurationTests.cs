using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Pondhawk.Waf.AspNetCore;
using Pondhawk.Waf.CoreRuleSet;

namespace Pondhawk.Waf.Tests;

public class ConfigurationTests
{
    // Without CRS the engine builds in milliseconds; one custom rule shows which configuration is in force.
    private static Dictionary<string, string?> Settings(string blocked, string ruleEngine = "On") => new()
    {
        ["Pondhawk:Waf:UseCoreRuleSet"] = "false",
        ["Pondhawk:Waf:WarmUp"] = "false",
        ["Pondhawk:Waf:RuleEngine"] = ruleEngine,
        ["Pondhawk:Waf:Directives"] = $"SecRule ARGS \"@contains {blocked}\" \"id:1,phase:1,deny,status:403\"",
    };

    [Fact]
    public void BindsEveryOption()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Pondhawk:Waf:RuleEngine"] = "On",
            ["Pondhawk:Waf:Profile"] = "Strict",
            ["Pondhawk:Waf:ParanoiaLevel"] = "3",
            ["Pondhawk:Waf:InboundAnomalyScoreThreshold"] = "10",
            ["Pondhawk:Waf:InspectResponses"] = "false",
            ["Pondhawk:Waf:ResponseMimeTypes:0"] = "text/html",
            ["Pondhawk:Waf:ResponseMimeTypes:1"] = "application/json",
            ["Pondhawk:Waf:RequestBodyLimit"] = "1048576",
            ["Pondhawk:Waf:RequestBodyNoFilesLimit"] = "65536",
            ["Pondhawk:Waf:ArgumentsLimit"] = "300",
            ["Pondhawk:Waf:Plugins:0"] = "WordPress",
            ["Pondhawk:Waf:Plugins:1"] = "nextcloud",
            ["Pondhawk:Waf:Exclusions:0:Rule"] = "942100",
            ["Pondhawk:Waf:Exclusions:0:Target"] = "ARGS:password",
            ["Pondhawk:Waf:Exclusions:0:Path"] = "/login",
            ["Pondhawk:Waf:Exclusions:1:Tag"] = "attack-xss",
            ["Pondhawk:Waf:Exclusions:1:Path"] = "/cms/editor",
            ["Pondhawk:Waf:RuleFiles:0"] = "rules/custom.conf",
            ["Pondhawk:Waf:DirectivesAfterRules"] = "SecRuleRemoveById 920350",
            ["Pondhawk:Waf:ReloadOnChange"] = "false",
        }).Build();
        var services = new ServiceCollection().AddPondhawkWaf(config.GetSection("Pondhawk:Waf"), o => o.Bypass = _ => false);
        var o = services.BuildServiceProvider().GetRequiredService<IOptions<WafOptions>>().Value;

        Assert.Equal(RuleEngineMode.On, o.RuleEngine);
        Assert.Equal(WafProfile.Strict, o.Profile);
        Assert.Equal(3, o.ParanoiaLevel);
        Assert.Equal(10, o.InboundAnomalyScoreThreshold);
        Assert.False(o.InspectResponses);
        Assert.Equal(["text/html", "application/json"], o.ResponseMimeTypes);
        Assert.Equal(1048576, o.RequestBodyLimit);
        Assert.Equal(65536, o.RequestBodyNoFilesLimit);
        Assert.Equal(300, o.ArgumentsLimit);
        Assert.Equal([CrsPlugin.WordPress, CrsPlugin.Nextcloud], o.Plugins);
        Assert.Equal(2, o.Exclusions.Count);
        Assert.Equal(("942100", "ARGS:password", "/login"), (o.Exclusions[0].Rule, o.Exclusions[0].Target, o.Exclusions[0].Path));
        Assert.Equal(("attack-xss", "/cms/editor"), (o.Exclusions[1].Tag, o.Exclusions[1].Path));
        Assert.Equal(["rules/custom.conf"], o.RuleFiles);
        Assert.Equal("SecRuleRemoveById 920350", o.DirectivesAfterRules);
        Assert.False(o.ReloadOnChange);
        Assert.NotNull(o.Bypass);
    }

    [Fact]
    public async Task ReloadSwapsTheEngine()
    {
        var source = Settings("first");
        var (config, provider) = Build(source);
        using var _ = provider;
        var reloaded = Next(provider);

        Assert.True(Blocked(provider.Current, "first"));
        Assert.False(Blocked(provider.Current, "second"));

        source["Pondhawk:Waf:Directives"] = Settings("second")["Pondhawk:Waf:Directives"];
        Reload(config, source);
        var snapshot = await reloaded.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(1, snapshot.Generation);
        Assert.Same(snapshot.Engine, provider.Current);
        Assert.False(Blocked(provider.Current, "first"));
        Assert.True(Blocked(provider.Current, "second"));
    }

    [Fact]
    public async Task InvalidConfigurationKeepsTheCurrentEngine()
    {
        var source = Settings("first");
        var (config, provider) = Build(source);
        using var _ = provider;
        var original = provider.Current;
        var failed = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
        provider.ReloadFailed += (_, ex) => failed.TrySetResult(ex);

        source["Pondhawk:Waf:ParanoiaLevel"] = "9";
        Reload(config, source);
        await failed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Same(original, provider.Current);
        Assert.True(Blocked(provider.Current, "first"));

        source.Remove("Pondhawk:Waf:ParanoiaLevel");
        source["Pondhawk:Waf:Profile"] = "Bogus";
        failed = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
        Reload(config, source);
        await failed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Same(original, provider.Current);

        source.Remove("Pondhawk:Waf:Profile");
        source["Pondhawk:Waf:Directives"] = "SecRule ARGS \"@bogus\" \"id:1\"";
        failed = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
        Reload(config, source);
        await failed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Same(original, provider.Current);

        // A valid configuration after failures still loads.
        var reloaded = Next(provider);
        source["Pondhawk:Waf:Directives"] = Settings("third")["Pondhawk:Waf:Directives"];
        Reload(config, source);
        await reloaded.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(Blocked(provider.Current, "third"));
    }

    [Fact]
    public async Task ABurstOfChangesBuildsOnce()
    {
        var source = Settings("first");
        var (config, provider) = Build(source);
        using var _ = provider;
        var builds = 0;
        provider.Reloaded += (_, _) => Interlocked.Increment(ref builds);
        var reloaded = Next(provider);
        for (var i = 0; i < 5; i++)
        {
            source["Pondhawk:Waf:Directives"] = Settings("burst" + i)["Pondhawk:Waf:Directives"];
            Reload(config, source);
        }

        await reloaded.WaitAsync(TimeSpan.FromSeconds(10));
        await Task.Delay(500);
        Assert.Equal(1, builds);
        Assert.True(Blocked(provider.Current, "burst4"));
    }

    [Fact]
    public async Task ReloadOnChangeOffKeepsTheEngine()
    {
        var source = Settings("first");
        source["Pondhawk:Waf:ReloadOnChange"] = "false";
        var (config, provider) = Build(source);
        using var _ = provider;
        var original = provider.Current;
        source["Pondhawk:Waf:Directives"] = Settings("second")["Pondhawk:Waf:Directives"];
        Reload(config, source);
        await Task.Delay(500);
        Assert.Same(original, provider.Current);
    }

    [Fact]
    public async Task MiddlewareUsesTheNewEngineAndInFlightRequestsFinishOnTheOld()
    {
        var source = Settings("first");
        var config = new ConfigurationBuilder().AddInMemoryCollection(source).Build();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        WafEngine? inFlightEngine = null;
        using var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(s => s.AddPondhawkWaf(config.GetSection("Pondhawk:Waf")))
                .Configure(app =>
                {
                    app.ApplicationServices.GetRequiredService<WafEngineProvider>().ReloadDelay = TimeSpan.FromMilliseconds(10);
                    app.UsePondhawkWaf();
                    app.Run(async ctx =>
                    {
                        if (ctx.Request.Path == "/slow")
                        {
                            inFlightEngine = ((Transaction)ctx.Items[WafMiddleware.TransactionKey]!).Waf;
                            started.SetResult();
                            await release.Task;
                        }

                        await ctx.Response.WriteAsync("ok");
                    });
                }))
            .StartAsync();
        var client = host.GetTestClient();
        var provider = host.Services.GetRequiredService<WafEngineProvider>();
        var original = provider.Current;

        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/?q=first")).StatusCode);
        var slow = client.GetAsync("/slow");
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10));

        var reloaded = Next(provider);
        source["Pondhawk:Waf:Directives"] = Settings("second")["Pondhawk:Waf:Directives"];
        Reload(config, source);
        await reloaded.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/?q=first")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/?q=second")).StatusCode);
        Assert.Same(provider.Current, host.Services.GetRequiredService<WafEngine>());

        release.SetResult();
        Assert.Equal(HttpStatusCode.OK, (await slow).StatusCode);
        Assert.Same(original, inFlightEngine);
        await host.StopAsync();
    }

    private static (IConfigurationRoot Config, WafEngineProvider Provider) Build(Dictionary<string, string?> source)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(source).Build();
        var sp = new ServiceCollection().AddLogging().AddPondhawkWaf(config.GetSection("Pondhawk:Waf")).BuildServiceProvider();
        var provider = sp.GetRequiredService<WafEngineProvider>();
        provider.ReloadDelay = TimeSpan.FromMilliseconds(50);
        return (config, provider);
    }

    // Replaces the in-memory values and signals a change, as a file provider does when appsettings.json is saved.
    private static void Reload(IConfigurationRoot config, Dictionary<string, string?> source)
    {
        var memory = config.Providers.OfType<Microsoft.Extensions.Configuration.Memory.MemoryConfigurationProvider>().Single();
        foreach (var key in memory.GetChildKeys([], "Pondhawk:Waf").Distinct().ToList())
        {
            memory.Set("Pondhawk:Waf:" + key, null);
        }

        foreach (var (k, v) in source)
        {
            memory.Set(k, v);
        }

        config.Reload();
    }

    private static Task<WafSnapshot> Next(WafEngineProvider provider)
    {
        var tcs = new TaskCompletionSource<WafSnapshot>(TaskCreationOptions.RunContinuationsAsynchronously);
        provider.Reloaded += (_, s) => tcs.TrySetResult(s);
        return tcs.Task;
    }

    private static bool Blocked(WafEngine waf, string value)
    {
        using var tx = waf.NewTransaction();
        tx.ProcessUri("/?q=" + value, "GET", "HTTP/1.1");
        return tx.ProcessRequestHeaders() is not null;
    }
}
