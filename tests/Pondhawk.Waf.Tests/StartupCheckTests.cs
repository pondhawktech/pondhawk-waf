using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Pondhawk.Waf.AspNetCore;

namespace Pondhawk.Waf.Tests;

/// <summary>#18: registering the WAF services without the middleware leaves the app unprotected; startup warns.</summary>
public sealed class StartupCheckTests
{
    private const string Warning = "Pondhawk WAF services are registered but the middleware is not";

    [Fact]
    public async Task Warns_when_services_are_registered_without_the_middleware()
    {
        var logs = await StartAsync(app => app.Run(ctx => ctx.Response.WriteAsync("ok")));

        Assert.Contains(logs.Messages("Pondhawk.Waf"), m => m.StartsWith(Warning, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Does_not_warn_when_the_middleware_is_added()
    {
        var logs = await StartAsync(app =>
        {
            app.UsePondhawkWaf();
            app.Run(ctx => ctx.Response.WriteAsync("ok"));
        });

        Assert.DoesNotContain(logs.Messages("Pondhawk.Waf"), m => m.StartsWith(Warning, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Does_not_warn_when_the_middleware_is_added_in_a_branch()
    {
        var logs = await StartAsync(app =>
        {
            app.Map("/api", api =>
            {
                api.UsePondhawkWaf();
                api.Run(ctx => ctx.Response.WriteAsync("ok"));
            });
            app.Run(ctx => ctx.Response.WriteAsync("ok"));
        });

        Assert.DoesNotContain(logs.Messages("Pondhawk.Waf"), m => m.StartsWith(Warning, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Registering_twice_warns_once()
    {
        var logs = await StartAsync(
            app => app.Run(ctx => ctx.Response.WriteAsync("ok")),
            services => services.AddPondhawkWaf(o => o.WarmUp = false));

        Assert.Single(logs.Messages("Pondhawk.Waf"), m => m.StartsWith(Warning, StringComparison.Ordinal));
    }

    private static async Task<CapturingLoggerProvider> StartAsync(Action<IApplicationBuilder> configure, Action<IServiceCollection>? more = null)
    {
        var logs = new CapturingLoggerProvider();
        using var host = await new HostBuilder()
            .ConfigureLogging(l => l.ClearProviders().AddProvider(logs).SetMinimumLevel(LogLevel.Information))
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(s =>
                {
                    s.AddPondhawkWaf(o => o.WarmUp = false);
                    more?.Invoke(s);
                })
                .Configure(configure))
            .StartAsync();
        await host.StopAsync();
        return logs;
    }
}
