using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Pondhawk.Waf.AspNetCore;

namespace Pondhawk.Waf.Tests;

/// <summary>
/// Middleware outside the WAF (a security headers middleware, for example) registers OnStarting callbacks on the
/// server's response feature. When the server starts the response they must change the real headers, not the WAF's
/// read-only copy (#30).
/// </summary>
public sealed class OuterOnStartingTests
{
    [Theory]
    [InlineData(RuleEngineMode.On, false, "/held")]
    [InlineData(RuleEngineMode.On, false, "/not-held")]
    [InlineData(RuleEngineMode.On, false, "/empty")]
    [InlineData(RuleEngineMode.DetectionOnly, false, "/held")]
    [InlineData(RuleEngineMode.DetectionOnly, false, "/not-held")]
    [InlineData(RuleEngineMode.DetectionOnly, true, "/held")]
    [InlineData(RuleEngineMode.Off, false, "/held")]
    public async Task OuterCallbacksSetHeadersOnAPassedResponse(RuleEngineMode mode, bool hold, string path)
    {
        using var host = await StartAsync(mode, hold);
        using var response = await host.GetTestClient().GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("1", response.Headers.GetValues("X-Outer").Single());
        Assert.Equal("1", response.Headers.GetValues("X-Inner").Single());
        await host.StopAsync();
    }

    [Theory]
    [InlineData("/held?attack=1")]
    [InlineData("/leak")]
    public async Task OuterCallbacksSetHeadersOnABlockedResponse(string path)
    {
        using var host = await StartAsync(RuleEngineMode.On, hold: false);
        using var response = await host.GetTestClient().GetAsync(path);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("1", response.Headers.GetValues("X-Outer").Single());
        Assert.False(response.Headers.Contains("X-Inner"));
        await host.StopAsync();
    }

    [Fact]
    public async Task InnerHeadersStillCannotChangeAfterPhase3()
    {
        // The fix must not reopen the headers to the application (#20): only callbacks the server runs may change them.
        using var host = await StartAsync(RuleEngineMode.On, hold: false);
        using var response = await host.GetTestClient().GetAsync("/late-header");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("threw", response.Headers.GetValues("X-Outer-Saw").Single());
        Assert.False(response.Headers.Contains("X-Late"));
        await host.StopAsync();
    }

    private static async Task<IHost> StartAsync(RuleEngineMode mode, bool hold) =>
        await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(s => s.AddPondhawkWaf(o =>
                {
                    o.RuleEngine = mode;
                    o.WarmUp = false;
                    o.HoldResponsesInDetectionOnly = hold;
                    o.UseCoreRuleSet = false;
                    o.DirectivesAfterRules = """
                        SecRule ARGS:attack "@streq 1" "id:10200,phase:1,deny,status:403,log"
                        SecRule RESPONSE_HEADERS:X-Leak "@rx ." "id:10201,phase:3,deny,status:403,log"
                        """;
                }))
                .Configure(app =>
                {
                    // Outer middleware, as UseSecurityHeaders(): registers on the server's feature before the WAF runs.
                    app.Use(async (ctx, next) =>
                    {
                        ctx.Response.OnStarting(() =>
                        {
                            ctx.Response.Headers["X-Outer"] = "1";
                            if (ctx.Items["late"] is string late)
                            {
                                ctx.Response.Headers["X-Outer-Saw"] = late;
                            }

                            return Task.CompletedTask;
                        });
                        await next(ctx);
                    });
                    app.UsePondhawkWaf();
                    app.Run(HandleAsync);
                }))
            .StartAsync();

    private static async Task HandleAsync(HttpContext ctx)
    {
        ctx.Response.Headers["X-Inner"] = "1";
        switch (ctx.Request.Path.Value)
        {
            case "/held":
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync("{\"ok\":true}");
                break;
            case "/not-held":
                ctx.Response.ContentType = "image/png";
                await ctx.Response.Body.WriteAsync(new byte[] { 0x89, 0x50, 0x4e, 0x47 });
                break;
            case "/empty":
                break;
            case "/leak":
                ctx.Response.Headers["X-Leak"] = "1";
                await ctx.Response.WriteAsync("secret");
                break;
            case "/late-header":
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync("{}");
                try
                {
                    ctx.Response.Headers["X-Late"] = "1";
                    ctx.Items["late"] = "set";
                }
                catch (InvalidOperationException)
                {
                    // The outer callback reports it in a header.
                    ctx.Items["late"] = "threw";
                }

                break;
        }
    }
}
