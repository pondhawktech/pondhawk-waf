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
/// Phase 3 inspects the response headers when the response starts. A held response has not reached the server yet,
/// so the WAF must make it behave as started: headers from OnStarting callbacks are inspected, later header changes
/// fail as they would on a started response, and an error page written after an exception cannot replace it (#19, #20).
/// </summary>
public sealed class ResponseStartTests : IAsyncLifetime
{
    private const string ErrorPage = "Unhandled exception: connection string Server=db;Password=hunter2";

    private IHost _host = null!;
    private HttpClient _client = null!;
    private volatile string _lateHeaderResult = string.Empty;

    public async Task InitializeAsync()
    {
        _host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(s => s.AddPondhawkWaf(o =>
                {
                    o.RuleEngine = RuleEngineMode.On;
                    o.WarmUp = false;
                    o.DirectivesAfterRules = """
                        SecRule RESPONSE_HEADERS:X-Debug-Token "@rx ." "id:10100,phase:3,deny,status:502,log,msg:'Debug token leaked'"
                        """;
                }))
                .Configure(app =>
                {
                    // An exception handler outside the WAF, as the README recommends.
                    app.Use(async (ctx, next) =>
                    {
                        try
                        {
                            await next(ctx);
                        }
                        catch (InvalidOperationException) when (!ctx.Response.HasStarted)
                        {
                            ctx.Response.Clear();
                            ctx.Response.StatusCode = 500;
                            await ctx.Response.WriteAsync(ErrorPage);
                        }
                    });
                    app.UsePondhawkWaf();
                    app.Run(HandleAsync);
                }))
            .StartAsync();
        _client = _host.GetTestClient();
        _client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (X11; Linux x86_64)");
        _client.DefaultRequestHeaders.Accept.ParseAdd("*/*");
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }

    [Theory]
    [InlineData("/on-starting")]
    [InlineData("/on-starting-empty")]
    public async Task HeadersAddedInOnStartingAreInspected(string path)
    {
        var response = await _client.GetAsync(path);
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.False(response.Headers.Contains("X-Debug-Token"));
    }

    [Fact]
    public async Task OnStartingCallbacksRunOnceInReverseOrder()
    {
        var response = await _client.GetAsync("/on-starting-order");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("second,first", response.Headers.GetValues("X-Order").Single());
        Assert.Equal("ok", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task HeadersCannotChangeAfterThePhase3Inspection()
    {
        var response = await _client.GetAsync("/late-header");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains("X-Debug-Token"));
        Assert.Equal("threw", _lateHeaderResult);
        Assert.Equal("body", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ErrorPageCannotReplaceAHeldResponse()
    {
        // As on a server without the WAF, a response that started and then failed is aborted, not replaced.
        var ex = await Assert.ThrowsAsync<OperationCanceledException>(() => _client.GetAsync("/throw-after-write"));
        Assert.DoesNotContain("hunter2", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ErrorPageStillWorksWhenTheApplicationWroteNothing()
    {
        var response = await _client.GetAsync("/throw-before-write");
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
    }

    private async Task HandleAsync(HttpContext ctx)
    {
        ctx.Response.ContentType = "text/html";
        switch (ctx.Request.Path.Value)
        {
            case "/on-starting":
                ctx.Response.OnStarting(() =>
                {
                    ctx.Response.Headers["X-Debug-Token"] = "abc123";
                    return Task.CompletedTask;
                });
                await ctx.Response.WriteAsync("<html>hello</html>");
                break;
            case "/on-starting-empty":
                ctx.Response.OnStarting(() =>
                {
                    ctx.Response.Headers["X-Debug-Token"] = "abc123";
                    return Task.CompletedTask;
                });
                break;
            case "/on-starting-order":
                ctx.Response.OnStarting(() =>
                {
                    ctx.Response.Headers["X-Order"] += "first";
                    return Task.CompletedTask;
                });
                ctx.Response.OnStarting(() =>
                {
                    ctx.Response.Headers["X-Order"] = "second,";
                    return Task.CompletedTask;
                });
                await ctx.Response.WriteAsync("ok");
                break;
            case "/late-header":
                await ctx.Response.WriteAsync("body");
                try
                {
                    ctx.Response.Headers["X-Debug-Token"] = "abc123";
                    _lateHeaderResult = "set";
                }
                catch (InvalidOperationException)
                {
                    _lateHeaderResult = "threw";
                }

                break;
            case "/throw-after-write":
                await ctx.Response.WriteAsync("<html>partial");
                throw new InvalidOperationException("boom");
            case "/throw-before-write":
                throw new InvalidOperationException("boom");
        }
    }
}
