using System.Net;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Pondhawk.Waf.AspNetCore;

namespace Pondhawk.Waf.Tests;

/// <summary>End-to-end tests of the middleware with the embedded CRS (SecRuleEngine On, paranoia level 1).</summary>
public sealed class MiddlewareTests : IAsyncLifetime
{
    private IHost _host = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(s => s.AddPondhawkWaf(o =>
                {
                    o.RuleEngine = RuleEngineMode.On;
                    o.Bypass = ctx => ctx.Request.Path == "/health";
                    o.DirectivesAfterRules = "SecRequestBodyLimit 65536";
                }))
                .Configure(app =>
                {
                    app.UsePondhawkWaf();
                    app.Run(async ctx =>
                    {
                        using var reader = new StreamReader(ctx.Request.Body);
                        var body = await reader.ReadToEndAsync();
                        await ctx.Response.WriteAsync("echo:" + body);
                    });
                }))
            .StartAsync();
        _client = _host.GetTestClient();
        _client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (X11; Linux x86_64)");
        _client.DefaultRequestHeaders.Accept.ParseAdd("text/html");
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }

    [Fact]
    public async Task CleanRequestPassesAndAppCanReadTheBody()
    {
        var response = await _client.PostAsync("/comments", Form("name=Alice&comment=Nice+article%2C+thanks%21"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("echo:name=Alice&comment=Nice+article%2C+thanks%21", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("/search?q=1%27%20OR%20%271%27%3D%271")]
    [InlineData("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")]
    [InlineData("/download?file=..%2F..%2F..%2Fetc%2Fpasswd")]
    [InlineData("/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd")]
    public async Task AttacksInTheQueryAreBlocked(string uri)
    {
        var response = await _client.GetAsync(uri);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task SqlInjectionInJsonBodyIsBlocked()
    {
        var content = new StringContent("""{"user":{"name":"x' UNION SELECT password FROM users--"}}""", Encoding.UTF8, "application/json");
        var response = await _client.PostAsync("/api/users", content);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task MalformedJsonIsRejected()
    {
        var content = new StringContent("""{"name": "x""", Encoding.UTF8, "application/json");
        var response = await _client.PostAsync("/api/users", content);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task OversizedBodyIsRejectedWith413()
    {
        var response = await _client.PostAsync("/upload", Form("data=" + new string('a', 70_000)));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task BypassSkipsTheWaf()
    {
        var response = await _client.GetAsync("/health?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static StringContent Form(string body) =>
        new(body, Encoding.UTF8, "application/x-www-form-urlencoded");
}
