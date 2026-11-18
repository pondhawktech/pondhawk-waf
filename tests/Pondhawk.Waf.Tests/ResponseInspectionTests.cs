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

/// <summary>Response phases 3-4 with the embedded CRS and SecRuleEngine On.</summary>
public sealed class ResponseInspectionTests : IAsyncLifetime
{
    private const string SqlError = "Warning: mysql_fetch_array() expects parameter 1 to be resource. You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version";
    private static readonly byte[] LargeBody = Encoding.ASCII.GetBytes(new string('a', 600_000) + " " + SqlError);

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
                    o.DirectivesAfterRules = """
                        SecRule RESPONSE_HEADERS:X-Debug-Token "@rx ." "id:10100,phase:3,deny,status:502,log,msg:'Debug token leaked'"
                        """;
                }))
                .Configure(app =>
                {
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
    [InlineData("/html-leak")]
    [InlineData("/json-leak")]
    [InlineData("/pipe-leak")]
    [InlineData("/chunks-leak")]
    public async Task SqlErrorLeakIsBlockedBeforeTheClientSeesIt(string path)
    {
        var response = await _client.GetAsync(path);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.DoesNotContain("SQL syntax", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.False(response.Headers.Contains("X-App"));
    }

    [Fact]
    public async Task CleanResponseIsSentUnchanged()
    {
        var response = await _client.GetAsync("/clean");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("<html><body>Hello</body></html>", await response.Content.ReadAsStringAsync());
        Assert.Equal("yes", response.Headers.GetValues("X-App").Single());
        Assert.Equal(31, response.Content.Headers.ContentLength);
    }

    [Fact]
    public async Task ResponseHeaderRuleBlocksInPhase3()
    {
        var response = await _client.GetAsync("/debug-header");
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.False(response.Headers.Contains("X-Debug-Token"));
    }

    [Fact]
    public async Task UninspectedMimeTypeStreamsThrough()
    {
        // application/octet-stream is not inspected, so the SQL error text in it passes.
        var response = await _client.GetAsync("/binary-leak");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("SQL syntax", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task LargeResponseIsInspectedPartiallyAndSentWhole()
    {
        // ProcessPartial: the first 512 KiB are inspected; the leak after them is not; the body arrives complete.
        var response = await _client.GetAsync("/large");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(LargeBody, await response.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task EmptyResponseRunsResponsePhases()
    {
        var response = await _client.GetAsync("/no-content");
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    private static async Task HandleAsync(HttpContext ctx)
    {
        var r = ctx.Response;
        r.Headers["X-App"] = "yes";
        switch (ctx.Request.Path.Value)
        {
            case "/clean":
                r.ContentType = "text/html";
                r.ContentLength = 31;
                await r.WriteAsync("<html><body>Hello</body></html>");
                break;
            case "/html-leak":
                r.ContentType = "text/html; charset=utf-8";
                await r.WriteAsync("<html><body>" + SqlError + "</body></html>");
                break;
            case "/json-leak":
                r.StatusCode = 500;
                r.ContentType = "application/problem+json";
                await r.WriteAsync($$"""{"title":"error","detail":"{{SqlError}}"}""");
                break;
            case "/pipe-leak":
                r.ContentType = "text/plain";
                await r.BodyWriter.WriteAsync(Encoding.UTF8.GetBytes(SqlError));
                await r.BodyWriter.FlushAsync();
                break;
            case "/chunks-leak":
                r.ContentType = "text/plain";
                await r.StartAsync();
                foreach (var part in SqlError.Chunk(10))
                {
                    await r.WriteAsync(new string(part));
                    await r.Body.FlushAsync();
                }

                break;
            case "/debug-header":
                r.Headers["X-Debug-Token"] = "abc";
                r.ContentType = "text/plain";
                await r.WriteAsync("ok");
                break;
            case "/binary-leak":
                r.ContentType = "application/octet-stream";
                await r.WriteAsync(SqlError);
                break;
            case "/large":
                r.ContentType = "text/plain";
                foreach (var chunk in LargeBody.Chunk(64 * 1024))
                {
                    await r.Body.WriteAsync(chunk);
                }

                break;
            case "/no-content":
                r.StatusCode = 204;
                break;
        }
    }
}
