using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Text;

namespace Pondhawk.Waf.Compatibility;

/// <summary>
/// A clean request must get the same response with the WAF as without it, in every rule engine mode: same status,
/// headers and body. The app has the usual middleware on both sides of the WAF, so a WAF that disturbs one of them
/// (#30: outer OnStarting callbacks) shows up here without a test written for that case.
/// </summary>
[Collection(ServersCollection.Name)]
public sealed class DifferentialTests(Servers servers)
{
    private static readonly Dictionary<string, Func<Servers, Uri, Task<Outcome>>> Cases = new()
    {
        ["html"] = Get("/html"),
        ["html gzip"] = Get("/html", r => r.Headers.AcceptEncoding.ParseAdd("gzip")),
        ["html brotli"] = Get("/html", r => r.Headers.AcceptEncoding.ParseAdd("br")),
        ["HEAD html"] = Send(HttpMethod.Head, "/html"),
        ["json"] = Get("/json"),
        ["json CORS"] = Get("/json", r => r.Headers.Add("Origin", CompatibilityApp.AllowedOrigin)),
        ["CORS preflight"] = Send(HttpMethod.Options, "/json", r =>
        {
            r.Headers.Add("Origin", CompatibilityApp.AllowedOrigin);
            r.Headers.Add("Access-Control-Request-Method", "POST");
            r.Headers.Add("Access-Control-Request-Headers", "content-type");
        }),
        ["flushed chunks"] = Get("/text-chunks"),
        ["server-sent events"] = Get("/sse"),
        ["DisableBuffering"] = Get("/disable-buffering"),
        ["large text"] = Get("/large-text"),
        ["large html over the response body limit"] = Get("/large-html"),
        ["large html gzip"] = Get("/large-html", r => r.Headers.AcceptEncoding.ParseAdd("gzip")),
        ["BodyWriter without flush"] = Get("/pipe"),
        ["Results.File"] = Get("/sendfile"),
        ["empty 200"] = Get("/empty"),
        ["204"] = Get("/no-content"),
        ["redirect"] = Get("/redirect"),
        ["problem details"] = Get("/problem"),
        ["404 status code page"] = Get("/missing"),
        ["exception before the response"] = Get("/error-before"),
        ["exception after the response started"] = Get("/error-after"),
        ["401 challenge"] = Get("/me"),
        ["authenticated"] = Get("/me", r => r.Headers.Add("X-User", "alice")),
        ["antiforgery cookie"] = Get("/antiforgery-token"),
        ["antiforgery refusal"] = Post("/form-protected", () => new FormUrlEncodedContent([new("name", "alice")])),
        ["form post"] = Post("/form", () => new FormUrlEncodedContent([new("name", "alice")])),
        ["json post"] = Post("/json-echo", () => new StringContent("""{"name":"bolt","quantity":4}""", Encoding.UTF8, "application/json")),
        ["multipart upload"] = Post("/upload", () => new MultipartFormDataContent
        {
            { new ByteArrayContent("file contents"u8.ToArray()) { Headers = { ContentType = new MediaTypeHeaderValue("text/plain") } }, "file", "notes.txt" },
        }),
        ["output cache hit"] = Twice(Get("/cached")),
        ["forwarded headers"] = Get("/whoami", r =>
        {
            r.Headers.Add("X-Forwarded-For", "203.0.113.7");
            r.Headers.Add("X-Forwarded-Proto", "https");
        }),
        ["inner OnStarting"] = Get("/inner-on-starting"),
        ["static file"] = Get("/static.txt"),
        ["static html page"] = Get("/page.html"),
        ["static gzip"] = Get("/page.html", r => r.Headers.AcceptEncoding.ParseAdd("gzip")),
        ["static HEAD"] = Send(HttpMethod.Head, "/static.txt"),
        ["static range"] = Get("/static.txt", r => r.Headers.Range = new RangeHeaderValue(0, 5)),
        ["static 304"] = Conditional("/static.txt"),
        ["static script"] = Get("/app.js"),
        ["proxy json"] = Get("/proxy/json"),
        ["proxy html"] = Get("/proxy/html"),
        ["proxy stream"] = Get("/proxy/stream"),
        ["proxy post"] = Post("/proxy/echo", () => new StringContent("""{"to":"backend"}""", Encoding.UTF8, "application/json")),
    };

    public static TheoryData<WafSetup, string> Matrix()
    {
        var data = new TheoryData<WafSetup, string>();
        foreach (var setup in Enum.GetValues<WafSetup>().Where(s => s != WafSetup.None))
        {
            foreach (var name in Cases.Keys)
            {
                data.Add(setup, name);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public async Task CleanRequestGetsTheSameResponseAsWithoutTheWaf(WafSetup setup, string name)
    {
        var expected = await Cases[name](servers, servers.Address(WafSetup.None));
        var actual = await Cases[name](servers, servers.Address(setup));
        Assert.Equal(expected.Text, actual.Text);
    }

    [Theory]
    [InlineData(WafSetup.Off)]
    [InlineData(WafSetup.DetectionOnly)]
    [InlineData(WafSetup.DetectionOnlyHeld)]
    [InlineData(WafSetup.On)]
    public async Task WebSocketEchoes(WafSetup setup)
    {
        using var socket = new ClientWebSocket();
        var server = servers.Address(setup);
        socket.Options.SetRequestHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await socket.ConnectAsync(new Uri($"ws://{server.Authority}/ws"), timeout.Token);
        var message = "hello through the WAF"u8.ToArray();
        await socket.SendAsync(message, WebSocketMessageType.Text, endOfMessage: true, timeout.Token);
        var buffer = new byte[1024];
        var result = await socket.ReceiveAsync(buffer, timeout.Token);
        Assert.Equal(message, buffer[..result.Count]);
        await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, timeout.Token);
    }

    private static Func<Servers, Uri, Task<Outcome>> Get(string path, Action<HttpRequestMessage>? configure = null) =>
        Send(HttpMethod.Get, path, configure);

    private static Func<Servers, Uri, Task<Outcome>> Post(string path, Func<HttpContent> content) =>
        (servers, server) => servers.SendAsync(Servers.Request(HttpMethod.Post, server, path, content()));

    private static Func<Servers, Uri, Task<Outcome>> Send(HttpMethod method, string path, Action<HttpRequestMessage>? configure = null) =>
        (servers, server) =>
        {
            var request = Servers.Request(method, server, path);
            configure?.Invoke(request);
            return servers.SendAsync(request);
        };

    /// <summary>The second response: a cache hit on every server, whatever ran before.</summary>
    private static Func<Servers, Uri, Task<Outcome>> Twice(Func<Servers, Uri, Task<Outcome>> send) =>
        async (servers, server) =>
        {
            await send(servers, server);
            return await send(servers, server);
        };

    /// <summary>GET with the ETag of a first response in If-None-Match: 304.</summary>
    private static Func<Servers, Uri, Task<Outcome>> Conditional(string path) =>
        async (servers, server) =>
        {
            using var first = await servers.Client.SendAsync(Servers.Request(HttpMethod.Get, server, path));
            var request = Servers.Request(HttpMethod.Get, server, path);
            request.Headers.IfNoneMatch.Add(first.Headers.ETag!);
            return await servers.SendAsync(request);
        };
}
