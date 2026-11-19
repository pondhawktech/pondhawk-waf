using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Pondhawk.Waf.AspNetCore;

namespace Pondhawk.Waf.Tests;

/// <summary>
/// Regression tests for the findings of the adversarial security review (request body limit, multipart and JSON
/// parsing, regex classes, response inspection, logging). Each test fails on the code before the fix.
/// </summary>
public sealed class SecurityHardeningTests
{
    private const string Xss = "<script>alert(document.cookie)</script>";
    private const string Sqli = "1' UNION SELECT password FROM users--";
    private const string SqlError = "Warning: mysql_fetch_array() expects parameter 1 to be resource. You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version";

    // ----- Request body limit -----

    [Fact]
    public async Task BodyFillingTheLimitExactlyCannotSmuggleATailPastInspection()
    {
        // Chunked body: exactly SecRequestBodyLimit bytes, a pause, then the payload. Before the fix the middleware
        // took the full buffer for ProcessPartial and the application read the uninspected tail.
        const int limit = 65536;
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrel(k => k.Listen(IPAddress.Loopback, 0));
        builder.Services.AddPondhawkWaf(o =>
        {
            o.RuleEngine = RuleEngineMode.On;
            o.RequestBodyLimit = limit;
            o.RequestBodyNoFilesLimit = limit;
        });
        await using var app = builder.Build();
        app.UsePondhawkWaf();
        app.Run(async ctx =>
        {
            using var reader = new StreamReader(ctx.Request.Body);
            await ctx.Response.WriteAsync("app read " + (await reader.ReadToEndAsync()).Length);
        });
        await app.StartAsync();
        var port = new Uri(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First()).Port;

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes(
            "POST /comments HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\n" +
            "Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n"));
        var first = "a=" + new string('x', limit - 2);
        for (var i = 0; i < first.Length; i += 16384)
        {
            await stream.WriteAsync(Chunk(first.Substring(i, Math.Min(16384, first.Length - i))));
        }

        await stream.FlushAsync();
        await Task.Delay(500);
        await stream.WriteAsync(Chunk("&q=" + Uri.EscapeDataString(Sqli)));
        await stream.WriteAsync("0\r\n\r\n"u8.ToArray());
        var response = await ReadStatusLineAsync(stream);
        Assert.StartsWith("HTTP/1.1 413", response, StringComparison.Ordinal);
    }

    [Fact]
    public void EngineRejectsTheFirstByteAfterAFullBuffer()
    {
        var waf = Engine(o =>
        {
            o.RuleEngine = RuleEngineMode.On;
            o.RequestBodyLimit = 10;
        });
        using var tx = PostTransaction(waf, "application/octet-stream");
        Assert.Equal((null, 10), tx.WriteRequestBody(new byte[10]));
        var (interruption, written) = tx.WriteRequestBody(new byte[1]);
        Assert.Equal(413, interruption?.Status);
        Assert.Equal(0, written);
    }

    [Fact]
    public async Task DetectionOnlyRecordsButDoesNotRejectAnOversizedBody()
    {
        using var host = await StartAsync(o =>
        {
            o.RuleEngine = RuleEngineMode.DetectionOnly;
            o.RequestBodyNoFilesLimit = 1024;
        }, Echo);
        var response = await host.Client.PostAsync("/upload", Form("a=" + new string('x', 5000)));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("5002", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public void DetectionOnlyKeepsTheWouldBeInterruption()
    {
        var waf = Engine(o =>
        {
            o.RuleEngine = RuleEngineMode.DetectionOnly;
            o.RequestBodyLimit = 10;
        });
        using var tx = PostTransaction(waf, "application/octet-stream");
        Assert.Null(tx.CheckDeclaredRequestBodyLength(20));
        var (interruption, written) = tx.WriteRequestBody(new byte[20]);
        Assert.Null(interruption);
        Assert.Equal(10, written);
        Assert.Equal(413, tx.DetectionOnlyInterruption?.Status);
    }

    [Fact]
    public async Task FieldOnlyBodiesAreHeldToTheNoFilesLimitButFileUploadsAreNot()
    {
        using var host = await StartAsync(o =>
        {
            o.RuleEngine = RuleEngineMode.On;
            o.RequestBodyNoFilesLimit = 4096;
        }, Echo);

        var form = await host.Client.PostAsync("/f", Form("a=" + new string('x', 5000)));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, form.StatusCode);

        var json = new StringContent("{\"a\":\"" + new string('x', 5000) + "\"}", Encoding.UTF8, "application/json");
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await host.Client.PostAsync("/j", json)).StatusCode);

        var file = await host.Client.PostAsync("/u", Raw(
            "--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n" +
            new string('x', 50_000) + "\r\n--B--\r\n", "multipart/form-data; boundary=B"));
        Assert.Equal(HttpStatusCode.OK, file.StatusCode);

        var fields = await host.Client.PostAsync("/m", Raw(
            "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n" + new string('x', 5000) + "\r\n--B--\r\n",
            "multipart/form-data; boundary=B"));
        Assert.Equal(HttpStatusCode.BadRequest, fields.StatusCode);
    }

    // ----- Multipart differentials with ASP.NET Core's MultipartReader -----

    [Theory]
    [InlineData("x--B\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n" + Xss + "\r\n--B--\r\n")]
    [InlineData("--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n--B--x\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n" + Xss + "\r\n--B--\r\n")]
    [InlineData("--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhi\n--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"f.txt\"\r\n\r\n" + Xss + "\r\n--B--\r\n")]
    [InlineData("--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"f.txt\"\r\n\r\nhi\r\n--Bx\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n" + Xss + "\r\n--B--\r\n")]
    public async Task MultipartBodiesThatParseDifferentlyInAspNetCoreAreRejected(string body)
    {
        using var host = await StartAsync(o => o.RuleEngine = RuleEngineMode.On, ReadForm);
        var response = await host.Client.PostAsync("/submit", Raw(body, "multipart/form-data; boundary=B"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task WellFormedMultipartStillPasses()
    {
        using var host = await StartAsync(o => o.RuleEngine = RuleEngineMode.On, ReadForm);
        var content = new MultipartFormDataContent("B")
        {
            { new StringContent("Alice"), "name" },
            { new ByteArrayContent(Encoding.ASCII.GetBytes("plain file content")), "file", "notes.txt" },
        };
        var response = await host.Client.PostAsync("/submit", content);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("[field name=Alice]", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public void ManyMultipartPartsAreLinearAndLimited()
    {
        var sb = new StringBuilder();
        for (var i = 0; i < 16_000; i++)
        {
            sb.Append("--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a\"\r\n\r\n").Append('x', 200).Append("\r\n");
        }

        sb.Append("--B--\r\n");
        var waf = Engine(o => o.RuleEngine = RuleEngineMode.On);
        using var tx = PostTransaction(waf, "multipart/form-data; boundary=B");
        tx.WriteRequestBody(Encoding.ASCII.GetBytes(sb.ToString()));
        var sw = Stopwatch.StartNew();
        tx.ProcessRequestBody();
        Assert.True(sw.ElapsedMilliseconds < 1000, $"took {sw.ElapsedMilliseconds} ms");
        Assert.Equal("1", tx.Variables.ArgumentsLimitReached.Value);
        Assert.Equal(400, tx.Interruption?.Status);
    }

    // ----- JSON -----

    [Fact]
    public void LongJsonKeyAboveALargeArrayIsRejectedCheaply()
    {
        var body = "{\"" + new string('k', 30_000) + "\":[" + string.Join(',', Enumerable.Repeat("1", 999)) + "]}";
        var waf = Engine(o => o.RuleEngine = RuleEngineMode.On);
        using var tx = PostTransaction(waf, "application/json");
        tx.WriteRequestBody(Encoding.ASCII.GetBytes(body));
        var before = GC.GetAllocatedBytesForCurrentThread();
        tx.ProcessRequestBody();
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal("1", tx.Variables.ReqbodyError.Value);
        Assert.Equal(400, tx.Interruption?.Status);
        Assert.True(allocated < 50L * body.Length, $"allocated {allocated / 1_000_000} MB");
    }

    [Theory]
    [InlineData(new byte[] { (byte)'{', (byte)'"', (byte)'a', (byte)'"', (byte)':', (byte)'"', (byte)'\\', (byte)'u', (byte)'d', (byte)'8', (byte)'0', (byte)'0', (byte)'"', (byte)'}' })]
    [InlineData(new byte[] { (byte)'{', (byte)'"', (byte)'a', (byte)'"', (byte)':', (byte)'"', 0xC3, 0x28, (byte)'"', (byte)'}' })]
    public void InvalidJsonStringsAreABodyErrorNotAnException(byte[] body)
    {
        var waf = Engine(o => o.RuleEngine = RuleEngineMode.On);
        using var tx = PostTransaction(waf, "application/json");
        tx.WriteRequestBody(body);
        tx.ProcessRequestBody();
        Assert.Equal("1", tx.Variables.ReqbodyError.Value);
        Assert.Equal(400, tx.Interruption?.Status);
    }

    // ----- Regex classes are ASCII-only, as in RE2 -----

    [Theory]
    [InlineData("%C2%AAphpinfo()")]
    [InlineData("%C2%AAeval($c)")]
    [InlineData("%C2%AAassert($a)")]
    [InlineData("%C2%AApassthru($c)")]
    [InlineData("%C2%AAdatabase()")]
    [InlineData("%C2%AAsetTimeout(x)")]
    [InlineData("%C2%AAalert(1)")]
    [InlineData("%C2%AAallow_url_include=1")]
    public void Latin1LetterBeforeAKeywordDoesNotHideIt(string payload)
    {
        var waf = Engine(o => o.RuleEngine = RuleEngineMode.On);
        var tx = waf.NewTransaction();
        tx.ProcessConnection("10.0.0.1", 40000, "10.0.0.2", 80);
        tx.ProcessUri("/?q=" + payload, "GET", "HTTP/1.1");
        tx.AddRequestHeader("Host", "example.com");
        tx.AddRequestHeader("User-Agent", "Mozilla/5.0");
        tx.AddRequestHeader("Accept", "text/html");
        tx.ProcessRequestHeaders();
        tx.ProcessRequestBody();
        Assert.Equal(949110, tx.Interruption?.RuleId);
        tx.Dispose();
    }

    [Theory]
    [InlineData(@"\w", "a", true)]
    [InlineData(@"\w", "\u00e9", false)]
    [InlineData(@"\W", "\u00e9", true)]
    [InlineData(@"[\w-]", "\u00aa", false)]
    [InlineData(@"\d", "\u0661", false)]
    [InlineData(@"\s", "\u00a0", false)]
    [InlineData(@"\s", "\u0085", false)]
    [InlineData(@"\s", "\v", false)]
    [InlineData(@"\S", "\u00a0", true)]
    [InlineData(@"[^\s]", "\u00a0", true)]
    [InlineData(@"\beval\b", "\u00aaeval", true)]
    [InlineData(@"\beval\b", "xeval", false)]
    [InlineData(@"^\x{c2}\xaa\beval", "\u00c2\u00aaeval", true)]
    public void RegexClassesFollowRe2(string pattern, string input, bool matches) =>
        Assert.Equal(matches, new Pondhawk.Waf.Operators.RxOperator(new Pondhawk.Waf.Operators.RegexCache().Get(pattern), Pondhawk.Waf.Operators.RegexCache.UsesWordBoundary(pattern))
            .Evaluate(Engine(_ => { }).NewTransaction(), input));

    // ----- Response inspection -----

    [Theory]
    [InlineData("text/json", null)]
    [InlineData("application/xml", null)]
    [InlineData("application/vnd.api+json", null)]
    [InlineData("application/atom+xml", null)]
    [InlineData("application/json; charset=utf-16", "utf-16")]
    [InlineData("text/plain", "utf-16-bom")]
    [InlineData(null, null)]
    public async Task ResponseFormatsTheClientCanChooseAreInspected(string? contentType, string? encoding)
    {
        using var host = await StartAsync(o => o.RuleEngine = RuleEngineMode.On, async ctx =>
        {
            if (contentType is not null)
            {
                ctx.Response.ContentType = contentType;
            }

            var bytes = encoding switch
            {
                "utf-16" => Encoding.Unicode.GetBytes(SqlError),
                "utf-16-bom" => [.. Encoding.Unicode.GetPreamble(), .. Encoding.Unicode.GetBytes(SqlError)],
                _ => Encoding.UTF8.GetBytes(SqlError),
            };
            await ctx.Response.Body.WriteAsync(bytes);
        });
        var response = await host.Client.GetAsync("/leak");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task UnflushedBodyWriterBytesAreInspectedAndSent()
    {
        using var host = await StartAsync(o => o.RuleEngine = RuleEngineMode.On, ctx =>
        {
            ctx.Response.ContentType = "text/plain";
            var data = "hello from the pipe"u8;
            data.CopyTo(ctx.Response.BodyWriter.GetSpan(data.Length));
            ctx.Response.BodyWriter.Advance(data.Length);
            return Task.CompletedTask;
        });
        var response = await host.Client.GetAsync("/");
        Assert.Equal("hello from the pipe", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task StreamingResponseThatDisablesBufferingIsNotHeld()
    {
        var release = new TaskCompletionSource();
        using var host = await StartAsync(o => o.RuleEngine = RuleEngineMode.On, async ctx =>
        {
            ctx.Response.ContentType = "text/plain";
            ctx.Features.GetRequiredFeature<IHttpResponseBodyFeature>().DisableBuffering();
            await ctx.Response.WriteAsync("event-1\n");
            await ctx.Response.Body.FlushAsync();
            await release.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await ctx.Response.WriteAsync("event-2\n");
        });
        var sw = Stopwatch.StartNew();
        using var response = await host.Client.GetAsync("/events", HttpCompletionOption.ResponseHeadersRead);
        var headersAfter = sw.ElapsedMilliseconds;
        release.SetResult();
        Assert.True(headersAfter < 5000, $"headers after {headersAfter} ms");
        Assert.Equal("event-1\nevent-2\n", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public void ResponseBodyIsSetWhenAResponseBodyProcessorRuns()
    {
        var waf = Engine(o => o.Directives = "SecAction \"id:10001,phase:3,pass,nolog,ctl:responseBodyProcessor=JSON\"");
        using var tx = waf.NewTransaction();
        tx.ProcessUri("/", "GET", "HTTP/1.1");
        tx.ProcessRequestHeaders();
        tx.ProcessRequestBody();
        tx.AddResponseHeader("Content-Type", "application/json");
        tx.ProcessResponseHeaders(200, "HTTP/1.1");
        tx.WriteResponseBody("{\"a\":\"b\"}"u8);
        tx.ProcessResponseBody();
        Assert.Equal("{\"a\":\"b\"}", tx.Variables.ResponseBody.Value);
        Assert.Equal("b", tx.Variables.ResponseArgs.GetFirst("json.a"));
    }

    // ----- Logging -----

    [Fact]
    public async Task LoggedMatchDataIsTruncated()
    {
        var logs = new CapturingLoggerProvider();
        using var host = await StartAsync(o => o.RuleEngine = RuleEngineMode.DetectionOnly, Echo, logs);
        await host.Client.PostAsync("/c", Form("q=" + Uri.EscapeDataString("<script>" + new string('a', 400_000))));
        var ruleLines = logs.Messages("Pondhawk.Waf.Rules");
        Assert.NotEmpty(ruleLines);
        Assert.All(ruleLines, line => Assert.True(line.Length < 4096, $"rule log line of {line.Length} chars"));
        Assert.All(logs.Messages("Pondhawk.Waf.Audit"), entry => Assert.True(entry.Length < 64 * 1024, $"audit entry of {entry.Length} chars"));
    }

    [Fact]
    public async Task CredentialsDoNotReachTheLogs()
    {
        var logs = new CapturingLoggerProvider();
        using var host = await StartAsync(o => o.RuleEngine = RuleEngineMode.On, Echo, logs);

        // A cookie value and a password that trip rules, and a token in the query string.
        var request = new HttpRequestMessage(HttpMethod.Post, "/login?reset_token=SECRET-QUERY-TOKEN&page=2")
        {
            Content = Form("user=alice&password=" + Uri.EscapeDataString("SECRET-PASSWORD' OR 1=1--")),
        };
        request.Headers.TryAddWithoutValidation("Cookie", "session=" + Uri.EscapeDataString("SECRET-COOKIE<script>alert(1)</script>"));
        request.Headers.TryAddWithoutValidation("X-Access-Token", "SECRET-HEADER-TOKEN");
        var response = await host.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        var all = string.Join('\n', logs.Messages("Pondhawk.Waf.Rules").Concat(logs.Messages("Pondhawk.Waf.Audit")));
        Assert.Contains("949110", all, StringComparison.Ordinal);
        Assert.DoesNotContain("SECRET", all, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PlainNotFoundIsNotAudited()
    {
        var logs = new CapturingLoggerProvider();
        using var host = await StartAsync(o => o.RuleEngine = RuleEngineMode.On, ctx =>
        {
            ctx.Response.StatusCode = 404;
            return Task.CompletedTask;
        }, logs);
        await host.Client.GetAsync("/reset-password?token=abc");
        Assert.Empty(logs.Messages("Pondhawk.Waf.Audit"));
    }

    [Fact]
    public async Task AFailingLogSinkDoesNotFailRequests()
    {
        var logs = new CapturingLoggerProvider { Throw = true };
        using var host = await StartAsync(o => o.RuleEngine = RuleEngineMode.DetectionOnly, Echo, logs);
        var response = await host.Client.GetAsync("/search?q=" + Uri.EscapeDataString(Sqli));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(host.Services.GetRequiredService<WafEngine>().LogFailures > 0);
    }

    [Fact]
    public void RuleLogEscapesUnicodeLineBreaksAndC1Controls()
    {
        var waf = Engine(o => o.Directives = "SecRule ARGS \"@contains x\" \"id:10002,phase:1,pass,log,logdata:'%{MATCHED_VAR}'\"");
        string? line = null;
        waf.Config.ErrorCallback = m => line = m.ErrorLogLine();
        using var tx = waf.NewTransaction();
        tx.ProcessUri("/?a=x%E2%80%A8forged%C2%85%C2%9B", "GET", "HTTP/1.1");
        tx.ProcessRequestHeaders();
        Assert.NotNull(line);
        Assert.DoesNotContain((char)0x2028, line);
        Assert.DoesNotContain('\u0085', line);
        Assert.DoesNotContain('\u009b', line);
    }

    [Fact]
    public async Task StartupWarnsWhenTheRuleEngineDoesNotBlock()
    {
        var logs = new CapturingLoggerProvider();
        using var host = await StartAsync(_ => { }, Echo, logs);
        Assert.Contains(logs.Messages("Pondhawk.Waf"), m => m.Contains("NOT blocked", StringComparison.Ordinal));
    }

    // ----- Configuration -----

    [Theory]
    [InlineData("text/html\\")]
    [InlineData("text/html\"")]
    [InlineData("text/html\nSecRuleEngine Off")]
    [InlineData("text")]
    public void InvalidResponseMimeTypesAreRejected(string type) =>
        Assert.ThrowsAny<ArgumentException>(() => new WafOptions { ResponseMimeTypes = [type] }.Resolve());

    [Fact]
    public async Task WithoutCoreRuleSetRequestBodiesAreStillInspectedAndLimited()
    {
        using var host = await StartAsync(o =>
        {
            o.UseCoreRuleSet = false;
            o.RuleEngine = RuleEngineMode.On;
            o.RequestBodyNoFilesLimit = 100;
            o.DirectivesAfterRules = "SecRule ARGS:x \"@contains evil\" \"id:10003,phase:2,deny,status:403,log\"";
        }, Echo);
        Assert.Equal(HttpStatusCode.Forbidden, (await host.Client.PostAsync("/", Form("x=evil"))).StatusCode);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await host.Client.PostAsync("/", Form("x=" + new string('a', 200)))).StatusCode);
    }

    [Fact]
    public void TransformationCacheStopsGrowingAtItsBudget()
    {
        var cache = new Rules.TransformationCache();
        var big = new string('a', (int)(Rules.TransformationCache.MaxChars / 2) + 1);
        cache.Add(1, "x", big);
        cache.Add(2, "x", big);
        Assert.Equal(1, cache.Count);

        // A transformation that changed nothing returns its input: caching it costs nothing.
        cache.Add(3, big, big);
        Assert.Equal(2, cache.Count);
    }

    // ----- Helpers -----

    private static WafEngine Engine(Action<WafOptions> configure)
    {
        var o = new WafOptions { WarmUp = false };
        configure(o);
        return WafServiceCollectionExtensions.CreateEngine(o, Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance);
    }

    private static Transaction PostTransaction(WafEngine waf, string contentType)
    {
        var tx = waf.NewTransaction();
        tx.ProcessConnection("10.0.0.1", 40000, "10.0.0.2", 80);
        tx.ProcessUri("/submit", "POST", "HTTP/1.1");
        tx.AddRequestHeader("Host", "example.com");
        tx.AddRequestHeader("User-Agent", "Mozilla/5.0");
        tx.AddRequestHeader("Accept", "text/html");
        tx.AddRequestHeader("Content-Type", contentType);
        tx.ProcessRequestHeaders();
        return tx;
    }

    private static async Task Echo(HttpContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.Body);
        await ctx.Response.WriteAsync((await reader.ReadToEndAsync()).Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    private static async Task ReadForm(HttpContext ctx)
    {
        var form = await ctx.Request.ReadFormAsync();
        var sb = new StringBuilder();
        foreach (var kv in form)
        {
            sb.Append("[field ").Append(kv.Key).Append('=').Append(kv.Value.ToString()).Append(']');
        }

        await ctx.Response.WriteAsync(sb.ToString());
    }

    private static StringContent Form(string body) => new(body, Encoding.UTF8, "application/x-www-form-urlencoded");

    private static ByteArrayContent Raw(string body, string contentType)
    {
        var content = new ByteArrayContent(Encoding.Latin1.GetBytes(body));
        content.Headers.TryAddWithoutValidation("Content-Type", contentType);
        return content;
    }

    private static byte[] Chunk(string data) =>
        Encoding.Latin1.GetBytes(data.Length.ToString("x", System.Globalization.CultureInfo.InvariantCulture) + "\r\n" + data + "\r\n");

    private static async Task<string> ReadStatusLineAsync(NetworkStream stream)
    {
        var buffer = new byte[4096];
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var n = await stream.ReadAsync(buffer, cts.Token);
        return Encoding.Latin1.GetString(buffer, 0, n);
    }

    private static async Task<TestHostHandle> StartAsync(Action<WafOptions> waf, RequestDelegate handler, ILoggerProvider? logs = null)
    {
        var host = await new HostBuilder()
            .ConfigureLogging(l =>
            {
                l.ClearProviders();
                if (logs is not null)
                {
                    l.AddProvider(logs);
                    l.SetMinimumLevel(LogLevel.Information);
                }
            })
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(s => s.AddPondhawkWaf(o =>
                {
                    o.WarmUp = false;
                    waf(o);
                }))
                .Configure(app =>
                {
                    app.UsePondhawkWaf();
                    app.Run(handler);
                }))
            .StartAsync();
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (X11; Linux x86_64)");
        client.DefaultRequestHeaders.Accept.ParseAdd("text/html");
        return new TestHostHandle(host, client);
    }

    private sealed class TestHostHandle(IHost host, HttpClient client) : IDisposable
    {
        public HttpClient Client { get; } = client;

        public IServiceProvider Services => host.Services;

        public void Dispose()
        {
            Client.Dispose();
            host.StopAsync().GetAwaiter().GetResult();
            host.Dispose();
        }
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<(string Category, string Message)> _entries = new();

        public bool Throw { get; init; }

        public IReadOnlyList<string> Messages(string category) =>
            _entries.Where(e => e.Category == category).Select(e => e.Message).ToList();

        public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

        public void Dispose()
        {
        }

        private sealed class Logger(CapturingLoggerProvider provider, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                if (provider.Throw && category.StartsWith("Pondhawk.Waf.", StringComparison.Ordinal))
                {
                    throw new IOException("log sink down");
                }

                provider._entries.Enqueue((category, formatter(state, exception)));
            }
        }
    }
}
