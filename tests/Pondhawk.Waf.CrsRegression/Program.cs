// Runs the OWASP CRS regression tests (go-ftw YAML format) against Pondhawk WAF hosted on Kestrel.
// Requests are sent as raw bytes over TCP, so the full stack (Kestrel parsing + middleware + engine) is tested.
// Test configuration mirrors Coraza's FTW setup (coraza/testing/coreruleset).
//
// Usage: dotnet run --project tests/Pondhawk.Waf.CrsRegression -- [--filter <substring>] [--report <file>] [--verbose]
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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Pondhawk.Waf;
using Pondhawk.Waf.AspNetCore;
using YamlDotNet.Serialization;

var filter = ArgValue(args, "--filter");
var reportPath = ArgValue(args, "--report");
var verbose = args.Contains("--verbose");
var debug = args.Contains("--debug");
var baseDir = AppContext.BaseDirectory;

const string TestingConfig = """
    SecResponseBodyMimeType text/plain
    SecAction "id:900005,\
      phase:1,\
      nolog,\
      pass,\
      ctl:ruleEngine=DetectionOnly,\
      ctl:ruleRemoveById=910000,\
      setvar:tx.blocking_paranoia_level=4,\
      setvar:tx.crs_validate_utf8_encoding=1,\
      setvar:tx.arg_name_length=100,\
      setvar:tx.arg_length=400,\
      setvar:tx.total_arg_length=64000,\
      setvar:tx.max_num_args=255,\
      setvar:tx.max_file_size=64100,\
      setvar:tx.combined_file_sizes=65535"
    """;

var collected = new ConcurrentBag<int>();
var done = new SemaphoreSlim(0);

// The CRS tests run without plugins (a plugin changes results on its application's paths); the plugin tests run on a
// second server with every plugin loaded.
WebApplication CreateApp(IEnumerable<Pondhawk.Waf.CoreRuleSet.CrsPlugin> plugins)
{
    var builder = WebApplication.CreateSlimBuilder();
    builder.Logging.ClearProviders();
    builder.WebHost.UseKestrel(k =>
    {
        k.Listen(IPAddress.Loopback, 0);
        k.Limits.MaxRequestBodySize = 64 * 1024 * 1024;
    });
    builder.Services.AddPondhawkWaf(o =>
    {
        o.Directives = TestingConfig;
        o.Plugins.AddRange(plugins);
        o.Configure = b =>
        {
            b.Config.ErrorCallback = m => collected.Add(m.Rule.LogId);
            b.Config.AuditLogWriter = null;
        };
    });

    var app = builder.Build();
    app.Use(async (ctx, next) =>
    {
        try
        {
            await next(ctx);
        }
        finally
        {
            if (debug && ctx.Items[WafMiddleware.TransactionKey] is Transaction tx)
            {
                var v = tx.Variables;
                Console.WriteLine($"  tx {tx.Id}: engine={tx.RuleEngine} lastPhase={tx.LastPhase} reqbodyProcessor={v.ReqbodyProcessor.Value} bodyLen={v.RequestBodyLength.Value} reqbodyError={v.ReqbodyErrorMsg.Value}");
                Console.WriteLine($"  args: {string.Join(", ", Enumerable.Range(0, 1).SelectMany(_ => { var l = new List<Pondhawk.Waf.Collections.MatchData>(); v.Args.FindAll(l); return l.Select(m => m.Key + "=" + m.Value); }))}");
                Console.WriteLine($"  matched: {string.Join(", ", tx.MatchedRules.Select(m => m.Rule.LogId + (m.Rule.Log ? "" : "(nolog)") + (m.Rule.LogId == 200000 ? "[" + string.Join(";", m.Matches.Select(x => x.Match.FullName + "=" + x.Match.Value)) + " op=" + m.Rule.OperatorData + "]" : "")))}");
                { var hl = new List<Pondhawk.Waf.Collections.MatchData>(); v.RequestHeaders.FindAll(hl); Console.WriteLine("  headers: " + string.Join(" | ", hl.Select(x => x.Key + ": " + x.Value))); }
            }

            done.Release();
        }
    });
    app.UsePondhawkWaf();
    app.Run(async ctx =>
    {
        // Read the body as an application would, then answer like the albedo backend the CRS tests expect.
        using var sink = new MemoryStream();
        await ctx.Request.Body.CopyToAsync(sink);
        ctx.Response.ContentType = "text/plain";
        if (ctx.Request.Path == "/reflect" && sink.Length > 0)
        {
            await ReflectAsync(ctx, sink.ToArray());
            return;
        }

        await ctx.Response.WriteAsync("ok");
    });
    return app;
}

var sw = Stopwatch.StartNew();
var app = CreateApp([]);
var pluginApp = CreateApp(Enum.GetValues<Pondhawk.Waf.CoreRuleSet.CrsPlugin>());
await app.StartAsync();
await pluginApp.StartAsync();
Console.WriteLine($"WAF loaded and servers started in {sw.ElapsedMilliseconds} ms");
var address = ServerAddress(app);
var pluginAddress = ServerAddress(pluginApp);

var overrides = LoadOverrides(Path.Combine(baseDir, "coraza-overrides.yaml"));
foreach (var (k, val) in LoadOverrides(Path.Combine(baseDir, "kestrel-overrides.yaml"))
             .Concat(LoadOverrides(Path.Combine(baseDir, "plugin-overrides.yaml"))))
{
    overrides[k] = val;
}

var files = Directory.GetFiles(Path.Combine(baseDir, "crs-tests"), "*.yaml", SearchOption.AllDirectories).Order(StringComparer.Ordinal)
    .Concat(Directory.GetFiles(Path.Combine(baseDir, "plugin-tests"), "*.yaml", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
    .ToList();
var deserializer = new DeserializerBuilder().Build();

int pass = 0, fail = 0;
var failures = new List<string>();
var byGroup = new SortedDictionary<string, (int Pass, int Fail)>(StringComparer.Ordinal);
sw.Restart();
foreach (var file in files)
{
    var group = Path.GetFileName(Path.GetDirectoryName(file)!);
    var isPlugin = file.Contains(Path.DirectorySeparatorChar + "plugin-tests" + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    if (isPlugin)
    {
        group = "plugin/" + group;
    }
    var doc = deserializer.Deserialize<Dictionary<object, object>?>(File.ReadAllText(file));
    if (doc is null || doc.GetValueOrDefault("tests") is not List<object>)
    {
        continue;
    }

    // Older go-ftw tests have no rule_id; the file is named after the rule.
    var ruleId = doc.TryGetValue("rule_id", out var rid)
        ? Convert.ToInt32(rid, System.Globalization.CultureInfo.InvariantCulture)
        : int.Parse(Path.GetFileNameWithoutExtension(file), System.Globalization.CultureInfo.InvariantCulture);
    foreach (Dictionary<object, object> test in (List<object>)doc["tests"])
    {
        // Older go-ftw tests name each test with test_title ("9510100-1") instead of test_id.
        var name = test.TryGetValue("test_id", out var tid)
            ? $"{ruleId}-{Convert.ToInt32(tid, System.Globalization.CultureInfo.InvariantCulture)}"
            : test["test_title"].ToString()!;
        if (filter is not null && (filter.EndsWith('$') ? name != filter[..^1] : !name.Contains(filter, StringComparison.Ordinal) && !group.Contains(filter, StringComparison.Ordinal)))
        {
            continue;
        }

        var ok = true;
        var detail = new StringBuilder();
        foreach (Dictionary<object, object> wrapped in (List<object>)test["stages"])
        {
            // Older go-ftw tests wrap input and output in "stage".
            var stage = wrapped.TryGetValue("stage", out var inner) && inner is Dictionary<object, object> innerStage ? innerStage : wrapped;
            var input = (Dictionary<object, object>)stage["input"];
            // A stage without output only prepares the next one; nothing is checked.
            var output = overrides.TryGetValue(name, out var o) ? o
                : stage.TryGetValue("output", out var so) && so is Dictionary<object, object> stageOutput ? stageOutput : [];
            var request = BuildRequest(input);
            collected.Clear();
            while (done.CurrentCount > 0)
            {
                await done.WaitAsync();
            }

            var (status, error) = await SendAsync(isPlugin ? pluginAddress : address, request);
            // Wait for the WAF to finish (logging phase runs after the response is sent).
            if (error is null || status > 0)
            {
                await done.WaitAsync(status is 400 or 0 ? 300 : 3000);
            }

            var ids = collected.ToHashSet();
            if (debug)
            {
                Console.WriteLine($"  -> status {status} error {error}");
            }
            var (stageOk, why) = Check(output, ids, status, error);
            if (!stageOk)
            {
                ok = false;
                detail.Append(why);
            }
        }

        var counts = byGroup.GetValueOrDefault(group);
        if (ok)
        {
            pass++;
            byGroup[group] = (counts.Pass + 1, counts.Fail);
        }
        else
        {
            fail++;
            byGroup[group] = (counts.Pass, counts.Fail + 1);
            var desc = test.TryGetValue("desc", out var d) ? d?.ToString()?.Trim().ReplaceLineEndings(" ") : string.Empty;
            failures.Add($"{name}: {detail} -- {desc}");
            if (verbose)
            {
                Console.WriteLine($"FAIL {name}: {detail}");
            }
        }
    }
}

Console.WriteLine();
foreach (var (group, (p, f)) in byGroup)
{
    Console.WriteLine($"{group,-45} {p,5} pass {f,5} fail");
}

Console.WriteLine();
Console.WriteLine($"Total: {pass} pass, {fail} fail in {sw.Elapsed.TotalSeconds:F1} s");
foreach (var failure in failures.Take(50))
{
    Console.WriteLine("FAIL " + failure);
}
if (reportPath is not null)
{
    await File.WriteAllLinesAsync(reportPath, failures);
    Console.WriteLine($"Failures written to {reportPath}");
}

await app.StopAsync();
await pluginApp.StopAsync();
return fail == 0 ? 0 : 1;

static Uri ServerAddress(WebApplication app) =>
    new(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First());

static (bool Ok, string Why) Check(Dictionary<object, object> output, HashSet<int> ids, int status, string? error)
{
    // any_of: alternative expectations, for behavior that differs between ASP.NET Core versions.
    if (output.TryGetValue("any_of", out var anyOf) && anyOf is List<object> alternatives)
    {
        var whys = new List<string>();
        foreach (var alternative in alternatives.OfType<Dictionary<object, object>>())
        {
            var (ok, altWhy) = Check(alternative, ids, status, error);
            if (ok)
            {
                return (true, string.Empty);
            }

            whys.Add(altWhy);
        }

        return (false, "no alternative matched: " + string.Join(" | ", whys));
    }

    if (output.TryGetValue("expect_error", out var expectError) && IsTrue(expectError))
    {
        return error is not null || status == 0 ? (true, string.Empty) : (false, $"expected a connection error, got {status}; ");
    }

    var why = new StringBuilder();
    var checkedSomething = false;
    if (output.TryGetValue("log", out var logObj) && logObj is Dictionary<object, object> log)
    {
        if (log.TryGetValue("expect_ids", out var e) && e is List<object> expect)
        {
            checkedSomething = true;
            var missing = expect.Select(ToInt).Where(id => !ids.Contains(id)).ToList();
            if (missing.Count > 0)
            {
                why.Append($"missing [{string.Join(',', missing)}] got [{string.Join(',', ids.Order())}]; ");
            }
        }

        if (log.TryGetValue("no_expect_ids", out var n) && n is List<object> noExpect)
        {
            checkedSomething = true;
            var unexpected = noExpect.Select(ToInt).Where(ids.Contains).ToList();
            if (unexpected.Count > 0)
            {
                why.Append($"unexpected [{string.Join(',', unexpected)}]; ");
            }
        }
    }

    // Regex checks against the log text, for patterns about rule ids only: each logged rule appears as [id "N"], as
    // in a ModSecurity error log line. Patterns about messages or matched data are not checked. Older go-ftw tests put
    // log_contains / no_log_contains directly under output.
    var logText = string.Concat(ids.Order().Select(id => $"[id \"{id}\"] "));
    var regexChecks = new (Dictionary<object, object>? Source, string Key, bool Expect)[]
    {
        (logObj as Dictionary<object, object>, "match_regex", true),
        (logObj as Dictionary<object, object>, "no_match_regex", false),
        (output, "log_contains", true),
        (output, "no_log_contains", false),
    };
    foreach (var (source, key, expect) in regexChecks)
    {
        if (source is not null && source.TryGetValue(key, out var rx) && rx is string pattern
            && pattern.Contains("id \"", StringComparison.Ordinal) && !pattern.Contains("msg", StringComparison.Ordinal))
        {
            checkedSomething = true;
            if (System.Text.RegularExpressions.Regex.IsMatch(logText, pattern) != expect)
            {
                why.Append($"{key} '{pattern}' failed, got [{string.Join(',', ids.Order())}]; ");
            }
        }
    }

    if (output.TryGetValue("status", out var st) && !checkedSomething)
    {
        var allowed = st is List<object> list ? list.Select(ToInt).ToList() : [ToInt(st)];
        if (!allowed.Contains(status))
        {
            why.Append($"status {status} not in [{string.Join(',', allowed)}] {error}; ");
        }
    }

    return (why.Length == 0, why.ToString());
}

static byte[] BuildRequest(Dictionary<object, object> input)
{
    if (input.TryGetValue("encoded_request", out var enc) && enc is string encoded)
    {
        return Convert.FromBase64String(encoded.Trim());
    }

    var method = input.TryGetValue("method", out var m) ? m?.ToString() ?? "GET" : "GET";
    var uri = input.TryGetValue("uri", out var u) ? u?.ToString() ?? "/" : "/";
    var version = input.TryGetValue("version", out var v) ? v?.ToString() ?? "HTTP/1.1" : "HTTP/1.1";
    var data = input.TryGetValue("data", out var dt) ? dt?.ToString() ?? string.Empty : string.Empty;
    var autocomplete = !input.TryGetValue("autocomplete_headers", out var ac) || IsTrue(ac);
    var headers = new List<(string Name, string Value)>();
    if (input.TryGetValue("headers", out var h) && h is Dictionary<object, object> hd)
    {
        foreach (var (k, val) in hd)
        {
            headers.Add((k.ToString()!, val?.ToString() ?? string.Empty));
        }
    }

    var body = Encoding.UTF8.GetBytes(data);
    if (autocomplete)
    {
        if (body.Length > 0 && !headers.Any(x => x.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)))
        {
            headers.Add(("Content-Length", body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }

        if (body.Length > 0 && !headers.Any(x => x.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)))
        {
            headers.Add(("Content-Type", "application/x-www-form-urlencoded"));
        }

        if (!headers.Any(x => x.Name.Equals("Connection", StringComparison.OrdinalIgnoreCase)))
        {
            headers.Add(("Connection", "close"));
        }
    }

    var sb = new StringBuilder();
    sb.Append(method).Append(' ').Append(uri).Append(' ').Append(version).Append("\r\n");
    foreach (var (name, value) in headers)
    {
        sb.Append(name).Append(": ").Append(value).Append("\r\n");
    }

    sb.Append("\r\n");
    return [.. Encoding.UTF8.GetBytes(sb.ToString()), .. body];
}

static async Task<(int Status, string? Error)> SendAsync(Uri address, byte[] request)
{
    try
    {
        using var client = new TcpClient();
        await client.ConnectAsync(address.Host, address.Port);
        using var stream = client.GetStream();
        await stream.WriteAsync(request);
        await stream.FlushAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var response = new MemoryStream();
        var buffer = new byte[8192];
        int read;
        try
        {
            while ((read = await stream.ReadAsync(buffer, cts.Token)) > 0)
            {
                response.Write(buffer, 0, read);
                if (HasCompleteHeaders(response))
                {
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException)
        {
            if (response.Length == 0)
            {
                return (0, ex.GetType().Name);
            }
        }

        var text = Encoding.Latin1.GetString(response.ToArray());
        var parts = text.Split(' ', 3);
        return parts.Length >= 2 && int.TryParse(parts[1], out var status) ? (status, null) : (0, "no status line");
    }
    catch (Exception ex) when (ex is IOException or SocketException)
    {
        return (0, ex.GetType().Name);
    }
}

// albedo /reflect: the request body is JSON {"status": n, "headers": {..}, "body": "..", "encodedBody": "base64"}.
static async Task ReflectAsync(HttpContext ctx, byte[] json)
{
    using var doc = System.Text.Json.JsonDocument.Parse(json);
    var root = doc.RootElement;
    if (root.TryGetProperty("status", out var status) && status.TryGetInt32(out var code))
    {
        ctx.Response.StatusCode = code;
    }

    if (root.TryGetProperty("headers", out var headers) && headers.ValueKind == System.Text.Json.JsonValueKind.Object)
    {
        foreach (var h in headers.EnumerateObject())
        {
            ctx.Response.Headers[h.Name] = h.Value.ToString();
        }
    }

    if (root.TryGetProperty("encodedBody", out var encoded) && encoded.GetString() is { Length: > 0 } b64)
    {
        await ctx.Response.Body.WriteAsync(Convert.FromBase64String(b64));
    }
    else if (root.TryGetProperty("body", out var body) && body.GetString() is { } text)
    {
        await ctx.Response.WriteAsync(text);
    }
}

static bool HasCompleteHeaders(MemoryStream ms)
{
    var buf = ms.GetBuffer().AsSpan(0, (int)ms.Length);
    return buf.IndexOf("\r\n\r\n"u8) >= 0;
}

static Dictionary<string, Dictionary<object, object>> LoadOverrides(string path)
{
    var result = new Dictionary<string, Dictionary<object, object>>(StringComparer.Ordinal);
    var doc = new DeserializerBuilder().Build().Deserialize<Dictionary<object, object>>(File.ReadAllText(path));
    foreach (Dictionary<object, object> o in (List<object>)doc["test_overrides"])
    {
        if (!o.TryGetValue("output", out var output))
        {
            // Coraza marks these as known failures without a replacement expectation; run the original test.
            continue;
        }

        var ruleId = o["rule_id"].ToString();
        foreach (var id in (List<object>)o["test_ids"])
        {
            result[$"{ruleId}-{id}"] = (Dictionary<object, object>)output;
        }
    }

    return result;
}

static int ToInt(object o) => Convert.ToInt32(o, System.Globalization.CultureInfo.InvariantCulture);

static bool IsTrue(object? o) => o is not null && bool.TryParse(o.ToString(), out var b) && b;

static string? ArgValue(string[] args, string name)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}
