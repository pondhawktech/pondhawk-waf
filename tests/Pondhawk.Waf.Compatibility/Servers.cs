using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;

namespace Pondhawk.Waf.Compatibility;

/// <summary>Starts the backend, the baseline (no WAF) and one app per WAF setup, once for all tests.</summary>
public sealed class Servers : IAsyncLifetime
{
    private readonly Dictionary<WafSetup, WebApplication> _apps = [];
    private WebApplication _backend = null!;

    public HttpClient Client { get; } = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        AutomaticDecompression = DecompressionMethods.None,
        UseCookies = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(1),
    })
    { Timeout = TimeSpan.FromSeconds(60) };

    public Uri Address(WafSetup setup) => CompatibilityApp.Address(_apps[setup]);

    public async Task InitializeAsync()
    {
        _backend = await Backend.StartAsync();
        foreach (var setup in Enum.GetValues<WafSetup>())
        {
            _apps[setup] = await CompatibilityApp.StartAsync(setup, Backend.Address(_backend));
        }
    }

    public async Task DisposeAsync()
    {
        Client.Dispose();
        foreach (var app in _apps.Values)
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }

        await _backend.StopAsync();
        await _backend.DisposeAsync();
    }

    /// <summary>A request a browser could send: the CRS treats a request without these headers as suspicious.</summary>
    public static HttpRequestMessage Request(HttpMethod method, Uri server, string path, HttpContent? content = null)
    {
        var request = new HttpRequestMessage(method, new Uri(server, path)) { Content = content };
        request.Headers.Host = "localhost";
        request.Headers.UserAgent.ParseAdd("Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0");
        request.Headers.Accept.ParseAdd("*/*");
        return request;
    }

    /// <summary>Sends a request and reads the whole response. A connection reset becomes <see cref="Outcome.Aborted"/>.</summary>
    public async Task<Outcome> SendAsync(HttpRequestMessage request)
    {
        try
        {
            using var response = await Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
            var body = await response.Content.ReadAsByteArrayAsync();
            return Outcome.From(response, body);
        }
        catch (HttpRequestException)
        {
            return Outcome.Aborted;
        }
        catch (IOException)
        {
            return Outcome.Aborted;
        }
    }
}

[CollectionDefinition(Name)]
public sealed class ServersCollection : ICollectionFixture<Servers>
{
    public const string Name = "Servers";
}

/// <summary>
/// What the client got, normalized for comparison: Date dropped, cookie values and Age replaced by placeholders, a
/// compressed body decompressed, the trace id in problem details replaced. Framing (Content-Length or chunked) is part
/// of the comparison.
/// </summary>
public sealed partial record Outcome(string Text)
{
    public static readonly Outcome Aborted = new("aborted (connection reset before the response completed)");

    public static Outcome From(HttpResponseMessage response, byte[] body)
    {
        var sb = new StringBuilder();
        sb.Append((int)response.StatusCode).Append(' ').AppendLine(response.ReasonPhrase);
        var headers = response.Headers.Concat(response.Content.Headers)
            .Where(h => !h.Key.Equals("Date", StringComparison.OrdinalIgnoreCase))
            .SelectMany(h => h.Value.Select(v => (Name: h.Key.ToLowerInvariant(), Value: Normalize(h.Key, v))))
            .OrderBy(h => h.Name, StringComparer.Ordinal)
            .ThenBy(h => h.Value, StringComparer.Ordinal);
        foreach (var (name, value) in headers)
        {
            sb.Append(name).Append(": ").AppendLine(value);
        }

        var decoded = Decode(response.Content.Headers.ContentEncoding, body);
        if (response.Content.Headers.ContentType?.MediaType == "application/problem+json")
        {
            // Problem details carry the request's trace id.
            decoded = Encoding.UTF8.GetBytes(TraceId().Replace(Encoding.UTF8.GetString(decoded), "\"traceId\":\"<trace>\""));
        }

        sb.Append("body: ").Append(decoded.Length).Append(" bytes, sha256 ").AppendLine(Convert.ToHexStringLower(SHA256.HashData(decoded)));
        sb.Append(Encoding.UTF8.GetString(decoded.AsSpan(0, Math.Min(decoded.Length, 300))));
        return new Outcome(sb.ToString());
    }

    public override string ToString() => Text;

    [System.Text.RegularExpressions.GeneratedRegex("\"traceId\":\"[^\"]*\"")]
    private static partial System.Text.RegularExpressions.Regex TraceId();

    private static string Normalize(string name, string value) => name.ToLowerInvariant() switch
    {
        "set-cookie" => value[..value.IndexOf('=', StringComparison.Ordinal)] + "=<value>" + (value.IndexOf(';', StringComparison.Ordinal) is var i and >= 0 ? value[i..] : string.Empty),
        "age" => "<age>",
        _ => value,
    };

    private static byte[] Decode(ICollection<string> encodings, byte[] body)
    {
        if (encodings.Count == 0 || body.Length == 0 || encodings.Last() == "identity")
        {
            return body;
        }

        using var input = new MemoryStream(body);
        using Stream decoder = encodings.Last() switch
        {
            "gzip" => new GZipStream(input, CompressionMode.Decompress),
            "br" => new BrotliStream(input, CompressionMode.Decompress),
            var other => throw new NotSupportedException($"Content-Encoding {other}"),
        };
        using var output = new MemoryStream();
        decoder.CopyTo(output);
        return output.ToArray();
    }
}
