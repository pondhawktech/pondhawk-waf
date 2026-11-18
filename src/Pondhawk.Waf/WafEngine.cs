using System.Text.RegularExpressions;
using Pondhawk.Waf.AuditLog;
using Pondhawk.Waf.Operators;
using Pondhawk.Waf.Rules;
using Pondhawk.Waf.SecLang;

namespace Pondhawk.Waf;

/// <summary>Engine settings. Directives (SecRuleEngine, SecRequestBodyLimit, ...) change them while rules load.</summary>
public sealed class WafConfig
{
    public RuleEngineMode RuleEngine { get; set; } = RuleEngineMode.DetectionOnly;

    public bool RequestBodyAccess { get; set; }

    /// <summary>Maximum request body size in bytes (SecRequestBodyLimit). Default 13 MiB, as Coraza recommends.</summary>
    public long RequestBodyLimit { get; set; } = 13_107_200;

    /// <summary>
    /// Maximum size in bytes of a request body without files (SecRequestBodyNoFilesLimit): URL-encoded, JSON, XML and
    /// raw bodies, and the form fields of a multipart body. Every rule runs over these bytes, so they cost far more to
    /// inspect than file content. 0 means only <see cref="RequestBodyLimit"/> applies.
    /// </summary>
    public long RequestBodyNoFilesLimit { get; set; } = 1_048_576;

    /// <summary>Bytes kept in memory before the body spills to a temporary file.</summary>
    public long RequestBodyInMemoryLimit { get; set; } = 131_072;

    public BodyLimitAction RequestBodyLimitAction { get; set; } = BodyLimitAction.Reject;

    public int RequestBodyJsonDepthLimit { get; set; } = 1024;

    /// <summary>Maximum number of arguments per collection (SecArgumentsLimit). 0 means unlimited.</summary>
    public int ArgumentsLimit { get; set; } = 1000;

    public bool ResponseBodyAccess { get; set; }

    public long ResponseBodyLimit { get; set; } = 524_288;

    public BodyLimitAction ResponseBodyLimitAction { get; set; } = BodyLimitAction.ProcessPartial;

    /// <summary>Response MIME types to inspect (SecResponseBodyMimeType).</summary>
    public List<string> ResponseBodyMimeTypes { get; } = ["text/html", "text/plain"];

    public AuditEngineMode AuditEngine { get; set; } = AuditEngineMode.Off;

    public string AuditLogParts { get; set; } = "ABIJDEFHZ";

    public Regex? AuditLogRelevantStatus { get; set; }

    public IAuditLogWriter? AuditLogWriter { get; set; }

    /// <summary>Called for every matched rule that has the log action (the ModSecurity error log).</summary>
    public Action<MatchedRule>? ErrorCallback { get; set; }

    public string? TempDirectory { get; set; }

    public List<string> ComponentSignatures { get; } = [];
}

/// <summary>A compiled rule set plus configuration. Thread-safe; create one per application and a transaction per request.</summary>
public sealed class WafEngine
{
    private readonly List<Rule> _rules;
    private long _counter;

    internal WafEngine(WafConfig config, List<Rule> rules)
    {
        Config = config;
        _rules = rules;
    }

    public WafConfig Config { get; }

    private long _logFailures;

    /// <summary>
    /// Times the error callback threw. Rule matching ignores these failures so that a broken log sink does not fail
    /// requests; monitor this count instead.
    /// </summary>
    public long LogFailures => Interlocked.Read(ref _logFailures);

    internal void RecordLogFailure() => Interlocked.Increment(ref _logFailures);

    /// <summary>Top-level rules in evaluation order (chain links hang off <see cref="Rule.Chain"/>).</summary>
    public IReadOnlyList<Rule> Rules => _rules;

    /// <summary>Starts a transaction. The id becomes UNIQUE_ID.</summary>
    public Transaction NewTransaction(string? id = null)
    {
        id ??= GenerateId();
        return new Transaction(this, id);
    }

    /// <summary>
    /// Runs a few synthetic requests through the rules so lazily built regex automata exist before real traffic.
    /// Matches from these requests are not logged.
    /// </summary>
    public void WarmUp()
    {
        var callback = Config.ErrorCallback;
        var writer = Config.AuditLogWriter;
        try
        {
            Config.ErrorCallback = null;
            Config.AuditLogWriter = null;
            string[] samples =
            [
                "q=hello+world&id=42&page=2",
                "name=O%27Brien&comment=%3Cb%3Ehi%3C%2Fb%3E+select+1&path=..%2Fetc&cmd=ls+-la",
            ];
            foreach (var body in samples)
            {
                using var tx = NewTransaction("warmup");
                tx.RuleEngine = RuleEngineMode.DetectionOnly;
                tx.ProcessConnection("127.0.0.1", 50000, "127.0.0.1", 80);
                tx.ProcessUri("/warmup/index.html?" + body, "POST", "HTTP/1.1");
                tx.AddRequestHeader("Host", "localhost");
                tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
                tx.AddRequestHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
                tx.AddRequestHeader("Cookie", "session=abc123; theme=dark");
                tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                tx.ProcessRequestHeaders();
                tx.WriteRequestBody(System.Text.Encoding.ASCII.GetBytes(body));
                tx.ProcessRequestBody();
                tx.ProcessResponseHeaders(200, "HTTP/1.1");
                tx.ProcessResponseBody();
                tx.ProcessLogging();
            }
        }
        finally
        {
            Config.ErrorCallback = callback;
            Config.AuditLogWriter = writer;
        }
    }

    /// <summary>Builds an engine from SecLang directives.</summary>
    public static WafEngine FromDirectives(string directives, IConfigFileSystem? fileSystem = null, WafConfig? config = null)
    {
        var builder = new WafBuilder(fileSystem ?? PhysicalConfigFileSystem.Instance, config);
        builder.AddDirectives(directives);
        return builder.Build();
    }

    private string GenerateId()
    {
        var n = Interlocked.Increment(ref _counter);
        return $"{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds():x}{n:x6}{Random.Shared.Next():x8}";
    }
}

/// <summary>Loads SecLang configuration into a new <see cref="WafEngine"/>.</summary>
public sealed class WafBuilder
{
    private readonly SecLangParser _parser;

    public WafBuilder(IConfigFileSystem? fileSystem = null, WafConfig? config = null)
    {
        Config = config ?? new WafConfig();
        _parser = new SecLangParser(Config, fileSystem ?? PhysicalConfigFileSystem.Instance, new RegexCache());
    }

    public WafConfig Config { get; }

    /// <summary>Parses directives. Relative Include paths resolve against <paramref name="baseDirectory"/>.</summary>
    public WafBuilder AddDirectives(string directives, string baseDirectory = "")
    {
        _parser.ParseString(directives, "<directives>", baseDirectory);
        return this;
    }

    public WafBuilder AddFile(string path)
    {
        _parser.ParseFile(path);
        return this;
    }

    public WafEngine Build() => new(Config, _parser.Finish());
}
