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

    /// <summary>Called each time <see cref="ErrorCallback"/> or the audit log writer throws (see <see cref="WafEngine.LogFailures"/>).</summary>
    public Action? LogFailureCallback { get; set; }

    public string? TempDirectory { get; set; }

    public List<string> ComponentSignatures { get; } = [];
}

/// <summary>A compiled rule set plus configuration. Thread-safe; create one per application and a transaction per request.</summary>
public sealed class WafEngine
{
    private readonly List<Rule> _rules;
    private long _counter;

    internal WafEngine(WafConfig config, List<Rule> rules, bool fillsRuleCollection = true)
    {
        Config = config;
        _rules = rules;
        FillsRuleCollection = fillsRuleCollection;
    }

    /// <summary>False when no rule reads the RULE collection, so rules skip filling it.</summary>
    internal bool FillsRuleCollection { get; }

    /// <summary>Working memory reused by transactions.</summary>
    internal EvaluationScratchPool ScratchPool { get; } = new();

    /// <summary>
    /// Completes when every @rx automaton is built. The engine is usable before: a rule whose regex is not built yet
    /// builds it (or waits for it) on first use. Await it to take that cost before serving traffic.
    /// </summary>
    public Task Compiled { get; internal set; } = Task.CompletedTask;

    public WafConfig Config { get; }

    private long _logFailures;

    /// <summary>
    /// Times a log sink threw: the error callback, or the audit log writer as reported by the host. The WAF ignores these
    /// failures so that a broken log sink does not fail requests; monitor this count instead.
    /// </summary>
    public long LogFailures => Interlocked.Read(ref _logFailures);

    /// <summary>Counts a log sink failure. Hosts call it when the audit log writer throws in <see cref="Transaction.ProcessLogging"/>.</summary>
    public void RecordLogFailure()
    {
        Interlocked.Increment(ref _logFailures);
        try
        {
            Config.LogFailureCallback?.Invoke();
        }
#pragma warning disable CA1031 // Counting a failure must not fail the request.
        catch (Exception)
#pragma warning restore CA1031
        {
        }
    }

    /// <summary>Top-level rules in evaluation order (chain links hang off <see cref="Rule.Chain"/>).</summary>
    public IReadOnlyList<Rule> Rules => _rules;

    /// <summary>Starts a transaction. The id becomes UNIQUE_ID.</summary>
    public Transaction NewTransaction(string? id = null)
    {
        id ??= GenerateId();
        return new Transaction(this, id);
    }

    /// <summary>
    /// Waits for <see cref="Compiled"/>, then runs a few synthetic requests through the rules so the DFA states that
    /// typical traffic needs exist before real traffic. Matches from these requests are not logged. Safe to run while
    /// the engine serves requests.
    /// </summary>
    public void WarmUp()
    {
        Compiled.GetAwaiter().GetResult();
        string[] samples =
        [
            "q=hello+world&id=42&page=2",
            "name=O%27Brien&comment=%3Cb%3Ehi%3C%2Fb%3E+select+1&path=..%2Fetc&cmd=ls+-la",
        ];
        foreach (var body in samples)
        {
            using var tx = NewTransaction("warmup");
            tx.SuppressLogs = true;
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
    private readonly RegexCache _regexCache = new();

    public WafBuilder(IConfigFileSystem? fileSystem = null, WafConfig? config = null)
    {
        Config = config ?? new WafConfig();
        _parser = new SecLangParser(Config, fileSystem ?? PhysicalConfigFileSystem.Instance, _regexCache);
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

    /// <summary>
    /// Builds the engine. The @rx automata build in the background (<see cref="WafEngine.Compiled"/>); the engine is
    /// usable at once.
    /// </summary>
    public WafEngine Build()
    {
        var rules = _parser.Finish();
        var engine = new WafEngine(Config, rules, _parser.ReadsRuleCollection);
        var cache = _regexCache;
        engine.Compiled = Task.Run(cache.CompileAll);
        return engine;
    }
}
