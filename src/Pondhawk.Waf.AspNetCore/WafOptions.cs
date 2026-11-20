using Microsoft.AspNetCore.Http;
using Pondhawk.Waf.CoreRuleSet;

namespace Pondhawk.Waf.AspNetCore;

/// <summary>Options for <see cref="WafMiddleware"/>.</summary>
public sealed class WafOptions
{
    /// <summary>Load the embedded OWASP Core Rule Set and the Pondhawk base configuration. Default true.</summary>
    public bool UseCoreRuleSet { get; set; } = true;

    /// <summary>
    /// Overrides SecRuleEngine. Null keeps the configuration's value (DetectionOnly in the base configuration).
    /// </summary>
    public RuleEngineMode? RuleEngine { get; set; }

    /// <summary>
    /// Pre-selected security/performance settings. Default <see cref="WafProfile.Balanced"/>. The options below
    /// override single values of the profile when set. <see cref="RuleEngine"/> is not part of a profile.
    /// </summary>
    public WafProfile Profile { get; set; } = WafProfile.Balanced;

    /// <summary>CRS blocking paranoia level 1-4. Higher catches more and has more false positives. Null: from the profile.</summary>
    public int? ParanoiaLevel { get; set; }

    /// <summary>
    /// CRS detection paranoia level 1-4: rules above <see cref="ParanoiaLevel"/> up to this level log but do not block.
    /// Null: from the profile, raised to <see cref="ParanoiaLevel"/> when that is higher.
    /// </summary>
    public int? DetectionParanoiaLevel { get; set; }

    /// <summary>Request anomaly score that blocks (critical match = 5). Null: from the profile.</summary>
    public int? InboundAnomalyScoreThreshold { get; set; }

    /// <summary>Response anomaly score that blocks (error-level leak = 4). Null: from the profile.</summary>
    public int? OutboundAnomalyScoreThreshold { get; set; }

    /// <summary>Hold and inspect response bodies (phases 3-4 on the body). Null: from the profile.</summary>
    public bool? InspectResponses { get; set; }

    /// <summary>Response MIME types that are held and inspected. Null: from the profile.</summary>
    public IReadOnlyList<string>? ResponseMimeTypes { get; set; }

    /// <summary>Response bytes held and inspected; the rest of a larger response is not inspected. Null: from the profile.</summary>
    public long? ResponseBodyLimit { get; set; }

    /// <summary>Largest request body; larger bodies are rejected with 413. Null: from the profile.</summary>
    public long? RequestBodyLimit { get; set; }

    /// <summary>Most arguments per request; more are rejected with 400. Null: from the profile.</summary>
    public int? ArgumentsLimit { get; set; }

    /// <summary>
    /// Largest request body without files (URL-encoded, JSON, XML, and the form fields of a multipart body); larger
    /// bodies are rejected with 413. Every rule runs over these bytes, so this limit bounds the CPU time of one request.
    /// Null: from the profile.
    /// </summary>
    public long? RequestBodyNoFilesLimit { get; set; }

    /// <summary>Returns the effective settings: the profile with the options above applied. Validates them.</summary>
    public WafSettings Resolve()
    {
        var p = WafSettings.For(Profile);
        var paranoia = ParanoiaLevel ?? p.ParanoiaLevel;
        var settings = new WafSettings(
            paranoia,
            DetectionParanoiaLevel ?? Math.Max(p.DetectionParanoiaLevel, paranoia),
            InboundAnomalyScoreThreshold ?? p.InboundAnomalyScoreThreshold,
            OutboundAnomalyScoreThreshold ?? p.OutboundAnomalyScoreThreshold,
            InspectResponses ?? p.InspectResponses,
            ResponseMimeTypes ?? p.ResponseMimeTypes,
            ResponseBodyLimit ?? p.ResponseBodyLimit,
            RequestBodyLimit ?? p.RequestBodyLimit,
            ArgumentsLimit ?? p.ArgumentsLimit,
            RequestBodyNoFilesLimit ?? p.RequestBodyNoFilesLimit);
        settings.Validate();
        return settings;
    }

    /// <summary>
    /// Official CRS rule exclusion plugins to load, for example <see cref="CrsPlugin.WordPress"/>. Each removes the
    /// false positives of one application on that application's paths. Needs <see cref="UseCoreRuleSet"/>.
    /// </summary>
    public List<CrsPlugin> Plugins { get; } = [];

    /// <summary>
    /// Rule exclusions for false positives. Prefer the helpers (<see cref="RemoveRule"/>, <see cref="Exclude(int, string, string?)"/> and
    /// the others) in code; bind this list from configuration. Validated when the engine is built.
    /// </summary>
    public List<WafExclusion> Exclusions { get; } = [];

    /// <summary>Turns off a rule for all requests, or for <paramref name="path"/> and the paths below it.</summary>
    public WafOptions RemoveRule(int ruleId, string? path = null) =>
        Add(new WafExclusion { Rule = ruleId.ToString(System.Globalization.CultureInfo.InvariantCulture), Path = path });

    /// <summary>Turns off the rules <paramref name="firstRuleId"/> to <paramref name="lastRuleId"/> (inclusive).</summary>
    public WafOptions RemoveRules(int firstRuleId, int lastRuleId, string? path = null) =>
        Add(new WafExclusion { Rule = string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{firstRuleId}-{lastRuleId}"), Path = path });

    /// <summary>Turns off the rules with a tag, for example <c>attack-sqli</c>.</summary>
    public WafOptions RemoveRulesByTag(string tag, string? path = null) =>
        Add(new WafExclusion { Tag = tag, Path = path });

    /// <summary>
    /// Stops a rule from inspecting one target, for example <c>Exclude(942100, "ARGS:password", path: "/login")</c>.
    /// The rule still inspects everything else.
    /// </summary>
    public WafOptions Exclude(int ruleId, string target, string? path = null) =>
        Add(new WafExclusion { Rule = ruleId.ToString(System.Globalization.CultureInfo.InvariantCulture), Target = target, Path = path });

    /// <summary>Stops the rules <paramref name="firstRuleId"/> to <paramref name="lastRuleId"/> from inspecting one target.</summary>
    public WafOptions Exclude(int firstRuleId, int lastRuleId, string target, string? path = null) =>
        Add(new WafExclusion { Rule = string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{firstRuleId}-{lastRuleId}"), Target = target, Path = path });

    /// <summary>Stops the rules with a tag from inspecting one target.</summary>
    public WafOptions ExcludeByTag(string tag, string target, string? path = null) =>
        Add(new WafExclusion { Tag = tag, Target = target, Path = path });

    private WafOptions Add(WafExclusion exclusion)
    {
        exclusion.Validate();
        Exclusions.Add(exclusion);
        return this;
    }

    /// <summary>SecLang loaded after the CRS setup and before the CRS rules: SecAction tuning, ctl-based exclusions.</summary>
    public string? Directives { get; set; }

    /// <summary>SecLang loaded after the CRS rules: SecRuleRemoveById, SecRuleUpdateTargetById.</summary>
    public string? DirectivesAfterRules { get; set; }

    /// <summary>
    /// SecLang files loaded after <see cref="DirectivesAfterRules"/>, from the local file system. Relative paths here,
    /// and in Include and @pmFromFile in the directives, resolve against the application's content root.
    /// </summary>
    public List<string> RuleFiles { get; } = [];

    /// <summary>Requests for which this returns true skip the WAF (e.g. health checks). Keep it narrow.</summary>
    public Func<HttpContext, bool>? Bypass { get; set; }

    /// <summary>
    /// In DetectionOnly, hold inspected response bodies until phase 4 as SecRuleEngine On does. Default false: a response
    /// that cannot be blocked streams to the client as it is written, and a copy is inspected. Turn it on to measure
    /// the latency and memory that switching to On will add.
    /// </summary>
    public bool HoldResponsesInDetectionOnly { get; set; }

    /// <summary>
    /// After the regex automata are built (in the background, see <see cref="WafEngine.Compiled"/>), run synthetic
    /// requests so the first real requests do not pay for building DFA states. Runs in the background; startup does not
    /// wait. Default true.
    /// </summary>
    public bool WarmUp { get; set; } = true;

    /// <summary>
    /// Rebuild the engine when the options change, for example when appsettings.json bound with
    /// <c>AddPondhawkWaf(IConfiguration)</c> is edited. Requests in flight finish on the old engine; a configuration
    /// that fails to build is logged and the old engine stays. Changes to <see cref="RuleFiles"/> on disk are not
    /// watched. Default true.
    /// </summary>
    public bool ReloadOnChange { get; set; } = true;

    /// <summary>Configures the engine further after the options above are applied.</summary>
    public Action<WafBuilder>? Configure { get; set; }
}
