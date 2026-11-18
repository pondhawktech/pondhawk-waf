using Microsoft.AspNetCore.Http;

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

    /// <summary>SecLang loaded after the CRS setup and before the CRS rules: SecAction tuning, ctl-based exclusions.</summary>
    public string? Directives { get; set; }

    /// <summary>SecLang loaded after the CRS rules: SecRuleRemoveById, SecRuleUpdateTargetById.</summary>
    public string? DirectivesAfterRules { get; set; }

    /// <summary>SecLang files loaded after <see cref="DirectivesAfterRules"/>, from the local file system.</summary>
    public List<string> RuleFiles { get; } = [];

    /// <summary>Requests for which this returns true skip the WAF (e.g. health checks). Keep it narrow.</summary>
    public Func<HttpContext, bool>? Bypass { get; set; }

    /// <summary>
    /// Run synthetic requests at startup so the first real requests do not pay for regex compilation. Default true.
    /// </summary>
    public bool WarmUp { get; set; } = true;

    /// <summary>Configures the engine further after the options above are applied.</summary>
    public Action<WafBuilder>? Configure { get; set; }
}
