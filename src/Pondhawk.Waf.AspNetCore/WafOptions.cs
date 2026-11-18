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

    /// <summary>CRS paranoia level 1-4 (tx.blocking_paranoia_level). Higher catches more and has more false positives.</summary>
    public int ParanoiaLevel { get; set; } = 1;

    /// <summary>CRS inbound anomaly score threshold (tx.inbound_anomaly_score_threshold). Default 5: one critical match blocks.</summary>
    public int InboundAnomalyScoreThreshold { get; set; } = 5;

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
