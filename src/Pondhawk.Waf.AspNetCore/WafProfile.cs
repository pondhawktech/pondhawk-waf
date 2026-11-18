namespace Pondhawk.Waf.AspNetCore;

/// <summary>Pre-selected security/performance settings. Options set explicitly in <see cref="WafOptions"/> override them.</summary>
public enum WafProfile
{
    /// <summary>
    /// Lowest latency: CRS paranoia level 1, no response inspection, no log-only rules. Request-side protection is the
    /// same as <see cref="Balanced"/>.
    /// </summary>
    Performance,

    /// <summary>
    /// The default: paranoia level 1 blocking, level 2 log-only, text and JSON responses inspected. Few false
    /// positives; suits most applications.
    /// </summary>
    Balanced,

    /// <summary>
    /// Paranoia level 2 blocking, level 3 log-only, XML responses also inspected, tighter limits. Expect to add
    /// exclusions during a DetectionOnly period.
    /// </summary>
    Strict,

    /// <summary>
    /// Paranoia level 3 blocking, level 4 log-only, lower anomaly thresholds, tight limits. For high-risk
    /// applications with time to tune false positives.
    /// </summary>
    Paranoid,
}

/// <summary>The effective settings of a profile, or of a profile with option overrides applied.</summary>
/// <param name="ParanoiaLevel">CRS blocking paranoia level (tx.blocking_paranoia_level), 1-4.</param>
/// <param name="DetectionParanoiaLevel">CRS detection paranoia level (tx.detection_paranoia_level): rules above the
/// blocking level up to this level run and log, but add no blocking score. Not lower than <paramref name="ParanoiaLevel"/>.</param>
/// <param name="InboundAnomalyScoreThreshold">Request anomaly score that blocks (critical = 5, error = 4, warning = 3).</param>
/// <param name="OutboundAnomalyScoreThreshold">Response anomaly score that blocks.</param>
/// <param name="InspectResponses">Hold and inspect response bodies of <paramref name="ResponseMimeTypes"/>.</param>
/// <param name="ResponseMimeTypes">Response MIME types that are held and inspected.</param>
/// <param name="ResponseBodyLimit">Response bytes held and inspected; larger responses are inspected partially.</param>
/// <param name="RequestBodyLimit">Largest request body; larger bodies are rejected with 413.</param>
/// <param name="ArgumentsLimit">Most arguments per request; more are rejected with 400.</param>
public sealed record WafSettings(
    int ParanoiaLevel,
    int DetectionParanoiaLevel,
    int InboundAnomalyScoreThreshold,
    int OutboundAnomalyScoreThreshold,
    bool InspectResponses,
    IReadOnlyList<string> ResponseMimeTypes,
    long ResponseBodyLimit,
    long RequestBodyLimit,
    int ArgumentsLimit)
{
    private static readonly string[] TextAndJson =
        ["text/plain", "text/html", "text/xml", "application/json", "application/problem+json"];

    private static readonly string[] TextJsonAndXml =
        [.. TextAndJson, "application/xml", "application/problem+xml"];

    /// <summary>The settings of a profile.</summary>
    public static WafSettings For(WafProfile profile) => profile switch
    {
        WafProfile.Performance => new(1, 1, 5, 4, false, TextAndJson, 524_288, 13_107_200, 1000),
        WafProfile.Balanced => new(1, 2, 5, 4, true, TextAndJson, 524_288, 13_107_200, 1000),
        WafProfile.Strict => new(2, 3, 5, 4, true, TextJsonAndXml, 1_048_576, 8_388_608, 500),
        WafProfile.Paranoid => new(3, 4, 3, 3, true, TextJsonAndXml, 1_048_576, 4_194_304, 255),
        _ => throw new ArgumentOutOfRangeException(nameof(profile), profile, "Unknown WAF profile."),
    };

    /// <summary>Throws when a value is out of range.</summary>
    public void Validate()
    {
        if (ParanoiaLevel is < 1 or > 4)
        {
            throw new ArgumentOutOfRangeException(nameof(ParanoiaLevel), ParanoiaLevel, "ParanoiaLevel must be 1-4.");
        }

        if (DetectionParanoiaLevel is < 1 or > 4 || DetectionParanoiaLevel < ParanoiaLevel)
        {
            throw new ArgumentOutOfRangeException(nameof(DetectionParanoiaLevel), DetectionParanoiaLevel,
                "DetectionParanoiaLevel must be 1-4 and not lower than ParanoiaLevel.");
        }

        if (InboundAnomalyScoreThreshold < 1 || OutboundAnomalyScoreThreshold < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(InboundAnomalyScoreThreshold), "Anomaly score thresholds must be at least 1.");
        }

        if (ResponseBodyLimit < 1 || RequestBodyLimit < 1 || ArgumentsLimit < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(RequestBodyLimit), "Limits must be at least 1.");
        }

        if (InspectResponses && ResponseMimeTypes.Count == 0)
        {
            throw new ArgumentException("InspectResponses needs at least one response MIME type.", nameof(ResponseMimeTypes));
        }

        foreach (var type in ResponseMimeTypes)
        {
            if (string.IsNullOrWhiteSpace(type) || type.Any(char.IsWhiteSpace))
            {
                throw new ArgumentException($"Invalid response MIME type '{type}'.", nameof(ResponseMimeTypes));
            }
        }
    }
}
