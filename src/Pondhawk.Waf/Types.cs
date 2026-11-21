namespace Pondhawk.Waf;

/// <summary>SecRuleEngine.</summary>
public enum RuleEngineMode
{
    /// <summary>Rules run and disruptive actions are enforced.</summary>
    On,

    /// <summary>Rules run and matches are logged, but no request is blocked.</summary>
    DetectionOnly,

    /// <summary>Rules do not run.</summary>
    Off,
}

/// <summary>The regex engine for @rx patterns. The trade-off is memory against a time bound per match.</summary>
public enum RegexEngine
{
    /// <summary>
    /// Linear-time matching (<c>RegexOptions.NonBacktracking</c>): no input can make a match slow. The automata of the
    /// Core Rule Set hold about 500 MB for the life of the process. Patterns that need backtracking (lookarounds,
    /// backreferences) use <see cref="Backtracking"/>.
    /// </summary>
    NonBacktracking,

    /// <summary>
    /// The backtracking engine (<c>RegexOptions.Compiled</c>) with a timeout per match (<see cref="WafBuilder.RegexTimeout"/>,
    /// default 250 ms). The Core Rule Set holds about 16 MB. A crafted input can make one match take up to the timeout; a
    /// match that times out counts as a match and is reported (<see cref="WafConfig.RegexTimeoutCallback"/>). For small hosts.
    /// </summary>
    Backtracking,
}

/// <summary>An @rx match that ran out of time and so counted as a match.</summary>
/// <param name="RuleId">The rule id (the chain's id for a chained rule).</param>
/// <param name="Variable">The variable, e.g. ARGS:q.</param>
/// <param name="ValueLength">Length of the inspected value, after transformations.</param>
/// <param name="Timeout">The timeout that ran out.</param>
public sealed record RegexTimeout(int RuleId, string Variable, int ValueLength, TimeSpan Timeout);

/// <summary>SecAuditEngine.</summary>
public enum AuditEngineMode
{
    Off,
    On,
    RelevantOnly,
}

/// <summary>What to do when a request body exceeds SecRequestBodyLimit.</summary>
public enum BodyLimitAction
{
    /// <summary>Reject the request with 413.</summary>
    Reject,

    /// <summary>Inspect only the first SecRequestBodyLimit bytes.</summary>
    ProcessPartial,
}

/// <summary>Scope of the allow action.</summary>
public enum AllowType
{
    Unset,
    Phase,
    Request,
    All,
}

/// <summary>A decision to stop the transaction.</summary>
/// <param name="RuleId">The rule that interrupted.</param>
/// <param name="Action">deny, drop or redirect.</param>
/// <param name="Status">The HTTP status to return.</param>
/// <param name="Data">The redirect target, for redirect.</param>
public sealed record Interruption(int RuleId, string Action, int Status, string? Data);

/// <summary>Processing phases.</summary>
public static class Phases
{
    public const int RequestHeaders = 1;
    public const int RequestBody = 2;
    public const int ResponseHeaders = 3;
    public const int ResponseBody = 4;
    public const int Logging = 5;
}
