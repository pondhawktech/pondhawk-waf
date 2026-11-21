using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Pondhawk.Waf.AspNetCore;

/// <summary>
/// WAF metrics on the <c>Pondhawk.Waf</c> meter (<see cref="MeterName"/>). Collect them with OpenTelemetry
/// (<c>.WithMetrics(m =&gt; m.AddMeter("Pondhawk.Waf"))</c>), dotnet-counters or any <see cref="MeterListener"/>.
/// </summary>
/// <remarks>
/// <list type="table">
/// <item><term>pondhawk.waf.requests</term><description>Requests, by <c>waf.result</c>: allowed, blocked, detected
/// (DetectionOnly would have blocked), bypassed (<see cref="WafOptions.Bypass"/>), off (rule engine Off).</description></item>
/// <item><term>pondhawk.waf.blocks</term><description>Blocked requests, by <c>waf.rule.id</c>, <c>waf.action</c> and
/// <c>http.response.status_code</c>.</description></item>
/// <item><term>pondhawk.waf.would_block</term><description>Requests DetectionOnly would have blocked, by the same tags.
/// Watch it before switching to On.</description></item>
/// <item><term>pondhawk.waf.rule.matches</term><description>Matches of rules that log, by <c>waf.rule.id</c>. Use it to
/// find false positives when tuning.</description></item>
/// <item><term>pondhawk.waf.phase.duration</term><description>Histogram, seconds, by <c>waf.phase</c>: request_headers,
/// request_body, response_headers, response_body, logging. WAF processing only, not network waits.</description></item>
/// <item><term>pondhawk.waf.log_failures</term><description>Rule log or audit log writes that threw.</description></item>
/// <item><term>pondhawk.waf.reloads</term><description>Configuration reloads, by <c>waf.result</c>: success, failure.</description></item>
/// <item><term>pondhawk.waf.regex_timeouts</term><description>Regex matches that ran out of time and counted as matches,
/// by <c>waf.rule.id</c>. Should stay at 0; see <see cref="WafOptions.RegexTimeout"/>.</description></item>
/// </list>
/// </remarks>
public sealed class WafMetrics
{
    /// <summary>The meter name.</summary>
    public const string MeterName = "Pondhawk.Waf";

    private static readonly string[] PhaseNames = ["", "request_headers", "request_body", "response_headers", "response_body", "logging"];

    private readonly Counter<long> _requests;
    private readonly Counter<long> _blocks;
    private readonly Counter<long> _wouldBlock;
    private readonly Counter<long> _matches;
    private readonly Histogram<double> _phaseDuration;
    private readonly Counter<long> _logFailures;
    private readonly Counter<long> _reloads;
    private readonly Counter<long> _regexTimeouts;

    public WafMetrics(IMeterFactory meterFactory)
    {
        ArgumentNullException.ThrowIfNull(meterFactory);
        var meter = meterFactory.Create(MeterName, typeof(WafMetrics).Assembly.GetName().Version?.ToString(3));
        _requests = meter.CreateCounter<long>("pondhawk.waf.requests", "{request}", "Requests seen by the WAF.");
        _blocks = meter.CreateCounter<long>("pondhawk.waf.blocks", "{request}", "Requests blocked by a rule.");
        _wouldBlock = meter.CreateCounter<long>("pondhawk.waf.would_block", "{request}", "Requests that DetectionOnly would have blocked.");
        _matches = meter.CreateCounter<long>("pondhawk.waf.rule.matches", "{match}", "Matches of rules that log.");
        _phaseDuration = meter.CreateHistogram("pondhawk.waf.phase.duration", "s", "WAF processing time per phase.",
            advice: new InstrumentAdvice<double>
            {
                HistogramBucketBoundaries = [0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1],
            });
        _logFailures = meter.CreateCounter<long>("pondhawk.waf.log_failures", "{failure}", "Rule log or audit log writes that threw.");
        _reloads = meter.CreateCounter<long>("pondhawk.waf.reloads", "{reload}", "Configuration reloads.");
        _regexTimeouts = meter.CreateCounter<long>("pondhawk.waf.regex_timeouts", "{timeout}", "Regex matches that ran out of time and counted as matches.");
    }

    internal void Bypassed() => _requests.Add(1, new KeyValuePair<string, object?>("waf.result", "bypassed"));

    internal void LogFailure() => _logFailures.Add(1);

    internal void RegexTimeout(int ruleId) => _regexTimeouts.Add(1, new KeyValuePair<string, object?>("waf.rule.id", ruleId));

    internal void Reload(bool success) => _reloads.Add(1, new KeyValuePair<string, object?>("waf.result", success ? "success" : "failure"));

    /// <summary>Records a finished transaction.</summary>
    internal void Completed(Transaction tx)
    {
        string result;
        if (tx.IsRuleEngineOff)
        {
            result = "off";
        }
        else if (tx.Interruption is { } it)
        {
            result = "blocked";
            _blocks.Add(1, InterruptionTags(it));
        }
        else if (tx.DetectionOnlyInterruption is { } would)
        {
            result = "detected";
            _wouldBlock.Add(1, InterruptionTags(would));
        }
        else
        {
            result = "allowed";
        }

        _requests.Add(1, new KeyValuePair<string, object?>("waf.result", result));

        if (_matches.Enabled)
        {
            foreach (var m in tx.MatchedRules)
            {
                if (m.Rule.Log)
                {
                    _matches.Add(1, new KeyValuePair<string, object?>("waf.rule.id", m.Rule.LogId));
                }
            }
        }

        if (_phaseDuration.Enabled)
        {
            for (var phase = Phases.RequestHeaders; phase <= Phases.Logging; phase++)
            {
                var elapsed = tx.PhaseDuration(phase);
                if (elapsed > TimeSpan.Zero)
                {
                    _phaseDuration.Record(elapsed.TotalSeconds, new KeyValuePair<string, object?>("waf.phase", PhaseNames[phase]));
                }
            }
        }
    }

    private static TagList InterruptionTags(Interruption it) => new()
    {
        { "waf.rule.id", it.RuleId },
        { "waf.action", it.Action },
        { "http.response.status_code", it.Status },
    };
}
