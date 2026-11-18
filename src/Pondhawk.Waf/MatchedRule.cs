using System.Text;
using Pondhawk.Waf.Rules;
using Pondhawk.Waf.Text;

namespace Pondhawk.Waf;

/// <summary>A rule that matched in a transaction.</summary>
public sealed class MatchedRule(
    Rule rule,
    string transactionId,
    string uri,
    string clientAddress,
    string hostname,
    string message,
    string data,
    IReadOnlyList<RuleMatch> matches,
    string? disruptiveAction,
    bool disruptive)
{
    public Rule Rule { get; } = rule;

    public string TransactionId { get; } = transactionId;

    public string Uri { get; } = uri;

    public string ClientAddress { get; } = clientAddress;

    public string Hostname { get; } = hostname;

    /// <summary>The expanded msg (byte string).</summary>
    public string Message { get; } = message;

    /// <summary>The expanded logdata (byte string).</summary>
    public string Data { get; } = data;

    public IReadOnlyList<RuleMatch> Matches { get; } = matches;

    /// <summary>The rule's disruptive action (deny, block, pass, ...), also in DetectionOnly mode.</summary>
    public string? DisruptiveAction { get; } = disruptiveAction;

    /// <summary>True when the disruptive action was enforced (SecRuleEngine On).</summary>
    public bool Disruptive { get; } = disruptive;

    /// <summary>A ModSecurity-style error log line.</summary>
    public string ErrorLogLine()
    {
        var sb = new StringBuilder();
        sb.Append("[client \"").Append(ClientAddress).Append("\"] ");
        sb.Append(Disruptive ? "Pondhawk WAF: Access denied" : "Pondhawk WAF: Warning");
        sb.Append(". ");
        if (Matches.Count > 0 && Matches[0].Match.Variable != Collections.Variable.Unknown)
        {
            sb.Append("Matched \"").Append(Escape(Matches[^1].Match.FullName)).Append("\". ");
        }

        Append(sb, "file", Rule.File);
        Append(sb, "line", Rule.Line.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Append(sb, "id", Rule.LogId.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Append(sb, "rev", Rule.Revision);
        Append(sb, "msg", Message);
        Append(sb, "data", Data);
        Append(sb, "severity", Rule.Severity == Severity.Unset ? string.Empty : Rule.Severity.ToString().ToLowerInvariant());
        Append(sb, "ver", Rule.Version);
        Append(sb, "maturity", Rule.Maturity.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Append(sb, "accuracy", Rule.Accuracy.ToString(System.Globalization.CultureInfo.InvariantCulture));
        foreach (var tag in Rule.Tags)
        {
            Append(sb, "tag", tag);
        }

        Append(sb, "hostname", Hostname);
        Append(sb, "uri", Uri);
        Append(sb, "unique_id", TransactionId);
        return sb.ToString().TrimEnd();
    }

    private static void Append(StringBuilder sb, string name, string value) =>
        sb.Append('[').Append(name).Append(" \"").Append(Escape(value)).Append("\"] ");

    private static string Escape(string value)
    {
        var display = ByteString.ToDisplay(value);
        var sb = new StringBuilder(display.Length);
        foreach (var c in display)
        {
            switch (c)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                // Control characters, C1 controls (0x85 NEL, 0x9B CSI) and Unicode line breaks, which some log viewers
                // and terminals render as new lines or escape sequences.
                case < ' ' or (>= '\u007f' and <= '\u009f') or '\u2028' or '\u2029':
                    sb.Append("\\u").Append(((int)c).ToString("x4", System.Globalization.CultureInfo.InvariantCulture));
                    break;
                default:
                    sb.Append(c);
                    break;
            }
        }

        return sb.ToString();
    }
}
