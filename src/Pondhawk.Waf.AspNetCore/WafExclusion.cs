using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Pondhawk.Waf.AspNetCore;

/// <summary>
/// Turns off a rule, a range of rules or a tag, for all requests or for one path, or excludes one target (an argument,
/// header or cookie) from them. The WAF generates the SecLang. Use the helpers on <see cref="WafOptions"/> in code, or
/// bind a list from configuration.
/// </summary>
/// <remarks>
/// Set <see cref="Rule"/> or <see cref="Tag"/>, not both. Without <see cref="Target"/>, the rules are removed;
/// with it, only the target is ignored by them. Without <see cref="Path"/>, the exclusion applies to every request.
/// </remarks>
public sealed partial class WafExclusion
{
    /// <summary>Lowest id of the rules the WAF generates for path exclusions, one per exclusion.</summary>
    public const int FirstGeneratedRuleId = 10_000_000;

    /// <summary>A rule id (<c>942100</c>) or an inclusive range (<c>942100-942199</c>).</summary>
    public string? Rule { get; set; }

    /// <summary>A rule tag, for example <c>attack-sqli</c> or <c>paranoia-level/2</c>. Matched exactly.</summary>
    public string? Tag { get; set; }

    /// <summary>
    /// A variable, optionally with a key: <c>ARGS:password</c>, <c>REQUEST_COOKIES:session</c>,
    /// <c>REQUEST_HEADERS:User-Agent</c>, or a key regex such as <c>ARGS:/^json\.comment/</c>. Null: remove the rules.
    /// </summary>
    public string? Target { get; set; }

    /// <summary>
    /// A path prefix, for example <c>/login</c> or <c>/api/upload</c>. It matches the path and the paths below it,
    /// ignoring case, as the client sends it (before PathBase is removed). Null: all requests.
    /// </summary>
    /// <remarks>
    /// The exclusion does not apply to request targets that a server could route to another path: dot segments
    /// (<c>/login/../admin</c>), encoded slashes or dots, backslashes, and absolute-form targets. Those requests get
    /// the full rules.
    /// </remarks>
    public string? Path { get; set; }

    /// <summary>Throws <see cref="ArgumentException"/> when the exclusion is incomplete or a value is not allowed.</summary>
    public void Validate()
    {
        if (Rule is null == Tag is null)
        {
            throw new ArgumentException($"Exclusion {this}: set Rule or Tag, not both.");
        }

        if (Rule is not null && !RuleRegex().IsMatch(Rule))
        {
            throw new ArgumentException($"Exclusion {this}: Rule must be an id or a range like 942100-942199.");
        }

        if (Rule is not null && ParseRule(Rule) is var (first, last) && last < first)
        {
            throw new ArgumentException($"Exclusion {this}: the range ends before it starts.");
        }

        if (Tag is not null && !TagRegex().IsMatch(Tag))
        {
            throw new ArgumentException($"Exclusion {this}: Tag has characters that are not allowed.");
        }

        if (Target is not null && !TargetRegex().IsMatch(Target))
        {
            throw new ArgumentException(
                $"Exclusion {this}: Target must be a variable with an optional key, like ARGS:password, without quotes, commas, pipes or spaces.");
        }

        if (Path is not null && !PathRegex().IsMatch(Path))
        {
            throw new ArgumentException(
                $"Exclusion {this}: Path must start with '/' and contain only URL path characters (no query, fragment, backslash or dot segment).");
        }
    }

    /// <inheritdoc />
    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.Append(Rule is not null ? "rule " + Rule : "tag " + Tag);
        if (Target is not null)
        {
            sb.Append(", target ").Append(Target);
        }

        if (Path is not null)
        {
            sb.Append(", path ").Append(Path);
        }

        return sb.ToString();
    }

    /// <summary>
    /// SecLang for exclusions that apply to all requests: <c>SecRuleRemoveById</c>, <c>SecRuleRemoveByTag</c> and
    /// <c>SecRuleUpdateTargetBy*</c>. Load it after all rules.
    /// </summary>
    internal static string StaticDirectives(IReadOnlyList<WafExclusion> exclusions)
    {
        var sb = new StringBuilder();
        foreach (var e in exclusions)
        {
            if (e.Path is not null)
            {
                continue;
            }

            switch (e.Target, e.Rule)
            {
                case (null, not null):
                    sb.Append("SecRuleRemoveById ").AppendLine(e.Rule);
                    break;
                case (null, null):
                    sb.Append("SecRuleRemoveByTag ").AppendLine(e.Tag);
                    break;
                case (not null, not null):
                    sb.Append("SecRuleUpdateTargetById ").Append(e.Rule).Append(" \"!").Append(e.Target).AppendLine("\"");
                    break;
                default:
                    sb.Append("SecRuleUpdateTargetByTag ").Append(e.Tag).Append(" \"!").Append(e.Target).AppendLine("\"");
                    break;
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// SecLang for path exclusions: one phase-1 rule each, which removes the rules or targets for the rest of the
    /// transaction with <c>ctl</c>. Load it before the rules it excludes.
    /// </summary>
    internal static string PathDirectives(IReadOnlyList<WafExclusion> exclusions)
    {
        var sb = new StringBuilder();
        var id = FirstGeneratedRuleId;
        foreach (var e in exclusions)
        {
            if (e.Path is null)
            {
                continue;
            }

            var ctl = (e.Target, e.Rule) switch
            {
                (null, not null) => "ruleRemoveById=" + e.Rule,
                (null, null) => "ruleRemoveByTag=" + e.Tag,
                (not null, not null) => $"ruleRemoveTargetById={e.Rule};{e.Target}",
                _ => $"ruleRemoveTargetByTag={e.Tag};{e.Target}",
            };

            // Match the raw request target, not the decoded REQUEST_FILENAME: decoding turns "%2F" into "/", which the
            // application does not. The chained rule refuses targets whose path the server could normalize to another
            // path: dot segments, encoded slashes, dots and backslashes.
            var prefix = PathPrefixPattern(e.Path);
            sb.Append(CultureInfo.InvariantCulture,
                $"SecRule REQUEST_URI_RAW \"@rx ^({prefix}(?:/[^?#]*)?)(?:[?#]|$)\" \"id:{id},phase:1,pass,nolog,t:none,t:lowercase,capture,chain,msg:'Pondhawk exclusion: {e}'\"\n");
            sb.Append(
                "    SecRule TX:1 \"!@rx (?:\\x5c|%5c|%2f|%2e|(?:^|/)\\.{1,2}(?:/|$))\" \"t:none,ctl:")
                .Append(ctl).AppendLine("\"");
            id++;
        }

        return sb.ToString();
    }

    private static string PathPrefixPattern(string path)
    {
        var trimmed = path.Length > 1 ? path.TrimEnd('/') : string.Empty;
        var sb = new StringBuilder();
        foreach (var c in trimmed.ToLowerInvariant())
        {
            if (!char.IsAsciiLetterOrDigit(c) && c != '/')
            {
                sb.Append('\\');
            }

            sb.Append(c);
        }

        return sb.ToString();
    }

    private static (int First, int Last) ParseRule(string rule)
    {
        var dash = rule.IndexOf('-', StringComparison.Ordinal);
        return dash < 0
            ? (int.Parse(rule, CultureInfo.InvariantCulture), int.Parse(rule, CultureInfo.InvariantCulture))
            : (int.Parse(rule.AsSpan(0, dash), CultureInfo.InvariantCulture), int.Parse(rule.AsSpan(dash + 1), CultureInfo.InvariantCulture));
    }

    [GeneratedRegex(@"^[1-9][0-9]{0,8}(?:-[1-9][0-9]{0,8})?$")]
    private static partial Regex RuleRegex();

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}$")]
    private static partial Regex TagRegex();

    [GeneratedRegex(@"^[A-Za-z_]+(?::[^\s"",'|]{1,256})?$")]
    private static partial Regex TargetRegex();

    // URL path characters except '\', '?' and '#'; no dot segments; at most 512 characters.
    [GeneratedRegex(@"^(?!.*(?:^|/)\.{1,2}(?:/|$))/[A-Za-z0-9\-._~!$&()*+;=:@/%]{0,511}$")]
    private static partial Regex PathRegex();
}
