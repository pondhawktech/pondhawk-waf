using System.Text;
using Pondhawk.Waf.Collections;
using Pondhawk.Waf.Rules;

namespace Pondhawk.Waf;

/// <summary>
/// Keeps credentials and oversized attacker input out of the rule log and the audit log. Applied when a matched rule
/// is recorded, so every log sink gets the redacted, truncated values.
/// </summary>
public static class LogRedaction
{
    /// <summary>Longest msg or logdata kept, in bytes, as ModSecurity truncates logdata.</summary>
    public const int MaxDataLength = 512;

    /// <summary>Replaces a redacted value.</summary>
    public const string Redacted = "[redacted]";

    /// <summary>Request headers whose values are never logged. Names that contain a <see cref="SensitiveNameParts"/> entry are redacted too.</summary>
    public static readonly HashSet<string> SensitiveHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "X-Auth-Token", "X-Csrf-Token",
        "X-Xsrf-Token", "X-Amz-Security-Token", "Api-Key",
    };

    /// <summary>
    /// Argument, header and cookie names containing one of these (case-insensitive) hold credentials: their values are
    /// redacted in the query string of logged URIs and in the data of rules that matched them.
    /// </summary>
    public static readonly List<string> SensitiveNameParts =
    [
        "pass", "pwd", "secret", "token", "apikey", "api_key", "api-key", "credential", "auth", "session", "cookie",
    ];

    /// <summary>True for a header whose value is never logged.</summary>
    public static bool IsSensitiveHeader(string name) => SensitiveHeaders.Contains(name) || IsSensitiveName(name);

    /// <summary>True for an argument, cookie or header name that suggests a credential.</summary>
    public static bool IsSensitiveName(string name)
    {
        foreach (var part in SensitiveNameParts)
        {
            if (name.Contains(part, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>True when a matched value is a credential: any cookie, a sensitive header, or a sensitive argument.</summary>
    public static bool IsSensitive(MatchData match) => match.Variable switch
    {
        Variable.RequestCookies => true,
        Variable.RequestHeaders => IsSensitiveHeader(match.Key),
        Variable.Args or Variable.ArgsGet or Variable.ArgsPost or Variable.ArgsPath or Variable.MatchedVars
            or Variable.ResponseArgs => IsSensitiveName(match.Key),
        _ => false,
    };

    /// <summary>True when any match of a rule (or its chain) is sensitive.</summary>
    public static bool IsSensitive(IReadOnlyList<RuleMatch> matches)
    {
        foreach (var m in matches)
        {
            if (IsSensitive(m.Match))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Cuts a byte string to <see cref="MaxDataLength"/> bytes and marks the cut.</summary>
    public static string Truncate(string value) =>
        value.Length <= MaxDataLength ? value : string.Concat(value.AsSpan(0, MaxDataLength), "...");

    /// <summary>Replaces the values of sensitive query parameters in a request target or URI.</summary>
    public static string RedactQuery(string uri)
    {
        var q = uri.IndexOf('?', StringComparison.Ordinal);
        if (q < 0)
        {
            return uri;
        }

        var fragment = uri.IndexOf('#', q);
        var query = fragment < 0 ? uri[(q + 1)..] : uri[(q + 1)..fragment];
        var sb = new StringBuilder(uri.Length);
        sb.Append(uri, 0, q + 1);
        var first = true;
        foreach (var pair in query.Split('&'))
        {
            if (!first)
            {
                sb.Append('&');
            }

            first = false;
            var eq = pair.IndexOf('=', StringComparison.Ordinal);
            var name = eq < 0 ? pair : pair[..eq];
            if (eq >= 0 && IsSensitiveName(Uri.UnescapeDataString(name.Replace('+', ' '))))
            {
                sb.Append(name).Append('=').Append(Redacted);
            }
            else
            {
                sb.Append(pair);
            }
        }

        if (fragment >= 0)
        {
            sb.Append(uri, fragment, uri.Length - fragment);
        }

        return sb.ToString();
    }
}
