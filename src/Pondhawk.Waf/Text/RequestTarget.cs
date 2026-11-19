using System.Text;

namespace Pondhawk.Waf.Text;

/// <summary>Request-target parsing with the semantics of Go's url.ParseRequestURI, which Coraza uses.</summary>
internal static class RequestTarget
{
    /// <summary>
    /// Parses a request target (fragment already removed). On success, <paramref name="path"/> is the percent-decoded
    /// path (byte string), <paramref name="rawQuery"/> the undecoded query.
    /// </summary>
    public static bool TryParse(string uri, out string path, out string rawQuery, out string normalized)
    {
        path = string.Empty;
        rawQuery = string.Empty;
        normalized = uri;

        foreach (var c in uri)
        {
            if (c < 0x20 || c == 0x7f)
            {
                return false;
            }
        }

        if (uri.Length == 0)
        {
            return false;
        }

        if (uri == "*")
        {
            path = "*";
            return true;
        }

        var rest = uri;
        var q = rest.IndexOf('?', StringComparison.Ordinal);
        if (q >= 0)
        {
            rawQuery = rest[(q + 1)..];
            rest = rest[..q];
        }

        var schemeEnd = SchemeLength(rest);
        if (schemeEnd < 0)
        {
            return false;
        }

        var hasScheme = schemeEnd > 0;
        if (hasScheme)
        {
            rest = rest[(schemeEnd + 1)..];
        }

        if (!rest.StartsWith('/'))
        {
            // "scheme:opaque" is accepted with an empty path; anything else is not a valid request target.
            return hasScheme;
        }

        if (hasScheme && rest.StartsWith("//", StringComparison.Ordinal))
        {
            var authorityEnd = rest.IndexOf('/', 2);
            var authority = authorityEnd < 0 ? rest[2..] : rest[2..authorityEnd];
            if (!ValidAuthority(authority))
            {
                return false;
            }

            rest = authorityEnd < 0 ? string.Empty : rest[authorityEnd..];
        }

        if (!TryUnescapePath(rest, out path))
        {
            return false;
        }

        return true;
    }

    // Returns the index of ':' ending a valid scheme, 0 when there is no scheme, -1 when the target is invalid.
    private static int SchemeLength(string s)
    {
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (char.IsAsciiLetter(c))
            {
                continue;
            }

            if (char.IsAsciiDigit(c) || c is '+' or '-' or '.')
            {
                if (i == 0)
                {
                    return 0;
                }

                continue;
            }

            if (c == ':')
            {
                return i == 0 ? -1 : i;
            }

            // An invalid character before any ':' means there is no scheme.
            return 0;
        }

        return 0;
    }

    private static bool ValidAuthority(string authority)
    {
        foreach (var c in authority)
        {
            if (c is ' ' or '<' or '>' or '"' or '{' or '}' or '|' or '\\' or '^' or '`')
            {
                return false;
            }
        }

        for (var i = 0; i < authority.Length; i++)
        {
            if (authority[i] == '%' && (i + 2 >= authority.Length || !ByteString.IsHex(authority[i + 1]) || !ByteString.IsHex(authority[i + 2])))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Percent-decodes a path. Fails on a malformed escape, as Go's url.PathUnescape does. '+' is kept.</summary>
    public static bool TryUnescapePath(string s, out string result)
    {
        if (!s.Contains('%', StringComparison.Ordinal))
        {
            result = s;
            return true;
        }

        var sb = new StringBuilder(s.Length);
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (c != '%')
            {
                sb.Append(c);
                continue;
            }

            if (i + 2 >= s.Length || !ByteString.IsHex(s[i + 1]) || !ByteString.IsHex(s[i + 2]))
            {
                result = string.Empty;
                return false;
            }

            sb.Append((char)((ByteString.HexValue(s[i + 1]) << 4) | ByteString.HexValue(s[i + 2])));
            i += 2;
        }

        result = sb.ToString();
        return true;
    }
}

/// <summary>application/x-www-form-urlencoded parsing (Coraza internal/url).</summary>
public static class UrlEncoded
{
    /// <summary>Parses pairs in order. Returns true when <paramref name="limit"/> pairs were reached and the rest was dropped.</summary>
    public static bool Parse(string query, char separator, int limit, Action<string, string> add)
    {
        var count = 0;
        var start = 0;
        while (start <= query.Length && query.Length > 0)
        {
            var end = query.IndexOf(separator, start);
            if (end < 0)
            {
                end = query.Length;
            }

            var pair = query.AsSpan(start, end - start);
            start = end + 1;
            if (pair.Length > 0)
            {
                if (limit > 0 && count >= limit)
                {
                    return true;
                }

                var eq = pair.IndexOf('=');
                var key = eq < 0 ? pair : pair[..eq];
                var value = eq < 0 ? [] : pair[(eq + 1)..];
                add(Unescape(key), Unescape(value));
                count++;
            }

            if (end == query.Length)
            {
                break;
            }
        }

        return false;
    }

    /// <summary>Lenient query unescape: '+' to space, valid %XX decoded, invalid escapes kept.</summary>
    public static string Unescape(string input) =>
        input.AsSpan().IndexOfAny('%', '+') < 0 ? input : Unescape(input.AsSpan());

    /// <summary>Lenient query unescape of a slice: '+' to space, valid %XX decoded, invalid escapes kept.</summary>
    public static string Unescape(ReadOnlySpan<char> input)
    {
        if (input.IsEmpty)
        {
            return string.Empty;
        }

        var first = input.IndexOfAny('%', '+');
        if (first < 0)
        {
            return new string(input);
        }

        var length = input.Length;
        for (var i = first; i < input.Length; i++)
        {
            if (input[i] == '%' && i + 2 < input.Length && ByteString.IsHex(input[i + 1]) && ByteString.IsHex(input[i + 2]))
            {
                length -= 2;
                i += 2;
            }
        }

        return string.Create(length, input, static (span, input) =>
        {
            var w = 0;
            for (var i = 0; i < input.Length; i++)
            {
                var c = input[i];
                if (c == '+')
                {
                    span[w++] = ' ';
                }
                else if (c == '%' && i + 2 < input.Length && ByteString.IsHex(input[i + 1]) && ByteString.IsHex(input[i + 2]))
                {
                    span[w++] = (char)((ByteString.HexValue(input[i + 1]) << 4) | ByteString.HexValue(input[i + 2]));
                    i += 2;
                }
                else
                {
                    span[w++] = c;
                }
            }
        });
    }
}

/// <summary>Cookie header parsing (Coraza internal/cookies). Values are not URL-decoded.</summary>
public static class Cookies
{
    public static IEnumerable<(string Name, string Value)> Parse(string raw)
    {
        raw = Trim(raw);
        foreach (var rawPart in raw.Split(';'))
        {
            var part = Trim(rawPart);
            if (part.Length == 0)
            {
                continue;
            }

            var eq = part.IndexOf('=', StringComparison.Ordinal);
            var name = Trim(eq < 0 ? part : part[..eq]);
            var value = Trim(eq < 0 ? string.Empty : part[(eq + 1)..]);
            if (name.Length == 0 && value.Length == 0)
            {
                continue;
            }

            yield return (name, value);
        }
    }

    private static string Trim(string s)
    {
        int start = 0, end = s.Length;
        while (start < end && (s[start] <= ' ' || s[start] == 0x7f))
        {
            start++;
        }

        while (end > start && (s[end - 1] <= ' ' || s[end - 1] == 0x7f))
        {
            end--;
        }

        return s[start..end];
    }
}
