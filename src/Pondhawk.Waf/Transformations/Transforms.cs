// Transformation semantics follow OWASP Coraza (Apache-2.0), which follows ModSecurity v2.
// All inputs and outputs are byte strings (one char per byte); see Text/ByteString.cs.
using System.Buffers;
using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Text;
using Pondhawk.Waf.Text;

namespace Pondhawk.Waf.Transformations;

/// <summary>A SecLang transformation (t:name).</summary>
public delegate string Transformation(string input);

/// <summary>The built-in transformations.</summary>
public static class Transforms
{
    private static readonly FrozenDictionary<string, Transformation> Registry = new Dictionary<string, Transformation>(StringComparer.OrdinalIgnoreCase)
    {
        ["base64Decode"] = s => Base64Decode(s, false),
        ["base64DecodeExt"] = s => Base64Decode(s, true),
        ["base64Encode"] = Base64Encode,
        ["cmdLine"] = CmdLine,
        ["compressWhitespace"] = CompressWhitespace,
        ["cssDecode"] = CssDecode,
        ["escapeSeqDecode"] = EscapeSeqDecode,
        ["hexDecode"] = HexDecode,
        ["hexEncode"] = HexEncode,
        ["htmlEntityDecode"] = HtmlEntityDecode,
        ["jsDecode"] = JsDecode,
        ["length"] = s => s.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ["lowercase"] = Lowercase,
        ["md5"] = s => ByteString.FromBytes(MD5.HashData(ByteString.ToBytes(s))),
        ["normalisePath"] = NormalizePath,
        ["normalisePathWin"] = NormalizePathWin,
        ["normalizePath"] = NormalizePath,
        ["normalizePathWin"] = NormalizePathWin,
        ["removeComments"] = RemoveComments,
        ["removeCommentsChar"] = RemoveCommentsChar,
        ["removeNulls"] = s => s.Contains('\0') ? s.Replace("\0", string.Empty, StringComparison.Ordinal) : s,
        ["removeWhitespace"] = RemoveWhitespace,
        ["replaceComments"] = ReplaceComments,
        ["replaceNulls"] = s => s.Contains('\0') ? s.Replace('\0', ' ') : s,
        ["sha1"] = s => ByteString.FromBytes(SHA1.HashData(ByteString.ToBytes(s))),
        ["uppercase"] = Uppercase,
        ["urlDecode"] = UrlDecode,
        ["urlDecodeUni"] = UrlDecodeUni,
        ["urlEncode"] = UrlEncode,
        ["utf8toUnicode"] = Utf8ToUnicode,
        ["trim"] = s => s.Trim(TrimChars),
        ["trimLeft"] = s => s.TrimStart(TrimChars),
        ["trimRight"] = s => s.TrimEnd(TrimChars),
    }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    private static readonly char[] TrimChars = [' ', '\t', '\n', '\v', '\f', '\r'];

    private static readonly SearchValues<char> CmdLineChanging = SearchValues.Create("\"'\\^,;\t\r\nABCDEFGHIJKLMNOPQRSTUVWXYZ");

    private static readonly SearchValues<char> CompressWhitespaceChanging = SearchValues.Create("\t\n\v\f\r\u00A0\u00C2");

    private static readonly SearchValues<char> RemoveWhitespaceChanging = SearchValues.Create(" \t\n\v\f\r");

    /// <summary>Finds a transformation by name (case-insensitive). "none" is handled by the parser.</summary>
    public static bool TryGet(string name, out Transformation transformation) =>
        Registry.TryGetValue(name, out transformation!);

    public static string UrlDecode(string input)
    {
        var pos = input.AsSpan().IndexOfAny('%', '+');
        if (pos < 0)
        {
            return input;
        }

        var sb = StringBuilderCache.Acquire(input.Length);
        sb.Append(input, 0, pos);
        for (var i = pos; i < input.Length; i++)
        {
            var ch = input[i];
            if (ch == '%' && i + 2 < input.Length && ByteString.IsHex(input[i + 1]) && ByteString.IsHex(input[i + 2]))
            {
                sb.Append((char)((ByteString.HexValue(input[i + 1]) << 4) | ByteString.HexValue(input[i + 2])));
                i += 2;
            }
            else
            {
                sb.Append(ch == '+' ? ' ' : ch);
            }
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    public static string UrlDecodeUni(string input)
    {
        var pos = input.AsSpan().IndexOfAny('%', '+');
        if (pos < 0)
        {
            return input;
        }

        var sb = StringBuilderCache.Acquire(input.Length);
        sb.Append(input, 0, pos);
        var i = pos;
        while (i < input.Length)
        {
            var ch = input[i];
            if (ch == '+')
            {
                sb.Append(' ');
                i++;
                continue;
            }

            if (ch != '%')
            {
                sb.Append(ch);
                i++;
                continue;
            }

            if (i + 1 < input.Length && (input[i + 1] == 'u' || input[i + 1] == 'U'))
            {
                if (i + 5 < input.Length)
                {
                    int h2 = ByteString.HexValue(input[i + 2]), h3 = ByteString.HexValue(input[i + 3]);
                    int h4 = ByteString.HexValue(input[i + 4]), h5 = ByteString.HexValue(input[i + 5]);
                    if (h2 >= 0 && h3 >= 0 && h4 >= 0 && h5 >= 0)
                    {
                        var code = (h2 << 12) | (h3 << 8) | (h4 << 4) | h5;
                        if (UnicodeBestFit.Ascii.TryGetValue(code, out var b))
                        {
                            sb.Append((char)b);
                        }
                        else
                        {
                            // Use the lower byte; full-width ASCII (ff01 - ff5e) needs 0x20 added.
                            var low = (h4 << 4) | h5;
                            if (low > 0x00 && low < 0x5f && h2 == 15 && h3 == 15)
                            {
                                low += 0x20;
                            }

                            sb.Append((char)low);
                        }

                        i += 6;
                        continue;
                    }
                }

                // Invalid or truncated %u escape: copy "%u" verbatim.
                sb.Append(input[i]).Append(input[i + 1]);
                i += 2;
                continue;
            }

            if (i + 2 < input.Length && ByteString.IsHex(input[i + 1]) && ByteString.IsHex(input[i + 2]))
            {
                sb.Append((char)((ByteString.HexValue(input[i + 1]) << 4) | ByteString.HexValue(input[i + 2])));
                i += 3;
                continue;
            }

            sb.Append(ch);
            i++;
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    public static string UrlEncode(string input)
    {
        var sb = StringBuilderCache.Acquire(input.Length * 3);
        foreach (var c in input)
        {
            if (c == ' ')
            {
                sb.Append('+');
            }
            else if (c == '*' || char.IsAsciiLetterOrDigit(c))
            {
                sb.Append(c);
            }
            else
            {
                sb.Append('%').Append("0123456789abcdef"[(c & 0xff) >> 4]).Append("0123456789abcdef"[c & 0x0f]);
            }
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    public static string JsDecode(string input)
    {
        var pos = input.IndexOf('\\', StringComparison.Ordinal);
        if (pos < 0)
        {
            return input;
        }

        var sb = StringBuilderCache.Acquire(input.Length);
        sb.Append(input, 0, pos);
        var i = pos;
        var n = input.Length;
        while (i < n)
        {
            if (input[i] != '\\')
            {
                sb.Append(input[i++]);
                continue;
            }

            var extLen = 0;
            if (i + 2 < n && input[i + 1] == 'u' && input[i + 2] == '{')
            {
                extLen = JsExtendedUnicodeEscapeLen(input, i + 3);
            }

            if (extLen > 0)
            {
                // \u{H...H}: lower byte of the value, with the full-width ASCII fold.
                var code = 0;
                for (var k = 0; k < extLen; k++)
                {
                    code = (code << 4) | ByteString.HexValue(input[i + 3 + k]);
                }

                var b = code & 0xff;
                if (code is >= 0xff01 and <= 0xff5e)
                {
                    b = (b + 0x20) & 0xff;
                }

                sb.Append((char)b);
                i += extLen + 4;
            }
            else if (i + 5 < n && input[i + 1] == 'u' && ByteString.IsHex(input[i + 2]) && ByteString.IsHex(input[i + 3])
                     && ByteString.IsHex(input[i + 4]) && ByteString.IsHex(input[i + 5]))
            {
                // \uHHHH: use only the lower byte; full-width ASCII (ff01 - ff5e) needs 0x20 added.
                var b = (ByteString.HexValue(input[i + 4]) << 4) | ByteString.HexValue(input[i + 5]);
                if (b > 0x00 && b < 0x5f && (input[i + 2] is 'f' or 'F') && (input[i + 3] is 'f' or 'F'))
                {
                    b += 0x20;
                }

                sb.Append((char)b);
                i += 6;
            }
            else if (i + 3 < n && input[i + 1] == 'x' && ByteString.IsHex(input[i + 2]) && ByteString.IsHex(input[i + 3]))
            {
                sb.Append((char)((ByteString.HexValue(input[i + 2]) << 4) | ByteString.HexValue(input[i + 3])));
                i += 4;
            }
            else if (i + 1 < n && IsOctal(input[i + 1]))
            {
                // \OOO (one byte only, \000 - \377)
                var j = 0;
                while (i + 1 + j < n && j < 3)
                {
                    j++;
                    if (i + 1 + j >= n || !IsOctal(input[i + 1 + j]))
                    {
                        break;
                    }
                }

                if (j == 3 && input[i + 1] > '3')
                {
                    j = 2;
                }

                var value = 0;
                for (var k = 0; k < j; k++)
                {
                    value = (value * 8) + (input[i + 1 + k] - '0');
                }

                sb.Append((char)(value & 0xff));
                i += 1 + j;
            }
            else if (i + 1 < n)
            {
                var c = input[i + 1] switch
                {
                    'a' => '\a',
                    'b' => '\b',
                    'f' => '\f',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'v' => '\v',
                    var other => other,
                };
                sb.Append(c);
                i += 2;
            }
            else
            {
                sb.Append(input, i, n - i);
                i = n;
            }
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    private static int JsExtendedUnicodeEscapeLen(string input, int pos)
    {
        var j = 0;
        while (j < 6 && pos + j < input.Length && ByteString.IsHex(input[pos + j]))
        {
            j++;
        }

        if (j == 0 || pos + j >= input.Length || input[pos + j] != '}')
        {
            return 0;
        }

        return j;
    }

    public static string CssDecode(string input)
    {
        var pos = input.IndexOf('\\', StringComparison.Ordinal);
        if (pos < 0)
        {
            return input;
        }

        var sb = StringBuilderCache.Acquire(input.Length);
        sb.Append(input, 0, pos);
        var i = pos;
        var n = input.Length;
        Span<byte> utf8 = stackalloc byte[4];
        while (i < n)
        {
            if (input[i] != '\\')
            {
                sb.Append(input[i++]);
                continue;
            }

            if (i + 1 >= n)
            {
                // A trailing backslash is a continuation to nothing.
                i++;
                continue;
            }

            i++;
            var j = 0;
            while (j < 6 && i + j < n && ByteString.IsHex(input[i + j]))
            {
                j++;
            }

            if (j > 0)
            {
                var code = 0;
                for (var k = 0; k < j; k++)
                {
                    code = (code << 4) | ByteString.HexValue(input[i + k]);
                }

                if (code == 0)
                {
                    code = 0xFFFD;
                }

                if (code is >= 0xff01 and <= 0xff5e)
                {
                    code -= 0xfee0;
                }

                AppendUtf8(sb, code, utf8);

                // A single whitespace after a hex escape is ignored.
                if (i + j < n && IsCSpace(input[i + j]))
                {
                    j++;
                }

                i += j;
            }
            else if (input[i] == '\n')
            {
                i++;
            }
            else
            {
                sb.Append(input[i++]);
            }
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    public static string EscapeSeqDecode(string input)
    {
        var pos = input.IndexOf('\\', StringComparison.Ordinal);
        if (pos < 0)
        {
            return input;
        }

        var sb = StringBuilderCache.Acquire(input.Length);
        sb.Append(input, 0, pos);
        var i = pos;
        var n = input.Length;
        while (i < n)
        {
            if (input[i] != '\\' || i + 1 >= n)
            {
                sb.Append(input[i++]);
                continue;
            }

            char? simple = input[i + 1] switch
            {
                'a' => '\a',
                'b' => '\b',
                'f' => '\f',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'v' => '\v',
                '\\' => '\\',
                '?' => '?',
                '\'' => '\'',
                '"' => '"',
                _ => null,
            };
            if (simple is { } s)
            {
                sb.Append(s);
                i += 2;
                continue;
            }

            if ((input[i + 1] is 'x' or 'X') && i + 3 < n && ByteString.IsHex(input[i + 2]) && ByteString.IsHex(input[i + 3]))
            {
                sb.Append((char)((ByteString.HexValue(input[i + 2]) << 4) | ByteString.HexValue(input[i + 3])));
                i += 4;
                continue;
            }

            if (IsOctal(input[i + 1]))
            {
                var j = 2;
                while (j < 4 && i + j < n && IsOctal(input[i + j]))
                {
                    j++;
                }

                var value = 0;
                for (var k = i + 1; k < i + j; k++)
                {
                    value = (value * 8) + (input[k] - '0');
                }

                sb.Append((char)(value & 0xff));
                i += j;
                continue;
            }

            // Unrecognized escape: drop the backslash.
            sb.Append(input[i + 1]);
            i += 2;
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    public static string HtmlEntityDecode(string input)
    {
        var pos = input.IndexOf('&', StringComparison.Ordinal);
        if (pos < 0)
        {
            return input;
        }

        var sb = StringBuilderCache.Acquire(input.Length);
        sb.Append(input, 0, pos);
        Span<byte> utf8 = stackalloc byte[4];
        var i = pos;
        var n = input.Length;
        while (i < n)
        {
            var c = input[i];
            if (c != '&')
            {
                sb.Append(c);
                i++;
                continue;
            }

            i = DecodeEntity(input, i, sb, utf8);
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    // Follows Go's html.UnescapeString (HTML5 rules, outside an attribute value). Returns the index after the entity.
    private static int DecodeEntity(string s, int start, StringBuilder sb, Span<byte> utf8)
    {
        var n = s.Length;
        var i = start + 1;
        if (i >= n)
        {
            sb.Append('&');
            return i;
        }

        if (s[i] == '#')
        {
            i++;
            var hex = false;
            if (i < n && (s[i] is 'x' or 'X'))
            {
                hex = true;
                i++;
            }

            var digitsStart = i;
            long value = 0;
            while (i < n)
            {
                var d = hex ? ByteString.HexValue(s[i]) : (s[i] is >= '0' and <= '9' ? s[i] - '0' : -1);
                if (d < 0)
                {
                    break;
                }

                value = Math.Min((value * (hex ? 16 : 10)) + d, 0x110000);
                i++;
            }

            if (i == digitsStart)
            {
                // No digits: not an entity.
                sb.Append(s, start, i - start);
                return i;
            }

            if (i < n && s[i] == ';')
            {
                i++;
            }

            var code = (int)value;
            if (code is >= 0x80 and <= 0x9F)
            {
                code = Windows1252Replacements[code - 0x80];
            }
            else if (code == 0 || code is >= 0xD800 and <= 0xDFFF || code > 0x10FFFF)
            {
                code = 0xFFFD;
            }

            AppendUtf8(sb, code, utf8);
            return i;
        }

        // Named reference: consume the alphanumeric run and an optional ';'.
        var j = i;
        while (j < n && j - i < HtmlEntities.LongestName && char.IsAsciiLetterOrDigit(s[j]))
        {
            j++;
        }

        var nameEnd = j;
        if (j < n && s[j] == ';')
        {
            j++;
        }

        var name = s[i..j];
        if (name.Length == 0)
        {
            sb.Append('&');
            return i;
        }

        if (HtmlEntities.Table.TryGetValue(name, out var cps))
        {
            foreach (var cp in cps)
            {
                AppendUtf8(sb, cp, utf8);
            }

            return j;
        }

        // Longest prefix that is an entity valid without a semicolon, e.g. "&ampfoo" -> "&foo".
        var plain = s[i..nameEnd];
        var maxLen = Math.Min(plain.Length - 1, HtmlEntities.LongestWithoutSemicolon);
        for (var len = maxLen; len > 1; len--)
        {
            if (HtmlEntities.Table.TryGetValue(plain[..len], out cps))
            {
                foreach (var cp in cps)
                {
                    AppendUtf8(sb, cp, utf8);
                }

                return i + len;
            }
        }

        sb.Append(s, start, j - start);
        return j;
    }

    private static readonly int[] Windows1252Replacements =
    [
        0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
        0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
    ];

    public static string Utf8ToUnicode(string input)
    {
        var i = 0;
        while (i < input.Length && input[i] < 0x80)
        {
            i++;
        }

        if (i == input.Length)
        {
            return input;
        }

        var sb = StringBuilderCache.Acquire(input.Length * 2);
        sb.Append(input, 0, i);
        var bytes = ByteString.ToBytes(input);
        while (i < bytes.Length)
        {
            if (bytes[i] < 0x80)
            {
                sb.Append((char)bytes[i]);
                i++;
                continue;
            }

            // Go's range-over-string: an invalid byte decodes to U+FFFD and consumes one byte.
            var status = Rune.DecodeFromUtf8(bytes.AsSpan(i), out var rune, out var consumed);
            int code;
            if (status == OperationStatus.Done)
            {
                code = rune.Value;
            }
            else
            {
                code = 0xFFFD;
                consumed = 1;
            }

            sb.Append("%u").Append(code.ToString(code <= 0xffff ? "x4" : "x", System.Globalization.CultureInfo.InvariantCulture));
            i += consumed;
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    public static string CmdLine(string input)
    {
        // Unchanged when there is nothing to delete, fold or merge.
        var span = input.AsSpan();
        if (!span.ContainsAny(CmdLineChanging) && !span.Contains("  ", StringComparison.Ordinal)
            && !span.Contains(" /", StringComparison.Ordinal) && !span.Contains(" (", StringComparison.Ordinal))
        {
            return input;
        }

        return CmdLineCore(input);
    }

    // The full transformation; CmdLine skips it when the input cannot change.
    internal static string CmdLineCore(string input)
    {
        var sb = StringBuilderCache.Acquire(input.Length);
        var space = false;
        foreach (var a in input)
        {
            switch (a)
            {
                case '"' or '\'' or '\\' or '^':
                    break;
                case ' ' or ',' or ';' or '\t' or '\r' or '\n':
                    if (!space)
                    {
                        sb.Append(' ');
                        space = true;
                    }

                    break;
                case '/' or '(':
                    if (space)
                    {
                        sb.Length--;
                    }

                    space = false;
                    sb.Append(a);
                    break;
                default:
                    sb.Append(a is >= 'A' and <= 'Z' ? (char)(a + 32) : a);
                    space = false;
                    break;
            }
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    public static string ReplaceComments(string input)
    {
        if (!input.Contains("/*", StringComparison.Ordinal))
        {
            return input;
        }

        return ReplaceCommentsCore(input);
    }

    // The full transformation; ReplaceComments skips it when the input cannot change.
    internal static string ReplaceCommentsCore(string input)
    {
        var sb = StringBuilderCache.Acquire(input.Length);
        var inComment = false;
        var i = 0;
        var n = input.Length;
        while (i < n)
        {
            if (!inComment)
            {
                if (input[i] == '/' && i + 1 < n && input[i + 1] == '*')
                {
                    inComment = true;
                    i += 2;
                }
                else
                {
                    sb.Append(input[i++]);
                }
            }
            else if (input[i] == '*' && i + 1 < n && input[i + 1] == '/')
            {
                inComment = false;
                i += 2;
                sb.Append(' ');
            }
            else
            {
                i++;
            }
        }

        if (inComment)
        {
            sb.Append(' ');
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    public static string RemoveComments(string input)
    {
        // "--" also covers "<!--".
        if (!input.Contains("/*", StringComparison.Ordinal) && !input.Contains("--", StringComparison.Ordinal) && !input.Contains('#', StringComparison.Ordinal))
        {
            return input;
        }

        return RemoveCommentsCore(input);
    }

    // The full transformation; RemoveComments skips it when the input cannot change.
    internal static string RemoveCommentsCore(string input)
    {
        var sb = StringBuilderCache.Acquire(input.Length);
        var inComment = false;
        var i = 0;
        var n = input.Length;
        while (i < n)
        {
            if (!inComment)
            {
                if (input[i] == '/' && i + 1 < n && input[i + 1] == '*')
                {
                    inComment = true;
                    i += 2;
                }
                else if (input[i] == '<' && i + 3 < n && input[i + 1] == '!' && input[i + 2] == '-' && input[i + 3] == '-')
                {
                    inComment = true;
                    i += 4;
                }
                else if ((input[i] == '-' && i + 1 < n && input[i + 1] == '-') || input[i] == '#')
                {
                    // Line comment: the rest of the input is dropped.
                    sb.Append(' ');
                    return StringBuilderCache.GetStringAndRelease(sb);
                }
                else
                {
                    sb.Append(input[i++]);
                }
            }
            else if (input[i] == '*' && i + 1 < n && input[i + 1] == '/')
            {
                inComment = false;
                i += 2;
                if (i < n)
                {
                    sb.Append(input[i++]);
                }
            }
            else if (input[i] == '-' && i + 2 < n && input[i + 1] == '-' && input[i + 2] == '>')
            {
                inComment = false;
                i += 3;
                if (i < n)
                {
                    sb.Append(input[i++]);
                }
            }
            else
            {
                i++;
            }
        }

        if (inComment)
        {
            sb.Append(' ');
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    public static string RemoveCommentsChar(string input)
    {
        // "--" also covers "<!--" and "-->".
        if (!input.Contains("/*", StringComparison.Ordinal) && !input.Contains("*/", StringComparison.Ordinal)
            && !input.Contains("--", StringComparison.Ordinal) && !input.Contains('#', StringComparison.Ordinal))
        {
            return input;
        }

        return RemoveCommentsCharCore(input);
    }

    // The full transformation; RemoveCommentsChar skips it when the input cannot change.
    internal static string RemoveCommentsCharCore(string input)
    {
        var sb = StringBuilderCache.Acquire(input.Length);
        var n = input.Length;
        for (var i = 0; i < n;)
        {
            if (input[i] == '/' && i + 1 < n && input[i + 1] == '*')
            {
                i += 2;
            }
            else if (input[i] == '*' && i + 1 < n && input[i + 1] == '/')
            {
                i += 2;
            }
            else if (input[i] == '<' && i + 3 < n && input[i + 1] == '!' && input[i + 2] == '-' && input[i + 3] == '-')
            {
                i += 4;
            }
            else if (input[i] == '-' && i + 2 < n && input[i + 1] == '-' && input[i + 2] == '>')
            {
                i += 3;
            }
            else if (input[i] == '-' && i + 1 < n && input[i + 1] == '-')
            {
                i += 2;
            }
            else if (input[i] == '#')
            {
                i++;
            }
            else
            {
                sb.Append(input[i++]);
            }
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    public static string CompressWhitespace(string input)
    {
        // Unchanged when the only whitespace is single spaces (0xC2 may start a UTF-8 encoded space).
        if (!input.AsSpan().ContainsAny(CompressWhitespaceChanging) && !input.Contains("  ", StringComparison.Ordinal))
        {
            return input;
        }

        return CompressWhitespaceCore(input);
    }

    // The full transformation; CompressWhitespace skips it when the input cannot change.
    internal static string CompressWhitespaceCore(string input)
    {
        var sb = StringBuilderCache.Acquire(input.Length);
        var inWhitespace = false;
        var i = 0;
        var n = input.Length;
        while (i < n)
        {
            var width = LatinSpaceWidth(input, i);
            if (width > 0)
            {
                if (!inWhitespace)
                {
                    sb.Append(' ');
                    inWhitespace = true;
                }

                i += width;
            }
            else
            {
                sb.Append(input[i++]);
                inWhitespace = false;
            }
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    // ASCII whitespace, a raw 0xA0 byte, or UTF-8 encoded U+0085 / U+00A0. Returns the byte length, or 0.
    private static int LatinSpaceWidth(string s, int i)
    {
        var c = s[i];
        if (c is ' ' or '\t' or '\n' or '\v' or '\f' or '\r' or '\xA0')
        {
            return 1;
        }

        if (c == '\xC2' && i + 1 < s.Length && s[i + 1] is '\x85' or '\xA0')
        {
            return 2;
        }

        return 0;
    }

    public static string RemoveWhitespace(string input)
    {
        if (!input.AsSpan().ContainsAny(RemoveWhitespaceChanging) && Ascii.IsValid(input))
        {
            return input;
        }

        return RemoveWhitespaceCore(input);
    }

    // The full transformation; RemoveWhitespace skips it when the input cannot change.
    internal static string RemoveWhitespaceCore(string input)
    {
        var sb = StringBuilderCache.Acquire(input.Length);
        var bytes = ByteString.ToBytes(input);
        var i = 0;
        while (i < bytes.Length)
        {
            var b = bytes[i];
            if (b < 0x80)
            {
                if (!(b is (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\v' or (byte)'\f' or (byte)'\r'))
                {
                    sb.Append((char)b);
                }

                i++;
                continue;
            }

            if (b == 0xA0)
            {
                i++;
                continue;
            }

            if (Rune.DecodeFromUtf8(bytes.AsSpan(i), out var rune, out var consumed) == OperationStatus.Done)
            {
                if (!Rune.IsWhiteSpace(rune))
                {
                    sb.Append(input, i, consumed);
                }

                i += consumed;
            }
            else
            {
                sb.Append((char)b);
                i++;
            }
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    public static string Lowercase(string input) => MapCase(input, upper: false);

    public static string Uppercase(string input) => MapCase(input, upper: true);

    // ASCII case mapping, plus Unicode case mapping of valid UTF-8 sequences (as Go's strings.ToLower/ToUpper do).
    private static string MapCase(string input, bool upper)
    {
        var needsWork = false;
        foreach (var c in input)
        {
            if (c >= 0x80 || (upper ? c is >= 'a' and <= 'z' : c is >= 'A' and <= 'Z'))
            {
                needsWork = true;
                break;
            }
        }

        if (!needsWork)
        {
            return input;
        }

        var bytes = ByteString.ToBytes(input);
        var sb = StringBuilderCache.Acquire(input.Length);
        Span<byte> utf8 = stackalloc byte[4];
        var i = 0;
        while (i < bytes.Length)
        {
            var b = bytes[i];
            if (b < 0x80)
            {
                var c = (char)b;
                sb.Append(upper ? (c is >= 'a' and <= 'z' ? (char)(c - 32) : c) : (c is >= 'A' and <= 'Z' ? (char)(c + 32) : c));
                i++;
                continue;
            }

            if (Rune.DecodeFromUtf8(bytes.AsSpan(i), out var rune, out var consumed) == OperationStatus.Done)
            {
                var mapped = upper ? Rune.ToUpperInvariant(rune) : Rune.ToLowerInvariant(rune);
                AppendUtf8(sb, mapped.Value, utf8);
                i += consumed;
            }
            else
            {
                sb.Append((char)b);
                i++;
            }
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    public static string HexEncode(string input) =>
        Convert.ToHexStringLower(ByteString.ToBytes(input));

    public static string HexDecode(string input)
    {
        if (input.Length % 2 != 0)
        {
            return string.Empty;
        }

        foreach (var c in input)
        {
            if (!ByteString.IsHex(c))
            {
                return string.Empty;
            }
        }

        return ByteString.FromBytes(Convert.FromHexString(input));
    }

    public static string Base64Encode(string input) =>
        Convert.ToBase64String(ByteString.ToBytes(input));

    private static readonly sbyte[] Base64DecMap = BuildBase64Map();

    private static sbyte[] BuildBase64Map()
    {
        var map = new sbyte[128];
        Array.Fill(map, (sbyte)-1);
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (var i = 0; i < alphabet.Length; i++)
        {
            map[alphabet[i]] = (sbyte)i;
        }

        return map;
    }

    /// <summary>Lenient base64 decode (ModSecurity semantics): stops at '=', ' ' or an invalid char unless <paramref name="ext"/>.</summary>
    public static string Base64Decode(string input, bool ext)
    {
        if (input.Length == 0)
        {
            return input;
        }

        var sb = StringBuilderCache.Acquire(input.Length);
        int n = 0, x = 0;
        foreach (var raw in input)
        {
            var c = raw;
            if (ext && (char.IsWhiteSpace(c) || c == '.'))
            {
                continue;
            }

            if (c is '\r' or '\n')
            {
                continue;
            }

            if (c is '=' or ' ')
            {
                break;
            }

            if (ext)
            {
                c = c switch
                {
                    '-' => '+',
                    '_' => '/',
                    _ => c,
                };
            }

            var d = c < 128 ? Base64DecMap[c] : (sbyte)-1;
            if (d < 0)
            {
                if (ext)
                {
                    continue;
                }

                break;
            }

            x = (x << 6) | (d & 0x3f);
            n++;
            if (n == 4)
            {
                sb.Append((char)((x >> 16) & 0xff)).Append((char)((x >> 8) & 0xff)).Append((char)(x & 0xff));
                n = 0;
                x = 0;
            }
        }

        if (n == 2)
        {
            x <<= 12;
            sb.Append((char)((x >> 16) & 0xff));
        }
        else if (n == 3)
        {
            x <<= 6;
            sb.Append((char)((x >> 16) & 0xff)).Append((char)((x >> 8) & 0xff));
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    public static string NormalizePath(string input)
    {
        if (input.Length == 0)
        {
            return input;
        }

        return IsCleanPath(input) ? input : NormalizePathCore(input);
    }

    // The full transformation; NormalizePath skips it for a path that is already clean.
    internal static string NormalizePathCore(string input)
    {
        if (input.Length == 0)
        {
            return input;
        }

        var clean = CleanPath(input);
        if (clean == ".")
        {
            return string.Empty;
        }

        if (input[^1] == '/' && clean != "/")
        {
            return clean + "/";
        }

        return clean;
    }

    public static string NormalizePathWin(string input)
    {
        if (input.Length == 0)
        {
            return input;
        }

        var clean = NormalizePath(input.Replace('\\', '/'));
        return StripWindowsTrailingDotsAndSpaces(StripWindowsAds(clean));
    }

    private static string StripWindowsAds(string data)
    {
        if (!data.Contains(':', StringComparison.Ordinal))
        {
            return data;
        }

        var prefix = string.Empty;
        if (data.Length >= 2 && data[1] == ':' && char.IsAsciiLetter(data[0]))
        {
            prefix = data[..2];
            data = data[2..];
        }

        var trailing = string.Empty;
        if (data.Length > 0 && data[^1] == '/')
        {
            trailing = "/";
            data = data[..^1];
        }

        var idx = data.LastIndexOf('/');
        if (idx >= 0)
        {
            var colon = data.IndexOf(':', idx + 1);
            if (colon >= 0)
            {
                data = data[..colon];
            }
        }
        else
        {
            var colon = data.IndexOf(':', StringComparison.Ordinal);
            if (colon >= 0)
            {
                data = data[..colon];
            }
        }

        return prefix + data + trailing;
    }

    private static string StripWindowsTrailingDotsAndSpaces(string data)
    {
        if (data.AsSpan().IndexOfAny('.', ' ') < 0)
        {
            return data;
        }

        var segments = data.Split('/');
        var trimmable = segments.Any(seg => seg.Length > 0 && !IsAllDots(seg) && seg[^1] is '.' or ' ');
        if (!trimmable)
        {
            return data;
        }

        var sb = StringBuilderCache.Acquire(data.Length);
        var wroteAny = false;
        foreach (var raw in segments)
        {
            var seg = raw;
            if (!IsAllDots(seg))
            {
                seg = seg.TrimEnd('.', ' ');
                if (seg.Length == 0)
                {
                    continue;
                }
            }

            if (wroteAny)
            {
                sb.Append('/');
            }

            sb.Append(seg);
            wroteAny = true;
        }

        return StringBuilderCache.GetStringAndRelease(sb);
    }

    private static bool IsAllDots(string s)
    {
        foreach (var c in s)
        {
            if (c != '.')
            {
                return false;
            }
        }

        return true;
    }

    // True when NormalizePath leaves the path as it is: no empty segment except a leading or trailing slash, and no
    // "." or ".." segment.
    private static bool IsCleanPath(string path)
    {
        var i = path[0] == '/' ? 1 : 0;
        while (i < path.Length)
        {
            var end = path.IndexOf('/', i);
            if (end < 0)
            {
                end = path.Length;
            }

            var length = end - i;
            if (length == 0 || (length == 1 && path[i] == '.') || (length == 2 && path[i] == '.' && path[i + 1] == '.'))
            {
                return false;
            }

            i = end + 1;
        }

        return true;
    }

    /// <summary>Go's path.Clean: lexical processing of '.', '..' and repeated slashes.</summary>
    internal static string CleanPath(string path)
    {
        if (path.Length == 0)
        {
            return ".";
        }

        var rooted = path[0] == '/';
        var n = path.Length;
        var output = new StringBuilder(n);
        int r = 0, dotdot = 0;
        if (rooted)
        {
            output.Append('/');
            r = 1;
            dotdot = 1;
        }

        while (r < n)
        {
            if (path[r] == '/')
            {
                r++;
            }
            else if (path[r] == '.' && (r + 1 == n || path[r + 1] == '/'))
            {
                r++;
            }
            else if (path[r] == '.' && path[r + 1] == '.' && (r + 2 == n || path[r + 2] == '/'))
            {
                r += 2;
                if (output.Length > dotdot)
                {
                    var w = output.Length - 1;
                    while (w > dotdot && output[w] != '/')
                    {
                        w--;
                    }

                    output.Length = w;
                }
                else if (!rooted)
                {
                    if (output.Length > 0)
                    {
                        output.Append('/');
                    }

                    output.Append("..");
                    dotdot = output.Length;
                }
            }
            else
            {
                if ((rooted && output.Length != 1) || (!rooted && output.Length != 0))
                {
                    output.Append('/');
                }

                while (r < n && path[r] != '/')
                {
                    output.Append(path[r++]);
                }
            }
        }

        return output.Length == 0 ? "." : output.ToString();
    }

    private static bool IsOctal(char c) => c is >= '0' and <= '7';

    private static bool IsCSpace(char c) => c is ' ' or '\f' or '\n' or '\t' or '\r' or '\v';

    private static void AppendUtf8(StringBuilder sb, int code, Span<byte> buffer)
    {
        if (code < 0x80)
        {
            sb.Append((char)code);
            return;
        }

        if (!Rune.TryCreate(code, out var rune))
        {
            rune = Rune.ReplacementChar;
        }

        var written = rune.EncodeToUtf8(buffer);
        for (var k = 0; k < written; k++)
        {
            sb.Append((char)buffer[k]);
        }
    }
}
