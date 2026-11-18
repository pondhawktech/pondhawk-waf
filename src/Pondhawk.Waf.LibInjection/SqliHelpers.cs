// Ported from libinjection-go (https://github.com/corazawaf/libinjection-go), sqli_helpers.go.
// Copyright (c) 2022-Present, Coraza. BSD-3-Clause; see LICENSE-libinjection.txt.

using System.Collections.Frozen;

namespace Pondhawk.Waf.LibInjection;

internal static class SqliHelpers
{
    public static byte Flag2Delimiter(int flag)
    {
        if ((flag & SqliFlags.QuoteSingle) != 0)
        {
            return SqliChars.Single;
        }

        if ((flag & SqliFlags.QuoteDouble) != 0)
        {
            return SqliChars.Double;
        }

        return SqliChars.Null;
    }

    /// <summary>
    /// "\"" one backslash = escaped; "\\"" two = not escaped; "\\\"" three = escaped.
    /// </summary>
    public static bool IsBackslashEscaped(ReadOnlySpan<byte> str)
    {
        int count = 0;
        for (int i = str.Length - 1; i >= 0; i--)
        {
            if (str[i] == '\\')
            {
                count++;
            }
            else
            {
                break;
            }
        }

        // if number of backslashes is odd, it is escaped
        return count % 2 != 0;
    }

    public static bool IsDoubleDelimiterEscaped(ReadOnlySpan<byte> str) => str.Length >= 2 && str[0] == str[1];

    /// <summary>
    /// ' ', \t, \n, \v, \f, \r, 0xA0 (Latin-1 non-breaking space) and NUL (Oracle).
    /// </summary>
    public static bool IsByteWhite(byte ch) =>
        ch is (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\v' or (byte)'\f' or (byte)'\r' or 0xA0 or 0x00;

    /// <summary>
    /// Length of the longest prefix of <paramref name="s"/> (first <paramref name="length"/> bytes) made of
    /// bytes in <paramref name="accept"/>. As with C's strchr, NUL belongs to every accept set.
    /// </summary>
    public static int StrLenSpn(ReadOnlySpan<byte> s, int length, ReadOnlySpan<byte> accept)
    {
        for (int i = 0; i < length; i++)
        {
            if (s[i] == 0)
            {
                continue;
            }

            if (accept.IndexOf(s[i]) == -1)
            {
                return i;
            }
        }

        return length;
    }

    /// <summary>
    /// Length of the longest prefix with no byte flagged in <paramref name="reject"/> (a 256-entry table).
    /// NUL always ends the span.
    /// </summary>
    public static int StrLenCSpn(ReadOnlySpan<byte> s, int length, ReadOnlySpan<bool> reject)
    {
        for (int i = 0; i < length; i++)
        {
            if (s[i] == 0 || reject[s[i]])
            {
                return i;
            }
        }

        return length;
    }

    /// <summary>
    /// Detects MySQL comments that start with /*! (banned outright).
    /// Caller has checked s[pos] == '/' and s[pos+1] == '*'.
    /// </summary>
    public static bool IsMysqlComment(ReadOnlySpan<byte> s, int pos)
    {
        if (pos + 2 >= s.Length)
        {
            return false;
        }

        return s[pos + 2] == '!';
    }

    /// <summary>ASCII case-insensitive compare of <paramref name="s"/> with an upper-case <paramref name="expectedUpper"/>.</summary>
    public static bool ToUpperCmp(ReadOnlySpan<byte> expectedUpper, ReadOnlySpan<byte> s)
    {
        if (expectedUpper.Length != s.Length)
        {
            return false;
        }

        for (int i = 0; i < expectedUpper.Length; i++)
        {
            byte c = s[i];
            if (c is >= (byte)'a' and <= (byte)'z')
            {
                c -= 0x20;
            }

            if (expectedUpper[i] != c)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Builds a 256-entry table that flags each byte in <paramref name="chars"/>.
    /// </summary>
    public static bool[] BuildTable(ReadOnlySpan<byte> chars)
    {
        var table = new bool[256];
        foreach (byte b in chars)
        {
            table[b] = true;
        }

        return table;
    }
}

/// <summary>The libinjection keyword, operator, phrase and fingerprint map (sqlKeywords).</summary>
internal static class SqliKeywords
{
    private static readonly FrozenDictionary<string, byte> Map = Build();

    private static readonly FrozenDictionary<string, byte>.AlternateLookup<ReadOnlySpan<char>> SpanMap =
        Map.GetAlternateLookup<ReadOnlySpan<char>>();

    /// <summary>Longest key in the map; longer words cannot match.</summary>
    private static readonly int MaxKeyLength = Map.Keys.Max(k => k.Length);

    internal static int Count => Map.Count;

    private static FrozenDictionary<string, byte> Build()
    {
        var d = new Dictionary<string, byte>(SqliData.KeywordCount, StringComparer.Ordinal);
        foreach (var (category, keys) in SqliData.KeywordGroups)
        {
            foreach (var key in keys.Split('\n'))
            {
                d.Add(key, (byte)category);
            }
        }

        return d.ToFrozenDictionary(StringComparer.Ordinal);
    }

    /// <summary>
    /// Go: <c>searchKeyword(key)</c> = <c>sqlKeywords[strings.ToUpper(key)]</c>, or 0 when absent.
    /// </summary>
    /// <remarks>
    /// Go's strings.ToUpper decodes UTF-8. All keys are ASCII, so a non-ASCII byte can only match when it
    /// is part of a UTF-8 sequence that upper-cases to ASCII: U+0131 (C4 B1) to 'I' and U+017F (C5 BF) to 'S'.
    /// Any other non-ASCII byte leaves a non-ASCII rune (or U+FFFD) in the key, which never matches.
    /// </remarks>
    public static byte Search(ReadOnlySpan<byte> key)
    {
        if (key.Length > MaxKeyLength * 2)
        {
            return SqliChars.Null;
        }

        Span<char> upper = stackalloc char[key.Length];
        int n = 0;
        for (int i = 0; i < key.Length; i++)
        {
            byte b = key[i];
            if (b < 0x80)
            {
                upper[n++] = b is >= (byte)'a' and <= (byte)'z' ? (char)(b - 0x20) : (char)b;
            }
            else if (b == 0xC4 && i + 1 < key.Length && key[i + 1] == 0xB1)
            {
                upper[n++] = 'I';
                i++;
            }
            else if (b == 0xC5 && i + 1 < key.Length && key[i + 1] == 0xBF)
            {
                upper[n++] = 'S';
                i++;
            }
            else
            {
                return SqliChars.Null;
            }
        }

        return SpanMap.TryGetValue(upper[..n], out byte value) ? value : SqliChars.Null;
    }

    /// <summary>Exact (already upper-case) lookup, used for fingerprints.</summary>
    public static bool TryGetExact(ReadOnlySpan<char> key, out byte value) => SpanMap.TryGetValue(key, out value);
}
