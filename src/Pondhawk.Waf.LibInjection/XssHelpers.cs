// Ported from libinjection-go (https://github.com/corazawaf/libinjection-go), xss_helpers.go and xss_decls.go.
// Copyright (c) 2022-Present, Coraza. BSD-3-Clause; see LICENSE-libinjection.txt.

using System.Collections.Frozen;

namespace Pondhawk.Waf.LibInjection;

/// <summary>Attribute classification.</summary>
internal enum AttributeType
{
    None,
    Black,
    AttrUrl,
    Style,
    AttrIndirect,
}

internal static class XssHelpers
{
    /// <summary>
    /// Stack buffer size for upper-cased, NUL-stripped tag and attribute names. Must exceed the longest
    /// blacklisted name ("ON" + "WEBKITCURRENTPLAYBACKTARGETISWIRELESSCHANGED" = 48).
    /// </summary>
    public const int MaxNormalizedTokenLen = 64;

    public const int ByteEof = -1;

    private static readonly FrozenDictionary<string, AttributeType>.AlternateLookup<ReadOnlySpan<char>> BlackEventsMap =
        XssData.BlackEvents.ToFrozenDictionary(e => e.Name, e => e.Type, StringComparer.Ordinal)
            .GetAlternateLookup<ReadOnlySpan<char>>();

    private static readonly FrozenDictionary<string, AttributeType>.AlternateLookup<ReadOnlySpan<char>> BlacksMap =
        XssData.Blacks.ToFrozenDictionary(e => e.Name, e => e.Type, StringComparer.Ordinal)
            .GetAlternateLookup<ReadOnlySpan<char>>();

    private static readonly byte[][] BlackTagBytes =
        [.. XssData.BlackTags.Select(t => t.Select(c => (byte)c).ToArray())];

    /// <summary>Compares two equal-length ASCII strings case-insensitively.</summary>
    public static bool AsciiEqualFold(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

        for (int i = 0; i < a.Length; i++)
        {
            byte ca = a[i], cb = b[i];
            if (ca is >= (byte)'A' and <= (byte)'Z')
            {
                ca += 0x20;
            }

            if (cb is >= (byte)'A' and <= (byte)'Z')
            {
                cb += 0x20;
            }

            if (ca != cb)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Normalizes <paramref name="s"/> into <paramref name="buf"/>: upper-cases ASCII and removes NUL bytes.
    /// Returns the number of bytes written; <paramref name="truncated"/> is true when the non-NUL bytes
    /// did not fit.
    /// </summary>
    public static int UpperRemoveNulls(Span<byte> buf, ReadOnlySpan<byte> s, out bool truncated)
    {
        int n = 0;
        truncated = false;
        for (int i = 0; i < s.Length; i++)
        {
            byte c = s[i];
            if (c == 0)
            {
                continue;
            }

            if (n == buf.Length)
            {
                truncated = true;
                break;
            }

            if (c is >= (byte)'a' and <= (byte)'z')
            {
                c -= 0x20;
            }

            buf[n] = c;
            n++;
        }

        return n;
    }

    public static bool IsBlackTag(ReadOnlySpan<byte> s)
    {
        if (s.Length < 3)
        {
            return false;
        }

        Span<byte> buf = stackalloc byte[MaxNormalizedTokenLen];
        int n = UpperRemoveNulls(buf, s, out bool truncated);
        if (truncated)
        {
            // Input is longer than any blacklisted tag name; cannot match.
            return false;
        }

        ReadOnlySpan<byte> normalized = buf[..n];
        foreach (byte[] tag in BlackTagBytes)
        {
            if (normalized.SequenceEqual(tag))
            {
                return true;
            }
        }

        // anything SVG or XSL(t) related (prefix match on first 3 chars)
        return n >= 3 &&
               ((normalized[0] == 'S' && normalized[1] == 'V' && normalized[2] == 'G') ||
                (normalized[0] == 'X' && normalized[1] == 'S' && normalized[2] == 'L'));
    }

    public static AttributeType IsBlackAttr(ReadOnlySpan<byte> s)
    {
        Span<byte> buf = stackalloc byte[MaxNormalizedTokenLen];
        int n = UpperRemoveNulls(buf, s, out bool truncated);
        if (truncated)
        {
            // Input is longer than any blacklisted attribute name; cannot match.
            return AttributeType.None;
        }

        if (n < 2)
        {
            return AttributeType.None;
        }

        Span<char> chars = stackalloc char[MaxNormalizedTokenLen];
        for (int i = 0; i < n; i++)
        {
            chars[i] = (char)buf[i];
        }

        ReadOnlySpan<char> normalized = chars[..n];

        if (n >= 5)
        {
            if (normalized.SequenceEqual("XMLNS") || normalized.SequenceEqual("XLINK"))
            {
                // got xmlns or xlink tags
                return AttributeType.Black;
            }

            // JavaScript on.* event handlers
            if (buf[0] == 'O' && buf[1] == 'N' && BlackEventsMap.TryGetValue(normalized[2..], out var eventType))
            {
                return eventType;
            }
        }

        return BlacksMap.TryGetValue(normalized, out var type) ? type : AttributeType.None;
    }

    /// <summary>
    /// Decodes one byte or HTML numeric entity at the start of <paramref name="s"/>.
    /// Returns the value (<see cref="ByteEof"/> for empty input) and the bytes consumed.
    /// </summary>
    public static int HtmlDecodeByteAt(ReadOnlySpan<byte> s, out int consumed)
    {
        int length = s.Length;
        int val;

        if (length == 0)
        {
            consumed = 0;
            return ByteEof;
        }

        if (s[0] != '&' || length < 2)
        {
            consumed = 1;
            return s[0];
        }

        if (s[1] != '#' || length < 3)
        {
            // normally this would be for named entities
            // but for this case we don't actually care
            consumed = 1;
            return '&';
        }

        ReadOnlySpan<short> hex = XssData.HexDecodeMap;
        int ch;
        int i;
        if (s[2] == 'x' || s[2] == 'X')
        {
            if (length < 4)
            {
                consumed = 1;
                return '&';
            }

            ch = hex[s[3]];
            if (ch == 256)
            {
                // degenerate case '&#[?]'
                consumed = 1;
                return '&';
            }

            val = ch;
            i = 4;

            while (i < length)
            {
                ch = s[i];
                if (ch == ';')
                {
                    consumed = i + 1;
                    return val;
                }

                ch = hex[ch];
                if (ch == 256)
                {
                    consumed = i;
                    return val;
                }

                val = (val * 16) + ch;
                if (val > 0x1000FF)
                {
                    consumed = 1;
                    return '&';
                }

                i++;
            }

            consumed = i;
            return val;
        }

        i = 2;
        ch = s[i];
        if (ch < '0' || ch > '9')
        {
            consumed = 1;
            return '&';
        }

        val = ch - '0';
        i++;
        while (i < length)
        {
            ch = s[i];
            if (ch == ';')
            {
                consumed = i + 1;
                return val;
            }

            if (ch < '0' || ch > '9')
            {
                consumed = i;
                return val;
            }

            val = (val * 10) + (ch - '0');
            if (val > 0x1000FF)
            {
                consumed = 1;
                return '&';
            }

            i++;
        }

        consumed = i;
        return val;
    }

    /// <summary>
    /// Does an HTML-encoded byte string <paramref name="b"/> start with the upper-case ASCII
    /// <paramref name="a"/>, case-insensitive? Ignores leading whitespace/control chars and embedded NUL and LF.
    /// </summary>
    public static bool HtmlEncodeStartsWith(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        bool first = true;
        int pos = 0;
        int length = b.Length;
        int ai = 0;

        while (length > 0)
        {
            int cb = HtmlDecodeByteAt(b[pos..], out int consumed);
            pos += consumed;
            length -= consumed;

            if (first && cb <= 32)
            {
                // ignore all leading whitespace and control characters
                continue;
            }

            first = false;

            if (cb == 0 || cb == 10)
            {
                // always ignore null characters in user input
                // always ignore vertical tab characters in user input
                continue;
            }

            if (cb is >= 'a' and <= 'z')
            {
                cb -= 0x20;
            }

            // Mask to 8 bits to match C's implicit char truncation behavior.
            byte ch = (byte)(cb & 0xFF);

            if (ai >= a.Length)
            {
                // already matched the full prefix
                return true;
            }

            if (ch != a[ai])
            {
                return false;
            }

            ai++;
        }

        return ai >= a.Length;
    }

    public static bool IsBlackUrl(ReadOnlySpan<byte> s)
    {
        // HEY: this is a signed character.
        // We are intentionally skipping high-bit characters too
        // since they are not ASCII, and Opera sometimes uses UTF-8 whitespace.
        //
        // Also in EUC-JP some of the high bytes are just ignored.
        //
        // Go trims leading runes r <= 32 || r >= 127 (strings.TrimLeftFunc). Every byte >= 0x80 belongs to
        // a multi-byte rune >= 128 or is invalid UTF-8 (U+FFFD); both are trimmed, so a byte-wise trim of
        // bytes <= 32 or >= 127 is identical.
        int start = 0;
        while (start < s.Length && (s[start] <= 32 || s[start] >= 127))
        {
            start++;
        }

        ReadOnlySpan<byte> str = s[start..];
        return HtmlEncodeStartsWith("DATA"u8, str) || // data url
               HtmlEncodeStartsWith("VIEW-SOURCE"u8, str) || // view source url
               HtmlEncodeStartsWith("VBSCRIPT"u8, str) || // obsolete but interesting signal
               HtmlEncodeStartsWith("JAVA"u8, str); // covers JAVA, JAVASCRIPT, + colon
    }
}
