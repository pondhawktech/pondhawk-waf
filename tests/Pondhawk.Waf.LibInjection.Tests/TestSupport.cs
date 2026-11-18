// Test harness ported from libinjection-go (https://github.com/corazawaf/libinjection-go),
// sqli_test.go and xss_test.go (readTestData, printToken, printHTML5Token).
// Copyright (c) 2022-Present, Coraza. BSD-3-Clause; see TestData/LICENSE-libinjection.txt.

using System.Text;

namespace Pondhawk.Waf.LibInjection.Tests;

internal static class TestSupport
{
    public const string SectionTest = "--TEST--";
    public const string SectionInput = "--INPUT--";
    public const string SectionExpected = "--EXPECTED--";

    private static readonly string[] Sections = [SectionTest, SectionInput, SectionExpected];

    public static string TestDataDir => Path.Combine(AppContext.BaseDirectory, "TestData");

    /// <summary>Bytes to a string with one char per byte (Latin-1), the same view the library takes.</summary>
    public static string Latin1(ReadOnlySpan<byte> bytes) => Encoding.Latin1.GetString(bytes);

    public static byte[] Bytes(string latin1)
    {
        var b = new byte[latin1.Length];
        LibInjection.ToBytes(latin1, b);
        return b;
    }

    /// <summary>Go: readTestData. Values are Latin-1 strings of the file bytes.</summary>
    public static Dictionary<string, string> ReadTestData(string path)
    {
        byte[] content = File.ReadAllBytes(path);
        var data = new Dictionary<string, StringBuilder>();
        int count = 0;
        string state = "";

        var lines = new List<string>();
        int start = 0;
        for (int i = 0; i < content.Length; i++)
        {
            if (content[i] == '\n')
            {
                int end = i > start && content[i - 1] == '\r' ? i - 1 : i;
                lines.Add(Latin1(content.AsSpan(start, end - start)));
                start = i + 1;
            }
        }

        if (start < content.Length)
        {
            lines.Add(Latin1(content.AsSpan(start)));
        }

        foreach (string str in lines)
        {
            if (count < Sections.Length && GoTrimSpace(str) == Sections[count])
            {
                state = Sections[count];
                count++;
                continue;
            }

            if (state.Length == 0)
            {
                throw new InvalidDataException($"unexpected content before first section in {path}");
            }

            if (!data.TryGetValue(state, out var sb))
            {
                data[state] = sb = new StringBuilder();
            }

            sb.Append(str).Append('\n');
        }

        if (count != Sections.Length)
        {
            throw new InvalidDataException($"missing sections in {path} (got {count}/{Sections.Length})");
        }

        // Right-trim only (matching C's modp_rtrim), not left-trim
        var result = new Dictionary<string, string>();
        foreach (string s in Sections)
        {
            result[s] = data.TryGetValue(s, out var sb) ? sb.ToString().TrimEnd(' ', '\t', '\n', '\r') : "";
        }

        return result;
    }

    // Unicode White_Space runes outside ASCII, as Go's unicode.IsSpace sees them.
    private static readonly int[] UnicodeSpaces =
        [0x85, 0xA0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
            0x2028, 0x2029, 0x202F, 0x205F, 0x3000];

    private static readonly byte[][] UnicodeSpaceUtf8 =
        [.. UnicodeSpaces.Select(r => Encoding.UTF8.GetBytes(char.ConvertFromUtf32(r)))];

    /// <summary>
    /// Go: strings.TrimSpace on a byte string (given as Latin-1): trims ASCII white space and
    /// valid UTF-8 encodings of Unicode white space at both ends.
    /// </summary>
    public static string GoTrimSpace(string s)
    {
        byte[] b = Bytes(s);
        int lo = 0, hi = b.Length;
        while (lo < hi)
        {
            if (b[lo] is (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\v' or (byte)'\f' or (byte)'\r')
            {
                lo++;
                continue;
            }

            var seq = UnicodeSpaceUtf8.FirstOrDefault(u => b.AsSpan(lo, hi - lo).StartsWith(u));
            if (seq is null)
            {
                break;
            }

            lo += seq.Length;
        }

        while (hi > lo)
        {
            if (b[hi - 1] is (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\v' or (byte)'\f' or (byte)'\r')
            {
                hi--;
                continue;
            }

            var seq = UnicodeSpaceUtf8.FirstOrDefault(u => b.AsSpan(lo, hi - lo).EndsWith(u));
            if (seq is null)
            {
                break;
            }

            hi -= seq.Length;
        }

        return s.Substring(lo, hi - lo);
    }

    private static string PrintTokenString(in SqliToken t)
    {
        var sb = new StringBuilder();
        if (t.StrOpen != 0)
        {
            sb.Append((char)t.StrOpen);
        }

        sb.Append(Latin1(((ReadOnlySpan<byte>)t.Val)[..t.Len]));
        if (t.StrClose != 0)
        {
            sb.Append((char)t.StrClose);
        }

        return sb.ToString();
    }

    /// <summary>Go: printToken.</summary>
    public static string PrintToken(in SqliToken t)
    {
        var sb = new StringBuilder();
        sb.Append((char)t.Category).Append(' ');
        switch ((char)t.Category)
        {
            case 's':
                sb.Append(PrintTokenString(t));
                break;
            case 'v':
                if (t.Count == 1)
                {
                    sb.Append('@');
                }
                else if (t.Count == 2)
                {
                    sb.Append("@@");
                }

                sb.Append(PrintTokenString(t));
                break;
            default:
                sb.Append(Latin1(((ReadOnlySpan<byte>)t.Val)[..t.Len]));
                break;
        }

        return sb.ToString().TrimEnd('\n', '\r');
    }

    public static string H5TypeToString(Html5Type type) => type switch
    {
        Html5Type.DataText => "DATA_TEXT",
        Html5Type.TagNameOpen => "TAG_NAME_OPEN",
        Html5Type.TagNameClose => "TAG_NAME_CLOSE",
        Html5Type.TagNameSelfClose => "TAG_NAME_SELFCLOSE",
        Html5Type.TagData => "TAG_DATA",
        Html5Type.TagClose => "TAG_CLOSE",
        Html5Type.AttrName => "ATTR_NAME",
        Html5Type.AttrValue => "ATTR_VALUE",
        Html5Type.TagComment => "TAG_COMMENT",
        Html5Type.DocType => "DOCTYPE",
        _ => "",
    };

    /// <summary>Go: printHTML5Token.</summary>
    public static string PrintHtml5Token(in H5State h) =>
        $"{H5TypeToString(h.TokenType)},{h.TokenLen},{Latin1(h.Token)}";
}
