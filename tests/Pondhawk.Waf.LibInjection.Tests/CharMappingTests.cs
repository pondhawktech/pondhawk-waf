namespace Pondhawk.Waf.LibInjection.Tests;

/// <summary>Tests for the char-to-byte mapping of the public API (not in libinjection-go).</summary>
public class CharMappingTests
{
    [Fact]
    public void Latin1CharsKeepTheirByteValue()
    {
        byte[] b = new byte[4];
        LibInjection.ToBytes("a\u00A0\u00FF\u0000", b);
        Assert.Equal(new byte[] { (byte)'a', 0xA0, 0xFF, 0x00 }, b);
    }

    [Fact]
    public void CharsAboveLatin1BecomeNonAsciiByte()
    {
        byte[] b = new byte[3];
        LibInjection.ToBytes("\u0100\uFF1C\u20AC", b);
        Assert.Equal(new byte[] { 0x80, 0x80, 0x80 }, b);
    }

    [Fact]
    public void NonBreakingSpaceIsSqlWhiteSpace()
    {
        // 0xA0 is white space for the SQLi tokenizer, as in libinjection.
        Assert.True(LibInjection.IsSqli("1\u00A0UNION\u00A0SELECT\u00A01,2--", out _));
    }

    [Fact]
    public void NonLatin1CharsAreWordChars()
    {
        Assert.True(LibInjection.IsSqli("1' or '1'='1", out _));
        Assert.False(LibInjection.IsSqli("\u4F60\u597D", out _));
        Assert.False(LibInjection.IsXss("\u4F60\u597D <b>"));
    }

    [Fact]
    public void LongInputUsesPooledBuffer()
    {
        string attack = new string(' ', 5000) + "1' or '1'='1";
        Assert.True(LibInjection.IsSqli(attack, out _));
        Assert.True(LibInjection.IsXss(new string('a', 5000) + "<script>alert(1)</script>"));
    }

    [Fact]
    public void EmptyInput()
    {
        Assert.False(LibInjection.IsSqli("", out string fp));
        Assert.Equal("", fp);
        Assert.False(LibInjection.IsXss(""));
    }

    [Fact]
    public void GoToUpperDotlessIMatchesKeyword()
    {
        // Go's strings.ToUpper maps U+0131 (UTF-8 C4 B1) to 'I'. As Latin-1 chars these bytes are U+00C4 U+00B1.
        Assert.Equal(SqliKeywords.Search("UNION"u8), SqliKeywords.Search([(byte)'U', (byte)'N', 0xC4, 0xB1, (byte)'O', (byte)'N']));
        Assert.Equal(0, SqliKeywords.Search([(byte)'U', (byte)'N', 0xC4, (byte)'O', (byte)'N']));
    }

    [Fact]
    public void RandomInputsDoNotThrow()
    {
        // Robustness: the detectors must not throw on any input. Fixed seed, alphabet biased to syntax bytes.
        const string alphabet = "'\"`\\/*-#$@!=<>()[]{}%&|^~+.,;:?_ \t\n\r\0aAbBeEnNqQuUxXsS019\u00A0\u00E9\u0100";
        var rng = new Random(12345);
        char[] buf = new char[64];
        for (int n = 0; n < 200_000; n++)
        {
            int len = rng.Next(0, buf.Length);
            for (int i = 0; i < len; i++)
            {
                buf[i] = alphabet[rng.Next(alphabet.Length)];
            }

            LibInjection.IsSqli(buf.AsSpan(0, len), out _);
            LibInjection.IsXss(buf.AsSpan(0, len));
        }
    }
}
