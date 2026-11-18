using Pondhawk.Waf.Operators;
using Pondhawk.Waf.Transformations;

namespace Pondhawk.Waf.Tests;

public class TransformationTests
{
    [Theory]
    [InlineData("a%20b+c", "a b c")]
    [InlineData("%zz%4", "%zz%4")]
    [InlineData("%u0041%uff1c", "A<")]
    [InlineData("%u2018x%u2019", "'x'")]
    [InlineData("%u12", "%u12")]
    public void UrlDecodeUni(string input, string expected) => Assert.Equal(expected, Transforms.UrlDecodeUni(input));

    [Theory]
    [InlineData(@"\x3cscript\x3e", "<script>")]
    [InlineData(@"\u003c\uff1c", "<<")]
    [InlineData(@"\u{3c}", "<")]
    [InlineData(@"\101\n", "A\n")]
    [InlineData(@"a\", @"a\")]
    public void JsDecode(string input, string expected) => Assert.Equal(expected, Transforms.JsDecode(input));

    [Theory]
    [InlineData(@"\3c script", "<script")]
    [InlineData(@"ja\vascript", "javascript")]
    [InlineData("&lt;svg&gt;", "<svg>")]
    public void CssAndHtml(string input, string expected)
    {
        var result = input.StartsWith('&') ? Transforms.HtmlEntityDecode(input) : Transforms.CssDecode(input);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("javascript&colon;alert&lpar;1&rpar;", "javascript:alert(1)")]
    [InlineData("&#x6A;&#97;", "ja")]
    [InlineData("&#X6a&#97", "ja")]
    [InlineData("&ampfoo", "&foo")]
    [InlineData("&unknown;", "&unknown;")]
    [InlineData("a&b", "a&b")]
    public void HtmlEntityDecodeHandlesHtml5Entities(string input, string expected) =>
        Assert.Equal(expected, Transforms.HtmlEntityDecode(input));

    [Fact]
    public void HtmlEntityDecodeEmitsUtf8Bytes() =>
        Assert.Equal("\u00e2\u0080\u009c", Transforms.HtmlEntityDecode("&#8220;"));

    [Theory]
    [InlineData("C^A\"T /e't'c/passwd", "cat/etc/passwd")]
    [InlineData("ls,;-la", "ls -la")]
    [InlineData("echo  (x)", "echo(x)")]
    public void CmdLine(string input, string expected) => Assert.Equal(expected, Transforms.CmdLine(input));

    [Theory]
    [InlineData("/a/b/../../../etc/passwd", "/etc/passwd")]
    [InlineData("a/./b//c/", "a/b/c/")]
    [InlineData("../../x", "../../x")]
    [InlineData(".", "")]
    public void NormalizePath(string input, string expected) => Assert.Equal(expected, Transforms.NormalizePath(input));

    [Fact]
    public void NormalizePathWinStripsBackslashesAndStreams() =>
        Assert.Equal("c:/windows/win.ini", Transforms.NormalizePathWin("c:\\windows\\system32\\..\\win.ini::$DATA"));

    [Theory]
    [InlineData("sel/**/ect", "sel ect")]
    [InlineData("a/*open", "a ")]
    public void ReplaceComments(string input, string expected) => Assert.Equal(expected, Transforms.ReplaceComments(input));

    [Fact]
    public void RemoveCommentsChar() => Assert.Equal("selectx", Transforms.RemoveCommentsChar("sel/*ect*/--#x"));

    [Fact]
    public void CompressWhitespace() => Assert.Equal("a b c", Transforms.CompressWhitespace("a \t\n b\u00A0c"));

    [Fact]
    public void Utf8ToUnicodeEncodesMultibyteAndInvalidBytes()
    {
        // "é" as UTF-8 bytes, then an invalid lone 0xff byte.
        Assert.Equal("a%u00e9%ufffd", Transforms.Utf8ToUnicode("a\u00c3\u00a9\u00ff"));
    }

    [Theory]
    [InlineData("aGVsbG8=", "hello")]
    [InlineData("aGVsbG8", "hello")]
    [InlineData("aGVs!bG8", "hel")]
    public void Base64Decode(string input, string expected) => Assert.Equal(expected, Transforms.Base64Decode(input, false));

    [Fact]
    public void LowercaseHandlesUtf8() => Assert.Equal("select \u00c3\u00a9", Transforms.Lowercase("SELECT \u00c3\u0089"));

    [Theory]
    [InlineData(@"[\--9]", @"[\x2d-9]")]
    [InlineData(@"\x{e2}[\x80-\x{bf}]", @"\xe2[\x80-\xbf]")]
    [InlineData(@"[a-z-[b]", @"[a-z-\[b]")]
    [InlineData(@"[]a]", @"[\]a]")]
    [InlineData(@"(?P<n>x)", @"(?<n>x)")]
    public void RegexTranslation(string re2, string dotnet) => Assert.Equal(dotnet, RegexCache.TranslatePattern(re2));

    [Fact]
    public void EscapedRangeStartMatchesLikeRe2()
    {
        var rx = new RegexCache().Get(@"^[\--9]+$");
        Assert.Matches(rx, "/0-9.");
        Assert.DoesNotMatch(rx, "a");
    }
}
