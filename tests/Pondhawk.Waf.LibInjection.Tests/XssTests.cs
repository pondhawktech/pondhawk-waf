// Tests ported from libinjection-go (https://github.com/corazawaf/libinjection-go),
// xss_test.go, xss_helpers_test.go, xss_stack_overflow_test.go and pool_test.go.
// Copyright (c) 2022-Present, Coraza. BSD-3-Clause; see TestData/LICENSE-libinjection.txt.

namespace Pondhawk.Waf.LibInjection.Tests;

public class XssTests
{
    // Examples from https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
    [Theory]
    // True positives
    [InlineData("<script>alert(1);</script>", true)]
    [InlineData("><script>alert(1);</script>", true)]
    [InlineData("x ><script>alert(1);</script>", true)]
    [InlineData("' ><script>alert(1);</script>", true)]
    [InlineData("\"><script>alert(1);</script>", true)]
    [InlineData("red;</style><script>alert(1);</script>", true)]
    [InlineData("red;}</style><script>alert(1);</script>", true)]
    [InlineData("red;\"/><script>alert(1);</script>", true)]
    [InlineData("');}</style><script>alert(1);</script>", true)]
    [InlineData("onerror=alert(1)>", true)]
    [InlineData("x onerror=alert(1);>", true)]
    [InlineData("x' onerror=alert(1);>", true)]
    [InlineData("x\" onerror=alert(1);>", true)]
    [InlineData("<a href=\"javascript:alert(1)\">", true)]
    [InlineData("<a href='javascript:alert(1)'>", true)]
    [InlineData("<a href=javascript:alert(1)>", true)]
    [InlineData("<a href  =   javascript:alert(1); >", true)]
    [InlineData("<a href=\"  javascript:alert(1);\" >", true)]
    [InlineData("<a href=\"JAVASCRIPT:alert(1);\" >", true)]
    [InlineData("<style>@keyframes x{}</style><xss style=\"animation-name:x\" onanimationstart=\"alert(1)\"></xss>", true)]
    [InlineData("<noembed><img title=\"</noembed><img src onerror=alert(1)>\"></noembed>", true)]
    [InlineData("javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>", true)]
    [InlineData("<xss class=progress-bar-animated onanimationstart=alert(1)>", true)]
    [InlineData("<button popovertarget=x>Click me</button><xss ontoggle=alert(1) popover id=x>XSS</xss>", true)]
    [InlineData("<HTML xmlns:xss><?import namespace=\"xss\" implementation=\"%(htc)s\"><xss:xss>XSS</xss:xss></HTML>\"\"\",\"XML namespace.\"),(\"\"\"<XML ID=\"xss\"><I><B>&lt;IMG SRC=\"javas<!-- -->cript:javascript:alert(1)\"&gt;</B></I></XML><SPAN DATASRC=\"#xss\" DATAFLD=\"B\" DATAFORMATAS=\"HTML\"></SPAN>", true)]
    [InlineData("<img onauxclick=alert(1)>", true)]
    [InlineData("<img onpagereveal=alert(1)>", true)]
    [InlineData("<img onpageswap=alert(1)>", true)]
    [InlineData("<img onscrollsnapchange=alert(1)>", true)]
    [InlineData("<img onscrollsnapchanging=alert(1)>", true)]
    [InlineData("<!--xml -->", true)]
    [InlineData("<!--xmlfoo-->", true)]
    [InlineData("<!--xml:namespace-->", true)]
    [InlineData("<!--XML -->", true)]
    [InlineData("<svg>", true)]
    [InlineData("<svg onload=alert(1)>", true)]
    [InlineData("<svganimate>", true)]
    // True negatives
    [InlineData("<!--xml-->", false)]
    [InlineData("<!--?xml -->", false)]
    [InlineData("<!--axml -->", false)]
    [InlineData("myvar=onfoobar==", false)]
    [InlineData("onY29va2llcw==", false)]
    [InlineData("<", false)]
    [InlineData("=<a href=\"https://data\">", false)]
    [InlineData("<a href=\"https://github.com/Simbiat/database\">", false)]
    [InlineData("<!DOCTYPE html>", true)]
    [InlineData("<div style=\"color:red\">", true)]
    [InlineData("<div filter=\"alpha\">", true)]
    [InlineData("<div attributename=\"onclick\">", true)]
    [InlineData("<div attributename=\"class\">", false)]
    [InlineData("<!--[IF IE]>foo<![endif]-->", true)]
    [InlineData("<!--[if IE]>foo<![endif]-->", true)]
    [InlineData("<!--`foo`-->", true)]
    [InlineData("<!--IMPORT resource.htc-->", true)]
    [InlineData("<!--ENTITY foo bar-->", true)]
    // TestXSS
    [InlineData("href=&#", false)]
    [InlineData("href=&#X", false)]
    // TestIsXSSEmbeddedNullsInTagComment
    [InlineData("<?im\u0000port namespace=\"t\">", true)]
    [InlineData("<?\u0000import namespace=\"t\">", true)]
    [InlineData("<!\u0000ENTITY x SYSTEM \"file:///etc/passwd\">", true)]
    [InlineData("<!EN\u0000TITY x SYSTEM \"file:///etc/passwd\">", true)]
    public void IsXss(string input, bool isXss)
    {
        Assert.Equal(isXss, LibInjection.IsXss(input));
    }

    // TestIsXSSCDataBounds: must not throw.
    [Theory]
    [InlineData("<![CDATA[]]]")]
    [InlineData("<![CDATA[]]]]")]
    [InlineData("<![CDATA[a]]b]]]")]
    [InlineData("<![CDATA[]]")]
    [InlineData("<![CDATA[]]>")]
    [InlineData("<![CDATA[x]]>y")]
    [InlineData("<![CDATA[]]]>")]
    public void CDataBounds(string input)
    {
        LibInjection.IsXss(input);
    }

    // xss_stack_overflow_test.go: TestMemory.
    [Fact]
    public void NoStackOverflowOnLongSlashRun()
    {
        string input = new('/', 10_000_000);
        LibInjection.IsXss(input);
    }

    [Theory]
    [InlineData("doctype", "doctype", true)]
    [InlineData("DOCTYPE", "doctype", true)]
    [InlineData("doctype", "DOCTYPE", true)]
    [InlineData("data", "date", false)]
    [InlineData("data", "dat", false)]
    public void AsciiEqualFold(string a, string b, bool want)
    {
        Assert.Equal(want, XssHelpers.AsciiEqualFold(TestSupport.Bytes(a), TestSupport.Bytes(b)));
    }

    [Theory]
    [InlineData("", XssHelpers.ByteEof, 0)]
    [InlineData("a", 'a', 1)]
    [InlineData("&", '&', 1)]
    [InlineData("&a", '&', 1)]
    [InlineData("&#", '&', 1)]
    [InlineData("&#a", '&', 1)]
    [InlineData("&#5", 5, 3)]
    [InlineData("&#5;", 5, 4)]
    [InlineData("&#5a", 5, 3)]
    [InlineData("&#9999999", '&', 1)]
    [InlineData("&#x", '&', 1)]
    [InlineData("&#X", '&', 1)]
    [InlineData("&#xG", '&', 1)]
    [InlineData("&#x5", 5, 4)]
    [InlineData("&#x5;", 5, 5)]
    [InlineData("&#X5", 5, 4)]
    [InlineData("&#x5G", 5, 4)]
    [InlineData("&#x1000FF5", '&', 1)]
    public void HtmlDecodeByteAt(string input, int wantVal, int wantConsumed)
    {
        int val = XssHelpers.HtmlDecodeByteAt(TestSupport.Bytes(input), out int consumed);
        Assert.Equal((wantVal, wantConsumed), (val, consumed));
    }

    [Theory]
    [InlineData("xmlns", (int)AttributeType.Black)]
    [InlineData("class", (int)AttributeType.None)]
    [InlineData("onclick", (int)AttributeType.Black)]
    [InlineData("a", (int)AttributeType.None)]
    [InlineData("a\0\0\0\0\0", (int)AttributeType.None)]
    public void IsBlackAttr(string attr, int want)
    {
        Assert.Equal(want, (int)XssHelpers.IsBlackAttr(TestSupport.Bytes(attr)));
    }

    [Fact]
    public void IsBlackAttrOverLength()
    {
        string attr = "onclick" + new string('x', XssHelpers.MaxNormalizedTokenLen);
        Assert.Equal(AttributeType.None, XssHelpers.IsBlackAttr(TestSupport.Bytes(attr)));
    }

    [Theory]
    [InlineData("DATA", "data:", true)]
    [InlineData("JAVA", "javascript:alert(1)", true)]
    [InlineData("DATA", "https://example.com", false)]
    [InlineData("DATA", "https://github.com/Simbiat/database", false)]
    [InlineData("DATA", "nodata", false)]
    [InlineData("DATA", "\tdata:", true)]
    [InlineData("DATA", "d\0ata:", true)]
    [InlineData("DATA", "d\nata:", true)]
    [InlineData("DATA", "dat", false)]
    public void HtmlEncodeStartsWith(string prefix, string input, bool want)
    {
        Assert.Equal(want, XssHelpers.HtmlEncodeStartsWith(TestSupport.Bytes(prefix), TestSupport.Bytes(input)));
    }

    [Theory]
    [InlineData("data:text/html,<script>alert(1)</script>", true)]
    [InlineData("javascript:alert(1)", true)]
    [InlineData("vbscript:msgbox", true)]
    [InlineData("https://example.com", false)]
    [InlineData("https://github.com/Simbiat/database", false)]
    [InlineData("https://example.com/javascript-tutorials", false)]
    public void IsBlackUrl(string url, bool want)
    {
        Assert.Equal(want, XssHelpers.IsBlackUrl(TestSupport.Bytes(url)));
    }

    [Theory]
    [InlineData("SCRIPT", true)]
    [InlineData("svg", true)]
    [InlineData("SVG", true)]
    [InlineData("svganimate", true)]
    [InlineData("svg:rect", true)]
    [InlineData("xsl", true)]
    [InlineData("xsl:template", true)]
    [InlineData("div", false)]
    [InlineData("span", false)]
    [InlineData("sv", false)]
    public void IsBlackTag(string tag, bool want)
    {
        Assert.Equal(want, XssHelpers.IsBlackTag(TestSupport.Bytes(tag)));
    }

    [Theory]
    [InlineData("script")]
    [InlineData("svg")]
    public void IsBlackTagOverLength(string prefix)
    {
        string tag = prefix + new string('x', XssHelpers.MaxNormalizedTokenLen);
        Assert.False(XssHelpers.IsBlackTag(TestSupport.Bytes(tag)));
    }

    // pool_test.go: TestXSSPoolReuse.
    [Fact]
    public void ConsecutiveCallsDoNotLeakState()
    {
        (string Input, bool IsXss)[] cases =
        [
            ("<script>alert(1)</script>", true),
            ("<p>Hello world</p>", false),
            ("<img src=x onerror=alert(1)>", true),
            ("normal text without any html", false),
            ("<svg onload=alert(1)>", true),
            ("john.doe@example.com", false),
            ("<script>alert(1)</script>", true),
            ("<script>alert(1)</script>", true),
            ("<p>Hello world</p>", false),
            ("<p>Hello world</p>", false),
        ];

        foreach (var (input, isXss) in cases)
        {
            Assert.True(isXss == LibInjection.IsXss(input), input);
        }
    }

    // pool_test.go: TestXSSDataStatePrefilter.
    [Theory]
    [InlineData("onerror=alert(1)", true)]
    [InlineData("onerror=alert(1)>", true)]
    [InlineData("x onerror=alert(1);>", true)]
    [InlineData("x' onerror=alert(1);>", true)]
    [InlineData("x\" onerror=alert(1);>", true)]
    [InlineData("onload=alert(1)", true)]
    [InlineData("onclick=alert(1)", true)]
    [InlineData("hello world", false)]
    [InlineData("john.doe@example.com", false)]
    [InlineData("onY29va2llcw==", false)]
    [InlineData("myvar=onfoobar==", false)]
    [InlineData("2024-01-15", false)]
    public void DataStatePrefilter(string input, bool want)
    {
        Assert.Equal(want, LibInjection.IsXss(input));
    }

    // pool_test.go: TestPoolConcurrency (XSS).
    [Fact]
    public void Concurrency()
    {
        Parallel.For(0, 50, worker =>
        {
            for (int i = 0; i < 200; i++)
            {
                Assert.True(LibInjection.IsXss("<script>alert(1)</script>"));
                Assert.False(LibInjection.IsXss("hello world"));
            }
        });
    }
}
