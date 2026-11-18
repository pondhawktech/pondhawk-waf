// Tests ported from libinjection-go (https://github.com/corazawaf/libinjection-go), html5_test.go.
// Copyright (c) 2022-Present, Coraza. BSD-3-Clause; see TestData/LICENSE-libinjection.txt.

namespace Pondhawk.Waf.LibInjection.Tests;

public class Html5Tests
{
    /// <summary>Collects "type:len" for every token, as Go's nextTokenInfos does.</summary>
    private static string[] Tokens(string input, Html5Flags flags = Html5Flags.DataState)
    {
        var h = new H5State(TestSupport.Bytes(input), flags);
        var list = new List<string>();
        while (h.Next())
        {
            list.Add($"{h.TokenType}:{h.TokenLen}");
        }

        return [.. list];
    }

    private static void Check(string input, params string[] want) => Assert.Equal(want, Tokens(input));

    [Fact]
    public void SkipWhiteEof() => Check("<div   ", "TagNameOpen:3");

    [Fact]
    public void StateBogusComment2Continue() => Check("<%a%b>", "TagComment:4");

    [Fact]
    public void StateBogusComment2PctGt() => Check("<%foo%>", "TagComment:3");

    [Fact]
    public void StateCommentNullBytes() => Check("<!---\0->", "TagComment:0");

    [Fact]
    public void StateCommentNonDashBangContinue() => Check("<!--foo-bar-->", "TagComment:7");

    [Fact]
    public void StateCommentNullBytesEof() => Check("<!---\0\0", "TagComment:3");

    [Fact]
    public void StateCommentDashBangNoGt() => Check("<!--foo-!bar-->", "TagComment:8");

    [Fact]
    public void StateCommentEofAfterDashNull() => Check("<!---\0-", "TagComment:3");

    [Fact]
    public void StateEndTagOpenEof() => Check("</");

    [Fact]
    public void StateEndTagOpenGt() => Check("</>", "DataText:1");

    [Fact]
    public void StateEndTagOpenBogus() => Check("</0abc>", "TagComment:4");

    [Fact]
    public void StateTagOpenNullChar() => Check("<\0div>", "TagNameOpen:4", "TagNameClose:1");

    [Fact]
    public void StateTagOpenDefaultNonZeroPos() => Check("<1foo>", "DataText:1", "DataText:5");

    [Fact]
    public void StateTagOpenDefaultZeroPos()
    {
        var h = new H5State("1foo"u8, Html5Flags.DataState) { Pos = 0, State = Html5StateFn.TagOpen };
        Assert.True(h.Next());
        Assert.Equal(Html5Type.DataText, h.TokenType);
        Assert.NotEqual(0, h.TokenLen);
    }

    [Fact]
    public void StateAfterAttributeNameEof() => Check("<div foo   ", "TagNameOpen:3", "AttrName:3");

    [Fact]
    public void StateAfterAttributeNameSlash() =>
        Check("<div foo />", "TagNameOpen:3", "AttrName:3", "TagNameSelfClose:2");

    [Fact]
    public void StateAfterAttributeNameGt() =>
        Check("<div foo >", "TagNameOpen:3", "AttrName:3", "TagNameClose:1");

    [Fact]
    public void StateBeforeAttributeValueEof() => Check("<div href=   ", "TagNameOpen:3", "AttrName:4");

    [Fact]
    public void StateBeforeAttributeNameSlashContinue() =>
        Check("<div / foo>", "TagNameOpen:3", "AttrName:3", "TagNameClose:1");
}
