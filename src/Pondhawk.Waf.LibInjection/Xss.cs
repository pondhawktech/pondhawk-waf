// Ported from libinjection-go (https://github.com/corazawaf/libinjection-go), xss.go.
// Copyright (c) 2022-Present, Coraza. BSD-3-Clause; see LICENSE-libinjection.txt.

namespace Pondhawk.Waf.LibInjection;

/// <summary>XSS entry point on bytes.</summary>
internal static class Xss
{
    /// <summary>
    /// Go: <c>IsXSS(input)</c>. Five HTML5 parse contexts are tried. The DataState context requires '&lt;'
    /// to produce any tag tokens, so it is skipped when '&lt;' is absent. The four attribute-value contexts
    /// can detect injection without '&lt;' (e.g. onerror=...) and always run.
    /// </summary>
    public static bool IsXss(ReadOnlySpan<byte> input)
    {
        if (input.IndexOf((byte)'<') != -1 && IsXss(input, Html5Flags.DataState))
        {
            return true;
        }

        return IsXss(input, Html5Flags.ValueNoQuote) ||
               IsXss(input, Html5Flags.ValueSingleQuote) ||
               IsXss(input, Html5Flags.ValueDoubleQuote) ||
               IsXss(input, Html5Flags.ValueBackQuote);
    }

    public static bool IsXss(ReadOnlySpan<byte> input, Html5Flags flags)
    {
        var h5 = new H5State(input, flags);
        var attr = AttributeType.None;
        while (h5.Next())
        {
            if (h5.TokenType != Html5Type.AttrValue)
            {
                attr = AttributeType.None;
            }

            if (CheckToken(ref h5, attr, out attr))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Reports whether the current token triggers XSS detection, and returns the attribute context to carry
    /// into the next token. An attribute name sets the context that its value is then judged against; every
    /// other token type leaves the incoming context alone.
    /// </summary>
    private static bool CheckToken(ref H5State h5, AttributeType attr, out AttributeType nextAttr)
    {
        switch (h5.TokenType)
        {
            case Html5Type.DocType:
                nextAttr = attr;
                return true;
            case Html5Type.TagNameOpen:
                nextAttr = attr;
                return XssHelpers.IsBlackTag(h5.Token);
            case Html5Type.AttrName:
                nextAttr = XssHelpers.IsBlackAttr(h5.Token);
                return false;
            case Html5Type.AttrValue:
                nextAttr = AttributeType.None;
                return HandleAttrValue(h5.Token, attr);
            case Html5Type.TagComment:
                nextAttr = attr;
                return HandleTagComment(h5.Token);
            default:
                nextAttr = attr;
                return false;
        }
    }

    /// <summary>
    /// Reports whether an attribute value triggers XSS detection given the attribute context.
    /// IE6/7/8 may hide a full &lt;script&gt; or other black tag inside an attribute value under HTML5 parsing;
    /// see http://html5sec.org/#102.
    /// </summary>
    private static bool HandleAttrValue(ReadOnlySpan<byte> token, AttributeType attr) => attr switch
    {
        AttributeType.None => false,
        AttributeType.Black => true,
        AttributeType.AttrUrl => XssHelpers.IsBlackUrl(token),
        AttributeType.Style => true,

        // an attribute name is specified in a _value_
        AttributeType.AttrIndirect => XssHelpers.IsBlackAttr(token) == AttributeType.Black,
        _ => false,
    };

    /// <summary>
    /// Reports whether a comment token opens with an IE conditional comment ("[if") or an XML namespace
    /// declaration ("xml").
    /// </summary>
    private static bool HasCommentPrefix(ReadOnlySpan<byte> token)
    {
        if (token.Length < 4)
        {
            return false;
        }

        byte l0 = (byte)(token[0] | 0x20), l1 = (byte)(token[1] | 0x20), l2 = (byte)(token[2] | 0x20);
        return (token[0] == '[' && l1 == 'i' && l2 == 'f') ||
               (l0 == 'x' && l1 == 'm' && l2 == 'l');
    }

    /// <summary>
    /// Reports whether an HTML comment token triggers XSS detection (IE backtick terminator,
    /// IE conditional comments, XML namespace declarations, or IE import/entity pseudo-tags).
    /// </summary>
    private static bool HandleTagComment(ReadOnlySpan<byte> token)
    {
        // IE uses "`" as a tag ending byte.
        if (token.IndexOf((byte)'`') != -1)
        {
            return true;
        }

        if (HasCommentPrefix(token))
        {
            return true;
        }

        // IE <?import pseudo-tag or XML Entity definition. The whole token is
        // normalized, not just its first 6 bytes: UpperRemoveNulls drops NULs, so
        // an embedded NUL shifts the keyword past a fixed-width window.
        if (token.Length > 5)
        {
            Span<byte> buf = stackalloc byte[6];
            int n = XssHelpers.UpperRemoveNulls(buf, token, out _);
            if (n == 6 && (buf.SequenceEqual("IMPORT"u8) || buf.SequenceEqual("ENTITY"u8)))
            {
                return true;
            }
        }

        return false;
    }
}
