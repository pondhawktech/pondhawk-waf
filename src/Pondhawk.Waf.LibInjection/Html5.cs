// Ported from libinjection-go (https://github.com/corazawaf/libinjection-go), html5.go and html5_decls.go.
// Copyright (c) 2022-Present, Coraza. BSD-3-Clause; see LICENSE-libinjection.txt.

namespace Pondhawk.Waf.LibInjection;

/// <summary>HTML5 token types.</summary>
internal enum Html5Type
{
    DataText,
    TagNameOpen,
    TagNameClose,
    TagNameSelfClose,
    TagData,
    TagClose,
    AttrName,
    AttrValue,
    TagComment,
    DocType,
}

/// <summary>Start states for the HTML5 tokenizer.</summary>
internal enum Html5Flags
{
    DataState,
    ValueNoQuote,
    ValueSingleQuote,
    ValueDoubleQuote,
    ValueBackQuote,
}

/// <summary>Tokenizer states (Go: function values of type fnH5State).</summary>
internal enum Html5StateFn
{
    Eof,
    Data,
    TagOpen,
    TagNameClose,
    SelfClosingStartTag,
    BeforeAttributeName,
    AfterAttributeName,
    BeforeAttributeValue,
    AfterAttributeValueQuotedState,
    AttributeValueSingleQuote,
    AttributeValueDoubleQuote,
    AttributeValueBackQuote,
}

/// <summary>A small HTML5 tokenizer (the libinjection html5 state machine). Lives on the stack.</summary>
internal ref struct H5State
{
    private const int ByteEof = -1;
    private const byte ByteBang = 33;
    private const byte BytePercent = 37;
    private const byte ByteDash = 45;
    private const byte ByteSlash = 47;
    private const byte ByteLt = 60;
    private const byte ByteEquals = 61;
    private const byte ByteGt = 62;
    private const byte ByteQuestion = 63;
    private const byte ByteRightB = 93;

    public ReadOnlySpan<byte> S;
    public int Len;
    public int Pos;
    public bool IsClose;
    public Html5StateFn State;

    /// <summary>Start offset of the current token in <see cref="S"/>.</summary>
    public int TokenStart;

    public int TokenLen;
    public Html5Type TokenType;

    public H5State(ReadOnlySpan<byte> input, Html5Flags flags)
    {
        S = input;
        Len = input.Length;
        State = flags switch
        {
            Html5Flags.DataState => Html5StateFn.Data,
            Html5Flags.ValueNoQuote => Html5StateFn.BeforeAttributeName,
            Html5Flags.ValueSingleQuote => Html5StateFn.AttributeValueSingleQuote,
            Html5Flags.ValueDoubleQuote => Html5StateFn.AttributeValueDoubleQuote,
            Html5Flags.ValueBackQuote => Html5StateFn.AttributeValueBackQuote,
            _ => Html5StateFn.Eof,
        };
    }

    /// <summary>The current token bytes.</summary>
    public readonly ReadOnlySpan<byte> Token => S.Slice(TokenStart, TokenLen);

    /// <summary>Reads the next token. Returns false at the end.</summary>
    public bool Next() => State switch
    {
        Html5StateFn.Eof => false,
        Html5StateFn.Data => StateData(),
        Html5StateFn.TagOpen => StateTagOpen(),
        Html5StateFn.TagNameClose => StateTagNameClose(),
        Html5StateFn.SelfClosingStartTag => StateSelfClosingStartTag(),
        Html5StateFn.BeforeAttributeName => StateBeforeAttributeName(),
        Html5StateFn.AfterAttributeName => StateAfterAttributeName(),
        Html5StateFn.BeforeAttributeValue => StateBeforeAttributeValue(),
        Html5StateFn.AfterAttributeValueQuotedState => StateAfterAttributeValueQuotedState(),
        Html5StateFn.AttributeValueSingleQuote => StateAttributeValueQuote(SqliChars.Single),
        Html5StateFn.AttributeValueDoubleQuote => StateAttributeValueQuote(SqliChars.Double),
        Html5StateFn.AttributeValueBackQuote => StateAttributeValueQuote(SqliChars.Tick),
        _ => false,
    };

    public static bool IsH5White(byte ch) =>
        ch is (byte)'\n' or (byte)'\t' or (byte)'\v' or (byte)'\f' or (byte)'\r' or (byte)' ';

    private int SkipWhite()
    {
        while (Pos < Len)
        {
            byte ch = S[Pos];
            switch (ch)
            {
                case 0x00:
                case 0x20:
                case 0x09:
                case 0x0A:
                case 0x0B:
                case 0x0C:
                case 0x0D:
                    Pos++;
                    break;
                default:
                    return ch;
            }
        }

        return ByteEof;
    }

    // 12.2.4.44
    private bool StateBogusComment()
    {
        int index = S[Pos..].IndexOf(ByteGt);
        if (index == -1)
        {
            TokenStart = Pos;
            TokenLen = Len - Pos;
            Pos = Len;
            State = Html5StateFn.Eof;
        }
        else
        {
            TokenStart = Pos;
            TokenLen = index;
            Pos = Pos + index + 1;
            State = Html5StateFn.Data;
        }

        TokenType = Html5Type.TagComment;
        return true;
    }

    // 12.2.4.44 ALT
    private bool StateBogusComment2()
    {
        int pos = Pos;
        while (true)
        {
            int index = S[pos..].IndexOf(BytePercent);
            if (index == -1 || pos + index + 1 >= Len)
            {
                TokenStart = Pos;
                TokenLen = Len - Pos;
                Pos = Len;
                TokenType = Html5Type.TagComment;
                State = Html5StateFn.Eof;
                return true;
            }

            // Note: indexes from Pos, not pos, exactly as libinjection-go does.
            if (S[Pos + index + 1] != ByteGt)
            {
                pos = pos + index + 1;
                continue;
            }

            // ends in %>
            TokenStart = Pos;
            TokenLen = index;
            Pos = pos + index + 2;
            State = Html5StateFn.Data;
            TokenType = Html5Type.TagComment;
            return true;
        }
    }

    // 12.2.4.48 - 12.2.4.51
    // state machine spec is confusing since it can only look
    // at one character at a time but simply it's comments end by:
    // 1) EOF
    // 2) ending in -->
    // 3) ending in -!>
    private bool StateComment()
    {
        int pos = Pos;

        while (true)
        {
            int index = S[pos..].IndexOf(ByteDash);

            // did not find anything or has less than 3 characters
            if (index == -1 || pos + index + 3 > Len)
            {
                State = Html5StateFn.Eof;
                TokenStart = Pos;
                TokenLen = Len - Pos;
                TokenType = Html5Type.TagComment;
                return true;
            }

            int offset = 1;

            // skip all nulls
            while (pos + index + offset < Len && S[pos + index + offset] == 0x00)
            {
                offset++;
            }

            if (pos + index + offset == Len)
            {
                State = Html5StateFn.Eof;
                TokenStart = Pos;
                TokenLen = Len - Pos;
                TokenType = Html5Type.TagComment;
                return true;
            }

            byte ch = S[pos + index + offset];
            if (ch != ByteDash && ch != ByteBang)
            {
                pos = pos + index + 1;
                continue;
            }

            offset++;

            if (pos + index + offset == Len)
            {
                State = Html5StateFn.Eof;
                TokenStart = Pos;
                TokenLen = Len - Pos;
                TokenType = Html5Type.TagComment;
                return true;
            }

            if (S[pos + index + offset] != ByteGt)
            {
                pos = pos + index + 1;
                continue;
            }

            offset++;

            // ends in --> or -!>
            TokenStart = Pos;
            TokenLen = index + pos - Pos;
            Pos = pos + index + offset;
            State = Html5StateFn.Data;
            TokenType = Html5Type.TagComment;
            return true;
        }
    }

    private bool StateCData()
    {
        int pos = Pos;

        while (true)
        {
            int index = S[pos..].IndexOf(ByteRightB);

            // did not find anything or has less 3 chars left
            if (index == -1 || pos + index + 3 > Len)
            {
                State = Html5StateFn.Eof;
                TokenStart = Pos;
                TokenLen = Len - Pos;
                TokenType = Html5Type.DataText;
                return true;
            }

            if (S[pos + index + 1] == ByteRightB && S[pos + index + 2] == ByteGt)
            {
                State = Html5StateFn.Data;
                TokenStart = Pos;
                TokenLen = pos + index - Pos;
                Pos = pos + index + 3;
                TokenType = Html5Type.DataText;
                return true;
            }

            pos = pos + index + 1;
        }
    }

    private bool StateDoctype()
    {
        TokenStart = Pos;
        TokenType = Html5Type.DocType;

        int index = S[Pos..].IndexOf(ByteGt);
        if (index == -1)
        {
            State = Html5StateFn.Eof;
            TokenLen = Len - Pos;
        }
        else
        {
            State = Html5StateFn.Data;
            TokenLen = index;
            Pos = Pos + index + 1;
        }

        return true;
    }

    private bool StateMarkupDeclarationOpen()
    {
        int remaining = Len - Pos;
        if (remaining >= 7 && XssHelpers.AsciiEqualFold(S.Slice(Pos, 7), "doctype"u8))
        {
            return StateDoctype();
        }

        if (remaining >= 7 && S.Slice(Pos, 7).SequenceEqual("[CDATA["u8))
        {
            Pos += 7;
            return StateCData();
        }

        if (remaining >= 2 && S.Slice(Pos, 2).SequenceEqual("--"u8))
        {
            Pos += 2;
            return StateComment();
        }

        return StateBogusComment();
    }

    private bool StateSelfClosingStartTag()
    {
        // WARNING: This function is partially inlined into StateBeforeAttributeName()
        if (Pos >= Len)
        {
            return false;
        }

        byte ch = S[Pos];
        if (ch == ByteGt)
        {
            TokenStart = Pos - 1;
            TokenLen = 2;
            TokenType = Html5Type.TagNameSelfClose;
            State = Html5StateFn.Data;
            Pos++;
            return true;
        }

        return StateBeforeAttributeName();
    }

    private bool StateTagNameClose()
    {
        IsClose = false;
        TokenStart = Pos;
        TokenLen = 1;
        TokenType = Html5Type.TagNameClose;
        Pos++;
        State = Pos < Len ? Html5StateFn.Data : Html5StateFn.Eof;
        return true;
    }

    // 12.2.4.10
    private bool StateTagName()
    {
        int pos = Pos;

        while (pos < Len)
        {
            byte ch = S[pos];
            if (ch == 0)
            {
                // special non-standard case
                // allow nulls in tag name
                // some old browsers apparently allow and ignore them
                pos++;
            }
            else if (IsH5White(ch))
            {
                TokenStart = Pos;
                TokenLen = pos - Pos;
                TokenType = Html5Type.TagNameOpen;
                Pos = pos + 1;
                State = Html5StateFn.BeforeAttributeName;
                return true;
            }
            else if (ch == ByteSlash)
            {
                TokenStart = Pos;
                TokenLen = pos - Pos;
                TokenType = Html5Type.TagNameOpen;
                Pos = pos + 1;
                State = Html5StateFn.SelfClosingStartTag;
                return true;
            }
            else if (ch == ByteGt)
            {
                TokenStart = Pos;
                TokenLen = pos - Pos;
                if (IsClose)
                {
                    Pos = pos + 1;
                    IsClose = false;
                    TokenType = Html5Type.TagClose;
                    State = Html5StateFn.Data;
                }
                else
                {
                    Pos = pos;
                    TokenType = Html5Type.TagNameOpen;
                    State = Html5StateFn.TagNameClose;
                }

                return true;
            }
            else
            {
                pos++;
            }
        }

        TokenStart = Pos;
        TokenLen = Len - Pos;
        TokenType = Html5Type.TagNameOpen;
        State = Html5StateFn.Eof;
        return true;
    }

    // 12.2.4.9
    private bool StateEndTagOpen()
    {
        if (Pos >= Len)
        {
            return false;
        }

        byte ch = S[Pos];
        if (ch == ByteGt)
        {
            return StateData();
        }

        if (ch is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z')
        {
            return StateTagName();
        }

        IsClose = false;
        return StateBogusComment();
    }

    private bool StateTagOpen()
    {
        if (Pos >= Len)
        {
            return false;
        }

        byte ch = S[Pos];
        switch (ch)
        {
            case ByteBang:
                Pos++;
                return StateMarkupDeclarationOpen();
            case ByteSlash:
                Pos++;
                IsClose = true;
                return StateEndTagOpen();
            case ByteQuestion:
                Pos++;
                return StateBogusComment();
            case BytePercent:
                // this is not in spec.. alternative comment format used
                // by IE <= 9 and Safari < 4.0.3
                Pos++;
                return StateBogusComment2();
            case >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z':
                return StateTagName();
            case 0:
                // IE-ism NULL characters are ignored
                return StateTagName();
            default:
                // user input mistake in configuring state
                if (Pos == 0)
                {
                    return StateData();
                }

                TokenStart = Pos - 1;
                TokenLen = 1;
                TokenType = Html5Type.DataText;
                State = Html5StateFn.Data;
                return true;
        }
    }

    private bool StateData()
    {
        int index = S[Pos..].IndexOf(ByteLt);
        if (index == -1)
        {
            TokenStart = Pos;
            TokenLen = Len - Pos;
            TokenType = Html5Type.DataText;
            State = Html5StateFn.Eof;
            if (TokenLen == 0)
            {
                return false;
            }
        }
        else
        {
            TokenStart = Pos;
            TokenType = Html5Type.DataText;
            TokenLen = index;
            Pos = Pos + index + 1;
            State = Html5StateFn.TagOpen;
            if (TokenLen == 0)
            {
                return StateTagOpen();
            }
        }

        return true;
    }

    private bool StateAttributeValueNoQuote()
    {
        int pos = Pos;

        while (pos < Len)
        {
            byte ch = S[pos];
            if (IsH5White(ch))
            {
                TokenType = Html5Type.AttrValue;
                TokenStart = Pos;
                TokenLen = pos - Pos;
                Pos = pos + 1;
                State = Html5StateFn.BeforeAttributeName;
                return true;
            }

            if (ch == ByteGt)
            {
                TokenType = Html5Type.AttrValue;
                TokenStart = Pos;
                TokenLen = pos - Pos;
                Pos = pos;
                State = Html5StateFn.TagNameClose;
                return true;
            }

            pos++;
        }

        State = Html5StateFn.Eof;
        TokenStart = Pos;
        TokenLen = Len - Pos;
        TokenType = Html5Type.AttrValue;
        return true;
    }

    // 12.2.4.37
    private bool StateBeforeAttributeValue()
    {
        int ch = SkipWhite();

        if (ch == ByteEof)
        {
            State = Html5StateFn.Eof;
            return false;
        }

        return ch switch
        {
            SqliChars.Double => StateAttributeValueQuote(SqliChars.Double),
            SqliChars.Single => StateAttributeValueQuote(SqliChars.Single),

            // non standard IE
            SqliChars.Tick => StateAttributeValueQuote(SqliChars.Tick),
            _ => StateAttributeValueNoQuote(),
        };
    }

    private bool StateAfterAttributeName()
    {
        int ch = SkipWhite();

        switch (ch)
        {
            case ByteEof:
                return false;
            case ByteSlash:
                Pos++;
                return StateSelfClosingStartTag();
            case ByteEquals:
                Pos++;
                return StateBeforeAttributeValue();
            case ByteGt:
                return StateTagNameClose();
            default:
                return StateAttributeName();
        }
    }

    private bool StateAttributeName()
    {
        int pos = Pos + 1;

        while (pos < Len)
        {
            byte ch = S[pos];
            if (IsH5White(ch))
            {
                TokenStart = Pos;
                TokenLen = pos - Pos;
                TokenType = Html5Type.AttrName;
                State = Html5StateFn.AfterAttributeName;
                Pos = pos + 1;
                return true;
            }

            if (ch == ByteSlash)
            {
                TokenStart = Pos;
                TokenLen = pos - Pos;
                TokenType = Html5Type.AttrName;
                State = Html5StateFn.SelfClosingStartTag;
                Pos = pos + 1;
                return true;
            }

            if (ch == ByteEquals)
            {
                TokenStart = Pos;
                TokenLen = pos - Pos;
                TokenType = Html5Type.AttrName;
                State = Html5StateFn.BeforeAttributeValue;
                Pos = pos + 1;
                return true;
            }

            if (ch == ByteGt)
            {
                TokenStart = Pos;
                TokenLen = pos - Pos;
                TokenType = Html5Type.AttrName;
                State = Html5StateFn.TagNameClose;
                Pos = pos;
                return true;
            }

            pos++;
        }

        // EOF
        TokenStart = Pos;
        TokenLen = Len - Pos;
        TokenType = Html5Type.AttrName;
        State = Html5StateFn.Eof;
        Pos = Len;
        return true;
    }

    private bool StateBeforeAttributeName()
    {
        // The loop is intentionally unbounded: SkipWhite advances Pos and returns
        // ByteEof when Pos >= Len. Every other branch either returns or continues
        // back to SkipWhite, so the loop always terminates.
        while (true)
        {
            int ch = SkipWhite();
            switch (ch)
            {
                case ByteEof:
                    return false;

                case ByteSlash:
                    Pos++;

                    // Logically, we want to call StateSelfClosingStartTag() here
                    // But this function might call us back and result in deep recursion, so
                    // we iterate within this function instead.
                    if (Pos < Len && S[Pos] != ByteGt)
                    {
                        continue;
                    }

                    return StateSelfClosingStartTag();

                case ByteGt:
                    State = Html5StateFn.Data;
                    TokenStart = Pos;
                    TokenLen = 1;
                    TokenType = Html5Type.TagNameClose;
                    Pos++;
                    return true;

                default:
                    return StateAttributeName();
            }
        }
    }

    // 12.2.4.41
    private bool StateAfterAttributeValueQuotedState()
    {
        if (Pos >= Len)
        {
            return false;
        }

        byte ch = S[Pos];
        if (IsH5White(ch))
        {
            Pos++;
            return StateBeforeAttributeName();
        }

        if (ch == ByteSlash)
        {
            Pos++;
            return StateSelfClosingStartTag();
        }

        if (ch == ByteGt)
        {
            TokenStart = Pos;
            TokenLen = 1;
            TokenType = Html5Type.TagNameClose;
            Pos++;
            State = Html5StateFn.Data;
            return true;
        }

        return StateBeforeAttributeName();
    }

    private bool StateAttributeValueQuote(byte ch)
    {
        // skip initial quote in normal case.
        // don't do this "if (pos == 0)" since it means we have started
        // in a non-data state.  given an input of '><foo
        // we want to make 0-length attribute name
        if (Pos > 0)
        {
            Pos++;
        }

        int index = S[Pos..].IndexOf(ch);
        if (index == -1)
        {
            TokenStart = Pos;
            TokenLen = Len - Pos;
            TokenType = Html5Type.AttrValue;
            State = Html5StateFn.Eof;
        }
        else
        {
            TokenStart = Pos;
            TokenLen = index;
            TokenType = Html5Type.AttrValue;
            State = Html5StateFn.AfterAttributeValueQuotedState;
            Pos += TokenLen + 1;
        }

        return true;
    }
}
