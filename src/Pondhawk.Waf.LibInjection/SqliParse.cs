// Ported from libinjection-go (https://github.com/corazawaf/libinjection-go), sqli_parse.go.
// Copyright (c) 2022-Present, Coraza. BSD-3-Clause; see LICENSE-libinjection.txt.

namespace Pondhawk.Waf.LibInjection;

/// <summary>Byte tables for the SQLi tokenizer.</summary>
internal static class SqliTables
{
    /// <summary>Bytes that end a word: <c>" []{}&lt;&gt;:\?=@!#~+-*/&amp;|^%(),';\t\n\v\f\r\""</c>, 0xA0 and NUL.</summary>
    public static readonly bool[] WordReject =
        SqliHelpers.BuildTable([.. " []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\v\f\r\""u8, 0xA0, 0x00]);

    /// <summary>Bytes that end a variable name.</summary>
    public static readonly bool[] VarReject =
        SqliHelpers.BuildTable(" <>:\\?=@!#~+-*/&|^%(),';\t\n\v\f\r'`\""u8);
}

internal ref partial struct SqliState
{
    private int ParseQStringCore(int offset)
    {
        int pos = Pos + offset;

        // if we are already at the end of the string
        // if current byte is not q or Q
        // if we don't have 2 more bytes
        // if byte[2] != a single quote
        // then, just treat as word
        if (pos >= Length || (Input[pos] != 'q' && Input[pos] != 'Q') || pos + 2 >= Length || Input[pos + 1] != SqliChars.Single)
        {
            return ParseWord();
        }

        byte ch = Input[pos + 2];

        // upstream C relies on char being signed so that bytes >= 0x80 fail the
        // ch < 33 check; check the upper bound explicitly
        if (ch < 33 || ch > 127)
        {
            return ParseWord();
        }

        ch = ch switch
        {
            (byte)'(' => (byte)')',
            (byte)'[' => (byte)']',
            (byte)'{' => (byte)'}',
            (byte)'<' => (byte)'>',
            _ => ch,
        };

        ReadOnlySpan<byte> end = [ch, SqliChars.Single];
        int index = Input[(pos + 3)..].IndexOf(end);
        ref SqliToken cur = ref CurrentToken;
        if (index == -1)
        {
            cur.Assign(SqliChars.TypeString, pos + 3, Length - pos - 3, Input[(pos + 3)..]);
            cur.StrOpen = (byte)'q';
            cur.StrClose = SqliChars.Null;
            return Length;
        }

        cur.Assign(SqliChars.TypeString, pos + 3, index, Input[(pos + 3)..]);
        cur.StrOpen = (byte)'q';
        cur.StrClose = (byte)'q';
        return pos + 3 + index + 2;
    }

    /// <summary>Dispatches on the byte at <see cref="Pos"/> (Go: byteParsers table).</summary>
    private int ParseByteFunctions(byte ch) => ch switch
    {
        <= 32 => ParseWhite(),
        33 => ParseOperator2(),
        34 => ParseString(),
        35 => ParseHash(),
        36 => ParseMoney(),
        37 => ParseOperator1(),
        38 => ParseOperator2(),
        39 => ParseString(),
        40 or 41 => ParseByte(),
        42 => ParseOperator2(),
        43 => ParseOperator1(),
        44 => ParseByte(),
        45 => ParseDash(),
        46 => ParseNumber(),
        47 => ParseSlash(),
        >= 48 and <= 57 => ParseNumber(),
        58 => ParseOperator2(),
        59 => ParseByte(),
        >= 60 and <= 62 => ParseOperator2(),
        63 => ParseOther(),
        64 => ParseVar(),
        65 => ParseWord(),
        66 => ParseBString(),
        67 or 68 => ParseWord(),
        69 => ParseEString(),
        >= 70 and <= 77 => ParseWord(),
        78 => ParseNqString(),
        79 or 80 => ParseWord(),
        81 => ParseQString(),
        >= 82 and <= 84 => ParseWord(),
        85 => ParseUString(),
        86 or 87 => ParseWord(),
        88 => ParseXString(),
        89 or 90 => ParseWord(),
        91 => ParseBWord(),
        92 => ParseBackSlash(),
        93 => ParseOther(),
        94 => ParseOperator1(),
        95 => ParseWord(),
        96 => ParseTick(),
        97 => ParseWord(),
        98 => ParseBString(),
        99 or 100 => ParseWord(),
        101 => ParseEString(),
        >= 102 and <= 109 => ParseWord(),
        110 => ParseNqString(),
        111 or 112 => ParseWord(),
        113 => ParseQString(),
        >= 114 and <= 116 => ParseWord(),
        117 => ParseUString(),
        118 or 119 => ParseWord(),
        120 => ParseXString(),
        121 or 122 => ParseWord(),
        123 => ParseByte(),
        124 => ParseOperator2(),
        125 => ParseByte(),
        126 => ParseOperator1(),
        127 => ParseWhite(),
        160 => ParseWhite(),
        _ => ParseWord(), // 128..159, 161..255
    };

    private int ParseEolComment()
    {
        int index = Input[Pos..].IndexOf((byte)'\n');
        ref SqliToken cur = ref CurrentToken;
        if (index == -1)
        {
            cur.Assign(SqliChars.TypeComment, Pos, Length - Pos, Input[Pos..]);
            return Length;
        }

        cur.Assign(SqliChars.TypeComment, Pos, index, Input[Pos..]);
        return Pos + index + 1;
    }

    private int ParseMoney()
    {
        ref SqliToken cur = ref CurrentToken;
        if (Pos + 1 == Length)
        {
            cur.Assign(SqliChars.TypeBareWord, Pos, 1, "$"u8);
            return Length;
        }

        // $1,000.00 or $1.000,00 ok!
        // This also parses $.....,,111 but that's ok
        int length = SqliHelpers.StrLenSpn(Input[(Pos + 1)..], Length - Pos - 1, "0123456789.,"u8);
        if (length == 0)
        {
            if (Input[Pos + 1] == '$')
            {
                // we have $$ .. find ending $$ and make string
                int index = Input[(Pos + 2)..].IndexOf("$$"u8);
                if (index == -1)
                {
                    cur.Assign(SqliChars.TypeString, Pos + 2, Length - (Pos + 2), Input[(Pos + 2)..]);
                    cur.StrOpen = (byte)'$';
                    cur.StrClose = SqliChars.Null;
                    return Length;
                }

                cur.Assign(SqliChars.TypeString, Pos + 2, index, Input[(Pos + 2)..]);
                cur.StrOpen = (byte)'$';
                cur.StrClose = (byte)'$';
                return Pos + 2 + index + 2;
            }

            // ok it's not a number or '$$', but maybe it's pgsql "$ quoted strings"
            int xlen = SqliHelpers.StrLenSpn(Input[(Pos + 1)..], Length - Pos - 1,
                "abcdefghjiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"u8);
            if (xlen == 0)
            {
                // hmm, it's "$" _something_ .. just add $ and keep going
                cur.Assign(SqliChars.TypeBareWord, Pos, 1, "$"u8);
                return Pos + 1;
            }

            // we have $foobar?????
            if (Pos + xlen + 1 == Length || Input[Pos + xlen + 1] != '$')
            {
                // not $foobar$, or fell off edge
                cur.Assign(SqliChars.TypeBareWord, Pos, 1, "$"u8);
                return Pos + 1;
            }

            // we have $foobar$ ... find it again
            int index2 = Input[(Pos + xlen + 2)..].IndexOf(Input[Pos..(Pos + xlen + 2)]);
            if (index2 == -1)
            {
                cur.Assign(SqliChars.TypeString, Pos + xlen + 2, Length - Pos - xlen - 2, Input[(Pos + xlen + 2)..]);
                cur.StrOpen = (byte)'$';
                cur.StrClose = SqliChars.Null;
                return Length;
            }

            // get one
            cur.Assign(SqliChars.TypeString, Pos + xlen + 2, index2, Input[(Pos + xlen + 2)..]);
            cur.StrOpen = (byte)'$';
            cur.StrClose = (byte)'$';
            return Pos + xlen + 2 + index2 + xlen + 2;
        }

        if (length == 1 && Input[Pos + 1] == '.')
        {
            return ParseWord();
        }

        cur.Assign(SqliChars.TypeNumber, Pos, length + 1, Input[Pos..]);
        return Pos + length + 1;
    }

    private int ParseOther()
    {
        CurrentToken.Assign(SqliChars.TypeUnknown, Pos, 1, Input[Pos..]);
        return Pos + 1;
    }

    private readonly int ParseWhite() => Pos + 1;

    private int ParseOperator1()
    {
        CurrentToken.Assign(SqliChars.TypeOperator, Pos, 1, Input[Pos..]);
        return Pos + 1;
    }

    private int ParseByte()
    {
        CurrentToken.Assign(Input[Pos], Pos, 1, Input[Pos..]);
        return Pos + 1;
    }

    /// <summary>In ANSI mode, hash is an operator. In MySQL mode, it is an EOL comment like '--'.</summary>
    private int ParseHash()
    {
        StatsCommentHash++;
        if ((Flags & SqliFlags.SqlMysql) != 0)
        {
            StatsCommentHash++;
            return ParseEolComment();
        }

        CurrentToken.Assign(SqliChars.TypeOperator, Pos, 1, "#"u8);
        return Pos + 1;
    }

    private int ParseDash()
    {
        // five cases
        // 1) --[white] this is always a SQL comment
        // 2) --[EOL] this is a comment
        // 3) --[not white] in MYSQL this is NOT a comment but two unary operators
        // 4) --[not white] everyone else thinks this is a comment
        // 5) -[not dash] '-' is a unary operator
        if (Pos + 2 < Length && Input[Pos + 1] == '-' && SqliHelpers.IsByteWhite(Input[Pos + 2]))
        {
            return ParseEolComment();
        }

        if (Pos + 2 == Length && Input[Pos + 1] == '-')
        {
            return ParseEolComment();
        }

        if (Pos + 1 < Length && Input[Pos + 1] == '-' && (Flags & SqliFlags.SqlAnsi) != 0)
        {
            // --[not white] not white case
            StatsCommentDdx++;
            return ParseEolComment();
        }

        CurrentToken.Assign(SqliChars.TypeOperator, Pos, 1, "-"u8);
        return Pos + 1;
    }

    private int ParseSlash()
    {
        if (Pos + 1 == Length || Input[Pos + 1] != '*')
        {
            return ParseOperator1();
        }

        byte ctype = SqliChars.TypeComment;

        // skip over initial '/*'
        int index = Input[(Pos + 2)..].IndexOf("*/"u8);
        int length = index == -1 ? Length - Pos : 2 + index + 2;

        // postgresql allows nested comments which makes
        // which is incompatible with parsing so
        // if we find a '/x' inside the comment, then
        // make a new token.
        //
        // Also, Mysql's "conditional" comments for version
        // are an automatic black ban!
        if (index != -1 && Input[(Pos + 2)..(Pos + 2 + index + 1)].IndexOf("/*"u8) != -1)
        {
            ctype = SqliChars.TypeEvil;
        }
        else if (SqliHelpers.IsMysqlComment(Input, Pos))
        {
            ctype = SqliChars.TypeEvil;
        }

        CurrentToken.Assign(ctype, Pos, length, Input[Pos..]);
        return Pos + length;
    }

    /// <summary>Weird MySQL alias for NULL, "\N" (capital N only).</summary>
    private int ParseBackSlash()
    {
        if (Pos + 1 < Length && Input[Pos + 1] == 'N')
        {
            CurrentToken.Assign(SqliChars.TypeNumber, Pos, 2, Input[Pos..]);
            return Pos + 2;
        }

        CurrentToken.Assign(SqliChars.TypeBackslash, Pos, 1, Input[Pos..]);
        return Pos + 1;
    }

    private int ParseOperator2()
    {
        if (Pos + 1 >= Length)
        {
            return ParseOperator1();
        }

        if (Pos + 2 < Length && Input[Pos] == '<' && Input[Pos + 1] == '=' && Input[Pos + 2] == '>')
        {
            // special 3-char operator
            CurrentToken.Assign(SqliChars.TypeOperator, Pos, 3, Input[Pos..]);
            return Pos + 3;
        }

        byte ch = SqliKeywords.Search(Input.Slice(Pos, 2));
        if (ch != SqliChars.Null)
        {
            CurrentToken.Assign(ch, Pos, 2, Input[Pos..]);
            return Pos + 2;
        }

        // not an operator, what to do with the two characters we got?
        if (Input[Pos] == ':')
        {
            // ':' is not an operator
            CurrentToken.Assign(SqliChars.TypeColon, Pos, 1, Input[Pos..]);
            return Pos + 1;
        }

        // must be a single char operator
        return ParseOperator1();
    }

    /// <summary>Used when first char is a ' or ".</summary>
    private int ParseString() => CurrentToken.ParseStringCore(Input, Length, Pos, 1, Input[Pos]);

    private int ParseWord()
    {
        ref SqliToken cur = ref CurrentToken;
        int length = SqliHelpers.StrLenCSpn(Input[Pos..], Length - Pos, SqliTables.WordReject);
        cur.Assign(SqliChars.TypeBareWord, Pos, length, Input[Pos..]);

        // now we need to look inside what we got for "." and "`"
        // and see if what is before is a keyword or not
        for (int i = 0; i < cur.Len; i++)
        {
            byte delimiter = cur.Val[i];
            if (delimiter == '.' || delimiter == '`')
            {
                byte ch = SqliKeywords.Search(cur.Value[..i]);
                if (ch != SqliChars.TypeNone && ch != SqliChars.TypeBareWord)
                {
                    cur = default;

                    // we got something like "SELECT.1"
                    // or SELECT `column`
                    cur.Assign(ch, Pos, i, Input[Pos..]);
                    return Pos + i;
                }
            }
        }

        // do normal lookup with word including '.'
        if (length < SqliToken.TokenSize)
        {
            byte ch = SqliKeywords.Search(cur.Value[..length]);
            if (ch == SqliChars.Null)
            {
                ch = SqliChars.TypeBareWord;
            }

            cur.Category = ch;
        }

        return Pos + length;
    }

    private int ParseVar()
    {
        int pos = Pos + 1;
        ref SqliToken cur = ref CurrentToken;

        // var count is only used to reconstruct
        // the input. It counts the number of '@'
        // seen 0 in the case of NULL, 1 or 2
        //
        // move past optional other '@'
        if (pos < Length && Input[pos] == '@')
        {
            pos++;
            cur.Count = 2;
        }
        else
        {
            cur.Count = 1;
        }

        // MySQL allows @@`version`
        if (pos < Length)
        {
            if (Input[pos] == '`')
            {
                Pos = pos;
                pos = ParseTick();
                cur.Category = SqliChars.TypeVariable;
                return pos;
            }

            if (Input[pos] == SqliChars.Single || Input[pos] == SqliChars.Double)
            {
                Pos = pos;
                pos = ParseString();
                cur.Category = SqliChars.TypeVariable;
                return pos;
            }
        }

        int length = SqliHelpers.StrLenCSpn(Input[pos..], Length - pos, SqliTables.VarReject);
        if (length == 0)
        {
            cur.Assign(SqliChars.TypeVariable, pos, 0, Input[pos..]);
            return pos;
        }

        cur.Assign(SqliChars.TypeVariable, pos, length, Input[pos..]);
        return pos + length;
    }

    private static bool IsDigit(byte b) => (byte)(b - '0') <= 9;

    private int ParseNumber()
    {
        ReadOnlySpan<byte> digits = default;
        bool haveDigits = false;
        int haveE = 0;
        int haveExp = 0;

        if (Input[Pos] == '0' && Pos + 1 < Length)
        {
            if (Input[Pos + 1] == 'X' || Input[Pos + 1] == 'x')
            {
                digits = "0123456789ABCDEFabcdef"u8;
                haveDigits = true;
            }
            else if (Input[Pos + 1] == 'B' || Input[Pos + 1] == 'b')
            {
                digits = "01"u8;
                haveDigits = true;
            }

            if (haveDigits)
            {
                int length = SqliHelpers.StrLenSpn(Input[(Pos + 2)..], Length - Pos - 2, digits);
                if (length == 0)
                {
                    CurrentToken.Assign(SqliChars.TypeBareWord, Pos, 2, Input[Pos..]);
                    return Pos + 2;
                }

                CurrentToken.Assign(SqliChars.TypeNumber, Pos, 2 + length, Input[Pos..]);
                return Pos + 2 + length;
            }
        }

        int pos = Pos;
        int start = Pos;
        while (pos < Length && IsDigit(Input[pos]))
        {
            pos++;
        }

        if (pos < Length && Input[pos] == '.')
        {
            pos++;
            while (pos < Length && IsDigit(Input[pos]))
            {
                pos++;
            }

            if (pos - start == 1)
            {
                // only one character read so far
                CurrentToken.Assign(SqliChars.TypeDot, start, 1, "."u8);
                return pos;
            }
        }

        if (pos < Length)
        {
            if (Input[pos] == 'E' || Input[pos] == 'e')
            {
                haveE = 1;
                pos++;

                if (pos < Length && (Input[pos] == '+' || Input[pos] == '-'))
                {
                    pos++;
                }

                while (pos < Length && IsDigit(Input[pos]))
                {
                    haveExp = 1;
                    pos++;
                }
            }
        }

        // oracle's ending float or double suffix
        // http://docs.oracle.com/cd/B19306_01/server.102/b14200/sql_elements003.htm#i139891
        if (pos < Length && (Input[pos] == 'd' || Input[pos] == 'D' || Input[pos] == 'f' || Input[pos] == 'F'))
        {
            if (pos + 1 == Length)
            {
                // line ends evaluate "... 1.2f$" as '1.2f'
                pos++;
            }
            else if (SqliHelpers.IsByteWhite(Input[pos + 1]) || Input[pos + 1] == ';')
            {
                // easy case, evaluate "... 1.2f ..." as '1.2f'
                pos++;
            }
            else if (Input[pos + 1] == 'u' || Input[pos + 1] == 'U')
            {
                // a bit of a hack but makes '1fUNION' parse as '1f UNION'
                pos++;
            }

            // otherwise it's like "123FROM": parse as "123" only
        }

        // very special form of "1234.e" "10.10E" ".E" "1e+":
        // MySQL ignores 1.e (https://gosecure.ai/blog/2021/10/19/a-scientific-notation-bug-in-mysql-left-aws-waf-clients-vulnerable-to-sql-injection/),
        // so don't assign any token when haveE == 1 && haveExp == 0.
        if (!(haveE == 1 && haveExp == 0))
        {
            CurrentToken.Assign(SqliChars.TypeNumber, start, pos - start, Input[start..]);
        }

        return pos;
    }

    /// <summary>MySQL back ticks are a cross between string and a bare word.</summary>
    private int ParseTick()
    {
        ref SqliToken cur = ref CurrentToken;
        int pos = cur.ParseStringCore(Input, Length, Pos, 1, SqliChars.Tick);

        // check value of string to see if it's a keyword,
        // function, operator, etc
        byte ch = SqliKeywords.Search(cur.Value);

        // if it's a function, then convert token; otherwise it's a 'n' type --
        // mysql treats everything as a bare word
        cur.Category = ch == SqliChars.TypeFunction ? SqliChars.TypeFunction : SqliChars.TypeBareWord;
        return pos;
    }

    private int ParseUString()
    {
        int pos = Pos;
        if (pos + 2 < Length && Input[pos + 1] == '&' && Input[pos + 2] == SqliChars.Single)
        {
            Pos += 2;
            pos = ParseString();
            ref SqliToken cur = ref CurrentToken;
            cur.StrOpen = (byte)'u';
            if (cur.StrClose == SqliChars.Single)
            {
                cur.StrClose = (byte)'u';
            }

            return pos;
        }

        return ParseWord();
    }

    /// <summary>Oracle's q string.</summary>
    private int ParseQString() => ParseQStringCore(0);

    private int ParseNqString()
    {
        if (Pos + 2 < Length && Input[Pos + 1] == SqliChars.Single)
        {
            return ParseEString();
        }

        return ParseQStringCore(1);
    }

    /// <summary>Hex literal string: [xX]'[0123456789abcdefABCDEF]*'.</summary>
    private int ParseXString()
    {
        // need at least 2 more characters
        // if next char isn't a single quote, then
        // continue as a normal word
        if (Pos + 2 >= Length || Input[Pos + 1] != SqliChars.Single)
        {
            return ParseWord();
        }

        int length = SqliHelpers.StrLenSpn(Input[(Pos + 2)..], Length - Pos - 2, "0123456789abcdefABCDEF"u8);
        if (Pos + 2 + length >= Length || Input[Pos + 2 + length] != SqliChars.Single)
        {
            return ParseWord();
        }

        CurrentToken.Assign(SqliChars.TypeNumber, Pos, length + 3, Input[Pos..]);
        return Pos + 2 + length + 1;
    }

    /// <summary>Binary literal string: [bB]'[01]*'.</summary>
    private int ParseBString()
    {
        // need at least 3 characters
        // if next byte isn't a single quote, then
        // continue as normal word
        if (Pos + 2 >= Length || Input[Pos + 1] != SqliChars.Single)
        {
            return ParseWord();
        }

        int length = SqliHelpers.StrLenSpn(Input[(Pos + 2)..], Length - Pos - 2, "01"u8);
        if (Pos + 2 + length >= Length || Input[Pos + 2 + length] != SqliChars.Single)
        {
            return ParseWord();
        }

        CurrentToken.Assign(SqliChars.TypeNumber, Pos, length + 3, Input[Pos..]);
        return Pos + 2 + length + 1;
    }

    /// <summary>
    /// Used when first byte is E or e (psql "Escaped String"), or N or n (MySQL "National Character set").
    /// </summary>
    private int ParseEString()
    {
        if (Pos + 2 >= Length || Input[Pos + 1] != SqliChars.Single)
        {
            return ParseWord();
        }

        return CurrentToken.ParseStringCore(Input, Length, Pos, 2, SqliChars.Single);
    }

    /// <summary>MS SQL Server bracket words.</summary>
    private int ParseBWord()
    {
        int end = Input[Pos..].IndexOf((byte)']');
        if (end == -1)
        {
            CurrentToken.Assign(SqliChars.TypeBareWord, Pos, Length - Pos, Input[Pos..]);
            return Length;
        }

        CurrentToken.Assign(SqliChars.TypeBareWord, Pos, end + 1, Input[Pos..]);
        return Pos + end + 1;
    }
}
