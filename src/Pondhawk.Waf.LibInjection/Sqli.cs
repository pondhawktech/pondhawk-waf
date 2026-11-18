// Ported from libinjection-go (https://github.com/corazawaf/libinjection-go), sqli.go.
// Copyright (c) 2022-Present, Coraza. BSD-3-Clause; see LICENSE-libinjection.txt.

using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Pondhawk.Waf.LibInjection;

/// <summary>Token vector: max tokens + 1 extra (to type the previous token), rounded up to 8 as in Go.</summary>
[InlineArray(8)]
internal struct SqliTokenVec
{
    private SqliToken _element0;
}

/// <summary>Fingerprint buffer (at most <see cref="SqliToken.MaxTokens"/> bytes).</summary>
[InlineArray(8)]
internal struct SqliFingerprintBuffer
{
    private byte _element0;
}

/// <summary>SQLi entry point on bytes.</summary>
internal static class Sqli
{
    /// <summary>Go: <c>IsSQLi(input)</c>.</summary>
    public static bool IsSqli(ReadOnlySpan<byte> input, out string fingerprint)
    {
        var state = new SqliState(input, 0);
        if (state.Check())
        {
            fingerprint = string.Create(state.Fingerprint.Length, state.FingerprintBuffer, static (dst, buf) =>
            {
                ReadOnlySpan<byte> src = buf;
                for (int i = 0; i < dst.Length; i++)
                {
                    dst[i] = (char)src[i];
                }
            });
            return true;
        }

        fingerprint = string.Empty;
        return false;
    }
}

/// <summary>SQLi tokenizer, folder and fingerprint checker. Lives on the stack.</summary>
internal ref partial struct SqliState
{
    /// <summary>Input; not modified.</summary>
    public ReadOnlySpan<byte> Input;

    public int Length;
    public int Flags;

    /// <summary>Position in the input during tokenization.</summary>
    public int Pos;

    public SqliTokenVec TokenVec;

    /// <summary>Index in <see cref="TokenVec"/> of the current token (Go: <c>current</c> pointer).</summary>
    public int Current;

    public SqliFingerprintBuffer FingerprintBuffer;
    public int FingerprintLength;

    /// <summary>Number of ddx (dash-dash-[not white]) comments.</summary>
    public int StatsCommentDdx;

    /// <summary>'#' operators or MySQL EOL comments found.</summary>
    public int StatsCommentHash;

    /// <summary>Number of tokens folded away.</summary>
    public int StatsFolds;

    /// <summary>Total tokens processed.</summary>
    public int StatsTokens;

    /// <summary>Go: <c>sqliInit</c>.</summary>
    public SqliState(ReadOnlySpan<byte> input, int flags)
    {
        Init(input, flags);
    }

    [UnscopedRef]
    public ref SqliToken CurrentToken => ref TokenVec[Current];

    [UnscopedRef]
    public ReadOnlySpan<byte> Fingerprint => ((ReadOnlySpan<byte>)FingerprintBuffer)[..FingerprintLength];

    public void Init(ReadOnlySpan<byte> input, int flags)
    {
        if (flags == 0)
        {
            flags = SqliFlags.QuoteNone | SqliFlags.SqlAnsi;
        }

        this = default;
        Input = input;
        Length = input.Length;
        Flags = flags;
        Current = 0;
    }

    public void SetFingerprint(scoped ReadOnlySpan<byte> fingerprint)
    {
        Span<byte> buf = FingerprintBuffer;
        buf.Clear();
        fingerprint.CopyTo(buf);
        FingerprintLength = fingerprint.Length;
    }

    /// <summary>
    /// Fingerprints the input in the context given by <paramref name="flags"/>
    /// (quote none / single / double, ANSI or MySQL).
    /// </summary>
    public void SqliFingerprint(int flags)
    {
        Reset(flags);
        int length = Fold();

        // check for magic PHP backquote comment
        // If:
        //     last token is of type "bareword"
        //     And is quoted in a backtick
        //     And isn't closed
        //     And it's empty?
        //     Then convert it to comment
        if (length > 2)
        {
            ref SqliToken last = ref TokenVec[length - 1];
            if (last.Category == SqliChars.TypeBareWord && last.StrOpen == SqliChars.Tick &&
                last.Len == 0 && last.StrClose == SqliChars.Null)
            {
                last.Category = SqliChars.TypeComment;
            }
        }

        Span<byte> buf = stackalloc byte[SqliToken.MaxTokens];
        for (int i = 0; i < length; i++)
        {
            byte c = TokenVec[i].Category;

            // check for 'X' in pattern, and then
            // clear out all tokens
            //
            // this means parsing could not be done
            // accurately due to pgsql's double comments
            // or other syntax that isn't consistent.
            // Should be very rare false positive
            if (c == SqliChars.TypeEvil)
            {
                SetFingerprint([SqliChars.TypeEvil]);
                TokenVec[0].Category = SqliChars.TypeEvil;
                TokenVec[0].SetVal([SqliChars.TypeEvil]);
                return;
            }

            buf[i] = c;
        }

        SetFingerprint(buf[..length]);
    }

    /// <summary>
    /// See if two tokens can be merged since they are compound SQL phrases
    /// (example: "UNION" + "ALL" = "UNION ALL").
    /// </summary>
    private static bool Merge(ref SqliToken a, ref SqliToken b)
    {
        // first token is of right type?
        if (!(a.Category is SqliChars.TypeKeyword or SqliChars.TypeBareWord or SqliChars.TypeOperator
                or SqliChars.TypeUnion or SqliChars.TypeFunction or SqliChars.TypeExpression
                or SqliChars.TypeTsql or SqliChars.TypeSqlType))
        {
            return false;
        }

        if (!(b.Category is SqliChars.TypeKeyword or SqliChars.TypeBareWord or SqliChars.TypeOperator
                or SqliChars.TypeUnion or SqliChars.TypeFunction or SqliChars.TypeExpression
                or SqliChars.TypeTsql or SqliChars.TypeSqlType or SqliChars.TypeLogicOperator))
        {
            return false;
        }

        // +1 for space in the middle
        if (a.Len + b.Len + 1 > SqliToken.TokenSize)
        {
            // make sure there is room for ending null
            return false;
        }

        Span<byte> tmp = stackalloc byte[SqliToken.TokenSize];
        int n = a.Len + b.Len + 1;
        a.Value.CopyTo(tmp);
        tmp[a.Len] = (byte)' ';
        b.Value.CopyTo(tmp[(a.Len + 1)..]);
        tmp = tmp[..n];

        byte ch = SqliKeywords.Search(tmp);
        if (ch != SqliChars.Null)
        {
            a.Assign(ch, a.Pos, n, tmp);
            return true;
        }

        return false;
    }

    private bool IsUserFunctionWord(ref SqliToken t)
    {
        ReadOnlySpan<byte> v = t.Value;
        return

            // TSQL functions but common enough to be column names
            SqliHelpers.ToUpperCmp("USER_ID"u8, v) ||
            SqliHelpers.ToUpperCmp("USER_NAME"u8, v) ||

            // Function in MySQL
            SqliHelpers.ToUpperCmp("DATABASE"u8, v) ||
            SqliHelpers.ToUpperCmp("PASSWORD"u8, v) ||
            SqliHelpers.ToUpperCmp("USER"u8, v) ||

            // MySQL words that act as a variable and are a function

            // TSQL current_users is fake_variable
            // http://msdn.microsoft.com/en-us/library/ms176050.aspx
            SqliHelpers.ToUpperCmp("CURRENT_USER"u8, v) ||
            SqliHelpers.ToUpperCmp("CURRENT_DATE"u8, v) ||
            SqliHelpers.ToUpperCmp("CURRENT_TIME"u8, v) ||
            SqliHelpers.ToUpperCmp("CURRENT_TIMESTAMP"u8, v) ||
            SqliHelpers.ToUpperCmp("LOCALTIME"u8, v) ||
            SqliHelpers.ToUpperCmp("LOCALTIMESTAMP"u8, v);
    }

    /// <summary>Tokenizes into the token at <paramref name="pos"/>; tracks the last comment.</summary>
    private void FetchToken(ref bool more, ref int pos, ref SqliToken lastComment)
    {
        Current = pos;
        more = Tokenize();
        if (more)
        {
            if (CurrentToken.Category == SqliChars.TypeComment)
            {
                lastComment = CurrentToken;
            }
            else
            {
                lastComment.Category = SqliChars.Null;
                pos++;
            }
        }
    }

    /// <summary>Parses and folds the input, up to 5 tokens. Returns the number of tokens.</summary>
    public int Fold()
    {
        int pos = 0; // position where the next token goes
        int left = 0; // count of tokens already folded or processed (part of the fingerprint)
        bool more = true;
        SqliToken lastComment = default;

        Current = 0;
        while (more)
        {
            more = Tokenize();
            ref SqliToken c = ref CurrentToken;
            if (!(c.Category == SqliChars.TypeComment ||
                  c.Category == SqliChars.TypeLeftParenthesis ||
                  c.Category == SqliChars.TypeSqlType ||
                  c.IsUnaryOp()))
            {
                break;
            }
        }

        if (!more)
        {
            // if input was only comments, unary or (, then exit
            return 0;
        }

        // it's some other token
        pos++;

        while (true)
        {
            // do we have all the max number of tokens? if so do
            // some special cases for 5 tokens
            if (pos >= SqliToken.MaxTokens)
            {
                byte t0 = TokenVec[0].Category, t1 = TokenVec[1].Category, t2 = TokenVec[2].Category,
                    t3 = TokenVec[3].Category, t4 = TokenVec[4].Category;
                if ((t0 == SqliChars.TypeNumber &&
                     (t1 == SqliChars.TypeOperator || t1 == SqliChars.TypeComma) &&
                     t2 == SqliChars.TypeLeftParenthesis &&
                     t3 == SqliChars.TypeNumber &&
                     t4 == SqliChars.TypeRightParenthesis) ||
                    (t0 == SqliChars.TypeBareWord &&
                     t1 == SqliChars.TypeOperator &&
                     t2 == SqliChars.TypeLeftParenthesis &&
                     (t3 == SqliChars.TypeBareWord || t3 == SqliChars.TypeNumber) &&
                     t4 == SqliChars.TypeRightParenthesis) ||
                    (t0 == SqliChars.TypeNumber &&
                     t1 == SqliChars.TypeRightParenthesis &&
                     t2 == SqliChars.TypeComma &&
                     t3 == SqliChars.TypeLeftParenthesis &&
                     t4 == SqliChars.TypeNumber) ||
                    (t0 == SqliChars.TypeBareWord &&
                     t1 == SqliChars.TypeRightParenthesis &&
                     t2 == SqliChars.TypeOperator &&
                     t3 == SqliChars.TypeLeftParenthesis &&
                     t4 == SqliChars.TypeBareWord))
                {
                    // If we've already read an extra token beyond maxTokens,
                    // preserve it by moving it into position 1; otherwise,
                    // just reset to start from tokenVec[0] again.
                    if (pos > SqliToken.MaxTokens)
                    {
                        TokenVec[1] = TokenVec[SqliToken.MaxTokens];
                        left = 1;
                        pos = 2;
                    }
                    else
                    {
                        pos = 1;
                        left = 0;
                    }
                }
            }

            if (!more || left >= SqliToken.MaxTokens)
            {
                left = pos;
                break;
            }

            // get up to two tokens
            while (more && pos <= SqliToken.MaxTokens && pos - left < 2)
            {
                FetchToken(ref more, ref pos, ref lastComment);
            }

            // did we get 2 tokens? if not then we are done
            if (pos - left < 2)
            {
                left = pos;
                continue;
            }

            ref SqliToken l0 = ref TokenVec[left];
            ref SqliToken l1 = ref TokenVec[left + 1];

            // FOLD: "ss" -> "s"
            // "foo" "bar" is valid SQL
            // just ignore second string
            if (l0.Category == SqliChars.TypeString && l1.Category == SqliChars.TypeString)
            {
                pos--;
                StatsFolds++;
                continue;
            }

            if (l0.Category == SqliChars.TypeSemiColon && l1.Category == SqliChars.TypeSemiColon)
            {
                // not sure how various engines handle
                // 'select 1;;drop table foo' or
                // 'select 1;/x foo x/;drop table foo'
                // to prevent surprises, just fold away repeated semicolons
                pos--;
                StatsFolds++;
                continue;
            }

            if ((l0.Category == SqliChars.TypeOperator || l0.Category == SqliChars.TypeLogicOperator) &&
                (l1.IsUnaryOp() || l1.Category == SqliChars.TypeSqlType))
            {
                pos--;
                StatsFolds++;
                left = 0;
                continue;
            }

            if (l0.Category == SqliChars.TypeLeftParenthesis && l1.IsUnaryOp())
            {
                pos--;
                StatsFolds++;
                if (left > 0)
                {
                    left--;
                }

                continue;
            }

            if (Merge(ref l0, ref l1))
            {
                pos--;
                StatsFolds++;
                if (left > 0)
                {
                    left--;
                }

                continue;
            }

            if (l0.Category == SqliChars.TypeSemiColon &&
                l1.Category == SqliChars.TypeFunction &&
                (l1.Val[0] == 'I' || l1.Val[0] == 'i') &&
                (l1.Val[1] == 'F' || l1.Val[1] == 'f'))
            {
                // IF is normally a function, except in Transact-SQL where it can be used as a standalone
                // control flow operator, e.g. IF 1=1...
                // if found after a semicolon, convert from 'f' type to 'T' type
                l1.Category = SqliChars.TypeTsql;

                // reparse everything, but we probably can advance left, and pos
                continue;
            }

            if ((l0.Category == SqliChars.TypeBareWord || l0.Category == SqliChars.TypeVariable) &&
                l1.Category == SqliChars.TypeLeftParenthesis &&
                IsUserFunctionWord(ref l0))
            {
                // pos is the same
                // other conversions need to go here... for instance
                // password CAN be a function, coalesce CAN be a function
                l0.Category = SqliChars.TypeFunction;
                continue;
            }

            if (l0.Category == SqliChars.TypeKeyword &&
                (SqliHelpers.ToUpperCmp("IN"u8, l0.Value) || SqliHelpers.ToUpperCmp("NOT IN"u8, l0.Value)))
            {
                // got ... IN ( ... (or 'NOT IN'): it's an operator; otherwise it's nothing.
                // "IN" can be used as "IN BOOLEAN MODE" for mysql
                // in which case merging of words can be done later
                // otherwise it acts as an equality operator __ IN (values..)
                l0.Category = l1.Category == SqliChars.TypeLeftParenthesis
                    ? SqliChars.TypeOperator
                    : SqliChars.TypeBareWord;
                continue;
            }

            bool matched2 = false;
            if (l0.Category == SqliChars.TypeOperator &&
                (SqliHelpers.ToUpperCmp("LIKE"u8, l0.Value) || SqliHelpers.ToUpperCmp("NOT LIKE"u8, l0.Value)))
            {
                matched2 = true;
                if (l1.Category == SqliChars.TypeLeftParenthesis && !IsOperandBefore(left))
                {
                    // SELECT LIKE(...
                    // it's a function.
                    // After an operand ("1 LIKE (SELECT 1)") it can only be the
                    // binary operator, so leave it alone.
                    l0.Category = SqliChars.TypeFunction;
                }
            }

            if (!matched2 && l0.Category == SqliChars.TypeSqlType &&
                (l1.Category is SqliChars.TypeBareWord or SqliChars.TypeNumber or SqliChars.TypeSqlType
                    or SqliChars.TypeLeftParenthesis or SqliChars.TypeFunction or SqliChars.TypeVariable
                    or SqliChars.TypeString))
            {
                l0 = l1;
                pos--;
                StatsFolds++;
                left = 0;
                continue;
            }

            if (!matched2 && l0.Category == SqliChars.TypeCollate && l1.Category == SqliChars.TypeBareWord)
            {
                matched2 = true;

                // there are too many collation types.. so if the bareword has a "_"
                // then it's TYPE_SQLTYPE
                if (l1.Value.IndexOf((byte)'_') != -1)
                {
                    l1.Category = SqliChars.TypeSqlType;
                    left = 0;
                }
            }

            if (!matched2 && l0.Category == SqliChars.TypeBackslash)
            {
                if (l1.IsArithmeticOp())
                {
                    // very weird case in TSQL where '\%1' is parsed as '0 % 1', etc.
                    l0.Category = SqliChars.TypeNumber;
                }
                else
                {
                    // just ignore it. Again TSQL seems to parse \1 as "1"
                    l0 = l1;
                    pos--;
                    StatsFolds++;
                }

                left = 0;
                continue;
            }

            if (!matched2 && l0.Category == SqliChars.TypeLeftParenthesis && l1.Category == SqliChars.TypeLeftParenthesis)
            {
                pos--;
                left = 0;
                StatsFolds++;
                continue;
            }

            if (!matched2 && l0.Category == SqliChars.TypeRightParenthesis && l1.Category == SqliChars.TypeRightParenthesis)
            {
                pos--;
                left = 0;
                StatsFolds++;
                continue;
            }

            if (!matched2 && l0.Category == SqliChars.TypeLeftBrace && l1.Category == SqliChars.TypeBareWord)
            {
                // MySQL degenerate case
                //
                // select { ``.``.id }; -- valid!!
                // select { ``.``.``.id }; --invalid
                // select ``.``.id; --invalid     todo: this is valid
                // select { ``.id }; --invalid
                //
                // so it appears {``.``.id} is a magic case
                // I suspect this is "current database, current table, field id"
                //
                // The folding code can't look at more than 3 tokens, and
                // I don't want to make two passes.
                //
                // Since "{ ``" so rare, we are just going to blacklist it.
                //
                // Highly likely this will need revisiting!
                //
                // CREDIT @rsalgado 2013-11-25
                if (l1.Len == 0)
                {
                    l1.Category = SqliChars.TypeEvil;
                    return left + 2;
                }

                // weird ODBC / MySQL {foo expr} --> expr
                // but for this rule we just strip away the "{ foo" part
                left = 0;
                pos -= 2;
                StatsFolds += 2;
                continue;
            }

            if (!matched2 && l1.Category == SqliChars.TypeRightBrace)
            {
                pos--;
                left = 0;
                StatsFolds++;
                continue;
            }

            // all cases of handing 2 token is done
            // and nothing matched. Get one more token
            while (more && pos <= SqliToken.MaxTokens && pos - left < 3)
            {
                FetchToken(ref more, ref pos, ref lastComment);
            }

            // do we have three tokens? If not then we are done
            if (pos - left < 3)
            {
                left = pos;
                continue;
            }

            // now look for three token folding
            ref SqliToken a = ref TokenVec[left];
            ref SqliToken b = ref TokenVec[left + 1];
            ref SqliToken c2 = ref TokenVec[left + 2];

            if (a.Category == SqliChars.TypeNumber &&
                b.Category == SqliChars.TypeOperator &&
                c2.Category == SqliChars.TypeNumber)
            {
                pos -= 2;
                left = 0;
                continue;
            }

            if (a.Category == SqliChars.TypeOperator &&
                b.Category != SqliChars.TypeLeftParenthesis &&
                c2.Category == SqliChars.TypeOperator)
            {
                pos -= 2;
                left = 0;
                continue;
            }

            if (a.Category == SqliChars.TypeLogicOperator &&
                c2.Category == SqliChars.TypeLogicOperator)
            {
                pos -= 2;
                left = 0;
                continue;
            }

            if (a.Category == SqliChars.TypeVariable &&
                b.Category == SqliChars.TypeOperator &&
                c2.Category is SqliChars.TypeVariable or SqliChars.TypeNumber or SqliChars.TypeBareWord)
            {
                pos -= 2;
                left = 0;
                continue;
            }

            if (a.Category is SqliChars.TypeBareWord or SqliChars.TypeNumber &&
                b.Category == SqliChars.TypeOperator &&
                c2.Category is SqliChars.TypeNumber or SqliChars.TypeBareWord)
            {
                pos -= 2;
                left = 0;
                continue;
            }

            if (a.Category is SqliChars.TypeBareWord or SqliChars.TypeNumber or SqliChars.TypeVariable or SqliChars.TypeString &&
                b.Category == SqliChars.TypeOperator &&
                b.Value.SequenceEqual("::"u8) &&
                c2.Category == SqliChars.TypeSqlType)
            {
                pos -= 2;
                left = 0;
                StatsFolds += 2;
                continue;
            }

            if (a.Category is SqliChars.TypeBareWord or SqliChars.TypeNumber or SqliChars.TypeString or SqliChars.TypeVariable &&
                b.Category == SqliChars.TypeComma &&
                c2.Category is SqliChars.TypeNumber or SqliChars.TypeBareWord or SqliChars.TypeString or SqliChars.TypeVariable)
            {
                pos -= 2;
                left = 0;
                continue;
            }

            if (a.Category is SqliChars.TypeExpression or SqliChars.TypeGroup or SqliChars.TypeComma &&
                b.IsUnaryOp() &&
                c2.Category == SqliChars.TypeLeftParenthesis)
            {
                // got something like SELECT + (, LIMIT + (
                // remove unary operator
                b = c2;
                pos--;
                left = 0;
                continue;
            }

            if (a.Category is SqliChars.TypeKeyword or SqliChars.TypeExpression or SqliChars.TypeGroup &&
                b.IsUnaryOp() &&
                c2.Category is SqliChars.TypeNumber or SqliChars.TypeBareWord or SqliChars.TypeVariable
                    or SqliChars.TypeString or SqliChars.TypeFunction)
            {
                // remove unary operators
                // select -1
                b = c2;
                pos--;
                left = 0;
                continue;
            }

            if (a.Category == SqliChars.TypeComma &&
                b.IsUnaryOp() &&
                c2.Category is SqliChars.TypeNumber or SqliChars.TypeBareWord or SqliChars.TypeVariable or SqliChars.TypeString)
            {
                // interesting case turn ", -1" --> ",1" PLUS we need to back up
                // one token if possible to see if more folding can be done
                // "1, -1" --> "1"
                b = c2;
                left = 0;
                pos -= 3;
                continue;
            }

            if (a.Category == SqliChars.TypeComma &&
                b.IsUnaryOp() &&
                c2.Category == SqliChars.TypeFunction)
            {
                // Separate case from above since you end up with
                // 1,-sin(1) --> 1 (1)
                // Here, just do
                // 1,-sin(1) --> 1,sin(1)
                // just remove unary operator
                b = c2;
                pos--;
                left = 0;
                continue;
            }

            if (a.Category == SqliChars.TypeBareWord &&
                b.Category == SqliChars.TypeDot &&
                c2.Category == SqliChars.TypeBareWord)
            {
                // ignore the '.n'
                // typically is this database name .table
                pos -= 2;
                left = 0;
                continue;
            }

            if (a.Category == SqliChars.TypeExpression &&
                b.Category == SqliChars.TypeDot &&
                c2.Category == SqliChars.TypeBareWord)
            {
                // select . `foo` --> select `foo`
                b = c2;
                pos--;
                left = 0;
                continue;
            }

            if (a.Category == SqliChars.TypeFunction &&
                b.Category == SqliChars.TypeLeftParenthesis &&
                c2.Category != SqliChars.TypeRightParenthesis)
            {
                // Some SQL functions like USER() have 0 args
                // if we get User(foo), then User is not a function
                // This should be expanded since it eliminated a lot of false
                // positives.
                if (SqliHelpers.ToUpperCmp("USER"u8, a.Value))
                {
                    a.Category = SqliChars.TypeBareWord;
                }
            }

            // no folding -- assume left-most token is
            // good, now use the existing 2 tokens --
            // do not get another
            left++;
        }

        // if we have 4 or fewer tokens, and we had a comment token
        // at the end, add it back
        if (left < SqliToken.MaxTokens && lastComment.Category == SqliChars.TypeComment)
        {
            TokenVec[left] = lastComment;
            left++;
        }

        // sometimes we grab a 6th token to help
        // determine the type of token 5
        if (left > SqliToken.MaxTokens)
        {
            left = SqliToken.MaxTokens;
        }

        return left;
    }

    /// <summary>Reads the next token into the current token. Returns false at end of input.</summary>
    public bool Tokenize()
    {
        if (Length == 0)
        {
            return false;
        }

        ref SqliToken cur = ref CurrentToken;
        cur = default;

        // if we are at beginning of string and in single quote or double quote mode
        // then pretend the input starts with a quote
        if (Pos == 0 && (Flags & (SqliFlags.QuoteSingle | SqliFlags.QuoteDouble)) != 0)
        {
            Pos = cur.ParseStringCore(Input, Length, 0, 0, SqliHelpers.Flag2Delimiter(Flags));
            StatsTokens++;
            return true;
        }

        while (Pos < Length)
        {
            // get current character, look up the parser, and call it
            Pos = ParseByteFunctions(Input[Pos]);

            if (cur.Category != SqliChars.Null)
            {
                StatsTokens++;
                return true;
            }
        }

        return false;
    }

    /// <summary>Given a pattern determine if it's a SQLi pattern.</summary>
    public readonly bool Blacklist()
    {
        int length = FingerprintLength;
        if (length < 1)
        {
            return false;
        }

        Span<char> fp = stackalloc char[SqliToken.MaxTokens + 2];
        fp[0] = '0';
        for (int i = 0; i < length; i++)
        {
            byte ch = FingerprintBuffer[i];
            if (ch is >= (byte)'a' and <= (byte)'z')
            {
                ch -= 0x20;
            }

            fp[i + 1] = (char)ch;
        }

        return SqliKeywords.TryGetExact(fp[..(length + 1)], out byte val) && val == SqliChars.TypeFingerprint;
    }

    /// <summary>Input byte at <paramref name="i"/>, or 0 past the end (Go would panic; not reachable in practice).</summary>
    private readonly byte InputAt(int i) => (uint)i < (uint)Input.Length ? Input[i] : (byte)0;

    /// <summary>
    /// Given a positive match for a pattern (i.e. pattern is SQLi), this function
    /// does additional analysis to reduce false positives.
    /// </summary>
    public readonly bool NotWhitelist()
    {
        // We assume we got a SQLi match
        // This next part just helps reduce false positives
        ReadOnlySpan<byte> fp = ((ReadOnlySpan<byte>)FingerprintBuffer)[..FingerprintLength];
        int length = fp.Length;

        if (length > 1 && fp[length - 1] == SqliChars.TypeComment)
        {
            // if ending comment is contains 'sp_password' then it's SQLi!
            // MS Audit log apparently ignores anything with
            // 'sp_password' in it. Unable to find primary reference to
            // this "feature" of SQL Server but seems to be known SQLi
            // technique
            if (Input.IndexOf("sp_password"u8) != -1)
            {
                return true;
            }
        }

        switch (length)
        {
            case 2:
            {
                // case 2 are "very small SQLi" which make them
                // hard to tell from normal input...
                if (fp[1] == SqliChars.TypeUnion)
                {
                    //  not sure why but 1U comes up in SQLi attack
                    //  likely part of parameter splitting/etc.
                    //  lots of reasons why "1 union" might be normal
                    //  input, so beep only if other SQLi things are present
                    //
                    //  it really is a number and 'union'
                    //  otherwise it has folding or comments
                    return StatsTokens != 2;
                }

                ref readonly SqliToken t0 = ref TokenVec[0];
                ref readonly SqliToken t1 = ref TokenVec[1];

                // if 'comment' is '#' ignore.. too many FP
                if (t1.Val[0] == '#')
                {
                    return false;
                }

                // for fingerprint like 'nc', only comments of /x are treated
                // as SQL... ending comments of "--" and "#" are not SQLi
                if (t0.Category == SqliChars.TypeBareWord &&
                    t1.Category == SqliChars.TypeComment &&
                    t1.Val[0] != '/')
                {
                    return false;
                }

                // if '1c' ends with '/x' then it's SQLi
                if (t0.Category == SqliChars.TypeNumber &&
                    t1.Category == SqliChars.TypeComment &&
                    t1.Val[0] == '/')
                {
                    return true;
                }

                // there are some odd base64-looking query string values
                // 1234-ABCDEFEhfhihwuefi--
                // which evaluate to "1c"... these are not SQLi
                // but 1234-- probably is.
                // Make sure the "1" in "1c" is actually a true decimal number
                //
                // Need to check -original- string since the folding step
                // may have merged tokens, e.g. "1+FOO" is folded into "1"
                //
                // Note: evasion: 1*1--
                if (t0.Category == SqliChars.TypeNumber && t1.Category == SqliChars.TypeComment)
                {
                    if (StatsTokens > 2)
                    {
                        // we have some folding going on, highly likely SQLi
                        return true;
                    }

                    // we check that next character after the number is either whitespace,
                    // or '/' or a '-' ==> SQLi
                    byte ch = InputAt(t0.Len);
                    if (ch <= 32)
                    {
                        // next char was whitespace,e.g. "1234 --"
                        // this isn't exactly correct. ideally we should skip over all whitespace
                        // but this seems to be ok for now
                        return true;
                    }

                    if (ch == '/' && InputAt(t0.Len + 1) == '*')
                    {
                        return true;
                    }

                    if (ch == '-' && InputAt(t0.Len + 1) == '-')
                    {
                        return true;
                    }

                    return false;
                }

                // detect obvious SQLi scans.. many people put '--' in plain text
                // so only detect if input ends with '--', e.g. 1-- but not 1-- foo
                if (t1.Len > 2 && t1.Val[0] == '-')
                {
                    return false;
                }

                break;
            }

            case 3:
            {
                // ...foo' + 'bar...
                // no opening quote, no closing quote
                // and each string has data
                // sos || s&s are string and operator || logic operator and string
                if (fp.SequenceEqual("sos"u8) || fp.SequenceEqual("s&s"u8))
                {
                    if (TokenVec[0].StrOpen == SqliChars.Null &&
                        TokenVec[2].StrClose == SqliChars.Null &&
                        TokenVec[0].StrClose == TokenVec[2].StrOpen)
                    {
                        // if ...foo" + "bar ...
                        return true;
                    }

                    return false;
                }

                if (fp.SequenceEqual("s&n"u8) || fp.SequenceEqual("n&1"u8) || fp.SequenceEqual("1&1"u8) ||
                    fp.SequenceEqual("1&v"u8) || fp.SequenceEqual("1&s"u8))
                {
                    // 'sexy and 17' not SQLi
                    // 'sexy and 17<18' SQLi
                    if (StatsTokens == 3)
                    {
                        return false;
                    }
                }

                ref readonly SqliToken t1 = ref TokenVec[1];
                if (t1.Category == SqliChars.TypeKeyword &&
                    (t1.Len < 5 || !SqliHelpers.ToUpperCmp("INTO"u8, ((ReadOnlySpan<byte>)t1.Val)[..4])))
                {
                    // if it's not "INTO OUTFILE", or "INTO DUMPFILE" (MySQL)
                    // then treat as safe
                    return false;
                }

                break;
            }
        }

        return true;
    }

    public readonly bool CheckFingerprint() => Blacklist() && NotWhitelist();

    public void Reset(int flags)
    {
        if (flags == 0)
        {
            flags = SqliFlags.QuoteNone | SqliFlags.SqlAnsi;
        }

        Init(Input, flags);
    }

    public readonly bool ReparseAsMySql() => StatsCommentDdx != 0 || StatsCommentHash != 0;

    /// <summary>Main check: tries the input as-is, then as if it started with ' and ".</summary>
    public bool Check()
    {
        // no input? not SQLi
        if (Length == 0)
        {
            return false;
        }

        // test input "as-is"
        SqliFingerprint(SqliFlags.QuoteNone | SqliFlags.SqlAnsi);
        if (CheckFingerprint())
        {
            return true;
        }

        if (ReparseAsMySql())
        {
            SqliFingerprint(SqliFlags.QuoteNone | SqliFlags.SqlMysql);
            if (CheckFingerprint())
            {
                return true;
            }
        }

        // if input has a single quote, then
        // test as if input was actually '
        // example: if input if "1' = 1", then pretend it's "'1' = 1"
        if (Input.IndexOf(SqliChars.Single) != -1)
        {
            SqliFingerprint(SqliFlags.QuoteSingle | SqliFlags.SqlAnsi);
            if (CheckFingerprint())
            {
                return true;
            }

            if (ReparseAsMySql())
            {
                SqliFingerprint(SqliFlags.QuoteSingle | SqliFlags.SqlMysql);
                if (CheckFingerprint())
                {
                    return true;
                }
            }
        }

        // same as above but with a double quote
        if (Input.IndexOf(SqliChars.Double) != -1)
        {
            SqliFingerprint(SqliFlags.QuoteDouble | SqliFlags.SqlMysql);
            if (CheckFingerprint())
            {
                return true;
            }
        }

        // Hurry, input is not SQLi
        return false;
    }

    /// <summary>
    /// Reports whether the committed token before position <paramref name="left"/> is an operand
    /// (number, string, bareword, variable or closing parenthesis).
    /// </summary>
    private readonly bool IsOperandBefore(int left)
    {
        if (left == 0)
        {
            return false;
        }

        return TokenVec[left - 1].Category is SqliChars.TypeNumber or SqliChars.TypeString or SqliChars.TypeBareWord
            or SqliChars.TypeVariable or SqliChars.TypeRightParenthesis;
    }
}
