// Ported from libinjection-go (https://github.com/corazawaf/libinjection-go), sqli_const.go and sqli_token.go.
// Copyright (c) 2022-Present, Coraza. BSD-3-Clause; see LICENSE-libinjection.txt.

using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Pondhawk.Waf.LibInjection;

/// <summary>SQLi parser flags.</summary>
internal static class SqliFlags
{
    public const int QuoteNone = 1;
    public const int QuoteSingle = 2;
    public const int QuoteDouble = 4;
    public const int SqlAnsi = 8;
    public const int SqlMysql = 16;
}

/// <summary>Byte constants and SQLi token categories (one ASCII byte each, as in the fingerprint).</summary>
internal static class SqliChars
{
    public const byte Null = 0;
    public const byte Single = (byte)'\'';
    public const byte Double = (byte)'"';
    public const byte Tick = (byte)'`';

    public const byte TypeNone = 0;
    public const byte TypeKeyword = (byte)'k';
    public const byte TypeUnion = (byte)'U';
    public const byte TypeGroup = (byte)'B';
    public const byte TypeExpression = (byte)'E';
    public const byte TypeSqlType = (byte)'t';
    public const byte TypeFunction = (byte)'f';
    public const byte TypeBareWord = (byte)'n';
    public const byte TypeNumber = (byte)'1';
    public const byte TypeVariable = (byte)'v';
    public const byte TypeString = (byte)'s';
    public const byte TypeOperator = (byte)'o';
    public const byte TypeLogicOperator = (byte)'&';
    public const byte TypeComment = (byte)'c';
    public const byte TypeCollate = (byte)'A';
    public const byte TypeLeftParenthesis = (byte)'(';
    public const byte TypeRightParenthesis = (byte)')';
    public const byte TypeLeftBrace = (byte)'{';
    public const byte TypeRightBrace = (byte)'}';
    public const byte TypeDot = (byte)'.';
    public const byte TypeComma = (byte)',';
    public const byte TypeColon = (byte)':';
    public const byte TypeSemiColon = (byte)';';
    public const byte TypeTsql = (byte)'T';
    public const byte TypeUnknown = (byte)'?';
    public const byte TypeEvil = (byte)'X';
    public const byte TypeFingerprint = (byte)'F';
    public const byte TypeBackslash = (byte)'\\';
}

/// <summary>Fixed 32-byte token value buffer (the C/Go token value is capped at 31 bytes).</summary>
[InlineArray(SqliToken.TokenSize)]
internal struct SqliTokenValue
{
    private byte _element0;
}

/// <summary>One SQLi token.</summary>
internal struct SqliToken
{
    public const int MaxTokens = 5;
    public const int TokenSize = 32;

    /// <summary>Position of the token in the input.</summary>
    public int Pos;

    /// <summary>Length of the token value (capped at <see cref="TokenSize"/> - 1).</summary>
    public int Len;

    /// <summary>For type 'v': the number of leading '@'.</summary>
    public int Count;

    public byte Category;
    public byte StrOpen;
    public byte StrClose;

    /// <summary>The token value. Bytes past <see cref="Len"/> are zero.</summary>
    public SqliTokenValue Val;

    /// <summary>The token value, <see cref="Len"/> bytes.</summary>
    [UnscopedRef]
    public ReadOnlySpan<byte> Value => ((ReadOnlySpan<byte>)Val)[..Len];

    /// <summary>Value byte at <paramref name="i"/>; zero past the end (Go would panic there).</summary>
    public readonly byte ValAt(int i) => (uint)i < TokenSize ? Val[i] : (byte)0;

    public void Assign(byte tokenType, int pos, int length, ReadOnlySpan<byte> value)
    {
        int last = length < TokenSize ? length : TokenSize - 1;
        Category = tokenType;
        Pos = pos;
        Len = last;
        Span<byte> v = Val;
        v.Clear();
        value[..last].CopyTo(v);
    }

    /// <summary>Sets the value to <paramref name="value"/> without changing <see cref="Len"/> (as Go's <c>t.val = ...</c>).</summary>
    public void SetVal(ReadOnlySpan<byte> value)
    {
        Span<byte> v = Val;
        v.Clear();
        value.CopyTo(v);
    }

    /// <summary>
    /// Parses a string that starts at <paramref name="pos"/> + <paramref name="offset"/>.
    /// Looks forward for doubling of the delimiter: 'foo' 'bar' -> foo' 'bar.
    /// The ending quote is not duplicated (escaped) since it is the wrong one or EOL.
    /// </summary>
    public int ParseStringCore(ReadOnlySpan<byte> s, int length, int pos, int offset, byte delimiter)
    {
        // offset is to skip the perhaps first quote char
        int start = pos + offset;
        int str = start; // Go: str := s[pos+offset:]; tracked as an absolute index

        // offset > 0: this is a real quote; otherwise a simulated one
        StrOpen = offset > 0 ? delimiter : SqliChars.Null;

        while (true)
        {
            int index = s[str..].IndexOf(delimiter);
            if (index != -1)
            {
                str += index;
            }

            if (index == -1)
            {
                // string ended with no trailing quote; assign what we have
                Assign(SqliChars.TypeString, start, length - start, s[start..]);
                StrClose = SqliChars.Null;
                return length;
            }

            if (SqliHelpers.IsBackslashEscaped(s[start..str]))
            {
                // keep going, move ahead one character
                str += 1;
                continue;
            }

            if (SqliHelpers.IsDoubleDelimiterEscaped(s[str..]))
            {
                // keep going, move ahead two characters
                str += 2;
                continue;
            }

            // a normal string
            Assign(SqliChars.TypeString, start, str - start, s[start..]);
            StrClose = delimiter;
            return str + 1;
        }
    }

    public readonly bool IsUnaryOp()
    {
        if (Category != SqliChars.TypeOperator)
        {
            return false;
        }

        return Len switch
        {
            1 => Val[0] is (byte)'+' or (byte)'-' or (byte)'!' or (byte)'~',
            2 => Val[0] == '!' && Val[1] == '!',
            3 => SqliHelpers.ToUpperCmp("NOT"u8, ((ReadOnlySpan<byte>)Val)[..3]),
            _ => false,
        };
    }

    public readonly bool IsArithmeticOp() =>
        Category == SqliChars.TypeOperator && Len == 1 &&
        Val[0] is (byte)'*' or (byte)'/' or (byte)'+' or (byte)'-' or (byte)'%';
}
