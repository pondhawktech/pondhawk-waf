// Ported from libinjection-go (https://github.com/corazawaf/libinjection-go), sqli.go and xss.go (IsSQLi, IsXSS).
// Copyright (c) 2022-Present, Coraza. BSD-3-Clause; see LICENSE-libinjection.txt.

using System.Buffers;
using System.Text;

namespace Pondhawk.Waf.LibInjection;

/// <summary>
/// SQL injection and cross-site scripting detection. A C# port of libinjection-go.
/// </summary>
/// <remarks>
/// <para>
/// libinjection works on bytes. This port converts the input to bytes before it runs the byte-oriented
/// detector, so that every index, length and token is the same as in libinjection-go for the same bytes:
/// </para>
/// <list type="bullet">
///   <item>A char U+0000..U+00FF becomes the byte with the same value (Latin-1). A string whose chars are
///   the raw request bytes (Latin-1 decoded) therefore gives exactly the libinjection-go result for those bytes.
///   This is how the WAF engine calls it.</item>
///   <item>A char above U+00FF becomes its UTF-8 bytes (a lone surrogate becomes U+FFFD), the bytes Go would see
///   for that char. This matters: Go uppercases U+0131 to I and U+017F to S when it looks up keywords.</item>
/// </list>
/// <para>
/// A .NET string that holds U+0080..U+00FF as text (not as bytes) is therefore not the same as its UTF-8 form:
/// pass the UTF-8 bytes as a Latin-1 string to get the libinjection-go result for UTF-8 text.
/// </para>
/// <para>All methods are thread-safe. They keep no static mutable state; the parser state lives on the stack.</para>
/// </remarks>
public static class LibInjection
{
    /// <summary>Inputs up to this length are converted on the stack; longer inputs use a pooled array.</summary>
    private const int StackBufferLength = 1024;


    /// <summary>
    /// Detects SQL injection.
    /// </summary>
    /// <param name="input">The value to test.</param>
    /// <param name="fingerprint">The libinjection fingerprint (at most 5 chars) when SQLi is found; otherwise empty.</param>
    /// <returns><see langword="true"/> if the input is SQL injection.</returns>
    public static bool IsSqli(ReadOnlySpan<char> input, out string fingerprint)
    {
        int length = ByteLength(input);
        byte[]? rented = null;
        Span<byte> bytes = length <= StackBufferLength
            ? stackalloc byte[StackBufferLength]
            : (rented = ArrayPool<byte>.Shared.Rent(length));
        try
        {
            bytes = bytes[..length];
            ToBytes(input, bytes);
            return Sqli.IsSqli(bytes, out fingerprint);
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    /// <summary>
    /// Detects cross-site scripting.
    /// </summary>
    /// <param name="input">The value to test.</param>
    /// <returns><see langword="true"/> if the input is XSS.</returns>
    public static bool IsXss(ReadOnlySpan<char> input)
    {
        int length = ByteLength(input);
        byte[]? rented = null;
        Span<byte> bytes = length <= StackBufferLength
            ? stackalloc byte[StackBufferLength]
            : (rented = ArrayPool<byte>.Shared.Rent(length));
        try
        {
            bytes = bytes[..length];
            ToBytes(input, bytes);
            return Xss.IsXss(bytes);
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    /// <summary>The number of bytes <see cref="ToBytes"/> writes for <paramref name="source"/>.</summary>
    internal static int ByteLength(ReadOnlySpan<char> source)
    {
        int i = source.IndexOfAnyExceptInRange('\u0000', '\u00FF');
        if (i < 0)
        {
            return source.Length;
        }

        int length = i;
        while (i < source.Length)
        {
            char c = source[i];
            if (c <= '\u00FF')
            {
                length++;
                i++;
            }
            else if (char.IsHighSurrogate(c) && i + 1 < source.Length && char.IsLowSurrogate(source[i + 1]))
            {
                length += 4;
                i += 2;
            }
            else
            {
                length += c < '\u0800' ? 2 : 3; // a lone surrogate becomes U+FFFD: 3 bytes
                i++;
            }
        }

        return length;
    }

    /// <summary>
    /// Converts chars to bytes: U+0000..U+00FF keep their value, other chars become their UTF-8 bytes.
    /// <paramref name="destination"/> must be exactly <see cref="ByteLength"/> bytes long.
    /// </summary>
    internal static void ToBytes(ReadOnlySpan<char> source, Span<byte> destination)
    {
        // Vectorized fast path for the ASCII prefix (usually the whole input).
        Ascii.FromUtf16(source, destination, out int done);
        int j = done;
        for (int i = done; i < source.Length; i++)
        {
            char c = source[i];
            if (c <= '\u00FF')
            {
                destination[j++] = (byte)c;
                continue;
            }

            Rune rune;
            if (char.IsHighSurrogate(c) && i + 1 < source.Length && char.IsLowSurrogate(source[i + 1]))
            {
                rune = new Rune(c, source[++i]);
            }
            else
            {
                rune = char.IsSurrogate(c) ? Rune.ReplacementChar : new Rune(c);
            }

            j += rune.EncodeToUtf8(destination[j..]);
        }
    }
}
