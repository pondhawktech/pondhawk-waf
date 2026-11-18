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
/// libinjection works on bytes. This port converts the input to one byte per <see cref="char"/>
/// before it runs the byte-oriented detector, so that every index, length and token is the same
/// as in libinjection-go for the same bytes:
/// </para>
/// <list type="bullet">
///   <item>A char U+0000..U+00FF becomes the byte with the same value (Latin-1). A string whose chars are
///   the raw request bytes (Latin-1 decoded) therefore gives exactly the libinjection-go result for those bytes.</item>
///   <item>A char above U+00FF becomes the byte 0x80. libinjection-go treats every byte 0x80..0xFF other than
///   0xA0 the same way (a word byte in SQLi, a non-ASCII byte in XSS), so 0x80 stands for "some non-ASCII byte".
///   This is one byte, where Go would see the 2 or 3 bytes of its UTF-8 form.</item>
/// </list>
/// <para>All methods are thread-safe. They keep no static mutable state; the parser state lives on the stack.</para>
/// </remarks>
public static class LibInjection
{
    /// <summary>Inputs up to this length are converted on the stack; longer inputs use a pooled array.</summary>
    private const int StackBufferLength = 1024;

    /// <summary>The byte that stands for a char above U+00FF.</summary>
    internal const byte NonLatin1Byte = 0x80;

    /// <summary>
    /// Detects SQL injection.
    /// </summary>
    /// <param name="input">The value to test.</param>
    /// <param name="fingerprint">The libinjection fingerprint (at most 5 chars) when SQLi is found; otherwise empty.</param>
    /// <returns><see langword="true"/> if the input is SQL injection.</returns>
    public static bool IsSqli(ReadOnlySpan<char> input, out string fingerprint)
    {
        byte[]? rented = null;
        Span<byte> bytes = input.Length <= StackBufferLength
            ? stackalloc byte[StackBufferLength]
            : (rented = ArrayPool<byte>.Shared.Rent(input.Length));
        try
        {
            bytes = bytes[..input.Length];
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
        byte[]? rented = null;
        Span<byte> bytes = input.Length <= StackBufferLength
            ? stackalloc byte[StackBufferLength]
            : (rented = ArrayPool<byte>.Shared.Rent(input.Length));
        try
        {
            bytes = bytes[..input.Length];
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

    /// <summary>
    /// Converts chars to bytes, one byte per char: U+0000..U+00FF keep their value, other chars become
    /// <see cref="NonLatin1Byte"/>. <paramref name="destination"/> must be exactly as long as <paramref name="source"/>.
    /// </summary>
    internal static void ToBytes(ReadOnlySpan<char> source, Span<byte> destination)
    {
        // Vectorized fast path for the ASCII prefix (usually the whole input).
        Ascii.FromUtf16(source, destination, out int done);
        for (int i = done; i < source.Length; i++)
        {
            char c = source[i];
            destination[i] = c <= '\u00FF' ? (byte)c : NonLatin1Byte;
        }
    }
}
