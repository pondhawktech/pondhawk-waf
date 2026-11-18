using System.Text;

namespace Pondhawk.Waf.Text;

/// <summary>
/// The engine holds all HTTP data as "byte strings": .NET strings where each char is one byte (0x00-0xFF).
/// This keeps the byte semantics of ModSecurity and Coraza for transformations (urlDecode, utf8toUnicode,
/// validateUtf8Encoding, ...) and avoids lossy UTF-16 decoding of attacker-controlled data.
/// </summary>
public static class ByteString
{
    /// <summary>Converts raw bytes to a byte string (Latin-1 mapping, lossless).</summary>
    public static string FromBytes(ReadOnlySpan<byte> bytes) => Encoding.Latin1.GetString(bytes);

    /// <summary>Converts a .NET (UTF-16) string to a byte string of its UTF-8 bytes. ASCII-only strings are returned unchanged.</summary>
    public static string FromUtf16(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        if (Ascii.IsValid(value))
        {
            return value;
        }

        return Encoding.Latin1.GetString(Encoding.UTF8.GetBytes(value));
    }

    /// <summary>Returns the raw bytes of a byte string.</summary>
    public static byte[] ToBytes(string value) => Encoding.Latin1.GetBytes(value);

    /// <summary>Decodes a byte string as UTF-8 for display. Invalid sequences become U+FFFD.</summary>
    public static string ToDisplay(string value)
    {
        if (Ascii.IsValid(value))
        {
            return value;
        }

        return Encoding.UTF8.GetString(Encoding.Latin1.GetBytes(value));
    }

    /// <summary>ASCII-only lowercase, the same as C tolower() in the "C" locale.</summary>
    public static string ToLowerAscii(string value)
    {
        var i = 0;
        for (; i < value.Length; i++)
        {
            var c = value[i];
            if (c is >= 'A' and <= 'Z')
            {
                break;
            }
        }

        if (i == value.Length)
        {
            return value;
        }

        return string.Create(value.Length, (value, i), static (span, state) =>
        {
            var (src, start) = state;
            src.AsSpan(0, start).CopyTo(span);
            for (var j = start; j < src.Length; j++)
            {
                var c = src[j];
                span[j] = c is >= 'A' and <= 'Z' ? (char)(c + 32) : c;
            }
        });
    }

    internal static int HexValue(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => -1,
    };

    internal static bool IsHex(char c) => HexValue(c) >= 0;
}
