// multipart/form-data processing, following OWASP Coraza (Apache-2.0) bodyprocessors/multipart.go and the parsing
// rules of Go's mime/multipart, which Coraza relies on.
using System.Globalization;
using System.Text;
using Pondhawk.Waf.Text;

namespace Pondhawk.Waf.BodyProcessors;

internal static class Multipart
{
    public static void Process(ReadOnlySpan<byte> body, Transaction tx, BodyProcessorOptions options)
    {
        var v = tx.Variables;
        if (!MediaType.TryParse(ByteString.FromUtf16(options.ContentType), out var mediaType, out var parameters))
        {
            v.MultipartStrictError.Set("1");
            throw new BodyProcessorException("invalid multipart content type");
        }

        if (!mediaType.StartsWith("multipart/", StringComparison.Ordinal))
        {
            throw new BodyProcessorException("not a multipart body");
        }

        if (!parameters.TryGetValue("boundary", out var boundary) || boundary.Length == 0)
        {
            v.MultipartStrictError.Set("1");
            throw new BodyProcessorException("multipart boundary missing");
        }

        var text = ByteString.FromBytes(body);
        var dashBoundary = "--" + boundary;
        long totalSize = 0;
        long fieldSize = 0;
        var parts = 0;

        // Skip the preamble: find the first boundary line.
        var pos = FindBoundaryLine(text, dashBoundary, 0, first: true);
        if (pos < 0)
        {
            v.MultipartStrictError.Set("1");
            throw new BodyProcessorException("multipart: NextPart: EOF");
        }

        // ASP.NET Core's MultipartReader takes the first "--boundary" anywhere in the preamble, even mid-line, and
        // later delimiters only after CRLF. Go's mime/multipart (and Coraza) take a boundary after a bare LF and
        // ignore one mid-line. Every place where the two parsers would split the body differently is a strict error,
        // so a part the WAF did not see as a form field is never delivered to the application as one.
        var delimiters = new List<int> { pos };
        if (text.IndexOf(dashBoundary, StringComparison.Ordinal) != pos)
        {
            v.MultipartStrictError.Set("1");
        }

        try
        {
            while (true)
            {
                // pos is at the start of "--boundary".
                var afterBoundary = pos + dashBoundary.Length;
                if (string.CompareOrdinal(text, afterBoundary, "--", 0, 2) == 0)
                {
                    // Final boundary: only CRLF or the end of the body may follow; ASP.NET Core keeps reading parts
                    // after "--boundary--x".
                    var afterFinal = afterBoundary + 2;
                    if (afterFinal < text.Length && string.CompareOrdinal(text, afterFinal, "\r\n", 0, 2) != 0)
                    {
                        v.MultipartStrictError.Set("1");
                    }

                    var rest = text[afterFinal..].Trim('\r', '\n', ' ', '\t');
                    if (rest.Length > 0)
                    {
                        v.MultipartDataAfter.Set("1");
                    }

                    return;
                }

                var lineEnd = text.IndexOf('\n', afterBoundary);
                if (lineEnd < 0)
                {
                    FlagUnexpectedEof(v);
                    return;
                }

                // Only optional linear whitespace may follow the boundary on its line.
                if (text.AsSpan(afterBoundary, lineEnd - afterBoundary).TrimEnd('\r').Trim(" \t").Length != 0)
                {
                    v.MultipartStrictError.Set("1");
                    throw new BodyProcessorException("multipart: boundary followed by data");
                }

                if (lineEnd == afterBoundary || text[lineEnd - 1] != '\r')
                {
                    // A bare LF ends the boundary line.
                    v.MultipartStrictError.Set("1");
                }

                parts++;
                if (options.ArgumentsLimit > 0 && parts > options.ArgumentsLimit)
                {
                    // Parts with files count too: their number is not otherwise bounded.
                    v.ArgumentsLimitReached.Set("1");
                    return;
                }

                var headersStart = lineEnd + 1;
                var next = FindBoundaryLine(text, dashBoundary, headersStart, first: false);
                var partEnd = next < 0 ? text.Length : next;
                var headersEnd = FindHeadersEnd(text, headersStart, partEnd, out var bodyStart);
                if (headersEnd < 0)
                {
                    if (next >= 0)
                    {
                        v.MultipartStrictError.Set("1");
                        throw new BodyProcessorException("multipart: part headers not terminated");
                    }

                    FlagUnexpectedEof(v);
                    return;
                }

                if (HasBareLineFeed(text, headersStart, bodyStart))
                {
                    v.MultipartStrictError.Set("1");
                }

                var headers = ParseHeaders(text[headersStart..headersEnd], out var malformedHeaders);
                string content;
                var truncated = false;
                if (next < 0)
                {
                    content = text[bodyStart..];
                    truncated = true;
                }
                else
                {
                    // The CRLF before the boundary belongs to the delimiter.
                    var end = next;
                    if (end > bodyStart && text[end - 1] == '\n')
                    {
                        end--;
                        if (end > bodyStart && text[end - 1] == '\r')
                        {
                            end--;
                        }
                        else
                        {
                            // A delimiter after a bare LF: part content to ASP.NET Core, a new part to Go.
                            v.MultipartStrictError.Set("1");
                        }
                    }

                    content = text[bodyStart..Math.Max(bodyStart, end)];
                    delimiters.Add(next);
                }

                if (ProcessPart(tx, headers, malformedHeaders, content, ref totalSize))
                {
                    fieldSize += content.Length;
                    if (options.NoFilesLimit > 0 && fieldSize > options.NoFilesLimit)
                    {
                        v.InboundDataError.Set("1");
                        throw new BodyProcessorException("multipart: form fields exceed SecRequestBodyNoFilesLimit");
                    }
                }

                if (truncated)
                {
                    FlagUnexpectedEof(v);
                    return;
                }

                pos = next;
            }
        }
        finally
        {
            CheckStrayBoundaries(text, dashBoundary, delimiters, v);
        }
    }

    // A "--boundary" that is not a delimiter the WAF used (mid-line, or followed by other characters) is a delimiter
    // to some other multipart parser.
    private static void CheckStrayBoundaries(string text, string dashBoundary, List<int> delimiters, Collections.TransactionVariables v)
    {
        var last = delimiters[^1];
        var used = 0;
        var i = text.IndexOf(dashBoundary, StringComparison.Ordinal);
        while (i >= 0 && i <= last)
        {
            if (used < delimiters.Count && delimiters[used] == i)
            {
                used++;
            }
            else
            {
                v.MultipartStrictError.Set("1");
                return;
            }

            i = text.IndexOf(dashBoundary, i + 1, StringComparison.Ordinal);
        }
    }

    private static bool HasBareLineFeed(string text, int start, int end)
    {
        for (var i = text.IndexOf('\n', start, end - start); i >= 0; i = i + 1 < end ? text.IndexOf('\n', i + 1, end - i - 1) : -1)
        {
            if (i == 0 || text[i - 1] != '\r')
            {
                return true;
            }
        }

        return false;
    }

    // Returns true when the part is a form field (no file name).
    private static bool ProcessPart(Transaction tx, List<KeyValuePair<string, string>> headers, bool malformedHeaders, string content, ref long totalSize)
    {
        var v = tx.Variables;
        var disposition = headers.FirstOrDefault(h => h.Key == "Content-Disposition").Value ?? string.Empty;
        var partName = FormName(disposition);

        var duplicateHeader = malformedHeaders;
        foreach (var group in headers.GroupBy(h => h.Key, StringComparer.Ordinal))
        {
            if (group.Count() > 1)
            {
                duplicateHeader = true;
            }

            foreach (var h in group)
            {
                v.MultipartPartHeaders.Add(partName, h.Key + ": " + h.Value);
            }
        }

        var fields = FileNameFields.From(disposition);
        if (duplicateHeader || fields.DuplicateParam)
        {
            v.MultipartDuplicatePartHeader.Set("1");
        }

        if (fields.InvalidQuoting)
        {
            v.MultipartInvalidQuoting.Set("1");
        }

        if (duplicateHeader || fields.DuplicateParam || fields.Malformed || fields.InvalidQuoting)
        {
            v.MultipartStrictError.Set("1");
        }

        v.MultipartName.Add(partName, partName);
        if (fields.FileName.Length > 0)
        {
            v.MultipartFilename.Add(partName, fields.FileName);
        }

        if (fields.AltFileName.Length > 0)
        {
            v.MultipartFilename.Add(partName, fields.AltFileName);
        }

        if (fields.HasExtended)
        {
            v.MultipartFilenameCharset.Add(partName, fields.Charset);
            v.MultipartFilenameLanguage.Add(partName, fields.Language);
        }

        var fileName = fields.FileName.Length > 0 ? fields.FileName : fields.AltFileName;
        totalSize += content.Length;
        if (fileName.Length > 0)
        {
            // Keyed by the part's field name, as ModSecurity does (Coraza uses empty keys), so FILES:avatar selects
            // and ctl:ruleRemoveTargetById=...;FILES:avatar excludes one upload field.
            var size = content.Length.ToString(CultureInfo.InvariantCulture);
            v.Files.Add(partName, fileName);
            if (fields.AltFileName.Length > 0 && fields.AltFileName != fileName)
            {
                v.Files.Add(partName, fields.AltFileName);
            }

            v.FilesSizes.Add(partName, size);
            v.FilesNames.Add(partName, partName);
            v.FilesCombinedSize.Set(totalSize.ToString(CultureInfo.InvariantCulture));
            return false;
        }

        tx.AddPostRequestArgument(partName, content);
        v.FilesCombinedSize.Set(totalSize.ToString(CultureInfo.InvariantCulture));
        return true;
    }

    private static void FlagUnexpectedEof(Collections.TransactionVariables v)
    {
        if (v.InboundDataError.Value != "1")
        {
            v.MultipartStrictError.Set("1");
        }
    }

    // Finds "--boundary" at the start of a line. The first boundary may appear at offset 0.
    private static int FindBoundaryLine(string text, string dashBoundary, int from, bool first)
    {
        var i = from;
        while (true)
        {
            var idx = text.IndexOf(dashBoundary, i, StringComparison.Ordinal);
            if (idx < 0)
            {
                return -1;
            }

            if ((first && idx == 0) || (idx > 0 && text[idx - 1] == '\n') || (idx == from && !first && from == 0))
            {
                var after = idx + dashBoundary.Length;
                if (after >= text.Length || text[after] is '\r' or '\n' or '-' or ' ' or '\t')
                {
                    return idx;
                }
            }

            i = idx + 1;
        }
    }

    // Finds the blank line that ends the part headers, searching only up to the next delimiter (searching the whole
    // rest of the body for every part is quadratic).
    private static int FindHeadersEnd(string text, int start, int limit, out int bodyStart)
    {
        // An empty header block: the body starts right after a blank line.
        if (string.CompareOrdinal(text, start, "\r\n", 0, 2) == 0)
        {
            bodyStart = start + 2;
            return start;
        }

        if (start < text.Length && text[start] == '\n')
        {
            bodyStart = start + 1;
            return start;
        }

        var count = Math.Max(0, limit - start);
        var crlf = text.IndexOf("\r\n\r\n", start, count, StringComparison.Ordinal);
        var lf = text.IndexOf("\n\n", start, count, StringComparison.Ordinal);
        if (crlf >= 0 && (lf < 0 || crlf < lf))
        {
            bodyStart = crlf + 4;
            return crlf;
        }

        if (lf >= 0)
        {
            bodyStart = lf + 2;
            return lf;
        }

        bodyStart = -1;
        return -1;
    }

    private static List<KeyValuePair<string, string>> ParseHeaders(string block, out bool malformed)
    {
        malformed = false;
        var result = new List<KeyValuePair<string, string>>();
        foreach (var rawLine in block.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            if (line.Length == 0)
            {
                continue;
            }

            if (line[0] is ' ' or '\t' && result.Count > 0)
            {
                // Obsolete line folding.
                var last = result[^1];
                result[^1] = new(last.Key, last.Value + " " + line.Trim());
                continue;
            }

            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
            {
                malformed = true;
                continue;
            }

            result.Add(new(CanonicalHeaderKey(line[..colon].Trim()), line[(colon + 1)..].Trim(' ', '\t')));
        }

        return result;
    }

    // Go's textproto.CanonicalMIMEHeaderKey.
    private static string CanonicalHeaderKey(string key)
    {
        foreach (var c in key)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c == '-' || "!#$%&'*+.^_`|~".Contains(c, StringComparison.Ordinal)))
            {
                return key;
            }
        }

        var sb = new StringBuilder(key.Length);
        var upper = true;
        foreach (var c in key)
        {
            sb.Append(upper ? char.ToUpperInvariant(c) : char.ToLowerInvariant(c));
            upper = c == '-';
        }

        return sb.ToString();
    }

    private static string FormName(string disposition)
    {
        if (!MediaType.TryParse(disposition, out var type, out var parameters) || type != "form-data")
        {
            return string.Empty;
        }

        return parameters.GetValueOrDefault("name") ?? string.Empty;
    }

    private sealed class FileNameFields
    {
        public string FileName { get; private set; } = string.Empty;

        public string AltFileName { get; private set; } = string.Empty;

        public string Charset { get; private set; } = string.Empty;

        public string Language { get; private set; } = string.Empty;

        public bool HasExtended { get; private set; }

        public bool Malformed { get; private set; }

        public bool DuplicateParam { get; private set; }

        public bool InvalidQuoting { get; private set; }

        public static FileNameFields From(string cd)
        {
            var f = new FileNameFields();
            if (!MediaType.TryParse(cd, out _, out var parameters))
            {
                if (cd.Length > 0)
                {
                    f.Malformed = true;
                    f.DuplicateParam = HasDuplicateParam(cd);
                }

                return f;
            }

            var plain = parameters.GetValueOrDefault("filename") ?? string.Empty;
            f.FileName = plain;
            if (!TryFindParam(cd, "filename*", out var raw))
            {
                if (HasFilenameContinuation(cd))
                {
                    f.Malformed = true;
                    if (TryFindParam(cd, "filename", out var rawPlain))
                    {
                        rawPlain = UnquoteIfQuoted(rawPlain, out _);
                        f.FileName = rawPlain;
                        if (plain.Length > 0 && plain != rawPlain)
                        {
                            f.AltFileName = plain;
                        }
                    }
                }

                return f;
            }

            if (HasFilenameContinuation(cd))
            {
                f.Malformed = true;
            }

            raw = UnquoteIfQuoted(raw, out var wasQuoted);
            if (wasQuoted)
            {
                f.InvalidQuoting = true;
            }

            var parts = raw.Split('\'', 3);
            if (parts.Length != 3)
            {
                f.Malformed = true;
                return f;
            }

            var decoded = PercentDecodeLenient(parts[2], out var invalidEscape);
            f.FileName = decoded;
            f.Charset = parts[0];
            f.Language = parts[1];
            f.HasExtended = true;
            if (TryFindParam(cd, "filename", out var plainRaw))
            {
                plainRaw = UnquoteIfQuoted(plainRaw, out _);
                if (plainRaw.Length > 0 && plainRaw != decoded)
                {
                    f.AltFileName = plainRaw;
                }
            }

            if (invalidEscape)
            {
                f.Malformed = true;
            }

            return f;
        }

        private static string UnquoteIfQuoted(string s, out bool wasQuoted)
        {
            wasQuoted = false;
            if (s.Length < 2 || s[0] != '"' || s[^1] != '"')
            {
                return s;
            }

            wasQuoted = true;
            var inner = s[1..^1];
            var sb = new StringBuilder(inner.Length);
            for (var i = 0; i < inner.Length; i++)
            {
                if (inner[i] == '\\' && i + 1 < inner.Length)
                {
                    i++;
                }

                sb.Append(inner[i]);
            }

            return sb.ToString();
        }

        private static bool HasFilenameContinuation(string s)
        {
            foreach (var seg in Params(s))
            {
                var eq = seg.IndexOf('=', StringComparison.Ordinal);
                if (eq < 0)
                {
                    continue;
                }

                var key = seg[..eq].Trim().TrimEnd('*').ToLowerInvariant();
                if (key.StartsWith("filename*", StringComparison.Ordinal))
                {
                    var digits = key["filename*".Length..];
                    if (digits.Length > 0 && digits.All(char.IsAsciiDigit))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static bool TryFindParam(string s, string key, out string value)
        {
            foreach (var seg in Params(s))
            {
                var eq = seg.IndexOf('=', StringComparison.Ordinal);
                if (eq >= 0 && string.Equals(seg[..eq].Trim(), key, StringComparison.OrdinalIgnoreCase))
                {
                    value = seg[(eq + 1)..].Trim();
                    return true;
                }
            }

            value = string.Empty;
            return false;
        }

        private static bool HasDuplicateParam(string s)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var seg in Params(s))
            {
                var eq = seg.IndexOf('=', StringComparison.Ordinal);
                if (eq >= 0 && !seen.Add(seg[..eq].Trim().ToLowerInvariant()))
                {
                    return true;
                }
            }

            return false;
        }

        private static IEnumerable<string> Params(string s)
        {
            var inQuotes = false;
            var start = 0;
            for (var i = 0; i < s.Length; i++)
            {
                if (s[i] == '\\' && inQuotes)
                {
                    i++;
                }
                else if (s[i] == '"')
                {
                    inQuotes = !inQuotes;
                }
                else if (s[i] == ';' && !inQuotes)
                {
                    yield return s[start..i];
                    start = i + 1;
                }
            }

            yield return s[start..];
        }

        private static string PercentDecodeLenient(string s, out bool invalid)
        {
            invalid = false;
            if (!s.Contains('%', StringComparison.Ordinal))
            {
                return s;
            }

            var sb = new StringBuilder(s.Length);
            for (var i = 0; i < s.Length; i++)
            {
                if (s[i] == '%' && i + 2 < s.Length && ByteString.IsHex(s[i + 1]) && ByteString.IsHex(s[i + 2]))
                {
                    sb.Append((char)((ByteString.HexValue(s[i + 1]) << 4) | ByteString.HexValue(s[i + 2])));
                    i += 2;
                    continue;
                }

                if (s[i] == '%')
                {
                    invalid = true;
                }

                sb.Append(s[i]);
            }

            return sb.ToString();
        }
    }
}

/// <summary>Go's mime.ParseMediaType, simplified: type/subtype; params with token or quoted-string values.</summary>
internal static class MediaType
{
    public static bool TryParse(string value, out string mediaType, out Dictionary<string, string> parameters)
    {
        parameters = new Dictionary<string, string>(StringComparer.Ordinal);
        var semi = value.IndexOf(';', StringComparison.Ordinal);
        mediaType = (semi < 0 ? value : value[..semi]).Trim().ToLowerInvariant();
        if (mediaType.Length == 0 || !IsTokenOrSlash(mediaType))
        {
            return false;
        }

        var rest = semi < 0 ? string.Empty : value[(semi + 1)..];
        var i = 0;
        while (i < rest.Length)
        {
            while (i < rest.Length && (rest[i] is ' ' or '\t' or ';'))
            {
                i++;
            }

            if (i >= rest.Length)
            {
                break;
            }

            var keyStart = i;
            while (i < rest.Length && IsTokenChar(rest[i]))
            {
                i++;
            }

            var key = rest[keyStart..i].ToLowerInvariant();
            while (i < rest.Length && rest[i] is ' ' or '\t')
            {
                i++;
            }

            if (key.Length == 0 || i >= rest.Length || rest[i] != '=')
            {
                return false;
            }

            i++;
            while (i < rest.Length && rest[i] is ' ' or '\t')
            {
                i++;
            }

            string val;
            if (i < rest.Length && rest[i] == '"')
            {
                var sb = new StringBuilder();
                i++;
                var closed = false;
                while (i < rest.Length)
                {
                    var c = rest[i];
                    // As in Go's mime package, a backslash escapes only a tspecial; otherwise it is kept, so
                    // name="..\x" still shows the backslash to the rules.
                    if (c == '\\' && i + 1 < rest.Length && IsTSpecial(rest[i + 1]))
                    {
                        sb.Append(rest[i + 1]);
                        i += 2;
                        continue;
                    }

                    if (c == '"')
                    {
                        closed = true;
                        i++;
                        break;
                    }

                    sb.Append(c);
                    i++;
                }

                if (!closed)
                {
                    return false;
                }

                val = sb.ToString();
            }
            else
            {
                var valStart = i;
                while (i < rest.Length && IsTokenChar(rest[i]))
                {
                    i++;
                }

                val = rest[valStart..i];
                if (val.Length == 0)
                {
                    return false;
                }
            }

            if (!parameters.TryAdd(key, val))
            {
                // Duplicate parameter names are an error in Go's mime.ParseMediaType.
                return false;
            }

            while (i < rest.Length && rest[i] is ' ' or '\t')
            {
                i++;
            }

            if (i < rest.Length && rest[i] != ';')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsTSpecial(char c) => "()<>@,;:\\\"/[]?=".Contains(c, StringComparison.Ordinal);

    private static bool IsTokenChar(char c) =>
        c > ' ' && c < 0x7f && !"()<>@,;:\\\"/[]?=".Contains(c, StringComparison.Ordinal);

    private static bool IsTokenOrSlash(string s)
    {
        var slash = s.IndexOf('/', StringComparison.Ordinal);
        if (slash < 0)
        {
            return s.All(IsTokenChar);
        }

        var major = s[..slash];
        var minor = s[(slash + 1)..];
        return major.Length > 0 && minor.Length > 0 && major.All(IsTokenChar) && minor.All(IsTokenChar);
    }
}
