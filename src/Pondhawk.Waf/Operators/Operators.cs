// Operator semantics follow OWASP Coraza (Apache-2.0).
using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Pondhawk.Waf.LibInjection;
using Pondhawk.Waf.Rules;
using Pondhawk.Waf.SecLang;
using Pondhawk.Waf.Text;

namespace Pondhawk.Waf.Operators;

/// <summary>A SecLang operator (@name). Values are byte strings.</summary>
public interface IOperator
{
    bool Evaluate(Transaction tx, string value);
}

/// <summary>What an operator factory needs: its argument and where to read data files from.</summary>
public sealed record OperatorOptions(string Arguments, string ConfigDirectory, IConfigFileSystem FileSystem, RegexCache RegexCache);

/// <summary>The built-in operators.</summary>
public static class OperatorRegistry
{
    private static readonly FrozenDictionary<string, Func<OperatorOptions, IOperator>> Factories =
        new Dictionary<string, Func<OperatorOptions, IOperator>>(StringComparer.OrdinalIgnoreCase)
        {
            ["rx"] = o => RxOperator.Create(o.Arguments, o.RegexCache),
            ["pm"] = o => new PmOperator(o.Arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries)),
            ["pmFromFile"] = o => new PmOperator(ReadDataFile(o)),
            ["pmf"] = o => new PmOperator(ReadDataFile(o)),
            ["detectSQLi"] = _ => new DetectSqliOperator(),
            ["detectXSS"] = _ => new DetectXssOperator(),
            ["eq"] = o => new NumericOperator(Macro.Parse(o.Arguments), (v, d) => v == d),
            ["ge"] = o => new NumericOperator(Macro.Parse(o.Arguments), (v, d) => v >= d),
            ["gt"] = o => new NumericOperator(Macro.Parse(o.Arguments), (v, d) => v > d),
            ["le"] = o => new NumericOperator(Macro.Parse(o.Arguments), (v, d) => v <= d),
            ["lt"] = o => new NumericOperator(Macro.Parse(o.Arguments), (v, d) => v < d),
            ["streq"] = o => new StringOperator(Macro.Parse(o.Arguments), (v, d) => v == d),
            ["beginsWith"] = o => new StringOperator(Macro.Parse(o.Arguments), (v, d) => v.StartsWith(d, StringComparison.Ordinal)),
            ["endsWith"] = o => new StringOperator(Macro.Parse(o.Arguments), (v, d) => v.EndsWith(d, StringComparison.Ordinal)),
            ["contains"] = o => new StringOperator(Macro.Parse(o.Arguments), (v, d) => v.Contains(d, StringComparison.Ordinal)),
            ["containsWord"] = o => new StringOperator(Macro.Parse(o.Arguments), ContainsWord),
            ["within"] = o => new StringOperator(Macro.Parse(o.Arguments), (v, d) => d.Contains(v, StringComparison.Ordinal)),
            ["strmatch"] = o => new StringOperator(Macro.Parse(o.Arguments), (v, d) => v.Contains(d, StringComparison.Ordinal)),
            ["unconditionalMatch"] = _ => new ConstantOperator(true),
            ["noMatch"] = _ => new ConstantOperator(false),
            ["validateByteRange"] = o => ValidateByteRangeOperator.Create(o.Arguments),
            ["validateUrlEncoding"] = _ => new ValidateUrlEncodingOperator(),
            ["validateUtf8Encoding"] = _ => new ValidateUtf8EncodingOperator(),
            ["ipMatch"] = o => new IpMatchOperator(o.Arguments.Split(',')),
            ["ipMatchFromFile"] = o => new IpMatchOperator(ReadDataFile(o)),
            ["ipMatchF"] = o => new IpMatchOperator(ReadDataFile(o)),
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    public static bool IsKnown(string name) => Factories.ContainsKey(name);

    public static IOperator Create(string name, OperatorOptions options)
    {
        if (!Factories.TryGetValue(name, out var factory))
        {
            throw new NotSupportedException($"unsupported operator @{name}");
        }

        return factory(options);
    }

    /// <summary>Reads a data file: one entry per line, '#' comments and blank lines skipped. Relative to the config file.</summary>
    internal static List<string> ReadDataFile(OperatorOptions o)
    {
        var path = o.FileSystem.Combine(o.ConfigDirectory, o.Arguments.Trim());
        if (!o.FileSystem.FileExists(path))
        {
            throw new FileNotFoundException($"data file not found: {o.Arguments}", path);
        }

        var lines = new List<string>();
        foreach (var raw in o.FileSystem.ReadAllText(path).Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            lines.Add(ByteString.FromUtf16(line));
        }

        return lines;
    }

    private static bool ContainsWord(string value, string word)
    {
        if (word.Length == 0)
        {
            return true;
        }

        var start = 0;
        while (true)
        {
            var idx = value.IndexOf(word, start, StringComparison.Ordinal);
            if (idx < 0)
            {
                return false;
            }

            var before = idx == 0 || !IsWordChar(value[idx - 1]);
            var end = idx + word.Length;
            var after = end == value.Length || !IsWordChar(value[end]);
            if (before && after)
            {
                return true;
            }

            start = idx + 1;
        }
    }

    private static bool IsWordChar(char c) => char.IsAsciiLetterOrDigit(c) || c == '_';
}

/// <summary>Compiles and shares regexes across rules (CRS reuses many patterns).</summary>
public sealed class RegexCache
{
    private const string MaxAutomataSizeSwitch = "REGEX_NONBACKTRACKING_MAX_AUTOMATA_SIZE";

    // Process-wide: every engine built from the same rules shares one Regex per pattern (#32). Regex is immutable and
    // thread-safe. The key holds everything that changes the result. Entries live as long as the process; patterns
    // come from rule files, so the store grows only when a reload brings new patterns.
    private static readonly ConcurrentDictionary<(string Key, bool NonBacktracking, TimeSpan Timeout), Lazy<Regex>> SharedRegexes = new();
    private static readonly ConcurrentDictionary<string, Lazy<RegexPrefilter?>> SharedPrefilters = new(StringComparer.Ordinal);

    // This cache's patterns: the ones CompileAll builds.
    private readonly Dictionary<string, Lazy<Regex>> _cache = new(StringComparer.Ordinal);

    static RegexCache()
    {
        // Large CRS patterns (e.g. 932235, 10 KB) exceed the default NonBacktracking limit of 10,000 nodes and would
        // fall back to the backtracking engine. Raise the limit unless the host already set it.
        if (AppContext.GetData(MaxAutomataSizeSwitch) is null)
        {
            AppContext.SetData(MaxAutomataSizeSwitch, 200_000);
        }
    }

    /// <summary>Use the linear-time NonBacktracking engine when the pattern allows it. Default true.</summary>
    public bool PreferNonBacktracking { get; init; } = true;

    /// <summary>Skip @rx evaluation when a value lacks a literal every match needs (see <see cref="RegexPrefilter"/>). Default true.</summary>
    public bool UsePrefilter { get; init; } = true;

    /// <summary>The prefilter for a SecLang pattern, or null.</summary>
    internal RegexPrefilter? GetPrefilter(string pattern) =>
        UsePrefilter
            ? SharedPrefilters.GetOrAdd(pattern, static p => new Lazy<RegexPrefilter?>(() => RegexPrefilter.Create(p), LazyThreadSafetyMode.ExecutionAndPublication)).Value
            : null;

    /// <summary>Timeout for patterns that need the backtracking engine.</summary>
    public TimeSpan BacktrackingTimeout { get; init; } = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// Compiles a SecLang (RE2/PCRE syntax) pattern as Coraza does: with (?s) and (?m).
    /// </summary>
    public Regex Get(string pattern) => GetDeferred(pattern).Value;

    /// <summary>
    /// Like <see cref="Get"/>, but builds the regex on first use. Building the NonBacktracking automata of CRS takes
    /// seconds; <see cref="CompileAll"/> builds the deferred ones in the background after the rules load. The syntax is
    /// checked now (a few milliseconds for all of CRS), so an invalid pattern still fails the configuration.
    /// </summary>
    internal Lazy<Regex> GetDeferred(string pattern)
    {
        lock (_cache)
        {
            if (!_cache.TryGetValue(pattern, out var cached))
            {
                const RegexOptions options = RegexOptions.Singleline | RegexOptions.Multiline;
                var key = (pattern, PreferNonBacktracking, BacktrackingTimeout);
                if (!SharedRegexes.TryGetValue(key, out cached))
                {
                    // Not seen in this process: check the syntax now, so an invalid pattern fails the configuration.
                    _ = new Regex(TranslatePattern(pattern), RegexOptions.CultureInvariant | options);
                    cached = SharedRegexes.GetOrAdd(key, static k => new Lazy<Regex>(() => Compile(k.Key, options, k.NonBacktracking, k.Timeout), LazyThreadSafetyMode.ExecutionAndPublication));
                }

                _cache[pattern] = cached;
            }

            return cached;
        }
    }

    /// <summary>
    /// Builds every deferred regex, in parallel. A regex in use before this reaches it is built by its user; one another
    /// engine in the process already built is shared and costs nothing.
    /// </summary>
    internal void CompileAll()
    {
        Lazy<Regex>[] pending;
        lock (_cache)
        {
            pending = [.. _cache.Values.Where(l => !l.IsValueCreated)];
        }

        Parallel.ForEach(pending, lazy => WarmUp(lazy.Value));
    }

    // Runs a compiled (backtracking) regex once, so the JIT compiles its code here and not in a request's match. The
    // probe does not reach every method of every regex; RxOperator.Evaluate handles the rest.
    private static void WarmUp(Regex regex)
    {
        if (regex.MatchTimeout == Regex.InfiniteMatchTimeout || (regex.Options & RegexOptions.NonBacktracking) != 0)
        {
            return;
        }

        try
        {
            _ = regex.IsMatch(WarmUpProbe);
        }
        catch (RegexMatchTimeoutException)
        {
            // The JIT took the time; it has run.
        }
    }

    private const string WarmUpProbe = "GET /index.php?id=1&q=select+1+from+t Host: localhost <script>alert(1)</script> ../../etc/passwd; cat /x | $(id) {\"a\":[1]}";

    /// <summary>Compiles a pattern without the SecLang default flags (used for collection key selectors).</summary>
    public Regex GetPlain(string pattern)
    {
        var key = "\0plain\0" + pattern;
        Lazy<Regex>? cached;
        lock (_cache)
        {
            if (!_cache.TryGetValue(key, out cached))
            {
                cached = SharedRegexes.GetOrAdd((key, PreferNonBacktracking, BacktrackingTimeout),
                    k => new Lazy<Regex>(() => Compile(pattern, RegexOptions.None, k.NonBacktracking, k.Timeout), LazyThreadSafetyMode.ExecutionAndPublication));
                _cache[key] = cached;
            }
        }

        return cached.Value;
    }

    // Static: a shared Lazy must not keep the RegexCache that created it alive.
    private static Regex Compile(string pattern, RegexOptions extra, bool preferNonBacktracking, TimeSpan backtrackingTimeout)
    {
        var translated = TranslatePattern(pattern, remapHighBytes: extra != RegexOptions.None && UsesWordBoundary(pattern));
        var options = RegexOptions.CultureInvariant | extra;
        if (preferNonBacktracking)
        {
            try
            {
                return new Regex(translated, options | RegexOptions.NonBacktracking);
            }
            catch (Exception ex) when (ex is not RegexParseException)
            {
                // Lookarounds, backreferences, atomic groups or an automaton over the size limit (NotSupportedException):
                // fall back to the backtracking engine with a timeout.
            }
        }

        try
        {
            return new Regex(translated, options | RegexOptions.Compiled, backtrackingTimeout);
        }
        catch (Exception ex) when (ex is not RegexParseException)
        {
            // The syntax was checked when the rule loaded; never fail a request over code generation.
            return new Regex(translated, options, backtrackingTimeout);
        }
    }

    /// <summary>
    /// Translates RE2/PCRE syntax that .NET reads differently:
    /// <list type="bullet">
    /// <item>\x{HH} escapes (not supported by .NET);</item>
    /// <item>(?P&lt;name&gt;...) groups;</item>
    /// <item>escaped punctuation inside a character class, e.g. [\--9]: .NET does not accept an escaped character as a
    /// range start, so it is rewritten as \xHH;</item>
    /// <item>a bare '[' inside a class, which .NET can read as class subtraction ("-[").</item>
    /// <item>\w, \W, \d, \D, \s and \S, which are ASCII-only in RE2 but Unicode in .NET: byte strings hold bytes
    /// 0x80-0xFF as Latin-1 letters and spaces (é, ª, NBSP), so "%C2%AAeval(" would hide "eval" from \b and \w.</item>
    /// </list>
    /// With <paramref name="remapHighBytes"/> (patterns with \b or \B), byte escapes 0x80-0xFF become U+E080-U+E0FF,
    /// matching inputs passed through <see cref="RemapHighBytes"/>: .NET has no ASCII-only \b, and private-use
    /// characters are not word characters.
    /// </summary>
    internal static string TranslatePattern(string pattern, bool remapHighBytes = false)
    {
        var sb = new StringBuilder(pattern.Length + 16);
        var inClass = false;
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == '\\' && i + 1 < pattern.Length)
            {
                var next = pattern[i + 1];
                if (next == 'x' && i + 2 < pattern.Length && pattern[i + 2] == '{')
                {
                    var close = pattern.IndexOf('}', i + 3);
                    if (close > i + 3 && int.TryParse(pattern.AsSpan(i + 3, close - i - 3), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code))
                    {
                        // Coraza matches \x{HH} (HH <= ff) as a raw byte; byte strings hold bytes as chars.
                        sb.Append(code is >= 0x80 and <= 0xff && remapHighBytes ? $"\\u{0xE000 + code:x4}"
                            : code <= 0xff ? $"\\x{code:x2}" : $"\\u{code:x4}");
                        i = close;
                        continue;
                    }
                }

                if (next == 'x' && remapHighBytes && i + 3 < pattern.Length && ByteString.IsHex(pattern[i + 2]) && ByteString.IsHex(pattern[i + 3]))
                {
                    var code = (ByteString.HexValue(pattern[i + 2]) << 4) | ByteString.HexValue(pattern[i + 3]);
                    sb.Append(code >= 0x80 ? $"\\u{0xE000 + code:x4}" : $"\\x{code:x2}");
                    i += 3;
                    continue;
                }

                if (AsciiClass(next, inClass) is { } ascii)
                {
                    sb.Append(ascii);
                    i++;
                    continue;
                }

                if (inClass && !char.IsAsciiLetterOrDigit(next) && next < 0x80)
                {
                    sb.Append($"\\x{(int)next:x2}");
                    i++;
                    continue;
                }

                sb.Append(c).Append(next);
                i++;
                continue;
            }

            if (inClass)
            {
                if (c == ']')
                {
                    inClass = false;
                    sb.Append(c);
                }
                else if (c == '[')
                {
                    sb.Append("\\[");
                }
                else
                {
                    sb.Append(c);
                }

                continue;
            }

            if (c == '[')
            {
                inClass = true;
                sb.Append(c);
                // A ']' right after '[' or '[^' is a literal.
                if (i + 1 < pattern.Length && pattern[i + 1] == '^')
                {
                    sb.Append('^');
                    i++;
                }

                if (i + 1 < pattern.Length && pattern[i + 1] == ']')
                {
                    sb.Append("\\]");
                    i++;
                }

                continue;
            }

            if (remapHighBytes && c is >= '\u0080' and <= '\u00ff')
            {
                sb.Append($"\\u{0xE000 + c:x4}");
                continue;
            }

            if (c == '(' && string.CompareOrdinal(pattern, i, "(?P<", 0, 4) == 0)
            {
                sb.Append("(?<");
                i += 3;
                continue;
            }

            sb.Append(c);
        }

        return sb.ToString();
    }

    /// <summary>True when the pattern uses \b or \B (outside a character class).</summary>
    internal static bool UsesWordBoundary(string pattern)
    {
        var inClass = false;
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == '\\' && i + 1 < pattern.Length)
            {
                if (!inClass && pattern[i + 1] is 'b' or 'B')
                {
                    return true;
                }

                i++;
            }
            else if (c == '[')
            {
                inClass = true;
            }
            else if (c == ']')
            {
                inClass = false;
            }
        }

        return false;
    }

    /// <summary>
    /// True when the pattern matches bytes, not UTF-8 characters: it contains a non-ASCII character or an escape for a
    /// byte 0x80-0xFF (\x80, \x{ff}). Coraza compiles such patterns as binary regexes too; all others match runes.
    /// </summary>
    internal static bool MatchesBytes(string pattern)
    {
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c > 0x7f)
            {
                return true;
            }

            if (c != '\\' || i + 1 >= pattern.Length)
            {
                continue;
            }

            if (pattern[i + 1] == 'x')
            {
                if (i + 3 < pattern.Length && ByteString.IsHex(pattern[i + 2]) && ByteString.IsHex(pattern[i + 3])
                    && ((ByteString.HexValue(pattern[i + 2]) << 4) | ByteString.HexValue(pattern[i + 3])) >= 0x80)
                {
                    return true;
                }

                if (i + 2 < pattern.Length && pattern[i + 2] == '{')
                {
                    var close = pattern.IndexOf('}', i + 3);
                    if (close > i + 3 && int.TryParse(pattern.AsSpan(i + 3, close - i - 3), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code) && code >= 0x80)
                    {
                        return true;
                    }
                }
            }

            i++;
        }

        return false;
    }

    /// <summary>
    /// Stands for one non-ASCII character in values matched by rune patterns (see <see cref="CollapseUtf8"/>). Private
    /// use: not a word, digit or space character, and not case-folded to anything.
    /// </summary>
    internal const char NonAsciiPlaceholder = '\ue000';

    /// <summary>
    /// For patterns that match UTF-8 characters (Go regexp semantics): replaces each UTF-8 encoded character, and each
    /// byte that is not valid UTF-8 (Go reads it as one U+FFFD rune), with one <see cref="NonAsciiPlaceholder"/>. A
    /// pure-ASCII pattern cannot tell non-ASCII characters apart (\w, \d, \s are ASCII classes), so `.`, `[^=]{1,10}`
    /// and other counts see one character where the bytes have two to four. ASCII input is returned as is.
    /// </summary>
    internal static string CollapseUtf8(string value)
    {
        var first = value.AsSpan().IndexOfAnyExceptInRange('\0', '\u007f');
        if (first < 0)
        {
            return value;
        }

        var sb = new StringBuilder(value.Length);
        sb.Append(value, 0, first);
        for (var i = first; i < value.Length;)
        {
            if (value[i] <= 0x7f)
            {
                sb.Append(value[i]);
                i++;
            }
            else
            {
                sb.Append(NonAsciiPlaceholder);
                i += Utf8Length(value, i);
            }
        }

        return sb.ToString();
    }

    /// <summary>For each char of <see cref="CollapseUtf8"/>(value), its index in value; the last entry is value.Length.</summary>
    internal static int[] CollapseUtf8Offsets(string value)
    {
        var offsets = new List<int>(value.Length + 1);
        for (var i = 0; i < value.Length;)
        {
            offsets.Add(i);
            i += value[i] <= 0x7f ? 1 : Utf8Length(value, i);
        }

        offsets.Add(value.Length);
        return [.. offsets];
    }

    // Bytes in one UTF-8 character starting at value[i] (chars are bytes), or 1 for a byte that does not start a valid
    // sequence, as Go's utf8.DecodeRune reads it: no overlong forms, surrogates or code points above U+10FFFF.
    private static int Utf8Length(string value, int i)
    {
        var b0 = value[i];
        var (length, lo, hi) = b0 switch
        {
            >= '\u00c2' and <= '\u00df' => (2, 0x80, 0xbf),
            '\u00e0' => (3, 0xa0, 0xbf),
            >= '\u00e1' and <= '\u00ec' or '\u00ee' or '\u00ef' => (3, 0x80, 0xbf),
            '\u00ed' => (3, 0x80, 0x9f),
            '\u00f0' => (4, 0x90, 0xbf),
            >= '\u00f1' and <= '\u00f3' => (4, 0x80, 0xbf),
            '\u00f4' => (4, 0x80, 0x8f),
            _ => (1, 0, 0),
        };
        if (length == 1 || i + length > value.Length || value[i + 1] < lo || value[i + 1] > hi)
        {
            return 1;
        }

        for (var k = 2; k < length; k++)
        {
            if (value[i + k] is < '\u0080' or > '\u00bf')
            {
                return 1;
            }
        }

        return length;
    }

    [ThreadStatic]
    private static string? _lastInput;

    [ThreadStatic]
    private static string? _lastRemapped;

    /// <summary>Moves chars 0x80-0xFF to U+E080-U+E0FF (see <see cref="TranslatePattern"/>). ASCII input is returned as is.</summary>
    internal static string RemapHighBytes(string value)
    {
        if (value.AsSpan().IndexOfAnyInRange('\u0080', '\u00ff') < 0)
        {
            return value;
        }

        // Many rules evaluate the same value in a row.
        if (ReferenceEquals(value, _lastInput))
        {
            return _lastRemapped!;
        }

        var remapped = string.Create(value.Length, value, static (span, source) =>
        {
            for (var i = 0; i < source.Length; i++)
            {
                var c = source[i];
                span[i] = c is >= '\u0080' and <= '\u00ff' ? (char)(0xE000 + c) : c;
            }
        });
        _lastInput = value;
        _lastRemapped = remapped;
        return remapped;
    }

    internal static string UnmapHighBytes(string value)
    {
        if (value.AsSpan().IndexOfAnyInRange('\ue080', '\ue0ff') < 0)
        {
            return value;
        }

        return string.Create(value.Length, value, static (span, source) =>
        {
            for (var i = 0; i < source.Length; i++)
            {
                var c = source[i];
                span[i] = c is >= '\ue080' and <= '\ue0ff' ? (char)(c - 0xE000) : c;
            }
        });
    }

    // RE2 classes are ASCII-only; .NET's are Unicode. Byte strings use chars up to 0xFF (and U+E080-U+E0FF after
    // remapping), so the complements run to U+FFFF.
    private static string? AsciiClass(char escape, bool inClass) => (escape, inClass) switch
    {
        ('w', false) => "[0-9A-Za-z_]",
        ('w', true) => "0-9A-Za-z_",
        ('W', false) => "[^0-9A-Za-z_]",
        ('W', true) => "\\x00-\\x2f\\x3a-\\x40\\x5b-\\x5e\\x60\\x7b-\\uffff",
        ('d', false) => "[0-9]",
        ('d', true) => "0-9",
        ('D', false) => "[^0-9]",
        ('D', true) => "\\x00-\\x2f\\x3a-\\uffff",
        ('s', false) => "[\\t\\n\\f\\r ]",
        ('s', true) => "\\t\\n\\f\\r\\x20",
        ('S', false) => "[^\\t\\n\\f\\r ]",
        ('S', true) => "\\x00-\\x08\\x0b\\x0e-\\x1f\\x21-\\uffff",
        _ => null,
    };
}

/// <summary>
/// @rx. A pattern without non-ASCII characters or byte escapes matches UTF-8 characters, as Go's regexp does in Coraza:
/// the value is matched with each non-ASCII character collapsed to one char (<see cref="RegexCache.CollapseUtf8"/>).
/// Other patterns match bytes; those with \b or \B see bytes 0x80-0xFF remapped so that they are not word characters.
/// </summary>
internal sealed class RxOperator(Lazy<Regex> regex, bool remapHighBytes = false, RegexPrefilter? prefilter = null, bool matchesRunes = false) : IOperator
{
    public RxOperator(Regex regex, bool remapHighBytes = false, RegexPrefilter? prefilter = null, bool matchesRunes = false)
        : this(new Lazy<Regex>(regex), remapHighBytes, prefilter, matchesRunes)
    {
    }

    public static RxOperator Create(string pattern, RegexCache cache)
    {
        var bytes = RegexCache.MatchesBytes(pattern);

        // Collapsed values hold no bytes 0x80-0xFF, so rune patterns need no remapping for \b.
        return new RxOperator(cache.GetDeferred(pattern), bytes && RegexCache.UsesWordBoundary(pattern), cache.GetPrefilter(pattern), !bytes);
    }

    /// <summary>True when the pattern matches UTF-8 characters rather than bytes.</summary>
    internal bool MatchesRunes => matchesRunes;

    public Regex Regex => regex.Value;

    /// <summary>The deferred regex, compiled when the rules are loaded (see <see cref="RegexCache.CompileAll"/>).</summary>
    internal Lazy<Regex> DeferredRegex => regex;

    /// <summary>Tests only: called for every value the prefilter rejects, to check that the regex does not match it.</summary>
    internal static Action<RxOperator, string>? VerifyPrefilter { get; set; }

    /// <summary>The prefilter, or null when the pattern has none or prefiltering is off.</summary>
    internal RegexPrefilter? Prefilter { get; } = prefilter;

    public bool Evaluate(Transaction tx, string value)
    {
        // Collapsing and remapping leave ASCII in place, so the prefilter's literals are found either way; its minimum
        // length counts the chars the regex sees.
        var input = matchesRunes ? tx.CollapseUtf8(value) : value;
        if (Prefilter is not null && !Prefilter.MightMatch(input))
        {
            if (VerifyPrefilter is { } verify)
            {
                verify(this, value);
            }

            return false;
        }

        if (remapHighBytes)
        {
            input = RegexCache.RemapHighBytes(input);
        }

        // A compiled (backtracking) regex is JIT-compiled method by method, on the first call of each: the first matches
        // can exceed the timeout although the input is harmless (#34). A timeout is thrown at a check after the methods
        // on its path are compiled, so after the first timeout the code is ready. A match that started before it gets
        // one retry; a match that started after it is timed on compiled code.
        var jitDone = _timedOut;
        try
        {
            return Match(tx, value, input);
        }
        catch (RegexMatchTimeoutException) when (!jitDone)
        {
            _timedOut = true;
            return Match(tx, value, input);
        }
    }

    private volatile bool _timedOut;

    /// <summary>Tests only: runs before each match of this operator.</summary>
    internal Action? BeforeMatch { get; set; }

    private bool Match(Transaction tx, string value, string input)
    {
        BeforeMatch?.Invoke();
        if (!tx.Capturing)
        {
            return Regex.IsMatch(input);
        }

        var match = Regex.Match(input);
        if (!match.Success)
        {
            return false;
        }

        // Captures are the original bytes: map collapsed positions back.
        var offsets = matchesRunes && !ReferenceEquals(input, value) ? RegexCache.CollapseUtf8Offsets(value) : null;
        for (var i = 0; i < match.Groups.Count && i < 9; i++)
        {
            var g = match.Groups[i];
            var captured = !g.Success ? string.Empty
                : offsets is not null ? value[offsets[g.Index]..offsets[g.Index + g.Length]]
                : remapHighBytes ? RegexCache.UnmapHighBytes(g.Value)
                : g.Value;
            tx.CaptureField(i, captured);
        }

        return true;
    }

    /// <summary>Whether the regex matches the value, without the prefilter or captures.</summary>
    internal bool RegexMatches(string value)
    {
        var input = matchesRunes ? RegexCache.CollapseUtf8(value) : value;
        return Regex.IsMatch(remapHighBytes ? RegexCache.RemapHighBytes(input) : input);
    }
}

internal sealed class PmOperator : IOperator
{
    private readonly AhoCorasick _matcher;

    // Vectorized search for the common case of ASCII patterns. No byte 0x80-0xFF case-folds to an ASCII letter, so
    // OrdinalIgnoreCase finds exactly what the ASCII-folding Aho-Corasick automaton finds.
    private readonly System.Buffers.SearchValues<string>? _any;

    public PmOperator(IEnumerable<string> patterns)
    {
        var list = patterns as IReadOnlyCollection<string> ?? [.. patterns];
        _matcher = new AhoCorasick(list);
        if (!_matcher.MatchesEmpty && list.Count > 0 && list.All(p => Ascii.IsValid(p)))
        {
            _any = System.Buffers.SearchValues.Create([.. list.Distinct(StringComparer.OrdinalIgnoreCase)], StringComparison.OrdinalIgnoreCase);
        }
    }

    public bool Evaluate(Transaction tx, string value)
    {
        if (value.Length < _matcher.MinLength)
        {
            return false;
        }

        if (_any is not null)
        {
            if (!value.AsSpan().ContainsAny(_any))
            {
                return false;
            }

            if (!tx.Capturing)
            {
                return true;
            }
        }
        else if (!tx.Capturing)
        {
            return _matcher.IsMatch(value);
        }

        var matches = _matcher.FindAll(value, 10, _any);
        for (var i = 0; i < matches.Count; i++)
        {
            tx.CaptureField(i, matches[i]);
        }

        return matches.Count > 0;
    }
}

internal sealed class DetectSqliOperator : IOperator
{
    public bool Evaluate(Transaction tx, string value)
    {
        if (!LibInjection.LibInjection.IsSqli(value, out var fingerprint))
        {
            return false;
        }

        tx.CaptureField(0, fingerprint);
        return true;
    }
}

internal sealed class DetectXssOperator : IOperator
{
    public bool Evaluate(Transaction tx, string value) => LibInjection.LibInjection.IsXss(value);
}

internal sealed class NumericOperator(Macro data, Func<long, long, bool> compare) : IOperator
{
    public bool Evaluate(Transaction tx, string value) =>
        compare(ParseInt(value), ParseInt(data.Expand(tx)));

    // Go's strconv.Atoi: invalid input yields 0.
    internal static long ParseInt(string s) =>
        long.TryParse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var v) ? v : 0;
}

internal sealed class StringOperator(Macro data, Func<string, string, bool> compare) : IOperator
{
    public bool Evaluate(Transaction tx, string value) => compare(value, data.Expand(tx));
}

internal sealed class ConstantOperator(bool result) : IOperator
{
    public bool Evaluate(Transaction tx, string value) => result;
}

internal sealed class ValidateByteRangeOperator(bool[] valid) : IOperator
{
    public static IOperator Create(string arguments)
    {
        if (string.IsNullOrWhiteSpace(arguments))
        {
            return new ConstantOperator(true);
        }

        var valid = new bool[256];
        foreach (var raw in arguments.Split(','))
        {
            var part = raw.Trim();
            var dash = part.IndexOf('-', StringComparison.Ordinal);
            var start = int.Parse(dash < 0 ? part : part[..dash], CultureInfo.InvariantCulture);
            var end = dash < 0 ? start : int.Parse(part[(dash + 1)..], CultureInfo.InvariantCulture);
            if (start is < 0 or > 255 || end is < 0 or > 255)
            {
                throw new FormatException($"invalid byte range '{part}'");
            }

            for (var b = start; b <= end; b++)
            {
                valid[b] = true;
            }
        }

        return new ValidateByteRangeOperator(valid);
    }

    public bool Evaluate(Transaction tx, string value)
    {
        foreach (var c in value)
        {
            if (c > 0xff || !valid[c])
            {
                return true;
            }
        }

        return false;
    }
}

internal sealed class ValidateUrlEncodingOperator : IOperator
{
    public bool Evaluate(Transaction tx, string value)
    {
        var i = 0;
        while (i < value.Length)
        {
            if (value[i] != '%')
            {
                i++;
                continue;
            }

            if (i + 2 >= value.Length || !ByteString.IsHex(value[i + 1]) || !ByteString.IsHex(value[i + 2]))
            {
                return true;
            }

            i += 3;
        }

        return false;
    }
}

internal sealed class ValidateUtf8EncodingOperator : IOperator
{
    public bool Evaluate(Transaction tx, string value)
    {
        foreach (var c in value)
        {
            if (c >= 0x80)
            {
                return !System.Text.Unicode.Utf8.IsValid(ByteString.ToBytes(value));
            }
        }

        return false;
    }
}

internal sealed class IpMatchOperator : IOperator
{
    private readonly List<IPNetwork> _networks = [];

    public IpMatchOperator(IEnumerable<string> entries)
    {
        foreach (var raw in entries)
        {
            var entry = raw.Trim();
            if (entry.Length == 0)
            {
                continue;
            }

            if (!entry.Contains('/', StringComparison.Ordinal))
            {
                entry += entry.Contains(':', StringComparison.Ordinal) ? "/128" : "/32";
            }

            if (IPNetwork.TryParse(entry, out var network))
            {
                _networks.Add(network);
            }
            else if (TryParseLenientCidr(entry, out network))
            {
                _networks.Add(network);
            }
        }
    }

    public bool Evaluate(Transaction tx, string value)
    {
        if (!IPAddress.TryParse(value, out var ip))
        {
            return false;
        }

        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        foreach (var n in _networks)
        {
            if (n.Contains(ip))
            {
                return true;
            }
        }

        return false;
    }

    // Go's net.ParseCIDR masks host bits (10.0.0.1/8 is valid); IPNetwork.TryParse rejects them.
    private static bool TryParseLenientCidr(string entry, out IPNetwork network)
    {
        network = default;
        var slash = entry.IndexOf('/', StringComparison.Ordinal);
        if (!IPAddress.TryParse(entry[..slash], out var address)
            || !int.TryParse(entry[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix))
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        var max = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix > max)
        {
            return false;
        }

        for (var i = 0; i < bytes.Length; i++)
        {
            var bits = Math.Clamp(prefix - (i * 8), 0, 8);
            bytes[i] &= (byte)(0xff << (8 - bits));
        }

        network = new IPNetwork(new IPAddress(bytes), prefix);
        return true;
    }
}
