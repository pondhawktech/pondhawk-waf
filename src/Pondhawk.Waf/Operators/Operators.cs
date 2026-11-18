// Operator semantics follow OWASP Coraza (Apache-2.0).
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
            ["rx"] = o => new RxOperator(o.RegexCache.Get(o.Arguments)),
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

    private readonly Dictionary<string, Regex> _cache = new(StringComparer.Ordinal);

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

    /// <summary>Timeout for patterns that need the backtracking engine.</summary>
    public TimeSpan BacktrackingTimeout { get; init; } = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// Compiles a SecLang (RE2/PCRE syntax) pattern as Coraza does: with (?s) and (?m).
    /// </summary>
    public Regex Get(string pattern)
    {
        lock (_cache)
        {
            if (_cache.TryGetValue(pattern, out var cached))
            {
                return cached;
            }

            var regex = Compile(pattern, RegexOptions.Singleline | RegexOptions.Multiline);
            _cache[pattern] = regex;
            return regex;
        }
    }

    /// <summary>Compiles a pattern without the SecLang default flags (used for collection key selectors).</summary>
    public Regex GetPlain(string pattern)
    {
        var key = "\0plain\0" + pattern;
        lock (_cache)
        {
            if (_cache.TryGetValue(key, out var cached))
            {
                return cached;
            }

            var regex = Compile(pattern, RegexOptions.None);
            _cache[key] = regex;
            return regex;
        }
    }

    private Regex Compile(string pattern, RegexOptions extra)
    {
        var translated = TranslatePattern(pattern);
        var options = RegexOptions.CultureInvariant | extra;
        if (PreferNonBacktracking)
        {
            try
            {
                return new Regex(translated, options | RegexOptions.NonBacktracking);
            }
            catch (NotSupportedException)
            {
                // Lookarounds, backreferences or atomic groups: fall back to the backtracking engine with a timeout.
            }
        }

        return new Regex(translated, options | RegexOptions.Compiled, BacktrackingTimeout);
    }

    /// <summary>
    /// Translates RE2/PCRE syntax that .NET reads differently:
    /// <list type="bullet">
    /// <item>\x{HH} escapes (not supported by .NET);</item>
    /// <item>(?P&lt;name&gt;...) groups;</item>
    /// <item>escaped punctuation inside a character class, e.g. [\--9]: .NET does not accept an escaped character as a
    /// range start, so it is rewritten as \xHH;</item>
    /// <item>a bare '[' inside a class, which .NET can read as class subtraction ("-[").</item>
    /// </list>
    /// </summary>
    internal static string TranslatePattern(string pattern)
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
                        sb.Append(code <= 0xff ? $"\\x{code:x2}" : $"\\u{code:x4}");
                        i = close;
                        continue;
                    }
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
}

internal sealed class RxOperator(Regex regex) : IOperator
{
    public Regex Regex { get; } = regex;

    public bool Evaluate(Transaction tx, string value)
    {
        if (!tx.Capturing)
        {
            return Regex.IsMatch(value);
        }

        var match = Regex.Match(value);
        if (!match.Success)
        {
            return false;
        }

        for (var i = 0; i < match.Groups.Count && i < 9; i++)
        {
            var g = match.Groups[i];
            tx.CaptureField(i, g.Success ? g.Value : string.Empty);
        }

        return true;
    }
}

internal sealed class PmOperator(IEnumerable<string> patterns) : IOperator
{
    private readonly AhoCorasick _matcher = new(patterns);

    public bool Evaluate(Transaction tx, string value)
    {
        if (value.Length < _matcher.MinLength)
        {
            return false;
        }

        if (!tx.Capturing)
        {
            return _matcher.IsMatch(value);
        }

        var matches = _matcher.FindAll(value, 10);
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
