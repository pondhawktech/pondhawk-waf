// Differential fuzzer for the libinjection port (#21).
//
// Sends the same bytes to Pondhawk.Waf.LibInjection and to libinjection-go (the oracle in oracle/, pinned in
// oracle/go.mod) and compares IsSQLi, the fingerprint and IsXSS. Every difference is minimized and reported.
//
// Phases:
//   1. Sweep: every SQLi keyword, XSS tag, event and attribute from the port's tables, in fixed templates.
//   2. Fuzz: mutated test vectors, keyword soups and random bytes, from a seeded random generator.
//   3. Unicode: fuzz inputs with chars above U+00FF, which the port encodes as UTF-8 (Go gets the same bytes).
//
// Usage: tests/Pondhawk.Waf.LibInjection.Fuzz/run.sh [--count N] [--seed N] [--max-len N] [--report file]
// Exit code: 0 no difference, 1 differences or exceptions, 2 usage or oracle error.

using System.Diagnostics;
using System.Globalization;
using System.Text;
using Pondhawk.Waf.LibInjection;

namespace Pondhawk.Waf.LibInjection.Fuzz;

internal static class Program
{
    private const int BatchSize = 2000;

    private static int Main(string[] args)
    {
        string? oraclePath = null;
        string? reportPath = null;
        long count = 1_000_000;
        int seed = Environment.TickCount;
        int maxLen = 512;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--oracle": oraclePath = args[++i]; break;
                case "--report": reportPath = args[++i]; break;
                case "--count": count = long.Parse(args[++i], CultureInfo.InvariantCulture); break;
                case "--seed": seed = int.Parse(args[++i], CultureInfo.InvariantCulture); break;
                case "--max-len": maxLen = int.Parse(args[++i], CultureInfo.InvariantCulture); break;
                default:
                    Console.Error.WriteLine($"Unknown argument {args[i]}");
                    return 2;
            }
        }

        if (oraclePath is null || !File.Exists(oraclePath))
        {
            Console.Error.WriteLine("--oracle <path to libinjection-oracle> is required (run.sh builds it).");
            return 2;
        }

        using var oracle = new Oracle(oraclePath);
        var findings = new Findings(oracle);
        var stopwatch = Stopwatch.StartNew();

        var sweep = Corpus.Sweep().ToList();
        foreach (var batch in sweep.Chunk(BatchSize))
        {
            findings.Check(batch.Select(Latin1).ToList());
        }

        Console.WriteLine($"Sweep: {sweep.Count:N0} inputs, {findings.Total:N0} differences");

        var generator = new Generator(seed, Corpus.Seeds(), maxLen);
        long done = 0;
        while (done < count)
        {
            var batch = new string[(int)Math.Min(BatchSize, count - done)];
            for (int i = 0; i < batch.Length; i++)
            {
                batch[i] = Latin1(generator.Next());
            }

            findings.Check(batch);
            done += batch.Length;
            if (done % 200_000 < BatchSize)
            {
                Console.WriteLine($"  {done:N0} / {count:N0} fuzzed, {findings.Total:N0} differences, {stopwatch.Elapsed:mm\\:ss}");
            }
        }

        var unicode = Corpus.UnicodeSweep().ToList();
        long unicodeCount = Math.Max(1, count / 10);
        for (long u = 0; u < unicodeCount; u += BatchSize)
        {
            var batch = new string[(int)Math.Min(BatchSize, unicodeCount - u)];
            for (int i = 0; i < batch.Length; i++)
            {
                batch[i] = generator.NextUnicode();
            }

            unicode.AddRange(batch);
        }

        foreach (var batch in unicode.Chunk(BatchSize))
        {
            findings.Check(batch);
        }

        Console.WriteLine($"Unicode: {unicode.Count:N0} inputs, {findings.Total:N0} differences in total");

        var report = findings.Report(seed, sweep.Count, count, unicode.Count, stopwatch.Elapsed);
        Console.WriteLine();
        Console.WriteLine(report);
        if (reportPath is not null)
        {
            File.WriteAllText(reportPath, report);
        }

        return findings.Total == 0 ? 0 : 1;
    }

    private static string Latin1(byte[] bytes) => Encoding.Latin1.GetString(bytes);
}

/// <summary>The result of both checks for one input. Fingerprint "-" when there is none.</summary>
internal readonly record struct Verdict(bool Sqli, string Fingerprint, bool Xss, string? Exception = null)
{
    public override string ToString() => Exception is not null
        ? $"exception {Exception}"
        : $"sqli={(Sqli ? 1 : 0)} fp={Fingerprint} xss={(Xss ? 1 : 0)}";

    public static Verdict Local(string text, out long ticks)
    {
        long start = Stopwatch.GetTimestamp();
        try
        {
            bool sqli = LibInjection.IsSqli(text, out var fingerprint);
            bool xss = LibInjection.IsXss(text);
            ticks = Stopwatch.GetTimestamp() - start;
            return new Verdict(sqli, fingerprint.Length == 0 ? "-" : fingerprint, xss);
        }
#pragma warning disable CA1031 // A crash is a finding, not a harness failure.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            ticks = Stopwatch.GetTimestamp() - start;
            return new Verdict(false, "-", false, ex.GetType().Name + ": " + ex.Message);
        }
    }

    /// <summary>What differs: "exception", "go-panic", "sqli", "fingerprint", "xss", or null when nothing does.</summary>
    public static string? Difference(Verdict local, Verdict go) =>
        local.Exception is not null ? "exception"
        : go.Exception is not null ? "go-panic"
        : local.Sqli != go.Sqli ? "sqli"
        : local.Fingerprint != go.Fingerprint ? "fingerprint"
        : local.Xss != go.Xss ? "xss"
        : null;
}

/// <summary>libinjection-go in a child process: one hex line in, one verdict line out.</summary>
internal sealed class Oracle : IDisposable
{
    private readonly Process _process;

    public Oracle(string path)
    {
        _process = Process.Start(new ProcessStartInfo(path)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        }) ?? throw new InvalidOperationException("Cannot start the oracle.");
        _process.StandardInput.AutoFlush = false;
    }

    /// <summary>
    /// The bytes Go gets for <paramref name="input"/>: chars up to U+00FF are one byte each (a byte string), other
    /// chars are their UTF-8 bytes. Computed here, not with the port's own conversion, so that a mistake there shows.
    /// </summary>
    public static byte[] Bytes(string input)
    {
        var bytes = new List<byte>(input.Length);
        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];
            if (c <= '\u00FF')
            {
                bytes.Add((byte)c);
            }
            else
            {
                int n = char.IsHighSurrogate(c) && i + 1 < input.Length && char.IsLowSurrogate(input[i + 1]) ? 2 : 1;
                bytes.AddRange(Encoding.UTF8.GetBytes(input.Substring(i, n))); // a lone surrogate gives EF BF BD
                i += n - 1;
            }
        }

        return [.. bytes];
    }

    public Verdict[] Query(IReadOnlyList<string> inputs)
    {
        // Output is about 10 bytes per input, so a batch fits the pipe buffer: write all, then read all.
        foreach (var input in inputs)
        {
            _process.StandardInput.WriteLine(Convert.ToHexString(Bytes(input)));
        }

        _process.StandardInput.Flush();
        var verdicts = new Verdict[inputs.Count];
        for (int i = 0; i < verdicts.Length; i++)
        {
            var line = _process.StandardOutput.ReadLine() ?? throw new InvalidOperationException("The oracle exited.");
            if (line == "panic")
            {
                verdicts[i] = new Verdict(false, "-", false, "Go panic");
                continue;
            }

            var parts = line.Split(' ');
            verdicts[i] = new Verdict(parts[0] == "1", parts[1], parts[2] == "1");
        }

        return verdicts;
    }

    public Verdict Query(string input) => Query([input])[0];

    public void Dispose()
    {
        _process.StandardInput.Close();
        _process.WaitForExit(5000);
        _process.Dispose();
    }
}

/// <summary>Collects differences, minimizes the first ones of each kind, and tracks the slowest inputs.</summary>
internal sealed class Findings(Oracle oracle)
{
    private const int MaxReportedPerKind = 15;

    private readonly Dictionary<string, long> _counts = [];
    private readonly Dictionary<string, List<(string Original, string Minimal, Verdict Local, Verdict Go)>> _examples = [];
    private readonly HashSet<string> _seen = [];
    private readonly List<(double MicrosPerByte, double Micros, int Length, string Input)> _slowest = [];
    private long _checked;
    private long _totalTicks;
    private long _totalBytes;

    public long Total => _counts.Values.Sum();

    public void Check(IReadOnlyList<string> inputs)
    {
        var go = oracle.Query(inputs);
        for (int i = 0; i < inputs.Count; i++)
        {
            var local = Verdict.Local(inputs[i], out long ticks);
            Track(inputs[i], ticks);
            if (Verdict.Difference(local, go[i]) is { } kind)
            {
                Record(kind, inputs[i], local, go[i]);
            }
        }
    }

    private void Track(string input, long ticks)
    {
        _checked++;
        _totalTicks += ticks;
        _totalBytes += input.Length;
        if (input.Length < 16)
        {
            return;
        }

        double micros = ticks * 1_000_000.0 / Stopwatch.Frequency;
        double perByte = micros / input.Length;
        if (_slowest.Count < 5 || perByte > _slowest[^1].MicrosPerByte)
        {
            _slowest.Add((perByte, micros, input.Length, input));
            _slowest.Sort((a, b) => b.MicrosPerByte.CompareTo(a.MicrosPerByte));
            if (_slowest.Count > 5)
            {
                _slowest.RemoveAt(5);
            }
        }
    }

    private void Record(string kind, string input, Verdict local, Verdict go)
    {
        _counts[kind] = _counts.GetValueOrDefault(kind) + 1;
        var examples = _examples.TryGetValue(kind, out var list) ? list : _examples[kind] = [];
        if (examples.Count >= MaxReportedPerKind)
        {
            return;
        }

        var minimal = Minimize(input, kind);
        if (!_seen.Add(kind + minimal))
        {
            return;
        }

        examples.Add((input, minimal, Verdict.Local(minimal, out _), oracle.Query(minimal)));
    }

    /// <summary>Removes chunks, then single chars, while the same kind of difference remains.</summary>
    private string Minimize(string input, string kind)
    {
        var current = input;
        for (int chunk = Math.Max(1, current.Length / 2); chunk >= 1; chunk /= 2)
        {
            bool progress = true;
            while (progress)
            {
                progress = false;
                for (int start = 0; start + chunk <= current.Length; start += chunk)
                {
                    var candidate = current.Remove(start, chunk);
                    if (Verdict.Difference(Verdict.Local(candidate, out _), oracle.Query(candidate)) == kind)
                    {
                        current = candidate;
                        progress = true;
                        break;
                    }
                }
            }
        }

        return current;
    }

    public string Report(int seed, int swept, long fuzzed, int unicode, TimeSpan elapsed)
    {
        var sb = new StringBuilder();
        var ci = CultureInfo.InvariantCulture;
        sb.AppendLine(ci, $"libinjection differential fuzz: seed {seed}, {swept:N0} sweep + {fuzzed:N0} fuzzed + {unicode:N0} Unicode inputs, {elapsed:hh\\:mm\\:ss}");
        sb.AppendLine(ci, $"Mean C# time: {_totalTicks * 1_000_000.0 / Stopwatch.Frequency / _checked:F2} µs per input, {_totalBytes / (double)_checked:F0} chars mean length");
        sb.AppendLine();
        if (Total == 0)
        {
            sb.AppendLine("No differences.");
        }
        else
        {
            foreach (var (kind, n) in _counts.OrderBy(k => k.Key, StringComparer.Ordinal))
            {
                sb.AppendLine(ci, $"## {kind}: {n:N0} inputs");
                foreach (var (original, minimal, local, go) in _examples[kind])
                {
                    sb.AppendLine(ci, $"- minimal {Show(minimal)}");
                    sb.AppendLine(ci, $"    bytes  {Convert.ToHexString(Oracle.Bytes(minimal))}");
                    sb.AppendLine(ci, $"    C#     {local}");
                    sb.AppendLine(ci, $"    Go     {go}");
                    sb.AppendLine(ci, $"    from   {Show(original.Length > 120 ? original[..120] : original)}{(original.Length > 120 ? "..." : "")}");
                }

                sb.AppendLine();
            }
        }

        // One timing can be a GC pause or a context switch: report the best of 20 runs.
        sb.AppendLine("Slowest inputs (C#, 16 bytes or more; best of 20 runs):");
        foreach (var (_, _, length, input) in _slowest)
        {
            double best = double.MaxValue;
            for (int run = 0; run < 20; run++)
            {
                Verdict.Local(input, out long ticks);
                best = Math.Min(best, ticks * 1_000_000.0 / Stopwatch.Frequency);
            }

            sb.AppendLine(ci, $"- {best / length:F3} µs/byte, {best:F1} µs, {length} bytes: {Show(input.Length > 80 ? input[..80] : input)}");
        }

        return sb.ToString();
    }

    /// <summary>Printable ASCII as is; other chars as \xHH (up to U+00FF, one byte) or \uHHHH.</summary>
    internal static string Show(string input)
    {
        var sb = new StringBuilder("\"");
        foreach (char c in input)
        {
            if (c is >= ' ' and < '\u007F' and not '\\' and not '"')
            {
                sb.Append(c);
            }
            else
            {
                sb.Append(c <= '\u00FF' ? "\\x" + ((int)c).ToString("X2", CultureInfo.InvariantCulture) : "\\u" + ((int)c).ToString("X4", CultureInfo.InvariantCulture));
            }
        }

        return sb.Append('"').ToString();
    }
}

/// <summary>Seeds, the token dictionary and the sweep inputs.</summary>
internal static class Corpus
{
    /// <summary>Whitespace and separators libinjection treats specially, plus bytes at the edges of its tables.</summary>
    public static readonly byte[] SpecialBytes =
    [
        0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x7F, 0x80, 0xBF, 0xC0, 0xFF,
        (byte)'\'', (byte)'"', (byte)'`', (byte)'\\', (byte)'/', (byte)'*', (byte)'-', (byte)'#', (byte)'(', (byte)')',
        (byte)';', (byte)',', (byte)'.', (byte)'=', (byte)'<', (byte)'>', (byte)'!', (byte)'&', (byte)'|', (byte)'@',
        (byte)'$', (byte)'{', (byte)'}', (byte)'[', (byte)']', (byte)':', (byte)'?', (byte)'%', (byte)'+', (byte)'~',
        (byte)'^', (byte)'0', (byte)'1', (byte)'9', (byte)'e', (byte)'x', (byte)'b', (byte)'N', (byte)'q', (byte)'Q',
    ];

    private static readonly string[] Fragments =
    [
        // SQL
        "'", "\"", "`", "1", "-1", "0x41", "0b1", "1e1", "1.e", ".1", "$1", "$$", "$tag$", "@a", "@@version", "N'", "q'[",
        "Q'{", "e'", "x'41'", "b'1'", "--", "-- ", "#", "/*", "*/", "/*!", "/*!50000", "{", "}", "(", ")", ",", ";", "||",
        "&&", "!=", "<>", "<=>", ":=", "::", "\\N", "NULL", "UNION", "SELECT", "ALL", "FROM", "WHERE", "OR", "AND", "XOR",
        "NOT", "LIKE", "IN", "IS", "BETWEEN", "CASE", "WHEN", "THEN", "ELSE", "END", "ORDER BY", "GROUP BY", "HAVING",
        "LIMIT", "INTO", "OUTFILE", "SLEEP(5)", "BENCHMARK(", "WAITFOR DELAY '0:0:5'", "EXEC", "xp_cmdshell", "DROP",
        "TABLE", "INSERT", "UPDATE", "DELETE", "CHAR(", "CONCAT(", "version()", "user()", "@@", "information_schema",
        "sysobjects", "1=1", "'1'='1", "' OR '", "\" OR \"", "') OR ('", "admin'--", "1;", "{fn", "{d '", "[a]", "a.b",
        "LOAD_FILE(", "IF(", "ASCII(", "SUBSTRING(", "COLLATE", "DIV", "MOD", "SOUNDS LIKE", "REGEXP", "RLIKE",
        // XSS
        "<", ">", "</", "/>", "<!--", "-->", "<!", "<?", "?>", "<![CDATA[", "]]>", "<script>", "</script>", "<img",
        "<svg", "<a", "<iframe", "<style>", "<x", " src=", " href=", " onerror=", " onload=", " style=", " xmlns=",
        " xlink:href=", " formaction=", " srcdoc=", "javascript:", "vbscript:", "data:", "jav&#x09;ascript:", "&#",
        "&#x", "&#106;", "&#x6A;", "&colon;", "&lt;", "=", "=\"", "='", "=`", "expression(", "url(", "alert(1)", "\t",
        "\n", "\r", "\f", "\v", "\0", " ",
    ];

    /// <summary>The input of every test vector file.</summary>
    public static List<byte[]> Seeds()
    {
        var seeds = new List<byte[]>();
        var dir = Path.Combine(AppContext.BaseDirectory, "Seeds");
        foreach (var file in Directory.GetFiles(dir, "test-*.txt").Order(StringComparer.Ordinal))
        {
            var bytes = File.ReadAllBytes(file);
            var text = Encoding.Latin1.GetString(bytes);
            int start = text.IndexOf("--INPUT--", StringComparison.Ordinal);
            int end = text.IndexOf("--EXPECTED--", StringComparison.Ordinal);
            if (start >= 0 && end > start)
            {
                var input = text[(start + "--INPUT--".Length)..end].Trim('\r', '\n');
                seeds.Add(Encoding.Latin1.GetBytes(input));
            }
        }

        foreach (var fragment in Fragments)
        {
            seeds.Add(Encoding.Latin1.GetBytes(fragment));
        }

        return seeds;
    }

    /// <summary>Dictionary tokens for mutations: fragments, SQLi keywords and XSS names.</summary>
    public static List<byte[]> Tokens()
    {
        var tokens = Fragments.Select(f => Encoding.Latin1.GetBytes(f)).ToList();
        tokens.AddRange(Keywords().Where(k => !k.StartsWith('0')).Select(k => Encoding.Latin1.GetBytes(k)));
        tokens.AddRange(XssData.BlackTags.Select(t => Encoding.Latin1.GetBytes("<" + t.ToLowerInvariant())));
        tokens.AddRange(XssData.BlackEvents.Select(e => Encoding.Latin1.GetBytes(" on" + e.Name.ToLowerInvariant() + "=")));
        tokens.AddRange(XssData.Blacks.Select(a => Encoding.Latin1.GetBytes(" " + a.Name.ToLowerInvariant() + "=")));
        return tokens;
    }

    private static IEnumerable<string> Keywords() =>
        SqliData.KeywordGroups.SelectMany(g => g.Keys.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));

    /// <summary>Every keyword, tag, event and attribute in fixed templates, in both cases.</summary>
    public static IEnumerable<byte[]> Sweep()
    {
        string[] sqlTemplates = ["{0}", "1 {0}", "1 {0} 1", "1' {0} '1", "1) {0} (1", "{0}(1)", "1 {0}--", "'{0}'", "1 {0} SELECT 1"];
        foreach (var keyword in Keywords())
        {
            if (keyword.StartsWith('0'))
            {
                continue; // fingerprints, not text
            }

            foreach (var template in sqlTemplates)
            {
                yield return Bytes(string.Format(CultureInfo.InvariantCulture, template, keyword));
                yield return Bytes(string.Format(CultureInfo.InvariantCulture, template, keyword.ToLowerInvariant()));
            }
        }

        string[] tagTemplates = ["<{0}>", "<{0} ", "</{0}>", "<{0}/x>", "<{0}\tsrc=x>"];
        foreach (var tag in XssData.BlackTags.Append("A").Append("IMG").Append("SVG"))
        {
            foreach (var template in tagTemplates)
            {
                yield return Bytes(string.Format(CultureInfo.InvariantCulture, template, tag));
                yield return Bytes(string.Format(CultureInfo.InvariantCulture, template, tag.ToLowerInvariant()));
            }
        }

        string[] attrTemplates = ["<a {0}=x>", "<a {0}='x'>", "<a {0}=\"javascript:x\">", "<a/{0}=x>", "x {0}=x", "<a {0}>"];
        var names = XssData.BlackEvents.Select(e => "ON" + e.Name).Concat(XssData.Blacks.Select(a => a.Name));
        foreach (var name in names)
        {
            foreach (var template in attrTemplates)
            {
                yield return Bytes(string.Format(CultureInfo.InvariantCulture, template, name));
                yield return Bytes(string.Format(CultureInfo.InvariantCulture, template, name.ToLowerInvariant()));
            }
        }

        // Every single byte and every pair of special bytes.
        for (int b = 0; b < 256; b++)
        {
            yield return [(byte)b];
        }

        foreach (var a in Corpus.SpecialBytes)
        {
            foreach (var b in Corpus.SpecialBytes)
            {
                yield return [a, b];
                yield return [(byte)'1', a, b, (byte)'1'];
            }
        }
    }

    private static byte[] Bytes(string s) => Encoding.Latin1.GetBytes(s);

    /// <summary>Chars above U+00FF that Go's case mapping or UTF-8 handling could treat specially.</summary>
    public static readonly string[] UnicodeChars =
    [
        "\u0131", "\u017F", "\u0130", "\u212A", "\u212B", "\u0100", "\u01C5", "\u1E9E", "\u2028", "\u3000", "\uFEFF",
        "\uFF1C", "\uFF07", "\uFFFD", "\uD83D\uDE00", "\uD83D", "\uDE00", "\u00A0", "\u00E9",
    ];

    /// <summary>Every keyword with each I or S replaced by U+0131 or U+017F (Go uppercases them to I and S).</summary>
    public static IEnumerable<string> UnicodeSweep()
    {
        foreach (var keyword in Keywords().Where(k => !k.StartsWith('0')))
        {
            var lower = keyword.ToLowerInvariant();
            if (!lower.Contains('i', StringComparison.Ordinal) && !lower.Contains('s', StringComparison.Ordinal))
            {
                continue;
            }

            var all = lower.Replace('i', '\u0131').Replace('s', '\u017F');
            foreach (var word in new[] { all, ReplaceFirst(lower, 'i', '\u0131'), ReplaceFirst(lower, 's', '\u017F') })
            {
                yield return word;
                yield return "1 " + word + " 1";
                yield return "1' " + word + " '1";
                yield return word + "(1)";
            }
        }
    }

    private static string ReplaceFirst(string s, char from, char to)
    {
        int i = s.IndexOf(from, StringComparison.Ordinal);
        return i < 0 ? s : string.Concat(s.AsSpan(0, i), to.ToString(), s.AsSpan(i + 1));
    }
}

/// <summary>Seeded input generator: mutations of seeds, token soups and random bytes.</summary>
internal sealed class Generator(int seed, List<byte[]> seeds, int maxLen)
{
    private readonly Random _random = new(seed);
    private readonly List<byte[]> _tokens = Corpus.Tokens();

    public byte[] Next()
    {
        var input = _random.Next(10) switch
        {
            < 5 => Mutate(Pick(seeds).ToList(), 1 + _random.Next(8)),
            < 8 => Mutate(Soup(), _random.Next(3)),
            8 => RandomBytes(),
            _ => Long(),
        };
        return input.Count > maxLen && _random.Next(10) != 0 ? [.. input.Take(maxLen)] : [.. input];
    }

    /// <summary>A fuzz input with one to four chars above U+00FF inserted or replaced.</summary>
    public string NextUnicode()
    {
        var sb = new StringBuilder(Encoding.Latin1.GetString(Next()));
        int n = 1 + _random.Next(4);
        for (int i = 0; i < n; i++)
        {
            var u = _random.Next(4) == 0
                ? char.ConvertFromUtf32(_random.Next(0x100, 0xD800))
                : Pick(Corpus.UnicodeChars);
            int pos = _random.Next(sb.Length + 1);
            if (pos < sb.Length && _random.Next(2) == 0)
            {
                sb.Remove(pos, 1);
            }

            sb.Insert(pos, u);
        }

        return sb.ToString();
    }

    private List<byte> Soup()
    {
        var soup = new List<byte>();
        int n = 1 + _random.Next(12);
        for (int i = 0; i < n; i++)
        {
            soup.AddRange(Pick(_tokens));
            if (_random.Next(3) == 0)
            {
                soup.Add(Pick(Corpus.SpecialBytes));
            }
            else if (_random.Next(2) == 0)
            {
                soup.Add((byte)' ');
            }
        }

        return soup;
    }

    private List<byte> RandomBytes()
    {
        var bytes = new List<byte>();
        int n = _random.Next(48);
        for (int i = 0; i < n; i++)
        {
            bytes.Add(_random.Next(3) == 0 ? (byte)_random.Next(256) : Pick(Corpus.SpecialBytes));
        }

        return bytes;
    }

    /// <summary>A fragment repeated up to a few KB: token-count limits, folding and long strings or comments.</summary>
    private List<byte> Long()
    {
        var unit = _random.Next(2) == 0 ? Pick(seeds).ToList() : Soup();
        if (unit.Count == 0)
        {
            unit.Add((byte)'(');
        }

        var bytes = new List<byte>();
        int target = 256 + _random.Next(4096);
        while (bytes.Count < target)
        {
            bytes.AddRange(unit);
        }

        return Mutate(bytes, _random.Next(3));
    }

    private List<byte> Mutate(List<byte> b, int times)
    {
        for (int t = 0; t < times; t++)
        {
            int pos = b.Count == 0 ? 0 : _random.Next(b.Count + 1);
            switch (_random.Next(9))
            {
                case 0 when b.Count > 0 && pos < b.Count:
                    b[pos] = (byte)_random.Next(256);
                    break;
                case 1:
                    b.Insert(pos, Pick(Corpus.SpecialBytes));
                    break;
                case 2:
                    b.InsertRange(pos, Pick(_tokens));
                    break;
                case 3 when b.Count > 0:
                    int len = 1 + _random.Next(Math.Min(8, b.Count));
                    int start = _random.Next(b.Count - len + 1);
                    b.RemoveRange(start, len);
                    break;
                case 4 when b.Count > 1:
                    int dl = 1 + _random.Next(Math.Min(16, b.Count));
                    int ds = _random.Next(b.Count - dl + 1);
                    b.InsertRange(pos, b.GetRange(ds, dl));
                    break;
                case 5:
                    var other = Pick(seeds);
                    int cut = _random.Next(other.Length + 1);
                    b.InsertRange(pos, other[..cut]);
                    break;
                case 6 when b.Count > 0 && pos < b.Count:
                    byte c = b[pos];
                    b[pos] = c is >= (byte)'a' and <= (byte)'z' ? (byte)(c - 32) : c is >= (byte)'A' and <= (byte)'Z' ? (byte)(c + 32) : c;
                    break;
                case 7 when b.Count > 0 && pos < b.Count:
                    b[pos] = Pick(Corpus.SpecialBytes);
                    break;
                default:
                    b.Insert(pos, (byte)_random.Next(256));
                    break;
            }
        }

        return b;
    }

    private T Pick<T>(IReadOnlyList<T> items) => items[_random.Next(items.Count)];
}
