using System.Buffers;
using System.Text;

namespace Pondhawk.Waf.Operators;

/// <summary>
/// A cheap necessary condition for an @rx pattern, as Coraza's SecRxPreFilter: the minimum length of a match and
/// literals that every match contains. Most values of benign traffic fail it, and a vectorized substring search costs a
/// fraction of a regex scan.
/// </summary>
/// <remarks>
/// <para>
/// Safe by construction: the prefilter only answers "cannot match" when a required literal is absent or the value is
/// too short. Literals are taken only from parts of the pattern that every match must pass through (not from optional,
/// starred or alternated-away parts). Anything the analyzer does not fully understand (lookarounds, backreferences,
/// \Q..\E, extended mode, unknown escapes) yields no prefilter, and the regex runs as before.
/// </para>
/// <para>
/// Literals are ASCII only. A case-insensitive pattern ((?i) anywhere) makes every literal case-insensitive, which is a
/// weaker condition and so still safe. No char 0x80-0xFF case-folds to ASCII, so the ASCII literal search gives the same
/// answer before and after the high-byte remapping of patterns with \b.
/// </para>
/// </remarks>
internal sealed class RegexPrefilter
{
    // At most this many alternatives per required set; more make the set search slow and rarely reject.
    private const int MaxSetSize = 64;

    // Required sets checked per value, most selective first.
    private const int MaxSets = 3;

    // A literal shorter than this rejects too little to pay for the search.
    private const int MinLiteralLength = 2;

    private readonly SearchValues<string>[] _sets;

    private RegexPrefilter(int minLength, SearchValues<string>[] sets, string[][] literals)
    {
        MinLength = minLength;
        _sets = sets;
        Literals = literals;
    }

    /// <summary>The shortest value the pattern can match.</summary>
    public int MinLength { get; }

    /// <summary>The required sets: each match contains at least one string of every set.</summary>
    public IReadOnlyList<IReadOnlyList<string>> Literals { get; }

    /// <summary>False when the pattern cannot match the value; true when it might.</summary>
    public bool MightMatch(string value)
    {
        if (value.Length < MinLength)
        {
            return false;
        }

        var span = value.AsSpan();
        foreach (var set in _sets)
        {
            if (!span.ContainsAny(set))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Analyzes a SecLang (RE2/PCRE syntax) pattern. Null when no useful prefilter exists.</summary>
    public static RegexPrefilter? Create(string pattern)
    {
        Node node;
        bool ignoreCase;
        try
        {
            var parser = new Parser(pattern);
            node = parser.ParseAll();
            ignoreCase = parser.UsedIgnoreCase;
        }
        catch (UnsupportedPatternException)
        {
            return null;
        }

        // A pattern that is one fixed string requires that string.
        List<List<string>> required = node.Exact is { Length: > 0 } exact ? [[exact], .. node.Required] : node.Required;
        var sets = required
            .Select(set => set.Distinct(ignoreCase ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal).ToArray())
            .Where(set => set.Length is > 0 and <= MaxSetSize && set.All(s => s.Length >= MinLiteralLength))
            .OrderByDescending(set => set.Min(s => s.Length))
            .ThenBy(set => set.Length)
            .Take(MaxSets)
            .ToArray();

        if (sets.Length == 0 && node.MinLength < 4)
        {
            return null;
        }

        var comparison = ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return new RegexPrefilter(
            node.MinLength,
            [.. sets.Select(set => SearchValues.Create(set, comparison))],
            sets);
    }

    private sealed class UnsupportedPatternException : Exception;

    /// <summary>What every match of a sub-pattern has in common.</summary>
    /// <param name="MinLength">Shortest match, in chars (capped).</param>
    /// <param name="Exact">The only string it matches, when it is a fixed ASCII string; otherwise null.</param>
    /// <param name="Required">Sets of strings: every match contains at least one string of each set.</param>
    private sealed record Node(int MinLength, string? Exact, List<List<string>> Required)
    {
        public static Node Empty() => new(0, string.Empty, []);

        public static Node AnyChar() => new(1, null, []);

        public static Node Optional() => new(0, null, []);
    }

    private sealed class Parser(string pattern)
    {
        private const int Cap = 1 << 20;
        private const int MaxExact = 256;

        private int _pos;
        private bool _ignoreCase;

        public bool UsedIgnoreCase { get; private set; }

        public Node ParseAll()
        {
            var node = ParseAlternation();
            if (_pos != pattern.Length)
            {
                throw new UnsupportedPatternException(); // An unbalanced ')'.
            }

            return node;
        }

        private Node ParseAlternation()
        {
            var saved = _ignoreCase;
            var branches = new List<Node> { ParseSequence() };
            while (_pos < pattern.Length && pattern[_pos] == '|')
            {
                _pos++;
                branches.Add(ParseSequence());
            }

            _ignoreCase = saved;
            return branches.Count == 1 ? branches[0] : Alternate(branches);
        }

        private Node ParseSequence()
        {
            var parts = new List<Node>();
            while (_pos < pattern.Length && pattern[_pos] is not ('|' or ')'))
            {
                var atom = ParseAtom();
                if (atom is null)
                {
                    continue; // A flag group such as (?i).
                }

                parts.Add(ParseQuantifier(atom));
            }

            return Concat(parts);
        }

        private Node? ParseAtom()
        {
            var c = pattern[_pos++];
            switch (c)
            {
                case '(':
                    return ParseGroup();
                case '[':
                    SkipClass();
                    return Node.AnyChar();
                case '.':
                    return Node.AnyChar();
                case '^' or '$':
                    return Node.Empty() with { Exact = null };
                case '\\':
                    return ParseEscape();
                case '*' or '+' or '?' or '{':
                    throw new UnsupportedPatternException(); // A quantifier with nothing to repeat, or a literal '{'.
                default:
                    return Literal(c);
            }
        }

        private Node Literal(char c)
        {
            if (c >= 0x80)
            {
                return Node.AnyChar();
            }

            if (_ignoreCase && char.IsAsciiLetter(c))
            {
                UsedIgnoreCase = true;
            }

            return new Node(1, c.ToString(), []);
        }

        private Node? ParseGroup()
        {
            if (_pos < pattern.Length && pattern[_pos] == '?')
            {
                _pos++;
                if (_pos >= pattern.Length)
                {
                    throw new UnsupportedPatternException();
                }

                var c = pattern[_pos];
                if (c == ':')
                {
                    _pos++;
                    return GroupBody(_ignoreCase);
                }

                if (c == 'P' && _pos + 1 < pattern.Length && pattern[_pos + 1] == '<')
                {
                    _pos++;
                    SkipName();
                    return GroupBody(_ignoreCase);
                }

                if (c == '<' && _pos + 1 < pattern.Length && char.IsAsciiLetter(pattern[_pos + 1]))
                {
                    SkipName();
                    return GroupBody(_ignoreCase);
                }

                // Flags: (?i) (?s) (?m) (?-i) (?i:...) ... Anything else (lookarounds, atomic groups, conditionals,
                // comments, extended mode) is not analyzed.
                var on = true;
                var ignoreCase = _ignoreCase;
                while (_pos < pattern.Length && pattern[_pos] is 'i' or 's' or 'm' or 'U' or '-')
                {
                    switch (pattern[_pos])
                    {
                        case '-':
                            on = false;
                            break;
                        case 'i':
                            ignoreCase = on;
                            break;
                        case 'U':
                            break; // Ungreedy: does not change what can match.
                    }

                    _pos++;
                }

                if (_pos >= pattern.Length)
                {
                    throw new UnsupportedPatternException();
                }

                if (pattern[_pos] == ')')
                {
                    _pos++;
                    _ignoreCase = ignoreCase; // Applies to the rest of the enclosing group.
                    return null;
                }

                if (pattern[_pos] == ':')
                {
                    _pos++;
                    return GroupBody(ignoreCase);
                }

                throw new UnsupportedPatternException();
            }

            return GroupBody(_ignoreCase);
        }

        private Node GroupBody(bool ignoreCase)
        {
            var saved = _ignoreCase;
            _ignoreCase = ignoreCase;
            var node = ParseAlternation();
            _ignoreCase = saved;
            if (_pos >= pattern.Length || pattern[_pos] != ')')
            {
                throw new UnsupportedPatternException();
            }

            _pos++;
            return node;
        }

        private void SkipName()
        {
            // At '<': skip to after '>'.
            var close = pattern.IndexOf('>', _pos);
            if (close < 0)
            {
                throw new UnsupportedPatternException();
            }

            _pos = close + 1;
        }

        // After '[': skips to after the closing ']'. A ']' first (or after '^') is a literal; "[:name:]" is a POSIX
        // class; escapes skip the next char.
        private void SkipClass()
        {
            if (_pos < pattern.Length && pattern[_pos] == '^')
            {
                _pos++;
            }

            if (_pos < pattern.Length && pattern[_pos] == ']')
            {
                _pos++;
            }

            while (_pos < pattern.Length)
            {
                var c = pattern[_pos];
                if (c == '\\')
                {
                    _pos += 2;
                    continue;
                }

                if (c == '[' && _pos + 1 < pattern.Length && pattern[_pos + 1] == ':')
                {
                    var end = pattern.IndexOf(":]", _pos + 2, StringComparison.Ordinal);
                    if (end < 0)
                    {
                        throw new UnsupportedPatternException();
                    }

                    _pos = end + 2;
                    continue;
                }

                _pos++;
                if (c == ']')
                {
                    return;
                }
            }

            throw new UnsupportedPatternException();
        }

        private Node ParseEscape()
        {
            if (_pos >= pattern.Length)
            {
                throw new UnsupportedPatternException();
            }

            var c = pattern[_pos++];
            switch (c)
            {
                case 'd' or 'D' or 'w' or 'W' or 's' or 'S' or 'h' or 'H' or 'N':
                    return Node.AnyChar();
                case 'b' or 'B' or 'A' or 'z' or 'Z' or 'G':
                    return Node.Empty() with { Exact = null };
                case 't' or 'n' or 'r' or 'f' or 'v' or 'a' or 'e':
                    return Node.AnyChar();
                case 'x':
                    return ParseHexEscape();
                default:
                    if (char.IsAsciiLetterOrDigit(c))
                    {
                        // Backreferences, octal, \p, \Q, \k, \c, \R, \X, ...
                        throw new UnsupportedPatternException();
                    }

                    return Literal(c);
            }
        }

        private Node ParseHexEscape()
        {
            int code;
            if (_pos < pattern.Length && pattern[_pos] == '{')
            {
                var close = pattern.IndexOf('}', _pos);
                if (close < 0 || !int.TryParse(pattern.AsSpan(_pos + 1, close - _pos - 1), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out code))
                {
                    throw new UnsupportedPatternException();
                }

                _pos = close + 1;
            }
            else if (_pos + 1 < pattern.Length && Text.ByteString.IsHex(pattern[_pos]) && Text.ByteString.IsHex(pattern[_pos + 1]))
            {
                code = (Text.ByteString.HexValue(pattern[_pos]) << 4) | Text.ByteString.HexValue(pattern[_pos + 1]);
                _pos += 2;
            }
            else
            {
                throw new UnsupportedPatternException();
            }

            // Printable ASCII becomes a literal; anything else is one unknown char.
            return code is >= 0x20 and < 0x7f ? Literal((char)code) : Node.AnyChar();
        }

        private Node ParseQuantifier(Node atom)
        {
            if (_pos >= pattern.Length)
            {
                return atom;
            }

            int min, max;
            switch (pattern[_pos])
            {
                case '*':
                    min = 0;
                    max = -1;
                    _pos++;
                    break;
                case '+':
                    min = 1;
                    max = -1;
                    _pos++;
                    break;
                case '?':
                    min = 0;
                    max = 1;
                    _pos++;
                    break;
                case '{':
                    (min, max) = ParseCounted();
                    break;
                default:
                    return atom;
            }

            // Lazy or possessive modifier.
            if (_pos < pattern.Length && pattern[_pos] is '?' or '+')
            {
                _pos++;
            }

            if (_pos < pattern.Length && pattern[_pos] is '*' or '+' or '?' or '{')
            {
                throw new UnsupportedPatternException(); // A nested quantifier.
            }

            if (min == 0)
            {
                return Node.Optional();
            }

            // x{n,m} matches n to m copies of x, so it contains n copies.
            var repeated = atom.Exact is { Length: > 0 } && (long)atom.Exact.Length * min <= MaxExact
                ? string.Concat(Enumerable.Repeat(atom.Exact, min))
                : null;
            var minLength = (int)Math.Min(Cap, (long)atom.MinLength * min);
            if (min == max && repeated is not null)
            {
                return new Node(minLength, repeated, []);
            }

            return new Node(minLength, null, repeated is not null ? [[repeated], .. atom.Required] : atom.Required);
        }

        // At '{': {n}, {n,} or {n,m}. Anything else is not analyzed.
        private (int Min, int Max) ParseCounted()
        {
            var close = pattern.IndexOf('}', _pos);
            if (close < 0)
            {
                throw new UnsupportedPatternException();
            }

            var body = pattern.AsSpan(_pos + 1, close - _pos - 1);
            var comma = body.IndexOf(',');
            var ci = System.Globalization.CultureInfo.InvariantCulture;
            int min, max;
            if (comma < 0)
            {
                if (!int.TryParse(body, System.Globalization.NumberStyles.None, ci, out min))
                {
                    throw new UnsupportedPatternException();
                }

                max = min;
            }
            else
            {
                if (!int.TryParse(body[..comma], System.Globalization.NumberStyles.None, ci, out min))
                {
                    throw new UnsupportedPatternException();
                }

                var rest = body[(comma + 1)..];
                if (rest.IsEmpty)
                {
                    max = -1;
                }
                else if (!int.TryParse(rest, System.Globalization.NumberStyles.None, ci, out max) || max < min)
                {
                    throw new UnsupportedPatternException();
                }
            }

            _pos = close + 1;
            return (min, max);
        }

        private static Node Concat(List<Node> parts)
        {
            if (parts.Count == 0)
            {
                return Node.Empty();
            }

            if (parts.Count == 1)
            {
                return parts[0];
            }

            var required = new List<List<string>>();
            var run = new StringBuilder();
            var allExact = true;
            long minLength = 0;
            foreach (var part in parts)
            {
                minLength += part.MinLength;
                if (part.Exact is not null)
                {
                    run.Append(part.Exact);
                    continue;
                }

                allExact = false;
                if (run.Length > 0)
                {
                    required.Add([run.ToString()]);
                    run.Clear();
                }

                required.AddRange(part.Required);
            }

            var cappedLength = (int)Math.Min(Cap, minLength);
            if (allExact && run.Length <= MaxExact)
            {
                return new Node(cappedLength, run.ToString(), []);
            }

            if (run.Length > 0)
            {
                required.Add([run.ToString()]);
            }

            return new Node(cappedLength, null, required);
        }

        // Every match goes through one branch, so a set built from one required set of each branch is required.
        private static Node Alternate(List<Node> branches)
        {
            var minLength = branches.Min(b => b.MinLength);
            var union = new List<string>();
            foreach (var branch in branches)
            {
                var best = Best(branch);
                if (best is null)
                {
                    return new Node(minLength, null, []);
                }

                union.AddRange(best);
            }

            return new Node(minLength, null, union.Count <= MaxSetSize ? [union] : []);
        }

        // The most selective required set of a node: the one whose shortest string is longest.
        private static List<string>? Best(Node node)
        {
            if (node.Exact is { Length: > 0 } exact)
            {
                return [exact];
            }

            return node.Required
                .Where(set => set.Count > 0)
                .OrderByDescending(set => set.Min(s => s.Length))
                .ThenBy(set => set.Count)
                .FirstOrDefault();
        }
    }
}
