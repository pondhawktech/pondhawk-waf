namespace Pondhawk.Waf.Operators;

/// <summary>
/// ASCII case-insensitive multi-pattern matcher for @pm and @pmFromFile.
/// <see cref="IsMatch"/> runs in O(n) with failure links; <see cref="FindAll"/> returns leftmost-longest,
/// non-overlapping matches (used only when the rule captures).
/// </summary>
internal sealed class AhoCorasick
{
    private readonly List<Node> _nodes = [new Node()];

    public AhoCorasick(IEnumerable<string> patterns)
    {
        foreach (var p in patterns)
        {
            if (p.Length == 0)
            {
                MatchesEmpty = true;
                continue;
            }

            var node = 0;
            foreach (var raw in p)
            {
                var c = Fold(raw);
                if (!_nodes[node].Next.TryGetValue(c, out var next))
                {
                    next = _nodes.Count;
                    _nodes.Add(new Node { Depth = _nodes[node].Depth + 1 });
                    _nodes[node].Next[c] = next;
                }

                node = next;
            }

            _nodes[node].Terminal = true;
            _nodes[node].Output = true;
            MinLength = MinLength == 0 ? p.Length : Math.Min(MinLength, p.Length);
        }

        BuildFailureLinks();
    }

    public bool MatchesEmpty { get; }

    public int MinLength { get; }

    public bool IsMatch(string text)
    {
        if (MatchesEmpty)
        {
            return true;
        }

        var state = 0;
        foreach (var raw in text)
        {
            var c = Fold(raw);
            while (state != 0 && !_nodes[state].Next.ContainsKey(c))
            {
                state = _nodes[state].Fail;
            }

            if (_nodes[state].Next.TryGetValue(c, out var next))
            {
                state = next;
            }

            if (_nodes[state].Output)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Leftmost-longest, non-overlapping matches, up to <paramref name="max"/>. <paramref name="starts"/>, when given,
    /// finds the same patterns (ASCII case-insensitive) and skips ahead to the next position where one begins.
    /// </summary>
    public List<string> FindAll(string text, int max, System.Buffers.SearchValues<string>? starts = null)
    {
        var result = new List<string>();
        var i = 0;
        while (i < text.Length && result.Count < max)
        {
            if (starts is not null)
            {
                var next = text.AsSpan(i).IndexOfAny(starts);
                if (next < 0)
                {
                    break;
                }

                i += next;
            }

            var node = 0;
            var longest = 0;
            for (var j = i; j < text.Length; j++)
            {
                if (!_nodes[node].Next.TryGetValue(Fold(text[j]), out node))
                {
                    break;
                }

                if (_nodes[node].Terminal)
                {
                    longest = j - i + 1;
                }
            }

            if (longest > 0)
            {
                result.Add(text.Substring(i, longest));
                i += longest;
            }
            else
            {
                i++;
            }
        }

        return result;
    }

    private void BuildFailureLinks()
    {
        var queue = new Queue<int>();
        foreach (var child in _nodes[0].Next.Values)
        {
            _nodes[child].Fail = 0;
            queue.Enqueue(child);
        }

        while (queue.Count > 0)
        {
            var r = queue.Dequeue();
            foreach (var (c, u) in _nodes[r].Next)
            {
                queue.Enqueue(u);
                var f = _nodes[r].Fail;
                while (f != 0 && !_nodes[f].Next.ContainsKey(c))
                {
                    f = _nodes[f].Fail;
                }

                _nodes[u].Fail = _nodes[f].Next.TryGetValue(c, out var target) && target != u ? target : 0;
                _nodes[u].Output |= _nodes[_nodes[u].Fail].Output;
            }
        }
    }

    private static char Fold(char c) => c is >= 'A' and <= 'Z' ? (char)(c + 32) : c;

    private sealed class Node
    {
        public Dictionary<char, int> Next { get; } = [];

        public int Fail { get; set; }

        public int Depth { get; init; }

        public bool Terminal { get; set; }

        public bool Output { get; set; }
    }
}
