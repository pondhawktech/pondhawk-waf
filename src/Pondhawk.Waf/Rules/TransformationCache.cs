using System.Runtime.CompilerServices;

namespace Pondhawk.Waf.Rules;

/// <summary>
/// Transformed values of one phase, keyed by (transformation chain, input), so rules with the same chain transform a
/// value once. Short inputs are compared by content. Long inputs (<see cref="StepCacheMinLength"/> chars or more) are
/// compared by reference: collection values are the same string instances for every rule of a phase, and hashing a large
/// value by content would cost about as much as transforming it. Holds at most
/// <see cref="MaxChars"/> characters of transformed copies per transaction; past that, values are transformed again
/// instead of cached. A transformation chain that changes nothing returns its input, which costs no memory.
/// </summary>
internal sealed class TransformationCache
{
    internal const long MaxChars = 4 * 1024 * 1024;

    /// <summary>Values at least this long are also cached after each step of a chain.</summary>
    internal const int StepCacheMinLength = 256;

    private readonly Dictionary<Key, string> _values = new(KeyComparer.Instance);
    private long _chars;

    public int Count => _values.Count;

    public bool TryGetValue(int chainId, string input, out string value) =>
        _values.TryGetValue(new Key(chainId, input), out value!);

    public void Add(int chainId, string input, string value)
    {
        var cost = ReferenceEquals(input, value) ? 0 : value.Length;
        if (_chars + cost > MaxChars)
        {
            return;
        }

        _values[new Key(chainId, input)] = value;
        _chars += cost;
    }

    public void Clear()
    {
        _values.Clear();
        _chars = 0;
    }

    private readonly record struct Key(int ChainId, string Input);

    private sealed class KeyComparer : IEqualityComparer<Key>
    {
        public static readonly KeyComparer Instance = new();

        public bool Equals(Key x, Key y) =>
            x.ChainId == y.ChainId
            && (ReferenceEquals(x.Input, y.Input) || (x.Input.Length < StepCacheMinLength && string.Equals(x.Input, y.Input, StringComparison.Ordinal)));

        public int GetHashCode(Key obj) => HashCode.Combine(
            obj.ChainId,
            obj.Input.Length < StepCacheMinLength ? string.GetHashCode(obj.Input, StringComparison.Ordinal) : RuntimeHelpers.GetHashCode(obj.Input));
    }
}
