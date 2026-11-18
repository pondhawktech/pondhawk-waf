namespace Pondhawk.Waf.Rules;

/// <summary>
/// Transformed values of one phase, keyed by (transformation chain, input), so rules with the same chain transform a
/// value once. Holds at most <see cref="MaxChars"/> characters per transaction; past that, values are transformed
/// again instead of cached (each cached value is a full copy of an argument).
/// </summary>
internal sealed class TransformationCache
{
    internal const long MaxChars = 4 * 1024 * 1024;

    private readonly Dictionary<(int, string), string> _values = [];
    private long _chars;

    public int Count => _values.Count;

    public bool TryGetValue((int, string) key, out string value) => _values.TryGetValue(key, out value!);

    public void Add((int, string) key, string value)
    {
        if (_chars + value.Length > MaxChars)
        {
            return;
        }

        _values[key] = value;
        _chars += value.Length;
    }

    public void Clear()
    {
        _values.Clear();
        _chars = 0;
    }
}
