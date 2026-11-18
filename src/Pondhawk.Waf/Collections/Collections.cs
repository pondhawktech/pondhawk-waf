using System.Text.RegularExpressions;
using Pondhawk.Waf.Text;

namespace Pondhawk.Waf.Collections;

/// <summary>One value taken from a collection, as seen by a rule.</summary>
public readonly record struct MatchData(Variable Variable, string Key, string Value)
{
    /// <summary>The variable name in the form used by MATCHED_VAR_NAME, e.g. ARGS:id.</summary>
    public string FullName => Key.Length > 0 ? Variable.Name() + ":" + Key : Variable.Name();
}

/// <summary>A transaction collection that rules read from.</summary>
public interface IWafCollection
{
    Variable Variable { get; }

    void FindAll(List<MatchData> output);
}

/// <summary>A collection whose values can be selected by key, e.g. ARGS:id or ARGS:/^id/.</summary>
public interface IKeyedCollection : IWafCollection
{
    /// <summary>Returns the values for a key (case-insensitive), or an empty list.</summary>
    IReadOnlyList<string> Get(string key);

    void FindString(string key, List<MatchData> output);

    /// <summary>Adds the values whose lowercase key matches the regex.</summary>
    void FindRegex(Regex regex, List<MatchData> output);
}

/// <summary>A collection with a single value, e.g. REQUEST_METHOD.</summary>
public sealed class SingleCollection(Variable variable) : IWafCollection
{
    public Variable Variable { get; } = variable;

    public string Value { get; private set; } = string.Empty;

    public void Set(string value) => Value = value;

    public void Reset() => Value = string.Empty;

    public void FindAll(List<MatchData> output) => output.Add(new MatchData(Variable, string.Empty, Value));
}

/// <summary>
/// A multi-valued map with case-insensitive keys that keeps the original key spelling and the insertion order.
/// </summary>
public class MapCollection(Variable variable) : IKeyedCollection
{
    private readonly Dictionary<string, List<KeyValuePair<string, string>>> _data = new(StringComparer.Ordinal);
    private readonly List<string> _order = [];

    public Variable Variable { get; } = variable;

    public int Count { get; private set; }

    public bool IsEmpty => Count == 0;

    internal IEnumerable<KeyValuePair<string, List<KeyValuePair<string, string>>>> Entries
    {
        get
        {
            foreach (var k in _order)
            {
                yield return new(k, _data[k]);
            }
        }
    }

    public IReadOnlyList<string> Get(string key)
    {
        if (Count == 0 || !_data.TryGetValue(ByteString.ToLowerAscii(key), out var list) || list.Count == 0)
        {
            return [];
        }

        var result = new string[list.Count];
        for (var i = 0; i < list.Count; i++)
        {
            result[i] = list[i].Value;
        }

        return result;
    }

    /// <summary>Returns the first value for the key, or null.</summary>
    public string? GetFirst(string key)
    {
        if (Count == 0 || !_data.TryGetValue(ByteString.ToLowerAscii(key), out var list) || list.Count == 0)
        {
            return null;
        }

        return list[0].Value;
    }

    public bool ContainsKey(string key) => _data.ContainsKey(ByteString.ToLowerAscii(key));

    public void Add(string key, string value)
    {
        var lower = ByteString.ToLowerAscii(key);
        if (!_data.TryGetValue(lower, out var list))
        {
            list = [];
            _data[lower] = list;
            _order.Add(lower);
        }

        list.Add(new(key, value));
        Count++;
    }

    /// <summary>Replaces all values of the key.</summary>
    public void Set(string key, string value)
    {
        var lower = ByteString.ToLowerAscii(key);
        if (_data.TryGetValue(lower, out var list))
        {
            Count -= list.Count;
            list.Clear();
        }
        else
        {
            list = [];
            _data[lower] = list;
            _order.Add(lower);
        }

        list.Add(new(key, value));
        Count++;
    }

    /// <summary>Replaces all values of the key.</summary>
    public void Set(string key, IReadOnlyList<string> values)
    {
        var lower = ByteString.ToLowerAscii(key);
        if (_data.TryGetValue(lower, out var list))
        {
            Count -= list.Count;
            list.Clear();
        }
        else
        {
            list = [];
            _data[lower] = list;
            _order.Add(lower);
        }

        foreach (var v in values)
        {
            list.Add(new(key, v));
        }

        Count += values.Count;
    }

    public void Remove(string key)
    {
        var lower = ByteString.ToLowerAscii(key);
        if (_data.Remove(lower, out var list))
        {
            Count -= list.Count;
            _order.Remove(lower);
        }
    }

    public void Reset()
    {
        _data.Clear();
        _order.Clear();
        Count = 0;
    }

    public virtual void FindAll(List<MatchData> output)
    {
        foreach (var k in _order)
        {
            foreach (var kv in _data[k])
            {
                output.Add(Emit(kv));
            }
        }
    }

    public virtual void FindString(string key, List<MatchData> output)
    {
        if (key.Length == 0)
        {
            FindAll(output);
            return;
        }

        if (Count == 0 || !_data.TryGetValue(ByteString.ToLowerAscii(key), out var list))
        {
            return;
        }

        foreach (var kv in list)
        {
            output.Add(Emit(kv));
        }
    }

    public virtual void FindRegex(Regex regex, List<MatchData> output)
    {
        foreach (var k in _order)
        {
            if (!regex.IsMatch(k))
            {
                continue;
            }

            foreach (var kv in _data[k])
            {
                output.Add(Emit(kv));
            }
        }
    }

    protected virtual MatchData Emit(KeyValuePair<string, string> kv) => new(Variable, kv.Key, kv.Value);

    /// <summary>A view of this map's keys, used for the *_NAMES variables.</summary>
    public NamesCollection Names(Variable namesVariable) => new(namesVariable, this);
}

/// <summary>The keys of a map, e.g. REQUEST_HEADERS_NAMES. Each key appears once per value, with key = value = name.</summary>
public sealed class NamesCollection(Variable variable, MapCollection source) : IKeyedCollection
{
    public Variable Variable { get; } = variable;

    public IReadOnlyList<string> Get(string key) =>
        source.ContainsKey(key) ? source.Get(key).Select(_ => key).ToArray() : [];

    public void FindAll(List<MatchData> output)
    {
        foreach (var (_, list) in source.Entries)
        {
            foreach (var kv in list)
            {
                output.Add(new MatchData(Variable, kv.Key, kv.Key));
            }
        }
    }

    public void FindString(string key, List<MatchData> output)
    {
        var tmp = new List<MatchData>();
        source.FindString(key, tmp);
        foreach (var m in tmp)
        {
            output.Add(new MatchData(Variable, m.Key, m.Key));
        }
    }

    public void FindRegex(Regex regex, List<MatchData> output)
    {
        var tmp = new List<MatchData>();
        source.FindRegex(regex, tmp);
        foreach (var m in tmp)
        {
            output.Add(new MatchData(Variable, m.Key, m.Key));
        }
    }
}

/// <summary>Several keyed collections seen as one, e.g. ARGS = ARGS_GET + ARGS_POST + ARGS_PATH.</summary>
public sealed class ConcatCollection(Variable variable, params IKeyedCollection[] sources) : IKeyedCollection
{
    public Variable Variable { get; } = variable;

    public IReadOnlyList<string> Get(string key)
    {
        List<string>? result = null;
        foreach (var s in sources)
        {
            var values = s.Get(key);
            if (values.Count > 0)
            {
                (result ??= []).AddRange(values);
            }
        }

        return (IReadOnlyList<string>?)result ?? [];
    }

    public void FindAll(List<MatchData> output)
    {
        var start = output.Count;
        foreach (var s in sources)
        {
            s.FindAll(output);
        }

        Relabel(output, start);
    }

    public void FindString(string key, List<MatchData> output)
    {
        var start = output.Count;
        foreach (var s in sources)
        {
            s.FindString(key, output);
        }

        Relabel(output, start);
    }

    public void FindRegex(Regex regex, List<MatchData> output)
    {
        var start = output.Count;
        foreach (var s in sources)
        {
            s.FindRegex(regex, output);
        }

        Relabel(output, start);
    }

    private void Relabel(List<MatchData> output, int start)
    {
        for (var i = start; i < output.Count; i++)
        {
            output[i] = output[i] with { Variable = Variable };
        }
    }
}

/// <summary>The combined length of all keys and values of some maps, e.g. ARGS_COMBINED_SIZE.</summary>
public sealed class SizeCollection(Variable variable, params MapCollection[] sources) : IWafCollection
{
    public Variable Variable { get; } = variable;

    public int Size
    {
        get
        {
            var total = 0;
            foreach (var s in sources)
            {
                foreach (var (_, list) in s.Entries)
                {
                    foreach (var kv in list)
                    {
                        total += kv.Key.Length + kv.Value.Length;
                    }
                }
            }

            return total;
        }
    }

    public void FindAll(List<MatchData> output) =>
        output.Add(new MatchData(Variable, string.Empty, Size.ToString(System.Globalization.CultureInfo.InvariantCulture)));
}
