using System.Collections.Concurrent;
using Pondhawk.Waf.Collections;

namespace Pondhawk.Waf.Rules;

/// <summary>
/// Working memory for rule evaluation: the transformation cache and scratch lists. A transaction rents one from its
/// engine and returns it on dispose, so their buffers are allocated once per concurrent request instead of per request.
/// </summary>
internal sealed class EvaluationScratch
{
    // Buffers that grew past these sizes (a large request) are dropped instead of kept in the pool.
    private const int MaxPooledCacheEntries = 4096;
    private const int MaxPooledListCapacity = 1024;

    private readonly Stack<List<MatchData>> _matchLists = new();
    private readonly Stack<List<string>> _stringLists = new();

    public TransformationCache Cache { get; } = new();

    public List<MatchData> RentMatchList() => _matchLists.TryPop(out var list) ? list : new List<MatchData>(16);

    public List<string> RentStringList() => _stringLists.TryPop(out var list) ? list : new List<string>(4);

    public void Return(List<MatchData> list)
    {
        list.Clear();
        if (list.Capacity <= MaxPooledListCapacity)
        {
            _matchLists.Push(list);
        }
    }

    public void Return(List<string> list)
    {
        list.Clear();
        _stringLists.Push(list);
    }

    /// <summary>Clears everything; false when the buffers grew too large to keep.</summary>
    public bool Reset()
    {
        var keep = Cache.Count <= MaxPooledCacheEntries;
        Cache.Clear();
        return keep;
    }
}

/// <summary>A bounded pool of <see cref="EvaluationScratch"/>, one per engine.</summary>
internal sealed class EvaluationScratchPool
{
    private readonly ConcurrentQueue<EvaluationScratch> _items = new();
    private readonly int _max = Math.Max(16, Environment.ProcessorCount * 4);
    private int _count;

    public EvaluationScratch Rent()
    {
        if (_items.TryDequeue(out var scratch))
        {
            Interlocked.Decrement(ref _count);
            return scratch;
        }

        return new EvaluationScratch();
    }

    public void Return(EvaluationScratch scratch)
    {
        if (!scratch.Reset())
        {
            return;
        }

        if (Interlocked.Increment(ref _count) > _max)
        {
            Interlocked.Decrement(ref _count);
            return;
        }

        _items.Enqueue(scratch);
    }
}
