using System.Text;

namespace Pondhawk.Waf.Text;

/// <summary>
/// One reusable <see cref="StringBuilder"/> per thread for transformations, which run for every rule and value. A
/// builder taken and not released (an exception, or nested use) is simply not reused.
/// </summary>
internal static class StringBuilderCache
{
    // Larger builders are not kept, so one large value does not pin its buffer to the thread.
    private const int MaxCachedCapacity = 16 * 1024;

    [ThreadStatic]
    private static StringBuilder? _cached;

    public static StringBuilder Acquire(int capacity)
    {
        var sb = _cached;
        if (sb is not null && capacity <= MaxCachedCapacity)
        {
            _cached = null;
            sb.Clear();
            sb.EnsureCapacity(capacity);
            return sb;
        }

        return new StringBuilder(capacity);
    }

    public static string GetStringAndRelease(StringBuilder sb)
    {
        var result = sb.ToString();
        if (sb.Capacity <= MaxCachedCapacity)
        {
            _cached = sb;
        }

        return result;
    }
}
