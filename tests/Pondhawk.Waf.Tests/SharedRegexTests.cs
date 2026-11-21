using Pondhawk.Waf.Operators;

namespace Pondhawk.Waf.Tests;

/// <summary>
/// Engines in one process share compiled regexes: a test suite or a reload that builds many engines compiles the Core
/// Rule Set once, not once per engine (#32).
/// </summary>
public sealed class SharedRegexTests
{
    [Fact]
    public async Task EnginesFromTheSameRulesShareEveryRegex()
    {
        var first = CrsSmokeTests.BuildCrs();
        await first.Compiled;
        var second = CrsSmokeTests.BuildCrs();

        var a = Regexes(first);
        var b = Regexes(second);
        Assert.True(a.Count > 100, $"only {a.Count} @rx rules");
        Assert.Equal(a.Count, b.Count);
        for (var i = 0; i < a.Count; i++)
        {
            Assert.Same(a[i], b[i]);
        }

        // Nothing left for the second engine to compile: its regexes are built before it starts.
        Assert.All(b, lazy => Assert.True(lazy.IsValueCreated));
        await second.Compiled;
    }

    [Fact]
    public void CachesShareARegexOnlyWithTheSameSettings()
    {
        const string pattern = @"(?i)select\s+\w+\s+from";
        var regex = new RegexCache().Get(pattern);
        Assert.Same(regex, new RegexCache().Get(pattern));
        Assert.Same(new RegexCache().GetPlain(pattern), new RegexCache().GetPlain(pattern));
        Assert.NotSame(regex, new RegexCache().GetPlain(pattern));
        Assert.NotSame(regex, new RegexCache { PreferNonBacktracking = false }.Get(pattern));
        Assert.NotSame(regex, new RegexCache { BacktrackingTimeout = TimeSpan.FromSeconds(1) }.Get(pattern));
    }

    [Fact]
    public void AnInvalidPatternStillFailsInEveryCache()
    {
        Assert.ThrowsAny<ArgumentException>(() => new RegexCache().Get("(unclosed"));
        Assert.ThrowsAny<ArgumentException>(() => new RegexCache().Get("(unclosed"));
    }

    private static List<Lazy<System.Text.RegularExpressions.Regex>> Regexes(WafEngine engine) =>
        [.. engine.Rules.Select(r => r.Operator).OfType<RxOperator>().Select(o => o.DeferredRegex)];
}
