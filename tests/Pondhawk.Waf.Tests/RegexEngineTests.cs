using System.Text.RegularExpressions;
using Pondhawk.Waf.CoreRuleSet;
using Pondhawk.Waf.Operators;
using Pondhawk.Waf.Rules;

namespace Pondhawk.Waf.Tests;

/// <summary>
/// The application chooses the @rx engine: NonBacktracking (linear time, about 500 MB for CRS) or Backtracking (about
/// 16 MB, with a timeout per match) for small hosts (#33).
/// </summary>
public sealed class RegexEngineTests
{
    internal static WafEngine BuildCrs(RegexEngine engine)
    {
        var builder = new WafBuilder(CoreRuleSetFiles.FileSystem) { RegexEngine = engine };
        builder.AddDirectives(CoreRuleSetFiles.BaseDirectives);
        builder.AddDirectives("SecRuleEngine On\n");
        builder.AddDirectives(CoreRuleSetFiles.RuleDirectives);
        return builder.Build();
    }

    [Fact]
    public void AllCrsRegexesUseTheLinearTimeEngine()
    {
        // The default, and every CRS pattern compiles with it: none falls back to backtracking.
        Assert.Equal(RegexEngine.NonBacktracking, new WafBuilder().RegexEngine);
        var waf = CrsSmokeTests.BuildCrs();
        var backtracking = new List<string>();
        foreach (var top in waf.Rules)
        {
            for (Rule? r = top; r is not null; r = r.Chain)
            {
                if (r.Operator is RxOperator rx && (rx.Regex.Options & RegexOptions.NonBacktracking) == 0)
                {
                    backtracking.Add($"{top.Id}: {r.OperatorData}");
                }
            }
        }

        Assert.Empty(backtracking);
    }

    [Fact]
    public void NonBacktrackingBlocksSqlInjection() => AssertBlocksSqlInjection(BuildCrs(RegexEngine.NonBacktracking));

    [Theory]
    [InlineData("@rx", RuleEngineMode.On)]
    [InlineData("!@rx", RuleEngineMode.On)]
    [InlineData("@rx", RuleEngineMode.DetectionOnly)]
    public void AMatchThatTimesOutCountsAsAMatch(string op, RuleEngineMode mode)
    {
        // Exponential for a backtracking engine: 40 a's and a character that cannot end the match.
        var builder = new WafBuilder { RegexEngine = RegexEngine.Backtracking };
        builder.AddDirectives($"""
            SecRuleEngine {mode}
            SecRule ARGS:q "{op} ^(?:a|aa)+$" "id:1,phase:1,deny,status:403,log"
            """);
        var waf = builder.Build();
        using var tx = Request(waf, "/?q=" + new string('a', 40) + "!");
        var it = tx.ProcessRequestHeaders();
        Assert.Contains(tx.MatchedRules, m => m.Rule.Id == 1);
        if (mode == RuleEngineMode.On)
        {
            Assert.Equal(1, it?.RuleId);
        }
        else
        {
            Assert.Null(it);
        }
    }

    [Fact]
    public void AFirstMatchThatTimesOutIsRetried()
    {
        // The first match of a compiled regex runs the JIT and can exceed the timeout (#34): not a match.
        var (waf, rx) = TimeoutRule();
        var calls = 0;
        rx.BeforeMatch = () =>
        {
            if (++calls == 1)
            {
                throw new RegexMatchTimeoutException("x", "y", TimeSpan.FromMilliseconds(250));
            }
        };
        using var tx = Request(waf, "/?q=grant_type");
        Assert.Null(tx.ProcessRequestHeaders());
        Assert.Equal(2, calls);
        Assert.DoesNotContain(tx.MatchedRules, m => m.Rule.Id == 2);
        Assert.Equal(0, waf.RegexTimeouts);
    }

    [Fact]
    public void ATimeoutAfterAnEarlierTimeoutIsNotRetried()
    {
        // After the first timeout the regex code is compiled: a later timeout is the input's doing.
        var (waf, rx) = TimeoutRule();
        var calls = 0;
        rx.BeforeMatch = () =>
        {
            calls++;
            throw new RegexMatchTimeoutException("x", "y", TimeSpan.FromMilliseconds(250));
        };
        using (var first = Request(waf, "/?q=one"))
        {
            Assert.NotNull(first.ProcessRequestHeaders());
            Assert.Equal(2, calls);
        }

        using var tx = Request(waf, "/?q=two");
        Assert.NotNull(tx.ProcessRequestHeaders());
        Assert.Equal(3, calls);
        Assert.Equal(2, waf.RegexTimeouts);
    }

    [Fact]
    public void ConcurrentFirstMatchesThatTimeOutAreAllRetried()
    {
        // Two requests wait for the same JIT and time out together: neither is a match.
        var (waf, rx) = TimeoutRule();
        using var bothStarted = new Barrier(2);
        var calls = 0;
        rx.BeforeMatch = () =>
        {
            if (Interlocked.Increment(ref calls) <= 2)
            {
                Assert.True(bothStarted.SignalAndWait(TimeSpan.FromSeconds(10)));
                throw new RegexMatchTimeoutException("x", "y", TimeSpan.FromMilliseconds(250));
            }
        };
        Parallel.For(0, 2, new ParallelOptions { MaxDegreeOfParallelism = 2 }, i =>
        {
            using var tx = Request(waf, "/?q=value" + i);
            Assert.Null(tx.ProcessRequestHeaders());
        });
        Assert.Equal(4, calls);
        Assert.Equal(0, waf.RegexTimeouts);
    }

    [Fact]
    public void ATimeoutIsReportedAndLogsTheInspectedValue()
    {
        var reported = new List<RegexTimeout>();
        var (waf, rx) = TimeoutRule(reported.Add);
        rx.BeforeMatch = () => throw new RegexMatchTimeoutException("x", "y", TimeSpan.FromMilliseconds(250));

        // Rule 1 captures "host" first: rule 2 must not log it as its data.
        using var tx = Request(waf, "/?h=host&q=grant_type");
        Assert.Equal(2, tx.ProcessRequestHeaders()?.RuleId);
        var matched = Assert.Single(tx.MatchedRules, m => m.Rule.Id == 2);
        Assert.Equal("Matched Data: grant_type", matched.Data);
        Assert.Equal(1, waf.RegexTimeouts);
        var timeout = Assert.Single(reported);
        Assert.Equal(new RegexTimeout(2, "ARGS:q", "grant_type".Length, TimeSpan.FromMilliseconds(250)), timeout);
    }

    [Fact]
    public void RegexTimeoutReachesTheBacktrackingRegexes()
    {
        var (waf, rx) = TimeoutRule(timeout: TimeSpan.FromSeconds(1));
        Assert.Equal(TimeSpan.FromSeconds(1), rx.Regex.MatchTimeout);
        Assert.Throws<ArgumentOutOfRangeException>(() => new WafBuilder { RegexTimeout = TimeSpan.Zero });
        Assert.Throws<ArgumentOutOfRangeException>(() => new WafBuilder { RegexTimeout = TimeSpan.FromSeconds(11) });
        GC.KeepAlive(waf);
    }

    private static (WafEngine Waf, RxOperator Rx) TimeoutRule(Action<RegexTimeout>? report = null, TimeSpan? timeout = null)
    {
        var builder = new WafBuilder { RegexEngine = RegexEngine.Backtracking, RegexTimeout = timeout ?? TimeSpan.FromMilliseconds(250) };
        builder.Config.RegexTimeoutCallback = report;
        builder.AddDirectives("""
            SecRuleEngine On
            SecRule ARGS:h "@rx ^(h)ost$" "id:1,phase:1,pass,capture,nolog"
            SecRule ARGS:q "@rx ^[0-9]+$" "id:2,phase:1,deny,status:403,capture,log,logdata:'Matched Data: %{TX.0}'"
            """);
        var waf = builder.Build();
        return (waf, (RxOperator)waf.Rules.Single(r => r.Id == 2).Operator!);
    }

    internal static void AssertBlocksSqlInjection(WafEngine waf)
    {
        using var tx = Request(waf, "/search?q=1%27%20OR%20%271%27=%271");
        tx.ProcessRequestHeaders();
        var it = tx.ProcessRequestBody();
        Assert.NotNull(it);
        Assert.Equal(949110, it.RuleId);
        Assert.Contains(tx.MatchedRules, m => m.Rule.Id == 942100);
    }

    private static Transaction Request(WafEngine waf, string uri)
    {
        var tx = waf.NewTransaction();
        tx.ProcessConnection("127.0.0.1", 5000, "127.0.0.1", 80);
        tx.ProcessUri(uri, "GET", "HTTP/1.1");
        tx.AddRequestHeader("Host", "localhost");
        tx.AddRequestHeader("User-Agent", "Mozilla/5.0");
        tx.AddRequestHeader("Accept", "*/*");
        return tx;
    }

    // Chained rules included.
    internal static List<Regex> Regexes(WafEngine engine)
    {
        var regexes = new List<Regex>();
        foreach (var top in engine.Rules)
        {
            for (Rule? r = top; r is not null; r = r.Chain)
            {
                if (r.Operator is RxOperator rx)
                {
                    regexes.Add(rx.Regex);
                }
            }
        }

        return regexes;
    }
}

/// <summary>Runs alone, after the parallel tests, so the managed heap shows only this engine.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class MemoryCollection
{
    public const string Name = "Memory";
}

// The only test that builds CRS with Backtracking: regexes are shared in the process (#32), so the measurement below
// would miss them if another test built them first.
[Collection(MemoryCollection.Name)]
public sealed class BacktrackingCoreRuleSetTests
{
    [Fact]
    public async Task HoldsLittleMemoryCompilesWithATimeoutAndBlocks()
    {
        var before = GC.GetTotalMemory(forceFullCollection: true);
        var waf = RegexEngineTests.BuildCrs(RegexEngine.Backtracking);
        await waf.Compiled;
        var held = GC.GetTotalMemory(forceFullCollection: true) - before;

        // About 47 MB of rules and 16 MB of regexes; NonBacktracking holds about 535 MB.
        Assert.True(held < 100L * 1024 * 1024, $"{held / (1024 * 1024)} MB");

        var regexes = RegexEngineTests.Regexes(waf);
        Assert.True(regexes.Count > 100, $"only {regexes.Count} @rx rules");
        Assert.All(regexes, r =>
        {
            Assert.False(r.Options.HasFlag(RegexOptions.NonBacktracking), r.ToString());
            Assert.Equal(TimeSpan.FromMilliseconds(250), r.MatchTimeout);
        });
        RegexEngineTests.AssertBlocksSqlInjection(waf);
    }
}
