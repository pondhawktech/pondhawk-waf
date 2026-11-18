using System.Collections.Concurrent;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Pondhawk.Waf.AspNetCore;

namespace Pondhawk.Waf.Tests;

public class ProfileTests
{
    private static readonly ConcurrentDictionary<string, WafEngine> Engines = new();

    private static WafEngine Engine(string key, Action<WafOptions> configure) =>
        Engines.GetOrAdd(key, _ =>
        {
            var o = new WafOptions { RuleEngine = RuleEngineMode.On, WarmUp = false };
            configure(o);
            return WafServiceCollectionExtensions.CreateEngine(o, NullLoggerFactory.Instance);
        });

    private static Transaction Get(WafEngine waf, string uri)
    {
        var tx = waf.NewTransaction();
        tx.ProcessConnection("10.0.0.1", 40000, "10.0.0.2", 80);
        tx.ProcessUri(uri, "GET", "HTTP/1.1");
        tx.AddRequestHeader("Host", "example.com");
        tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)");
        tx.AddRequestHeader("Accept", "text/html");
        tx.ProcessRequestHeaders();
        tx.ProcessRequestBody();
        return tx;
    }

    [Theory]
    [InlineData(WafProfile.Performance, 1, 1, 5, 4, false, 13_107_200, 1000)]
    [InlineData(WafProfile.Balanced, 1, 2, 5, 4, true, 13_107_200, 1000)]
    [InlineData(WafProfile.Strict, 2, 3, 5, 4, true, 8_388_608, 500)]
    [InlineData(WafProfile.Paranoid, 3, 4, 3, 3, true, 4_194_304, 255)]
    public void ProfileTable(WafProfile profile, int pl, int detection, int inbound, int outbound, bool responses, long bodyLimit, int args)
    {
        var s = WafSettings.For(profile);
        s.Validate();
        Assert.Equal((pl, detection, inbound, outbound, responses, bodyLimit, args),
            (s.ParanoiaLevel, s.DetectionParanoiaLevel, s.InboundAnomalyScoreThreshold, s.OutboundAnomalyScoreThreshold,
                s.InspectResponses, s.RequestBodyLimit, s.ArgumentsLimit));
    }

    [Fact]
    public void BalancedIsTheDefault() =>
        Assert.Equal(WafSettings.For(WafProfile.Balanced), new WafOptions().Resolve());

    [Fact]
    public void ExplicitOptionsOverrideTheProfile()
    {
        var s = new WafOptions { Profile = WafProfile.Strict, InspectResponses = false, ArgumentsLimit = 2000 }.Resolve();
        Assert.False(s.InspectResponses);
        Assert.Equal(2000, s.ArgumentsLimit);
        Assert.Equal(2, s.ParanoiaLevel);
    }

    [Fact]
    public void DetectionLevelFollowsAHigherBlockingLevel()
    {
        var s = new WafOptions { Profile = WafProfile.Balanced, ParanoiaLevel = 4 }.Resolve();
        Assert.Equal(4, s.DetectionParanoiaLevel);
    }

    [Theory]
    [InlineData(0, null)]
    [InlineData(5, null)]
    [InlineData(3, 2)]
    public void InvalidLevelsAreRejected(int paranoia, int? detection) =>
        Assert.ThrowsAny<ArgumentException>(() =>
            new WafOptions { ParanoiaLevel = paranoia, DetectionParanoiaLevel = detection }.Resolve());

    [Theory]
    [InlineData(WafProfile.Performance)]
    [InlineData(WafProfile.Balanced)]
    [InlineData(WafProfile.Strict)]
    [InlineData(WafProfile.Paranoid)]
    public void EngineGetsTheProfileSettings(WafProfile profile)
    {
        var expected = WafSettings.For(profile);
        var waf = Engine(profile.ToString(), o => o.Profile = profile);
        Assert.Equal(expected.RequestBodyLimit, waf.Config.RequestBodyLimit);
        Assert.Equal(expected.ArgumentsLimit, waf.Config.ArgumentsLimit);
        Assert.Equal(expected.InspectResponses, waf.Config.ResponseBodyAccess);
        Assert.Equal(expected.ResponseBodyLimit, waf.Config.ResponseBodyLimit);
        Assert.Equal(expected.ResponseMimeTypes, waf.Config.ResponseBodyMimeTypes);

        using var tx = Get(waf, "/products?color=blue&page=2");
        Assert.Null(tx.Interruption);
        var txVars = tx.Variables.Tx;
        Assert.Equal(expected.ParanoiaLevel.ToString(), txVars.GetFirst("blocking_paranoia_level"));
        Assert.Equal(expected.DetectionParanoiaLevel.ToString(), txVars.GetFirst("detection_paranoia_level"));
        Assert.Equal(expected.InboundAnomalyScoreThreshold.ToString(), txVars.GetFirst("inbound_anomaly_score_threshold"));
        Assert.Equal(expected.OutboundAnomalyScoreThreshold.ToString(), txVars.GetFirst("outbound_anomaly_score_threshold"));
    }

    [Fact]
    public void BlockingLevelRaisedInDirectivesDoesNotTriggerTheCrsConfigurationError()
    {
        // Without the guard, CRS rule 901500 would answer every request with 500.
        var waf = Engine("raised-in-directives", o => o.Directives =
            "SecAction \"id:10000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=3\"");
        using var tx = Get(waf, "/products?color=blue&page=2");
        Assert.Null(tx.Interruption);
        Assert.Equal("3", tx.Variables.Tx.GetFirst("detection_paranoia_level"));
    }

    [Fact]
    public void HigherProfilesCountWhatLowerProfilesOnlyLog()
    {
        // Paranoia level 2+ warnings (942430 and friends: many special characters). No level 1 rule matches.
        const string uri = "/search?q=" + "%28%29%28%29%28%29%28%29%28%29%28%29%28%29";

        // Balanced: blocking level 1, detection level 2. The level 2 match is logged and scored for detection only.
        using var balanced = Get(Engine(nameof(WafProfile.Balanced), o => o.Profile = WafProfile.Balanced), uri);
        Assert.Null(balanced.Interruption);
        Assert.Contains(balanced.MatchedRules, m => m.Rule.Id == 942430);
        Assert.Equal("0", balanced.Variables.Tx.GetFirst("blocking_inbound_anomaly_score"));
        Assert.NotEqual("0", balanced.Variables.Tx.GetFirst("detection_inbound_anomaly_score"));

        // Strict: level 2 is blocking, so the warnings count, but stay under the threshold of 5.
        using var strict = Get(Engine(nameof(WafProfile.Strict), o => o.Profile = WafProfile.Strict), uri);
        Assert.Null(strict.Interruption);
        Assert.NotEqual("0", strict.Variables.Tx.GetFirst("blocking_inbound_anomaly_score"));

        // Paranoid: level 3 blocking and threshold 3: the same request is blocked.
        using var paranoid = Get(Engine(nameof(WafProfile.Paranoid), o => o.Profile = WafProfile.Paranoid), uri);
        Assert.Equal(949110, paranoid.Interruption?.RuleId);

        // Performance: level 2 rules do not run at all.
        using var performance = Get(Engine(nameof(WafProfile.Performance), o => o.Profile = WafProfile.Performance), uri);
        Assert.DoesNotContain(performance.MatchedRules, m => m.Rule.Id == 942430);
    }

    [Fact]
    public void PerformanceProfileDoesNotInspectResponses()
    {
        var waf = Engine(nameof(WafProfile.Performance), o => o.Profile = WafProfile.Performance);
        using var tx = Get(waf, "/");
        tx.AddResponseHeader("Content-Type", "text/html");
        tx.ProcessResponseHeaders(200, "HTTP/1.1");
        tx.WriteResponseBody(Encoding.ASCII.GetBytes("You have an error in your SQL syntax"));
        tx.ProcessResponseBody();
        Assert.Null(tx.Interruption);
        Assert.False(tx.IsResponseBodyProcessable);
    }
}
