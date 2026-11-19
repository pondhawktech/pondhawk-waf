using System.Collections.Concurrent;
using Microsoft.Extensions.Logging.Abstractions;
using Pondhawk.Waf.AspNetCore;

namespace Pondhawk.Waf.Tests;

public class ExclusionTests
{
    private const string Sqli = "1%27%20OR%20%271%27%3D%271";

    private static readonly ConcurrentDictionary<string, WafEngine> Engines = new();

    private static WafEngine Engine(string key, Action<WafOptions> configure) =>
        Engines.GetOrAdd(key, _ =>
        {
            var o = new WafOptions { RuleEngine = RuleEngineMode.On, WarmUp = false, Profile = WafProfile.Strict };
            configure(o);
            return WafServiceCollectionExtensions.CreateEngine(o, NullLoggerFactory.Instance);
        });

    private static HashSet<int> Matches(WafEngine waf, string uri)
    {
        using var tx = waf.NewTransaction();
        tx.ProcessConnection("10.0.0.1", 40000, "10.0.0.2", 80);
        tx.ProcessUri(uri, "GET", "HTTP/1.1");
        tx.AddRequestHeader("Host", "example.com");
        tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)");
        tx.AddRequestHeader("Accept", "text/html");
        tx.ProcessRequestHeaders();
        tx.ProcessRequestBody();
        return tx.MatchedRules.Select(m => m.Rule.Id).ToHashSet();
    }

    private static WafEngine Baseline => Engine("baseline", _ => { });

    private static WafEngine LoginPassword => Engine("login-password", o => o.Exclude(942100, "ARGS:password", path: "/login"));

    [Fact]
    public void BaselineDetects() => Assert.Contains(942100, Matches(Baseline, "/login?password=" + Sqli));

    [Fact]
    public void RemoveRuleEverywhere()
    {
        var waf = Engine("remove-942100", o => o.RemoveRule(942100));
        Assert.DoesNotContain(waf.Rules, r => r.Id == 942100);
        Assert.DoesNotContain(942100, Matches(waf, "/any?q=" + Sqli));
    }

    [Fact]
    public void RemoveRangeEverywhere()
    {
        var waf = Engine("remove-942", o => o.RemoveRules(942000, 942999));
        Assert.DoesNotContain(waf.Rules, r => r.Id is >= 942000 and <= 942999);
    }

    [Fact]
    public void RemoveTagEverywhere()
    {
        var waf = Engine("remove-tag", o => o.RemoveRulesByTag("attack-sqli"));
        Assert.DoesNotContain(waf.Rules, r => r.Tags.Contains("attack-sqli"));
    }

    [Fact]
    public void ExcludeTargetEverywhere()
    {
        var waf = Engine("exclude-password", o => o.Exclude(942100, "ARGS:password"));
        Assert.DoesNotContain(942100, Matches(waf, "/x?password=" + Sqli));
        Assert.Contains(942100, Matches(waf, "/x?user=" + Sqli));
    }

    [Fact]
    public void ExcludeTargetByTagEverywhere()
    {
        var waf = Engine("exclude-tag-password", o => o.ExcludeByTag("attack-sqli", "ARGS:password"));
        Assert.DoesNotContain(Matches(waf, "/x?password=" + Sqli), id => id is >= 942100 and <= 942999);
    }

    [Theory]
    [InlineData("/login?password=")]
    [InlineData("/login/?password=")]
    [InlineData("/login/step2?password=")]
    [InlineData("/LOGIN?password=")]
    [InlineData("/login#x?password=")]
    public void PathExclusionApplies(string prefix) =>
        Assert.DoesNotContain(942100, Matches(LoginPassword, prefix + Sqli));

    [Theory]
    [InlineData("/login?user=")] // another argument
    [InlineData("/admin?password=")] // another path
    [InlineData("/login2?password=")] // not a path segment
    [InlineData("/loginx/y?password=")]
    [InlineData("/login/../admin?password=")] // dot segments
    [InlineData("/login/./x?password=")]
    [InlineData("/login/..?password=")]
    [InlineData("/login/%2e%2e/admin?password=")] // encoded dots
    [InlineData("/login/%2E%2E/admin?password=")]
    [InlineData("/login%2F..%2Fadmin?password=")] // encoded slash
    [InlineData("/login%2fadmin?password=")]
    [InlineData("/login\\..\\admin?password=")] // backslash
    [InlineData("/login/%5c..%5cadmin?password=")]
    [InlineData("http://example.com/login?password=")] // absolute form
    [InlineData("//login?password=")]
    [InlineData("/x/login?password=")]
    public void PathExclusionDoesNotApply(string prefix) =>
        Assert.Contains(942100, Matches(LoginPassword, prefix + Sqli));

    [Fact]
    public void PathExclusionWithTrailingSlashAndMetacharacters()
    {
        var waf = Engine("path-meta", o => o.RemoveRule(942100, "/api/v1.0/items(1)/"));
        Assert.DoesNotContain(942100, Matches(waf, "/api/v1.0/items(1)/x?q=" + Sqli));
        Assert.Contains(942100, Matches(waf, "/api/v1x0/items(1)/x?q=" + Sqli));
    }

    [Fact]
    public void PathRemoveTag()
    {
        var waf = Engine("path-tag", o => o.RemoveRulesByTag("attack-sqli", "/sql-console"));
        Assert.DoesNotContain(Matches(waf, "/sql-console?q=" + Sqli), id => id is >= 942100 and <= 942999);
        Assert.Contains(942100, Matches(waf, "/other?q=" + Sqli));
    }

    [Fact]
    public void PathExcludeRange()
    {
        var waf = Engine("path-range", o => o.Exclude(942000, 942999, "ARGS:q", "/search"));
        Assert.DoesNotContain(Matches(waf, "/search?q=" + Sqli), id => id is >= 942100 and <= 942999);
        Assert.Contains(942100, Matches(waf, "/search?r=" + Sqli));
    }

    [Fact]
    public void ExclusionsFromConfigurationAreValidatedAtBuild()
    {
        var o = new WafOptions { WarmUp = false };
        o.Exclusions.Add(new WafExclusion { Rule = "942100", Tag = "attack-sqli" });
        Assert.Throws<ArgumentException>(() => WafServiceCollectionExtensions.CreateEngine(o, NullLoggerFactory.Instance));
    }

    [Fact]
    public void UnknownRuleInTargetExclusionFailsTheBuild()
    {
        var o = new WafOptions { WarmUp = false };
        o.Exclude(123456, "ARGS:password");
        Assert.ThrowsAny<Exception>(() => WafServiceCollectionExtensions.CreateEngine(o, NullLoggerFactory.Instance));
    }

    [Theory]
    [InlineData(null, null, null, null)]
    [InlineData("942100", "attack-sqli", null, null)]
    [InlineData("0", null, null, null)]
    [InlineData("942100-", null, null, null)]
    [InlineData("942199-942100", null, null, null)]
    [InlineData("942100,942101", null, null, null)]
    [InlineData(null, "attack sqli", null, null)]
    [InlineData(null, "a\"b", null, null)]
    [InlineData("942100", null, "ARGS:a,ARGS:b", null)]
    [InlineData("942100", null, "ARGS:a|ARGS:b", null)]
    [InlineData("942100", null, "!ARGS:a", null)]
    [InlineData("942100", null, "ARGS:a\"", null)]
    [InlineData("942100", null, "ARGS:a'", null)]
    [InlineData("942100", null, null, "login")]
    [InlineData("942100", null, null, "/login?x=1")]
    [InlineData("942100", null, null, "/login#x")]
    [InlineData("942100", null, null, "/a/../b")]
    [InlineData("942100", null, null, "/a\\b")]
    [InlineData("942100", null, null, "/a b")]
    [InlineData("942100", null, null, "/a\"b")]
    [InlineData("942100", null, null, "/a'b")]
    public void InvalidExclusionsAreRejected(string? rule, string? tag, string? target, string? path) =>
        Assert.Throws<ArgumentException>(() => new WafExclusion { Rule = rule, Tag = tag, Target = target, Path = path }.Validate());

    [Theory]
    [InlineData("SecRuleUpdateTargetByTag \"t1\" \"!ARGS:ok\"")]
    [InlineData("SecRuleUpdateTargetByTag t1 \"!ARGS:ok\"")]
    [InlineData("SecRuleUpdateTargetById 1 \"!ARGS:ok\"")]
    [InlineData("SecRuleUpdateTargetById \"1\" \"!ARGS:ok\"")]
    public void UpdateTargetWithQuotedFields(string directive)
    {
        var waf = WafEngine.FromDirectives($"""
            SecRuleEngine On
            SecRule ARGS "@contains bad" "id:1,phase:1,deny,tag:'t1'"
            {directive}
            """);
        static Interruption? Run(WafEngine w, string uri)
        {
            using var tx = w.NewTransaction();
            tx.ProcessUri(uri, "GET", "HTTP/1.1");
            return tx.ProcessRequestHeaders();
        }

        Assert.Null(Run(waf, "/?ok=bad"));
        Assert.NotNull(Run(waf, "/?other=bad"));
    }

    [Fact]
    public void HelpersValidateImmediately() =>
        Assert.Throws<ArgumentException>(() => new WafOptions().Exclude(942100, "ARGS:a,b"));

    [Fact]
    public void GeneratedDirectives()
    {
        var o = new WafOptions()
            .RemoveRule(920350)
            .RemoveRules(942100, 942199)
            .RemoveRulesByTag("attack-xss")
            .Exclude(942100, "ARGS:password")
            .ExcludeByTag("attack-sqli", "REQUEST_COOKIES:session");
        Assert.Equal(
            """
            SecRuleRemoveById 920350
            SecRuleRemoveById 942100-942199
            SecRuleRemoveByTag attack-xss
            SecRuleUpdateTargetById 942100 "!ARGS:password"
            SecRuleUpdateTargetByTag attack-sqli "!REQUEST_COOKIES:session"

            """.ReplaceLineEndings("\n"),
            WafExclusion.StaticDirectives(o.Exclusions).ReplaceLineEndings("\n"));
        Assert.Empty(WafExclusion.PathDirectives(o.Exclusions));
    }
}
