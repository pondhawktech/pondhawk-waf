using System.Text;
using Pondhawk.Waf.CoreRuleSet;
using Pondhawk.Waf.Text;

namespace Pondhawk.Waf.Tests;

public class CrsSmokeTests
{
    internal static WafEngine BuildCrs(string extra = "")
    {
        var builder = new WafBuilder(CoreRuleSetFiles.FileSystem);
        builder.AddDirectives(CoreRuleSetFiles.BaseDirectives);
        builder.AddDirectives("SecRuleEngine On\n" + extra);
        builder.AddDirectives(CoreRuleSetFiles.RuleDirectives);
        return builder.Build();
    }

    [Fact]
    public void LoadsAllCrsRules()
    {
        var waf = BuildCrs();
        Assert.True(waf.Rules.Count > 500, $"only {waf.Rules.Count} rules");
    }

    [Fact]
    public void BlocksSqlInjectionInQuery()
    {
        var waf = BuildCrs();
        using var tx = waf.NewTransaction();
        tx.ProcessConnection("127.0.0.1", 5000, "127.0.0.1", 80);
        tx.ProcessUri("/search?q=1%27%20OR%20%271%27=%271", "GET", "HTTP/1.1");
        tx.AddRequestHeader("Host", "localhost");
        tx.AddRequestHeader("User-Agent", "Mozilla/5.0");
        tx.AddRequestHeader("Accept", "*/*");
        tx.ProcessRequestHeaders();
        var it = tx.ProcessRequestBody();
        Assert.NotNull(it);
        Assert.Equal(949110, it.RuleId);
        Assert.Contains(tx.MatchedRules, m => m.Rule.Id == 942100);
    }

    [Fact]
    public void AllowsCleanRequest()
    {
        var waf = BuildCrs();
        using var tx = waf.NewTransaction();
        tx.ProcessConnection("127.0.0.1", 5000, "127.0.0.1", 80);
        tx.ProcessUri("/products?id=42&sort=price", "GET", "HTTP/1.1");
        tx.AddRequestHeader("Host", "localhost");
        tx.AddRequestHeader("User-Agent", "Mozilla/5.0");
        tx.AddRequestHeader("Accept", "text/html");
        Assert.Null(tx.ProcessRequestHeaders());
        Assert.Null(tx.ProcessRequestBody());
        Assert.DoesNotContain(tx.MatchedRules, m => m.Rule.Log);
    }
}
