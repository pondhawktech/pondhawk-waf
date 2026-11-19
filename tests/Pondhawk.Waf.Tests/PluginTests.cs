using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Pondhawk.Waf.AspNetCore;
using Pondhawk.Waf.CoreRuleSet;

namespace Pondhawk.Waf.Tests;

public class PluginTests
{
    [Fact]
    public void EveryPluginHasConfigAndBeforeFiles()
    {
        foreach (var plugin in Enum.GetValues<CrsPlugin>())
        {
            Assert.NotNull(CoreRuleSetFiles.PluginDirectives(plugin, CrsPluginStage.Config));
            Assert.NotNull(CoreRuleSetFiles.PluginDirectives(plugin, CrsPluginStage.Before));
        }

        Assert.NotNull(CoreRuleSetFiles.PluginDirectives(CrsPlugin.PhpMyAdmin, CrsPluginStage.After));
        Assert.Null(CoreRuleSetFiles.PluginDirectives(CrsPlugin.WordPress, CrsPluginStage.After));
    }

    [Fact]
    public void PluginRulesLoadOnlyWhenSelected()
    {
        var without = WafServiceCollectionExtensions.CreateEngine(new WafOptions { WarmUp = false }, NullLoggerFactory.Instance);
        Assert.DoesNotContain(without.Rules, r => r.Id is >= 9507000 and <= 9507999);

        var options = new WafOptions { WarmUp = false };
        options.Plugins.Add(CrsPlugin.WordPress);
        options.Plugins.Add(CrsPlugin.WordPress);
        var with = WafServiceCollectionExtensions.CreateEngine(options, NullLoggerFactory.Instance);
        Assert.Contains(with.Rules, r => r.Id == 9507100);
        Assert.DoesNotContain(with.Rules, r => r.Id is >= 9508000 and <= 9508999);
    }

    [Fact]
    public void WordPressLoginPasswordIsNotInspected()
    {
        var options = new WafOptions { WarmUp = false, RuleEngine = RuleEngineMode.On };
        options.Plugins.Add(CrsPlugin.WordPress);
        var waf = WafServiceCollectionExtensions.CreateEngine(options, NullLoggerFactory.Instance);
        Assert.Null(Post(waf, "/wp-login.php", "log=admin&pwd=%3Cscript%3Ealert(1)%3C%2Fscript%3E"));
        Assert.NotNull(Post(waf, "/other.php", "log=admin&pwd=%3Cscript%3Ealert(1)%3C%2Fscript%3E"));
    }

    [Fact]
    public void PluginsNeedTheCoreRuleSet()
    {
        var options = new WafOptions { WarmUp = false, UseCoreRuleSet = false };
        options.Plugins.Add(CrsPlugin.Drupal);
        Assert.Throws<InvalidOperationException>(() => WafServiceCollectionExtensions.CreateEngine(options, NullLoggerFactory.Instance));
    }

    [Fact]
    public void FilesAreKeyedByFieldName()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRule FILES_NAMES:avatar "@streq avatar" "id:2,phase:2,pass,log"
            SecRule FILES_SIZES:avatar "@eq 5" "id:3,phase:2,pass,log"
            SecRule FILES:other "@rx ." "id:4,phase:2,pass,log"
            SecRule FILES:avatar "@streq a.php" "id:1,phase:2,deny,status:403"
            """);
        const string body = "--b\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"a.php\"\r\n\r\nhello\r\n--b--\r\n";
        using var tx = waf.NewTransaction();
        tx.ProcessUri("/upload", "POST", "HTTP/1.1");
        tx.AddRequestHeader("Content-Type", "multipart/form-data; boundary=b");
        tx.ProcessRequestHeaders();
        tx.WriteRequestBody(Encoding.ASCII.GetBytes(body));
        var it = tx.ProcessRequestBody();
        Assert.Equal(1, it?.RuleId);
        Assert.Contains(tx.MatchedRules, m => m.Rule.Id == 2);
        Assert.Contains(tx.MatchedRules, m => m.Rule.Id == 3);
        Assert.DoesNotContain(tx.MatchedRules, m => m.Rule.Id == 4);
    }

    private static Interruption? Post(WafEngine waf, string path, string body)
    {
        using var tx = waf.NewTransaction();
        tx.ProcessConnection("10.0.0.1", 40000, "10.0.0.2", 80);
        tx.ProcessUri(path, "POST", "HTTP/1.1");
        tx.AddRequestHeader("Host", "example.com");
        tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)");
        tx.AddRequestHeader("Accept", "text/html");
        tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        tx.ProcessRequestHeaders();
        tx.WriteRequestBody(Encoding.ASCII.GetBytes(body));
        return tx.ProcessRequestBody();
    }
}
