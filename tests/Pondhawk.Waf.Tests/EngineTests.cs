using System.Text;
using Pondhawk.Waf.SecLang;

namespace Pondhawk.Waf.Tests;

public class EngineTests
{
    private static Transaction Run(WafEngine waf, string uri, string method = "GET", string? body = null, string? contentType = null, params (string, string)[] headers)
    {
        var tx = waf.NewTransaction();
        tx.ProcessConnection("10.0.0.1", 40000, "10.0.0.2", 80);
        tx.ProcessUri(uri, method, "HTTP/1.1");
        tx.AddRequestHeader("Host", "example.com");
        if (contentType is not null)
        {
            tx.AddRequestHeader("Content-Type", contentType);
        }

        foreach (var (k, v) in headers)
        {
            tx.AddRequestHeader(k, v);
        }

        if (tx.ProcessRequestHeaders() is null && body is not null)
        {
            tx.WriteRequestBody(Encoding.UTF8.GetBytes(body));
        }

        tx.ProcessRequestBody();
        return tx;
    }

    [Fact]
    public void DenyStopsWithStatusAndRuleId()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecRule ARGS:id "@rx ^\d+$" "id:1,phase:1,pass,nolog"
            SecRule ARGS "@contains attack" "id:2,phase:1,deny,status:406,log,msg:'bad %{MATCHED_VAR_NAME}'"
            """);
        using var tx = Run(waf, "/?id=1&q=attack");
        Assert.Equal(new Interruption(2, "deny", 406, null), tx.Interruption);
        Assert.Equal("bad ARGS:q", tx.MatchedRules.Single(m => m.Rule.Id == 2).Message);
    }

    [Fact]
    public void DetectionOnlyRecordsButDoesNotInterrupt()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine DetectionOnly
            SecRule ARGS "@contains attack" "id:2,phase:1,deny,log"
            """);
        using var tx = Run(waf, "/?q=attack");
        Assert.Null(tx.Interruption);
        Assert.NotNull(tx.DetectionOnlyInterruption);
        Assert.False(tx.MatchedRules.Single().Disruptive);
    }

    [Fact]
    public void BlockUsesTheDefaultDisruptiveAction()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecDefaultAction "phase:1,log,deny,status:418"
            SecRule ARGS "@contains x" "id:3,phase:1,block"
            """);
        using var tx = Run(waf, "/?a=x");
        Assert.Equal(418, tx.Interruption?.Status);
    }

    [Fact]
    public void VariableNegationCountAndRegexKeys()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecRule ARGS|!ARGS:safe "@contains evil" "id:10,phase:1,pass,log"
            SecRule &ARGS "@eq 3" "id:11,phase:1,pass,log"
            SecRule ARGS:/^user_/ "@streq root" "id:12,phase:1,pass,log"
            """);
        using var tx = Run(waf, "/?safe=evil&user_name=root&other=1");
        var ids = tx.MatchedRules.Select(m => m.Rule.Id).ToList();
        Assert.DoesNotContain(10, ids);
        Assert.Contains(11, ids);
        Assert.Contains(12, ids);
    }

    [Fact]
    public void ChainMatchesOnlyWhenAllLinksMatch()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRule REQUEST_METHOD "@streq POST" "id:20,phase:2,deny,chain"
                SecRule ARGS:role "@streq admin"
            """);
        using (var get = Run(waf, "/?role=admin"))
        {
            Assert.Null(get.Interruption);
        }

        using var post = Run(waf, "/", "POST", "role=admin", "application/x-www-form-urlencoded");
        Assert.Equal(20, post.Interruption?.RuleId);
    }

    [Fact]
    public void SetVarArithmeticAndAnomalyScoring()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecAction "id:30,phase:1,pass,nolog,setvar:tx.score=0,setvar:tx.critical=5"
            SecRule ARGS "@contains a" "id:31,phase:1,pass,nolog,setvar:'tx.score=+%{tx.critical}'"
            SecRule ARGS "@contains b" "id:32,phase:1,pass,nolog,setvar:tx.score=+3"
            SecRule TX:score "@ge 8" "id:33,phase:1,deny,log"
            """);
        using var tx = Run(waf, "/?x=a&y=b");
        Assert.Equal("8", tx.Variables.Tx.GetFirst("score"));
        Assert.Equal(33, tx.Interruption?.RuleId);
    }

    [Fact]
    public void SkipAfterJumpsToMarker()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecAction "id:40,phase:1,pass,nolog,skipAfter:END"
            SecRule ARGS "@unconditionalMatch" "id:41,phase:1,deny"
            SecMarker END
            SecRule ARGS "@unconditionalMatch" "id:42,phase:1,pass,log"
            """);
        using var tx = Run(waf, "/?a=1");
        Assert.Null(tx.Interruption);
        Assert.Contains(tx.MatchedRules, m => m.Rule.Id == 42);
    }

    [Fact]
    public void CtlRuleRemoveTargetByIdExcludesAnArgument()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecRule REQUEST_FILENAME "@streq /login" "id:50,phase:1,pass,nolog,ctl:ruleRemoveTargetById=51;ARGS:password"
            SecRule ARGS "@contains '" "id:51,phase:1,deny"
            """);
        using (var login = Run(waf, "/login?password=it's"))
        {
            Assert.Null(login.Interruption);
        }

        using var other = Run(waf, "/other?password=it's");
        Assert.Equal(51, other.Interruption?.RuleId);
    }

    [Fact]
    public void CaptureSetsTxVariables()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecRule ARGS:q "@rx (sel)(ect)" "id:60,phase:1,pass,log,capture,logdata:'%{TX.0}-%{TX.2}'"
            """);
        using var tx = Run(waf, "/?q=xselect");
        Assert.Equal("select-ect", tx.MatchedRules.Single().Data);
    }

    [Fact]
    public void JsonBodyIsFlattenedIntoArgs()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
            SecRule ARGS:json.user.tags.1 "@streq b" "id:70,phase:2,deny"
            """);
        using var tx = Run(waf, "/", "POST", """{"user":{"tags":["a","b"]}}""", "application/json");
        Assert.Equal(70, tx.Interruption?.RuleId);
        Assert.Equal("2", tx.Variables.ArgsPost.GetFirst("json.user.tags"));
    }

    [Fact]
    public void InvalidJsonSetsReqbodyError()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
            SecRule REQBODY_ERROR "!@eq 0" "id:2,phase:2,deny,status:400"
            """);
        using var tx = Run(waf, "/", "POST", """{"a": """, "application/json");
        Assert.Equal(400, tx.Interruption?.Status);
    }

    [Fact]
    public void XmlBodyDoesNotResolveExternalEntities()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRule REQUEST_HEADERS:Content-Type "xml" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=XML"
            SecRule XML:/* "@contains root:x" "id:2,phase:2,deny"
            """);
        const string xxe = """<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;<name>bob</name></r>""";
        using var tx = Run(waf, "/", "POST", xxe, "application/xml");

        // The undeclared entity is not expanded; the parser stops and flags the body, which REQBODY_ERROR rules reject.
        Assert.Null(tx.Interruption);
        Assert.Equal("1", tx.Variables.ReqbodyError.Value);
    }

    [Fact]
    public void MultipartKeepsBackslashesInNamesAndFindsFiles()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRule FILES "@rx \.\.\x5c" "id:80,phase:2,deny"
            """);
        const string body = "--XB\r\nContent-Disposition: form-data; name=\"f\"; filename=\"..\\..\\x.php\"\r\n\r\n<?php ?>\r\n--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--XB--\r\n";
        using var tx = Run(waf, "/upload", "POST", body, "multipart/form-data; boundary=XB");
        Assert.Equal(80, tx.Interruption?.RuleId);
        Assert.Equal("v", tx.Variables.ArgsPost.GetFirst("a"));
    }

    [Fact]
    public void RequestBodyOverLimitIsRejected()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRequestBodyLimit 10
            SecRequestBodyLimitAction Reject
            """);
        using var tx = waf.NewTransaction();
        tx.ProcessUri("/", "POST", "HTTP/1.1");
        tx.ProcessRequestHeaders();
        var (interruption, _) = tx.WriteRequestBody(new byte[11]);
        Assert.Equal(413, interruption?.Status);
    }

    [Fact]
    public void InvalidUriSetsParseError()
    {
        var waf = WafEngine.FromDirectives("""
            SecRuleEngine On
            SecRule URI_PARSE_ERROR "@eq 1" "id:1,phase:1,deny,status:400"
            """);
        using var tx = Run(waf, "/a%zz?x=1");
        Assert.Equal(400, tx.Interruption?.Status);
        Assert.Equal("1", tx.Variables.ArgsGet.GetFirst("x"));
    }

    [Theory]
    [InlineData("SecRule ARGS \"@rx x\" \"phase:1,pass\"", "rules must have an id")]
    [InlineData("SecFoo On", "unknown directive")]
    [InlineData("SecRule ARGS \"@nope x\" \"id:1\"", "unsupported operator")]
    [InlineData("SecRule ARGS \"@rx x\" \"id:1,t:nope\"", "unsupported transformation")]
    [InlineData("SecAction \"id:1,pass\"\nSecAction \"id:1,pass\"", "duplicated rule id")]
    public void ParserReportsErrors(string directives, string expected)
    {
        var ex = Assert.Throws<SecLangException>(() => WafEngine.FromDirectives(directives));
        Assert.Contains(expected, ex.Message, StringComparison.Ordinal);
    }
}
