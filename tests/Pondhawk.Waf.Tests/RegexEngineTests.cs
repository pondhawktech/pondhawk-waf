using System.Text.RegularExpressions;
using Pondhawk.Waf.Operators;
using Pondhawk.Waf.Rules;

namespace Pondhawk.Waf.Tests;

public class RegexEngineTests
{
    [Fact]
    public void AllCrsRegexesUseTheLinearTimeEngine()
    {
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
}
