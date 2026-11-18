// Test drivers ported from libinjection-go (https://github.com/corazawaf/libinjection-go),
// sqli_test.go (TestSQLiDriver) and xss_test.go (TestXSSDriver).
// Copyright (c) 2022-Present, Coraza. BSD-3-Clause; see TestData/LICENSE-libinjection.txt.

using System.Text;

namespace Pondhawk.Waf.LibInjection.Tests;

/// <summary>Runs every libinjection-go tests/*.txt vector.</summary>
public class TestVectorTests
{
    public static TheoryData<string> Files()
    {
        var data = new TheoryData<string>();
        foreach (string path in Directory.GetFiles(TestSupport.TestDataDir, "test-*.txt").Order(StringComparer.Ordinal))
        {
            data.Add(Path.GetFileName(path));
        }

        return data;
    }

    [Fact]
    public void AllVectorFilesPresent()
    {
        Assert.Equal(503, Directory.GetFiles(TestSupport.TestDataDir, "test-*.txt").Length);
    }

    [Theory]
    [MemberData(nameof(Files))]
    public void Vector(string fileName)
    {
        string path = Path.Combine(TestSupport.TestDataDir, fileName);
        var data = TestSupport.ReadTestData(path);
        string input = data[TestSupport.SectionInput];
        string expected = data[TestSupport.SectionExpected];
        string actual;

        if (fileName.Contains("-sqli-", StringComparison.Ordinal))
        {
            actual = LibInjection.IsSqli(input, out string fp) ? fp : "";
        }
        else if (fileName.Contains("-folding-", StringComparison.Ordinal))
        {
            actual = Folding(input, SqliFlags.QuoteNone | SqliFlags.SqlAnsi);
        }
        else if (fileName.Contains("-tokens_mysql-", StringComparison.Ordinal))
        {
            actual = Tokens(input, SqliFlags.QuoteNone | SqliFlags.SqlMysql);
        }
        else if (fileName.Contains("-tokens-", StringComparison.Ordinal))
        {
            actual = Tokens(input, SqliFlags.QuoteNone | SqliFlags.SqlAnsi);
        }
        else if (fileName.Contains("-html5-", StringComparison.Ordinal))
        {
            actual = Html5(input);
        }
        else if (fileName.Contains("-xss-", StringComparison.Ordinal))
        {
            actual = LibInjection.IsXss(input) ? "1" : "0";
        }
        else
        {
            throw new InvalidOperationException($"unknown test file kind: {fileName}");
        }

        actual = TestSupport.GoTrimSpace(actual);
        Assert.True(expected == actual,
            $"FILE: ({fileName})\nINPUT: ({input})\nEXPECTED: ({expected})\nGOT: ({actual})");
    }

    private static string Folding(string input, int flags)
    {
        byte[] bytes = TestSupport.Bytes(input);
        var state = new SqliState(bytes, flags);
        int n = state.Fold();
        var sb = new StringBuilder();
        for (int i = 0; i < n; i++)
        {
            sb.Append(TestSupport.PrintToken(state.TokenVec[i])).Append('\n');
        }

        return sb.ToString();
    }

    private static string Tokens(string input, int flags)
    {
        byte[] bytes = TestSupport.Bytes(input);
        var state = new SqliState(bytes, flags);
        var sb = new StringBuilder();
        while (state.Tokenize())
        {
            sb.Append(TestSupport.PrintToken(state.CurrentToken)).Append('\n');
        }

        return sb.ToString();
    }

    private static string Html5(string input)
    {
        byte[] bytes = TestSupport.Bytes(input);
        var h5 = new H5State(bytes, Html5Flags.DataState);
        var sb = new StringBuilder();
        while (h5.Next())
        {
            sb.Append(TestSupport.PrintHtml5Token(h5)).Append('\n');
        }

        return sb.ToString();
    }
}
