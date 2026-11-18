// Tests ported from libinjection-go (https://github.com/corazawaf/libinjection-go),
// sqli_test.go, sqli_parity_test.go, sqli_quadratic_test.go and pool_test.go.
// Copyright (c) 2022-Present, Coraza. BSD-3-Clause; see TestData/LICENSE-libinjection.txt.

using System.Diagnostics;

namespace Pondhawk.Waf.LibInjection.Tests;

public class SqliTests
{
    [Fact]
    public void IsSqliSmoke()
    {
        bool result = LibInjection.IsSqli("-1' and 1=1 union/* foo */select load_file('/etc/passwd')--", out string fp);
        Assert.True(result);
        Assert.NotEmpty(fp);
        Assert.True(fp.Length <= 5);
    }

    [Fact]
    public void KeywordTableComplete()
    {
        Assert.Equal(SqliData.KeywordCount, SqliKeywords.Count);
    }

    [Theory]
    [InlineData(SqliFlags.QuoteSingle, (byte)'\'')]
    [InlineData(SqliFlags.QuoteDouble, (byte)'"')]
    [InlineData(SqliFlags.QuoteNone, (byte)0)]
    public void Flag2Delimiter(int flag, byte want)
    {
        Assert.Equal(want, SqliHelpers.Flag2Delimiter(flag));
    }

    [Fact]
    public void ResetWithZeroFlags()
    {
        var s = new SqliState("SELECT 1"u8, SqliFlags.QuoteNone | SqliFlags.SqlAnsi);
        s.Reset(0);
        Assert.Equal(SqliFlags.QuoteNone | SqliFlags.SqlAnsi, s.Flags);
    }

    [Theory]
    [InlineData("SELECT B0101")]
    [InlineData("SELECT b")]
    [InlineData("b'0x")]
    public void ParseBStringEarlyReturn(string input)
    {
        Assert.False(LibInjection.IsSqli(input, out string fp), $"fingerprint={fp}");
    }

    [Theory]
    [InlineData("Q'{hello}'", false)]
    [InlineData("Q'<hello>'", true)]
    [InlineData("q'{hello}'", false)]
    [InlineData("q'<hello>'", true)]
    [InlineData("Q'\u0001hello'", false)]
    public void ParseQStringCoreDelimiters(string input, bool wantSqli)
    {
        Assert.Equal(wantSqli, LibInjection.IsSqli(input, out _));
    }

    [Theory]
    [InlineData("1 UNION", false)]
    [InlineData("1 -- sp_password", true)]
    [InlineData("1+1/*comment*/", true)]
    [InlineData("1 /*comment*/", true)]
    public void NotWhitelistEdgeCases(string input, bool wantSqli)
    {
        Assert.Equal(wantSqli, LibInjection.IsSqli(input, out _));
    }

    private static SqliState MakeDirectState(ReadOnlySpan<byte> input)
    {
        var s = new SqliState(input, SqliFlags.QuoteNone | SqliFlags.SqlAnsi);
        s.SetFingerprint([SqliChars.TypeNumber, SqliChars.TypeComment]);
        s.StatsTokens = 2;
        s.TokenVec[0].Category = SqliChars.TypeNumber;
        s.TokenVec[0].Len = 1;
        s.TokenVec[1].Category = SqliChars.TypeComment;
        s.TokenVec[1].SetVal("-"u8);
        s.TokenVec[1].Len = 1;
        return s;
    }

    [Fact]
    public void NotWhitelistDirectStateDoubleDash()
    {
        var s = MakeDirectState("1--"u8);
        Assert.True(s.NotWhitelist());
    }

    [Fact]
    public void NotWhitelistDirectStateSingleDash()
    {
        var s = MakeDirectState("1-/"u8);
        Assert.False(s.NotWhitelist());
    }

    // sqli_parity_test.go: inputs whose verdict and fingerprint diverged from upstream C libinjection.
    [Theory]
    [InlineData("\t1/*", "1c", true)]
    [InlineData(" 0x1/*", "1c", true)]
    [InlineData("1/*", "1c", true)]
    [InlineData("1--", "1c", true)]
    [InlineData("1#x", "", false)]
    [InlineData("q'\u00E9' union /*!50000select*/ 1", "X", true)]
    [InlineData("-(top<>thendrop1.5\\'--null'--", "sc", true)]
    [InlineData("1 or 0x\u00001=1-- ", "1&1c", true)]
    [InlineData("'=0X\u0000#", "so1c", true)]
    [InlineData("=/Y2 \n'=c0\n0X\u0000#XY-b%\\`>Y `  %a*", "son1o", true)]
    [InlineData("0x\u00001", "", false)]
    [InlineData("@\u0000name", "", false)]
    public void UpstreamParity(string input, string fingerprint, bool detected)
    {
        bool got = LibInjection.IsSqli(input, out string fp);
        Assert.Equal((detected, fingerprint), (got, fp));
    }

    // sqli_quadratic_test.go (GHSA-974q-67pr-5pc2): string parsing must stay linear.
    [Theory]
    [InlineData("\\'")]
    [InlineData("''")]
    public void ParseStringLinear(string unit)
    {
        string payload = "'" + string.Concat(Enumerable.Repeat(unit, 500_000));
        var sw = Stopwatch.StartNew();
        LibInjection.IsSqli(payload, out _);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"took {sw.Elapsed}");
    }

    // pool_test.go: TestSQLiPoolReuse (here: no shared state between calls).
    [Fact]
    public void ConsecutiveCallsDoNotLeakState()
    {
        (string Input, bool IsSqli)[] cases =
        [
            ("1 UNION SELECT username, password FROM users--", true),
            ("hello world", false),
            ("1' AND 1=1--", true),
            ("user@example.com", false),
            ("1'; DROP TABLE users--", true),
            ("2024-01-15", false),
            ("1/**/UNION/**/SELECT/**/1,2,3--", true),
            ("The quick brown fox jumps over the lazy dog", false),
            ("1 UNION SELECT username, password FROM users--", true),
            ("1 UNION SELECT username, password FROM users--", true),
            ("hello world", false),
            ("hello world", false),
        ];

        foreach (var (input, isSqli) in cases)
        {
            Assert.True(isSqli == LibInjection.IsSqli(input, out _), input);
        }
    }

    // pool_test.go: TestPoolConcurrency (SQLi).
    [Fact]
    public void Concurrency()
    {
        Parallel.For(0, 50, worker =>
        {
            for (int i = 0; i < 200; i++)
            {
                Assert.True(LibInjection.IsSqli("1 UNION SELECT 1,2--", out _));
                Assert.False(LibInjection.IsSqli("hello world", out _));
            }
        });
    }
}
