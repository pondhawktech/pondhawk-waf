using System.Text;
using System.Text.RegularExpressions;
using Pondhawk.Waf.Operators;
using Pondhawk.Waf.Transformations;

namespace Pondhawk.Waf.Tests;

/// <summary>
/// The performance shortcuts must never change a result: the regex prefilter only rejects values the regex cannot
/// match, and a transformation's fast path only returns its input when the full transformation would not change it.
/// The CRS regression runner checks the prefilter on every request as well.
/// </summary>
public class PerformanceSafetyTests
{
    [Theory]
    [InlineData(@"(?i)select\s+from", 11, "select", "from")]
    [InlineData(@"foo|bar", 3, "foo|bar")]
    [InlineData(@"a(?:bc)?def", 4, "def")]
    [InlineData(@"(?:union|select)\s*\(", 6, "union|select")]
    [InlineData(@"-{2,}", 2, "--")]
    [InlineData(@"\x5cu[0-9a-f]{4}", 6, "\\u")]
    [InlineData(@"(?i:abc)xyz", 6, "abcxyz")]
    public void PrefilterRequiresWhatEveryMatchContains(string pattern, int minLength, params string[] sets)
    {
        var prefilter = RegexPrefilter.Create(pattern);
        Assert.NotNull(prefilter);
        Assert.Equal(minLength, prefilter.MinLength);
        Assert.Equal(sets.Order(), prefilter.Literals.Select(set => string.Join('|', set)).Order());
    }

    [Theory]
    [InlineData(@"foo(?=bar)")] // Lookahead.
    [InlineData(@"(a)\1")] // Backreference.
    [InlineData(@"(?x) a b c")] // Extended mode.
    [InlineData(@"\Qabc\E")] // Quoting.
    [InlineData(@"ab?")] // Too little to check.
    [InlineData(@"x{,3}y")] // Not a valid quantifier in RE2.
    public void PrefilterIsNotBuiltForWhatItDoesNotUnderstand(string pattern) =>
        Assert.Null(RegexPrefilter.Create(pattern));

    [Fact]
    public void PrefilterRejectsValuesWithoutTheLiterals()
    {
        var prefilter = RegexPrefilter.Create(@"(?i)\bunion\b.{1,100}?\bselect\b")!;
        Assert.False(prefilter.MightMatch("hello world, nothing to see here"));
        Assert.False(prefilter.MightMatch("union only"));
        Assert.True(prefilter.MightMatch("1 UNION ALL SeLeCt 2"));
    }

    // Random inputs built from the pattern's own literals, in random case and order, with noise between them: the
    // prefilter must accept every value the regex matches.
    [Theory]
    [InlineData(@"(?i)select\s+from")]
    [InlineData(@"(?i)(?:union|select)\s*\(")]
    [InlineData(@"foo|bar|ba")]
    [InlineData(@"(?i)<script[^>]*>")]
    [InlineData(@"(?:a|b)(?:cd|ef)+g?h")]
    [InlineData(@"(?i)on(?:error|load)\s*=")]
    [InlineData(@"\.\./|\.\.\\")]
    [InlineData(@"(?i)(?:\$\{|%\{)[^}]*jndi")]
    [InlineData(@"x{2,3}y")]
    [InlineData(@"(?i)a(?-i)b(?i)c")]
    public void PrefilterNeverRejectsAMatch(string pattern)
    {
        var prefilter = RegexPrefilter.Create(pattern);
        var regex = new RegexCache().Get(pattern);
        var pieces = Regex.Matches(pattern, "[A-Za-z]+|[^A-Za-z]").Select(m => m.Value).Append(" ").Append("(").Append("=").ToArray();
        var random = new Random(StableSeed(pattern));
        var matched = 0;
        for (var i = 0; i < 20_000; i++)
        {
            var sb = new StringBuilder();
            for (var n = random.Next(1, 8); n > 0; n--)
            {
                var piece = pieces[random.Next(pieces.Length)];
                sb.Append(random.Next(2) == 0 ? piece.ToUpperInvariant() : piece);
            }

            var value = sb.ToString();
            if (regex.IsMatch(value))
            {
                matched++;
                Assert.True(prefilter is null || prefilter.MightMatch(value), $"/{pattern}/ matches '{value}' but the prefilter rejected it");
            }
        }

        Assert.True(matched > 0, $"/{pattern}/ never matched; the test checked nothing");
    }

    public static TheoryData<string> FastPathTransformations => ["cmdLine", "replaceComments", "removeComments", "removeCommentsChar", "compressWhitespace", "removeWhitespace", "normalizePath"];

    [Theory]
    [MemberData(nameof(FastPathTransformations))]
    public void FastPathGivesTheFullResult(string name)
    {
        Func<string, string> full = name switch
        {
            "cmdLine" => Transforms.CmdLineCore,
            "replaceComments" => Transforms.ReplaceCommentsCore,
            "removeComments" => Transforms.RemoveCommentsCore,
            "removeCommentsChar" => Transforms.RemoveCommentsCharCore,
            "compressWhitespace" => Transforms.CompressWhitespaceCore,
            "removeWhitespace" => Transforms.RemoveWhitespaceCore,
            _ => Transforms.NormalizePathCore,
        };
        Assert.True(Transforms.TryGet(name, out var fast));
        string[] alphabet = ["a", "B", "z", "0", " ", "  ", "\t", "\n", "\r", "\v", "\f", "/", ".", "..", "*", "/*", "*/", "-", "--", "<!--", "-->", "#", "(", "\"", "'", "\\", "^", ",", ";", " ", "Â ", "Â\u0085", "é", "ÿ"];
        var random = new Random(StableSeed(name));
        for (var i = 0; i < 50_000; i++)
        {
            var sb = new StringBuilder();
            for (var n = random.Next(0, 10); n > 0; n--)
            {
                sb.Append(alphabet[random.Next(alphabet.Length)]);
            }

            var input = sb.ToString();
            Assert.Equal(full(input), fast(input));
        }
    }

    [Theory]
    [InlineData("cmdLine", "echo hello")]
    [InlineData("removeComments", "plain text")]
    [InlineData("compressWhitespace", "one two three")]
    [InlineData("removeWhitespace", "nospaces")]
    [InlineData("normalizePath", "/a/b/c.txt")]
    [InlineData("lowercase", "already lower")]
    [InlineData("urlDecodeUni", "no escapes")]
    public void UnchangedInputIsReturnedWithoutACopy(string name, string input)
    {
        Assert.True(Transforms.TryGet(name, out var transformation));
        Assert.Same(input, transformation(input));
    }

    // string.GetHashCode is randomized per process; a fixed seed makes every run test the same inputs.
    private static int StableSeed(string text)
    {
        var seed = 17;
        foreach (var c in text)
        {
            seed = unchecked((seed * 31) + c);
        }

        return seed;
    }
}
