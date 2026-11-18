using System.Reflection;
using Pondhawk.Waf.SecLang;

namespace Pondhawk.Waf.CoreRuleSet;

/// <summary>
/// The embedded OWASP Core Rule Set and the Pondhawk base configuration, exposed as a read-only file system:
/// <c>pondhawk-waf.conf</c>, <c>crs-setup.conf.example</c> and <c>rules/*.conf</c> / <c>rules/*.data</c>.
/// </summary>
public static class CoreRuleSetFiles
{
    private static readonly Lazy<IReadOnlyDictionary<string, string>> Files = new(Load);

    /// <summary>The CRS release embedded in this assembly.</summary>
    public static string Version => FileSystem.ReadAllText("VERSION").Trim();

    /// <summary>A file system over the embedded files.</summary>
    public static IConfigFileSystem FileSystem => new InMemoryConfigFileSystem(Files.Value);

    /// <summary>
    /// The directives that load the base configuration, the CRS setup and all CRS rules, in that order.
    /// Put tuning directives (paranoia level, exclusions) between <see cref="BaseDirectives"/> and <see cref="RuleDirectives"/>.
    /// </summary>
    public const string BaseDirectives = "Include pondhawk-waf.conf\nInclude crs-setup.conf.example";

    /// <summary>The directives that load all CRS rule files.</summary>
    public const string RuleDirectives = "Include rules/*.conf";

    private static IReadOnlyDictionary<string, string> Load()
    {
        var asm = typeof(CoreRuleSetFiles).Assembly;
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var name in asm.GetManifestResourceNames())
        {
            using var stream = asm.GetManifestResourceStream(name)!;
            using var reader = new StreamReader(stream);
            // MSBuild reports RecursiveDir with the OS separator; normalize to '/'.
            var path = name.Replace('\\', '/');
            if (path.StartsWith("crs/", StringComparison.Ordinal))
            {
                path = path[4..];
            }

            result[path] = reader.ReadToEnd();
        }

        return result;
    }
}
