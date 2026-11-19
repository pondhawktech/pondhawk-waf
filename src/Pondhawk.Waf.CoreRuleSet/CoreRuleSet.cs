using System.Reflection;
using Pondhawk.Waf.SecLang;

namespace Pondhawk.Waf.CoreRuleSet;

/// <summary>
/// The embedded OWASP Core Rule Set and the Pondhawk base configuration, exposed as a read-only file system:
/// <c>pondhawk-waf.conf</c>, <c>crs-setup.conf.example</c>, <c>rules/*.conf</c> / <c>rules/*.data</c> and
/// <c>plugins/*.conf</c>.
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

    /// <summary>The Pondhawk base configuration alone (engine settings and body processing), for use without CRS.</summary>
    public const string EngineDirectives = "Include pondhawk-waf.conf";

    /// <summary>
    /// The directive that loads one stage of a plugin (<c>Include plugins/wordpress-rule-exclusions-before.conf</c>),
    /// or null when the plugin has no file for that stage. Load the stages as CRS does: every plugin's
    /// <see cref="CrsPluginStage.Config"/> after the CRS setup, <see cref="CrsPluginStage.Before"/> before
    /// <see cref="RuleDirectives"/>, <see cref="CrsPluginStage.After"/> after it.
    /// </summary>
    public static string? PluginDirectives(CrsPlugin plugin, CrsPluginStage stage)
    {
        var path = $"plugins/{PluginName(plugin)}-{stage.ToString().ToLowerInvariant()}.conf";
        return Files.Value.ContainsKey(path) ? "Include " + path : null;
    }

    /// <summary>The plugin's name, as in its repository and file names: <c>wordpress-rule-exclusions</c>.</summary>
    public static string PluginName(CrsPlugin plugin) => plugin switch
    {
        CrsPlugin.WordPress => "wordpress-rule-exclusions",
        CrsPlugin.Drupal => "drupal-rule-exclusions",
        CrsPlugin.Nextcloud => "nextcloud-rule-exclusions",
        CrsPlugin.DokuWiki => "dokuwiki-rule-exclusions",
        CrsPlugin.CPanel => "cpanel-rule-exclusions",
        CrsPlugin.PhpBB => "phpbb-rule-exclusions",
        CrsPlugin.PhpMyAdmin => "phpmyadmin-rule-exclusions",
        CrsPlugin.XenForo => "xenforo-rule-exclusions",
        _ => throw new ArgumentOutOfRangeException(nameof(plugin), plugin, "Unknown CRS plugin."),
    };

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
