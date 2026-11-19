namespace Pondhawk.Waf.CoreRuleSet;

/// <summary>
/// The official CRS rule exclusion plugins embedded in this assembly. Each removes the false positives of one
/// application, on that application's paths only. Versions: <c>plugins/VERSIONS</c>.
/// </summary>
public enum CrsPlugin
{
    /// <summary>WordPress (wordpress-rule-exclusions-plugin).</summary>
    WordPress,

    /// <summary>Drupal (drupal-rule-exclusions-plugin).</summary>
    Drupal,

    /// <summary>Nextcloud (nextcloud-rule-exclusions-plugin).</summary>
    Nextcloud,

    /// <summary>DokuWiki (dokuwiki-rule-exclusions-plugin).</summary>
    DokuWiki,

    /// <summary>cPanel (cpanel-rule-exclusions-plugin).</summary>
    CPanel,

    /// <summary>phpBB (phpbb-rule-exclusions-plugin).</summary>
    PhpBB,

    /// <summary>phpMyAdmin (phpmyadmin-rule-exclusions-plugin).</summary>
    PhpMyAdmin,

    /// <summary>XenForo (xenforo-rule-exclusions-plugin).</summary>
    XenForo,
}

/// <summary>When a plugin file loads, relative to the CRS rules.</summary>
public enum CrsPluginStage
{
    /// <summary><c>*-config.conf</c>: after the CRS setup.</summary>
    Config,

    /// <summary><c>*-before.conf</c>: before the CRS rules.</summary>
    Before,

    /// <summary><c>*-after.conf</c>: after the CRS rules.</summary>
    After,
}
