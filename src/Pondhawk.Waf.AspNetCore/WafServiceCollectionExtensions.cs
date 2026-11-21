using System.Globalization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pondhawk.Waf.AuditLog;
using Pondhawk.Waf.CoreRuleSet;
using Pondhawk.Waf.SecLang;

namespace Pondhawk.Waf.AspNetCore;

public static class WafServiceCollectionExtensions
{
    /// <summary>
    /// Registers the WAF. By default it loads the embedded OWASP CRS in DetectionOnly mode.
    /// </summary>
    public static IServiceCollection AddPondhawkWaf(this IServiceCollection services, Action<WafOptions>? configure = null)
    {
        var optionsBuilder = services.AddOptions<WafOptions>();
        if (configure is not null)
        {
            optionsBuilder.Configure(configure);
        }

        return AddCore(services);
    }

    /// <summary>
    /// Registers the WAF with options bound from a configuration section, for example
    /// <c>builder.Configuration.GetSection("Pondhawk:Waf")</c>. <paramref name="configure"/> runs after the binding, for
    /// values that configuration cannot hold (<see cref="WafOptions.Bypass"/>, <see cref="WafOptions.Configure"/>).
    /// When the configuration changes, the engine is rebuilt and swapped without a restart
    /// (<see cref="WafOptions.ReloadOnChange"/>).
    /// </summary>
    public static IServiceCollection AddPondhawkWaf(this IServiceCollection services, IConfiguration configuration, Action<WafOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var optionsBuilder = services.AddOptions<WafOptions>().Bind(configuration);
        if (configure is not null)
        {
            optionsBuilder.Configure(configure);
        }

        return AddCore(services);
    }

    private static IServiceCollection AddCore(IServiceCollection services)
    {
        services.AddMetrics();
        services.TryAddSingleton<WafMetrics>();
        services.TryAddSingleton<WafEngineProvider>();
        if (!services.Any(d => d.ServiceType == typeof(WafStartupCheck)))
        {
            services.AddSingleton<WafStartupCheck>();
            services.AddHostedService(sp => sp.GetRequiredService<WafStartupCheck>());
        }

        // The engine for new requests; it changes on reload, so resolve it when needed instead of keeping it.
        services.TryAddTransient(sp => sp.GetRequiredService<WafEngineProvider>().Current);
        return services;
    }

    /// <summary>
    /// Adds the WAF middleware. Place it early: after exception handling and forwarded headers, before routing,
    /// authentication and any middleware that reads the request body.
    /// </summary>
    public static IApplicationBuilder UsePondhawkWaf(this IApplicationBuilder app)
    {
        // Build the engine now so configuration errors fail startup, not the first request.
        var snapshot = app.ApplicationServices.GetRequiredService<WafEngineProvider>().Snapshot;
        var logger = app.ApplicationServices.GetRequiredService<ILoggerFactory>().CreateLogger("Pondhawk.Waf");
        var (waf, s) = (snapshot.Engine, snapshot.Settings);
        WafLog.Started(logger, waf.Config.RuleEngine, snapshot.Options.Profile, s.ParanoiaLevel, s.DetectionParanoiaLevel,
            s.InboundAnomalyScoreThreshold, s.InspectResponses, waf.Rules.Count);
        if (waf.Config.RuleEngine != RuleEngineMode.On)
        {
            WafLog.NotBlocking(logger, waf.Config.RuleEngine);
        }

        app.ApplicationServices.GetService<WafStartupCheck>()?.MiddlewareAdded();
        return app.UseMiddleware<WafMiddleware>();
    }

    /// <summary>
    /// The SecLang that applies resolved settings. Loaded after the base configuration and CRS setup, and before
    /// <see cref="WafOptions.Directives"/>, so per-path ctl rules and directives there still win.
    /// </summary>
    internal static string SettingsDirectives(WafSettings s, bool coreRuleSet)
    {
        var ci = CultureInfo.InvariantCulture;
        var sb = new System.Text.StringBuilder();
        if (coreRuleSet)
        {
            sb.AppendLine(string.Create(ci, $"SecAction \"id:900000,phase:1,pass,t:none,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.30.0',setvar:tx.blocking_paranoia_level={s.ParanoiaLevel}\""));
            sb.AppendLine(string.Create(ci, $"SecAction \"id:900001,phase:1,pass,t:none,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.30.0',setvar:tx.detection_paranoia_level={s.DetectionParanoiaLevel}\""));
            sb.AppendLine(string.Create(ci, $"SecAction \"id:900110,phase:1,pass,t:none,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.30.0',setvar:tx.inbound_anomaly_score_threshold={s.InboundAnomalyScoreThreshold},setvar:tx.outbound_anomaly_score_threshold={s.OutboundAnomalyScoreThreshold}\""));
        }

        sb.AppendLine(string.Create(ci, $"SecRequestBodyLimit {s.RequestBodyLimit}"));
        sb.AppendLine(string.Create(ci, $"SecRequestBodyNoFilesLimit {s.RequestBodyNoFilesLimit}"));
        sb.AppendLine(string.Create(ci, $"SecArgumentsLimit {s.ArgumentsLimit}"));
        sb.AppendLine(s.InspectResponses ? "SecResponseBodyAccess On" : "SecResponseBodyAccess Off");
        sb.AppendLine("SecResponseBodyMimeTypesClear");
        if (s.ResponseMimeTypes.Count > 0)
        {
            sb.AppendLine("SecResponseBodyMimeType " + string.Join(' ', s.ResponseMimeTypes));
        }

        sb.AppendLine(string.Create(ci, $"SecResponseBodyLimit {s.ResponseBodyLimit}"));
        return sb.ToString();
    }

    // Relative paths in Directives, DirectivesAfterRules (Include, @pmFromFile) and RuleFiles resolve against
    // contentRoot, the application's content root. The working directory is / under systemd and System32 for a
    // Windows service.
    internal static WafEngine CreateEngine(WafOptions options, ILoggerFactory loggerFactory, WafMetrics? metrics = null, string? contentRoot = null)
    {
        var root = contentRoot ?? Directory.GetCurrentDirectory();
        var fs = new CompositeConfigFileSystem(CoreRuleSetFiles.FileSystem);
        var builder = new WafBuilder(fs);
        var errorLog = loggerFactory.CreateLogger("Pondhawk.Waf.Rules");
        var auditLog = loggerFactory.CreateLogger("Pondhawk.Waf.Audit");
        builder.Config.ErrorCallback = matched => WafLog.RuleMatched(errorLog, matched.ErrorLogLine());
        builder.Config.AuditLogWriter = new LoggerAuditLogWriter(auditLog);
        if (metrics is not null)
        {
            builder.Config.LogFailureCallback = metrics.LogFailure;
        }

        // The base configuration (body access and processors, limits, the deny rules for unparsable bodies) applies
        // with or without CRS: without it, request bodies would not be inspected or limited at all.
        builder.AddDirectives(options.UseCoreRuleSet ? CoreRuleSetFiles.BaseDirectives : CoreRuleSetFiles.EngineDirectives);

        var settings = options.Resolve();
        builder.AddDirectives(SettingsDirectives(settings, options.UseCoreRuleSet));

        if (options.RuleEngine is { } engine)
        {
            builder.Config.RuleEngine = engine;
        }

        foreach (var exclusion in options.Exclusions)
        {
            exclusion.Validate();
        }

        var plugins = options.Plugins.Distinct().ToList();
        if (plugins.Count > 0 && !options.UseCoreRuleSet)
        {
            throw new InvalidOperationException("WafOptions.Plugins needs UseCoreRuleSet: the CRS plugins exclude CRS rules.");
        }

        // Plugin configuration before Directives, so a SecAction there overrides a plugin's default setting.
        AddPluginStage(builder, plugins, CrsPluginStage.Config);

        if (!string.IsNullOrWhiteSpace(options.Directives))
        {
            builder.AddDirectives(options.Directives, root);
        }

        var pathExclusions = WafExclusion.PathDirectives(options.Exclusions);
        if (pathExclusions.Length > 0)
        {
            builder.AddDirectives(pathExclusions);
        }

        if (options.UseCoreRuleSet)
        {
            // CRS rule 901500 answers every request with 500 when the detection paranoia level is below the blocking
            // level. A blocking level raised in Directives (setvar:tx.blocking_paranoia_level=N) would do that with the
            // profile's detection level, so raise the detection level to the blocking level here.
            builder.AddDirectives("""
                SecRule TX:detection_paranoia_level "@lt %{tx.blocking_paranoia_level}" \
                    "id:900002,phase:1,pass,t:none,nolog,setvar:'tx.detection_paranoia_level=%{tx.blocking_paranoia_level}'"
                """);
            AddPluginStage(builder, plugins, CrsPluginStage.Before);
            builder.AddDirectives(CoreRuleSetFiles.RuleDirectives);
            AddPluginStage(builder, plugins, CrsPluginStage.After);
        }

        if (!string.IsNullOrWhiteSpace(options.DirectivesAfterRules))
        {
            builder.AddDirectives(options.DirectivesAfterRules, root);
        }

        foreach (var file in options.RuleFiles)
        {
            builder.AddFile(Path.GetFullPath(file, root));
        }

        // After every rule: SecRuleUpdateTargetById needs the rule to exist.
        var staticExclusions = WafExclusion.StaticDirectives(options.Exclusions);
        if (staticExclusions.Length > 0)
        {
            builder.AddDirectives(staticExclusions);
        }

        // RuleEngine set in options wins over SecRuleEngine in loaded files.
        if (options.RuleEngine is { } finalEngine)
        {
            builder.Config.RuleEngine = finalEngine;
        }

        options.Configure?.Invoke(builder);
        var waf = builder.Build();
        if (options.WarmUp)
        {
            // In the background: the application starts serving while the regex automata build (WafEngine.Compiled).
            var log = loggerFactory.CreateLogger("Pondhawk.Waf");
            _ = Task.Run(() =>
            {
                try
                {
                    waf.WarmUp();
                }
#pragma warning disable CA1031 // A failed warm-up only costs latency; the engine still works.
                catch (Exception ex)
#pragma warning restore CA1031
                {
                    WafLog.WarmUpFailed(log, ex);
                }
            });
        }

        return waf;
    }

    private static void AddPluginStage(WafBuilder builder, List<CrsPlugin> plugins, CrsPluginStage stage)
    {
        foreach (var plugin in plugins)
        {
            if (CoreRuleSetFiles.PluginDirectives(plugin, stage) is { } include)
            {
                builder.AddDirectives(include);
            }
        }
    }
}

/// <summary>Writes audit log entries as JSON through <see cref="ILogger"/>.</summary>
public sealed class LoggerAuditLogWriter(ILogger logger) : IAuditLogWriter
{
    public void Write(AuditLogEntry entry) => WafLog.Audit(logger, entry.ToJson());
}

internal static partial class WafLog
{
    [LoggerMessage(EventId = 10, Level = LogLevel.Warning, Message = "{Line}")]
    public static partial void RuleMatched(ILogger logger, string line);

    [LoggerMessage(EventId = 11, Level = LogLevel.Information, Message = "{Entry}")]
    public static partial void Audit(ILogger logger, string entry);

    [LoggerMessage(EventId = 12, Level = LogLevel.Information, Message = "Pondhawk WAF started: rule engine {RuleEngine}, profile {Profile}, paranoia level {ParanoiaLevel} (detection {DetectionParanoiaLevel}), inbound threshold {InboundThreshold}, response inspection {InspectResponses}, {RuleCount} rules")]
    public static partial void Started(ILogger logger, RuleEngineMode ruleEngine, WafProfile profile, int paranoiaLevel, int detectionParanoiaLevel, int inboundThreshold, bool inspectResponses, int ruleCount);

    [LoggerMessage(EventId = 13, Level = LogLevel.Warning, Message = "Pondhawk WAF rule engine is {RuleEngine}: requests are inspected and logged but NOT blocked. Set WafOptions.RuleEngine = RuleEngineMode.On to block.")]
    public static partial void NotBlocking(ILogger logger, RuleEngineMode ruleEngine);

    [LoggerMessage(EventId = 14, Level = LogLevel.Information, Message = "Pondhawk WAF reloaded: rule engine {RuleEngine}, profile {Profile}, paranoia level {ParanoiaLevel} (detection {DetectionParanoiaLevel}), inbound threshold {InboundThreshold}, response inspection {InspectResponses}, {RuleCount} rules")]
    public static partial void Reloaded(ILogger logger, RuleEngineMode ruleEngine, WafProfile profile, int paranoiaLevel, int detectionParanoiaLevel, int inboundThreshold, bool inspectResponses, int ruleCount);

    [LoggerMessage(EventId = 15, Level = LogLevel.Error, Message = "Pondhawk WAF configuration changed but the new configuration is not valid; the current rules stay in force")]
    public static partial void ReloadFailed(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 16, Level = LogLevel.Warning, Message = "Pondhawk WAF warm-up failed; the first requests may be slower")]
    public static partial void WarmUpFailed(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 17, Level = LogLevel.Warning, Message = "Pondhawk WAF services are registered but the middleware is not: requests are NOT inspected. Call app.UsePondhawkWaf().")]
    public static partial void MiddlewareMissing(ILogger logger);
}
