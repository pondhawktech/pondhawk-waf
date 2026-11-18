using System.Globalization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pondhawk.Waf.AuditLog;
using Pondhawk.Waf.CoreRuleSet;
using Pondhawk.Waf.SecLang;

namespace Pondhawk.Waf.AspNetCore;

public static class WafServiceCollectionExtensions
{
    /// <summary>
    /// Registers the WAF engine as a singleton. By default it loads the embedded OWASP CRS in DetectionOnly mode.
    /// </summary>
    public static IServiceCollection AddPondhawkWaf(this IServiceCollection services, Action<WafOptions>? configure = null)
    {
        var optionsBuilder = services.AddOptions<WafOptions>();
        if (configure is not null)
        {
            optionsBuilder.Configure(configure);
        }

        services.AddSingleton(sp => CreateEngine(
            sp.GetRequiredService<IOptions<WafOptions>>().Value,
            sp.GetRequiredService<ILoggerFactory>()));
        return services;
    }

    /// <summary>
    /// Adds the WAF middleware. Place it early: after exception handling and forwarded headers, before routing,
    /// authentication and any middleware that reads the request body.
    /// </summary>
    public static IApplicationBuilder UsePondhawkWaf(this IApplicationBuilder app)
    {
        // Build the engine now so configuration errors fail startup, not the first request.
        _ = app.ApplicationServices.GetRequiredService<WafEngine>();
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

    internal static WafEngine CreateEngine(WafOptions options, ILoggerFactory loggerFactory)
    {
        var fs = new CompositeConfigFileSystem(CoreRuleSetFiles.FileSystem);
        var builder = new WafBuilder(fs);
        var errorLog = loggerFactory.CreateLogger("Pondhawk.Waf.Rules");
        var auditLog = loggerFactory.CreateLogger("Pondhawk.Waf.Audit");
        builder.Config.ErrorCallback = matched => WafLog.RuleMatched(errorLog, matched.ErrorLogLine());
        builder.Config.AuditLogWriter = new LoggerAuditLogWriter(auditLog);

        if (options.UseCoreRuleSet)
        {
            builder.AddDirectives(CoreRuleSetFiles.BaseDirectives);
        }

        var settings = options.Resolve();
        builder.AddDirectives(SettingsDirectives(settings, options.UseCoreRuleSet));

        if (options.RuleEngine is { } engine)
        {
            builder.Config.RuleEngine = engine;
        }

        if (!string.IsNullOrWhiteSpace(options.Directives))
        {
            builder.AddDirectives(options.Directives, Directory.GetCurrentDirectory());
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
            builder.AddDirectives(CoreRuleSetFiles.RuleDirectives);
        }

        if (!string.IsNullOrWhiteSpace(options.DirectivesAfterRules))
        {
            builder.AddDirectives(options.DirectivesAfterRules, Directory.GetCurrentDirectory());
        }

        foreach (var file in options.RuleFiles)
        {
            builder.AddFile(Path.GetFullPath(file));
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
            waf.WarmUp();
        }

        return waf;
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
}
