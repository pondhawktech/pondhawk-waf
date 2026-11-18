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

        var ci = CultureInfo.InvariantCulture;
        if (options.ParanoiaLevel is < 1 or > 4)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "ParanoiaLevel must be 1-4.");
        }

        if (options.UseCoreRuleSet)
        {
            builder.AddDirectives(string.Create(ci, $"""
                SecAction "id:900000,phase:1,pass,t:none,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.30.0',setvar:tx.blocking_paranoia_level={options.ParanoiaLevel}"
                SecAction "id:900110,phase:1,pass,t:none,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.30.0',setvar:tx.inbound_anomaly_score_threshold={options.InboundAnomalyScoreThreshold}"
                """));
        }

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
