using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Pondhawk.Waf.AspNetCore;

/// <summary>
/// Warns when the WAF services are registered but <c>UsePondhawkWaf</c> never added the middleware: the application
/// would then run unprotected and nothing else would say so. The check runs when the host has started, after the web
/// server built the request pipeline, so a middleware added in a branch (<c>Map</c>, <c>UseWhen</c>) counts too.
/// </summary>
internal sealed class WafStartupCheck(IHostApplicationLifetime lifetime, ILoggerFactory loggerFactory) : IHostedService, IDisposable
{
    private CancellationTokenRegistration _registration;
    private volatile bool _middlewareAdded;

    /// <summary>Called by <c>UsePondhawkWaf</c>.</summary>
    public void MiddlewareAdded() => _middlewareAdded = true;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _registration = lifetime.ApplicationStarted.Register(Check);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public void Dispose() => _registration.Dispose();

    private void Check()
    {
        if (!_middlewareAdded)
        {
            WafLog.MiddlewareMissing(loggerFactory.CreateLogger("Pondhawk.Waf"));
        }
    }
}
