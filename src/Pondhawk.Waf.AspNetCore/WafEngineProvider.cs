using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Pondhawk.Waf.AspNetCore;

/// <summary>
/// Holds the current <see cref="WafEngine"/> and the options it was built from. When the options change (for example
/// appsettings.json is edited) and <see cref="WafOptions.ReloadOnChange"/> is on, it builds a new engine in the
/// background and swaps it in. Requests in flight finish on the engine they started with. A configuration that fails
/// to build is logged and the current engine stays.
/// </summary>
public sealed class WafEngineProvider : IDisposable
{
    private readonly IOptionsMonitor<WafOptions> _monitor;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger _logger;
    private readonly IDisposable? _subscription;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private volatile WafSnapshot _current;
    private long _requested;
    private long _generation;

    public WafEngineProvider(IOptionsMonitor<WafOptions> monitor, ILoggerFactory loggerFactory)
    {
        _monitor = monitor;
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger("Pondhawk.Waf");
        var options = monitor.CurrentValue;
        _current = new WafSnapshot(WafServiceCollectionExtensions.CreateEngine(options, loggerFactory), options, options.Resolve(), 0);
        if (options.ReloadOnChange)
        {
            _subscription = monitor.OnChange(_ => OnChange());
        }
    }

    /// <summary>The engine for new requests.</summary>
    public WafEngine Current => _current.Engine;

    /// <summary>The engine, the options it was built from, and their resolved settings. Read once per request.</summary>
    public WafSnapshot Snapshot => _current;

    /// <summary>Waits this long after a change before rebuilding, so a burst of file change events builds once.</summary>
    internal TimeSpan ReloadDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Raised after a new engine is swapped in.</summary>
    public event EventHandler<WafSnapshot>? Reloaded;

    /// <summary>Raised when a changed configuration fails to build; the current engine stays.</summary>
    public event EventHandler<Exception>? ReloadFailed;

    public void Dispose()
    {
        _subscription?.Dispose();
        _gate.Dispose();
    }

    private void OnChange()
    {
        var request = Interlocked.Increment(ref _requested);
        _ = Task.Run(() => RebuildAsync(request));
    }

    private async Task RebuildAsync(long request)
    {
        await Task.Delay(ReloadDelay).ConfigureAwait(false);
        if (request != Interlocked.Read(ref _requested))
        {
            return; // A newer change follows; it rebuilds.
        }

        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (request != Interlocked.Read(ref _requested))
            {
                return;
            }

            var options = _monitor.CurrentValue;
            WafSnapshot snapshot;
            try
            {
                var settings = options.Resolve();
                var engine = WafServiceCollectionExtensions.CreateEngine(options, _loggerFactory);
                snapshot = new WafSnapshot(engine, options, settings, Interlocked.Increment(ref _generation));
            }
#pragma warning disable CA1031 // Any build failure keeps the running engine.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                WafLog.ReloadFailed(_logger, ex);
                ReloadFailed?.Invoke(this, ex);
                return;
            }

            _current = snapshot;
            WafLog.Reloaded(_logger, snapshot.Engine.Config.RuleEngine, options.Profile, snapshot.Settings.ParanoiaLevel,
                snapshot.Settings.DetectionParanoiaLevel, snapshot.Settings.InboundAnomalyScoreThreshold,
                snapshot.Settings.InspectResponses, snapshot.Engine.Rules.Count);
            if (snapshot.Engine.Config.RuleEngine != RuleEngineMode.On)
            {
                WafLog.NotBlocking(_logger, snapshot.Engine.Config.RuleEngine);
            }

            Reloaded?.Invoke(this, snapshot);
        }
        finally
        {
            _gate.Release();
        }
    }
}

/// <summary>An engine and the options it was built from.</summary>
/// <param name="Engine">The engine.</param>
/// <param name="Options">The options it was built from.</param>
/// <param name="Settings">The resolved profile settings.</param>
/// <param name="Generation">0 for the engine built at startup, then 1, 2, ... for each reload.</param>
public sealed record WafSnapshot(WafEngine Engine, WafOptions Options, WafSettings Settings, long Generation);
