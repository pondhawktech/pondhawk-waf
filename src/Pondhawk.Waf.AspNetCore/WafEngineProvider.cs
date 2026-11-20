using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace Pondhawk.Waf.AspNetCore;

/// <summary>
/// Holds the current <see cref="WafEngine"/> and the options it was built from. When the options change (for example
/// appsettings.json is edited) and <see cref="WafOptions.ReloadOnChange"/> is on, it builds a new engine in the
/// background and swaps it in. Requests in flight finish on the engine they started with. A configuration that fails
/// to build is logged and the current engine stays.
/// </summary>
public sealed class WafEngineProvider : IDisposable
{
    private readonly IOptionsFactory<WafOptions> _factory;
    private readonly ILoggerFactory _loggerFactory;
    private readonly WafMetrics _metrics;
    private readonly string? _contentRoot;
    private readonly ILogger _logger;
    private readonly List<IDisposable> _subscriptions = [];
    private readonly SemaphoreSlim _gate = new(1, 1);
    private volatile WafSnapshot _current;
    private long _requested;
    private long _generation;

    // Options are created here, not read from IOptionsMonitor: a configuration value that fails to bind (an unknown
    // enum name) must be logged like any other invalid configuration, and IOptionsMonitor throws it into the
    // configuration provider's change callback instead.
    public WafEngineProvider(
        IOptionsFactory<WafOptions> factory,
        IEnumerable<IOptionsChangeTokenSource<WafOptions>> changeSources,
        ILoggerFactory loggerFactory,
        WafMetrics metrics,
        IHostEnvironment? environment = null)
    {
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentNullException.ThrowIfNull(changeSources);
        ArgumentNullException.ThrowIfNull(loggerFactory);
        _factory = factory;
        _loggerFactory = loggerFactory;
        _metrics = metrics;
        _contentRoot = environment?.ContentRootPath;
        _logger = loggerFactory.CreateLogger("Pondhawk.Waf");
        var options = factory.Create(Options.DefaultName);
        _current = new WafSnapshot(WafServiceCollectionExtensions.CreateEngine(options, loggerFactory, metrics, _contentRoot), options, options.Resolve(), 0);
        if (options.ReloadOnChange)
        {
            foreach (var source in changeSources)
            {
                if (source.Name is null || source.Name == Options.DefaultName)
                {
                    _subscriptions.Add(ChangeToken.OnChange(source.GetChangeToken, OnChange));
                }
            }
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
        foreach (var subscription in _subscriptions)
        {
            subscription.Dispose();
        }

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

        try
        {
            await _gate.WaitAsync().ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
            return; // Shutting down.
        }

        try
        {
            if (request != Interlocked.Read(ref _requested))
            {
                return;
            }

            WafOptions options;
            WafSnapshot snapshot;
            try
            {
                options = _factory.Create(Options.DefaultName);
                var settings = options.Resolve();
                var engine = WafServiceCollectionExtensions.CreateEngine(options, _loggerFactory, _metrics, _contentRoot);

                // Swap in a fully built engine, so requests after a reload do not wait for regex automata.
                await engine.Compiled.ConfigureAwait(false);
                snapshot = new WafSnapshot(engine, options, settings, Interlocked.Increment(ref _generation));
            }
#pragma warning disable CA1031 // Any build failure keeps the running engine.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                _metrics.Reload(success: false);
                WafLog.ReloadFailed(_logger, ex);
                ReloadFailed?.Invoke(this, ex);
                return;
            }

            _current = snapshot;
            _metrics.Reload(success: true);
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
