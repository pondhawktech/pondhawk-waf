using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Pondhawk.Waf.AspNetCore;

/// <summary>
/// The response feature the application sees while the WAF inspects its response. Phase 3 reads the status and headers
/// when the response starts, but a held response does not reach the server until phase 4, so the server would still
/// accept changes. This feature makes the response behave as started from phase 3 on:
/// <list type="bullet">
/// <item>OnStarting callbacks registered by the application run before phase 3, in reverse order, as the server runs
/// them, so the headers they add are inspected (#19).</item>
/// <item>After phase 3, HasStarted is true, the status and headers are read-only, and OnStarting throws, as on a started
/// response. An exception handler outside the WAF therefore cannot write an error page over a response the
/// application already started (#20).</item>
/// </list>
/// Callbacks registered before the WAF ran stay with the server's feature and run when the server starts the response.
/// </summary>
internal sealed class InspectedResponseFeature(IHttpResponseFeature inner) : IHttpResponseFeature
{
    private List<(Func<object, Task> Callback, object State)>? _onStarting;
    private HeaderDictionary? _frozenHeaders;

    /// <summary>True once phase 3 has read the status and headers.</summary>
    public bool Started { get; private set; }

    public int StatusCode
    {
        get => inner.StatusCode;
        set
        {
            ThrowIfStarted();
            inner.StatusCode = value;
        }
    }

    public string? ReasonPhrase
    {
        get => inner.ReasonPhrase;
        set
        {
            ThrowIfStarted();
            inner.ReasonPhrase = value;
        }
    }

    public IHeaderDictionary Headers
    {
        get
        {
            if (!Started)
            {
                return inner.Headers;
            }

            // A read-only copy: the server's headers are what phase 3 inspected and what the client will get.
            return _frozenHeaders ??= new HeaderDictionary(inner.Headers.ToDictionary(StringComparer.OrdinalIgnoreCase)) { IsReadOnly = true };
        }

        set => throw new NotSupportedException("The WAF does not support replacing the response header dictionary.");
    }

    [Obsolete("Use IHttpResponseBodyFeature.Stream instead.")]
    public Stream Body
    {
        get => inner.Body;
        set => inner.Body = value;
    }

    public bool HasStarted => Started || inner.HasStarted;

    public void OnStarting(Func<object, Task> callback, object state)
    {
        ThrowIfStarted();
        (_onStarting ??= []).Add((callback, state));
    }

    public void OnCompleted(Func<object, Task> callback, object state) => inner.OnCompleted(callback, state);

    /// <summary>True when OnStarting callbacks are waiting to run.</summary>
    public bool HasOnStarting => _onStarting is { Count: > 0 };

    /// <summary>Runs the OnStarting callbacks, last registered first. A callback may register more; they run too.</summary>
    public async Task RunOnStartingAsync()
    {
        while (_onStarting is { Count: > 0 } callbacks)
        {
            _onStarting = null;
            for (var i = callbacks.Count - 1; i >= 0; i--)
            {
                await callbacks[i].Callback(callbacks[i].State).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Phase 3 is about to read the status and headers: from now on they cannot change.</summary>
    public void MarkStarted() => Started = true;

    private void ThrowIfStarted()
    {
        if (HasStarted)
        {
            throw new InvalidOperationException("The response has already started; the WAF has inspected its status and headers.");
        }
    }
}
