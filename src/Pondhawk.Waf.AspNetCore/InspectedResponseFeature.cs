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
/// Code outside the WAF runs while the WAF sends the response on: a body feature that wraps the server's (response
/// compression sets Content-Encoding on its first write) and OnStarting callbacks registered before the WAF ran (security
/// headers), which the server runs when the WAF's write starts the response. They read this feature through
/// HttpContext, but they are not the application: during <see cref="EnterOuter"/> this feature passes everything to the
/// server's, as without the WAF. Phase 3 does not see their changes (#30, #31).
/// </summary>
internal sealed class InspectedResponseFeature(IHttpResponseFeature inner) : IHttpResponseFeature
{
    private List<(Func<object, Task> Callback, object State)>? _onStarting;
    private HeaderDictionary? _frozenHeaders;
    private int _outerCalls;

    /// <summary>True while the WAF calls the server's body feature: code outside the WAF runs.</summary>
    private bool Outer => _outerCalls > 0;

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
            if (!Started || Outer)
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

    public bool HasStarted => (Started && !Outer) || inner.HasStarted;

    public void OnStarting(Func<object, Task> callback, object state)
    {
        if (Outer)
        {
            inner.OnStarting(callback, state);
            return;
        }

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

    /// <summary>The WAF is about to call the server's body feature. Dispose the result when the call returns.</summary>
    public OuterCall EnterOuter()
    {
        _outerCalls++;
        return new OuterCall(this);
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

    internal readonly struct OuterCall(InspectedResponseFeature feature) : IDisposable
    {
        public void Dispose() => feature._outerCalls--;
    }
}
