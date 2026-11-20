using System.IO.Pipelines;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Pondhawk.Waf.Text;

namespace Pondhawk.Waf.AspNetCore;

/// <summary>
/// Replaces the response body feature so the WAF sees the response before the client does.
/// <list type="bullet">
/// <item>Phase 3 (response headers) runs when the application starts the response: first write, StartAsync,
/// CompleteAsync, or return without a body.</item>
/// <item>Inspectable bodies (SecResponseBodyAccess On, MIME type listed, not compressed) are held up to
/// SecResponseBodyLimit; phase 4 runs before any byte is sent, so a match can still replace the response. The bytes are
/// held once, in the transaction's buffer, and sent from there.</item>
/// <item>In DetectionOnly, which cannot block, inspectable bodies stream to the client as they are written and a copy
/// goes to the transaction for phase 4 (unless <see cref="WafOptions.HoldResponsesInDetectionOnly"/>).</item>
/// <item>Other bodies run phase 4 without the body, then stream through unchanged.</item>
/// </list>
/// </summary>
internal sealed class ResponseInspector : Stream, IHttpResponseBodyFeature
{
    private readonly HttpContext _context;
    private readonly Transaction _tx;
    private readonly IHttpResponseBodyFeature _inner;
    private readonly InspectedResponseFeature _response;
    private readonly bool _holdInDetectionOnly;
    private PipeWriter? _writer;
    private State _state = State.NotStarted;

    // Held bytes (in the transaction's buffer) not yet sent.
    private bool _heldPending;

    public ResponseInspector(HttpContext context, Transaction tx, IHttpResponseBodyFeature inner, InspectedResponseFeature response, bool holdInDetectionOnly = false)
    {
        _context = context;
        _tx = tx;
        _inner = inner;
        _response = response;
        _holdInDetectionOnly = holdInDetectionOnly;
    }

    private enum State
    {
        NotStarted,

        /// <summary>Bytes are held for phase 4.</summary>
        Holding,

        /// <summary>Bytes go to the client and a copy to phase 4 (DetectionOnly).</summary>
        Streaming,

        /// <summary>Phase 4 ran; bytes go to the client uninspected.</summary>
        PassThrough,

        /// <summary>Phase 3 or 4 interrupted; bytes are dropped and the middleware writes the error response.</summary>
        Blocked,
    }

    /// <summary>True once phase 3 ran: the application can no longer change the status or headers.</summary>
    public bool ResponseStarted => _state != State.NotStarted;

    /// <summary>The interruption raised in phase 3 or 4, if any. The middleware writes the error response.</summary>
    public Interruption? Interruption { get; private set; }

    // ----- IHttpResponseBodyFeature -----

    Stream IHttpResponseBodyFeature.Stream => this;

    public PipeWriter Writer => _writer ??= PipeWriter.Create(this, new StreamPipeWriterOptions(leaveOpen: true));

    /// <summary>
    /// A streaming response (server-sent events, streamed JSON) asks for its writes to go out at once. Holding it until
    /// the application finishes would stall the client, so phase 4 runs on what is held now and the rest streams
    /// through uninspected, as with a response over the limit.
    /// </summary>
    public void DisableBuffering()
    {
        BeginResponse();
        if (_state == State.Holding)
        {
            Interruption = _tx.ProcessResponseBody();
            _state = Interruption is null ? State.PassThrough : State.Blocked;
        }

        if (_state is State.PassThrough or State.Streaming)
        {
            _inner.DisableBuffering();
        }
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        await BeginResponseAsync();
        if (_state is State.PassThrough or State.Streaming)
        {
            await _inner.StartAsync(cancellationToken);
        }
    }

    public Task SendFileAsync(string path, long offset, long? count, CancellationToken cancellationToken = default) =>
        SendFileFallback.SendFileAsync(this, path, offset, count, cancellationToken);

    public async Task CompleteAsync()
    {
        if (_writer is not null)
        {
            await _writer.FlushAsync();
        }

        await FinishAsync();
        if (_state == State.PassThrough)
        {
            await _inner.CompleteAsync();
        }
    }

    // ----- Stream -----

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        BeginResponse();
        switch (_state)
        {
            case State.PassThrough:
                FlushHeld();
                _inner.Stream.Write(buffer);
                break;
            case State.Streaming:
                Copy(buffer);
                if (_state != State.Blocked)
                {
                    _inner.Stream.Write(buffer);
                }

                break;
            case State.Holding:
                var written = Hold(buffer);
                if (_state == State.PassThrough)
                {
                    FlushHeld();
                    _inner.Stream.Write(buffer[written..]);
                }

                break;
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await BeginResponseAsync();
        switch (_state)
        {
            case State.PassThrough:
                await FlushHeldAsync(cancellationToken);
                await _inner.Stream.WriteAsync(buffer, cancellationToken);
                break;
            case State.Streaming:
                Copy(buffer.Span);
                if (_state != State.Blocked)
                {
                    await _inner.Stream.WriteAsync(buffer, cancellationToken);
                }

                break;
            case State.Holding:
                var written = Hold(buffer.Span);
                if (_state == State.PassThrough)
                {
                    await FlushHeldAsync(cancellationToken);
                    await _inner.Stream.WriteAsync(buffer[written..], cancellationToken);
                }

                break;
        }
    }

    public override void Flush()
    {
        if (_state is State.PassThrough or State.Streaming)
        {
            FlushHeld();
            _inner.Stream.Flush();
        }
    }

    public override async Task FlushAsync(CancellationToken cancellationToken)
    {
        if (_state is State.PassThrough or State.Streaming)
        {
            await FlushHeldAsync(cancellationToken);
            await _inner.Stream.FlushAsync(cancellationToken);
        }
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    /// <summary>Called by the middleware after the application returned: runs pending phases and sends held bytes.</summary>
    public async Task FinishAsync()
    {
        // Bytes the application wrote to BodyWriter (GetSpan/Advance) without flushing are still in the pipe.
        if (_writer is not null)
        {
            await _writer.FlushAsync(_context.RequestAborted);
        }

        await BeginResponseAsync();
        if (_state is State.Holding or State.Streaming)
        {
            Interruption = _tx.ProcessResponseBody();
            if (Interruption is not null)
            {
                // Streaming: bytes already sent; the middleware aborts the connection.
                _state = State.Blocked;
                return;
            }

            _state = State.PassThrough;
            await FlushHeldAsync(_context.RequestAborted);
        }
    }

    // Phase 3, once, when the response starts. The application's OnStarting callbacks run first, as the server would
    // run them, so the headers they add are inspected. A synchronous write waits for them, as the server does.
    private void BeginResponse()
    {
        if (_state != State.NotStarted)
        {
            return;
        }

        if (_response.HasOnStarting)
        {
            _response.RunOnStartingAsync().GetAwaiter().GetResult();
        }

        BeginResponseCore();
    }

    private async ValueTask BeginResponseAsync()
    {
        if (_state != State.NotStarted)
        {
            return;
        }

        if (_response.HasOnStarting)
        {
            await _response.RunOnStartingAsync();
        }

        BeginResponseCore();
    }

    // Decides whether the body is held, streamed with a copy, or streamed.
    private void BeginResponseCore()
    {
        // A callback that wrote to the body started the response already.
        if (_state != State.NotStarted)
        {
            return;
        }

        // From here the status and headers are read-only: they are what phase 3 inspects.
        _response.MarkStarted();
        var response = _context.Response;
        foreach (var header in response.Headers)
        {
            var name = ByteString.FromUtf16(header.Key);
            foreach (var value in header.Value)
            {
                _tx.AddResponseHeader(name, ByteString.FromUtf16(value));
            }
        }

        Interruption = _tx.ProcessResponseHeaders(response.StatusCode, _context.Request.Protocol);
        if (Interruption is not null)
        {
            _state = State.Blocked;
            return;
        }

        if (CanInspectBody(response))
        {
            if (response.ContentLength is { } length)
            {
                _tx.ReserveResponseBody(length);
            }

            // DetectionOnly cannot replace the response, so there is nothing to hold it for.
            _state = _tx.RuleEngine == RuleEngineMode.DetectionOnly && !_holdInDetectionOnly ? State.Streaming : State.Holding;
            return;
        }

        // Not inspected: run phase 4 without a body while the response can still be replaced.
        Interruption = _tx.ProcessResponseBody();
        _state = Interruption is null ? State.PassThrough : State.Blocked;
    }

    private bool CanInspectBody(HttpResponse response)
    {
        if (!_tx.IsResponseBodyProcessable || HttpMethods.IsHead(_context.Request.Method)
            || response.StatusCode is StatusCodes.Status204NoContent or StatusCodes.Status304NotModified)
        {
            return false;
        }

        // A compressed body cannot be matched against text rules. Place response compression outside the WAF.
        var encoding = response.Headers.ContentEncoding;
        return encoding.Count == 0 || encoding.All(e => string.IsNullOrEmpty(e) || e.Equals("identity", StringComparison.OrdinalIgnoreCase));
    }

    // Holds bytes in the transaction's buffer for phase 4. Returns how many were accepted; at the limit (ProcessPartial)
    // phase 4 has run on the held bytes and the state becomes PassThrough, or Blocked when phase 4 interrupted.
    private int Hold(ReadOnlySpan<byte> data)
    {
        var (interruption, written) = _tx.WriteResponseBody(data);
        _heldPending |= written > 0;
        if (interruption is not null)
        {
            Interruption = interruption;
            _state = State.Blocked;
            return data.Length;
        }

        if (written < data.Length)
        {
            _state = State.PassThrough;
        }

        return written;
    }

    // Streaming: copies bytes to the transaction for phase 4. Past the limit phase 4 has run on what was copied and
    // the rest streams uninspected. Interrupts only if a rule switched the transaction to On (ctl:ruleEngine).
    private void Copy(ReadOnlySpan<byte> data)
    {
        var (interruption, written) = _tx.WriteResponseBody(data);
        if (interruption is not null)
        {
            Interruption = interruption;
            _state = State.Blocked;
        }
        else if (written < data.Length)
        {
            _state = State.PassThrough;
        }
    }

    private void FlushHeld()
    {
        if (_heldPending)
        {
            _heldPending = false;
            _inner.Stream.Write(_tx.BufferedResponseBody.Span);
        }
    }

    private async Task FlushHeldAsync(CancellationToken cancellationToken)
    {
        if (_heldPending)
        {
            _heldPending = false;
            await _inner.Stream.WriteAsync(_tx.BufferedResponseBody, cancellationToken);
        }
    }
}
