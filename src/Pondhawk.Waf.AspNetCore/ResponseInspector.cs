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
/// <item>Inspectable bodies (SecResponseBodyAccess On, MIME type listed, not compressed) are held in memory up to
/// SecResponseBodyLimit; phase 4 runs before any byte is sent, so a match can still replace the response.</item>
/// <item>Other bodies run phase 4 without the body, then stream through unchanged.</item>
/// </list>
/// </summary>
internal sealed class ResponseInspector : Stream, IHttpResponseBodyFeature
{
    private readonly HttpContext _context;
    private readonly Transaction _tx;
    private readonly IHttpResponseBodyFeature _inner;
    private readonly MemoryStream _held = new();
    private PipeWriter? _writer;
    private State _state = State.NotStarted;

    public ResponseInspector(HttpContext context, Transaction tx, IHttpResponseBodyFeature inner)
    {
        _context = context;
        _tx = tx;
        _inner = inner;
    }

    private enum State
    {
        NotStarted,
        Holding,
        PassThrough,
        Blocked,
    }

    /// <summary>The interruption raised in phase 3 or 4, if any. The middleware writes the error response.</summary>
    public Interruption? Interruption { get; private set; }

    // ----- IHttpResponseBodyFeature -----

    Stream IHttpResponseBodyFeature.Stream => this;

    public PipeWriter Writer => _writer ??= PipeWriter.Create(this, new StreamPipeWriterOptions(leaveOpen: true));

    public void DisableBuffering()
    {
        // Inspected bodies must be held until phase 4 has run; other bodies are not buffered here anyway.
        if (_state == State.PassThrough)
        {
            _inner.DisableBuffering();
        }
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        BeginResponse();
        if (_state == State.PassThrough)
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
                _inner.Stream.Write(buffer);
                break;
            case State.Holding:
                var rest = Hold(buffer);
                if (_state == State.PassThrough)
                {
                    _inner.Stream.Write(_held.GetBuffer().AsSpan(0, (int)_held.Length));
                    _held.SetLength(0);
                    _inner.Stream.Write(rest.Span);
                }

                break;
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        BeginResponse();
        switch (_state)
        {
            case State.PassThrough:
                await _inner.Stream.WriteAsync(buffer, cancellationToken);
                break;
            case State.Holding:
                var rest = Hold(buffer.Span, buffer);
                if (_state == State.PassThrough)
                {
                    await FlushHeldAsync(cancellationToken);
                    await _inner.Stream.WriteAsync(rest, cancellationToken);
                }

                break;
        }
    }

    public override void Flush()
    {
        if (_state == State.PassThrough)
        {
            _inner.Stream.Flush();
        }
    }

    public override Task FlushAsync(CancellationToken cancellationToken) =>
        _state == State.PassThrough ? _inner.Stream.FlushAsync(cancellationToken) : Task.CompletedTask;

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    /// <summary>Called by the middleware after the application returned: runs pending phases and sends held bytes.</summary>
    public async Task FinishAsync()
    {
        BeginResponse();
        if (_state == State.Holding)
        {
            Interruption = _tx.ProcessResponseBody();
            if (Interruption is not null)
            {
                _state = State.Blocked;
                return;
            }

            _state = State.PassThrough;
            await FlushHeldAsync(_context.RequestAborted);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _held.Dispose();
        }

        base.Dispose(disposing);
    }

    // Phase 3, once, when the response starts. Decides whether the body is held for phase 4 or streamed.
    private void BeginResponse()
    {
        if (_state != State.NotStarted)
        {
            return;
        }

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
            _state = State.Holding;
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

    // Holds bytes for phase 4. Returns the bytes not accepted (ProcessPartial at the limit); the state then becomes
    // PassThrough, or Blocked when phase 4 interrupted.
    private ReadOnlyMemory<byte> Hold(ReadOnlySpan<byte> data, ReadOnlyMemory<byte> memory = default)
    {
        var (interruption, written) = _tx.WriteResponseBody(data);
        _held.Write(data[..written]);
        if (interruption is not null)
        {
            Interruption = interruption;
            _state = State.Blocked;
            return ReadOnlyMemory<byte>.Empty;
        }

        if (written < data.Length)
        {
            // The limit was reached and phase 4 ran on the first bytes (ProcessPartial): send the rest unseen.
            _state = State.PassThrough;
            return memory.IsEmpty ? data[written..].ToArray() : memory[written..];
        }

        return ReadOnlyMemory<byte>.Empty;
    }

    private async Task FlushHeldAsync(CancellationToken cancellationToken)
    {
        if (_held.Length > 0)
        {
            await _inner.Stream.WriteAsync(_held.GetBuffer().AsMemory(0, (int)_held.Length), cancellationToken);
            _held.SetLength(0);
        }
    }
}
