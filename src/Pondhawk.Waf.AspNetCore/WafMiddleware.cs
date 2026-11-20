using System.Buffers;
using System.Globalization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;
using Pondhawk.Waf.Text;

namespace Pondhawk.Waf.AspNetCore;

/// <summary>
/// Runs every request through the WAF: phase 1 (request headers) and phase 2 (request body) before the application;
/// phase 3 (response headers) and phase 4 (response body) before the response reaches the client; phase 5 (logging)
/// at the end. A match in any of phases 1-4 replaces the response.
/// </summary>
public sealed partial class WafMiddleware(RequestDelegate next, WafEngineProvider engines, WafMetrics metrics, ILogger<WafMiddleware> logger)
{
    /// <summary>The key under which the transaction is stored in <see cref="HttpContext.Items"/>.</summary>
    public static readonly object TransactionKey = new();

    public async Task InvokeAsync(HttpContext context)
    {
        // One snapshot per request: a reload swaps the engine for new requests only.
        var snapshot = engines.Snapshot;
        if (snapshot.Options.Bypass?.Invoke(context) == true)
        {
            metrics.Bypassed();
            await next(context);
            return;
        }

        using var tx = snapshot.Engine.NewTransaction(context.TraceIdentifier);
        context.Items[TransactionKey] = tx;
        try
        {
            if (tx.IsRuleEngineOff)
            {
                await next(context);
                return;
            }

            var interruption = await ProcessRequestAsync(context, tx);
            if (interruption is not null)
            {
                await InterruptAsync(context, tx, interruption);
                return;
            }

            // Upgraded connections (WebSocket) bypass the body feature, so the wrapper only sees normal responses.
            // Do not skip on request headers: a client could send "Connection: Upgrade" to avoid inspection.
            var inner = context.Features.GetRequiredFeature<IHttpResponseBodyFeature>();
            var innerResponse = context.Features.GetRequiredFeature<IHttpResponseFeature>();
            var response = new InspectedResponseFeature(innerResponse);
            using var inspector = new ResponseInspector(context, tx, inner, response, snapshot.Options.HoldResponsesInDetectionOnly);
            context.Features.Set<IHttpResponseBodyFeature>(inspector);
            context.Features.Set<IHttpResponseFeature>(response);
            try
            {
                await next(context);
                await inspector.FinishAsync();
            }
            catch when (inspector.ResponseStarted && !innerResponse.HasStarted)
            {
                // The application started a response (phase 3 ran, nothing sent yet) and then failed. On a server
                // without the WAF the response would have started, so nothing outside could replace it. Abort, so an
                // exception handler outside the WAF cannot send an uninspected error page in its place.
                context.Abort();
                throw;
            }
            finally
            {
                context.Features.Set(inner);
                context.Features.Set(innerResponse);
            }

            if (inspector.Interruption is { } responseInterruption)
            {
                await InterruptAsync(context, tx, responseInterruption);
            }
        }
        finally
        {
            try
            {
                tx.ProcessLogging();
            }
#pragma warning disable CA1031 // A failing audit sink must not turn a served request into an error.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                tx.Waf.RecordLogFailure();
                try
                {
                    LogAuditFailure(logger, ex);
                }
#pragma warning disable CA1031
                catch (Exception)
#pragma warning restore CA1031
                {
                    // Already counted; nothing else can report it.
                }
            }

            metrics.Completed(tx);
        }
    }

    private static async Task<Interruption?> ProcessRequestAsync(HttpContext context, Transaction tx)
    {
        var request = context.Request;
        var connection = context.Connection;
        tx.ProcessConnection(
            connection.RemoteIpAddress?.ToString() ?? string.Empty,
            connection.RemotePort,
            connection.LocalIpAddress?.ToString() ?? string.Empty,
            connection.LocalPort);
        tx.SetServerName(ByteString.FromUtf16(request.Host.Host));

        var rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(rawTarget))
        {
            rawTarget = request.PathBase.Add(request.Path).ToUriComponent() + request.QueryString.ToUriComponent();
        }

        tx.ProcessUri(ByteString.FromUtf16(rawTarget), request.Method, request.Protocol);

        foreach (var header in request.Headers)
        {
            var name = ByteString.FromUtf16(header.Key);
            foreach (var value in header.Value)
            {
                tx.AddRequestHeader(name, ByteString.FromUtf16(value));
            }
        }

        var interruption = tx.ProcessRequestHeaders();
        if (interruption is not null)
        {
            return interruption;
        }

        if (tx.RequestBodyAccess && HasBody(request))
        {
            interruption = await ReadRequestBodyAsync(request, tx);
            if (interruption is not null)
            {
                return interruption;
            }
        }

        return tx.ProcessRequestBody();
    }

    // HTTP/2 and HTTP/3 requests can carry a body with neither Content-Length nor Transfer-Encoding, so ask the
    // server whether the request can have a body instead of inferring it from headers.
    private static bool HasBody(HttpRequest request)
    {
        if (request.ContentLength is { } length)
        {
            return length > 0;
        }

        return request.HttpContext.Features.Get<IHttpRequestBodyDetectionFeature>()?.CanHaveBody
               ?? request.Headers.TransferEncoding.Count > 0;
    }

    /// <summary>Buffers the body for inspection and rewinds it for the application.</summary>
    private static async Task<Interruption?> ReadRequestBodyAsync(HttpRequest request, Transaction tx)
    {
        // Reject early on a declared length over the limit: no need to read it.
        if (request.ContentLength is { } declared && tx.CheckDeclaredRequestBodyLength(declared) is { } rejected)
        {
            return rejected;
        }

        request.EnableBuffering(bufferThreshold: (int)Math.Min(tx.Waf.Config.RequestBodyInMemoryLimit, int.MaxValue), bufferLimit: long.MaxValue);
        var buffer = ArrayPool<byte>.Shared.Rent(16 * 1024);
        try
        {
            long total = 0;
            int read;
            while ((read = await request.Body.ReadAsync(buffer.AsMemory(0, buffer.Length), request.HttpContext.RequestAborted)) > 0)
            {
                total += read;
                var (it, written) = tx.WriteRequestBody(buffer.AsSpan(0, read));
                if (it is not null)
                {
                    return it;
                }

                if (written < read)
                {
                    // ProcessPartial: the limit was reached and the body was inspected; the rest is not read here.
                    break;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            request.Body.Position = 0;
        }

        return null;
    }

    private async Task InterruptAsync(HttpContext context, Transaction tx, Interruption interruption)
    {
        LogBlocked(logger, interruption.RuleId, interruption.Action, interruption.Status, tx.Id);
        if (interruption.Action == "drop")
        {
            context.Abort();
            return;
        }

        if (context.Response.HasStarted)
        {
            context.Abort();
            return;
        }

        // Not context.Response.Clear(): it would also reset the body feature. Nothing has been sent yet.
        context.Response.StatusCode = interruption.Status;
        context.Response.Headers.Clear();
        context.Features.Get<IHttpResponseFeature>()!.ReasonPhrase = null;
        tx.Variables.ResponseStatus.Set(interruption.Status.ToString(CultureInfo.InvariantCulture));
        if (interruption.Action == "redirect" && !string.IsNullOrEmpty(interruption.Data))
        {
            context.Response.Headers.Location = ByteString.ToDisplay(interruption.Data);
            return;
        }

        if (interruption.Status == StatusCodes.Status413PayloadTooLarge || interruption.Status >= 400)
        {
            // Do not let a client keep sending a body we refused.
            context.Response.Headers.Connection = "close";
        }

        await context.Response.CompleteAsync();
    }

    [LoggerMessage(EventId = 1, Level = LogLevel.Warning, Message = "Request blocked by WAF rule {RuleId} ({Action}, status {Status}), transaction {TransactionId}")]
    private static partial void LogBlocked(ILogger logger, int ruleId, string action, int status, string transactionId);

    [LoggerMessage(EventId = 2, Level = LogLevel.Error, Message = "WAF audit logging failed")]
    private static partial void LogAuditFailure(ILogger logger, Exception exception);
}
