using System.Text.Json;
using System.Text.Json.Serialization;
using Pondhawk.Waf.Text;

namespace Pondhawk.Waf.AuditLog;

/// <summary>Receives audit log entries (SecAuditEngine On / RelevantOnly).</summary>
public interface IAuditLogWriter
{
    void Write(AuditLogEntry entry);
}

/// <summary>A transaction summary for the audit log. Strings are display strings (UTF-8 decoded).</summary>
public sealed record AuditLogEntry(
    string TransactionId,
    DateTimeOffset Timestamp,
    string ClientAddress,
    string Method,
    string Uri,
    string Protocol,
    IReadOnlyDictionary<string, IReadOnlyList<string>> RequestHeaders,
    int? ResponseStatus,
    string RuleEngine,
    AuditLogInterruption? Interruption,
    IReadOnlyList<AuditLogMessage> Messages)
{
    /// <summary>Builds the entry from a finished transaction.</summary>
    public static AuditLogEntry From(Transaction tx)
    {
        var v = tx.Variables;
        var headers = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (_, list) in v.RequestHeaders.Entries)
        {
            foreach (var kv in list)
            {
                var name = ByteString.ToDisplay(kv.Key);
                if (!headers.TryGetValue(name, out var values))
                {
                    values = new List<string>();
                    headers[name] = values;
                }

                ((List<string>)values).Add(RedactedHeaders.Contains(name) ? "[redacted]" : ByteString.ToDisplay(kv.Value));
            }
        }

        var interruption = tx.Interruption ?? tx.DetectionOnlyInterruption;
        return new AuditLogEntry(
            tx.Id,
            DateTimeOffset.UtcNow,
            v.RemoteAddr.Value,
            v.RequestMethod.Value,
            ByteString.ToDisplay(v.RequestUriRaw.Value),
            v.RequestProtocol.Value,
            headers,
            int.TryParse(v.ResponseStatus.Value, System.Globalization.CultureInfo.InvariantCulture, out var status) ? status : null,
            tx.RuleEngine.ToString(),
            interruption is null ? null : new AuditLogInterruption(interruption.RuleId, interruption.Action, interruption.Status, tx.IsInterrupted),
            tx.MatchedRules
                .Where(m => m.Rule.Log || m.Rule.Audit)
                .Select(m => new AuditLogMessage(
                    m.Rule.LogId,
                    ByteString.ToDisplay(m.Message),
                    ByteString.ToDisplay(m.Data),
                    m.Rule.Severity.ToString(),
                    m.Rule.Tags,
                    m.Rule.File,
                    m.Rule.Line,
                    m.DisruptiveAction))
                .ToList());
    }

    /// <summary>Request headers whose values never go to the audit log (credentials and session tokens).</summary>
    public static readonly HashSet<string> RedactedHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "X-Auth-Token", "X-Csrf-Token", "X-Xsrf-Token",
    };

    public string ToJson() => JsonSerializer.Serialize(this, AuditLogJsonContext.Default.AuditLogEntry);
}

public sealed record AuditLogInterruption(int RuleId, string Action, int Status, bool Enforced);

public sealed record AuditLogMessage(int RuleId, string Message, string Data, string Severity, IReadOnlyList<string> Tags, string File, int Line, string? DisruptiveAction);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AuditLogEntry))]
internal sealed partial class AuditLogJsonContext : JsonSerializerContext;

/// <summary>Writes one JSON object per line to a <see cref="TextWriter"/>. Thread-safe.</summary>
public sealed class JsonLinesAuditLogWriter(TextWriter writer) : IAuditLogWriter
{
    private readonly Lock _lock = new();

    public void Write(AuditLogEntry entry)
    {
        var json = entry.ToJson();
        lock (_lock)
        {
            writer.WriteLine(json);
            writer.Flush();
        }
    }
}
