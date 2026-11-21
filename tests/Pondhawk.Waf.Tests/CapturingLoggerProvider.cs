using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Pondhawk.Waf.Tests;

/// <summary>Keeps every log message by category. With <see cref="Throw"/>, Pondhawk.Waf.* loggers throw.</summary>
internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<(string Category, string Message)> _entries = new();

    public bool Throw { get; init; }

    public IReadOnlyList<string> Messages(string category) =>
        _entries.Where(e => e.Category == category).Select(e => e.Message).ToList();

    public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

    public void Dispose()
    {
    }

    private sealed class Logger(CapturingLoggerProvider provider, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (provider.Throw && category.StartsWith("Pondhawk.Waf.", StringComparison.Ordinal))
            {
                throw new IOException("log sink down");
            }

            provider._entries.Enqueue((category, formatter(state, exception)));
        }
    }
}
