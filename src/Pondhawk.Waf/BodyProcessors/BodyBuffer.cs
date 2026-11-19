namespace Pondhawk.Waf.BodyProcessors;

/// <summary>
/// Buffers a request or response body for inspection. Data stays in memory up to the in-memory limit and spills to a
/// temporary file (deleted on dispose) after that. The caller enforces the total body limit.
/// </summary>
internal sealed class BodyBuffer(long inMemoryLimit, string? tempDirectory) : IDisposable
{
    private MemoryStream? _memory;
    private FileStream? _file;

    public long Length { get; private set; }

    /// <summary>Reserves memory for a body of the expected size (Content-Length), so the buffer does not grow by copying.</summary>
    public void Reserve(long expected)
    {
        if (_file is null && Length == 0 && expected > 0 && expected <= inMemoryLimit)
        {
            _memory ??= new MemoryStream((int)expected);
            if (_memory.Capacity < expected)
            {
                _memory.Capacity = (int)expected;
            }
        }
    }

    public void Write(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return;
        }

        _memory ??= new MemoryStream();
        if (_file is null && _memory.Length + data.Length > inMemoryLimit)
        {
            var dir = string.IsNullOrEmpty(tempDirectory) ? Path.GetTempPath() : tempDirectory;
            var path = Path.Combine(dir, "pondhawk-waf-" + Guid.NewGuid().ToString("N"));
            _file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 81920, FileOptions.DeleteOnClose);
            _memory.Position = 0;
            _memory.CopyTo(_file);
            _memory.Dispose();
            _memory = null;
        }

        if (_file is not null)
        {
            _file.Write(data);
        }
        else
        {
            _memory!.Write(data);
        }

        Length += data.Length;
    }

    /// <summary>
    /// The buffered bytes. In memory: a view of the buffer, valid until the next write or dispose. Spilled to a file:
    /// a new array.
    /// </summary>
    public ReadOnlyMemory<byte> ReadAll()
    {
        if (_file is null)
        {
            return _memory is null ? ReadOnlyMemory<byte>.Empty : _memory.GetBuffer().AsMemory(0, (int)_memory.Length);
        }

        var result = new byte[_file.Length];
        _file.Position = 0;
        _file.ReadExactly(result);
        return result;
    }

    public void Dispose()
    {
        _memory?.Dispose();
        _file?.Dispose();
    }
}
