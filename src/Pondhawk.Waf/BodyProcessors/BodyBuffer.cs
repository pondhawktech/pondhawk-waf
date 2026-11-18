namespace Pondhawk.Waf.BodyProcessors;

/// <summary>
/// Buffers a request or response body for inspection. Data stays in memory up to the in-memory limit and spills to a
/// temporary file (deleted on dispose) after that. The caller enforces the total body limit.
/// </summary>
internal sealed class BodyBuffer(long inMemoryLimit, string? tempDirectory) : IDisposable
{
    private MemoryStream? _memory = new();
    private FileStream? _file;

    public long Length { get; private set; }

    public void Write(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return;
        }

        if (_file is null && _memory!.Length + data.Length > inMemoryLimit)
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

    public byte[] ReadAll()
    {
        if (_file is null)
        {
            return _memory!.ToArray();
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
