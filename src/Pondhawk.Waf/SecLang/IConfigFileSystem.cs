namespace Pondhawk.Waf.SecLang;

/// <summary>Where SecLang configuration, Include targets and operator data files (@pmFromFile) are read from.</summary>
public interface IConfigFileSystem
{
    bool FileExists(string path);

    string ReadAllText(string path);

    /// <summary>Expands a path with '*' / '?' wildcards in the file name. Results are sorted ordinally.</summary>
    IReadOnlyList<string> Glob(string pattern);

    /// <summary>Combines a base directory with a relative path. Absolute paths are returned unchanged.</summary>
    string Combine(string directory, string path);

    string GetDirectoryName(string path);
}

/// <summary>The local file system.</summary>
public sealed class PhysicalConfigFileSystem : IConfigFileSystem
{
    public static PhysicalConfigFileSystem Instance { get; } = new();

    public bool FileExists(string path) => File.Exists(path);

    public string ReadAllText(string path) => File.ReadAllText(path);

    public IReadOnlyList<string> Glob(string pattern)
    {
        var dir = Path.GetDirectoryName(pattern);
        if (string.IsNullOrEmpty(dir))
        {
            dir = ".";
        }

        var filePattern = Path.GetFileName(pattern);
        if (!Directory.Exists(dir))
        {
            return [];
        }

        var files = Directory.GetFiles(dir, filePattern);
        Array.Sort(files, StringComparer.Ordinal);
        return files;
    }

    public string Combine(string directory, string path) =>
        Path.IsPathRooted(path) ? path : Path.GetFullPath(Path.Combine(directory, path));

    public string GetDirectoryName(string path) => Path.GetDirectoryName(path) ?? ".";
}

/// <summary>
/// An in-memory file system with '/'-separated paths. Used for embedded rule sets (e.g. the bundled OWASP CRS) and tests.
/// </summary>
public sealed class InMemoryConfigFileSystem(IReadOnlyDictionary<string, string> files) : IConfigFileSystem
{
    public bool FileExists(string path) => files.ContainsKey(Normalize(path));

    public string ReadAllText(string path) =>
        files.TryGetValue(Normalize(path), out var text) ? text : throw new FileNotFoundException("file not found", path);

    public IReadOnlyList<string> Glob(string pattern)
    {
        pattern = Normalize(pattern);
        var slash = pattern.LastIndexOf('/');
        var dir = slash < 0 ? string.Empty : pattern[..(slash + 1)];
        var name = slash < 0 ? pattern : pattern[(slash + 1)..];
        var regex = new System.Text.RegularExpressions.Regex(
            "^" + System.Text.RegularExpressions.Regex.Escape(name).Replace("\\*", "[^/]*", StringComparison.Ordinal).Replace("\\?", "[^/]", StringComparison.Ordinal) + "$");
        var result = files.Keys
            .Where(k => k.StartsWith(dir, StringComparison.Ordinal) && k.IndexOf('/', dir.Length) < 0 && regex.IsMatch(k[dir.Length..]))
            .ToList();
        result.Sort(StringComparer.Ordinal);
        return result;
    }

    public string Combine(string directory, string path)
    {
        if (path.StartsWith('/') || directory.Length == 0)
        {
            return Normalize(path);
        }

        return Normalize(directory.TrimEnd('/') + "/" + path);
    }

    public string GetDirectoryName(string path)
    {
        path = Normalize(path);
        var slash = path.LastIndexOf('/');
        return slash < 0 ? string.Empty : path[..slash];
    }

    private static string Normalize(string path)
    {
        var parts = new List<string>();
        foreach (var part in path.Replace('\\', '/').Split('/'))
        {
            if (part is "" or ".")
            {
                continue;
            }

            if (part == ".." && parts.Count > 0)
            {
                parts.RemoveAt(parts.Count - 1);
                continue;
            }

            parts.Add(part);
        }

        return string.Join('/', parts);
    }
}

/// <summary>
/// Rooted paths go to the physical file system; relative paths go to an embedded file system (e.g. the bundled CRS).
/// </summary>
public sealed class CompositeConfigFileSystem(IConfigFileSystem embedded) : IConfigFileSystem
{
    private static readonly PhysicalConfigFileSystem Physical = PhysicalConfigFileSystem.Instance;

    public bool FileExists(string path) => Pick(path).FileExists(path);

    public string ReadAllText(string path) => Pick(path).ReadAllText(path);

    public IReadOnlyList<string> Glob(string pattern) => Pick(pattern).Glob(pattern);

    public string Combine(string directory, string path)
    {
        if (Path.IsPathRooted(path))
        {
            return path;
        }

        return Path.IsPathRooted(directory) ? Physical.Combine(directory, path) : embedded.Combine(directory, path);
    }

    public string GetDirectoryName(string path) => Pick(path).GetDirectoryName(path);

    private IConfigFileSystem Pick(string path) => Path.IsPathRooted(path) ? Physical : embedded;
}
