using System.Buffers;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace StorageScanner.Core;

public sealed class DuplicateGroup
{
    public DuplicateGroup(long size, string hash, List<FileEntry> files)
    {
        Size = size;
        Hash = hash;
        Files = files;
    }

    public long Size { get; }
    public string Hash { get; }
    public List<FileEntry> Files { get; }
    public int Count => Files.Count;
    public long WastedSize => Size * (Files.Count - 1);
    public string FirstName => Files[0].Name;
    public string ShortHash => Hash.Length > 16 ? Hash[..16] : Hash;
}

public sealed class DuplicateProgress
{
    private long _filesDone, _bytesDone, _errors;
    private string? _currentPath;

    public string Stage { get; private set; } = "";
    public long FilesTotal { get; private set; }
    public long BytesTotal { get; private set; }
    public long FilesDone => Interlocked.Read(ref _filesDone);
    public long BytesDone => Interlocked.Read(ref _bytesDone);
    public long Errors => Interlocked.Read(ref _errors);

    public string? CurrentPath
    {
        get => Volatile.Read(ref _currentPath);
        internal set => Volatile.Write(ref _currentPath, value);
    }

    internal void StartStage(string stage, long files, long bytes)
    {
        Stage = stage;
        FilesTotal = files;
        BytesTotal = bytes;
        Interlocked.Exchange(ref _filesDone, 0);
        Interlocked.Exchange(ref _bytesDone, 0);
    }

    internal void FileDone() => Interlocked.Increment(ref _filesDone);
    internal void AddBytes(long n) => Interlocked.Add(ref _bytesDone, n);
    internal void AddError() => Interlocked.Increment(ref _errors);
}

/// <summary>Recherche de doublons en 3 passes pour limiter les lectures (critique sur un partage réseau) :
/// 1) même taille, 2) empreinte des 64 premiers + 64 derniers Ko, 3) SHA-256 complet.
/// Les fichiers « en ligne uniquement » (OneDrive…) sont ignorés : les lire déclencherait leur téléchargement.</summary>
public static class DuplicateFinder
{
    private const int PartialChunk = 64 * 1024;
    private const int ReadBuffer = 1024 * 1024;

    public static Task<List<DuplicateGroup>> FindAsync(IReadOnlyList<FileEntry> candidates, long minSize,
        int parallelism, DuplicateProgress progress, CancellationToken ct)
        => Task.Run(() => Find(candidates, minSize, parallelism, progress, ct), ct);

    private static List<DuplicateGroup> Find(IReadOnlyList<FileEntry> candidates, long minSize,
        int parallelism, DuplicateProgress progress, CancellationToken ct)
    {
        var po = new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(parallelism, 1, 64), CancellationToken = ct };

        // Passe 1 : regroupement par taille
        var sameSize = candidates
            .Where(f => f.Size >= minSize && f.Size > 0 && !SafePath.IsCloudOnly(f.Attributes))
            .GroupBy(f => f.Size)
            .Where(g => g.Skip(1).Any())
            .SelectMany(g => g)
            .ToList();

        // Passe 2 : empreinte partielle
        progress.StartStage("Empreinte partielle", sameSize.Count, sameSize.Sum(f => Math.Min(f.Size, 2L * PartialChunk)));
        var partial = new ConcurrentDictionary<FileEntry, string>();
        Parallel.ForEach(sameSize, po, f =>
        {
            var h = TryHash(f, partialOnly: true, progress, ct);
            if (h is not null) partial[f] = h;
            progress.FileDone();
        });

        var result = new List<DuplicateGroup>();
        var needFull = new List<FileEntry>();
        foreach (var g in sameSize.Where(partial.ContainsKey).GroupBy(f => (f.Size, Hash: partial[f])))
        {
            if (!g.Skip(1).Any()) continue;
            // Fichier ≤ 128 Ko : l'empreinte partielle couvre déjà tout le contenu
            if (g.Key.Size <= 2L * PartialChunk)
                result.Add(new DuplicateGroup(g.Key.Size, g.Key.Hash, g.ToList()));
            else
                needFull.AddRange(g);
        }

        // Passe 3 : SHA-256 complet
        progress.StartStage("Empreinte complète", needFull.Count, needFull.Sum(f => f.Size));
        var full = new ConcurrentDictionary<FileEntry, string>();
        Parallel.ForEach(needFull, po, f =>
        {
            var h = TryHash(f, partialOnly: false, progress, ct);
            if (h is not null) full[f] = h;
            progress.FileDone();
        });

        foreach (var g in needFull.Where(full.ContainsKey).GroupBy(f => (f.Size, Hash: full[f])))
            if (g.Skip(1).Any())
                result.Add(new DuplicateGroup(g.Key.Size, g.Key.Hash, g.ToList()));

        foreach (var g in result) g.Files.Sort((a, b) => string.Compare(a.FullPath, b.FullPath, StringComparison.OrdinalIgnoreCase));
        return result.OrderByDescending(g => g.WastedSize).ToList();
    }

    private static string? TryHash(FileEntry f, bool partialOnly, DuplicateProgress progress, CancellationToken ct)
    {
        string path = f.FullPath;
        progress.CurrentPath = path;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(ReadBuffer);
        try
        {
            using var fs = new FileStream(SafePath.ForIo(path), new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = FileAccess.Read,
                Share = FileShare.ReadWrite | FileShare.Delete,
                BufferSize = 0,
                Options = FileOptions.SequentialScan,
            });
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            if (partialOnly && f.Size > 2L * PartialChunk)
            {
                int n = fs.ReadAtLeast(buffer.AsSpan(0, PartialChunk), PartialChunk, throwOnEndOfStream: false);
                hash.AppendData(buffer, 0, n);
                fs.Seek(-PartialChunk, SeekOrigin.End);
                int m = fs.ReadAtLeast(buffer.AsSpan(0, PartialChunk), PartialChunk, throwOnEndOfStream: false);
                hash.AppendData(buffer, 0, m);
                progress.AddBytes(n + m);
            }
            else
            {
                int n;
                while ((n = fs.Read(buffer, 0, ReadBuffer)) > 0)
                {
                    ct.ThrowIfCancellationRequested();
                    hash.AppendData(buffer, 0, n);
                    progress.AddBytes(n);
                }
            }
            return Convert.ToHexString(hash.GetHashAndReset());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            progress.AddError();
            return null;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
