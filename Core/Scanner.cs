using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Enumeration;
using System.Security;

namespace StorageScanner.Core;

public sealed class ScanOptions
{
    /// <summary>Nombre de threads d'énumération. Sur un partage UNC la latence réseau domine :
    /// 16 à 32 threads donnent généralement le meilleur débit.</summary>
    public int Threads { get; init; } = 16;
    public int TopFilesCount { get; init; } = 1000;
    /// <summary>Taille minimale des fichiers conservés pour la recherche de doublons.</summary>
    public long DuplicateMinSize { get; init; } = 1024 * 1024;
}

/// <summary>Compteurs mis à jour par les threads de scan et lus par l'interface.</summary>
public sealed class ScanProgress
{
    private long _files, _dirs, _bytes, _errors;
    private string? _currentPath;

    public long Files => Interlocked.Read(ref _files);
    public long Directories => Interlocked.Read(ref _dirs);
    public long Bytes => Interlocked.Read(ref _bytes);
    public long Errors => Interlocked.Read(ref _errors);

    public string? CurrentPath
    {
        get => Volatile.Read(ref _currentPath);
        internal set => Volatile.Write(ref _currentPath, value);
    }

    internal void AddDirectory(int files, long bytes)
    {
        Interlocked.Increment(ref _dirs);
        if (files == 0) return;
        Interlocked.Add(ref _files, files);
        Interlocked.Add(ref _bytes, bytes);
    }

    internal void AddError() => Interlocked.Increment(ref _errors);

    private long _suspects;
    public long Suspects => Interlocked.Read(ref _suspects);
    internal void AddSuspect() => Interlocked.Increment(ref _suspects);
}

public static class Scanner
{
    public static Task<ScanResult> ScanAsync(string rootPath, ScanOptions options, ScanProgress progress, CancellationToken ct)
        => Task.Factory.StartNew(() => Scan(rootPath, options, progress, ct),
            CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

    public static string NormalizeRoot(string path)
    {
        path = path.Trim().Trim('"').Replace('/', '\\');
        if (path.Length == 2 && path[1] == ':') return path + "\\";
        // Chemin absolu sans « .. » ni chemin relatif (dépendant du dossier courant)
        if (path.Length > 0 && !path.StartsWith(@"\\?\", StringComparison.Ordinal) && !Unc.IsServerOnly(path))
        {
            try { path = Path.GetFullPath(path); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { }
        }
        if (path.Length > 3) path = path.TrimEnd('\\');
        return path;
    }

    private static ScanResult Scan(string rootPath, ScanOptions options, ScanProgress progress, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var root = new DirNode(rootPath, null);
        var ctx = new ScanContext(ct);

        if (Unc.IsServerOnly(rootPath))
        {
            // « \\serveur » : chaque partage devient un dossier de premier niveau
            var shares = Unc.GetShares(rootPath);
            if (shares.Count == 0)
                throw new DirectoryNotFoundException($"Aucun partage accessible sur {rootPath}");
            root.Children = shares.Select(s => new DirNode(s, root)).ToList();
            progress.AddDirectory(0, 0);
            ctx.Pending = root.Children.Count;
            foreach (var share in root.Children) ctx.Queue.Add(share);
        }
        else
        {
            if (!Directory.Exists(SafePath.ForIo(rootPath)))
                throw new DirectoryNotFoundException($"Dossier introuvable ou inaccessible : {rootPath}");
            try { root.LastWriteUtc = Directory.GetLastWriteTimeUtc(SafePath.ForIo(rootPath)); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            ctx.Pending = 1;
            ctx.Queue.Add(root);
        }

        int threadCount = Math.Clamp(options.Threads, 1, 128);
        var workers = new Worker[threadCount];
        var threads = new Thread[threadCount];
        for (int i = 0; i < threadCount; i++)
        {
            var w = workers[i] = new Worker(ctx, options, progress);
            threads[i] = new Thread(w.Run) { IsBackground = true, Name = $"Scan-{i}" };
            threads[i].Start();
        }
        foreach (var t in threads) t.Join();

        Aggregate(root);

        long total = root.TotalSize;
        var ext = new Dictionary<string, (long Count, long Size)>(StringComparer.OrdinalIgnoreCase);
        foreach (var w in workers)
            foreach (var (key, acc) in w.Extensions)
            {
                ext.TryGetValue(key, out var cur);
                ext[key] = (cur.Count + acc.Count, cur.Size + acc.Size);
            }

        return new ScanResult
        {
            Root = root,
            TopFiles = workers.SelectMany(w => w.TopFiles)
                .OrderByDescending(f => f.Size)
                .Take(options.TopFilesCount)
                .ToList(),
            Extensions = ext
                .Select(kv => new ExtensionStat(kv.Key, kv.Value.Count, kv.Value.Size,
                    total > 0 ? kv.Value.Size * 100.0 / total : 0))
                .OrderByDescending(e => e.Size)
                .ToList(),
            DuplicateCandidates = workers.SelectMany(w => w.DuplicateCandidates).ToList(),
            Errors = workers.SelectMany(w => w.Errors).ToList(),
            Suspicious = workers.SelectMany(w => w.Suspicious)
                .OrderByDescending(s => s.Suspicion.Level)
                .ThenByDescending(s => s.Entry.Size)
                .ToList(),
            DuplicateMinSize = options.DuplicateMinSize,
            Duration = sw.Elapsed,
            Cancelled = ct.IsCancellationRequested,
        };
    }

    /// <summary>Calcule les totaux de bas en haut (parcours postfixe itératif, sans risque de débordement de pile).</summary>
    private static void Aggregate(DirNode root)
    {
        var stack = new Stack<(DirNode Node, bool Visited)>();
        stack.Push((root, false));
        while (stack.Count > 0)
        {
            var (n, visited) = stack.Pop();
            if (!visited)
            {
                stack.Push((n, true));
                if (n.Children is { } ch)
                {
                    ch.TrimExcess();
                    foreach (var c in ch) stack.Push((c, false));
                }
                continue;
            }

            long size = n.OwnFilesSize, files = n.OwnFileCount, dirs = 0;
            int suspects = n.OwnSuspects;
            var newest = n.OwnNewestFileUtc;
            if (n.Children is { } children)
            {
                foreach (var c in children)
                {
                    suspects += c.TotalSuspects;
                    size += c.TotalSize;
                    files += c.TotalFiles;
                    dirs += 1 + c.TotalDirs;
                    if (c.NewestFileUtc > newest) newest = c.NewestFileUtc;
                }
            }
            n.TotalSize = size;
            n.TotalFiles = files;
            n.TotalDirs = dirs;
            n.NewestFileUtc = newest;
            n.TotalSuspects = suspects;
        }
    }

    private sealed class ScanContext(CancellationToken ct)
    {
        // Pile (LIFO) : parcours en profondeur, la file reste petite même sur des arbres énormes.
        public readonly BlockingCollection<DirNode> Queue = new(new ConcurrentStack<DirNode>());
        public int Pending;
        public readonly CancellationToken Ct = ct;
    }

    private sealed class ExtAccumulator
    {
        public long Count;
        public long Size;
    }

    /// <summary>Thread de scan. Chaque worker garde ses propres statistiques (aucun verrou par fichier),
    /// fusionnées à la fin.</summary>
    private sealed class Worker
    {
        private const int MaxErrorsPerWorker = 20_000;
        private const string NoExtension = "(sans extension)";

        private static readonly EnumerationOptions s_enumOptions = new()
        {
            RecurseSubdirectories = false,
            IgnoreInaccessible = false,
            AttributesToSkip = 0,
            ReturnSpecialDirectories = false,
            BufferSize = 64 * 1024, // moins d'allers-retours SMB
        };

        private readonly ScanContext _ctx;
        private readonly ScanProgress _progress;
        private readonly int _topN;
        private readonly long _dupMin;
        private readonly FileSystemEnumerable<DirNode?>.FindTransform _transform;

        private readonly PriorityQueue<FileEntry, long> _top = new();
        private long _topMin = long.MaxValue;
        private readonly Dictionary<string, ExtAccumulator> _ext = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, ExtAccumulator>.AlternateLookup<ReadOnlySpan<char>> _extLookup;

        // État du dossier en cours
        private DirNode _cur = null!;
        private int _files;
        private long _bytes;
        private DateTime _newest;
        private DirContext _dirContext;
        private int _suspects;
        private const int MaxSuspectsPerWorker = 50_000;

        public Worker(ScanContext ctx, ScanOptions options, ScanProgress progress)
        {
            _ctx = ctx;
            _progress = progress;
            _topN = Math.Max(0, options.TopFilesCount);
            _dupMin = Math.Max(1, options.DuplicateMinSize);
            _transform = Transform;
            _extLookup = _ext.GetAlternateLookup<ReadOnlySpan<char>>();
        }

        public List<FileEntry> DuplicateCandidates { get; } = [];
        public List<ScanError> Errors { get; } = [];
        public List<SuspiciousFile> Suspicious { get; } = [];
        public IEnumerable<FileEntry> TopFiles => _top.UnorderedItems.Select(x => x.Element);
        public IEnumerable<(string Key, ExtAccumulator Acc)> Extensions => _ext.Select(kv => (kv.Key, kv.Value));

        public void Run()
        {
            try
            {
                foreach (var dir in _ctx.Queue.GetConsumingEnumerable(_ctx.Ct))
                {
                    List<DirNode>? children = null;
                    try
                    {
                        children = Process(dir);
                    }
                    catch (Exception ex)
                    {
                        dir.HasError = true;
                        AddError(dir.FullPath, SafePath.Display(ex.Message));
                    }

                    if (children is not null)
                    {
                        dir.Children = children;
                        int toQueue = 0;
                        foreach (var c in children) if (!c.IsReparsePoint) toQueue++;
                        // Incrémenter avant de décrémenter : Pending ne peut pas tomber à 0 tant qu'on empile.
                        Interlocked.Add(ref _ctx.Pending, toQueue);
                        foreach (var c in children) if (!c.IsReparsePoint) _ctx.Queue.Add(c);
                    }

                    if (Interlocked.Decrement(ref _ctx.Pending) == 0)
                        _ctx.Queue.CompleteAdding();
                }
            }
            catch (OperationCanceledException)
            {
            }
        }

        private List<DirNode>? Process(DirNode dir)
        {
            string path = dir.FullPath;
            _progress.CurrentPath = path;
            _cur = dir;
            _files = 0;
            _bytes = 0;
            _newest = default;
            _suspects = 0;
            _dirContext = DirContext.For(path); // une seule fois par dossier, pas par fichier

            List<DirNode>? children = null;
            try
            {
                var e = new FileSystemEnumerable<DirNode?>(SafePath.ForIo(path), _transform, s_enumOptions);
                foreach (var child in e)
                {
                    if (child is not null) (children ??= []).Add(child);
                    if (_ctx.Ct.IsCancellationRequested) break;
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or SecurityException)
            {
                dir.HasError = true;
                AddError(path, SafePath.Display(ex.Message));
            }

            dir.OwnFileCount = _files;
            dir.OwnFilesSize = _bytes;
            dir.OwnNewestFileUtc = _newest;
            dir.OwnSuspects = _suspects;
            _progress.AddDirectory(_files, _bytes);
            return children;
        }

        private DirNode? Transform(ref FileSystemEntry entry)
        {
            if (entry.IsDirectory)
            {
                return new DirNode(entry.FileName.ToString(), _cur)
                {
                    LastWriteUtc = entry.LastWriteTimeUtc.UtcDateTime,
                    IsReparsePoint = (entry.Attributes & FileAttributes.ReparsePoint) != 0,
                    Attributes = entry.Attributes,
                };
            }

            long size = entry.Length;
            var lastWrite = entry.LastWriteTimeUtc.UtcDateTime;
            _files++;
            _bytes += size;
            if (lastWrite > _newest) _newest = lastWrite;

            ReadOnlySpan<char> name = entry.FileName;

            // Statistiques par extension (lookup sur span : pas d'allocation par fichier)
            int dot = name.LastIndexOf('.');
            ReadOnlySpan<char> ext = dot >= 0 && dot < name.Length - 1 && name.Length - dot <= 16
                ? name[dot..]
                : NoExtension;
            if (!_extLookup.TryGetValue(ext, out var acc))
            {
                acc = new ExtAccumulator();
                _ext[ext.ToString().ToLowerInvariant()] = acc;
            }
            acc.Count++;
            acc.Size += size;

            // Le nom n'est alloué que si le fichier est retenu (top N ou candidat doublon)
            FileEntry? fe = null;
            if (_topN > 0)
            {
                if (_top.Count < _topN)
                {
                    fe = new FileEntry(_cur, name.ToString(), size, lastWrite, entry.Attributes);
                    _top.Enqueue(fe, size);
                    if (_top.Count == _topN) _top.TryPeek(out _, out _topMin);
                }
                else if (size > _topMin)
                {
                    fe = new FileEntry(_cur, name.ToString(), size, lastWrite, entry.Attributes);
                    _top.DequeueEnqueue(fe, size);
                    _top.TryPeek(out _, out _topMin);
                }
            }

            if (size >= _dupMin)
                DuplicateCandidates.Add(fe ??= new FileEntry(_cur, name.ToString(), size, lastWrite, entry.Attributes));

            // Indices de fichier malveillant (sans allocation pour un fichier ordinaire)
            var suspicion = SuspicionRules.Evaluate(_dirContext, _cur.FullPath, name, entry.Attributes);
            if (suspicion.IsSuspect)
            {
                _suspects++;
                _progress.AddSuspect();
                if (Suspicious.Count < MaxSuspectsPerWorker)
                    Suspicious.Add(new SuspiciousFile(fe ?? new FileEntry(_cur, name.ToString(), size, lastWrite, entry.Attributes), suspicion));
            }

            return null;
        }

        private void AddError(string path, string message)
        {
            _progress.AddError();
            if (Errors.Count < MaxErrorsPerWorker) Errors.Add(new ScanError(path, message));
        }
    }
}
