using System.Text;

namespace StorageScanner.Core;

/// <summary>Un dossier de l'arborescence scannée. Les fichiers ne sont pas stockés individuellement
/// (seulement agrégés) pour tenir plusieurs millions d'entrées en mémoire.</summary>
public sealed class DirNode
{
    public DirNode(string name, DirNode? parent)
    {
        Name = name;
        Parent = parent;
    }

    /// <summary>Nom du dossier ; pour la racine, le chemin complet.</summary>
    public string Name { get; }
    public DirNode? Parent { get; }
    public List<DirNode>? Children { get; internal set; }

    public long OwnFilesSize { get; internal set; }
    public int OwnFileCount { get; internal set; }
    public DateTime OwnNewestFileUtc { get; internal set; }
    public DateTime LastWriteUtc { get; internal set; }

    // Valeurs agrégées (dossier + sous-dossiers), calculées en fin de scan.
    public long TotalSize { get; internal set; }
    public long TotalFiles { get; internal set; }
    public long TotalDirs { get; internal set; }
    public DateTime NewestFileUtc { get; internal set; }

    /// <summary>Jonction / lien symbolique : listé mais non parcouru (évite les boucles et doubles comptes).</summary>
    public bool IsReparsePoint { get; internal set; }
    public bool HasError { get; internal set; }
    public FileAttributes Attributes { get; internal set; }

    /// <summary>Fichiers suspects directement dans ce dossier / dans toute la sous-arborescence.</summary>
    public int OwnSuspects { get; internal set; }
    public int TotalSuspects { get; internal set; }

    private SafetyLevel? _safety;
    /// <summary>Dossier système / à ne pas supprimer (calculé à la demande, pour les lignes affichées).</summary>
    public SafetyLevel Safety => _safety ??= StorageScanner.Core.Safety.ForDirectory(FullPath, Parent is null ? "" : Name, Attributes);

    public bool HasChildren => Children is { Count: > 0 };

    public string FullPath
    {
        get
        {
            if (Parent is null) return Name;
            var parts = new Stack<string>();
            DirNode n = this;
            while (n.Parent is not null)
            {
                parts.Push(n.Name);
                n = n.Parent;
            }
            var sb = new StringBuilder(n.Name.TrimEnd('\\'));
            foreach (var p in parts) sb.Append('\\').Append(p);
            return sb.ToString();
        }
    }
}

public sealed class FileEntry
{
    public FileEntry(DirNode dir, string name, long size, DateTime lastWriteUtc, FileAttributes attributes = 0)
    {
        Dir = dir;
        Name = name;
        Size = size;
        LastWriteUtc = lastWriteUtc;
        Attributes = attributes;
    }

    public DirNode Dir { get; }
    public string Name { get; }
    public long Size { get; }
    public DateTime LastWriteUtc { get; }
    public FileAttributes Attributes { get; }

    private SafetyLevel? _safety;
    public SafetyLevel Safety => _safety ??= StorageScanner.Core.Safety.ForFile(Dir.FullPath, Name, Attributes);
    // Jamais de logo Windows ni de triangle « à ne pas supprimer » sur un fichier suspect : ce serait un gage de confiance
    public bool IsSystem => Safety != SafetyLevel.Normal && !Suspicion.IsSuspect;
    public bool IsCritical => Safety == SafetyLevel.Critical && !Suspicion.IsSuspect;
    public string? SafetyText => IsSystem ? StorageScanner.Core.Safety.Describe(Safety) : null;

    private Suspicion? _suspicion;
    public Suspicion Suspicion => _suspicion ??= SuspicionRules.Evaluate(DirContext.For(Dir.FullPath), Dir.FullPath, Name, Attributes);
    public bool IsSuspectDanger => Suspicion.Level == SuspicionLevel.Danger;
    public bool IsSuspectWarning => Suspicion.Level == SuspicionLevel.Warning;
    public string? SuspicionText => Suspicion.IsSuspect
        ? Loc.F("suspicionTip", SuspicionRules.LevelText(Suspicion.Level), SuspicionRules.Describe(Suspicion.Reasons))
        : null;

    public string DirectoryPath => Dir.FullPath;
    public string FullPath => Path.Join(Dir.FullPath, Name);
    public string Extension => Path.GetExtension(Name).ToLowerInvariant();
}

public sealed class ExtensionStat
{
    public ExtensionStat(string extension, long count, long size, double percent)
    {
        Extension = extension;
        Count = count;
        Size = size;
        Percent = percent;
    }

    public string Extension { get; }
    public long Count { get; }
    public long Size { get; }
    public double Percent { get; }
    public long AverageSize => Count == 0 ? 0 : Size / Count;
}

public sealed record ScanError(string Path, string Message);

/// <summary>Fichier repéré comme potentiellement malveillant pendant le scan.</summary>
public sealed class SuspiciousFile(FileEntry entry, Suspicion suspicion)
{
    public FileEntry Entry { get; } = entry;
    public Suspicion Suspicion { get; } = suspicion;
    public string ReasonsText => SuspicionRules.Describe(Suspicion.Reasons);
}

public sealed class ScanResult
{
    public required DirNode Root { get; init; }
    public required IReadOnlyList<FileEntry> TopFiles { get; init; }
    public required IReadOnlyList<ExtensionStat> Extensions { get; init; }
    public required IReadOnlyList<FileEntry> DuplicateCandidates { get; init; }
    public required IReadOnlyList<ScanError> Errors { get; init; }
    public required IReadOnlyList<SuspiciousFile> Suspicious { get; init; }
    public required long DuplicateMinSize { get; init; }
    public required TimeSpan Duration { get; init; }
    public required bool Cancelled { get; init; }
}
