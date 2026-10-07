using StorageScanner.Core;

namespace StorageScanner.UI;

/// <summary>Dossier sans aucune activité (fichier modifié, élément ajouté ou supprimé) depuis la date limite :
/// candidat à l'archivage.</summary>
public sealed class StaleFolder(DirNode node)
{
    public DirNode Node { get; } = node;
    public string Name => Node.Name;
    public string FullPath { get; } = node.FullPath;
    public long Size => Node.TotalSize;
    public long Files => Node.TotalFiles;
    public DateTime NewestUtc => StaleFolders.LastActivity(Node);
}

public static class StaleFolders
{
    private const int MaxResults = 5_000;
    private const long MinSize = 1024 * 1024;

    /// <summary>Dossiers les plus hauts de l'arborescence dont tout le contenu est plus ancien que la date limite
    /// (un dossier retenu n'est pas détaillé : ses sous-dossiers sont forcément inactifs eux aussi), du plus gros au
    /// plus petit. Les dossiers vides, inaccessibles ou de moins de 1 Mo sont ignorés.</summary>
    public static List<StaleFolder> Find(DirNode root, DateTime cutoffUtc)
    {
        var result = new List<StaleFolder>();
        var stack = new Stack<DirNode>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            if (n.Parent is not null && n.TotalFiles > 0 && n.NewestFileUtc != default && LastActivity(n) < cutoffUtc
                && n.TotalSize >= MinSize && !n.HasError)
            {
                result.Add(new StaleFolder(n));
                continue;
            }
            if (n.Children is { } ch) foreach (var c in ch) stack.Push(c);
        }
        result.Sort((a, b) => b.Size.CompareTo(a.Size));
        if (result.Count > MaxResults) result.RemoveRange(MaxResults, result.Count - MaxResults);
        return result;
    }

    /// <summary>Dernière activité connue : fichier le plus récent, ou date du dossier lui-même (création / suppression
    /// d'éléments). Sans elle, une archive extraite aujourd'hui dont les fichiers datent de 1980 paraîtrait inactive.</summary>
    public static DateTime LastActivity(DirNode n) => n.LastWriteUtc > n.NewestFileUtc ? n.LastWriteUtc : n.NewestFileUtc;
}
