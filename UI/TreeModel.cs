using System.Windows;
using System.Windows.Media;
using StorageScanner.Core;

namespace StorageScanner.UI;

public enum RowKind { Folder, Files }

public enum TreeSortMode { NameWindows, Size, Files, Date }

/// <summary>Une ligne affichée de l'arborescence (vue « aplatie » et virtualisée).</summary>
public sealed class TreeRow : ObservableObject
{
    private static readonly Brush FolderBrush = Frozen("#E8A93B");
    private static readonly Brush FilesBrush = Frozen("#5B7FA6");
    private static readonly Brush LinkBrush = Frozen("#8A8A8A");
    private static readonly Brush ErrorBrush = Frozen("#D9534F");

    private readonly long _parentTotal;
    private bool _isExpanded;

    public TreeRow(DirNode node, int depth, RowKind kind, long parentTotal)
    {
        Node = node;
        Depth = depth;
        Kind = kind;
        _parentTotal = parentTotal;
    }

    public DirNode Node { get; }
    public int Depth { get; }
    public RowKind Kind { get; }
    public bool IsFilesRow => Kind == RowKind.Files;

    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (Set(ref _isExpanded, value)) OnPropertyChanged(nameof(ExpanderGlyph));
        }
    }

    public bool CanExpand => Kind == RowKind.Folder && (Node.HasChildren || Node.OwnFileCount > 0);

    public string ExpanderGlyph => !CanExpand ? "" : IsExpanded ? "\xE70D" : "\xE76C";

    /// <summary>Libellé de remplacement (racine d'un lecteur mappé : « U:\ (\\serveur\partage) »).</summary>
    public string? DisplayName { get; init; }

    public string Name => IsFilesRow ? $"[{Node.OwnFileCount:N0} fichier(s)]" : DisplayName ?? Node.Name;
    public long Size => IsFilesRow ? Node.OwnFilesSize : Node.TotalSize;
    public long Files => IsFilesRow ? Node.OwnFileCount : Node.TotalFiles;
    public long? Dirs => IsFilesRow ? null : Node.TotalDirs;
    public DateTime ModifiedUtc => IsFilesRow ? Node.OwnNewestFileUtc : Node.NewestFileUtc;

    /// <summary>Pour la racine : occupation réelle du volume / quota (renseignée par le modèle).</summary>
    public double? RootPercent { get; init; }
    public string? RootInfo { get; init; }

    public double Percent => RootPercent ?? (_parentTotal > 0 ? Size * 100.0 / _parentTotal : 100);
    public string PercentText => $"{Percent:0.0} %";

    /// <summary>Vert / jaune / rouge selon la part occupée. La racine utilise les seuils d'un disque.</summary>
    public Brush PercentBrush => RootPercent.HasValue ? UsageColors.ForDisk(Percent) : UsageColors.ForShare(Percent);

    private bool _isFlashing;
    /// <summary>Mise en évidence temporaire après un clic sur la carte des volumes.</summary>
    public bool IsFlashing { get => _isFlashing; set => Set(ref _isFlashing, value); }

    public Thickness Indent => new(Depth * 16, 0, 0, 0);

    // Page, œil barré (dossier inaccessible), lien, dossier
    public string Icon => IsFilesRow ? "\xE7C3" : Node.HasError ? "\xED1A" : Node.IsReparsePoint ? "\xE71B" : "\xE8B7";
    public Brush IconBrush => IsFilesRow ? FilesBrush : Node.HasError ? ErrorBrush : Node.IsReparsePoint ? LinkBrush : FolderBrush;

    public string ToolTip => RootInfo is not null ? $"{FullPath}\n{RootInfo}"
        : Node.IsReparsePoint ? "Jonction / lien symbolique (non parcouru)"
        : Node.HasError ? "Dossier inaccessible : accès refusé ou erreur de lecture (voir l'onglet Erreurs)"
        : FullPath;

    public string FullPath => Node.FullPath;

    // Badges : logo Windows (système) / triangle (ne pas supprimer)
    public SafetyLevel Safety => IsFilesRow ? SafetyLevel.Normal : Node.Safety;
    public bool IsSystem => Safety != SafetyLevel.Normal; // un élément critique est aussi un élément système
    public bool IsCritical => Safety == SafetyLevel.Critical;
    public string? SafetyText => StorageScanner.Core.Safety.Describe(Safety);

    // Bouclier rouge : le dossier contient des fichiers suspects
    public int SuspectCount => IsFilesRow ? Node.OwnSuspects : Node.TotalSuspects;
    public bool IsSuspectDanger => SuspectCount > 0;
    public bool IsSuspectWarning => false;
    public string? SuspicionText => SuspectCount > 0
        ? $"⚠ ATTENTION : contient {SuspectCount:N0} fichier(s) potentiellement malveillant(s) — voir l'onglet Suspects"
        : null;

    private static Brush Frozen(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        b.Freeze();
        return b;
    }
}

/// <summary>Gère l'arborescence dépliable sous forme de liste plate (rapide même avec des
/// centaines de milliers de lignes, grâce à la virtualisation du DataGrid).</summary>
public sealed class TreeModel
{
    private readonly HashSet<DirNode> _expanded = [];
    private DirNode? _root;

    public BulkObservableCollection<TreeRow> Rows { get; } = new();
    public TreeSortMode SortMode { get; private set; } = TreeSortMode.NameWindows;

    private double? _rootPercent;
    private string? _rootInfo;
    private string? _rootDisplayName;

    /// <param name="rootPercent">Occupation réelle du volume (ou du quota) à afficher sur la ligne racine.</param>
    public void Load(DirNode root, double? rootPercent = null, string? rootInfo = null, string? rootDisplayName = null)
    {
        _root = root;
        _rootDisplayName = rootDisplayName;
        _rootPercent = rootPercent;
        _rootInfo = rootInfo;
        _expanded.Clear();
        _expanded.Add(root);
        Rebuild();
    }

    public void Clear()
    {
        _root = null;
        _expanded.Clear();
        Rows.ReplaceAll([]);
    }

    public void SetSort(TreeSortMode mode)
    {
        if (mode == SortMode) return;
        SortMode = mode;
        Rebuild();
    }

    public void Toggle(TreeRow row)
    {
        int idx = Rows.IndexOf(row);
        if (idx < 0) return;

        if (row.IsExpanded)
        {
            int end = idx + 1;
            while (end < Rows.Count && Rows[end].Depth > row.Depth) end++;
            row.IsExpanded = false;
            _expanded.Remove(row.Node);
            Rows.RemoveRange(idx + 1, end - idx - 1);
        }
        else if (row.CanExpand)
        {
            row.IsExpanded = true;
            _expanded.Add(row.Node);
            var list = new List<TreeRow>();
            AppendExpanded(row, list);
            Rows.InsertRange(idx + 1, list);
        }
    }

    /// <summary>Déplie tous les ancêtres d'un dossier et renvoie sa ligne.</summary>
    public TreeRow? Reveal(DirNode node)
    {
        if (_root is null) return null;
        for (var n = node.Parent; n is not null; n = n.Parent) _expanded.Add(n);
        Rebuild();
        foreach (var r in Rows)
            if (r.Kind == RowKind.Folder && ReferenceEquals(r.Node, node)) return r;
        return null;
    }

    private void Rebuild()
    {
        if (_root is null)
        {
            Rows.ReplaceAll([]);
            return;
        }
        var rootRow = new TreeRow(_root, 0, RowKind.Folder, _root.TotalSize) { IsExpanded = true, RootPercent = _rootPercent, RootInfo = _rootInfo, DisplayName = _rootDisplayName };
        var list = new List<TreeRow> { rootRow };
        AppendExpanded(rootRow, list);
        Rows.ReplaceAll(list);
    }

    private void AppendExpanded(TreeRow parent, List<TreeRow> output)
    {
        foreach (var child in BuildChildren(parent))
        {
            output.Add(child);
            if (child.Kind == RowKind.Folder && child.CanExpand && _expanded.Contains(child.Node))
            {
                child.IsExpanded = true;
                AppendExpanded(child, output);
            }
        }
    }

    private List<TreeRow> BuildChildren(TreeRow parent)
    {
        var node = parent.Node;
        int depth = parent.Depth + 1;
        var rows = new List<TreeRow>((node.Children?.Count ?? 0) + 1);
        if (node.Children is { } ch)
            foreach (var c in ch) rows.Add(new TreeRow(c, depth, RowKind.Folder, node.TotalSize));
        if (node.OwnFileCount > 0)
            rows.Add(new TreeRow(node, depth, RowKind.Files, node.TotalSize));
        rows.Sort(Compare);
        return rows;
    }

    private int Compare(TreeRow a, TreeRow b)
    {
        int c = SortMode switch
        {
            // Ordre de l'Explorateur : dossiers (tri naturel), puis les fichiers
            TreeSortMode.NameWindows => a.IsFilesRow != b.IsFilesRow ? (a.IsFilesRow ? 1 : -1) : 0,
            TreeSortMode.Size => b.Size.CompareTo(a.Size),
            TreeSortMode.Files => b.Files.CompareTo(a.Files),
            TreeSortMode.Date => b.ModifiedUtc.CompareTo(a.ModifiedUtc),
            _ => 0,
        };
        return c != 0 ? c : NaturalComparer.Instance.Compare(a.Name, b.Name);
    }
}
