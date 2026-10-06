using System.Collections.Concurrent;
using System.Globalization;
using System.IO.Enumeration;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using StorageScanner.Core;

namespace StorageScanner.UI;

public sealed class LegendItem(Brush brush, string name, string sizeText, string percentText)
{
    public Brush Brush { get; } = brush;
    public string Name { get; } = name;
    public string SizeText { get; } = sizeText;
    public string PercentText { get; } = percentText;
}

/// <summary>Carte des volumes : chaque rectangle a une surface proportionnelle à la taille du dossier
/// (algorithme « squarified »), avec l'ombrage en coussins de WinDirStat (van Wijk &amp; van de Wetering).
/// Le scan ne garde que des totaux par dossier ; les fichiers des blocs assez grands à l'écran sont
/// relus à la demande pour être dessinés individuellement.</summary>
public sealed class TreemapView : FrameworkElement
{
    // Paramètres de l'ombrage (proches de WinDirStat)
    private const double CushionHeight = 0.38;
    private const double ScaleFactor = 0.91;
    private const double Ambient = 0.18;
    private const double Diffuse = 1 - Ambient;
    private const double Brightness = 1.3;
    private const double MinCell = 2.5;          // en pixels physiques
    private const double DetailMinSide = 14;     // taille mini d'un bloc « fichiers » pour le détailler
    private const int MaxFetchPerPass = 300;
    private const int MaxFilesPerDir = 5000;
    private static readonly double Lx, Ly, Lz;

    private static readonly uint[] Palette =
    [
        0x5B93D6, 0xF28E2B, 0x59A14F, 0xE15759, 0x76B7B2, 0xEDC948,
        0xB07AA1, 0xFF9DA7, 0x9C755F, 0x6B9AC4, 0xD37295, 0x8CD17D,
    ];
    private const uint FilesColor = 0xA3A9B3;
    private const int LegendMax = 10;

    private static readonly Brush EmptyBg = Frozen(new SolidColorBrush(Color.FromRgb(0xF3, 0xF4, 0xF7)));
    private static readonly Brush HoverFill = Frozen(new SolidColorBrush(Color.FromArgb(55, 255, 255, 255)));
    private static readonly Pen HoverPen = Frozen(new Pen(Brushes.White, 1.5));
    private static readonly Pen SelectOuter = Frozen(new Pen(new SolidColorBrush(Color.FromRgb(0x11, 0x18, 0x27)), 3));
    private static readonly Pen SelectInner = Frozen(new Pen(Brushes.White, 1.5));

    static TreemapView()
    {
        double len = Math.Sqrt(1 + 1 + 100);
        Lx = -1 / len;
        Ly = -1 / len;
        Lz = 10 / len;
    }

    private readonly DispatcherTimer _debounce;
    private readonly ConcurrentDictionary<DirNode, FileList> _fileCache = new(ReferenceEqualityComparer.Instance);
    private DirNode? _focus;
    private WriteableBitmap? _bitmap;
    private Item[] _items = [];
    private readonly Dictionary<DirNode, Rect> _folderRects = new(ReferenceEqualityComparer.Instance);
    private int _hover = -1;
    private int _version;

    public TreemapView()
    {
        ClipToBounds = true;
        Cursor = Cursors.Hand;
        _debounce = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(120) };
        _debounce.Tick += (_, _) =>
        {
            _debounce.Stop();
            _ = RebuildAsync();
        };
    }

    public event Action<DirNode>? NodeClicked;

    // ---- Propriétés ----

    public static readonly DependencyProperty RootProperty = DependencyProperty.Register(
        nameof(Root), typeof(DirNode), typeof(TreemapView),
        new PropertyMetadata(null, (d, _) => ((TreemapView)d).OnRootChanged()));

    public DirNode? Root
    {
        get => (DirNode?)GetValue(RootProperty);
        set => SetValue(RootProperty, value);
    }

    public static readonly DependencyProperty SelectedNodeProperty = DependencyProperty.Register(
        nameof(SelectedNode), typeof(DirNode), typeof(TreemapView),
        new PropertyMetadata(null, (d, _) => ((TreemapView)d).OnSelectedChanged()));

    public DirNode? SelectedNode
    {
        get => (DirNode?)GetValue(SelectedNodeProperty);
        set => SetValue(SelectedNodeProperty, value);
    }

    private static readonly DependencyPropertyKey FocusPathKey = DependencyProperty.RegisterReadOnly(
        nameof(FocusPath), typeof(string), typeof(TreemapView), new PropertyMetadata(""));
    public static readonly DependencyProperty FocusPathProperty = FocusPathKey.DependencyProperty;
    public string FocusPath => (string)GetValue(FocusPathProperty);

    private static readonly DependencyPropertyKey HoverInfoKey = DependencyProperty.RegisterReadOnly(
        nameof(HoverInfo), typeof(string), typeof(TreemapView), new PropertyMetadata(""));
    public static readonly DependencyProperty HoverInfoProperty = HoverInfoKey.DependencyProperty;
    public string HoverInfo => (string)GetValue(HoverInfoProperty);

    private static readonly DependencyPropertyKey CanZoomOutKey = DependencyProperty.RegisterReadOnly(
        nameof(CanZoomOut), typeof(bool), typeof(TreemapView), new PropertyMetadata(false));
    public static readonly DependencyProperty CanZoomOutProperty = CanZoomOutKey.DependencyProperty;
    public bool CanZoomOut => (bool)GetValue(CanZoomOutProperty);

    private static readonly DependencyPropertyKey LegendKey = DependencyProperty.RegisterReadOnly(
        nameof(Legend), typeof(IReadOnlyList<LegendItem>), typeof(TreemapView), new PropertyMetadata(Array.Empty<LegendItem>()));
    public static readonly DependencyProperty LegendProperty = LegendKey.DependencyProperty;
    public IReadOnlyList<LegendItem> Legend => (IReadOnlyList<LegendItem>)GetValue(LegendProperty);

    // ---- Navigation ----

    private void OnRootChanged()
    {
        _fileCache.Clear();
        ZoomTo(Root);
    }

    public void ZoomTo(DirNode? node)
    {
        _focus = node;
        SetValue(FocusPathKey, node?.FullPath ?? "");
        SetValue(CanZoomOutKey, node is not null && Root is not null && !ReferenceEquals(node, Root));
        _ = RebuildAsync();
    }

    public void ZoomOut()
    {
        if (_focus?.Parent is { } parent && !ReferenceEquals(_focus, Root)) ZoomTo(parent);
    }

    public void ZoomRoot() => ZoomTo(Root);

    private void OnSelectedChanged()
    {
        var sel = SelectedNode;
        if (sel is not null && _focus is not null && !IsUnder(sel, _focus) && Root is not null && IsUnder(sel, Root))
            ZoomTo(Root);
        else
            InvalidateVisual();
    }

    private static bool IsUnder(DirNode node, DirNode ancestor)
    {
        for (DirNode? n = node; n is not null; n = n.Parent)
            if (ReferenceEquals(n, ancestor)) return true;
        return false;
    }

    // ---- Rendu ----

    protected override void OnRenderSizeChanged(SizeChangedInfo sizeInfo)
    {
        base.OnRenderSizeChanged(sizeInfo);
        _debounce.Stop();
        _debounce.Start();
    }

    private async Task RebuildAsync()
    {
        int version = ++_version;
        var focus = _focus;
        if (focus is null || ActualWidth < 4 || ActualHeight < 4)
        {
            _bitmap = null;
            _items = [];
            _folderRects.Clear();
            _hover = -1;
            SetValue(LegendKey, Array.Empty<LegendItem>());
            InvalidateVisual();
            return;
        }

        var dpi = VisualTreeHelper.GetDpi(this);
        int w = Math.Max(1, (int)Math.Round(ActualWidth * dpi.DpiScaleX));
        int h = Math.Max(1, (int)Math.Round(ActualHeight * dpi.DpiScaleY));
        var cache = _fileCache;
        var job = await Task.Run(() => new RenderJob(w, h, cache).Run(focus));
        if (version != _version) return;

        var bmp = new WriteableBitmap(w, h, dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Bgra32, null);
        bmp.WritePixels(new Int32Rect(0, 0, w, h), job.Pixels, w * 4, 0);
        bmp.Freeze();
        _bitmap = bmp;

        double sx = 1 / dpi.DpiScaleX, sy = 1 / dpi.DpiScaleY;
        var items = new Item[job.Items.Count];
        _folderRects.Clear();
        for (int i = 0; i < items.Length; i++)
        {
            var it = job.Items[i];
            var r = new Rect(it.Rect.X * sx, it.Rect.Y * sy, it.Rect.Width * sx, it.Rect.Height * sy);
            items[i] = it with { Rect = r };
            if (!it.IsFiles) _folderRects.TryAdd(it.Node, r);
        }
        _items = items;
        _hover = -1;

        long total = Math.Max(1, focus.TotalSize);
        SetValue(LegendKey, job.Legend
            .Select(l => new LegendItem(Frozen(new SolidColorBrush(ToColor(l.Color))), l.Name, Format.Bytes(l.Size),
                (l.Size * 100.0 / total).ToString("0.0", CultureInfo.CurrentCulture) + " %"))
            .ToList());
        InvalidateVisual();

        if (job.Wanted.Count > 0) _ = FetchFilesAsync(job.Wanted, version);
    }

    /// <summary>Relit la liste des fichiers des grands blocs visibles, puis redessine avec le détail.</summary>
    private async Task FetchFilesAsync(List<DirNode> dirs, int version)
    {
        var cache = _fileCache;
        await Task.Run(() => Parallel.ForEach(dirs, new ParallelOptions { MaxDegreeOfParallelism = 8 }, dir =>
        {
            if (cache.ContainsKey(dir)) return;
            var names = new List<string>();
            var sizes = new List<long>();
            try
            {
                var opts = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = 0, BufferSize = 64 * 1024 };
                var e = new FileSystemEnumerable<(string Name, long Size)>(dir.FullPath,
                    (ref FileSystemEntry en) => (en.FileName.ToString(), en.Length), opts)
                {
                    ShouldIncludePredicate = (ref FileSystemEntry en) => !en.IsDirectory && en.Length > 0,
                };
                foreach (var (n, s) in e)
                {
                    names.Add(n);
                    sizes.Add(s);
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            cache[dir] = FileList.Create(names, sizes);
        }));
        if (version == _version && ReferenceEquals(cache, _fileCache)) await RebuildAsync();
    }

    protected override void OnRender(DrawingContext dc)
    {
        var full = new Rect(RenderSize);
        dc.DrawRectangle(TryFindResource("TreemapBg") as Brush ?? EmptyBg, null, full); // suit le thème clair / sombre

        if (_bitmap is null)
        {
            var text = new FormattedText(Root is null ? "La carte des volumes s'affichera ici après l'analyse." : "Aucune donnée à afficher.",
                CultureInfo.CurrentCulture, FlowDirection.LeftToRight, new Typeface("Segoe UI"), 13,
                TryFindResource("FaintTextBr") as Brush ?? Brushes.Gray, VisualTreeHelper.GetDpi(this).PixelsPerDip);
            dc.DrawText(text, new Point((ActualWidth - text.Width) / 2, (ActualHeight - text.Height) / 2));
            return;
        }

        dc.DrawImage(_bitmap, full);

        if (_hover >= 0 && _hover < _items.Length)
            dc.DrawRectangle(HoverFill, HoverPen, Deflate(_items[_hover].Rect, 0.75));

        if (SelectedNode is { } sel && _folderRects.TryGetValue(sel, out var sr) && !ReferenceEquals(sel, _focus))
        {
            dc.DrawRectangle(null, SelectOuter, Deflate(sr, 1.5));
            dc.DrawRectangle(null, SelectInner, Deflate(sr, 1.5));
        }
    }

    private static Rect Deflate(Rect r, double d) =>
        r.Width > 2 * d && r.Height > 2 * d ? new Rect(r.X + d, r.Y + d, r.Width - 2 * d, r.Height - 2 * d) : r;

    // ---- Souris ----

    private int HitTest(Point p)
    {
        // Les éléments sont en ordre préfixe : le dernier qui contient le point est le plus profond.
        for (int i = _items.Length - 1; i >= 0; i--)
            if (_items[i].Rect.Contains(p)) return i;
        return -1;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        int idx = HitTest(e.GetPosition(this));
        if (idx == _hover) return;
        _hover = idx;
        SetValue(HoverInfoKey, idx >= 0 ? Describe(_items[idx]) : "");
        InvalidateVisual();
    }

    private string Describe(Item it)
    {
        long total = Math.Max(1, _focus?.TotalSize ?? 1);
        if (it.FileIndex >= 0 && _fileCache.TryGetValue(it.Node, out var list) && it.FileIndex < list.Names.Length)
        {
            long fs = list.Sizes[it.FileIndex];
            return $"{Path.Join(it.Node.FullPath, list.Names[it.FileIndex])}   ·   {Format.Bytes(fs)}   ·   {fs * 100.0 / total:0.0} %";
        }
        long size = it.IsFiles ? (it.FileIndex == FileList.RestIndex ? it.RestSize : it.Node.OwnFilesSize) : it.Node.TotalSize;
        long files = it.IsFiles ? it.Node.OwnFileCount : it.Node.TotalFiles;
        string label = it.FileIndex == FileList.RestIndex ? $"Autres petits fichiers dans {it.Node.FullPath}"
            : it.IsFiles ? $"Fichiers dans {it.Node.FullPath}"
            : it.Node.FullPath;
        string count = it.FileIndex == FileList.RestIndex ? "" : $"   ·   {files:N0} fichier(s)";
        return $"{label}   ·   {Format.Bytes(size)}   ·   {size * 100.0 / total:0.0} %{count}";
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        base.OnMouseLeave(e);
        _hover = -1;
        SetValue(HoverInfoKey, "");
        InvalidateVisual();
    }

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnMouseLeftButtonDown(e);
        int idx = HitTest(e.GetPosition(this));
        if (idx < 0 || _focus is null) return;
        var it = _items[idx];
        if (e.ClickCount == 2)
        {
            // Zoom d'un niveau : l'enfant direct du dossier affiché qui contient l'élément cliqué
            DirNode? n = it.Node;
            while (n is not null && !ReferenceEquals(n.Parent, _focus)) n = n.Parent;
            if (n is not null && n.HasChildren) ZoomTo(n);
        }
        else
        {
            NodeClicked?.Invoke(it.Node);
        }
        e.Handled = true;
    }

    protected override void OnMouseRightButtonDown(MouseButtonEventArgs e)
    {
        base.OnMouseRightButtonDown(e);
        ZoomOut();
        e.Handled = true;
    }

    // ---- Calcul (thread de fond) ----

    /// <summary>FileIndex : -1 = bloc agrégé des fichiers d'un dossier (ou dossier), ≥ 0 = fichier, RestIndex = reste.</summary>
    private readonly record struct Item(Rect Rect, DirNode Node, bool IsFiles, int FileIndex = -1, long RestSize = 0);

    private readonly record struct LegendEntry(string Name, long Size, uint Color);

    private readonly record struct Entry(DirNode Node, bool IsFiles)
    {
        public long Size => IsFiles ? Node.OwnFilesSize : Node.TotalSize;
    }

    private sealed class FileList
    {
        public const int RestIndex = -2;

        public required string[] Names { get; init; }
        public required long[] Sizes { get; init; }
        public long RestSize { get; init; }

        public static FileList Create(List<string> names, List<long> sizes)
        {
            var idx = Enumerable.Range(0, names.Count).OrderByDescending(i => sizes[i]).ToArray();
            int keep = Math.Min(idx.Length, MaxFilesPerDir);
            long rest = 0;
            for (int i = keep; i < idx.Length; i++) rest += sizes[idx[i]];
            return new FileList
            {
                Names = idx.Take(keep).Select(i => names[i]).ToArray(),
                Sizes = idx.Take(keep).Select(i => sizes[i]).ToArray(),
                RestSize = rest,
            };
        }
    }

    private sealed class RenderJob(int width, int height, ConcurrentDictionary<DirNode, FileList> fileCache)
    {
        public int[] Pixels { get; } = new int[width * height];
        public List<Item> Items { get; } = [];
        public List<LegendEntry> Legend { get; } = [];
        public List<DirNode> Wanted { get; } = [];

        public RenderJob Run(DirNode focus)
        {
            var rect = new Rect(0, 0, width, height);
            if (focus.TotalSize <= 0)
            {
                RenderLeaf(rect, new double[4], FilesColor);
                return this;
            }
            Recurse(new Entry(focus, false), rect, null, 0, new double[4], CushionHeight, FilesColor);
            return this;
        }

        private void Recurse(Entry entry, Rect rect, Rect? parentRect, int depth, double[] parentSurface, double h, uint color)
        {
            var surface = (double[])parentSurface.Clone();
            // Un dossier qui remplit exactement son parent (chaîne de sous-dossiers uniques) n'ajoute pas de relief :
            // sinon les reliefs s'accumulent et le bloc devient très sombre.
            if (rect.Width > 0 && rect.Height > 0 && rect != parentRect) AddRidge(rect, surface, h);
            Items.Add(new Item(rect, entry.Node, entry.IsFiles));

            if (rect.Width < MinCell || rect.Height < MinCell)
            {
                RenderLeaf(rect, surface, color);
                return;
            }

            if (entry.IsFiles)
            {
                RenderFiles(entry.Node, rect, surface, h * ScaleFactor, color);
                return;
            }

            var node = entry.Node;
            var kids = new List<Entry>((node.Children?.Count ?? 0) + 1);
            if (node.Children is { } ch)
                foreach (var c in ch)
                    if (c.TotalSize > 0) kids.Add(new Entry(c, false));
            if (node.OwnFilesSize > 0) kids.Add(new Entry(node, true));
            if (kids.Count == 0)
            {
                RenderLeaf(rect, surface, color);
                return;
            }

            kids.Sort((a, b) => b.Size.CompareTo(a.Size));
            var sizes = new long[kids.Count];
            for (int i = 0; i < sizes.Length; i++) sizes[i] = kids[i].Size;
            var rects = Squarify(sizes, rect);

            int colorIndex = 0;
            long others = 0;
            for (int i = 0; i < kids.Count; i++)
            {
                uint c = color;
                if (depth == 0)
                {
                    c = kids[i].IsFiles ? FilesColor : Palette[colorIndex++ % Palette.Length];
                    if (Legend.Count < LegendMax)
                        Legend.Add(new LegendEntry(kids[i].IsFiles ? "Fichiers à la racine" : kids[i].Node.Name, kids[i].Size, c));
                    else
                        others += kids[i].Size;
                }
                Recurse(kids[i], rects[i], rect, depth + 1, surface, h * ScaleFactor, c);
            }
            if (depth == 0 && others > 0) Legend.Add(new LegendEntry("Autres", others, 0xD1D5DB));
        }

        /// <summary>Bloc des fichiers d'un dossier : détaillé fichier par fichier si la liste est en cache,
        /// sinon dessiné d'un seul tenant (et demandé pour la passe suivante s'il est assez grand).</summary>
        private void RenderFiles(DirNode dir, Rect rect, double[] surface, double h, uint color)
        {
            if (!fileCache.TryGetValue(dir, out var list))
            {
                if (dir.OwnFileCount > 1 && rect.Width >= DetailMinSide && rect.Height >= DetailMinSide && Wanted.Count < MaxFetchPerPass)
                    Wanted.Add(dir);
                RenderLeaf(rect, surface, color);
                return;
            }
            if (list.Sizes.Length <= 1 && list.RestSize == 0)
            {
                RenderLeaf(rect, surface, color);
                return;
            }

            long[] sizes = list.RestSize > 0 ? [.. list.Sizes, list.RestSize] : list.Sizes;
            var rects = Squarify(sizes, rect);
            for (int i = 0; i < sizes.Length; i++)
            {
                var r = rects[i];
                bool isRest = i >= list.Sizes.Length;
                Items.Add(new Item(r, dir, true, isRest ? FileList.RestIndex : i, isRest ? list.RestSize : 0));
                var s = (double[])surface.Clone();
                if (r.Width > 0 && r.Height > 0) AddRidge(r, s, h);
                RenderLeaf(r, s, color);
            }
        }

        /// <summary>Squarified treemap (Bruls, Huizing, van Wijk). Tailles triées par ordre décroissant.</summary>
        private static Rect[] Squarify(long[] sizes, Rect r)
        {
            var result = new Rect[sizes.Length];
            double x = r.X, y = r.Y, w = r.Width, h = r.Height;
            double remaining = 0;
            foreach (var s in sizes) remaining += s;

            int i = 0;
            while (i < sizes.Length)
            {
                if (remaining <= 0 || w <= 0 || h <= 0)
                {
                    for (; i < sizes.Length; i++) result[i] = new Rect(x, y, Math.Max(0, w), Math.Max(0, h));
                    break;
                }

                double scale = w * h / remaining; // pixels² par octet
                bool vertical = w >= h;            // rangée posée le long du côté le plus court
                double side = vertical ? h : w;

                int j = i;
                double rowSum = 0, worst = double.MaxValue;
                while (j < sizes.Length)
                {
                    double newSum = rowSum + sizes[j];
                    double ratio = Worst(sizes[i], sizes[j], newSum, side, scale);
                    if (j > i && ratio > worst) break;
                    worst = ratio;
                    rowSum = newSum;
                    j++;
                }

                double thickness = rowSum * scale / side;
                if (j == sizes.Length) thickness = vertical ? w : h; // dernière rangée : remplit exactement
                double pos = 0;
                for (int k = i; k < j; k++)
                {
                    double len = k == j - 1 ? side - pos : sizes[k] * scale / thickness;
                    result[k] = vertical
                        ? new Rect(x, y + pos, thickness, Math.Max(0, len))
                        : new Rect(x + pos, y, Math.Max(0, len), thickness);
                    pos += len;
                }

                if (vertical)
                {
                    x += thickness;
                    w -= thickness;
                }
                else
                {
                    y += thickness;
                    h -= thickness;
                }
                remaining -= rowSum;
                i = j;
            }
            return result;
        }

        private static double Worst(long max, long min, double sum, double side, double scale)
        {
            double area = sum * scale;
            double s2 = side * side;
            double a2 = area * area;
            double aMax = max * scale, aMin = Math.Max(min, 1) * scale;
            return Math.Max(Math.Max(s2 * aMax / a2, a2 / (s2 * aMax)), Math.Max(s2 * aMin / a2, a2 / (s2 * aMin)));
        }

        private static void AddRidge(Rect r, double[] s, double h)
        {
            double h4 = 4 * h;
            double wf = h4 / r.Width;
            s[2] += wf * (r.Right + r.Left);
            s[0] -= wf;
            double hf = h4 / r.Height;
            s[3] += hf * (r.Bottom + r.Top);
            s[1] -= hf;
        }

        private void RenderLeaf(Rect r, double[] s, uint color)
        {
            int x0 = Math.Clamp((int)Math.Round(r.Left), 0, width);
            int x1 = Math.Clamp((int)Math.Round(r.Right), 0, width);
            int y0 = Math.Clamp((int)Math.Round(r.Top), 0, height);
            int y1 = Math.Clamp((int)Math.Round(r.Bottom), 0, height);
            if (x0 >= x1 || y0 >= y1) return;

            double cr = (color >> 16) & 0xFF, cg = (color >> 8) & 0xFF, cb = color & 0xFF;
            for (int py = y0; py < y1; py++)
            {
                double ny = -(2 * s[1] * (py + 0.5) + s[3]);
                int row = py * width;
                for (int px = x0; px < x1; px++)
                {
                    double nx = -(2 * s[0] * (px + 0.5) + s[2]);
                    double cosa = (nx * Lx + ny * Ly + Lz) / Math.Sqrt(nx * nx + ny * ny + 1);
                    if (cosa > 1) cosa = 1;
                    double p = Diffuse * cosa;
                    if (p < 0) p = 0;
                    p = (p + Ambient) * Brightness;
                    int R = Math.Min(255, (int)(cr * p));
                    int G = Math.Min(255, (int)(cg * p));
                    int B = Math.Min(255, (int)(cb * p));
                    Pixels[row + px] = unchecked((int)(0xFF000000u | ((uint)R << 16) | ((uint)G << 8) | (uint)B));
                }
            }
        }
    }

    private static Color ToColor(uint c) => Color.FromRgb((byte)(c >> 16), (byte)(c >> 8), (byte)c);

    private static T Frozen<T>(T f) where T : Freezable
    {
        f.Freeze();
        return f;
    }
}
