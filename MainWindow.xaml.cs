using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using StorageScanner.Core;
using StorageScanner.UI;

namespace StorageScanner;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm = new();
    private GridLength _treemapHeight = new(2, GridUnitType.Star);

    public MainWindow()
    {
        InitializeComponent();
        FitToWorkArea();
        DataContext = _vm;
        _vm.RevealRowRequested += (row, emphasize) => RevealRow(row, emphasize);
        _vm.PropertyChanged += Vm_PropertyChanged;
        Treemap.NodeClicked += node => _vm.ShowInTree(node);
        ThemeManager.Changed += Treemap.InvalidateVisual;
        Closed += (_, _) => ThemeManager.Changed -= Treemap.InvalidateVisual;
        Closing += (_, _) => _vm.CancelAll();
        StateChanged += (_, _) => UpdateWindowState();
        SourceInitialized += (_, _) => EnableRoundedCorners();
        Loaded += (_, _) =>
        {
            UpdateTreemapRow();
            PathBox.Focus();
            PathBox.CaretIndex = PathBox.Text.Length;
        };
    }

    // ---- Fenêtre (barre de titre personnalisée) ----

    /// <summary>Adapte la taille de départ à l'écran (zone hors barre des tâches, en unités indépendantes du DPI).</summary>
    private void FitToWorkArea()
    {
        var wa = SystemParameters.WorkArea;
        Width = Math.Max(MinWidth, Math.Min(1440, wa.Width * 0.92));
        Height = Math.Max(MinHeight, Math.Min(920, wa.Height * 0.92));
        if (wa.Width < 1280 || wa.Height < 780) WindowState = WindowState.Maximized; // petit écran ou zoom élevé
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => SystemCommands.MinimizeWindow(this);

    private void Maximize_Click(object sender, RoutedEventArgs e)
    {
        if (WindowState == WindowState.Maximized) SystemCommands.RestoreWindow(this);
        else SystemCommands.MaximizeWindow(this);
    }

    private void Close_Click(object sender, RoutedEventArgs e) => SystemCommands.CloseWindow(this);

    private void UpdateWindowState()
    {
        bool max = WindowState == WindowState.Maximized;
        MaxButton.Content = max ? "\xE923" : "\xE922";
        MaxButton.ToolTip = max ? "Restaurer" : "Agrandir";
        // Une fenêtre sans cadre natif déborde de l'écran une fois agrandie : on compense la bordure.
        RootBorder.Padding = max ? MaximizedInset() : new Thickness(0);
    }

    private Thickness MaximizedInset()
    {
        int frame = GetSystemMetrics(SM_CXSIZEFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);
        double scale = VisualTreeHelper.GetDpi(this).DpiScaleX;
        double v = frame / scale;
        return new Thickness(v);
    }

    private void EnableRoundedCorners()
    {
        // Windows 11 : coins arrondis et ombre natifs malgré la barre de titre personnalisée
        var hwnd = new WindowInteropHelper(this).Handle;
        int pref = DWMWCP_ROUND;
        _ = DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref pref, sizeof(int));
    }

    private const int SM_CXSIZEFRAME = 32;
    private const int SM_CXPADDEDBORDER = 92;
    private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    private const int DWMWCP_ROUND = 2;

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    // ---- Carte des volumes ----

    private void Vm_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.ShowResults)) UpdateTreemapRow();
    }

    private void TreemapToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (IsLoaded) UpdateTreemapRow();
    }

    private void UpdateTreemapRow()
    {
        bool visible = _vm.ShowResults && TreemapToggle.IsChecked == true;
        if (!visible && TreemapRow.Height.Value > 0) _treemapHeight = TreemapRow.Height;
        TreemapRow.Height = visible ? _treemapHeight : new GridLength(0);
        TreemapRow.MinHeight = visible ? 150 : 0;
        TreemapCard.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
        TreemapSplitter.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ZoomOut_Click(object sender, RoutedEventArgs e) => Treemap.ZoomOut();

    private void ZoomRoot_Click(object sender, RoutedEventArgs e) => Treemap.ZoomRoot();

    // ---- Barre de commande ----

    private void PathBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && _vm.ScanCommand.CanExecute(null)) _vm.ScanCommand.Execute(null);
    }

    private void History_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (HistoryList.SelectedItem is not string path) return;
        _vm.RootPath = path;
        HistoryList.SelectedItem = null;
        HistoryToggle.IsChecked = false;
        PathBox.Focus();
        PathBox.CaretIndex = PathBox.Text.Length;
    }

    // ---- Arborescence ----

    private void RevealRow(TreeRow row) => RevealRow(row, false);

    /// <param name="emphasize">Centre la ligne dans la grille et la surligne brièvement (clic sur la carte).</param>
    private void RevealRow(TreeRow row, bool emphasize)
    {
        TreeGrid.SelectedItem = row;
        // La liste vient souvent d'être reconstruite : on attend que la grille ait régénéré ses lignes.
        Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () =>
        {
            if (!ReferenceEquals(TreeGrid.SelectedItem, row)) TreeGrid.SelectedItem = row;
            TreeGrid.ScrollIntoView(row);
            if (!emphasize) return;

            int index = _vm.Tree.Rows.IndexOf(row);
            if (index >= 0 && FindDescendant<ScrollViewer>(TreeGrid) is { CanContentScroll: true } sv)
                sv.ScrollToVerticalOffset(Math.Max(0, index - sv.ViewportHeight / 2));

            row.IsFlashing = true;
            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.6) };
            timer.Tick += (_, _) =>
            {
                timer.Stop();
                row.IsFlashing = false;
            };
            timer.Start();
        });
    }

    private void ToggleRow(TreeRow row)
    {
        _vm.Tree.Toggle(row);
        RevealRow(row); // une réinitialisation en bloc de la liste peut perdre la sélection
    }

    private static T? FindDescendant<T>(DependencyObject root) where T : DependencyObject
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is T t) return t;
            if (FindDescendant<T>(child) is { } found) return found;
        }
        return null;
    }

    private void Expander_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: TreeRow row }) ToggleRow(row);
        e.Handled = true;
    }

    private void TreeGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        var source = e.OriginalSource as DependencyObject;
        if (FindAncestor<ButtonBase>(source) is not null) return; // déjà géré par le bouton
        if (FindAncestor<DataGridRow>(source) is { DataContext: TreeRow row }) ToggleRow(row);
    }

    private void TreeGrid_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (TreeGrid.SelectedItem is not TreeRow row) return;
        switch (e.Key)
        {
            case Key.Right:
                if (row.CanExpand && !row.IsExpanded) ToggleRow(row);
                e.Handled = true;
                break;
            case Key.Left:
                if (row.IsExpanded)
                {
                    ToggleRow(row);
                }
                else
                {
                    var rows = _vm.Tree.Rows;
                    for (int i = rows.IndexOf(row) - 1; i >= 0; i--)
                        if (rows[i].Depth < row.Depth)
                        {
                            RevealRow(rows[i]);
                            break;
                        }
                }
                e.Handled = true;
                break;
            case Key.Enter:
                ToggleRow(row);
                e.Handled = true;
                break;
        }
    }

    private void TreeGrid_Sorting(object sender, DataGridSortingEventArgs e)
    {
        e.Handled = true; // le tri s'applique niveau par niveau, pas sur la liste aplatie
        _vm.SortIndex = e.Column.SortMemberPath switch
        {
            "Size" => (int)TreeSortMode.Size,
            "Files" => (int)TreeSortMode.Files,
            "ModifiedUtc" => (int)TreeSortMode.Date,
            _ => (int)TreeSortMode.NameWindows,
        };
    }

    // ---- Menus contextuels (communs à toutes les grilles) ----

    private static object? ContextItem(object sender) =>
        sender is MenuItem { Parent: ContextMenu { PlacementTarget: DataGrid grid } } ? grid.SelectedItem : null;

    private static (string? Path, bool IsFile) PathOf(object? item) => item switch
    {
        TreeRow r => (r.FullPath, false),
        FileEntry f => (f.FullPath, true),
        FolderFileItem f => (f.FullPath, true),
        SuspectItem s => (s.FullPath, true),
        ScanError err => (err.Path, false),
        _ => (null, false),
    };

    private void OpenInExplorer_Click(object sender, RoutedEventArgs e)
    {
        var (path, isFile) = PathOf(ContextItem(sender));
        if (path is null) return;
        try
        {
            // Chemin absolu de l'Explorateur : on ne dépend pas du PATH (pas de détournement possible)
            string explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
            if (path.Contains('"')) return; // un chemin Windows valide ne contient jamais de guillemet
            Process.Start(new ProcessStartInfo(explorer, isFile ? $"/select,\"{path}\"" : $"\"{path}\"") { UseShellExecute = false });
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Explorateur", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void CopyPath_Click(object sender, RoutedEventArgs e)
    {
        var (path, _) = PathOf(ContextItem(sender));
        if (path is not null) Clipboard.SetText(path);
    }

    private void ShowInTree_Click(object sender, RoutedEventArgs e)
    {
        if (ContextItem(sender) is FileEntry f) _vm.ShowInTree(f.Dir);
        else if (ContextItem(sender) is SuspectItem s) _vm.ShowInTree(s.Entry.Dir);
    }

    private async void CheckWithAv_Click(object sender, RoutedEventArgs e)
    {
        var item = ContextItem(sender);
        if (item is SuspectItem suspect)
        {
            if (_vm.CheckSuspectCommand.CanExecute(null))
            {
                _vm.SelectedSuspect = suspect;
                _vm.CheckSuspectCommand.Execute(null);
            }
            return;
        }

        var (path, isFile) = PathOf(item);
        if (path is null || !isFile) return;
        Mouse.OverrideCursor = Cursors.Wait;
        AvResult r;
        try { r = await _vm.CheckFileAsync(path); }
        finally { Mouse.OverrideCursor = null; }
        MessageBox.Show(this, $"{Path.GetFileName(path)}\n\n{r.Message}", "Vérification antivirus", MessageBoxButton.OK,
            r.Verdict switch
            {
                AvVerdict.Threat => MessageBoxImage.Error,
                AvVerdict.Clean => MessageBoxImage.Information,
                _ => MessageBoxImage.Warning,
            });
    }

    private void SuspectsKpi_Click(object sender, MouseButtonEventArgs e)
    {
        if (_vm.Result is not null) _vm.SelectedTabIndex = 4;
    }

    private void ScanHere_Click(object sender, RoutedEventArgs e)
    {
        if (ContextItem(sender) is TreeRow row) _vm.ScanFrom(row.Node.FullPath);
    }

    private void ZoomTreemapHere_Click(object sender, RoutedEventArgs e)
    {
        if (ContextItem(sender) is not TreeRow row) return;
        if (TreemapToggle.IsChecked != true) TreemapToggle.IsChecked = true;
        Treemap.ZoomTo(row.Node);
    }

    private static T? FindAncestor<T>(DependencyObject? d) where T : DependencyObject
    {
        while (d is not null)
        {
            if (d is T t) return t;
            d = d is Visual or System.Windows.Media.Media3D.Visual3D ? VisualTreeHelper.GetParent(d) : LogicalTreeHelper.GetParent(d);
        }
        return null;
    }
}
