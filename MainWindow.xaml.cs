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
        TreemapToggle.IsChecked = SettingsStore.GetBool("treemap", true);
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
        TaskbarItemInfo = new System.Windows.Shell.TaskbarItemInfo();
        Loaded += (_, _) =>
        {
            UpdateTreemapRow();
            PathBox.Focus();
            PathBox.CaretIndex = PathBox.Text.Length;
            if (_vm.StartScanOnLoad && _vm.ScanCommand.CanExecute(null)) _vm.ScanCommand.Execute(null);
        };
    }

    // ---- Raccourcis clavier ----

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        bool ctrl = Keyboard.Modifiers == ModifierKeys.Control;
        switch (e.Key)
        {
            case Key.F when ctrl && _vm.ShowResults:
                _vm.SelectedTabIndex = 0;
                FolderSearchBox.Focus();
                FolderSearchBox.SelectAll();
                break;
            case Key.L when ctrl:
                PathBox.Focus();
                PathBox.SelectAll();
                break;
            case Key.O when ctrl:
                Execute(_vm.BrowseCommand);
                break;
            case Key.E when ctrl:
                Execute(_vm.ExportCommand);
                break;
            case Key.F5:
                // Relance l'analyse du dossier affiché (ou de celui saisi)
                if (!_vm.IsBusy && _vm.ScanTarget.Length > 0) _vm.RootPath = _vm.ScanTarget;
                Execute(_vm.ScanCommand);
                break;
            case Key.Escape when _vm.IsScanning:
                Execute(_vm.CancelCommand);
                break;
            case Key.Escape when _vm.IsFindingDuplicates:
                Execute(_vm.CancelDuplicatesCommand);
                break;
            case >= Key.D1 and <= Key.D7 when ctrl && _vm.ShowResults:
                _vm.SelectedTabIndex = e.Key - Key.D1;
                break;
            default:
                return;
        }
        e.Handled = true;
    }

    private static void Execute(ICommand command)
    {
        if (command.CanExecute(null)) command.Execute(null);
    }

    private void FolderSearchBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            _vm.FindFolder(Keyboard.Modifiers.HasFlag(ModifierKeys.Shift) ? -1 : +1);
            e.Handled = true;
        }
        else if (e.Key == Key.Escape && FolderSearchBox.Text.Length > 0)
        {
            _vm.FolderSearchText = "";
            e.Handled = true;
        }
    }

    // ---- Glisser-déposer d'un dossier ou d'un lecteur sur la fenêtre ----

    private static string? DroppedFolder(DragEventArgs e) =>
        e.Data.GetDataPresent(DataFormats.FileDrop) && e.Data.GetData(DataFormats.FileDrop) is string[] { Length: 1 } paths
        && Directory.Exists(SafePath.ForIo(paths[0])) ? paths[0] : null;

    private void Window_PreviewDragOver(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return; // texte : laissé au champ de saisie
        e.Effects = !_vm.IsBusy && DroppedFolder(e) is not null ? DragDropEffects.Link : DragDropEffects.None;
        e.Handled = true;
    }

    private void Window_PreviewDrop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        e.Handled = true;
        if (!_vm.IsBusy && DroppedFolder(e) is { } folder) _vm.ScanFrom(folder);
    }

    // ---- Barre des tâches : progression et signal de fin ----

    private bool _wasBusy;

    private void UpdateTaskbar()
    {
        var info = TaskbarItemInfo;
        if (_vm.IsFindingDuplicates)
        {
            info.ProgressState = System.Windows.Shell.TaskbarItemProgressState.Normal;
            info.ProgressValue = _vm.DupPercent / 100;
        }
        else
        {
            info.ProgressState = _vm.IsScanning ? System.Windows.Shell.TaskbarItemProgressState.Indeterminate
                                                : System.Windows.Shell.TaskbarItemProgressState.None;
        }

        // Fin d'une longue opération pendant que l'utilisateur fait autre chose : le bouton clignote
        if (_wasBusy && !_vm.IsBusy && !IsActive) FlashTaskbarButton();
        _wasBusy = _vm.IsBusy;
    }

    private void FlashTaskbarButton()
    {
        var info = new FLASHWINFO
        {
            cbSize = (uint)Marshal.SizeOf<FLASHWINFO>(),
            hwnd = new WindowInteropHelper(this).Handle,
            dwFlags = FLASHW_TRAY | FLASHW_TIMERNOFG,
            uCount = 5,
        };
        _ = FlashWindowEx(ref info);
    }

    private const uint FLASHW_TRAY = 2;
    private const uint FLASHW_TIMERNOFG = 12;

    [StructLayout(LayoutKind.Sequential)]
    private struct FLASHWINFO
    {
        public uint cbSize;
        public IntPtr hwnd;
        public uint dwFlags;
        public uint uCount;
        public uint dwTimeout;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlashWindowEx(ref FLASHWINFO info);

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
        if (e.PropertyName is nameof(MainViewModel.IsBusy) or nameof(MainViewModel.DupPercent)) UpdateTaskbar();
    }

    private void TreemapToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        SettingsStore.Set("treemap", TreemapToggle.IsChecked == true);
        UpdateTreemapRow();
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
    private int _revealGeneration;

    private void RevealRow(TreeRow row, bool emphasize)
    {
        TreeGrid.SelectedItem = row;
        int generation = ++_revealGeneration;
        // La liste vient souvent d'être reconstruite : on attend que la grille ait régénéré ses lignes.
        Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () =>
        {
            if (generation != _revealGeneration) return; // une demande plus récente l'emporte (recherche, clic sur la carte)
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
        StaleFolder s => (s.FullPath, false),
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
            if (path.Contains('"') || !Path.IsPathFullyQualified(path)) return; // un chemin Windows valide ne contient jamais de guillemet
            // Nom piégé (« virus.exe. ») : l'Explorateur ouvrirait un autre élément, on ouvre le dossier sain le plus proche
            if (SafePath.IsAmbiguousPath(path))
            {
                path = SafePath.NearestUnambiguousFolder(path);
                isFile = false;
            }
            // Un « dossier » remplacé entre-temps par un fichier serait exécuté par l'Explorateur : on le sélectionne seulement
            if (!isFile && !Directory.Exists(SafePath.ForIo(path))) isFile = true;
            Process.Start(new ProcessStartInfo(explorer, isFile ? $"/select,\"{path}\"" : $"\"{path}\"") { UseShellExecute = false });
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Explorateur", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    /// <summary>Fenêtre « Propriétés » de Windows (taille sur disque, sécurité, versions précédentes…).</summary>
    private void Properties_Click(object sender, RoutedEventArgs e)
    {
        var (path, _) = PathOf(ContextItem(sender));
        if (path is null || !Path.IsPathFullyQualified(path)) return;
        if (SafePath.IsAmbiguousPath(path)) path = SafePath.NearestUnambiguousFolder(path); // Windows ouvrirait un autre élément
        if (!SHObjectProperties(new WindowInteropHelper(this).Handle, SHOP_FILEPATH, path, null))
            MessageBox.Show(this, "Impossible d'afficher les propriétés de cet élément.", "Propriétés", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private const uint SHOP_FILEPATH = 2;

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SHObjectProperties(IntPtr hwnd, uint objectType, string objectName, string? propertyPage);

    private void CopyPath_Click(object sender, RoutedEventArgs e)
    {
        var (path, _) = PathOf(ContextItem(sender));
        if (path is not null) Clipboard.SetText(path);
    }

    private void ShowInTree_Click(object sender, RoutedEventArgs e)
    {
        if (ContextItem(sender) is FileEntry f) _vm.ShowInTree(f.Dir);
        else if (ContextItem(sender) is SuspectItem s) _vm.ShowInTree(s.Entry.Dir);
        else if (ContextItem(sender) is StaleFolder st) _vm.ShowInTree(st.Node);
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

    private void StaleGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject) is { DataContext: StaleFolder s }) _vm.ShowInTree(s.Node);
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
