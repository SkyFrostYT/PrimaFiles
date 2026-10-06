using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO.Enumeration;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Win32;
using StorageScanner.Core;

namespace StorageScanner.UI;

public sealed class FolderFileItem(string name, long size, DateTime lastWriteUtc, string fullPath, string directory,
    FileAttributes attributes, DirContext context)
{
    public Suspicion Suspicion { get; } = SuspicionRules.Evaluate(context, directory, name, attributes);
    public bool IsSuspectDanger => Suspicion.Level == SuspicionLevel.Danger;
    public bool IsSuspectWarning => Suspicion.Level == SuspicionLevel.Warning;
    public string? SuspicionText => Suspicion.IsSuspect
        ? $"⚠ ATTENTION — {SuspicionRules.LevelText(Suspicion.Level)} : {SuspicionRules.Describe(Suspicion.Reasons)}"
        : null;

    public string Name { get; } = name;
    public long Size { get; } = size;
    public DateTime LastWriteUtc { get; } = lastWriteUtc;
    public string FullPath { get; } = fullPath;
    public string Extension => Path.GetExtension(Name).ToLowerInvariant();

    public SafetyLevel Safety { get; } = StorageScanner.Core.Safety.ForFile(directory, name, attributes);
    public bool IsSystem => Safety != SafetyLevel.Normal;
    public bool IsCritical => Safety == SafetyLevel.Critical;
    public string? SafetyText => StorageScanner.Core.Safety.Describe(Safety);
}

public sealed class DriveItem(string root, string title, string detail, double usedPercent, bool isNetwork)
{
    public string Root { get; } = root;
    public string Title { get; } = title;
    public string Detail { get; } = detail;
    public string Kind => isNetwork ? "Lecteur réseau" : "Disque local";
    public string ToolTip => $"Analyser {Root}";
    public double UsedPercent { get; } = usedPercent;
    public string Icon => isNetwork ? "\xE8CE" : "\xEDA2";
    public string UsedText => $"{UsedPercent:0} %";
}

public sealed class MainViewModel : ObservableObject
{
    private const long MB = 1024 * 1024;
    private const int MaxFolderFiles = 200_000;
    private const string Dash = "—";

    private readonly DispatcherTimer _timer;
    private readonly Stopwatch _sw = new();
    private CancellationTokenSource? _scanCts, _dupCts, _folderCts;
    private ScanProgress? _scanProgress;
    private DuplicateProgress? _dupProgress;

    public MainViewModel()
    {
        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(250) };
        _timer.Tick += (_, _) => RefreshProgress();

        BrowseCommand = new RelayCommand(_ => Browse(), _ => !IsScanning);
        ScanCommand = new RelayCommand(async _ => await ScanAsync(), _ => !IsBusy && !string.IsNullOrWhiteSpace(RootPath));
        ScanPathCommand = new RelayCommand(p => { if (p is string s) ScanFrom(s); }, _ => !IsBusy);
        CancelCommand = new RelayCommand(_ => _scanCts?.Cancel(), _ => IsScanning);
        FindDuplicatesCommand = new RelayCommand(async _ => await FindDuplicatesAsync(),
            _ => !IsBusy && Result is { DuplicateCandidates.Count: > 1 });
        CancelDuplicatesCommand = new RelayCommand(_ => _dupCts?.Cancel(), _ => IsFindingDuplicates);
        ExportCommand = new RelayCommand(async _ => await ExportAsync(), _ => Result is not null && !IsBusy);
        NewScanCommand = new RelayCommand(_ => ResetToWelcome(), _ => !IsBusy && Result is not null);

        foreach (var p in RecentStore.Load()) RecentPaths.Add(p);
        _rootPath = InitialPathFromArgs() ?? RecentPaths.FirstOrDefault() ?? "";
        RestartAsAdminCommand = new RelayCommand(_ =>
        {
            if (Elevation.RestartElevated(RootPath)) Application.Current.Shutdown();
        }, _ => !IsBusy && !Elevation.IsElevated);
        ToggleThemeCommand = new RelayCommand(_ => ThemeManager.Toggle());
        CheckSuspectCommand = new RelayCommand(async _ => await CheckSuspectsAsync([SelectedSuspect!]),
            _ => _av is not null && !IsAvChecking && SelectedSuspect is not null);
        CheckAllSuspectsCommand = new RelayCommand(async _ => await CheckSuspectsAsync(Suspects),
            _ => _av is not null && !IsAvChecking && Suspects.Count > 0);
        CancelAvCommand = new RelayCommand(_ => _avCts?.Cancel(), _ => IsAvChecking);
        var dispatcher = Dispatcher.CurrentDispatcher;
        _ = Task.Run(AntivirusEngine.Detect).ContinueWith(t => dispatcher.BeginInvoke(() =>
        {
            _av = t.Result;
            AvName = _av is null
                ? "Aucun antivirus en ligne de commande détecté"
                : $"Vérification par : {_av.Name}";
            CommandManager.InvalidateRequerySuggested();
        }), TaskScheduler.Default);
        ThemeManager.Changed += () =>
        {
            OnPropertyChanged(nameof(ThemeGlyph));
            OnPropertyChanged(nameof(ThemeTooltip));
        };
        if (Elevation.IsElevated)
        {
            bool backup = Elevation.EnableBackupPrivilege();
            _statusText = backup
                ? "Mode administrateur · lecture étendue activée (privilège de sauvegarde)"
                : "Mode administrateur";
        }
        _ = LoadDrivesAsync();
    }

    /// <summary>Demande à la vue de sélectionner et faire défiler jusqu'à une ligne.</summary>
    /// <remarks>Second paramètre : centrer la ligne et la mettre en évidence (clic sur la carte).</remarks>
    public event Action<TreeRow, bool>? RevealRowRequested;

    public ICommand BrowseCommand { get; }
    public ICommand ScanCommand { get; }
    public ICommand ScanPathCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand FindDuplicatesCommand { get; }
    public ICommand CancelDuplicatesCommand { get; }
    public ICommand ExportCommand { get; }
    public ICommand NewScanCommand { get; }
    public ICommand RestartAsAdminCommand { get; }
    public ICommand ToggleThemeCommand { get; }
    public ICommand CheckSuspectCommand { get; }
    public ICommand CheckAllSuspectsCommand { get; }
    public ICommand CancelAvCommand { get; }

    // ---- Fichiers suspects / antivirus ----

    private AntivirusEngine? _av;
    private CancellationTokenSource? _avCts;

    private string _avName = "Recherche de l'antivirus…";
    public string AvName { get => _avName; private set => Set(ref _avName, value); }

    private IReadOnlyList<SuspectItem> _suspects = [];
    public IReadOnlyList<SuspectItem> Suspects
    {
        get => _suspects;
        private set
        {
            if (!Set(ref _suspects, value)) return;
            OnPropertyChanged(nameof(SuspectsHeader));
            OnPropertyChanged(nameof(HasSuspects));
            OnPropertyChanged(nameof(NoSuspects));
            OnPropertyChanged(nameof(SuspectsSummary));
        }
    }

    public bool HasSuspects => Suspects.Count > 0;
    public bool NoSuspects => Result is not null && Suspects.Count == 0;
    public string SuspectsHeader => Suspects.Count > 0 ? $"Suspects ({Suspects.Count:N0})" : "Suspects";
    public string SuspectsSummary
    {
        get
        {
            int danger = Suspects.Count(s => s.IsDanger);
            int warn = Suspects.Count - danger;
            return $"{danger:N0} fichier(s) suspect(s) et {warn:N0} à vérifier. Ces fichiers présentent des signes souvent associés aux "
                   + "logiciels malveillants, ce qui n'est pas une preuve : faites-les vérifier par l'antivirus avant toute action.";
        }
    }

    private SuspectItem? _selectedSuspect;
    public SuspectItem? SelectedSuspect { get => _selectedSuspect; set => Set(ref _selectedSuspect, value); }

    private bool _isAvChecking;
    public bool IsAvChecking
    {
        get => _isAvChecking;
        private set
        {
            if (Set(ref _isAvChecking, value)) CommandManager.InvalidateRequerySuggested();
        }
    }

    private string _kpiSuspects = Dash;
    public string KpiSuspects { get => _kpiSuspects; private set => Set(ref _kpiSuspects, value); }

    private async Task CheckSuspectsAsync(IReadOnlyList<SuspectItem> items)
    {
        if (_av is null || items.Count == 0) return;
        _avCts = new CancellationTokenSource();
        IsAvChecking = true;
        int threats = 0, done = 0;
        try
        {
            foreach (var item in items)
            {
                if (_avCts.IsCancellationRequested) break;
                item.SetChecking();
                StatusText = $"Vérification antivirus {++done}/{items.Count} : {item.Name}";
                var r = await _av.ScanAsync(item.FullPath, _avCts.Token);
                item.SetResult(r);
                if (r.Verdict == AvVerdict.Threat) threats++;
            }
            StatusText = threats > 0
                ? $"⚠ {threats} MENACE(S) CONFIRMÉE(S) par {_av.Name} — consultez votre antivirus ou votre service informatique"
                : $"Vérification terminée : aucune menace détectée par {_av.Name} sur {done} fichier(s)";
        }
        finally
        {
            IsAvChecking = false;
        }
    }

    /// <summary>Vérification d'un fichier quelconque (menu contextuel).</summary>
    public Task<AvResult> CheckFileAsync(string path) =>
        _av is null
            ? Task.FromResult(new AvResult(AvVerdict.Error, "Aucun antivirus utilisable en ligne de commande n'a été trouvé sur ce poste."))
            : _av.ScanAsync(path);

    public bool IsElevated => Elevation.IsElevated;
    public string ThemeGlyph => ThemeManager.IsDark ? "\xE706" : "\xE708"; // soleil / lune
    public string ThemeTooltip => ThemeManager.IsDark ? "Passer au thème clair" : "Passer au thème sombre";

    /// <summary>Chemin transmis lors d'une relance en administrateur (--path "…").</summary>
    private static string? InitialPathFromArgs()
    {
        var args = Environment.GetCommandLineArgs();
        int i = Array.IndexOf(args, "--path");
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    public TreeModel Tree { get; } = new();
    public ObservableCollection<string> RecentPaths { get; } = [];
    public ObservableCollection<DriveItem> Drives { get; } = [];

    // ---- Paramètres ----

    private string _rootPath;
    public string RootPath { get => _rootPath; set => Set(ref _rootPath, value); }

    private int _threads = 16;
    public int Threads { get => _threads; set => Set(ref _threads, Math.Clamp(value, 1, 128)); }

    private double _dupMinSizeMb = 1;
    public double DupMinSizeMb { get => _dupMinSizeMb; set => Set(ref _dupMinSizeMb, Math.Max(0.001, value)); }

    private int _dupThreads = 8;
    public int DupThreads { get => _dupThreads; set => Set(ref _dupThreads, Math.Clamp(value, 1, 64)); }

    private int _sortIndex;
    public int SortIndex
    {
        get => _sortIndex;
        set
        {
            if (!Set(ref _sortIndex, value)) return;
            var selected = SelectedTreeRow;
            Tree.SetSort((TreeSortMode)value);
            if (selected is not null && Tree.Reveal(selected.Node) is { } row) RevealRowRequested?.Invoke(row, false);
        }
    }

    private int _selectedTabIndex;
    public int SelectedTabIndex { get => _selectedTabIndex; set => Set(ref _selectedTabIndex, value); }

    // ---- État ----

    private bool _isScanning;
    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            if (!Set(ref _isScanning, value)) return;
            BusyChanged();
            OnPropertyChanged(nameof(ShowWelcome));
        }
    }

    private bool _isFindingDuplicates;
    public bool IsFindingDuplicates
    {
        get => _isFindingDuplicates;
        private set
        {
            if (Set(ref _isFindingDuplicates, value)) BusyChanged();
        }
    }

    public bool IsBusy => IsScanning || IsFindingDuplicates;
    public bool ShowWelcome => Result is null && !IsScanning;
    public bool ShowResults => Result is not null;

    private string _statusText = "Prêt";
    public string StatusText { get => _statusText; private set => Set(ref _statusText, value); }

    private string _progressText = "";
    public string ProgressText { get => _progressText; private set => Set(ref _progressText, value); }

    private string _currentPath = "";
    public string CurrentPath { get => _currentPath; private set => Set(ref _currentPath, value); }

    private string _scanTarget = "";
    public string ScanTarget { get => _scanTarget; private set => Set(ref _scanTarget, value); }

    // Indicateurs (cartes du haut)
    private string _kpiSize = Dash, _kpiFiles = Dash, _kpiDirs = Dash, _kpiDuration = Dash, _kpiErrors = Dash;
    public string KpiSize { get => _kpiSize; private set => Set(ref _kpiSize, value); }
    public string KpiFiles { get => _kpiFiles; private set => Set(ref _kpiFiles, value); }
    public string KpiDirs { get => _kpiDirs; private set => Set(ref _kpiDirs, value); }
    public string KpiDuration { get => _kpiDuration; private set => Set(ref _kpiDuration, value); }
    public string KpiErrors { get => _kpiErrors; private set => Set(ref _kpiErrors, value); }

    private string _kpiSizeSub = "";
    /// <summary>Occupation du volume ou du quota, affichée sous « Espace occupé ».</summary>
    public string KpiSizeSub { get => _kpiSizeSub; private set => Set(ref _kpiSizeSub, value); }

    // ---- Résultats ----

    private ScanResult? _result;
    public ScanResult? Result
    {
        get => _result;
        private set
        {
            if (!Set(ref _result, value)) return;
            OnPropertyChanged(nameof(TopFiles));
            OnPropertyChanged(nameof(Extensions));
            OnPropertyChanged(nameof(Errors));
            OnPropertyChanged(nameof(ErrorsHeader));
            Suspects = value?.Suspicious.Select(s => new SuspectItem(s)).ToList() ?? [];
            OnPropertyChanged(nameof(NoSuspects));
            OnPropertyChanged(nameof(TopFilesHeader));
            OnPropertyChanged(nameof(ShowWelcome));
            OnPropertyChanged(nameof(ShowResults));
            OnPropertyChanged(nameof(TreemapRoot));
        }
    }

    public DirNode? TreemapRoot => Result?.Root;
    public IReadOnlyList<FileEntry>? TopFiles => Result?.TopFiles;
    public IReadOnlyList<ExtensionStat>? Extensions => Result?.Extensions;
    public IReadOnlyList<ScanError>? Errors => Result?.Errors;
    public string ErrorsHeader => Result is { Errors.Count: > 0 } r ? $"Erreurs ({r.Errors.Count:N0})" : "Erreurs";
    public string TopFilesHeader => Result is { } r ? $"Les {r.TopFiles.Count:N0} plus gros fichiers" : "";

    private TreeRow? _selectedTreeRow;
    public TreeRow? SelectedTreeRow
    {
        get => _selectedTreeRow;
        set
        {
            if (!Set(ref _selectedTreeRow, value)) return;
            OnPropertyChanged(nameof(SelectedNode));
            _ = LoadFolderFilesAsync(value);
        }
    }

    public DirNode? SelectedNode => SelectedTreeRow?.Kind == RowKind.Folder ? SelectedTreeRow.Node : null;

    private IReadOnlyList<FolderFileItem> _folderFiles = [];
    public IReadOnlyList<FolderFileItem> FolderFiles { get => _folderFiles; private set => Set(ref _folderFiles, value); }

    private string _folderFilesTitle = "Fichiers";
    public string FolderFilesTitle { get => _folderFilesTitle; private set => Set(ref _folderFilesTitle, value); }

    private string _folderFilesHeader = "Sélectionnez un dossier pour voir ses fichiers.";
    public string FolderFilesHeader { get => _folderFilesHeader; private set => Set(ref _folderFilesHeader, value); }

    private IReadOnlyList<DuplicateGroup> _duplicates = [];
    public IReadOnlyList<DuplicateGroup> Duplicates { get => _duplicates; private set => Set(ref _duplicates, value); }

    private DuplicateGroup? _selectedDuplicate;
    public DuplicateGroup? SelectedDuplicate { get => _selectedDuplicate; set => Set(ref _selectedDuplicate, value); }

    private string _dupStatus = "Lancez la recherche pour trouver les fichiers identiques.";
    public string DupStatus { get => _dupStatus; private set => Set(ref _dupStatus, value); }

    private double _dupPercent;
    public double DupPercent { get => _dupPercent; private set => Set(ref _dupPercent, value); }

    // ---- Actions ----

    public void CancelAll()
    {
        _scanCts?.Cancel();
        _dupCts?.Cancel();
        _folderCts?.Cancel();
    }

    public void ScanFrom(string path)
    {
        RootPath = path;
        if (ScanCommand.CanExecute(null)) ScanCommand.Execute(null);
    }

    public void ShowInTree(DirNode node)
    {
        var row = Tree.Reveal(node);
        if (row is null) return;
        SelectedTabIndex = 0;
        RevealRowRequested?.Invoke(row, true);
    }

    private void ResetToWelcome()
    {
        _folderCts?.Cancel();
        SelectedTreeRow = null;
        Tree.Clear();
        Result = null;
        Duplicates = [];
        ResetKpis();
        ScanTarget = "";
        StatusText = "Prêt";
        ProgressText = "";
        GC.Collect();
        _ = LoadDrivesAsync();
    }

    private void ResetKpis()
    {
        KpiSize = KpiFiles = KpiDirs = KpiDuration = KpiErrors = KpiSuspects = Dash;
        KpiSizeSub = "";
    }

    private async Task LoadDrivesAsync()
    {
        var drives = await Task.Run(() =>
        {
            var list = new List<DriveItem>();
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (d.DriveType is not (DriveType.Fixed or DriveType.Network or DriveType.Removable) || !d.IsReady) continue;
                    // Valeurs applicables à l'utilisateur courant (quotas inclus)
                    long used = d.TotalSize - d.AvailableFreeSpace;
                    bool network = d.DriveType == DriveType.Network;
                    // Lecteur réseau : le nom du partage (« Public ») est plus parlant que le nom du volume, souvent
                    // identique pour tous les partages d'un même NAS. Le nom du serveur n'est jamais affiché.
                    string? share = network ? Unc.ShareName(Unc.GetMappedUnc(d.Name)) : null;
                    string label = share
                        ?? (!string.IsNullOrWhiteSpace(d.VolumeLabel) ? d.VolumeLabel : network ? "Lecteur réseau" : "Disque local");
                    list.Add(new DriveItem(d.RootDirectory.FullName, $"{d.Name.TrimEnd('\\')}  {label}",
                        $"{Format.Bytes(d.AvailableFreeSpace)} libres sur {Format.Bytes(d.TotalSize)}",
                        d.TotalSize > 0 ? used * 100.0 / d.TotalSize : 0, network));
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            return list;
        });
        Drives.Clear();
        foreach (var d in drives) Drives.Add(d);
    }

    private void Browse()
    {
        var dlg = new OpenFolderDialog { Title = "Dossier à analyser" };
        if (Directory.Exists(RootPath)) dlg.InitialDirectory = RootPath;
        if (dlg.ShowDialog() == true) RootPath = dlg.FolderName;
    }

    private async Task ScanAsync()
    {
        var path = Scanner.NormalizeRoot(RootPath);
        if (path.Length == 0) return;
        AddRecent(path);
        RootPath = path; // l'historique peut modifier le texte saisi

        // Libère le scan précédent avant d'en lancer un nouveau
        _folderCts?.Cancel();
        SelectedTreeRow = null;
        Tree.Clear();
        Result = null;
        Duplicates = [];
        DupPercent = 0;
        DupStatus = "Lancez la recherche pour trouver les fichiers identiques.";
        GC.Collect();

        _scanCts = new CancellationTokenSource();
        _scanProgress = new ScanProgress();
        // Lecteur mappé : seul le nom du partage est affiché, jamais le nom du serveur (confidentialité)
        string? share = Unc.ShareName(await Task.Run(() => Unc.GetMappedUnc(path)));
        ScanTarget = path;
        IsScanning = true;
        StatusText = "Analyse en cours…";
        _sw.Restart();
        _timer.Start();
        try
        {
            var options = new ScanOptions
            {
                Threads = Threads,
                DuplicateMinSize = (long)(DupMinSizeMb * MB),
            };
            var r = await Scanner.ScanAsync(path, options, _scanProgress, _scanCts.Token);
            var root = r.Root;
            var volume = await Task.Run(() => VolumeSpace.TryGet(path));
            double? rootPercent = null;
            string? rootInfo = null;
            KpiSizeSub = "";
            if (volume is { } v)
            {
                // Racine d'un disque ou d'un partage : occupation réelle (quota inclus). Sous-dossier : sa part du volume.
                bool isRoot = VolumeSpace.IsVolumeRoot(path);
                rootPercent = isRoot ? v.UsedPercent : root.TotalSize * 100.0 / v.Total;
                rootInfo = $"Volume : {Format.Bytes(v.Used)} utilisés sur {Format.Bytes(v.Total)} ({v.UsedPercent:0.0} %) · {Format.Bytes(v.Free)} libres";
                KpiSizeSub = $"{rootPercent:0.0} % du volume de {Format.Bytes(v.Total)}";
            }
            Result = r;
            Tree.Load(root, rootPercent, rootInfo, share is null ? null : $"{root.Name}   ({share})");
            KpiSize = Format.Bytes(root.TotalSize);
            KpiFiles = root.TotalFiles.ToString("N0");
            KpiDirs = root.TotalDirs.ToString("N0");
            KpiDuration = Format.Duration(r.Duration);
            KpiErrors = r.Errors.Count.ToString("N0");
            KpiSuspects = r.Suspicious.Count.ToString("N0");
            StatusText = (r.Cancelled ? "Analyse interrompue — résultats partiels" : "Analyse terminée")
                         + $" · {root.TotalFiles / Math.Max(r.Duration.TotalSeconds, 0.001):N0} fichiers/s"
                         + (r.Suspicious.Count > 0 ? $" · ⚠ {r.Suspicious.Count:N0} fichier(s) suspect(s) : voir l'onglet Suspects" : "");
            DupStatus = $"{r.DuplicateCandidates.Count:N0} fichiers de {Format.Bytes(r.DuplicateMinSize)} ou plus à comparer.";
            if (Tree.Rows.Count > 0) RevealRowRequested?.Invoke(Tree.Rows[0], false);
        }
        catch (Exception ex)
        {
            ScanTarget = "";
            ResetKpis();
            StatusText = "Erreur : " + ex.Message;
            MessageBox.Show(ex.Message, "Analyse impossible", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            IsScanning = false;
            StopTimerIfIdle();
            CurrentPath = "";
        }
    }

    private async Task FindDuplicatesAsync()
    {
        var r = Result;
        if (r is null) return;
        long min = (long)(DupMinSizeMb * MB);
        string note = "";
        if (min < r.DuplicateMinSize)
        {
            min = r.DuplicateMinSize;
            note = $" · seuil {Format.Bytes(min)} (fixé lors de l'analyse)";
        }

        _dupCts = new CancellationTokenSource();
        _dupProgress = new DuplicateProgress();
        Duplicates = [];
        SelectedDuplicate = null;
        DupPercent = 0;
        IsFindingDuplicates = true;
        var sw = Stopwatch.StartNew();
        _timer.Start();
        try
        {
            var groups = await DuplicateFinder.FindAsync(r.DuplicateCandidates, min, DupThreads, _dupProgress, _dupCts.Token);
            Duplicates = groups;
            SelectedDuplicate = groups.FirstOrDefault();
            DupPercent = 100;
            DupStatus = groups.Count == 0
                ? $"Aucun doublon trouvé ({Format.Duration(sw.Elapsed)}){note}"
                : $"{groups.Count:N0} groupe(s) · {groups.Sum(g => g.Count):N0} fichiers · {Format.Bytes(groups.Sum(g => g.WastedSize))} récupérables"
                  + $" · {Format.Duration(sw.Elapsed)}"
                  + (_dupProgress.Errors > 0 ? $" · {_dupProgress.Errors:N0} illisible(s)" : "")
                  + note;
        }
        catch (OperationCanceledException)
        {
            DupStatus = "Recherche annulée.";
        }
        catch (Exception ex)
        {
            DupStatus = "Erreur : " + ex.Message;
        }
        finally
        {
            IsFindingDuplicates = false;
            StopTimerIfIdle();
            CurrentPath = "";
        }
    }

    private async Task LoadFolderFilesAsync(TreeRow? row)
    {
        _folderCts?.Cancel();
        var cts = _folderCts = new CancellationTokenSource();
        FolderFiles = [];
        if (row is null)
        {
            FolderFilesTitle = "Fichiers";
            FolderFilesHeader = "Sélectionnez un dossier pour voir ses fichiers.";
            return;
        }

        string path = row.FullPath;
        FolderFilesTitle = row.Node.Name;
        FolderFilesHeader = "Chargement…";
        try
        {
            await Task.Delay(200, cts.Token); // anti-rebond pendant la navigation au clavier
            var items = await Task.Run(() =>
            {
                var opts = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = 0, BufferSize = 64 * 1024 };
                var context = DirContext.For(path);
                var e = new FileSystemEnumerable<FolderFileItem>(path,
                    (ref FileSystemEntry en) => new FolderFileItem(en.FileName.ToString(), en.Length, en.LastWriteTimeUtc.UtcDateTime,
                        en.ToFullPath(), path, en.Attributes, context),
                    opts)
                {
                    ShouldIncludePredicate = (ref FileSystemEntry en) => !en.IsDirectory,
                };
                var list = new List<FolderFileItem>();
                foreach (var it in e)
                {
                    list.Add(it);
                    if (list.Count >= MaxFolderFiles) break;
                    cts.Token.ThrowIfCancellationRequested();
                }
                list.Sort((a, b) => b.Size.CompareTo(a.Size));
                return list;
            }, cts.Token);

            if (cts.IsCancellationRequested) return;
            FolderFiles = items;
            FolderFilesHeader = items.Count == 0
                ? "Aucun fichier directement dans ce dossier."
                : $"{items.Count:N0} fichier(s) · {Format.Bytes(items.Sum(i => i.Size))}" + (items.Count >= MaxFolderFiles ? " (liste tronquée)" : "");
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            if (!cts.IsCancellationRequested) FolderFilesHeader = "Erreur : " + ex.Message;
        }
    }

    private async Task ExportAsync()
    {
        var r = Result;
        if (r is null) return;

        string defaultName = SelectedTabIndex switch
        {
            1 => "gros-fichiers",
            2 => "types-de-fichiers",
            3 => "doublons",
            4 => "fichiers-suspects",
            5 => "erreurs",
            _ => "arborescence",
        };
        var dlg = new SaveFileDialog
        {
            Title = "Exporter l'onglet affiché en CSV",
            Filter = "Fichier CSV (*.csv)|*.csv",
            FileName = $"{defaultName}_{DateTime.Now:yyyyMMdd_HHmm}.csv",
        };
        if (dlg.ShowDialog() != true) return;

        StatusText = "Export en cours…";
        try
        {
            await (SelectedTabIndex switch
            {
                1 => CsvExport.FilesAsync(r.TopFiles, dlg.FileName),
                2 => CsvExport.ExtensionsAsync(r.Extensions, dlg.FileName),
                3 => CsvExport.DuplicatesAsync(Duplicates, dlg.FileName),
                4 => CsvExport.SuspectsAsync(Suspects.Select(s => (s.File, s.AvText)), dlg.FileName),
                5 => CsvExport.ErrorsAsync(r.Errors, dlg.FileName),
                _ => CsvExport.TreeAsync(r.Root, dlg.FileName),
            });
            StatusText = $"Exporté : {dlg.FileName}";
        }
        catch (Exception ex)
        {
            StatusText = "Échec de l'export : " + ex.Message;
        }
    }

    private void RefreshProgress()
    {
        if (IsScanning && _scanProgress is { } p)
        {
            double secs = Math.Max(_sw.Elapsed.TotalSeconds, 0.001);
            KpiSize = Format.Bytes(p.Bytes);
            KpiFiles = p.Files.ToString("N0");
            KpiDirs = p.Directories.ToString("N0");
            KpiDuration = Format.Duration(_sw.Elapsed);
            KpiErrors = p.Errors.ToString("N0");
            KpiSuspects = p.Suspects.ToString("N0");
            ProgressText = $"{p.Files / secs:N0} fichiers/s";
            CurrentPath = p.CurrentPath ?? "";
        }

        if (IsFindingDuplicates && _dupProgress is { } d)
        {
            DupPercent = d.BytesTotal > 0 ? d.BytesDone * 100.0 / d.BytesTotal : 0;
            DupStatus = $"{d.Stage} : {d.FilesDone:N0} / {d.FilesTotal:N0} fichiers · {Format.Bytes(d.BytesDone)} / {Format.Bytes(d.BytesTotal)}";
            StatusText = d.CurrentPath ?? "";
        }
    }

    private void StopTimerIfIdle()
    {
        if (!IsBusy) _timer.Stop();
    }

    private void BusyChanged()
    {
        OnPropertyChanged(nameof(IsBusy));
        CommandManager.InvalidateRequerySuggested();
    }

    private void AddRecent(string path)
    {
        for (int i = RecentPaths.Count - 1; i >= 0; i--)
            if (string.Equals(RecentPaths[i], path, StringComparison.OrdinalIgnoreCase)) RecentPaths.RemoveAt(i);
        RecentPaths.Insert(0, path);
        RecentStore.Save(RecentPaths);
    }
}
