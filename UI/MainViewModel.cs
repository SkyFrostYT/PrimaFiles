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
        ? Loc.F("suspicionTip", SuspicionRules.LevelText(Suspicion.Level), SuspicionRules.Describe(Suspicion.Reasons))
        : null;

    public string Name { get; } = name;
    public long Size { get; } = size;
    public DateTime LastWriteUtc { get; } = lastWriteUtc;
    public string FullPath { get; } = fullPath;
    public string Extension => Path.GetExtension(Name).ToLowerInvariant();

    public SafetyLevel Safety { get; } = StorageScanner.Core.Safety.ForFile(context, name, attributes);
    // Jamais de logo Windows ni de triangle « à ne pas supprimer » sur un fichier suspect : ce serait un gage de confiance
    public bool IsSystem => Safety != SafetyLevel.Normal && !Suspicion.IsSuspect;
    public bool IsCritical => Safety == SafetyLevel.Critical && !Suspicion.IsSuspect;
    public string? SafetyText => IsSystem ? StorageScanner.Core.Safety.Describe(Safety) : null;
}

public sealed class DriveItem(string root, string title, string detail, double usedPercent, bool isNetwork)
{
    public string Root { get; } = root;
    public string Title { get; } = title;
    public string Detail { get; } = detail;
    public string Kind => Loc.T(isNetwork ? "networkDrive" : "localDisk");
    public string ToolTip => Loc.F("scanX", Root);
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
            _avDetected = true;
            OnPropertyChanged(nameof(AvName));
            CommandManager.InvalidateRequerySuggested();
        }), TaskScheduler.Default);
        Loc.Changed += OnLanguageChanged;
        ThemeManager.Changed += () =>
        {
            OnPropertyChanged(nameof(ThemeGlyph));
            OnPropertyChanged(nameof(ThemeTooltip));
        };
        if (Elevation.IsElevated)
        {
            bool backup = Elevation.EnableBackupPrivilege();
            _statusText = Loc.T(backup ? "adminStatusBackup" : "adminStatus");
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

    private bool _avDetected;
    public string AvName => !_avDetected ? Loc.T("avSearching") : _av is null ? Loc.T("avNone") : Loc.F("avBy", _av.Name);

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
    public string SuspectsHeader => Suspects.Count > 0 ? $"{Loc.T("suspectsHeader")} ({Suspects.Count:N0})" : Loc.T("suspectsHeader");
    public string SuspectsSummary
    {
        get
        {
            int danger = Suspects.Count(s => s.IsDanger);
            int warn = Suspects.Count - danger;
            return Loc.F("suspectsSummary", danger, warn);
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
                StatusText = Loc.F("avChecking", ++done, items.Count, item.Name);
                var r = await _av.ScanAsync(item.FullPath, _avCts.Token);
                item.SetResult(r);
                if (r.Verdict == AvVerdict.Threat) threats++;
            }
            StatusText = threats > 0
                ? Loc.F("avThreats", threats, _av.Name)
                : Loc.F("avDone", _av.Name, done);
        }
        finally
        {
            IsAvChecking = false;
        }
    }

    /// <summary>Vérification d'un fichier quelconque (menu contextuel).</summary>
    public Task<AvResult> CheckFileAsync(string path) =>
        _av is null
            ? Task.FromResult(new AvResult(AvVerdict.Error, Loc.T("avNoneFile")))
            : _av.ScanAsync(path);

    // ---- Textes du résultat (recalculés au changement de langue) ----

    private VolumeSpace? _volume;
    private double? _rootPercent;
    private bool _showScanSummary; // la barre d'état affiche le bilan de l'analyse (et non un autre message)

    private string? VolumeInfoText() => _volume is { } v
        ? Loc.F("volumeInfo", Format.Bytes(v.Used), Format.Bytes(v.Total), v.UsedPercent, Format.Bytes(v.Free)) : null;

    private void UpdateResultTexts()
    {
        if (Result is not { } r) return;
        KpiSize = Format.Bytes(r.Root.TotalSize);
        KpiSizeSub = _volume is { } v ? Loc.F("volumeShare", _rootPercent, Format.Bytes(v.Total)) : "";
        if (_showScanSummary)
        {
            StatusText = Loc.T(r.Cancelled ? "scanPartial" : "scanDone")
                         + " · " + Loc.F("filesPerSec", r.Root.TotalFiles / Math.Max(r.Duration.TotalSeconds, 0.001))
                         + (r.Suspicious.Count > 0 ? Loc.F("scanSuspects", r.Suspicious.Count) : "");
            _showScanSummary = true; // StatusText vient de remettre l'indicateur à faux
        }
    }

    // ---- Langue ----

    public string LanguageCode => Loc.Current.ToUpperInvariant();

    /// <summary>Changement de langue à chaud : les textes calculés sont réévalués, les listes déjà affichées
    /// régénérées et les messages d'état remis dans la nouvelle langue.</summary>
    private void OnLanguageChanged()
    {
        OnPropertyChanged(string.Empty); // toutes les propriétés calculées (en-têtes, info-bulles, résumés…)

        if (!IsBusy && Result is null) StatusText = Loc.T("ready");
        else if (!IsBusy) UpdateResultTexts();
        if (!IsFindingDuplicates && Duplicates.Count == 0)
            DupStatus = Result is { } r ? Loc.F("dupCandidates", r.DuplicateCandidates.Count, Format.Bytes(r.DuplicateMinSize)) : Loc.T("dupIdle");
        FolderSearchStatus = "";
        _ = LoadFolderFilesAsync(SelectedTreeRow);
        _ = RefreshStaleFoldersAsync();
        _ = LoadDrivesAsync();

        // Lignes déjà générées : leurs textes (noms, info-bulles, raisons) sont recalculés
        foreach (var list in new System.Collections.IEnumerable?[] { Tree.Rows, TopFiles, Extensions, Errors, Duplicates, Suspects, StaleFolders })
            if (list is not null) System.Windows.Data.CollectionViewSource.GetDefaultView(list)?.Refresh();
    }

    public bool IsElevated => Elevation.IsElevated;
    public string AppVersionText => "PrimaFiles " + Installation.CurrentVersion.ToString(3)
        + (Installation.IsRunningInstalled ? "" : Loc.T("notInstalled"));
    public string ThemeGlyph => ThemeManager.IsDark ? "\xE706" : "\xE708"; // soleil / lune
    public string ThemeTooltip => Loc.T(ThemeManager.IsDark ? "themeToLight" : "themeToDark");

    /// <summary>Chemin transmis au lancement : relance en administrateur (--path "…") ou menu « Analyser avec
    /// PrimaFiles » de l'Explorateur (--scan "…", l'analyse démarre aussitôt).</summary>
    private static string? InitialPathFromArgs()
    {
        var args = Environment.GetCommandLineArgs();
        foreach (var flag in new[] { "--scan", "--path" })
        {
            int i = Array.FindIndex(args, a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));
            // « "C:\" » arrive sous la forme « C:" » (la barre finale échappe le guillemet) : guillemets retirés
            if (i >= 0 && i + 1 < args.Length && args[i + 1].Trim().Trim('"') is { Length: > 0 and < 32_767 } p) return p;
        }
        return null;
    }

    /// <summary>Vrai si l'analyse doit démarrer dès l'ouverture (menu contextuel de l'Explorateur).</summary>
    public bool StartScanOnLoad { get; } =
        Environment.GetCommandLineArgs().Any(a => string.Equals(a, "--scan", StringComparison.OrdinalIgnoreCase));

    public TreeModel Tree { get; } = new();
    public ObservableCollection<string> RecentPaths { get; } = [];
    public ObservableCollection<DriveItem> Drives { get; } = [];

    // ---- Paramètres ----

    private string _rootPath;
    public string RootPath { get => _rootPath; set => Set(ref _rootPath, value); }

    private int _threads = SettingsStore.GetInt("threads", 16, 1, 128);
    public int Threads
    {
        get => _threads;
        set { if (Set(ref _threads, Math.Clamp(value, 1, 128))) SettingsStore.Set("threads", _threads); }
    }

    private double _dupMinSizeMb = SettingsStore.GetDouble("dupMinSizeMb", 1, 0.001, 1_000_000);
    public double DupMinSizeMb
    {
        get => _dupMinSizeMb;
        set { if (Set(ref _dupMinSizeMb, Math.Clamp(value, 0.001, 1_000_000))) SettingsStore.Set("dupMinSizeMb", _dupMinSizeMb); }
    }

    private int _dupThreads = SettingsStore.GetInt("dupThreads", 8, 1, 64);
    public int DupThreads
    {
        get => _dupThreads;
        set { if (Set(ref _dupThreads, Math.Clamp(value, 1, 64))) SettingsStore.Set("dupThreads", _dupThreads); }
    }

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

    private string _statusText = Loc.T("ready");
    public string StatusText
    {
        get => _statusText;
        private set
        {
            _showScanSummary = false;
            Set(ref _statusText, value);
        }
    }

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
            _searchMatches = null;
            _searchIndex = -1;
            FolderSearchStatus = "";
            _ = RefreshStaleFoldersAsync();
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
    public string ErrorsHeader => Result is { Errors.Count: > 0 } r ? $"{Loc.T("errorsHeader")} ({r.Errors.Count:N0})" : Loc.T("errorsHeader");
    public string TopFilesHeader => Result is { } r ? Loc.F("topFilesHeader", r.TopFiles.Count) : "";

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

    private string _folderFilesTitle = Loc.T("filesTitle");
    public string FolderFilesTitle { get => _folderFilesTitle; private set => Set(ref _folderFilesTitle, value); }

    private string _folderFilesHeader = Loc.T("selectFolder");
    public string FolderFilesHeader { get => _folderFilesHeader; private set => Set(ref _folderFilesHeader, value); }

    private IReadOnlyList<DuplicateGroup> _duplicates = [];
    public IReadOnlyList<DuplicateGroup> Duplicates { get => _duplicates; private set => Set(ref _duplicates, value); }

    private DuplicateGroup? _selectedDuplicate;
    public DuplicateGroup? SelectedDuplicate { get => _selectedDuplicate; set => Set(ref _selectedDuplicate, value); }

    private string _dupStatus = Loc.T("dupIdle");
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

    // ---- Dossiers inactifs (aucun fichier modifié depuis N ans) ----

    public static int[] StaleYearChoices { get; } = [1, 2, 3, 5, 10];

    private int _staleYears = SettingsStore.GetInt("staleYears", 3, 1, 10);
    public int StaleYears
    {
        get => _staleYears;
        set
        {
            if (!Set(ref _staleYears, value)) return;
            SettingsStore.Set("staleYears", value);
            _ = RefreshStaleFoldersAsync();
        }
    }

    private IReadOnlyList<StaleFolder> _staleFolders = [];
    public IReadOnlyList<StaleFolder> StaleFolders { get => _staleFolders; private set => Set(ref _staleFolders, value); }

    private string _staleSummary = "";
    public string StaleSummary { get => _staleSummary; private set => Set(ref _staleSummary, value); }

    private async Task RefreshStaleFoldersAsync()
    {
        if (Result is not { } r)
        {
            StaleFolders = [];
            StaleSummary = "";
            return;
        }
        var cutoff = DateTime.UtcNow.AddYears(-StaleYears);
        int years = StaleYears;
        var list = await Task.Run(() => UI.StaleFolders.Find(r.Root, cutoff));
        if (!ReferenceEquals(r, Result) || years != StaleYears) return; // résultat périmé entre-temps
        StaleFolders = list;
        StaleSummary = list.Count == 0
            ? Loc.F("staleNone", years)
            : Loc.F("staleResult", list.Count, years, Format.Bytes(list.Sum(s => s.Size)));
    }

    // ---- Recherche d'un dossier par son nom ----

    private const int MaxSearchMatches = 50_000;
    private string _folderSearchText = "";
    private List<DirNode>? _searchMatches;
    private string? _searchMatchesFor;
    private int _searchIndex = -1;

    public string FolderSearchText
    {
        get => _folderSearchText;
        set
        {
            if (!Set(ref _folderSearchText, value)) return;
            _searchMatches = null;
            _searchIndex = -1;
            FolderSearchStatus = "";
        }
    }

    private string _folderSearchStatus = "";
    public string FolderSearchStatus { get => _folderSearchStatus; private set => Set(ref _folderSearchStatus, value); }

    public ICommand FindNextFolderCommand => _findNext ??= new RelayCommand(_ => FindFolder(+1), _ => CanSearch);
    public ICommand FindPreviousFolderCommand => _findPrev ??= new RelayCommand(_ => FindFolder(-1), _ => CanSearch);
    private ICommand? _findNext, _findPrev;
    private bool CanSearch => Result is not null && !IsScanning && !string.IsNullOrWhiteSpace(FolderSearchText);

    /// <summary>Dossier suivant / précédent dont le nom contient le texte recherché (ordre de l'arborescence Windows).</summary>
    public void FindFolder(int direction)
    {
        if (Result is not { } r || string.IsNullOrWhiteSpace(FolderSearchText)) return;
        string text = FolderSearchText.Trim();
        if (_searchMatches is null || _searchMatchesFor != text)
        {
            _searchMatches = SearchFolders(r.Root, text);
            _searchMatchesFor = text;
            _searchIndex = -1;
        }
        if (_searchMatches.Count == 0)
        {
            FolderSearchStatus = Loc.T("searchNone");
            return;
        }
        _searchIndex = ((_searchIndex + direction) % _searchMatches.Count + _searchMatches.Count) % _searchMatches.Count;
        FolderSearchStatus = $"{_searchIndex + 1:N0} / {_searchMatches.Count:N0}" + (_searchMatches.Count >= MaxSearchMatches ? "+" : "");
        ShowInTree(_searchMatches[_searchIndex]);
    }

    private static List<DirNode> SearchFolders(DirNode root, string text)
    {
        var matches = new List<DirNode>();
        var stack = new Stack<DirNode>();
        stack.Push(root);
        while (stack.Count > 0 && matches.Count < MaxSearchMatches)
        {
            var n = stack.Pop();
            if (n.Parent is not null && n.Name.Contains(text, StringComparison.CurrentCultureIgnoreCase)) matches.Add(n);
            if (n.Children is not { Count: > 0 } ch) continue;
            var sorted = ch.ToList();
            sorted.Sort((a, b) => NaturalComparer.Instance.Compare(b.Name, a.Name)); // la pile inverse l'ordre
            foreach (var c in sorted) stack.Push(c);
        }
        return matches;
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
        StatusText = Loc.T("ready");
        ProgressText = "";
        GC.Collect();
        _ = LoadDrivesAsync();
    }

    private void ResetKpis()
    {
        KpiSize = KpiFiles = KpiDirs = KpiDuration = KpiErrors = KpiSuspects = Dash;
        KpiSizeSub = "";
    }

    private static Task? s_reconnect;

    /// <summary>Mode administrateur : reconnecte une fois les lecteurs réseau de la session normale (voir <see cref="Unc"/>).</summary>
    private static Task ReconnectNetworkDrivesAsync() => s_reconnect ??= !Elevation.IsElevated
        ? Task.CompletedTask
        : Task.Run(() =>
        {
            var map = Unc.GetPersistentMappings();
            foreach (var (k, v) in Unc.ParseDriveMapArgs(Environment.GetCommandLineArgs())) map[k] = v;
            Unc.ReconnectMissing(map);
        });

    private async Task LoadDrivesAsync()
    {
        await ReconnectNetworkDrivesAsync();
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
                        ?? (!string.IsNullOrWhiteSpace(d.VolumeLabel) ? d.VolumeLabel : Loc.T(network ? "networkDrive" : "localDisk"));
                    list.Add(new DriveItem(d.RootDirectory.FullName, $"{d.Name.TrimEnd('\\')}  {label}",
                        Loc.F("freeOf", Format.Bytes(d.AvailableFreeSpace), Format.Bytes(d.TotalSize)),
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
        var dlg = new OpenFolderDialog { Title = Loc.T("browseTitle") };
        if (Directory.Exists(RootPath)) dlg.InitialDirectory = RootPath;
        if (dlg.ShowDialog() == true) RootPath = dlg.FolderName;
    }

    private async Task ScanAsync()
    {
        await ReconnectNetworkDrivesAsync(); // lettre réseau demandée juste après le passage en administrateur
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
        DupStatus = Loc.T("dupIdle");
        GC.Collect();

        _scanCts = new CancellationTokenSource();
        _scanProgress = new ScanProgress();
        // Lecteur mappé : seul le nom du partage est affiché, jamais le nom du serveur (confidentialité)
        string? share = Unc.ShareName(await Task.Run(() => Unc.GetMappedUnc(path)));
        ScanTarget = path;
        IsScanning = true;
        StatusText = Loc.T("scanRunning");
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
            if (volume is { } v)
            {
                // Racine d'un disque ou d'un partage : occupation réelle (quota inclus). Sous-dossier : sa part du volume.
                bool isRoot = VolumeSpace.IsVolumeRoot(path);
                rootPercent = isRoot ? v.UsedPercent : root.TotalSize * 100.0 / v.Total;
            }
            _volume = volume;
            _rootPercent = rootPercent;
            Result = r;
            Tree.Load(root, rootPercent, VolumeInfoText, share is null ? null : $"{root.Name}   ({share})");
            KpiFiles = root.TotalFiles.ToString("N0");
            KpiDirs = root.TotalDirs.ToString("N0");
            KpiDuration = Format.Duration(r.Duration);
            KpiErrors = r.Errors.Count.ToString("N0");
            KpiSuspects = r.Suspicious.Count.ToString("N0");
            _showScanSummary = true;
            UpdateResultTexts();
            DupStatus = Loc.F("dupCandidates", r.DuplicateCandidates.Count, Format.Bytes(r.DuplicateMinSize));
            if (Tree.Rows.Count > 0) RevealRowRequested?.Invoke(Tree.Rows[0], false);
        }
        catch (Exception ex)
        {
            ScanTarget = "";
            ResetKpis();
            StatusText = Loc.F("errorPrefix", ex.Message);
            MessageBox.Show(ex.Message, Loc.T("scanImpossible"), MessageBoxButton.OK, MessageBoxImage.Warning);
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
            note = Loc.F("dupThreshold", Format.Bytes(min));
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
                ? Loc.F("dupNone", Format.Duration(sw.Elapsed), note)
                : Loc.F("dupResult", groups.Count, groups.Sum(g => g.Count), Format.Bytes(groups.Sum(g => g.WastedSize)), Format.Duration(sw.Elapsed))
                  + (_dupProgress.Errors > 0 ? Loc.F("dupUnreadable", _dupProgress.Errors) : "")
                  + note;
        }
        catch (OperationCanceledException)
        {
            DupStatus = Loc.T("dupCancelled");
        }
        catch (Exception ex)
        {
            DupStatus = Loc.F("errorPrefix", ex.Message);
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
            FolderFilesTitle = Loc.T("filesTitle");
            FolderFilesHeader = Loc.T("selectFolder");
            return;
        }

        string path = row.FullPath;
        FolderFilesTitle = row.Node.Name;
        FolderFilesHeader = Loc.T("loading");
        try
        {
            await Task.Delay(200, cts.Token); // anti-rebond pendant la navigation au clavier
            var items = await Task.Run(() =>
            {
                var opts = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = 0, BufferSize = 64 * 1024 };
                var context = DirContext.For(path);
                var e = new FileSystemEnumerable<FolderFileItem>(SafePath.ForIo(path),
                    (ref FileSystemEntry en) =>
                    {
                        string name = en.FileName.ToString();
                        return new FolderFileItem(name, en.Length, en.LastWriteTimeUtc.UtcDateTime,
                            Path.Join(path, name), path, en.Attributes, context);
                    },
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
                ? Loc.T("noDirectFiles")
                : Loc.F("folderFiles", items.Count, Format.Bytes(items.Sum(i => i.Size))) + (items.Count >= MaxFolderFiles ? Loc.T("truncated") : "");
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            if (!cts.IsCancellationRequested) FolderFilesHeader = Loc.F("errorPrefix", SafePath.Display(ex.Message));
        }
    }

    private async Task ExportAsync()
    {
        var r = Result;
        if (r is null) return;

        string defaultName = SelectedTabIndex switch
        {
            1 => Loc.T("csvBig"),
            2 => Loc.T("csvTypes"),
            3 => Loc.T("csvDup"),
            4 => Loc.T("csvSuspects"),
            5 => Loc.T("csvErrors"),
            6 => Loc.T("csvStale"),
            _ => Loc.T("csvTree"),
        };
        var dlg = new SaveFileDialog
        {
            Title = Loc.T("exportTitle"),
            Filter = Loc.T("csvFilter"),
            FileName = $"{defaultName}_{DateTime.Now:yyyyMMdd_HHmm}.csv",
        };
        if (dlg.ShowDialog() != true) return;

        StatusText = Loc.T("exporting");
        try
        {
            await (SelectedTabIndex switch
            {
                1 => CsvExport.FilesAsync(r.TopFiles, dlg.FileName),
                2 => CsvExport.ExtensionsAsync(r.Extensions, dlg.FileName),
                3 => CsvExport.DuplicatesAsync(Duplicates, dlg.FileName),
                4 => CsvExport.SuspectsAsync(Suspects.Select(s => (s.File, s.AvText)), dlg.FileName),
                5 => CsvExport.ErrorsAsync(r.Errors, dlg.FileName),
                6 => CsvExport.StaleAsync(StaleFolders.Select(s => (s.FullPath, s.Size, s.Files, s.NewestUtc)), dlg.FileName),
                _ => CsvExport.TreeAsync(r.Root, dlg.FileName),
            });
            StatusText = Loc.F("exported", dlg.FileName);
        }
        catch (Exception ex)
        {
            StatusText = Loc.F("exportFailed", ex.Message);
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
            ProgressText = Loc.F("filesPerSec", p.Files / secs);
            CurrentPath = p.CurrentPath ?? "";
        }

        if (IsFindingDuplicates && _dupProgress is { } d)
        {
            DupPercent = d.BytesTotal > 0 ? d.BytesDone * 100.0 / d.BytesTotal : 0;
            DupStatus = Loc.F("dupProgress", d.Stage, d.FilesDone, d.FilesTotal, Format.Bytes(d.BytesDone), Format.Bytes(d.BytesTotal));
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
