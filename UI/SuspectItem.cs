using System.Windows.Media;
using StorageScanner.Core;

namespace StorageScanner.UI;

/// <summary>Ligne de l'onglet « Suspects », avec le résultat de la vérification antivirus.</summary>
public sealed class SuspectItem(SuspiciousFile file) : ObservableObject
{
    public SuspiciousFile File { get; } = file;
    public FileEntry Entry => File.Entry;
    public string Name => Entry.Name;
    public string FullPath => Entry.FullPath;
    public string DirectoryPath => Entry.DirectoryPath;
    public long Size => Entry.Size;
    public DateTime LastWriteUtc => Entry.LastWriteUtc;

    public bool IsDanger => File.Suspicion.Level == SuspicionLevel.Danger;
    public string LevelText => SuspicionRules.LevelText(File.Suspicion.Level);
    public string ReasonsText => File.ReasonsText;

    private string _avText = "Non vérifié";
    public string AvText { get => _avText; private set => Set(ref _avText, value); }

    private Brush? _avBrush;
    public Brush? AvBrush { get => _avBrush; private set => Set(ref _avBrush, value); }

    private bool _isChecking;
    public bool IsChecking { get => _isChecking; private set => Set(ref _isChecking, value); }

    public void SetChecking()
    {
        IsChecking = true;
        AvText = "Analyse en cours…";
        AvBrush = null;
    }

    public void SetResult(AvResult r)
    {
        IsChecking = false;
        AvText = r.Message;
        AvBrush = r.Verdict switch
        {
            AvVerdict.Threat => UsageColors.Red,
            AvVerdict.Clean => UsageColors.Green,
            _ => UsageColors.Yellow,
        };
    }
}
