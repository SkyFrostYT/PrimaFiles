using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace StorageScanner.Core;

public static class Format
{
    private static readonly string[] Units = ["Ko", "Mo", "Go", "To", "Po"];

    public static string Bytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} o";
        double v = bytes;
        int i = -1;
        do
        {
            v /= 1024;
            i++;
        } while (v >= 1024 && i < Units.Length - 1);
        string fmt = v < 10 ? "0.00" : v < 100 ? "0.0" : "0";
        return v.ToString(fmt, CultureInfo.CurrentCulture) + " " + Units[i];
    }

    public static string Duration(TimeSpan t) =>
        t.TotalHours >= 1 ? $"{(int)t.TotalHours} h {t.Minutes:00} min"
        : t.TotalMinutes >= 1 ? $"{t.Minutes} min {t.Seconds:00} s"
        : $"{t.TotalSeconds:0.0} s";
}

/// <summary>Tri « naturel » identique à l'Explorateur Windows (Dossier2 avant Dossier10).</summary>
public sealed class NaturalComparer : IComparer<string>
{
    public static readonly NaturalComparer Instance = new();

    [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int StrCmpLogicalW(string x, string y);

    public int Compare(string? x, string? y) => StrCmpLogicalW(x ?? "", y ?? "");
}

/// <summary>Capacité d'un volume local ou d'un partage UNC, quotas disque inclus
/// (GetDiskFreeSpaceEx renvoie les valeurs applicables à l'utilisateur courant).</summary>
public readonly record struct VolumeSpace(long Total, long Free)
{
    public long Used => Total - Free;
    public double UsedPercent => Total > 0 ? Used * 100.0 / Total : 0;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDiskFreeSpaceExW(string directory, out ulong freeAvailableToCaller, out ulong totalForCaller, out ulong totalFree);

    public static VolumeSpace? TryGet(string path)
    {
        try
        {
            string dir = path.EndsWith('\\') ? path : path + "\\";
            if (GetDiskFreeSpaceExW(dir, out var free, out var total, out _) && total > 0)
                return new VolumeSpace((long)total, (long)free);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { }
        return null;
    }

    /// <summary>Vrai si le chemin est la racine d'un volume (C:\) ou d'un partage (\\serveur\partage).</summary>
    public static bool IsVolumeRoot(string path)
    {
        var root = Path.GetPathRoot(path);
        return root is not null && string.Equals(root.TrimEnd('\\'), path.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
    }
}

public static class CsvExport
{
    private const char Sep = ';'; // séparateur attendu par Excel en français

    private static string Esc(string s)
    {
        // Protection contre l'injection de formules Excel : un nom de fichier commençant par = + - @ serait
        // interprété comme une formule à l'ouverture du CSV. On le neutralise avec une apostrophe.
        if (s.Length > 0 && s[0] is '=' or '+' or '-' or '@' or '\t' or '\r') s = "'" + s;
        return s.AsSpan().IndexOfAny(";\"\r\n") >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }

    private static string Date(DateTime utc) =>
        utc == default ? "" : utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    private static StreamWriter Open(string file) => new(file, false, new UTF8Encoding(true));

    /// <summary>Exporte tous les dossiers dans l'ordre de l'arborescence Windows.</summary>
    public static Task TreeAsync(DirNode root, string file) => Task.Run(() =>
    {
        using var w = Open(file);
        w.WriteLine(string.Join(Sep, "Chemin", "Profondeur", "Taille (octets)", "Taille", "Fichiers", "Sous-dossiers", "Fichiers directs", "Taille fichiers directs (octets)", "Dernière modif. contenu", "Lien/Jonction", "Erreur"));
        var stack = new Stack<(DirNode Node, string Path, int Depth)>();
        stack.Push((root, root.FullPath, 0));
        while (stack.Count > 0)
        {
            var (n, path, depth) = stack.Pop();
            w.WriteLine(string.Join(Sep, Esc(path), depth, n.TotalSize, Esc(Format.Bytes(n.TotalSize)), n.TotalFiles, n.TotalDirs,
                n.OwnFileCount, n.OwnFilesSize, Date(n.NewestFileUtc), n.IsReparsePoint ? "oui" : "", n.HasError ? "oui" : ""));
            if (n.Children is { } ch)
            {
                var sorted = ch.ToList();
                sorted.Sort((a, b) => NaturalComparer.Instance.Compare(b.Name, a.Name)); // inversé : la pile dépile dans l'ordre
                foreach (var c in sorted) stack.Push((c, path.TrimEnd('\\') + "\\" + c.Name, depth + 1));
            }
        }
    });

    public static Task FilesAsync(IEnumerable<FileEntry> files, string file) => Task.Run(() =>
    {
        using var w = Open(file);
        w.WriteLine(string.Join(Sep, "Chemin", "Nom", "Extension", "Taille (octets)", "Taille", "Dernière modif."));
        foreach (var f in files)
            w.WriteLine(string.Join(Sep, Esc(f.FullPath), Esc(f.Name), Esc(f.Extension), f.Size, Esc(Format.Bytes(f.Size)), Date(f.LastWriteUtc)));
    });

    public static Task ExtensionsAsync(IEnumerable<ExtensionStat> stats, string file) => Task.Run(() =>
    {
        using var w = Open(file);
        w.WriteLine(string.Join(Sep, "Extension", "Fichiers", "Taille (octets)", "Taille", "% total", "Taille moyenne (octets)"));
        foreach (var s in stats)
            w.WriteLine(string.Join(Sep, Esc(s.Extension), s.Count, s.Size, Esc(Format.Bytes(s.Size)), s.Percent.ToString("0.00", CultureInfo.CurrentCulture), s.AverageSize));
    });

    public static Task DuplicatesAsync(IEnumerable<DuplicateGroup> groups, string file) => Task.Run(() =>
    {
        using var w = Open(file);
        w.WriteLine(string.Join(Sep, "Groupe", "SHA-256", "Taille (octets)", "Taille", "Copies", "Espace récupérable (octets)", "Chemin", "Dernière modif."));
        int id = 0;
        foreach (var g in groups)
        {
            id++;
            foreach (var f in g.Files)
                w.WriteLine(string.Join(Sep, id, g.Hash, g.Size, Esc(Format.Bytes(g.Size)), g.Count, g.WastedSize, Esc(f.FullPath), Date(f.LastWriteUtc)));
        }
    });

    public static Task SuspectsAsync(IEnumerable<(SuspiciousFile File, string Antivirus)> items, string file) => Task.Run(() =>
    {
        using var w = Open(file);
        w.WriteLine(string.Join(Sep, "Niveau", "Chemin", "Raisons", "Taille (octets)", "Dernière modif.", "Vérification antivirus"));
        foreach (var (s, av) in items)
            w.WriteLine(string.Join(Sep, SuspicionRules.LevelText(s.Suspicion.Level), Esc(s.Entry.FullPath), Esc(s.ReasonsText),
                s.Entry.Size, Date(s.Entry.LastWriteUtc), Esc(av)));
    });

    public static Task ErrorsAsync(IEnumerable<ScanError> errors, string file) => Task.Run(() =>
    {
        using var w = Open(file);
        w.WriteLine(string.Join(Sep, "Chemin", "Erreur"));
        foreach (var e in errors) w.WriteLine(string.Join(Sep, Esc(e.Path), Esc(e.Message.ReplaceLineEndings(" "))));
    });
}
