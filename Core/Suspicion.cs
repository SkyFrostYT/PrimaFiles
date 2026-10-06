using System.Buffers;

namespace StorageScanner.Core;

public enum SuspicionLevel : byte
{
    None,
    /// <summary>À vérifier : indice faible ou emplacement inhabituel.</summary>
    Warning,
    /// <summary>Fortement suspect : technique typique des logiciels malveillants.</summary>
    Danger,
}

[Flags]
public enum SuspicionReason : ushort
{
    None = 0,
    HiddenCharacters = 1 << 0,
    DoubleExtension = 1 << 1,
    RansomwareExtension = 1 << 2,
    RansomNote = 1 << 3,
    SystemImpersonation = 1 << 4,
    RiskyFileType = 1 << 5,
    RiskyLocation = 1 << 6,
    Startup = 1 << 7,
    HiddenExecutable = 1 << 8,
}

public readonly record struct Suspicion(SuspicionLevel Level, SuspicionReason Reasons)
{
    public bool IsSuspect => Level != SuspicionLevel.None;
}

/// <summary>Caractéristiques d'un dossier utiles aux règles, calculées une seule fois par dossier.</summary>
public readonly struct DirContext
{
    private readonly Flags _flags;

    [Flags]
    private enum Flags : ushort
    {
        Windows = 1, ProgramFiles = 2, Temp = 4, Downloads = 8, Startup = 16, RecycleBin = 32, Public = 64, DevTree = 128,
    }

    private DirContext(Flags flags) => _flags = flags;

    public bool IsWindows => (_flags & Flags.Windows) != 0;
    public bool IsProgramFiles => (_flags & Flags.ProgramFiles) != 0;
    /// <summary>Dossiers d'installation (Windows, Program Files, applications par utilisateur) : les règles
    /// d'emplacement ne s'y appliquent pas, elles n'y produiraient que des faux positifs.</summary>
    public bool IsTrusted => (_flags & (Flags.Windows | Flags.ProgramFiles)) != 0;
    public bool IsStartup => (_flags & Flags.Startup) != 0;
    /// <summary>Arborescence de développement ou de bibliothèques (node_modules, .git, site-packages…).</summary>
    public bool IsDevTree => (_flags & Flags.DevTree) != 0;
    public bool IsTemp => (_flags & Flags.Temp) != 0;
    /// <summary>Emplacements où les logiciels malveillants se déposent volontiers. Pour Temp et Téléchargements,
    /// seuls le dossier lui-même et ses sous-dossiers directs comptent : un projet décompressé plus bas n'est pas visé.</summary>
    public bool IsRisky => !IsTrusted && !IsDevTree
                           && (_flags & (Flags.Temp | Flags.Downloads | Flags.Startup | Flags.RecycleBin | Flags.Public)) != 0;

    private static readonly string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');

    private static readonly string[] WindowsLike = [@"\Windows.old\", @"\$Windows.~BT\", @"\$Windows.~WS\", @"\$WinREAgent\"];
    private static readonly string[] InstallDirs = [@"\Program Files", @"\ProgramData\Microsoft\", @"\AppData\Local\Programs\", @"\AppData\Local\Microsoft\"];
    private static readonly string[] DevMarkers =
    [
        @"\node_modules\", @"\.git\", @"\site-packages\", @"\dist-packages\", @"\vendor\", @"\.gradle\", @"\.m2\",
        @"\libraries\", @"\.nuget\", @"\packages\", @"\.venv\", @"\venv\", @"\.cargo\", @"\target\", @"\bin\Debug\", @"\bin\Release\",
    ];

    public static DirContext For(string path)
    {
        var f = (Flags)0;
        if (StartsWithDir(path, WindowsDir) || ContainsAny(path, WindowsLike)) f |= Flags.Windows;
        if (ContainsAny(path, InstallDirs)) f |= Flags.ProgramFiles;
        if (ContainsAny(path + "\\", DevMarkers)) f |= Flags.DevTree;
        if (IsShallowUnder(path, "temp") || IsShallowUnder(path, "tmp")) f |= Flags.Temp;
        if (IsShallowUnder(path, "downloads") || IsShallowUnder(path, "téléchargements")) f |= Flags.Downloads;
        if (path.Contains(@"\Start Menu\Programs\Startup", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\Menu Démarrer\Programmes\Démarrage", StringComparison.OrdinalIgnoreCase)) f |= Flags.Startup;
        if (path.Contains(@"\$Recycle.Bin", StringComparison.OrdinalIgnoreCase)) f |= Flags.RecycleBin;
        if (path.Contains(@"\Users\Public", StringComparison.OrdinalIgnoreCase)) f |= Flags.Public;
        return new DirContext(f);
    }

    private static bool ContainsAny(string path, string[] parts)
    {
        foreach (var p in parts)
            if (path.Contains(p, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static bool StartsWithDir(string path, string dir) =>
        dir.Length > 0 && path.StartsWith(dir, StringComparison.OrdinalIgnoreCase)
        && (path.Length == dir.Length || path[dir.Length] == '\\');

    /// <summary>Vrai si le chemin est le dossier « segment » lui-même ou un de ses sous-dossiers directs.</summary>
    private static bool IsShallowUnder(string path, string segment)
    {
        string token = $@"\{segment}";
        int i = path.LastIndexOf(token + "\\", StringComparison.OrdinalIgnoreCase);
        if (i < 0) return path.EndsWith(token, StringComparison.OrdinalIgnoreCase);
        int start = i + token.Length + 1;
        return path.IndexOf('\\', start) < 0; // au plus un niveau sous le dossier
    }
}

/// <summary>Repère les fichiers potentiellement malveillants à partir d'indices (nom, extension, emplacement,
/// attributs). Ce n'est pas un antivirus : un fichier signalé doit être vérifié, pas supprimé à l'aveugle.
/// Conçu pour être appelé sur chaque fichier pendant le scan : aucune allocation pour un fichier ordinaire.</summary>
public static class SuspicionRules
{
    private enum Kind : byte { Executable, HighRisk, Script, Text }

    private static readonly Dictionary<string, Kind> KindMap = new(StringComparer.OrdinalIgnoreCase)
    {
        [".exe"] = Kind.Executable, [".msi"] = Kind.Executable, [".dll"] = Kind.Executable, [".cpl"] = Kind.Executable,
        // Types quasiment jamais légitimes hors de Windows : économiseurs d'écran, anciens exécutables, scripts Windows Script Host
        [".scr"] = Kind.HighRisk, [".pif"] = Kind.HighRisk, [".com"] = Kind.HighRisk, [".hta"] = Kind.HighRisk,
        [".vbs"] = Kind.HighRisk, [".vbe"] = Kind.HighRisk, [".jse"] = Kind.HighRisk, [".wsf"] = Kind.HighRisk, [".wsh"] = Kind.HighRisk,
        [".js"] = Kind.Script, [".ps1"] = Kind.Script, [".bat"] = Kind.Script, [".cmd"] = Kind.Script, [".jar"] = Kind.Script,
        [".txt"] = Kind.Text, [".html"] = Kind.Text, [".htm"] = Kind.Text, [".rtf"] = Kind.Text,
    };
    private static readonly Dictionary<string, Kind>.AlternateLookup<ReadOnlySpan<char>> Kinds = KindMap.GetAlternateLookup<ReadOnlySpan<char>>();

    /// <summary>Extensions « leurres » placées devant une extension exécutable (facture.pdf.exe).</summary>
    private static readonly HashSet<string> DecoySet = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".txt", ".rtf", ".csv",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".avi", ".mov", ".wav", ".zip", ".rar", ".7z",
    };
    private static readonly HashSet<string>.AlternateLookup<ReadOnlySpan<char>> Decoys = DecoySet.GetAlternateLookup<ReadOnlySpan<char>>();

    /// <summary>Extensions ajoutées par des rançongiciels connus aux fichiers chiffrés.</summary>
    private static readonly HashSet<string> RansomSet = new(StringComparer.OrdinalIgnoreCase)
    {
        ".locky", ".wncry", ".wnry", ".wcry", ".cerber", ".cerber3", ".zepto", ".odin", ".thor", ".aesir", ".lockbit",
        ".ryk", ".ryuk", ".conti", ".crypted", ".cryptolocker", ".encrypted", ".locked", ".kraken", ".petya",
        ".phobos", ".djvu", ".makop", ".hive", ".basta", ".akira", ".blackcat", ".royal", ".medusa", ".rhysida",
    };
    private static readonly HashSet<string>.AlternateLookup<ReadOnlySpan<char>> Ransom = RansomSet.GetAlternateLookup<ReadOnlySpan<char>>();

    /// <summary>Noms de processus Windows souvent usurpés par les logiciels malveillants.</summary>
    private static readonly HashSet<string> SystemNameSet = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "wininit.exe", "services.exe", "smss.exe",
        "spoolsv.exe", "taskhostw.exe", "rundll32.exe", "dllhost.exe", "conhost.exe", "explorer.exe", "lsm.exe",
        "ctfmon.exe", "dwm.exe", "sihost.exe", "fontdrvhost.exe", "taskmgr.exe", "regsvr32.exe", "msiexec.exe",
    };
    private static readonly HashSet<string>.AlternateLookup<ReadOnlySpan<char>> SystemNames = SystemNameSet.GetAlternateLookup<ReadOnlySpan<char>>();

    /// <summary>Caractères de contrôle bidirectionnels : « facture\x202Efdp.exe » s'affiche « factureexe.pdf ».</summary>
    private static readonly SearchValues<char> BidiControls = SearchValues.Create("\x202A\x202B\x202C\x202D\x202E\x2066\x2067\x2068\x2069");

    /// <summary>Formules typiques des notes de rançon (« decrypt » seul est trop courant : documentation, protocoles…).</summary>
    private static readonly string[] RansomNoteKeywords =
    [
        "how_to_decrypt", "how-to-decrypt", "howtodecrypt", "how_decrypt", "decrypt_instruction", "decrypt-instruction",
        "decrypt_your", "decrypt-your", "decrypt_files", "decrypt-files", "readme_decrypt", "help_decrypt", "decryption_instructions",
        "how_to_recover", "how-to-recover", "restore-my-files", "restore_my_files", "recover_files", "recover-files",
        "your_files_are", "your-files-are", "files_encrypted", "files-encrypted", "readme_for_unlock", "ransom_note", "ransomnote",
    ];

    /// <summary>Comme <see cref="Evaluate(in DirContext, ReadOnlySpan{char}, FileAttributes)"/>, mais un simple
    /// « À vérifier » est levé si le fichier porte une signature numérique approuvée sur ce poste (scripts personnels
    /// signés, logiciels d'éditeurs reconnus). Les indices graves (« Suspect ») restent signalés même signés.</summary>
    public static Suspicion Evaluate(in DirContext dir, string directory, ReadOnlySpan<char> name, FileAttributes attributes)
    {
        var s = Evaluate(dir, name, attributes);
        return s.Level == SuspicionLevel.Warning && Authenticode.IsTrusted(Path.Join(directory, name)) ? default : s;
    }

    public static Suspicion Evaluate(in DirContext dir, ReadOnlySpan<char> name, FileAttributes attributes)
    {
        var reasons = SuspicionReason.None;
        var level = SuspicionLevel.None;

        if (name.IndexOfAny(BidiControls) >= 0)
            Raise(ref level, ref reasons, SuspicionLevel.Danger, SuspicionReason.HiddenCharacters);

        int dot = name.LastIndexOf('.');
        if (dot <= 0 || dot == name.Length - 1)
            return new Suspicion(level, reasons);
        var ext = name[dot..];

        if (Ransom.Contains(ext))
            Raise(ref level, ref reasons, SuspicionLevel.Danger, SuspicionReason.RansomwareExtension);

        if (!Kinds.TryGetValue(ext, out var kind))
            return new Suspicion(level, reasons);

        if (kind == Kind.Text)
        {
            if (!dir.IsTrusted && IsRansomNote(name))
                Raise(ref level, ref reasons, SuspicionLevel.Danger, SuspicionReason.RansomNote);
            return new Suspicion(level, reasons);
        }

        // facture.pdf.exe, photo.jpg   .scr… — uniquement pour ce qui s'ouvre d'un double-clic (pas les DLL :
        // « Windows.Data.Pdf.dll » est un nom de bibliothèque normal), et jamais dans le dossier Windows.
        bool launchable = kind != Kind.Executable || !ext.Equals(".dll", StringComparison.OrdinalIgnoreCase);
        if (launchable && !dir.IsWindows)
        {
            var stem = name[..dot].TrimEnd(' ');
            int dot2 = stem.LastIndexOf('.');
            if (dot2 > 0 && Decoys.Contains(stem[dot2..]) && IsLowerOrSpaced(name, dot2, dot))
                Raise(ref level, ref reasons, SuspicionLevel.Danger, SuspicionReason.DoubleExtension);
        }

        if (kind == Kind.Executable && !dir.IsWindows && SystemNames.Contains(name))
            Raise(ref level, ref reasons, SuspicionLevel.Danger, SuspicionReason.SystemImpersonation);

        // Règles d'emplacement : jamais dans Windows / Program Files / dépendances de développement
        if (!dir.IsTrusted && !dir.IsDevTree)
        {
            switch (kind)
            {
                case Kind.HighRisk when dir.IsRisky:
                    Raise(ref level, ref reasons, SuspicionLevel.Warning, SuspicionReason.RiskyFileType | SuspicionReason.RiskyLocation);
                    break;
                case Kind.HighRisk:
                    Raise(ref level, ref reasons, SuspicionLevel.Warning, SuspicionReason.RiskyFileType);
                    break;
                // Les scripts temporaires des installateurs sont trop fréquents dans Temp pour être signalés
                case Kind.Script when dir.IsRisky && !dir.IsTemp:
                    Raise(ref level, ref reasons, SuspicionLevel.Warning, SuspicionReason.RiskyLocation);
                    break;
            }

            if (kind is Kind.Executable or Kind.HighRisk && (attributes & FileAttributes.Hidden) != 0 && launchable)
                Raise(ref level, ref reasons, SuspicionLevel.Warning, SuspicionReason.HiddenExecutable);
        }

        // Démarrage automatique : surveillé partout, c'est un point d'ancrage classique des logiciels malveillants
        if (dir.IsStartup)
            Raise(ref level, ref reasons, SuspicionLevel.Warning, SuspicionReason.Startup);

        return new Suspicion(level, reasons);
    }

    /// <summary>Le leurre est écrit comme une vraie extension (« .pdf », « .PDF », « .jpg   ») et non comme un segment
    /// de nom en casse mixte de type « Windows.Data.Pdf » (bibliothèques, espaces de noms .NET).</summary>
    private static bool IsLowerOrSpaced(ReadOnlySpan<char> name, int decoyStart, int realDot)
    {
        var decoy = name[(decoyStart + 1)..realDot];
        if (decoy.Length > 0 && decoy[^1] == ' ') return true;
        bool hasUpper = false, hasLower = false;
        foreach (var c in decoy)
        {
            if (char.IsUpper(c)) hasUpper = true;
            else if (char.IsLower(c)) hasLower = true;
        }
        return !(hasUpper && hasLower);
    }

    private static bool IsRansomNote(ReadOnlySpan<char> name)
    {
        if (name.Equals("_readme.txt", StringComparison.OrdinalIgnoreCase)) return true; // famille STOP/Djvu
        foreach (var k in RansomNoteKeywords)
            if (name.Contains(k, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static void Raise(ref SuspicionLevel level, ref SuspicionReason reasons, SuspicionLevel l, SuspicionReason r)
    {
        reasons |= r;
        if (l > level) level = l;
    }

    public static string Describe(SuspicionReason r)
    {
        var parts = new List<string>(4);
        if (r.HasFlag(SuspicionReason.HiddenCharacters)) parts.Add("caractères invisibles qui inversent l'affichage du nom (vraie extension masquée)");
        if (r.HasFlag(SuspicionReason.DoubleExtension)) parts.Add("double extension : se fait passer pour un document alors que c'est un programme");
        if (r.HasFlag(SuspicionReason.RansomwareExtension)) parts.Add("extension typique d'un fichier chiffré par un rançongiciel");
        if (r.HasFlag(SuspicionReason.RansomNote)) parts.Add("ressemble à une demande de rançon");
        if (r.HasFlag(SuspicionReason.SystemImpersonation)) parts.Add("porte le nom d'un programme de Windows mais se trouve hors du dossier Windows");
        if (r.HasFlag(SuspicionReason.RiskyFileType)) parts.Add("type de fichier souvent utilisé par les virus (script / économiseur d'écran)");
        if (r.HasFlag(SuspicionReason.RiskyLocation)) parts.Add("situé dans un dossier à risque (Temp, Téléchargements, Corbeille, Public, Démarrage)");
        if (r.HasFlag(SuspicionReason.Startup)) parts.Add("se lance automatiquement au démarrage de Windows");
        if (r.HasFlag(SuspicionReason.HiddenExecutable)) parts.Add("programme caché hors des dossiers d'applications");
        return string.Join(" · ", parts);
    }

    public static string LevelText(SuspicionLevel level) => level switch
    {
        SuspicionLevel.Danger => "Suspect",
        SuspicionLevel.Warning => "À vérifier",
        _ => "",
    };
}
