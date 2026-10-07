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
    AmbiguousName = 1 << 9,
    SystemAttribute = 1 << 10,
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
        /// <summary>Cache Internet / pièces jointes Outlook ouvertes (INetCache\Content.Outlook).</summary>
        WebCache = 256,
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
    /// seuls le dossier lui-même et ses sous-dossiers directs comptent : un projet décompressé plus bas n'est pas visé.
    /// Un nom de dossier de développement (node_modules…) ne suffit pas à y échapper : il est trivial à imiter.</summary>
    public bool IsRisky => !IsTrusted
                           && ((_flags & (Flags.Temp | Flags.Downloads | Flags.WebCache)) != 0
                               || ((_flags & (Flags.Startup | Flags.RecycleBin | Flags.Public)) != 0 && !IsDevTree));

    private static readonly string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
    private static readonly string SystemDrive = Path.GetPathRoot(WindowsDir) is { Length: > 0 } r ? r : @"C:\";

    // Les emplacements de confiance ne sont reconnus qu'à leur place réelle (racine du volume ou profil) :
    // un dossier « Program Files » ou « Windows.old » créé dans Téléchargements n'accorde aucune confiance.
    private static readonly string[] WindowsLikeRoots = ["Windows.old", "$Windows.~BT", "$Windows.~WS", "$WinREAgent"];
    private static readonly string[] InstallRoots = ["Program Files", "Program Files (x86)", @"ProgramData\Microsoft"];
    private static readonly string[] ProfileInstallDirs = [@"AppData\Local\Programs", @"AppData\Local\Microsoft"];

    /// <summary>Sous-dossiers de Windows accessibles en écriture aux utilisateurs : souvent utilisés pour déposer
    /// et cacher un programme malveillant, ils ne bénéficient pas de la confiance accordée à Windows.</summary>
    private static readonly string[] WritableWindowsDirs =
    [
        "Temp", "Tasks", "tracing", @"System32\Tasks", @"SysWOW64\Tasks", @"System32\spool\drivers\color",
        @"System32\spool\PRINTERS", @"Registration\CRMLog", @"System32\Microsoft\Crypto\RSA\MachineKeys", "debug",
        @"ServiceProfiles\LocalService\AppData\Local\Temp", @"ServiceProfiles\NetworkService\AppData\Local\Temp",
    ];
    private static readonly string[] DevMarkers =
    [
        @"\node_modules\", @"\.git\", @"\site-packages\", @"\dist-packages\", @"\vendor\", @"\.gradle\", @"\.m2\",
        @"\libraries\", @"\.nuget\", @"\packages\", @"\.venv\", @"\venv\", @"\.cargo\", @"\target\", @"\bin\Debug\", @"\bin\Release\",
    ];

    public static DirContext For(string path)
    {
        var f = (Flags)0;
        string? rel = PathBelowVolumeRoot(path, out bool adminShare);
        if (rel is not null)
        {
            // Windows et ses anciennes copies : uniquement sur le disque système (ou le C$ d'un poste distant).
            // Ailleurs, n'importe quel utilisateur peut créer un dossier « Windows » à la racine d'un disque.
            bool systemVolume = adminShare || path.StartsWith(SystemDrive, StringComparison.OrdinalIgnoreCase);
            bool windows = (!adminShare && StartsWithDir(path, WindowsDir))
                           || (adminShare && StartsWithSegment(rel, "Windows"))
                           || (systemVolume && StartsWithAny(rel, WindowsLikeRoots));
            if (windows)
            {
                string winRel = adminShare || !StartsWithDir(path, WindowsDir)
                    ? rel[Math.Min(rel.Length, rel.IndexOf('\\') < 0 ? rel.Length : rel.IndexOf('\\') + 1)..]
                    : path[Math.Min(path.Length, WindowsDir.Length + 1)..];
                if (!StartsWithAny(winRel, WritableWindowsDirs)) f |= Flags.Windows;
            }
            if (StartsWithAny(rel, InstallRoots)) f |= Flags.ProgramFiles;
            // C:\Users\<nom>\AppData\Local\Programs|Microsoft (hors cache Internet / pièces jointes Outlook)
            if (StartsWithSegment(rel, "Users"))
            {
                var parts = rel.Split('\\', 3);
                if (parts.Length == 3 && StartsWithAny(parts[2], ProfileInstallDirs)) f |= Flags.ProgramFiles;
            }
        }
        if (path.Contains(@"\INetCache\", StringComparison.OrdinalIgnoreCase) || path.EndsWith(@"\INetCache", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\Temporary Internet Files\", StringComparison.OrdinalIgnoreCase))
        {
            f &= ~Flags.ProgramFiles;
            f |= Flags.WebCache;
        }
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

    /// <summary>Partie du chemin sous la racine du volume (« C:\Program Files\X » → « Program Files\X »). Les partages
    /// d'administration (\\pc\C$\…) sont traités comme le volume distant ; un partage ordinaire n'a pas de racine système.</summary>
    private static string? PathBelowVolumeRoot(string path, out bool adminShare)
    {
        adminShare = false;
        if (path.Length >= 2 && path[1] == ':') return path.Length > 3 ? path[3..] : "";
        if (!path.StartsWith(@"\\", StringComparison.Ordinal)) return null;
        var parts = path[2..].Split('\\', 3);
        if (parts.Length >= 2 && parts[1].Length == 2 && char.IsAsciiLetter(parts[1][0]) && parts[1][1] == '$')
        {
            adminShare = true;
            return parts.Length == 3 ? parts[2] : "";
        }
        return null;
    }

    private static bool StartsWithSegment(string rel, string segment) =>
        rel.StartsWith(segment, StringComparison.OrdinalIgnoreCase) && (rel.Length == segment.Length || rel[segment.Length] == '\\');

    private static bool StartsWithAny(string rel, string[] segments)
    {
        foreach (var s in segments)
            if (StartsWithSegment(rel, s)) return true;
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
    private enum Kind : byte { Executable, HighRisk, Script, Text, Shortcut }

    private static readonly Dictionary<string, Kind> KindMap = new(StringComparer.OrdinalIgnoreCase)
    {
        [".exe"] = Kind.Executable, [".msi"] = Kind.Executable, [".dll"] = Kind.Executable, [".cpl"] = Kind.Executable,
        // Types quasiment jamais légitimes hors de Windows : économiseurs d'écran, anciens exécutables, scripts Windows Script Host
        [".scr"] = Kind.HighRisk, [".pif"] = Kind.HighRisk, [".com"] = Kind.HighRisk, [".hta"] = Kind.HighRisk,
        [".vbs"] = Kind.HighRisk, [".vbe"] = Kind.HighRisk, [".jse"] = Kind.HighRisk, [".wsf"] = Kind.HighRisk, [".wsh"] = Kind.HighRisk,
        // Raccourcis : « facture.pdf.lnk » lance n'importe quelle commande. Console MMC, compléments Excel, aide compilée :
        // vecteurs d'attaque récents, rares hors des dossiers d'applications.
        [".lnk"] = Kind.Shortcut, [".url"] = Kind.Shortcut,
        [".msc"] = Kind.HighRisk, [".xll"] = Kind.Script, [".chm"] = Kind.Script,
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
        // Fichier « en ligne uniquement » : vérifier la signature le téléchargerait, on garde l'avertissement
        return s.Level == SuspicionLevel.Warning && !SafePath.IsCloudOnly(attributes)
               && Authenticode.IsTrusted(Path.Join(directory, name)) ? default : s;
    }

    public static Suspicion Evaluate(in DirContext dir, ReadOnlySpan<char> name, FileAttributes attributes)
    {
        var reasons = SuspicionReason.None;
        var level = SuspicionLevel.None;

        if (name.IndexOfAny(BidiControls) >= 0)
            Raise(ref level, ref reasons, SuspicionLevel.Danger, SuspicionReason.HiddenCharacters);

        // « virus.exe. », « nul.txt » : impossibles à créer normalement, Windows les confond avec un autre fichier
        if (SafePath.IsAmbiguousName(name))
        {
            Raise(ref level, ref reasons, SuspicionLevel.Danger, SuspicionReason.AmbiguousName);
            name = name.TrimEnd(". ");
        }

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
        // Raccourcis : seulement dans les dossiers à risque (les « Récents » de Windows et d'Office en contiennent des milliers)
        if (launchable && !dir.IsWindows && (kind != Kind.Shortcut || dir.IsRisky))
        {
            var stem = name[..dot].TrimEnd(' ');
            int dot2 = stem.LastIndexOf('.');
            if (dot2 > 0 && Decoys.Contains(stem[dot2..]) && IsLowerOrSpaced(name, dot2, dot))
                Raise(ref level, ref reasons, SuspicionLevel.Danger, SuspicionReason.DoubleExtension);
        }

        if (kind == Kind.Executable && !dir.IsWindows && SystemNames.Contains(name))
            Raise(ref level, ref reasons, SuspicionLevel.Danger, SuspicionReason.SystemImpersonation);

        // Règles d'emplacement : jamais dans Windows / Program Files, ni dans les dépendances de développement
        // situées hors des dossiers à risque
        if (!dir.IsTrusted && (dir.IsRisky || !dir.IsDevTree))
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

            // Attribut Système posé sur un programme hors de Windows : camouflage pour paraître légitime
            if (kind is Kind.Executable or Kind.HighRisk or Kind.Script && (attributes & FileAttributes.System) != 0 && launchable)
                Raise(ref level, ref reasons, SuspicionLevel.Warning, SuspicionReason.SystemAttribute);
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
        if (r.HasFlag(SuspicionReason.HiddenCharacters)) parts.Add(Loc.T("rHidden"));
        if (r.HasFlag(SuspicionReason.DoubleExtension)) parts.Add(Loc.T("rDouble"));
        if (r.HasFlag(SuspicionReason.RansomwareExtension)) parts.Add(Loc.T("rRansomExt"));
        if (r.HasFlag(SuspicionReason.RansomNote)) parts.Add(Loc.T("rRansomNote"));
        if (r.HasFlag(SuspicionReason.SystemImpersonation)) parts.Add(Loc.T("rImpersonation"));
        if (r.HasFlag(SuspicionReason.RiskyFileType)) parts.Add(Loc.T("rRiskyType"));
        if (r.HasFlag(SuspicionReason.RiskyLocation)) parts.Add(Loc.T("rRiskyLocation"));
        if (r.HasFlag(SuspicionReason.Startup)) parts.Add(Loc.T("rStartup"));
        if (r.HasFlag(SuspicionReason.HiddenExecutable)) parts.Add(Loc.T("rHiddenExe"));
        if (r.HasFlag(SuspicionReason.SystemAttribute)) parts.Add(Loc.T("rSystemAttr"));
        if (r.HasFlag(SuspicionReason.AmbiguousName)) parts.Add(Loc.T("rAmbiguous"));
        return string.Join(" · ", parts);
    }

    public static string LevelText(SuspicionLevel level) => level switch
    {
        SuspicionLevel.Danger => Loc.T("levelDanger"),
        SuspicionLevel.Warning => Loc.T("levelWarning"),
        _ => "",
    };
}
