namespace StorageScanner.Core;

/// <summary>Chemins sûrs pour les entrées/sorties. Windows « corrige » silencieusement un chemin classique : il retire
/// les points et espaces finaux et redirige les noms réservés (NUL, CON, COM1…). Un fichier « virus.exe. » ou un dossier
/// « Docs  » créés volontairement (préfixe \\?\) seraient alors confondus avec un autre fichier : l'analyse, le calcul
/// d'empreinte ou la vérification antivirus porteraient sur le mauvais fichier. Le préfixe \\?\ désactive cette correction.</summary>
public static class SafePath
{
    /// <summary>Forme \\?\ d'un chemin absolu (local ou UNC), à utiliser pour toute lecture du disque.</summary>
    public static string ForIo(string path)
    {
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\\.\", StringComparison.Ordinal)) return path;
        if (path.StartsWith(@"\\", StringComparison.Ordinal)) return @"\\?\UNC\" + path[2..];
        if (path.Length >= 3 && path[1] == ':' && path[2] == '\\') return @"\\?\" + path;
        return path;
    }

    /// <summary>Retire le préfixe \\?\ des messages d'erreur affichés.</summary>
    public static string Display(string text) =>
        text.Replace(@"\\?\UNC\", @"\\", StringComparison.Ordinal).Replace(@"\\?\", "", StringComparison.Ordinal);

    /// <summary>Nom que Windows réinterprète : point ou espace final, ou nom de périphérique réservé (« nul.txt »).</summary>
    public static bool IsAmbiguousName(ReadOnlySpan<char> name)
    {
        if (name.Length == 0) return false;
        if (name[^1] is '.' or ' ') return !(name is "." or "..");
        int dot = name.IndexOf('.');
        var stem = (dot >= 0 ? name[..dot] : name).TrimEnd(' ');
        if (stem.Length == 3)
            return stem.Equals("CON", StringComparison.OrdinalIgnoreCase) || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase)
                || stem.Equals("AUX", StringComparison.OrdinalIgnoreCase) || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase);
        if (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) || stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)))
            return stem[3] is (>= '0' and <= '9') or '¹' or '²' or '³';
        return stem.Equals("CONIN$", StringComparison.OrdinalIgnoreCase) || stem.Equals("CONOUT$", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Vrai si un des éléments du chemin (après la racine) est ambigu.</summary>
    public static bool IsAmbiguousPath(string path)
    {
        var root = Path.GetPathRoot(path) ?? "";
        foreach (var part in path.AsSpan(root.Length).Split('\\'))
            if (IsAmbiguousName(path.AsSpan(root.Length)[part])) return true;
        return false;
    }

    /// <summary>Fichier « en ligne uniquement » (OneDrive, SharePoint, archivage) : le lire le téléchargerait en entier.</summary>
    public static bool IsCloudOnly(FileAttributes attributes) =>
        (attributes & (FileAttributes.Offline | RecallOnOpen | RecallOnDataAccess)) != 0;

    private const FileAttributes RecallOnOpen = (FileAttributes)0x40000;
    private const FileAttributes RecallOnDataAccess = (FileAttributes)0x400000;

    /// <summary>Dossier parent le plus proche dont le chemin n'est pas ambigu (pour l'Explorateur ou l'antivirus).</summary>
    public static string NearestUnambiguousFolder(string path)
    {
        string? p = Path.GetDirectoryName(path);
        while (p is not null && IsAmbiguousPath(p)) p = Path.GetDirectoryName(p);
        return p ?? Path.GetPathRoot(path) ?? path;
    }
}
