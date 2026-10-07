using System.Runtime.InteropServices;
using System.Text;

namespace StorageScanner.Core;

/// <summary>Outils pour les chemins réseau : lecteurs mappés → chemin UNC, et liste des partages d'un serveur.</summary>
public static class Unc
{
    /// <summary>Chemin UNC derrière un lecteur réseau mappé (U:\Dossier → \\serveur\partage\Dossier), sinon null.</summary>
    public static string? GetMappedUnc(string path)
    {
        if (path.Length < 2 || path[1] != ':') return null;
        try
        {
            var sb = new StringBuilder(1024);
            int len = sb.Capacity;
            if (WNetGetConnectionW(path[..2], sb, ref len) != 0) return null;
            string rest = path.Length > 2 ? path[2..].Trim('\\') : "";
            return rest.Length == 0 ? sb.ToString() : sb.ToString().TrimEnd('\\') + "\\" + rest;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
    }

    /// <summary>Nom du partage seul (\\serveur\Public\Dossier → « Public »), sans le nom du serveur.</summary>
    public static string? ShareName(string? unc)
    {
        if (unc is null || !unc.StartsWith(@"\\", StringComparison.Ordinal)) return null;
        var parts = unc[2..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 ? parts[1] : null;
    }

    /// <summary>Vrai pour « \\serveur » (sans partage).</summary>
    public static bool IsServerOnly(string path)
    {
        if (!path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith(@"\\?\", StringComparison.Ordinal)) return false;
        var rest = path[2..].TrimEnd('\\');
        return rest.Length > 0 && !rest.Contains('\\');
    }

    /// <summary>Partages disque d'un serveur, y compris les partages cachés (Commun$) ; les partages
    /// d'administration (C$, ADMIN$) sont exclus.</summary>
    public static List<string> GetShares(string server)
    {
        var result = new List<string>();
        int resume = 0;
        int status = NetShareEnum(server.TrimEnd('\\'), 1, out var buffer, -1, out int read, out _, ref resume);
        try
        {
            if (status != 0)
                throw new IOException(Loc.F("sharesFailed", server, status));
            int size = Marshal.SizeOf<ShareInfo1>();
            for (int i = 0; i < read; i++)
            {
                var info = Marshal.PtrToStructure<ShareInfo1>(buffer + i * size);
                bool isDisk = (info.Type & 0xFF) == StypeDiskTree;
                // Partages d'administration (C$, ADMIN$, IPC$…) exclus ; partages cachés métier (Commun$…) conservés
                bool isSpecial = (info.Type & StypeSpecial) != 0 || info.Name.Equals("print$", StringComparison.OrdinalIgnoreCase);
                // Nom renvoyé par le serveur : on refuse ce qui ne peut pas être un nom de partage (« .. », « a\b », « C: »…)
                // pour qu'un serveur malveillant ne puisse pas faire analyser un autre chemin
                if (isDisk && !isSpecial && IsValidShareName(info.Name)) result.Add(info.Name);
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        }
        result.Sort(NaturalComparer.Instance);
        return result;
    }

    // ---- Lecteurs réseau en mode administrateur ----
    // Windows sépare la session administrateur (UAC) de la session normale : les lecteurs réseau connectés dans la
    // session normale n'y existent pas. L'instance normale transmet ses lecteurs (« --drive-map U=\\serveur\partage »),
    // l'instance administrateur les reconnecte de son côté, temporairement et avec les identifiants Windows actuels.

    /// <summary>Lecteurs réseau visibles dans la session courante : lettre → chemin UNC.</summary>
    public static Dictionary<char, string> GetMappedDrives()
    {
        var map = new Dictionary<char, string>();
        foreach (var d in DriveInfo.GetDrives())
        {
            if (d.DriveType != DriveType.Network) continue;
            char letter = char.ToUpperInvariant(d.Name[0]);
            if (GetMappedUnc($"{letter}:") is { } unc && IsValidUncShare(unc)) map[letter] = unc.TrimEnd('\\');
        }
        return map;
    }

    /// <summary>Lecteurs réseau permanents de l'utilisateur (reconnectés à chaque ouverture de session).</summary>
    public static Dictionary<char, string> GetPersistentMappings()
    {
        var map = new Dictionary<char, string>();
        try
        {
            using var network = Microsoft.Win32.Registry.CurrentUser.OpenSubKey("Network");
            if (network is null) return map;
            foreach (var name in network.GetSubKeyNames())
            {
                if (name.Length != 1 || !char.IsAsciiLetter(name[0])) continue;
                using var key = network.OpenSubKey(name);
                if (key?.GetValue("RemotePath") is string unc && IsValidUncShare(unc))
                    map[char.ToUpperInvariant(name[0])] = unc.TrimEnd('\\');
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }
        return map;
    }

    /// <summary>Lit les « --drive-map X=\\serveur\partage » transmis par l'instance normale (valeurs vérifiées).</summary>
    public static Dictionary<char, string> ParseDriveMapArgs(string[] args)
    {
        var map = new Dictionary<char, string>();
        for (int i = 0; i + 1 < args.Length; i++)
        {
            if (!string.Equals(args[i], "--drive-map", StringComparison.OrdinalIgnoreCase)) continue;
            string v = args[i + 1];
            if (v.Length > 3 && char.IsAsciiLetter(v[0]) && v[1] == '=' && IsValidUncShare(v[2..]))
                map[char.ToUpperInvariant(v[0])] = v[2..].TrimEnd('\\');
        }
        return map;
    }

    /// <summary>Connecte, pour ce processus seulement (connexion temporaire, jamais mémorisée), les lettres qui
    /// n'existent pas encore. Les échecs (serveur injoignable…) sont ignorés : la lettre n'apparaît simplement pas.</summary>
    public static int ReconnectMissing(IReadOnlyDictionary<char, string> mappings)
    {
        var present = new HashSet<char>(DriveInfo.GetDrives().Select(d => char.ToUpperInvariant(d.Name[0])));
        var missing = mappings.Where(m => !present.Contains(m.Key)).ToList();
        int ok = 0;
        Parallel.ForEach(missing, new ParallelOptions { MaxDegreeOfParallelism = 8 }, m =>
        {
            var res = new NetResource { Type = ResourceTypeDisk, LocalName = $"{m.Key}:", RemoteName = m.Value };
            if (WNetAddConnection2W(ref res, null, null, ConnectTemporary) == 0) Interlocked.Increment(ref ok);
        });
        return ok;
    }

    /// <summary>« \\serveur\partage » (éventuellement suivi d'un sous-dossier), sans caractère interdit.</summary>
    private static bool IsValidUncShare(string unc)
    {
        if (!unc.StartsWith(@"\\", StringComparison.Ordinal) || unc.StartsWith(@"\\?\", StringComparison.Ordinal)
            || unc.StartsWith(@"\\.\", StringComparison.Ordinal) || unc.Length > 260) return false;
        var parts = unc[2..].TrimEnd('\\').Split('\\');
        if (parts.Length < 2 || parts[0].Length == 0) return false;
        foreach (var p in parts)
            if (p.Length == 0 || p.Trim('.').Length == 0 || p.AsSpan().IndexOfAny("/:*?\"<>|") >= 0 || p.Any(char.IsControl)) return false;
        return true;
    }

    private const int ResourceTypeDisk = 1;
    private const int ConnectTemporary = 4;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NetResource
    {
        public int Scope;
        public int Type;
        public int DisplayType;
        public int Usage;
        public string? LocalName;
        public string? RemoteName;
        public string? Comment;
        public string? Provider;
    }

    [DllImport("mpr.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int WNetAddConnection2W(ref NetResource resource, string? password, string? userName, int flags);

    private static bool IsValidShareName(string? name) =>
        !string.IsNullOrWhiteSpace(name) && name.Length <= 80 && name.Trim('.').Length > 0
        && name.AsSpan().IndexOfAny("\\/:*?\"<>|") < 0 && !name.Any(char.IsControl);

    private const uint StypeDiskTree = 0;
    private const uint StypeSpecial = 0x80000000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ShareInfo1
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string Name;
        public uint Type;
        [MarshalAs(UnmanagedType.LPWStr)] public string Remark;
    }

    [DllImport("mpr.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int WNetGetConnectionW(string localName, StringBuilder remoteName, ref int length);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int NetShareEnum(string serverName, int level, out IntPtr buffer, int prefMaxLen,
        out int entriesRead, out int totalEntries, ref int resumeHandle);

    [DllImport("netapi32.dll", ExactSpelling = true)]
    private static extern int NetApiBufferFree(IntPtr buffer);
}
