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
                throw new IOException($"Impossible de lister les partages de {server} (code {status}).");
            int size = Marshal.SizeOf<ShareInfo1>();
            for (int i = 0; i < read; i++)
            {
                var info = Marshal.PtrToStructure<ShareInfo1>(buffer + i * size);
                bool isDisk = (info.Type & 0xFF) == StypeDiskTree;
                // Partages d'administration (C$, ADMIN$, IPC$…) exclus ; partages cachés métier (Commun$…) conservés
                bool isSpecial = (info.Type & StypeSpecial) != 0 || info.Name.Equals("print$", StringComparison.OrdinalIgnoreCase);
                if (isDisk && !isSpecial) result.Add(info.Name);
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        }
        result.Sort(NaturalComparer.Instance);
        return result;
    }

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
