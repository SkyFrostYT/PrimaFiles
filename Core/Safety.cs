namespace StorageScanner.Core;

public enum SafetyLevel
{
    /// <summary>Élément ordinaire.</summary>
    Normal,
    /// <summary>Élément système Windows (attribut Système ou situé dans Windows) : logo Windows.</summary>
    System,
    /// <summary>Élément indispensable : ne pas supprimer (triangle danger).</summary>
    Critical,
}

/// <summary>Repère les fichiers et dossiers système, et ceux qu'il ne faut surtout pas supprimer.
/// Classification indicative, fondée sur les emplacements et noms connus de Windows et sur l'attribut Système.</summary>
public static class Safety
{
    private static readonly string WindowsDir = Normalize(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
    private static readonly string SystemDrive = Path.GetPathRoot(WindowsDir) ?? @"C:\";

    /// <summary>Dossiers à la racine du disque système qu'il ne faut pas supprimer.</summary>
    private static readonly HashSet<string> CriticalRootDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "Windows", "Boot", "EFI", "Recovery", "System Volume Information", "$Recycle.Bin", "$WinREAgent",
        "$SysReset", "$Windows.~BT", "$Windows.~WS", "Config.Msi", "ProgramData", "Program Files",
        "Program Files (x86)", "Users", "Documents and Settings", "PerfLogs",
    };

    /// <summary>Sous-dossiers de Windows dont la suppression rend le système inutilisable.</summary>
    private static readonly HashSet<string> CriticalWindowsDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "System32", "SysWOW64", "WinSxS", "servicing", "Boot", "Fonts", "assembly", "Microsoft.NET", "INF",
        "Resources", "SystemApps", "SystemResources", "WinStore", "ImmersiveControlPanel", "Globalization",
        "Registration", "security", "Panther", "PolicyDefinitions", "Provisioning", "Containers", "CbsTemp",
        "apppatch", "AppReadiness", "Branding", "DigitalLocker", "IME", "LiveKernelReports", "Media", "Speech",
        "Speech_OneCore", "System", "SystemTemp", "TextInput", "twain_32", "Vss", "WaaS", "Web", "bcastdvr",
    };

    /// <summary>Fichiers indispensables, où qu'ils soient (pagination, hibernation, démarrage, profils).</summary>
    private static readonly HashSet<string> CriticalFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "pagefile.sys", "hiberfil.sys", "swapfile.sys", "bootmgr", "BOOTNXT", "ntldr", "NTDETECT.COM", "boot.ini",
        "bootsect.bak", "NTUSER.DAT", "ntuser.ini", "UsrClass.dat", "DumpStack.log", "DumpStack.log.tmp",
    };

    /// <summary>Extensions critiques lorsqu'elles se trouvent dans le dossier Windows.</summary>
    private static readonly HashSet<string> CriticalWindowsExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".sys", ".dll", ".exe", ".efi", ".mui", ".cat", ".mum", ".manifest", ".drv", ".ocx", ".cpl", ".msc",
    };

    public static SafetyLevel ForDirectory(string fullPath, string name, FileAttributes attributes)
    {
        string path = Normalize(fullPath);
        if (IsUnder(path, WindowsDir))
        {
            if (path.Length == WindowsDir.Length) return SafetyLevel.Critical;
            string parent = Normalize(Path.GetDirectoryName(path) ?? "");
            return string.Equals(parent, WindowsDir, StringComparison.OrdinalIgnoreCase) && CriticalWindowsDirs.Contains(name)
                ? SafetyLevel.Critical
                : SafetyLevel.System;
        }

        // Dossier à la racine du disque système (C:\Program Files, C:\Users…)
        string? dir = Path.GetDirectoryName(path);
        if (dir is not null && string.Equals(Normalize(dir), Normalize(SystemDrive), StringComparison.OrdinalIgnoreCase)
            && CriticalRootDirs.Contains(name))
            return SafetyLevel.Critical;

        if (name.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase)
            || name.Equals("$Recycle.Bin", StringComparison.OrdinalIgnoreCase))
            return SafetyLevel.Critical;

        return (attributes & FileAttributes.System) != 0 ? SafetyLevel.System : SafetyLevel.Normal;
    }

    public static SafetyLevel ForFile(string directoryPath, string name, FileAttributes attributes)
    {
        if (CriticalFiles.Contains(name) || name.StartsWith("ntuser.dat", StringComparison.OrdinalIgnoreCase))
            return SafetyLevel.Critical;

        string dir = Normalize(directoryPath);
        if (IsUnder(dir, WindowsDir))
            return CriticalWindowsExtensions.Contains(Path.GetExtension(name)) ? SafetyLevel.Critical : SafetyLevel.System;

        return (attributes & FileAttributes.System) != 0 ? SafetyLevel.System : SafetyLevel.Normal;
    }

    public static string? Describe(SafetyLevel level) => level switch
    {
        SafetyLevel.Critical => "Ne pas supprimer : élément indispensable au fonctionnement de Windows ou des applications",
        SafetyLevel.System => "Élément système Windows : à ne modifier qu'en connaissance de cause",
        _ => null,
    };

    private static bool IsUnder(string path, string root) =>
        root.Length > 0 && path.StartsWith(root, StringComparison.OrdinalIgnoreCase)
        && (path.Length == root.Length || path[root.Length] == '\\');

    private static string Normalize(string p) => p.Length > 3 ? p.TrimEnd('\\') : p;
}
