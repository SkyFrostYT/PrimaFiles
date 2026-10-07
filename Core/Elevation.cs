using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace StorageScanner.Core;

/// <summary>Mode administrateur : détection, relance élevée et privilège de sauvegarde.</summary>
public static class Elevation
{
    public static bool IsElevated { get; } = CheckElevated();

    private static bool CheckElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>Relance l'application en administrateur (invite UAC). Renvoie false si l'utilisateur refuse.</summary>
    public static bool RestartElevated(string? path)
    {
        var exe = Environment.ProcessPath;
        if (exe is null) return false;
        var psi = new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas" };
        if (!string.IsNullOrWhiteSpace(path))
        {
            psi.ArgumentList.Add("--path");
            psi.ArgumentList.Add(path);
        }
        // Lecteurs réseau de la session normale : invisibles en administrateur, ils y seront reconnectés
        try
        {
            foreach (var (letter, unc) in Unc.GetMappedDrives())
            {
                psi.ArgumentList.Add("--drive-map");
                psi.ArgumentList.Add($"{letter}={unc}");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        try
        {
            Process.Start(psi);
            return true;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) // ERROR_CANCELLED : UAC refusé
        {
            return false;
        }
    }

    /// <summary>Lance ce même exécutable en administrateur avec les arguments donnés et attend sa fin.
    /// Renvoie son code de sortie, ou null si l'utilisateur refuse l'invite UAC.</summary>
    public static int? RunElevatedAndWait(params string[] args)
    {
        var exe = Environment.ProcessPath;
        if (exe is null) return null;
        var psi = new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas" };
        foreach (var a in args) psi.ArgumentList.Add(a);
        psi.ArgumentList.Add("--requested-by");
        psi.ArgumentList.Add(Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
        try
        {
            using var p = Process.Start(psi);
            if (p is null) return null;
            p.WaitForExit();
            return p.ExitCode;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) // ERROR_CANCELLED : UAC refusé
        {
            return null;
        }
    }

    /// <summary>Active SeBackupPrivilege (et SeRestore pour les métadonnées) : en administrateur, permet de lister
    /// des dossiers dont les droits n'autorisent normalement pas la lecture (System Volume Information, profils…).
    /// Lecture seule : l'application ne modifie rien.</summary>
    public static bool EnableBackupPrivilege()
    {
        if (!IsElevated) return false;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token)) return false;
        try
        {
            if (!LookupPrivilegeValueW(null, "SeBackupPrivilege", out var luid)) return false;
            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            return AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero) && Marshal.GetLastWin32Error() == 0;
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
    private const uint TOKEN_QUERY = 0x8;
    private const uint SE_PRIVILEGE_ENABLED = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValueW(string? system, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, [MarshalAs(UnmanagedType.Bool)] bool disableAll,
        ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
