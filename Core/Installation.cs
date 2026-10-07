using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

namespace StorageScanner.Core;

/// <summary>Installation intégrée : copie dans C:\Program Files\PrimaFiles, raccourci du menu Démarrer et entrée
/// « Applications installées ». Program Files n'est modifiable que par un administrateur : aucune DLL ne peut être
/// glissée à côté de l'exécutable installé, contrairement au dossier Téléchargements.</summary>
public static class Installation
{
    public static string Dir { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PrimaFiles");

    public static string InstalledExe => Path.Combine(Dir, "PrimaFiles.exe");

    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PrimaFiles";

    private static string ShortcutPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "PrimaFiles.lnk");

    /// <summary>Bibliothèques natives WPF livrées avec la version portable (copiées seulement si présentes).</summary>
    private static readonly string[] PortableFiles =
        ["D3DCompiler_47_cor3.dll", "PenImc_cor3.dll", "PresentationNative_cor3.dll", "vcruntime140_cor3.dll", "wpfgfx_cor3.dll"];

    /// <summary>Certificat créé par la procédure d'auto-signature du README (retiré à la désinstallation).</summary>
    private const string SelfSignedSubject = "CN=PrimaFiles (auto-signé sur ce PC)";

    public static Version CurrentVersion => typeof(Installation).Assembly.GetName().Version ?? new Version(0, 0);

    public static bool IsRunningInstalled =>
        Environment.ProcessPath is { } p
        && string.Equals(Path.GetDirectoryName(Path.GetFullPath(p)), Dir, StringComparison.OrdinalIgnoreCase);

    public static Version? InstalledVersion
    {
        get
        {
            try
            {
                if (!File.Exists(InstalledExe)) return null;
                var info = FileVersionInfo.GetVersionInfo(InstalledExe);
                return Version.TryParse(info.FileVersion, out var v) ? v : null;
            }
            catch (IOException) { return null; }
        }
    }

    /// <summary>Copie l'exécutable en cours (et ses DLL natives s'il s'agit de la version portable) dans Program Files.
    /// Doit être appelé avec les droits administrateur.</summary>
    public static void Install()
    {
        if (IsRunningInstalled) { RegisterShortcutAndUninstall(); return; }
        string src = Environment.ProcessPath ?? throw new InvalidOperationException("Chemin de l'exécutable inconnu.");
        string srcDir = Path.GetDirectoryName(src)!;

        // Lecture complète avant écriture : ce qui est lu est exactement ce qui est installé, même si le dossier
        // source (Téléchargements, modifiable par l'utilisateur) change pendant l'opération.
        var files = new List<(string Name, byte[] Data)> { ("PrimaFiles.exe", File.ReadAllBytes(src)) };
        foreach (var name in PortableFiles)
        {
            string p = Path.Combine(srcDir, name);
            if (File.Exists(p)) files.Add((name, File.ReadAllBytes(p)));
        }

        StopInstalledInstances();
        if (Directory.Exists(Dir)) Directory.Delete(Dir, recursive: true);
        Directory.CreateDirectory(Dir);
        // Fichiers créés ici : pas de marque « téléchargé depuis Internet », donc pas d'alerte SmartScreen
        foreach (var (name, data) in files) File.WriteAllBytes(Path.Combine(Dir, name), data);

        RegisterShortcutAndUninstall();
    }

    /// <summary>Menu contextuel de l'Explorateur (dossier, lecteur, fond d'un dossier ouvert).</summary>
    private static readonly string[] ShellVerbKeys =
    [
        @"SOFTWARE\Classes\Directory\shell\PrimaFiles",
        @"SOFTWARE\Classes\Drive\shell\PrimaFiles",
        @"SOFTWARE\Classes\Directory\Background\shell\PrimaFiles",
    ];

    private static void RegisterExplorerMenu()
    {
        foreach (var path in ShellVerbKeys)
        {
            using var verb = Registry.LocalMachine.CreateSubKey(path, writable: true);
            verb.SetValue("", "Analyser avec PrimaFiles");
            verb.SetValue("Icon", $"\"{InstalledExe}\",0");
            using var command = verb.CreateSubKey("command", writable: true);
            // %V : chemin du dossier, toujours entre guillemets ; PrimaFiles ne fait que le lire (lecture seule)
            command.SetValue("", $"\"{InstalledExe}\" --scan \"%V\"");
        }
    }

    private static void UnregisterExplorerMenu()
    {
        foreach (var path in ShellVerbKeys) Registry.LocalMachine.DeleteSubKeyTree(path, throwOnMissingSubKey: false);
    }

    private static void RegisterShortcutAndUninstall()
    {
        CreateShortcut();
        RegisterExplorerMenu();
        using var key = Registry.LocalMachine.CreateSubKey(UninstallKey, writable: true);
        string exe = InstalledExe;
        key.SetValue("DisplayName", "PrimaFiles");
        key.SetValue("DisplayVersion", CurrentVersion.ToString(3));
        key.SetValue("Publisher", "Primatoria");
        key.SetValue("DisplayIcon", exe);
        key.SetValue("InstallLocation", Dir);
        key.SetValue("URLInfoAbout", "https://github.com/SkyFrostYT/PrimaFiles");
        key.SetValue("UninstallString", $"\"{exe}\" --uninstall");
        key.SetValue("QuietUninstallString", $"\"{exe}\" --uninstall --quiet");
        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
        long size = Directory.EnumerateFiles(Dir).Sum(f => new FileInfo(f).Length);
        key.SetValue("EstimatedSize", (int)(size / 1024), RegistryValueKind.DWord);
    }

    private static void CreateShortcut()
    {
        var type = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("WScript.Shell indisponible.");
        dynamic shell = Activator.CreateInstance(type)!;
        try
        {
            dynamic link = shell.CreateShortcut(ShortcutPath);
            link.TargetPath = InstalledExe;
            link.WorkingDirectory = Dir;
            link.IconLocation = InstalledExe + ",0";
            link.Description = "Analyse de l'espace disque et des partages réseau";
            link.Save();
            Marshal.FinalReleaseComObject(link);
        }
        finally
        {
            Marshal.FinalReleaseComObject(shell);
        }
    }

    /// <summary>Retire PrimaFiles (raccourci, entrée « Applications installées », certificat d'auto-signature, fichiers).
    /// Doit être appelé avec les droits administrateur. Les réglages de l'utilisateur sont conservés.</summary>
    public static void Uninstall()
    {
        StopInstalledInstances();
        try { File.Delete(ShortcutPath); } catch (IOException) { }
        Registry.LocalMachine.DeleteSubKeyTree(UninstallKey, throwOnMissingSubKey: false);
        UnregisterExplorerMenu();
        RemoveSelfSignedCertificates();

        if (!Directory.Exists(Dir)) return;
        if (!IsRunningInstalled)
        {
            Directory.Delete(Dir, recursive: true);
            return;
        }

        // L'exécutable en cours ne peut pas se supprimer lui-même : tout le reste est supprimé maintenant,
        // le dossier l'est quelques secondes après la fermeture par l'interpréteur de commandes de Windows.
        foreach (var f in Directory.EnumerateFiles(Dir))
            if (!string.Equals(f, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase))
                try { File.Delete(f); } catch (IOException) { } catch (UnauthorizedAccessException) { }

        string sys = Environment.SystemDirectory;
        string cmd = Path.Combine(sys, "cmd.exe");
        string ping = Path.Combine(sys, "PING.EXE"); // chemin complet : aucune dépendance au PATH dans un processus administrateur
        if (Dir.Contains('"')) return;
        string script = $"for /l %i in (1,1,60) do (if exist \"{Dir}\" (rmdir /s /q \"{Dir}\" 2>nul & \"{ping}\" -n 2 127.0.0.1 >nul))";
        Process.Start(new ProcessStartInfo(cmd)
        {
            Arguments = "/d /c " + script,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = sys,
        });
    }

    /// <summary>Instance non administrateur qui a demandé l'opération (elle attend le résultat) : à ne pas fermer.</summary>
    public static int RequestingProcessId { get; set; }

    private static void StopInstalledInstances()
    {
        int self = Environment.ProcessId;
        foreach (var p in Process.GetProcessesByName("PrimaFiles"))
        {
            using (p)
            {
                try
                {
                    if (p.Id == self || p.Id == RequestingProcessId) continue;
                    string? path = p.MainModule?.FileName;
                    if (path is not null && string.Equals(Path.GetDirectoryName(path), Dir, StringComparison.OrdinalIgnoreCase))
                    {
                        p.Kill();
                        p.WaitForExit(5000);
                    }
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
            }
        }
    }

    private static void RemoveSelfSignedCertificates()
    {
        foreach (var name in new[] { StoreName.Root, StoreName.TrustedPublisher, StoreName.My })
        {
            try
            {
                using var store = new X509Store(name, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                foreach (var c in store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, SelfSignedSubject, validOnly: false))
                {
                    store.Remove(c);
                    c.Dispose();
                }
            }
            catch (System.Security.Cryptography.CryptographicException) { }
        }
    }
}
