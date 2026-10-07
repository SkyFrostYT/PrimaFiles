using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Markup;
using StorageScanner.Core;

namespace StorageScanner;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        HardenDllLoading();
        Loc.Set(StorageScanner.UI.SettingsStore.GetString("language") ?? Loc.SystemDefault);

        // Formats de nombres et de dates selon la langue de Windows (WPF utilise en-US par défaut)
        FrameworkElement.LanguageProperty.OverrideMetadata(typeof(FrameworkElement),
            new FrameworkPropertyMetadata(XmlLanguage.GetLanguage(CultureInfo.CurrentCulture.IetfLanguageTag)));

        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show(args.Exception.Message, Loc.T("unexpectedError"), MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };
        StorageScanner.UI.ThemeManager.LoadSaved();
        base.OnStartup(e);

        var args = e.Args;
        bool quiet = Has(args, "--quiet");
        bool child = Has(args, "--elevated"); // relancé par une autre instance de PrimaFiles via l'invite UAC
        int i = Array.FindIndex(args, a => string.Equals(a, "--requested-by", StringComparison.OrdinalIgnoreCase));
        if (i >= 0 && i + 1 < args.Length && int.TryParse(args[i + 1], out int requester)) Installation.RequestingProcessId = requester;
        if (Has(args, "--install"))
        {
            Shutdown(InstallCommand(quiet, child));
            return;
        }
        if (Has(args, "--uninstall"))
        {
            Shutdown(UninstallCommand(quiet, child));
            return;
        }
        if (!Has(args, "--path") && OfferInstall())
        {
            Shutdown(0);
            return;
        }
        new MainWindow().Show();
    }

    private static bool Has(string[] args, string flag) => args.Any(a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));

    private static string Title => Loc.T("installTitle");

    private static void Info(string text) => MessageBox.Show(text, Title, MessageBoxButton.OK, MessageBoxImage.Information);

    private static void Error(string text) => MessageBox.Show(text, Title, MessageBoxButton.OK, MessageBoxImage.Error);

    /// <summary>Premier lancement d'une copie téléchargée : propose l'installation (ou la mise à jour).
    /// Renvoie vrai si PrimaFiles a été installé et lancé depuis Program Files.</summary>
    private static bool OfferInstall()
    {
        if (Installation.IsRunningInstalled || Elevation.IsElevated) return false;
        var installed = Installation.InstalledVersion;
        var current = Installation.CurrentVersion;
        if (installed is not null && installed >= current) return false;
        string key = $"{Environment.ProcessPath}|{current}";
        if (StorageScanner.UI.InstallPromptStore.WasDeclined(key)) return false;

        string text = installed is null
            ? Loc.T("installAsk")
            : Loc.F("updateAsk", installed.ToString(3), current.ToString(3));
        if (MessageBox.Show(text, Title, MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            StorageScanner.UI.InstallPromptStore.Decline(key);
            return false;
        }

        int? code = Elevation.RunElevatedAndWait("--install", "--elevated");
        if (code != 0)
        {
            // Erreur : déjà affichée par l'instance administrateur
            if (code is null) Info(Loc.T("installCancelled"));
            return false;
        }
        Info(Loc.F("installedFull", current.ToString(3), Installation.Dir));
        Process.Start(new ProcessStartInfo(Installation.InstalledExe) { UseShellExecute = false, WorkingDirectory = Installation.Dir });
        return true;
    }

    private static int InstallCommand(bool quiet, bool child)
    {
        if (!Elevation.IsElevated)
        {
            var code = Elevation.RunElevatedAndWait(quiet ? ["--install", "--elevated", "--quiet"] : ["--install", "--elevated"]);
            if (!quiet && code == 0) Info(Loc.F("installedShort", Installation.Dir));
            return code ?? 1223;
        }
        try
        {
            Installation.Install();
            if (!quiet && !child) Info(Loc.F("installedShort", Installation.Dir));
            return 0;
        }
        catch (Exception ex)
        {
            if (!quiet) Error(Loc.F("installFailed", ex.Message));
            return 1;
        }
    }

    private static int UninstallCommand(bool quiet, bool child)
    {
        if (!quiet && !child && MessageBox.Show(Loc.T("uninstallAsk"),
                Loc.T("uninstallTitle"), MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return 1602; // ERROR_INSTALL_USEREXIT
        if (!Elevation.IsElevated)
        {
            var code = Elevation.RunElevatedAndWait(quiet ? ["--uninstall", "--elevated", "--quiet"] : ["--uninstall", "--elevated"]);
            if (!quiet && code == 0) Info(Loc.T("uninstalled"));
            return code ?? 1223;
        }
        try
        {
            Installation.Uninstall();
            if (!quiet && !child) Info(Loc.T("uninstalled"));
            return 0;
        }
        catch (Exception ex)
        {
            if (!quiet) Error(Loc.F("uninstallFailed", ex.Message));
            return 1;
        }
    }

    /// <summary>Protection contre le détournement de DLL (« DLL planting ») pour tout chargement ultérieur :
    /// le dossier courant est retiré de la recherche, les DLL de System32 sont préférées à une copie homonyme
    /// et les DLL marquées « intégrité faible » (téléchargées par un navigateur en mode protégé) sont refusées.</summary>
    private static void HardenDllLoading()
    {
        try
        {
            SetDllDirectoryW("");
            var policy = new ImageLoadPolicy { Flags = NoLowMandatoryLabelImages | PreferSystem32Images };
            SetProcessMitigationPolicy(ProcessImageLoadPolicy, ref policy, Marshal.SizeOf<ImageLoadPolicy>());
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException) { }
    }

    private const int ProcessImageLoadPolicy = 10;
    private const uint NoLowMandatoryLabelImages = 0x2;
    private const uint PreferSystem32Images = 0x4;

    [StructLayout(LayoutKind.Sequential)]
    private struct ImageLoadPolicy
    {
        public uint Flags;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetDllDirectoryW(string? path);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessMitigationPolicy(int policy, ref ImageLoadPolicy value, int size);
}
