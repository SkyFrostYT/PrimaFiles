using System.Globalization;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Markup;

namespace StorageScanner;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        HardenDllLoading();

        // Formats de nombres et de dates selon la langue de Windows (WPF utilise en-US par défaut)
        FrameworkElement.LanguageProperty.OverrideMetadata(typeof(FrameworkElement),
            new FrameworkPropertyMetadata(XmlLanguage.GetLanguage(CultureInfo.CurrentCulture.IetfLanguageTag)));

        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show(args.Exception.Message, "Erreur inattendue", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };
        StorageScanner.UI.ThemeManager.LoadSaved();
        base.OnStartup(e);
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
