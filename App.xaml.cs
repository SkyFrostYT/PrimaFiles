using System.Globalization;
using System.Windows;
using System.Windows.Markup;

namespace StorageScanner;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
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
}
