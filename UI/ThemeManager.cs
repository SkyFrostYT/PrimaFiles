using System.Windows;

namespace StorageScanner.UI;

/// <summary>Bascule clair / sombre à chaud en remplaçant la palette (1er dictionnaire fusionné de l'application).
/// Le choix est mémorisé dans %LOCALAPPDATA%\PrimaFiles\theme.txt.</summary>
public static class ThemeManager
{
    private static readonly string SettingsFile = AppData.File("theme.txt");

    public static bool IsDark { get; private set; }

    public static event Action? Changed;

    public static void LoadSaved()
    {
        bool dark = false;
        try { dark = File.Exists(SettingsFile) && File.ReadAllText(SettingsFile).Trim() == "dark"; }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        Apply(dark, save: false);
    }

    public static void Toggle() => Apply(!IsDark, save: true);

    public static void Apply(bool dark, bool save)
    {
        IsDark = dark;
        var dicts = Application.Current.Resources.MergedDictionaries;
        var palette = new ResourceDictionary
        {
            // URI liée à l'assembly (et non à l'exécutable lancé) : fonctionne aussi en hébergement / tests
            Source = new Uri($"pack://application:,,,/{typeof(ThemeManager).Assembly.GetName().Name};component/Themes/{(dark ? "Dark" : "Light")}.xaml", UriKind.Absolute),
        };
        if (dicts.Count > 0) dicts[0] = palette;
        else dicts.Insert(0, palette);

        if (save && AppData.CanWrite)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(SettingsFile)!);
                File.WriteAllText(SettingsFile, dark ? "dark" : "light");
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        Changed?.Invoke();
    }
}
