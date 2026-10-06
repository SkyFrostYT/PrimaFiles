using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Windows.Data;
using System.Windows.Input;
using StorageScanner.Core;

namespace StorageScanner.UI;

public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }
}

public sealed class RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null) : ICommand
{
    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? parameter) => canExecute?.Invoke(parameter) ?? true;
    public void Execute(object? parameter) => execute(parameter);
}

/// <summary>ObservableCollection avec insertions/suppressions en bloc : évite des milliers de
/// notifications quand on déplie un dossier contenant beaucoup de sous-dossiers.</summary>
public sealed class BulkObservableCollection<T> : ObservableCollection<T>
{
    private const int BulkThreshold = 64;

    private List<T> List => (List<T>)Items;

    public void InsertRange(int index, IList<T> items)
    {
        if (items.Count < BulkThreshold)
        {
            for (int i = 0; i < items.Count; i++) InsertItem(index + i, items[i]);
            return;
        }
        CheckReentrancy();
        List.InsertRange(index, items);
        RaiseReset();
    }

    public void RemoveRange(int index, int count)
    {
        if (count < BulkThreshold)
        {
            for (int i = 0; i < count; i++) RemoveItem(index);
            return;
        }
        CheckReentrancy();
        List.RemoveRange(index, count);
        RaiseReset();
    }

    public void ReplaceAll(IEnumerable<T> items)
    {
        CheckReentrancy();
        List.Clear();
        List.AddRange(items);
        RaiseReset();
    }

    private void RaiseReset()
    {
        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }
}

public sealed class BytesConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        long l => Format.Bytes(l),
        int i => Format.Bytes(i),
        _ => "",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class LocalDateConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is DateTime d && d.Year > 1700 ? d.ToLocalTime().ToString("g", CultureInfo.CurrentCulture) : "";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Code couleur des barres : vert = peu, jaune = moyen, rouge = beaucoup.</summary>
public static class UsageColors
{
    public static readonly System.Windows.Media.Brush Green = Frozen(0x22, 0xA3, 0x5A);
    public static readonly System.Windows.Media.Brush Yellow = Frozen(0xE6, 0xA8, 0x17);
    public static readonly System.Windows.Media.Brush Red = Frozen(0xDC, 0x26, 0x26);

    /// <summary>Part d'un élément dans son parent : &lt; 20 % vert, &lt; 50 % jaune, sinon rouge.</summary>
    public static System.Windows.Media.Brush ForShare(double percent) => For(percent, 20, 50);

    /// <summary>Remplissage d'un disque ou d'un quota : &lt; 75 % vert, &lt; 90 % jaune, sinon rouge.</summary>
    public static System.Windows.Media.Brush ForDisk(double percent) => For(percent, 75, 90);

    public static System.Windows.Media.Brush For(double percent, double warn, double critical) =>
        percent >= critical ? Red : percent >= warn ? Yellow : Green;

    private static System.Windows.Media.Brush Frozen(byte r, byte g, byte b)
    {
        var brush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }
}

/// <summary>Pourcentage → couleur. ConverterParameter = « disk » pour les seuils d'un disque.</summary>
public sealed class PercentToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        double p = value is double d ? d : 0;
        return parameter as string == "disk" ? UsageColors.ForDisk(p) : UsageColors.ForShare(p);
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => (value is true) ^ Invert ? System.Windows.Visibility.Visible : System.Windows.Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class NotConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;
}

/// <summary>Relie un groupe de RadioButton à un index entier (ConverterParameter = valeur du bouton).</summary>
public sealed class IntEqualsConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value?.ToString() == parameter?.ToString();

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is true && int.TryParse(parameter?.ToString(), out var i) ? i : Binding.DoNothing;
}

/// <summary>Dossier des réglages : %LOCALAPPDATA%\PrimaFiles (repris de l'ancien dossier StorageScanner).</summary>
public static class AppData
{
    public static string Dir { get; } = Init();

    public static string File(string name) => Path.Combine(Dir, name);

    private static string Init()
    {
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string dir = Path.Combine(local, "PrimaFiles");
        string legacy = Path.Combine(local, "StorageScanner");
        try
        {
            if (!Directory.Exists(dir) && Directory.Exists(legacy))
            {
                Directory.CreateDirectory(dir);
                foreach (var f in Directory.EnumerateFiles(legacy, "*.txt"))
                    System.IO.File.Copy(f, Path.Combine(dir, Path.GetFileName(f)), overwrite: false);
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return dir;
    }
}

/// <summary>Historique des chemins scannés (%LOCALAPPDATA%\StorageScanner\recent.txt).</summary>
public static class RecentStore
{
    private const int Max = 20;
    private static readonly string FilePath = AppData.File("recent.txt");

    public static IReadOnlyList<string> Load()
    {
        try { return File.Exists(FilePath) ? File.ReadAllLines(FilePath).Where(l => l.Length > 0).Take(Max).ToList() : []; }
        catch (IOException) { return []; }
        catch (UnauthorizedAccessException) { return []; }
    }

    public static void Save(IEnumerable<string> paths)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllLines(FilePath, paths.Take(Max));
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
