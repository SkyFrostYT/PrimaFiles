using System.Windows.Data;
using System.Windows.Markup;
using StorageScanner.Core;

namespace StorageScanner.UI;

/// <summary>Texte traduit en XAML : <c>Text="{ui:L clé}"</c>. Liaison vers <see cref="Loc"/> : le texte change
/// immédiatement quand l'utilisateur choisit une autre langue.</summary>
[MarkupExtensionReturnType(typeof(object))]
public sealed class LExtension(string key) : MarkupExtension
{
    public string Key { get; } = key;

    public override object ProvideValue(IServiceProvider serviceProvider) =>
        new Binding($"[{Key}]") { Source = Loc.Instance, Mode = BindingMode.OneWay }.ProvideValue(serviceProvider);
}
