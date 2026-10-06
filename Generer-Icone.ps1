<#
.SYNOPSIS
    Régénère Assets\PrimaFiles.ico à partir du logo vectoriel de Themes\Icons.xaml (clé « AppLogo »).

.DESCRIPTION
    Produit une icône Windows multi-tailles (16 à 256 px, images PNG) identique à celle du projet.
    Appelé automatiquement par Publier.ps1 si l'icône est absente.
#>
$ErrorActionPreference = 'Stop'

# WPF exige un thread STA : relance dans Windows PowerShell en mode STA si nécessaire
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -STA -ExecutionPolicy Bypass -File $PSCommandPath
    exit $LASTEXITCODE
}

Add-Type -AssemblyName PresentationCore, PresentationFramework, WindowsBase

$root = $PSScriptRoot
$assets = Join-Path $root 'Assets'
New-Item -ItemType Directory -Force $assets | Out-Null

$stream = [IO.File]::OpenRead((Join-Path $root 'Themes\Icons.xaml'))
try { $dict = [Windows.Markup.XamlReader]::Load($stream) } finally { $stream.Dispose() }
$logo = $dict['AppLogo']

$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
$pngs = foreach ($s in $sizes) {
    $visual = New-Object Windows.Media.DrawingVisual
    $dc = $visual.RenderOpen()
    $dc.DrawImage($logo, (New-Object Windows.Rect 0, 0, $s, $s))
    $dc.Close()
    $bitmap = New-Object Windows.Media.Imaging.RenderTargetBitmap $s, $s, 96, 96, ([Windows.Media.PixelFormats]::Pbgra32)
    $bitmap.Render($visual)
    $encoder = New-Object Windows.Media.Imaging.PngBitmapEncoder
    $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
    $ms = New-Object IO.MemoryStream
    $encoder.Save($ms)
    , $ms.ToArray()
}

# Format ICO : en-tête, répertoire des images, puis les images PNG
$file = [IO.File]::Create((Join-Path $assets 'PrimaFiles.ico'))
$writer = New-Object IO.BinaryWriter $file
try {
    $writer.Write([int16]0); $writer.Write([int16]1); $writer.Write([int16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    for ($i = 0; $i -lt $sizes.Count; $i++) {
        $dim = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
        $writer.Write([byte]$dim); $writer.Write([byte]$dim); $writer.Write([byte]0); $writer.Write([byte]0)
        $writer.Write([int16]1); $writer.Write([int16]32)
        $writer.Write([int32]$pngs[$i].Length); $writer.Write([int32]$offset)
        $offset += $pngs[$i].Length
    }
    foreach ($png in $pngs) { $writer.Write($png) }
}
finally {
    $writer.Dispose()
}
Write-Host "Icône générée : $(Join-Path $assets 'PrimaFiles.ico')"
