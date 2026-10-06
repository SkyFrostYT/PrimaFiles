<#
.SYNOPSIS
    Publie PrimaFiles en .exe, le signe (si un certificat est fourni) et calcule les empreintes SHA-256.

.DESCRIPTION
    Deux variantes sont produites dans .\publish :
      - PrimaFiles.exe (dossier "standard")   : un seul .exe léger, nécessite le runtime .NET 10 Desktop
                                                (déjà présent sur les postes à jour ; sinon Windows propose de l'installer).
      - dossier "portable"                    : .exe + quelques DLL natives WPF, fonctionne sans rien installer.
    Aucune variante n'utilise l'auto-extraction dans %TEMP% ni la compression, deux techniques que les
    antivirus considèrent comme suspectes.

.PARAMETER Thumbprint
    Empreinte d'un certificat de signature de code (Cert:\CurrentUser\My ou Cert:\LocalMachine\My).
    Sans ce paramètre, les fichiers ne sont pas signés.

.EXAMPLE
    .\Publier.ps1
    .\Publier.ps1 -Thumbprint 0123456789ABCDEF0123456789ABCDEF01234567
#>
param([string]$Thumbprint)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$out = Join-Path $root 'publish'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'

if (Test-Path $out) { Remove-Item $out -Recurse -Force }

# L'icône est générée à partir du logo vectoriel si elle est absente (ex. copie du code depuis Google Drive)
if (-not (Test-Path (Join-Path $root 'Assets\PrimaFiles.ico'))) { & (Join-Path $root 'Generer-Icone.ps1') }

$common = @('publish', (Join-Path $root 'PrimaFiles.csproj'), '-c', 'Release', '-r', 'win-x64', '--nologo',
            '-p:PublishSingleFile=true', '-p:PublishReadyToRun=true',
            '-p:EnableCompressionInSingleFile=false', '-p:IncludeNativeLibrariesForSelfExtraction=false')

Write-Host '1/2  Version standard (runtime .NET 10 requis)...'
dotnet @common --self-contained false -o (Join-Path $out 'standard')
if ($LASTEXITCODE -ne 0) { throw 'Échec de la publication standard' }

Write-Host '2/2  Version portable (sans installation)...'
dotnet @common --self-contained true -o (Join-Path $out 'portable')
if ($LASTEXITCODE -ne 0) { throw 'Échec de la publication portable' }

$binaries = Get-ChildItem $out -Recurse -Include *.exe, *.dll

if ($Thumbprint) {
    $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My |
        Where-Object { $_.Thumbprint -eq $Thumbprint -and $_.HasPrivateKey } | Select-Object -First 1
    if (-not $cert) { throw "Certificat $Thumbprint introuvable (ou sans clé privée)." }
    foreach ($f in $binaries | Where-Object { $_.Name -like 'PrimaFiles*' }) {
        $sig = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert -HashAlgorithm SHA256 `
            -TimestampServer 'http://timestamp.digicert.com'
        Write-Host "Signé : $($f.Name) -> $($sig.Status)"
    }
}

# Empreintes : permettent de vérifier qu'un exécutable distribué n'a pas été modifié
$hashFile = Join-Path $out 'SHA256SUMS.txt'
Get-ChildItem $out -Recurse -Filter PrimaFiles.exe | ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    "$h  $($_.FullName.Substring($out.Length + 1))"
} | Set-Content $hashFile -Encoding utf8

Write-Host ''
Write-Host "Terminé. Fichiers dans $out"
Get-Content $hashFile
