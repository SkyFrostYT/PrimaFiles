<#
.SYNOPSIS
    Installe PrimaFiles dans C:\Program Files\PrimaFiles (ou le désinstalle).

.DESCRIPTION
    - Utilise PrimaFiles.exe (ou le zip portable) placé à côté de ce script ; sinon télécharge la dernière version
      depuis GitHub. L'empreinte SHA-256 de chaque fichier est vérifiée avec SHA256SUMS.txt.
    - Version standard si le runtime .NET 10 Desktop est installé, sinon version portable (ou -Portable).
    - Copie dans C:\Program Files\PrimaFiles : dossier protégé, modifiable uniquement par un administrateur
      (aucune DLL ne peut y être glissée à côté de l'exécutable).
    - Retire la marque « téléchargé depuis Internet » : plus d'alerte SmartScreen au lancement.
    - Raccourci dans le menu Démarrer, entrée dans « Applications installées » (désinstallation possible).
    - -AutoSigner : signe l'exécutable avec un certificat créé sur ce PC et approuvé sur ce PC uniquement.
      La clé privée est détruite juste après la signature : le certificat ne pourra jamais signer autre chose.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Installer.ps1
    powershell -ExecutionPolicy Bypass -File .\Installer.ps1 -AutoSigner
    powershell -ExecutionPolicy Bypass -File "C:\Program Files\PrimaFiles\Installer.ps1" -Desinstaller
#>
param(
    [switch]$AutoSigner,
    [switch]$Portable,
    [switch]$Desinstaller
)

$ErrorActionPreference = 'Stop'
$Repo = 'SkyFrostYT/PrimaFiles'
if (-not [IO.Path]::IsPathRooted("$env:ProgramFiles")) { throw 'Dossier Program Files introuvable.' }
$Dest = Join-Path $env:ProgramFiles 'PrimaFiles'
$UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PrimaFiles'
$Shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\PrimaFiles.lnk'
$CertSubject = 'CN=PrimaFiles (auto-signé sur ce PC)'

# --- Droits administrateur (écriture dans Program Files) : relance avec l'invite UAC
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($AutoSigner) { $argList += '-AutoSigner' }
    if ($Portable) { $argList += '-Portable' }
    if ($Desinstaller) { $argList += '-Desinstaller' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    return
}

function Stop-PrimaFiles {
    Get-Process PrimaFiles -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path.StartsWith($Dest, [StringComparison]::OrdinalIgnoreCase) } |
        Stop-Process -Force
    Start-Sleep -Milliseconds 500
}

function Remove-OldCertificates {
    # Certificats posés par une installation précédente (partie publique uniquement)
    foreach ($store in 'Root', 'TrustedPublisher', 'My') {
        Get-ChildItem "Cert:\LocalMachine\$store" | Where-Object Subject -eq $CertSubject | Remove-Item -Force
    }
}

# ---------------------------------------------------------------- Désinstallation
if ($Desinstaller) {
    Stop-PrimaFiles
    Remove-OldCertificates
    Remove-Item $Shortcut -Force -ErrorAction SilentlyContinue
    Remove-Item $UninstallKey -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force }
    Write-Host 'PrimaFiles a été désinstallé. Vos réglages restent dans %LOCALAPPDATA%\PrimaFiles.'
    Start-Sleep -Seconds 3
    return
}

# ---------------------------------------------------------------- Fichiers à installer
function Get-Sums([string]$text) {
    $sums = @{}
    foreach ($line in $text -split "`r?`n") {
        if ($line -match '^\s*([0-9A-Fa-f]{64})\s+\*?(.+?)\s*$') { $sums[$Matches[2]] = $Matches[1].ToUpperInvariant() }
    }
    return $sums
}

function Assert-Hash([string]$file, [hashtable]$sums, [string]$name) {
    if (-not $sums.ContainsKey($name)) { throw "Aucune empreinte pour $name dans SHA256SUMS.txt : installation annulée." }
    $actual = (Get-FileHash $file -Algorithm SHA256).Hash
    if ($actual -ne $sums[$name]) { throw "Empreinte SHA-256 incorrecte pour $name : fichier corrompu ou modifié. Installation annulée." }
    Write-Host "Empreinte vérifiée : $name"
}

$runtime = Test-Path (Join-Path $env:ProgramFiles 'dotnet\shared\Microsoft.WindowsDesktop.App\10.*')
$usePortable = $Portable -or -not $runtime
if (-not $runtime -and -not $Portable) { Write-Host 'Runtime .NET 10 Desktop absent : installation de la version portable.' }

$work = Join-Path $env:TEMP ('PrimaFiles-install-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $work | Out-Null
try {
    $here = $PSScriptRoot
    $localSums = Join-Path $here 'SHA256SUMS.txt'
    $localZip = Get-ChildItem $here -Filter 'PrimaFiles-portable*.zip' -ErrorAction SilentlyContinue | Select-Object -First 1
    $localExe = Join-Path $here 'PrimaFiles.exe'

    # Fichiers locaux utilisés seulement s'ils sont accompagnés de leurs empreintes (sinon : téléchargement)
    $localSource = if ($usePortable) { if ($localZip) { $localZip.FullName } } elseif (Test-Path $localExe) { $localExe }
    $localSumsTable = if (Test-Path $localSums) { Get-Sums (Get-Content $localSums -Raw) } else { @{} }
    if ($localSource -and $localSumsTable.ContainsKey((Split-Path $localSource -Leaf))) {
        $source = $localSource
        Assert-Hash $source $localSumsTable (Split-Path $source -Leaf)
    }
    else {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $base = "https://github.com/$Repo/releases/latest/download"
        Write-Host 'Téléchargement de la dernière version depuis GitHub...'
        # Enregistré dans un fichier : GitHub sert les pièces jointes en binaire (Content serait un tableau d'octets)
        $sumsFile = Join-Path $work 'SHA256SUMS.txt'
        Invoke-WebRequest "$base/SHA256SUMS.txt" -OutFile $sumsFile -UseBasicParsing
        $sums = Get-Sums (Get-Content $sumsFile -Raw)
        $name = if ($usePortable) { $sums.Keys | Where-Object { $_ -like 'PrimaFiles-portable*.zip' } | Select-Object -First 1 } else { 'PrimaFiles.exe' }
        if (-not $name) { throw 'Version portable introuvable dans la dernière publication.' }
        $source = Join-Path $work $name
        Invoke-WebRequest "$base/$name" -OutFile $source -UseBasicParsing
        Assert-Hash $source $sums $name
    }

    # ------------------------------------------------------------ Copie dans Program Files
    Stop-PrimaFiles
    if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force }
    New-Item -ItemType Directory $Dest | Out-Null
    if ($usePortable) { Expand-Archive $source -DestinationPath $Dest -Force }
    else { Copy-Item $source (Join-Path $Dest 'PrimaFiles.exe') }
    if ($PSCommandPath) { Copy-Item $PSCommandPath (Join-Path $Dest 'Installer.ps1') -Force }
    # Marque « téléchargé depuis Internet » retirée : c'est elle qui déclenche l'alerte SmartScreen
    Get-ChildItem $Dest -Recurse -File | Unblock-File
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

$exe = Join-Path $Dest 'PrimaFiles.exe'
$version = (Get-Item $exe).VersionInfo.ProductVersion

# ---------------------------------------------------------------- Auto-signature (facultative)
$thumbprint = ''
if ($AutoSigner) {
    Remove-OldCertificates
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $CertSubject `
        -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears(10)
    try {
        # Seule la partie publique est approuvée, et pour cet ordinateur uniquement
        $cer = Join-Path $env:TEMP "PrimaFiles-$([Guid]::NewGuid().ToString('N')).cer"
        Export-Certificate -Cert $cert -FilePath $cer | Out-Null
        Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
        Remove-Item $cer -Force
        foreach ($f in @($exe, (Join-Path $Dest 'Installer.ps1'))) {
            if (Test-Path $f) {
                $sig = Set-AuthenticodeSignature -FilePath $f -Certificate $cert -HashAlgorithm SHA256
                if ($sig.Status -ne 'Valid') { throw "Signature impossible de $f : $($sig.StatusMessage)" }
            }
        }
        $thumbprint = $cert.Thumbprint
    }
    finally {
        # Destruction de la clé privée : personne ne pourra signer un autre programme avec ce certificat
        Remove-Item "Cert:\LocalMachine\My\$($cert.Thumbprint)" -DeleteKey -Force
    }
    Write-Host "Exécutable signé : $((Get-AuthenticodeSignature $exe).Status)"
}

# ---------------------------------------------------------------- Menu Démarrer et désinstallation
$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut($Shortcut)
$lnk.TargetPath = $exe
$lnk.WorkingDirectory = $Dest
$lnk.Description = "Analyse de l'espace disque et des partages réseau"
$lnk.Save()

New-Item $UninstallKey -Force | Out-Null
$props = @{
    DisplayName     = 'PrimaFiles'
    DisplayVersion  = $version
    Publisher       = 'Primatoria'
    DisplayIcon     = $exe
    InstallLocation = $Dest
    URLInfoAbout    = "https://github.com/$Repo"
    UninstallString = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Dest\Installer.ps1`" -Desinstaller"
    CertThumbprint  = $thumbprint
}
foreach ($k in $props.Keys) { New-ItemProperty $UninstallKey -Name $k -Value $props[$k] -PropertyType String -Force | Out-Null }
New-ItemProperty $UninstallKey -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty $UninstallKey -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
$size = [int]((Get-ChildItem $Dest -Recurse -File | Measure-Object Length -Sum).Sum / 1KB)
New-ItemProperty $UninstallKey -Name EstimatedSize -Value $size -PropertyType DWord -Force | Out-Null

Write-Host ''
Write-Host "PrimaFiles $version installé dans $Dest"
Write-Host 'Lancement : menu Démarrer > PrimaFiles'
Start-Sleep -Seconds 3
