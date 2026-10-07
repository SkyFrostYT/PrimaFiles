<p align="center">
  <img src="Assets/PrimaFiles.png" width="96" alt="PrimaFiles logo">
</p>

<h1 align="center">PrimaFiles</h1>

<p align="center">
  <b>See what fills your disks and network shares, and spot suspicious files, without changing anything.</b><br>
  Free and open-source disk space analyzer for Windows 10/11.
</p>

<p align="center">
  <a href="https://github.com/SkyFrostYT/PrimaFiles/releases/latest"><img src="https://img.shields.io/github/v/release/SkyFrostYT/PrimaFiles?label=download" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D4" alt="Windows 10 | 11">
  <img src="https://img.shields.io/badge/.NET-10-512BD4" alt=".NET 10">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT license"></a>
</p>

---

PrimaFiles scans a local drive, a folder or a network share (`\\server\share`) and shows where the space goes.
It is **read-only**: it never deletes, moves or modifies a file. It sends no telemetry and makes no outbound connection.

## Features

- **Fast parallel scan** of drives, folders, network shares, or a whole server (`\\server` scans every share it exposes).
- **Folder tree** sorted like Windows Explorer, or by size, file count or date, with usage bars.
- **Volume map** (treemap, like WinDirStat): every block is proportional to its size; click to locate, double-click to zoom.
- **Largest files**, **file types**, **duplicates** (size → partial hash → SHA-256), **inactive folders** (no activity for 1–10 years), **errors**.
- **Suspicious file detection**: double extensions (`invoice.pdf.exe`), hidden Unicode tricks, fake Windows processes, ransomware notes, scripts in Temp / Downloads / Startup… Each hit can be checked on demand with the installed antivirus (Microsoft Defender or WithSecure / F-Secure).
- **Administrator mode** to read protected folders (backup privilege, still read-only). Your mapped network drives stay available.
- **Handy**: folder search (Ctrl+F), drag & drop, *Scan with PrimaFiles* in the Explorer right-click menu, CSV export for Excel, keyboard shortcuts, light / dark theme.
- **4 languages**: English, French, Spanish, German (🌐 button, switches instantly).
- **Privacy**: network drives show only the share name, never the server name.

## Installation

1. Download **`PrimaFiles.exe`** from the [latest release](https://github.com/SkyFrostYT/PrimaFiles/releases/latest).
   No .NET 10 Desktop runtime? Take `PrimaFiles-portable-….zip` instead, extract it and run `PrimaFiles.exe`.
2. Run it. PrimaFiles offers to **install itself** in `C:\Program Files\PrimaFiles` (Start menu entry, listed in *Installed apps*).
   Choose *No* to use it without installing.

Uninstall from *Settings > Apps > Installed apps*. Silent deployment:

```powershell
PrimaFiles.exe --install --quiet
& "C:\Program Files\PrimaFiles\PrimaFiles.exe" --uninstall --quiet
```

### "Windows protected your PC" warning

PrimaFiles is not signed with a commercial certificate, so SmartScreen warns on first launch of a downloaded copy.
Click **More info → Run anyway** once, or unblock the file before running it:

```powershell
Unblock-File -Path "$env:USERPROFILE\Downloads\PrimaFiles.exe"
```

Once installed, the warning no longer appears.

<details>
<summary><b>Optional: self-sign the installed copy on your PC</b></summary>

Windows then shows an identified publisher instead of "Unknown publisher", and policies that only allow signed
programs accept it. Run in an **administrator** PowerShell after installing:

```powershell
$exe  = "C:\Program Files\PrimaFiles\PrimaFiles.exe"
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=PrimaFiles (auto-signé sur ce PC)" `
        -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 3072 -KeyExportPolicy NonExportable `
        -NotAfter (Get-Date).AddYears(10)
$cer  = "$env:TEMP\PrimaFiles.cer"
Export-Certificate -Cert $cert -FilePath $cer | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
Set-AuthenticodeSignature -FilePath $exe -Certificate $cert -HashAlgorithm SHA256
Remove-Item "Cert:\LocalMachine\My\$($cert.Thumbprint)" -DeleteKey   # destroy the private key
Remove-Item $cer
```

- The signature is trusted **only on this PC**.
- The private key is destroyed right after signing, so the certificate cannot sign anything else.
- Run it again after each update. Uninstalling PrimaFiles removes the certificate.
- Smart App Control (Windows 11) may still block self-signed programs.
- Keep the certificate name unchanged: the uninstaller looks for it.

</details>

## Security

- **Read-only by design**: no write, delete or move call on scanned files.
- **Starts without admin rights**; elevation only on explicit request (UAC), and settings are never written while elevated.
- **Hardened DLL loading** (System32 only, current folder excluded) and Explorer launched by absolute path.
- **Trap-proof paths** (`\\?\`): names such as `virus.exe.`, `nul.txt` or `Docs ` cannot redirect a scan, hash or antivirus check to another file.
- **Trusted locations recognized only at their real place**: a fake `Program Files` folder in Downloads protects nothing.
- **CSV export** neutralizes formula injection; **network replies** are filtered; **cloud-only files** (OneDrive) are never downloaded.
- No telemetry, no auto-update, no packer. SHA-256 checksums are published with every release.

The security audit and hardening were carried out with the help of **Claude Code** (Anthropic), used as a cybersecurity assistant.

## Build from source

Requires the .NET 10 SDK.

```powershell
.\Publier.ps1                 # builds publish\standard, publish\portable and SHA256SUMS.txt
dotnet build -c Release       # build only
```

| Folder | Content |
|---|---|
| `Core/` | Scan engine, duplicates, suspicious-file rules, antivirus check, network shares, installer, translations (`Loc.cs`) |
| `UI/` | View model, tree, treemap, inactive folders |
| `Themes/` | Light / dark palettes, styles, vector icons |

Contributions and translations are welcome: open an issue or a pull request.

## License

[MIT](LICENSE) © 2026 Primatoria
