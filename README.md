# PrimaFiles

Analyse de l'occupation d'un disque local ou d'un partage réseau (`\\serveur\partage`), en WPF/.NET 10.
**Lecture seule** : PrimaFiles ne supprime, ne déplace et ne modifie jamais aucun fichier.

## Installation

1. Téléchargez **`Installer.ps1`** depuis la [dernière version](https://github.com/SkyFrostYT/PrimaFiles/releases/latest).
2. Ouvrez PowerShell dans le dossier du téléchargement et lancez :

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Installer.ps1
   ```

3. Acceptez l'invite administrateur (UAC). PrimaFiles est ensuite disponible dans le **menu Démarrer**.

L'installateur :

- installe PrimaFiles dans **`C:\Program Files\PrimaFiles`** (dossier protégé : modifiable uniquement par un administrateur) ;
- télécharge la dernière version depuis GitHub et **vérifie son empreinte SHA-256** avant de l'installer
  (si `PrimaFiles.exe` et `SHA256SUMS.txt` sont à côté du script, ce sont eux qui sont utilisés) ;
- choisit la version standard si le runtime .NET 10 Desktop est présent, sinon la version portable (forcer : `-Portable`) ;
- retire la marque « téléchargé depuis Internet » : **plus d'alerte SmartScreen au lancement** ;
- ajoute PrimaFiles dans *Paramètres > Applications installées*, d'où il se désinstalle normalement.

Désinstallation manuelle :

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Program Files\PrimaFiles\Installer.ps1" -Desinstaller
```

Sans installation : téléchargez `PrimaFiles.exe` (ou le zip portable) et lancez-le directement.

## Éviter l'alerte de Windows (« Windows a protégé votre ordinateur »)

PrimaFiles n'est pas signé par un certificat commercial : un fichier téléchargé déclenche l'avertissement SmartScreen
au premier lancement. Trois solutions, de la plus simple à la plus complète :

**1. Passer l'alerte une fois** : « Informations complémentaires » → « Exécuter quand même ».

**2. Débloquer le fichier téléchargé** (c'est la marque « provient d'Internet » qui déclenche l'alerte) :

```powershell
Unblock-File -Path "$env:USERPROFILE\Downloads\PrimaFiles.exe"
```

**3. Auto-signer le programme sur votre PC** : Windows affiche alors un éditeur identifié (« PrimaFiles (auto-signé
sur ce PC) ») au lieu d'« Éditeur inconnu », et les stratégies qui n'autorisent que les programmes signés l'acceptent.

- Avec l'installateur (recommandé) :

  ```powershell
  powershell -ExecutionPolicy Bypass -File .\Installer.ps1 -AutoSigner
  ```

- Ou manuellement, sur un `PrimaFiles.exe` déjà copié dans un dossier protégé (PowerShell **administrateur**) :

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
  Remove-Item "Cert:\LocalMachine\My\$($cert.Thumbprint)" -DeleteKey   # destruction de la clé privée
  Remove-Item $cer
  ```

> [!IMPORTANT]
> - L'auto-signature n'est reconnue **que sur le PC où elle a été faite**. Pour une signature reconnue partout, il faut
>   un certificat commercial (DigiCert, Sectigo, Microsoft Artifact Signing…) ou un certificat d'entreprise déployé par GPO.
> - La **clé privée est détruite** juste après la signature : le certificat approuvé ne peut servir à signer aucun autre
>   programme, même si le PC est compromis plus tard.
> - Après une mise à jour, relancez l'installateur avec `-AutoSigner` (une signature ne couvre qu'une version précise).
> - Si **Smart App Control** est activé (Windows 11), il peut bloquer un programme auto-signé : il faut alors le désactiver
>   ou attendre que PrimaFiles soit reconnu par Microsoft.
> - La désinstallation retire aussi le certificat.

## Fonctionnalités

- **Interface moderne** : barre de titre personnalisée (réduire / agrandir / fermer, coins arrondis Windows 11), accueil avec les lecteurs disponibles, indicateurs mis à jour en direct pendant l'analyse.
- **Thème clair / sombre** : bouton soleil / lune dans la barre de titre, choix mémorisé.
- **Carte des volumes** (bandeau du bas, comme WinDirStat / TreeSize) : chaque bloc est proportionnel à l'espace occupé. Survol : détail · clic : ligne correspondante dans l'arborescence · double-clic : zoom · clic droit : remonter.
- **Arborescence** dans l'ordre de l'Explorateur Windows (tri naturel), ou triée par taille, nombre de fichiers ou date. Barres vert / jaune / rouge selon la part occupée ; vrai taux d'occupation du volume (quota inclus) sur la ligne racine.
- **Repères** : logo Windows = élément système · triangle = à ne pas supprimer · œil barré = dossier inaccessible.
- **Fichiers suspects** (bouclier rouge = suspect, orange = à vérifier) : repérés pendant l'analyse par des indices typiques des logiciels malveillants : double extension (`facture.pdf.exe`), caractères invisibles qui masquent la vraie extension, nom de processus Windows hors de Windows (faux `svchost.exe`), extensions et notes de rançongiciel, scripts / économiseurs d'écran dans Temp, Téléchargements, Corbeille, Public ou Démarrage, programmes cachés. Onglet dédié avec bandeau d'alerte, bouclier sur les dossiers qui en contiennent, et **vérification à la demande par l'antivirus installé** (WithSecure / F-Secure, ou Microsoft Defender). Ces indices ne sont pas une preuve : seul l'antivirus confirme une menace.
- **Gros fichiers**, **types de fichiers**, **doublons** (taille → empreinte partielle → SHA-256), **erreurs**, **export CSV** pour Excel.
- **Mode administrateur** : relance avec élévation (UAC) et privilège de sauvegarde en lecture seule pour lister les dossiers protégés. Les lecteurs réseau mappés peuvent ne pas être visibles dans ce mode.
- **Serveur entier** : saisir `\\serveur` analyse tous ses partages (partages d'administration C$, ADMIN$… exclus).
- **Confidentialité** : le nom du serveur des lecteurs réseau n'est jamais affiché, seulement le nom du partage.

## Sécurité

| Mesure | Effet |
|---|---|
| Lecture seule | aucune API d'écriture, de suppression ou de déplacement sur les fichiers analysés |
| Manifeste `asInvoker` | démarre sans droits admin ; élévation uniquement sur demande explicite (UAC) |
| `DefaultDllImportSearchPaths(System32)` | les DLL système ne sont chargées que depuis System32 (anti « DLL hijacking ») |
| Explorateur lancé par chemin absolu | pas de détournement via le `PATH` |
| Export CSV protégé | les noms commençant par `= + - @` sont neutralisés (pas d'injection de formules Excel) |
| Aucune connexion réseau sortante | pas de télémétrie, pas de mise à jour automatique ; seuls les partages demandés sont lus |
| Réglages locaux | historique et thème dans `%LOCALAPPDATA%\PrimaFiles` uniquement |
| Publication sans auto-extraction ni compression | évite les heuristiques « packer » des antivirus |
| Métadonnées de version complètes, build déterministe | exécutable identifiable, empreintes SHA-256 fournies |
| Chemins `\\?\` pour toutes les lectures | un nom piégé (`virus.exe.`, `nul.txt`, dossier `Docs `) ne peut pas faire analyser, hacher ou vérifier un autre fichier |
| Vérification antivirus robuste | nom piégé → tout le dossier est analysé ; analyseur arrêté en cas d'annulation ; seul le bilan final est lu |
| Aucune écriture en mode administrateur | historique et thème non enregistrés : pas d'écrasement de fichier système via un lien placé dans le profil |
| Chargement des DLL durci | dossier courant exclu, DLL de System32 prioritaires, DLL « intégrité faible » refusées |
| Fichiers « en ligne uniquement » ignorés | doublons et signatures ne déclenchent pas le téléchargement des fichiers OneDrive / SharePoint |
| Réponses réseau filtrées | un serveur ne peut pas faire analyser un autre chemin via un nom de partage piégé |

### Détection des fichiers suspects : renforcements 1.3

- Les emplacements de confiance (Windows, Program Files, AppData\Local\Programs…) ne sont reconnus qu'à leur **place réelle** : un dossier `Program Files` ou `Windows.old` recréé dans Téléchargements ne protège plus un programme malveillant.
- Les sous-dossiers de Windows **accessibles en écriture** (`Windows\Temp`, `Tasks`, `tracing`, `spool\drivers\color`…) ne sont plus considérés comme système.
- Le cache Internet et les **pièces jointes Outlook ouvertes** (`INetCache\Content.Outlook`) sont des emplacements à risque.
- Nouveaux indices : nom piégé, programme marqué « fichier système » hors de Windows, raccourcis à double extension (`facture.pdf.lnk`), consoles `.msc`, compléments Excel `.xll`, aide `.chm`.
- Un fichier suspect n'affiche plus jamais le logo Windows ni le triangle « à ne pas supprimer ».

## Compiler et publier (développeurs)

```powershell
.\Publier.ps1
```

Si `Assets\PrimaFiles.ico` est absente, elle est d'abord recréée par `Generer-Icone.ps1` à partir du logo vectoriel
(`Themes\Icons.xaml`). Pour compiler sans publier : `.\Generer-Icone.ps1` puis `dotnet build -c Release`.

Produit dans `publish\` :

- `standard\PrimaFiles.exe` : un seul fichier léger ; nécessite le **runtime .NET 10 Desktop** (Windows propose de l'installer s'il manque).
- `portable\` : `PrimaFiles.exe` + quelques DLL natives WPF, fonctionne sans rien installer (copier le dossier entier).
- `SHA256SUMS.txt` : empreintes pour vérifier l'intégrité des fichiers distribués.

Avec un certificat de signature de code (commercial ou d'entreprise) : `.\Publier.ps1 -Thumbprint <empreinte>`
(signature SHA-256 horodatée). `Installer.ps1` est à joindre à chaque publication GitHub, avec `SHA256SUMS.txt`.

## Structure

| Dossier | Contenu |
|---|---|
| `Core/Scanner.cs` | Moteur de scan parallèle |
| `Core/DuplicateFinder.cs` | Recherche de doublons |
| `Core/Safety.cs` | Repérage des éléments système / à ne pas supprimer |
| `Core/Elevation.cs` | Mode administrateur |
| `Core/Unc.cs` | Lecteurs réseau et partages |
| `Core/Utils.cs` | Formatage, tri naturel Windows, volumes, export CSV |
| `UI/` | ViewModel, arborescence, carte des volumes, thèmes |
| `Themes/` | Palettes claire / sombre, styles, logos vectoriels |
| `Assets/` | Icône de l'application |

## Licence

[MIT](LICENSE) © 2026 Primatoria
