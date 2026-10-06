# PrimaFiles

Analyse de l'occupation d'un disque local ou d'un partage réseau (`\\serveur\partage`), en WPF/.NET 10.
**Lecture seule** : PrimaFiles ne supprime, ne déplace et ne modifie jamais aucun fichier.

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

## Publication

```powershell
.\Publier.ps1
```

Si `Assets\PrimaFiles.ico` est absente, elle est d'abord recréée par `Generer-Icone.ps1` à partir du logo vectoriel
(`Themes\Icons.xaml`). Pour compiler sans publier : `.\Generer-Icone.ps1` puis `dotnet build -c Release`.

Produit dans `publish\` :

- `standard\PrimaFiles.exe` : un seul fichier léger ; nécessite le **runtime .NET 10 Desktop** (Windows propose de l'installer s'il manque).
- `portable\` : `PrimaFiles.exe` + quelques DLL natives WPF, fonctionne sans rien installer (copier le dossier entier).
- `SHA256SUMS.txt` : empreintes pour vérifier l'intégrité des fichiers distribués.

### Signature (recommandée pour les antivirus et SmartScreen)

Un exécutable non signé peut afficher « Éditeur inconnu » (SmartScreen) et être traité avec méfiance par certains antivirus.
La seule solution durable est de le **signer avec un certificat de signature de code** :

- certificat d'entreprise (autorité interne déployée par GPO), ou certificat public OV/EV (DigiCert, Sectigo…) ;
- puis : `.\Publier.ps1 -Thumbprint <empreinte du certificat>` (signature SHA-256 horodatée).

Les exécutables publiés ici ne sont **pas signés** : au premier lancement, SmartScreen peut afficher « Windows a protégé
votre ordinateur » → « Informations complémentaires » → « Exécuter quand même ». Les empreintes de `SHA256SUMS.txt`
permettent de vérifier que le fichier téléchargé est intact. Vous pouvez aussi compiler vous-même à partir des sources.

En complément, l'exécutable peut être soumis à Microsoft pour analyse (portail « Submit a file for malware analysis » de Microsoft Defender) afin d'accélérer sa réputation.

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
