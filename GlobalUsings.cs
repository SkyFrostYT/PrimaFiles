global using System.IO;

// Sécurité : les DLL natives appelées (kernel32, shlwapi, netapi32, mpr, dwmapi, advapi32, user32) ne sont
// cherchées que dans System32, jamais dans le dossier de l'application ou le répertoire courant
// (protection contre le « DLL hijacking »).
[assembly: System.Runtime.InteropServices.DefaultDllImportSearchPaths(System.Runtime.InteropServices.DllImportSearchPath.System32)]
