using System.Diagnostics;
using System.Text.RegularExpressions;

namespace StorageScanner.Core;

public enum AvVerdict { Clean, Threat, Error }

public sealed record AvResult(AvVerdict Verdict, string Message);

/// <summary>Moteur antivirus installé, utilisé à la demande pour vérifier un fichier suspect.
/// PrimaFiles n'agit jamais lui-même sur le fichier : la décision (quarantaine…) reste celle de l'antivirus.</summary>
public sealed class AntivirusEngine
{
    private enum EngineKind { WithSecure, Defender }

    private readonly EngineKind _kind;
    private readonly string _exe;

    private AntivirusEngine(EngineKind kind, string exe, string name)
    {
        _kind = kind;
        _exe = exe;
        Name = name;
    }

    public string Name { get; }

    /// <summary>Recherche un analyseur en ligne de commande : WithSecure / F-Secure, sinon Microsoft Defender.</summary>
    public static AntivirusEngine? Detect()
    {
        string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        foreach (var candidate in new[]
                 {
                     Path.Combine(pf86, "F-Secure", "PSB", "fsscan.exe"),
                     Path.Combine(pf, "F-Secure", "PSB", "fsscan.exe"),
                     Path.Combine(pf, "WithSecure", "PSB", "fsscan.exe"),
                     Path.Combine(pf86, "WithSecure", "PSB", "fsscan.exe"),
                 })
        {
            if (File.Exists(candidate)) return new AntivirusEngine(EngineKind.WithSecure, candidate, "WithSecure");
        }

        string defender = Path.Combine(pf, "Windows Defender", "MpCmdRun.exe");
        return File.Exists(defender) ? new AntivirusEngine(EngineKind.Defender, defender, "Microsoft Defender") : null;
    }

    public async Task<AvResult> ScanAsync(string file, CancellationToken ct = default)
    {
        if (!File.Exists(SafePath.ForIo(file))) return new AvResult(AvVerdict.Error, Loc.T("avNotFound"));

        // Nom piégé (« virus.exe. ») : passé tel quel, l'antivirus analyserait un autre fichier et le déclarerait sain.
        // On analyse alors tout le dossier qui le contient.
        string target = file;
        string note = "";
        if (SafePath.IsAmbiguousPath(file))
        {
            target = SafePath.NearestUnambiguousFolder(file);
            note = Loc.F("avFolderScanned", target);
        }
        if (!Path.IsPathFullyQualified(target)) return new AvResult(AvVerdict.Error, Loc.T("avInvalidPath"));

        var psi = new ProcessStartInfo(_exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        if (_kind == EngineKind.WithSecure)
        {
            // Analyse simple, sans suppression : l'antivirus applique sa propre politique s'il détecte une menace
            psi.ArgumentList.Add("--skip_cache");
            psi.ArgumentList.Add("--noflyer");
            psi.ArgumentList.Add(target); // chemin absolu : ne peut pas être pris pour une option (« -… »)
        }
        else
        {
            psi.ArgumentList.Add("-Scan");
            psi.ArgumentList.Add("-ScanType");
            psi.ArgumentList.Add("3");
            psi.ArgumentList.Add("-File");
            psi.ArgumentList.Add(target);
            psi.ArgumentList.Add("-DisableRemediation");
        }

        Process? p = null;
        try
        {
            p = Process.Start(psi) ?? throw new InvalidOperationException(Loc.T("avCannotStart"));
            var stdout = p.StandardOutput.ReadToEndAsync(CancellationToken.None);
            var stderr = p.StandardError.ReadToEndAsync(CancellationToken.None);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromMinutes(10));
            await p.WaitForExitAsync(timeout.Token);
            string output = await stdout + await stderr;
            var r = Interpret(p.ExitCode, output);
            return note.Length == 0 ? r : r with { Message = r.Message + note };
        }
        catch (OperationCanceledException)
        {
            return new AvResult(AvVerdict.Error, ct.IsCancellationRequested ? Loc.T("avInterrupted") : Loc.T("avTimeout"));
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return new AvResult(AvVerdict.Error, ex.Message);
        }
        finally
        {
            // Annulation ou délai dépassé : l'analyseur ne doit pas continuer à tourner en arrière-plan
            if (p is not null)
            {
                try { if (!p.HasExited) p.Kill(entireProcessTree: true); }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
                p.Dispose();
            }
        }
    }

    private AvResult Interpret(int exitCode, string output)
    {
        if (_kind == EngineKind.WithSecure)
        {
            // Dernière occurrence : c'est le bilan final (le texte qui précède peut reprendre des noms de fichiers)
            var m = Regex.Match(output, @"^\s*Harmful items:\s*(\d{1,9})\s*$",
                RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.RightToLeft, TimeSpan.FromSeconds(2));
            if (m.Success)
                return int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture) > 0
                    ? new AvResult(AvVerdict.Threat, Loc.F("avThreat", Name))
                    : new AvResult(AvVerdict.Clean, Loc.F("avClean", Name));
            return new AvResult(AvVerdict.Error, Loc.F("avUnexpected", Name, exitCode));
        }

        return exitCode switch
        {
            0 => new AvResult(AvVerdict.Clean, Loc.F("avClean", Name)),
            2 => new AvResult(AvVerdict.Threat, Loc.F("avThreat", Name)),
            _ => new AvResult(AvVerdict.Error, Loc.F("avUnavailable", Name, exitCode)),
        };
    }
}
