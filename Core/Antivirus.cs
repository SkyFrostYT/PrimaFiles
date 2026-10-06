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
        if (!File.Exists(file)) return new AvResult(AvVerdict.Error, "Fichier introuvable (déplacé ou mis en quarantaine ?)");

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
            psi.ArgumentList.Add(file);
        }
        else
        {
            psi.ArgumentList.Add("-Scan");
            psi.ArgumentList.Add("-ScanType");
            psi.ArgumentList.Add("3");
            psi.ArgumentList.Add("-File");
            psi.ArgumentList.Add(file);
            psi.ArgumentList.Add("-DisableRemediation");
        }

        try
        {
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("Impossible de lancer l'antivirus");
            var stdout = p.StandardOutput.ReadToEndAsync(ct);
            var stderr = p.StandardError.ReadToEndAsync(ct);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromMinutes(10));
            await p.WaitForExitAsync(timeout.Token);
            string output = await stdout + await stderr;
            return Interpret(p.ExitCode, output);
        }
        catch (OperationCanceledException)
        {
            return new AvResult(AvVerdict.Error, "Analyse interrompue");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return new AvResult(AvVerdict.Error, ex.Message);
        }
    }

    private AvResult Interpret(int exitCode, string output)
    {
        if (_kind == EngineKind.WithSecure)
        {
            var m = Regex.Match(output, @"Harmful items:\s*(\d+)", RegexOptions.IgnoreCase);
            if (m.Success)
                return int.Parse(m.Groups[1].Value) > 0
                    ? new AvResult(AvVerdict.Threat, $"MENACE DÉTECTÉE par {Name}")
                    : new AvResult(AvVerdict.Clean, $"Aucune menace ({Name})");
            return new AvResult(AvVerdict.Error, $"Réponse inattendue de {Name} (code {exitCode})");
        }

        return exitCode switch
        {
            0 => new AvResult(AvVerdict.Clean, $"Aucune menace ({Name})"),
            2 => new AvResult(AvVerdict.Threat, $"MENACE DÉTECTÉE par {Name}"),
            _ => new AvResult(AvVerdict.Error, $"{Name} indisponible ou désactivé (code {exitCode})"),
        };
    }
}
