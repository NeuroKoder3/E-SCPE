using System.Diagnostics;

namespace EscpeWinUI.Services;

public sealed record EscpeRunResult(int ExitCode, string Stdout, string Stderr, TimeSpan Duration);

public sealed class EscpeCli
{
    public string EscpeExePath { get; }

    public EscpeCli(string escpeExePath)
    {
        EscpeExePath = escpeExePath;
    }

    public static EscpeCli FromAppDirectory()
    {
        var exe = Path.Combine(AppContext.BaseDirectory, "escpe.exe");
        return new EscpeCli(exe);
    }

    public async Task<EscpeRunResult> RunAsync(
        string arguments,
        string? workingDirectory = null,
        IDictionary<string, string?>? env = null,
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(EscpeExePath))
        {
            throw new FileNotFoundException(
                $"escpe.exe not found at '{EscpeExePath}'. Rebuild the WinUI app so the engine is copied to output.",
                EscpeExePath);
        }

        var psi = new ProcessStartInfo
        {
            FileName = EscpeExePath,
            Arguments = arguments,
            WorkingDirectory = workingDirectory ?? AppContext.BaseDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        if (env is not null)
        {
            foreach (var kv in env)
            {
                psi.Environment[kv.Key] = kv.Value;
            }
        }

        var sw = Stopwatch.StartNew();
        using var p = new Process { StartInfo = psi, EnableRaisingEvents = true };

        p.Start();

        var stdoutTask = p.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = p.StandardError.ReadToEndAsync(cancellationToken);

        await p.WaitForExitAsync(cancellationToken);

        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        sw.Stop();
        return new EscpeRunResult(p.ExitCode, stdout, stderr, sw.Elapsed);
    }
}

