namespace EscpeWinUI.Tests;

/// <summary>
/// Unit tests for the EscpeCli wrapper (process invocation).
/// These tests validate the CLI wrapper logic without requiring the actual
/// escpe.exe binary -- they test the construction and error-handling paths.
/// </summary>
public class EscpeCliTests
{
    [Fact]
    public void FromAppDirectory_ReturnsNonNull()
    {
        var cli = EscpeCli.FromAppDirectory();
        Assert.NotNull(cli);
        Assert.EndsWith("escpe.exe", cli.EscpeExePath);
    }

    [Fact]
    public void Constructor_SetsExePath()
    {
        var cli = new EscpeCli(@"C:\fake\path\escpe.exe");
        Assert.Equal(@"C:\fake\path\escpe.exe", cli.EscpeExePath);
    }

    [Fact]
    public async Task RunAsync_ThrowsIfExeNotFound()
    {
        var cli = new EscpeCli(@"C:\nonexistent\escpe.exe");
        await Assert.ThrowsAsync<FileNotFoundException>(
            () => cli.RunAsync("version"));
    }
}
