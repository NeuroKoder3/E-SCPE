namespace EscpeWinUI.Tests;

/// <summary>
/// Tests for the AppSettings file-based fallback.
/// </summary>
public class AppSettingsTests
{
    [Fact]
    public void Singleton_ReturnsSameInstance()
    {
        var a = AppSettings.Instance;
        var b = AppSettings.Instance;
        Assert.Same(a, b);
    }

    [Fact]
    public void GetValue_ReturnsNullForMissing()
    {
        var settings = AppSettings.Instance;
        var result = settings.GetValue("nonexistent_key_" + Guid.NewGuid());
        Assert.Null(result);
    }
}
