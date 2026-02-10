namespace EscpeWinUI.Tests;

/// <summary>
/// Tests for the EscpeNativeException class.
/// </summary>
public class EscpeNativeExceptionTests
{
    [Fact]
    public void Constructor_SetsProperties()
    {
        var ex = new EscpeNativeException(-2, "ledger error");
        Assert.Equal(-2, ex.StatusCode);
        Assert.Equal("ledger error", ex.Message);
    }

    [Fact]
    public void StatusCode_RoundTrips()
    {
        var ex = new EscpeNativeException(-99, "internal");
        Assert.Equal(-99, ex.StatusCode);
        Assert.True(ex is Exception);
    }
}
