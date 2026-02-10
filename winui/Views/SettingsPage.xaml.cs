using System.Linq;
using EscpeWinUI.Services;

namespace EscpeWinUI.Views;

public sealed partial class SettingsPage : Page
{
    private readonly AppSettings _settings = AppSettings.Instance;

    public SettingsPage()
    {
        InitializeComponent();
        LoadSettings();
    }

    private void LoadSettings()
    {
        DefaultDbPathBox.Text = _settings.GetValue(SettingsKeys.DbPath) as string ?? string.Empty;
        DefaultKeysDirBox.Text = _settings.GetValue(SettingsKeys.KeysDir) as string ?? string.Empty;
        DefaultOutDirBox.Text = _settings.GetValue(SettingsKeys.OutDir) as string ?? string.Empty;
        LicensePathBox.Text = _settings.GetValue(SettingsKeys.LicensePath) as string ?? string.Empty;

        var log = _settings.GetValue(SettingsKeys.LogLevel) as string ?? "info";
        foreach (var item in LogLevelBox.Items.Cast<ComboBoxItem>())
        {
            if (string.Equals(item.Content?.ToString(), log, StringComparison.OrdinalIgnoreCase))
            {
                LogLevelBox.SelectedItem = item;
                break;
            }
        }

        DbEncryptionToggle.IsOn = _settings.GetValue(SettingsKeys.DbEncryptionEnabled) as bool? ?? false;
    }

    private void OnSaveClicked(object sender, RoutedEventArgs e)
    {
        _settings.SetValue(SettingsKeys.DbPath, DefaultDbPathBox.Text.Trim());
        _settings.SetValue(SettingsKeys.KeysDir, DefaultKeysDirBox.Text.Trim());
        _settings.SetValue(SettingsKeys.OutDir, DefaultOutDirBox.Text.Trim());
        _settings.SetValue(SettingsKeys.LicensePath, LicensePathBox.Text.Trim());
        _settings.SetValue(SettingsKeys.DbEncryptionEnabled, DbEncryptionToggle.IsOn);

        var selected = (LogLevelBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "info";
        _settings.SetValue(SettingsKeys.LogLevel, selected);
    }
}

internal static class SettingsKeys
{
    public const string DbPath = "settings.db_path";
    public const string KeysDir = "settings.keys_dir";
    public const string OutDir = "settings.out_dir";
    public const string LicensePath = "settings.license_path";
    public const string LogLevel = "settings.log_level";
    public const string DbEncryptionEnabled = "settings.db_encryption_enabled";
}
