using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using EscpeWinUI.Services;
using Microsoft.UI;
using Microsoft.UI.Xaml.Media;

namespace EscpeWinUI.Views;

/// <summary>
/// Clickable test harness for the offline E‑SCPE engine.
/// </summary>
public sealed partial class MainPage : Page
{
    private readonly EscpeCli _cli = EscpeCli.FromAppDirectory();
    private readonly EscpeNative _native = new();
    private readonly bool _useNative;
    private bool _busy;
    private bool _licenseValid;
    private string _baseDir = string.Empty;
    private readonly AppSettings _settings = AppSettings.Instance;
    public ObservableCollection<LogEntry> LogEntries { get; } = new();

    public MainPage()
    {
        InitializeComponent();
        _useNative = File.Exists(Path.Combine(AppContext.BaseDirectory, "escpe_core.dll"));
        InitializeDefaults();
        LogList.ItemsSource = LogEntries;
        Loaded += OnLoaded;
    }

    private void InitializeDefaults()
    {
        _baseDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "E-SCPE");
        Directory.CreateDirectory(_baseDir);

        LedgerDbPathBox.Text = _settings.GetValue(SettingsKeys.DbPath) as string
            ?? Path.Combine(_baseDir, "escpe-ledger.db");
        KeysDirBox.Text = _settings.GetValue(SettingsKeys.KeysDir) as string
            ?? Path.Combine(_baseDir, "keys");
        AuditCsvPathBox.Text = Path.Combine(_baseDir, "serials.csv");
        ComplianceOutDirBox.Text = _settings.GetValue(SettingsKeys.OutDir) as string
            ?? Path.Combine(_baseDir, "compliance-pack");
        SerialBox.Text = "TEST-SERIAL-0001";
        ChshThresholdBox.Text = "2.0";

        AppendLog($"escpe.exe path: {_cli.EscpeExePath}", LogLevel.Info);
        AppendLog(_useNative ? "Using native escpe_core.dll (FFI)." : "Native DLL not found; using escpe.exe fallback.", LogLevel.Info);
        AppendLog("Tip: Click 'Generate Dev Signing Key + Cert' first.", LogLevel.Info);

        var savedDbKey = LoadDbPassword();
        if (!string.IsNullOrEmpty(savedDbKey))
        {
            DbPasswordBox.Password = savedDbKey;
            RememberDbPasswordBox.IsChecked = true;
        }

        _licenseValid = false;
        ApplyUiState();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        await CheckLicenseAsync();
    }

    private async void OnKeygenClicked(object sender, RoutedEventArgs e)
    {
        var keysDir = KeysDirBox.Text.Trim();
        Directory.CreateDirectory(keysDir);
        if (_useNative)
        {
            await RunNativeAsync("keygen", () => _native.Keygen(keysDir, "E-SCPE Dev"));
        }
        else
        {
            await RunEngineAsync($@"keygen --out-dir ""{keysDir}"" --common-name ""E-SCPE Dev""");
        }
    }

    private async void OnInitLedgerClicked(object sender, RoutedEventArgs e)
    {
        var db = LedgerDbPathBox.Text.Trim();
        var dbKey = GetDbKey();
        Directory.CreateDirectory(Path.GetDirectoryName(db)!);
        if (_useNative)
        {
            await RunNativeAsync("init-ledger", () => _native.InitLedger(db, dbKey));
        }
        else
        {
            await RunEngineAsync($@"init-ledger --db ""{db}""", dbKey);
        }
    }

    private async void OnScanClicked(object sender, RoutedEventArgs e)
    {
        var db = LedgerDbPathBox.Text.Trim();
        var serial = SerialBox.Text.Trim();
        var thr = ParseThresholdOrDefault();
        var keysDir = KeysDirBox.Text.Trim();
        var keyPem = Path.Combine(keysDir, "signing_key.pem");
        var certPem = Path.Combine(keysDir, "signing_cert.pem");
        var dbKey = GetDbKey();

        if (_useNative)
        {
            await RunNativeAsync(
                "scan",
                () => _native.Scan(db, dbKey, serial, thr, keyPem, certPem));
        }
        else
        {
            await RunEngineAsync(
                $@"scan --db ""{db}"" --serial ""{serial}"" --chsh-threshold {thr:0.###} --signing-key-pem ""{keyPem}"" --signing-cert-pem ""{certPem}""",
                dbKey);
        }
    }

    private async void OnVerifyClicked(object sender, RoutedEventArgs e)
    {
        var db = LedgerDbPathBox.Text.Trim();
        var dbKey = GetDbKey();
        if (_useNative)
        {
            await RunNativeAsync("verify-ledger", () => _native.VerifyLedger(db, dbKey));
        }
        else
        {
            await RunEngineAsync($@"verify-ledger --db ""{db}""", dbKey);
        }
    }

    private async void OnAuditClicked(object sender, RoutedEventArgs e)
    {
        var db = LedgerDbPathBox.Text.Trim();
        var csv = AuditCsvPathBox.Text.Trim();
        var outDir = ComplianceOutDirBox.Text.Trim();
        var thr = ParseThresholdOrDefault();
        var keysDir = KeysDirBox.Text.Trim();
        var keyPem = Path.Combine(keysDir, "signing_key.pem");
        var certPem = Path.Combine(keysDir, "signing_cert.pem");
        var dbKey = GetDbKey();

        // If the CSV doesn't exist, create a minimal sample.
        if (!File.Exists(csv))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(csv)!);
            await File.WriteAllTextAsync(csv, "serial\r\nTEST-0001\r\nTEST-0002\r\nTEST-0003\r\n");
            AppendLog($"Created sample CSV at: {csv}", LogLevel.Info);
        }

        Directory.CreateDirectory(outDir);

        if (_useNative)
        {
            await RunNativeAsync(
                "audit",
                () => _native.Audit(db, dbKey, csv, outDir, thr, keyPem, certPem));
        }
        else
        {
            await RunEngineAsync(
                $@"audit --db ""{db}"" --csv ""{csv}"" --out-dir ""{outDir}"" --chsh-threshold {thr:0.###} --signing-key-pem ""{keyPem}"" --signing-cert-pem ""{certPem}""",
                dbKey);
        }
    }

    private double ParseThresholdOrDefault()
    {
        if (double.TryParse(ChshThresholdBox.Text?.Trim(), out var thr))
        {
            return thr;
        }

        AppendLog("CHSH threshold is invalid; defaulting to 2.0", LogLevel.Warning);
        ChshThresholdBox.Text = "2.0";
        return 2.0;
    }

    private void OnClearLogClicked(object sender, RoutedEventArgs e)
    {
        LogEntries.Clear();
        StatusText.Text = "Idle";
    }

    private void OnOpenComplianceDirClicked(object sender, RoutedEventArgs e)
    {
        var outDir = ComplianceOutDirBox.Text.Trim();
        try
        {
            if (!Directory.Exists(outDir))
            {
                AppendLog($"Compliance directory does not exist yet: {outDir}", LogLevel.Warning);
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = outDir,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            AppendLog($"Failed to open folder: {ex.Message}", LogLevel.Error);
        }
    }

    private async void OnAboutClicked(object sender, RoutedEventArgs e)
    {
        var version = "unknown";
        var gitHash = "unknown";
        var buildTs = "unknown";

        try
        {
            if (_useNative)
            {
                var json = await Task.Run(() => _native.Version());
                var parsed = JsonSerializer.Deserialize<VersionInfo>(json);
                version = parsed?.Version ?? version;
                gitHash = parsed?.GitHash ?? gitHash;
                buildTs = parsed?.BuildTs ?? buildTs;
            }
            else
            {
                var res = await _cli.RunAsync("version");
                version = res.Stdout.Trim();
            }
        }
        catch (Exception ex)
        {
            AppendLog($"Failed to read version info: {ex.Message}", LogLevel.Warning);
        }

        var licenseStatus = _licenseValid ? "valid" : "invalid";
        var buildDisplay = TryFormatUnix(buildTs);
        var message =
            $"Version: {version}\n" +
            $"Git hash: {gitHash}\n" +
            $"Build time: {buildDisplay}\n" +
            $"License: {licenseStatus}";

        var dialog = new ContentDialog
        {
            Title = "About E-SCPE",
            Content = message,
            CloseButtonText = "OK",
            XamlRoot = Content.XamlRoot
        };
        await dialog.ShowAsync();
    }

    private static string TryFormatUnix(string value)
    {
        if (long.TryParse(value, out var seconds))
        {
            var dt = DateTimeOffset.FromUnixTimeSeconds(seconds).ToLocalTime();
            return dt.ToString("u");
        }
        return value;
    }

    private async Task RunEngineAsync(string args, string? dbKey = null)
    {
        if (_busy) return;
        SetBusy(true, $"Running: {args}");

        AppendLog(string.Empty, LogLevel.Info);
        AppendLog($"> escpe {args}", LogLevel.Info);
        SetAuditProgress(args.Contains("audit", StringComparison.OrdinalIgnoreCase));

        try
        {
            var env = string.IsNullOrWhiteSpace(dbKey)
                ? null
                : new Dictionary<string, string?> { ["ESCPE_DB_KEY"] = dbKey };
            var res = await _cli.RunAsync(args, env: env);
            if (!string.IsNullOrWhiteSpace(res.Stdout))
                AppendLog(res.Stdout.TrimEnd(), LogLevel.Info);
            if (!string.IsNullOrWhiteSpace(res.Stderr))
                AppendLog(res.Stderr.TrimEnd(), LogLevel.Warning);

            var level = res.ExitCode == 0 ? LogLevel.Success : LogLevel.Error;
            AppendLog($"[exit {res.ExitCode}] duration={res.Duration.TotalSeconds:0.00}s", level);
        }
        catch (Exception ex)
        {
            AppendLog($"ERROR: {ex}", LogLevel.Error);
        }
        finally
        {
            SetBusy(false, "Idle");
            SetAuditProgress(false);
        }
    }

    private async Task RunNativeAsync(string action, Func<string> call)
    {
        if (_busy) return;
        SetBusy(true, $"Running: {action}");

        AppendLog(string.Empty, LogLevel.Info);
        AppendLog($"> native {action}", LogLevel.Info);
        SetAuditProgress(action.Contains("audit", StringComparison.OrdinalIgnoreCase));

        try
        {
            var json = await Task.Run(call);
            if (!string.IsNullOrWhiteSpace(json))
            {
                AppendLog(json.TrimEnd(), LogLevel.Info);
            }
            AppendLog("[ok]", LogLevel.Success);
        }
        catch (EscpeNativeException ex)
        {
            AppendLog($"ERROR: {ex.Message} (code {ex.StatusCode})", LogLevel.Error);
        }
        catch (Exception ex)
        {
            AppendLog($"ERROR: {ex}", LogLevel.Error);
        }
        finally
        {
            SetBusy(false, "Idle");
            SetAuditProgress(false);
        }
    }

    private void SetBusy(bool busy, string status)
    {
        _busy = busy;
        StatusText.Text = status;
        ApplyUiState();
    }

    private void ApplyUiState()
    {
        var enabled = !_busy && _licenseValid;

        LedgerDbPathBox.IsEnabled = enabled;
        DbPasswordBox.IsEnabled = enabled;
        RememberDbPasswordBox.IsEnabled = enabled;
        KeysDirBox.IsEnabled = enabled;
        AuditCsvPathBox.IsEnabled = enabled;
        ComplianceOutDirBox.IsEnabled = enabled;
        SerialBox.IsEnabled = enabled;
        ChshThresholdBox.IsEnabled = enabled;

        KeygenBtn.IsEnabled = enabled;
        InitLedgerBtn.IsEnabled = enabled;
        ScanBtn.IsEnabled = enabled;
        VerifyBtn.IsEnabled = enabled;
        AuditBtn.IsEnabled = enabled;
        ClearLogBtn.IsEnabled = !_busy;
        OpenOutDirBtn.IsEnabled = !_busy;
    }

    private async Task CheckLicenseAsync()
    {
        var licensePath = _settings.GetValue(SettingsKeys.LicensePath) as string
            ?? Path.Combine(_baseDir, "license.json");

        var vendorPubkey = await LoadVendorPubkeyAsync();
        if (string.IsNullOrWhiteSpace(vendorPubkey))
        {
            _licenseValid = false;
            StatusText.Text = "License: vendor key missing";
            await ShowLicenseDialogAsync("Vendor public key missing. Provide vendor_public.key next to the app.");
            ApplyUiState();
            return;
        }

        try
        {
            if (_useNative)
            {
                var json = await Task.Run(() => _native.CheckLicense(licensePath, vendorPubkey));
                var parsed = JsonSerializer.Deserialize<LicenseCheckResult>(json);
                _licenseValid = parsed?.Valid ?? false;
                var status = parsed?.Status ?? "unknown";
                StatusText.Text = $"License: {status}";
                if (!_licenseValid)
                {
                    await ShowLicenseDialogAsync(
                        $"License invalid or missing ({status}). Place license.json in {_baseDir}.");
                }
            }
            else
            {
                // Graceful CLI fallback: use escpe.exe to check license.
                var res = await _cli.RunAsync(
                    $@"license-check --license ""{licensePath}"" --vendor-pubkey-b64 ""{vendorPubkey}""");
                _licenseValid = res.ExitCode == 0;
                StatusText.Text = _licenseValid ? "License: valid (CLI)" : "License: invalid (CLI)";
                if (!_licenseValid)
                {
                    AppendLog($"License check via CLI: {res.Stdout.Trim()} {res.Stderr.Trim()}", LogLevel.Warning);
                    await ShowLicenseDialogAsync(
                        $"License invalid or missing. Place license.json in {_baseDir}.\n(Using CLI fallback -- native DLL not found.)");
                }
                else
                {
                    AppendLog("Using escpe.exe fallback (escpe_core.dll not found).", LogLevel.Warning);
                }
            }
        }
        catch (EscpeNativeException ex)
        {
            _licenseValid = false;
            StatusText.Text = "License: error";
            await ShowLicenseDialogAsync($"License check failed: {ex.Message}");
        }
        catch (Exception ex)
        {
            // If CLI is also missing, allow degraded startup with a warning.
            _licenseValid = false;
            StatusText.Text = "License: error";
            AppendLog($"License check error: {ex.Message}", LogLevel.Error);
            await ShowLicenseDialogAsync(
                $"Could not verify license. Ensure escpe_core.dll or escpe.exe is next to the app.\n{ex.Message}");
        }
        finally
        {
            ApplyUiState();
        }
    }

    private string? GetDbKey()
    {
        var key = DbPasswordBox.Password?.Trim();
        return string.IsNullOrWhiteSpace(key) ? null : key;
    }

    private void OnDbPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (RememberDbPasswordBox.IsChecked == true)
        {
            SaveDbPassword(DbPasswordBox.Password);
        }
    }

    private void OnRememberDbPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (RememberDbPasswordBox.IsChecked == true)
        {
            SaveDbPassword(DbPasswordBox.Password);
        }
        else
        {
            DeleteDbPassword();
        }
    }

    private string LoadDbPassword()
    {
        var path = DbKeyPath();
        if (!File.Exists(path))
        {
            return string.Empty;
        }

        try
        {
            var encrypted = File.ReadAllBytes(path);
            var raw = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(raw);
        }
        catch
        {
            return string.Empty;
        }
    }

    private void SaveDbPassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return;
        }

        Directory.CreateDirectory(_baseDir);
        var raw = Encoding.UTF8.GetBytes(password);
        var encrypted = ProtectedData.Protect(raw, null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(DbKeyPath(), encrypted);
    }

    private void DeleteDbPassword()
    {
        var path = DbKeyPath();
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private string DbKeyPath() => Path.Combine(_baseDir, "db_key.dat");

    private static async Task<string> LoadVendorPubkeyAsync()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "vendor_public.key");
        if (File.Exists(path))
        {
            return (await File.ReadAllTextAsync(path)).Trim();
        }
        return string.Empty;
    }

    private async Task ShowLicenseDialogAsync(string message)
    {
        var dialog = new ContentDialog
        {
            Title = "Activation Required",
            Content = message,
            CloseButtonText = "OK",
            XamlRoot = Content.XamlRoot
        };
        await dialog.ShowAsync();
    }

    private sealed class LicenseCheckResult
    {
        [JsonPropertyName("status")]
        public string? Status { get; init; }
        [JsonPropertyName("valid")]
        public bool Valid { get; init; }
    }

    private sealed class VersionInfo
    {
        [JsonPropertyName("version")]
        public string? Version { get; init; }
        [JsonPropertyName("git_hash")]
        public string? GitHash { get; init; }
        [JsonPropertyName("build_ts")]
        public string? BuildTs { get; init; }
    }

    private void AppendLog(string text, LogLevel level)
    {
        if (DispatcherQueue.TryEnqueue(() =>
            {
                LogEntries.Add(new LogEntry(text, level));
            }))
        {
            // ok
        }
    }

    private void SetAuditProgress(bool show)
    {
        AuditProgressBar.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
    }
}

public enum LogLevel
{
    Info,
    Success,
    Warning,
    Error
}

public sealed class LogEntry
{
    public string Message { get; }
    public Brush Brush { get; }

    public LogEntry(string message, LogLevel level)
    {
        Message = message;
        Brush = level switch
        {
            LogLevel.Success => new SolidColorBrush(Colors.LightGreen),
            LogLevel.Warning => new SolidColorBrush(Colors.Gold),
            LogLevel.Error => new SolidColorBrush(Colors.IndianRed),
            _ => new SolidColorBrush(Colors.White),
        };
    }
}
