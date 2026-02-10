using System.Text.Json;

namespace EscpeWinUI.Services;

/// <summary>
/// Abstraction over application settings that works in both packaged and
/// unpackaged WinUI 3 modes.  Attempts <c>Windows.Storage.ApplicationData</c>
/// first, and falls back to a local JSON file if that API is unavailable
/// (e.g. in unit-test or non-Windows contexts).
/// </summary>
public sealed class AppSettings
{
    private static readonly Lazy<AppSettings> _instance = new(() => new AppSettings());
    public static AppSettings Instance => _instance.Value;

    private readonly string _jsonPath;
#pragma warning disable CS0414 // assigned but unused in non-WINDOWS builds
    private readonly bool _useWinStorage;
#pragma warning restore CS0414
    private Dictionary<string, object?> _fileStore;
    private readonly object _lock = new();

#if WINDOWS
    private Windows.Storage.ApplicationDataContainer? _container;
#endif

    private AppSettings()
    {
        _jsonPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "E-SCPE",
            "settings.json");

        _useWinStorage = false;

#if WINDOWS
        try
        {
            _container = Windows.Storage.ApplicationData.Current.LocalSettings;
            _useWinStorage = _container is not null;
        }
        catch
        {
            _container = null;
        }
#endif

        _fileStore = LoadFileStore();
    }

    public object? GetValue(string key)
    {
#if WINDOWS
        if (_useWinStorage && _container is not null)
        {
            return _container.Values.TryGetValue(key, out var val) ? val : null;
        }
#endif

        lock (_lock)
        {
            return _fileStore.TryGetValue(key, out var val) ? val : null;
        }
    }

    public void SetValue(string key, object? value)
    {
#if WINDOWS
        if (_useWinStorage && _container is not null)
        {
            _container.Values[key] = value;
            return;
        }
#endif

        lock (_lock)
        {
            _fileStore[key] = value;
            SaveFileStore();
        }
    }

    private Dictionary<string, object?> LoadFileStore()
    {
        try
        {
            if (File.Exists(_jsonPath))
            {
                var json = File.ReadAllText(_jsonPath);
                return JsonSerializer.Deserialize<Dictionary<string, object?>>(json)
                       ?? new Dictionary<string, object?>();
            }
        }
        catch
        {
            // Ignore corrupt settings file.
        }

        return new Dictionary<string, object?>();
    }

    private void SaveFileStore()
    {
        try
        {
            var dir = Path.GetDirectoryName(_jsonPath);
            if (dir is not null) Directory.CreateDirectory(dir);
            var json = JsonSerializer.Serialize(_fileStore, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_jsonPath, json);
        }
        catch
        {
            // Best effort.
        }
    }
}
