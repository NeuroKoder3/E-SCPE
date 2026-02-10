//! TOML configuration file support.
//!
//! Loads from (in order):
//! 1. `escpe.toml` next to the executable
//! 2. `%LOCALAPPDATA%\E-SCPE\config.toml`
//! 3. Environment variable overrides (e.g. `ESCPE_DB_KEY`)
//!
//! CLI arguments always take precedence over config file values.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Result, ResultExt as _};

// ---------------------------------------------------------------------------
// Config structs (map 1-to-1 with the TOML sections)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EscpeConfig {
    pub paths: PathsConfig,
    pub scan: ScanConfig,
    pub logging: LoggingConfig,
    pub license: LicenseConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PathsConfig {
    pub db: PathBuf,
    pub keys_dir: PathBuf,
    pub compliance_out_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub chsh_threshold: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    /// Path to a JSON-lines structured log file for SIEM integration.
    /// Empty string means no file logging.
    pub json_log_file: String,
    /// Whether to also output JSON to stdout (for container/SIEM pipelines).
    pub json_stdout: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LicenseConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub vendor_pubkey_b64: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    #[serde(default)]
    pub db_key: Option<String>,
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

impl Default for EscpeConfig {
    fn default() -> Self {
        Self {
            paths: PathsConfig::default(),
            scan: ScanConfig::default(),
            logging: LoggingConfig::default(),
            license: LicenseConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            db: PathBuf::from("escpe-ledger.db"),
            keys_dir: PathBuf::from("escpe-keys"),
            compliance_out_dir: PathBuf::from("escpe-compliance-pack"),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            chsh_threshold: 2.0,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            json_log_file: String::new(),
            json_stdout: false,
        }
    }
}

impl Default for LicenseConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("escpe-license.json"),
            vendor_pubkey_b64: None,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self { db_key: None }
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

impl EscpeConfig {
    /// Try to load from a specific path.  Returns `Ok(default)` if the file
    /// does not exist; returns `Err` if the file exists but is malformed.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .ctx_config(&format!("read config file {}", path.display()))?;
        let cfg: EscpeConfig =
            toml::from_str(&text).ctx_config("parse config TOML")?;
        Ok(cfg)
    }

    /// Load config using the standard search order:
    /// 1. Explicit path (if given)
    /// 2. `escpe.toml` next to the running binary
    /// 3. `%LOCALAPPDATA%\E-SCPE\config.toml`
    /// 4. Built-in defaults
    pub fn load(explicit: Option<&Path>) -> Result<Self> {
        if let Some(p) = explicit {
            return Self::load_from(p);
        }

        // Next to executable.
        if let Ok(exe) = std::env::current_exe() {
            let candidate = exe.with_file_name("escpe.toml");
            if candidate.exists() {
                return Self::load_from(&candidate);
            }
        }

        // Platform-standard config directory.
        #[cfg(windows)]
        {
            if let Ok(local) = std::env::var("LOCALAPPDATA") {
                let candidate = PathBuf::from(local).join("E-SCPE").join("config.toml");
                if candidate.exists() {
                    return Self::load_from(&candidate);
                }
            }
        }

        #[cfg(not(windows))]
        {
            if let Some(home) = std::env::var_os("HOME") {
                let candidate = PathBuf::from(home)
                    .join(".config")
                    .join("escpe")
                    .join("config.toml");
                if candidate.exists() {
                    return Self::load_from(&candidate);
                }
            }
        }

        Ok(Self::default())
    }

    /// Apply environment variable overrides.
    pub fn apply_env(&mut self) {
        if let Ok(key) = std::env::var("ESCPE_DB_KEY") {
            self.security.db_key = Some(key);
        }
        if let Ok(db) = std::env::var("ESCPE_DB") {
            self.paths.db = PathBuf::from(db);
        }
        if let Ok(level) = std::env::var("ESCPE_LOG_LEVEL") {
            self.logging.level = level;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sane_values() {
        let cfg = EscpeConfig::default();
        assert_eq!(cfg.scan.chsh_threshold, 2.0);
        assert_eq!(cfg.paths.db, PathBuf::from("escpe-ledger.db"));
        assert_eq!(cfg.logging.level, "info");
    }

    #[test]
    fn load_missing_file_returns_default() {
        let cfg = EscpeConfig::load_from(Path::new("nonexistent_file_xyz.toml")).unwrap();
        assert_eq!(cfg.scan.chsh_threshold, 2.0);
    }

    #[test]
    fn parse_partial_toml() {
        let toml_str = r#"
[scan]
chsh_threshold = 2.5
"#;
        let cfg: EscpeConfig = toml::from_str(toml_str).unwrap();
        assert!((cfg.scan.chsh_threshold - 2.5).abs() < f64::EPSILON);
        // Other sections should be defaults.
        assert_eq!(cfg.paths.db, PathBuf::from("escpe-ledger.db"));
    }
}
