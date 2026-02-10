//! Cryptographic helpers, encoding utilities, and input validation.

use base64::Engine as _;
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::error::{EscpeError, Result};

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

pub fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| EscpeError::Other(format!("invalid base64: {e}")))
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

pub fn now_utc_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Regex for serial numbers: starts with alphanumeric, then up to 127 more
/// alphanumeric / hyphen / dot / underscore characters.
static SERIAL_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9\-_.]{0,127}$").unwrap()
});

/// Validate a serial number format.
pub fn validate_serial(serial: &str) -> Result<()> {
    if serial.is_empty() {
        return Err(EscpeError::Validation(
            "serial number must not be empty".into(),
        ));
    }
    if !SERIAL_RE.is_match(serial) {
        return Err(EscpeError::Validation(format!(
            "invalid serial '{}': 1-128 chars, alphanumeric/hyphen/dot/underscore",
            serial
        )));
    }
    Ok(())
}

/// Validate that a CHSH threshold is in the physically meaningful range.
pub fn validate_chsh_threshold(threshold: f64) -> Result<()> {
    if !threshold.is_finite() || !(0.0..=4.0).contains(&threshold) {
        return Err(EscpeError::Validation(format!(
            "CHSH threshold {threshold} out of range [0, 4]"
        )));
    }
    Ok(())
}

/// Validate that a path is not empty and does not contain null bytes.
pub fn validate_path(p: &std::path::Path, label: &str) -> Result<()> {
    let s = p.to_string_lossy();
    if s.is_empty() {
        return Err(EscpeError::Validation(format!("{label} path is empty")));
    }
    if s.contains('\0') {
        return Err(EscpeError::Validation(format!(
            "{label} path contains null byte"
        )));
    }
    Ok(())
}

/// Canonicalize a path if it exists, otherwise return it unchanged.
pub fn canonicalize_if_exists(p: &Path, label: &str) -> Result<PathBuf> {
    validate_path(p, label)?;
    if p.exists() {
        std::fs::canonicalize(p).map_err(|e| {
            EscpeError::Validation(format!("{label} path invalid: {e}"))
        })
    } else {
        Ok(p.to_path_buf())
    }
}

/// Maximum number of rows allowed in CSV inputs.
pub const MAX_CSV_ROWS: usize = 10_000;

// ---------------------------------------------------------------------------
// Version constants (set by build.rs)
// ---------------------------------------------------------------------------

pub const GIT_HASH: &str = env!("ESCPE_GIT_HASH");
pub const BUILD_TS: &str = env!("ESCPE_BUILD_TS");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One-line version string for display.
pub fn version_string() -> String {
    format!("E-SCPE v{VERSION} (git {GIT_HASH}, built {BUILD_TS})")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // SHA-256 of empty string
        let digest = sha256(b"");
        assert_eq!(
            hex::encode(digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hello() {
        let digest = sha256(b"hello");
        assert_eq!(
            hex::encode(digest),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn b64_round_trip() {
        let data = b"E-SCPE test data";
        let encoded = b64_encode(data);
        let decoded = b64_decode(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn b64_decode_invalid() {
        assert!(b64_decode("not!!valid!!base64").is_err());
    }

    #[test]
    fn valid_serials() {
        assert!(validate_serial("AERO-ALLOY-000042").is_ok());
        assert!(validate_serial("TEST_123.v2").is_ok());
        assert!(validate_serial("A").is_ok());
    }

    #[test]
    fn invalid_serials() {
        assert!(validate_serial("").is_err());
        assert!(validate_serial("-leading-hyphen").is_err());
        assert!(validate_serial("has space").is_err());
        let long = "A".repeat(200);
        assert!(validate_serial(&long).is_err());
    }

    #[test]
    fn valid_thresholds() {
        assert!(validate_chsh_threshold(0.0).is_ok());
        assert!(validate_chsh_threshold(2.0).is_ok());
        assert!(validate_chsh_threshold(4.0).is_ok());
    }

    #[test]
    fn invalid_thresholds() {
        assert!(validate_chsh_threshold(-1.0).is_err());
        assert!(validate_chsh_threshold(5.0).is_err());
        assert!(validate_chsh_threshold(f64::NAN).is_err());
        assert!(validate_chsh_threshold(f64::INFINITY).is_err());
    }

    #[test]
    fn version_string_non_empty() {
        let v = version_string();
        assert!(v.contains("E-SCPE"));
    }
}
