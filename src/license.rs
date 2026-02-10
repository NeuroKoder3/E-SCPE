//! Hardware-bound licensing with Ed25519 signatures.
//!
//! ## Lifecycle
//! 1. **Vendor** generates an Ed25519 keypair: `generate_vendor_keypair()`
//! 2. **Vendor** creates a license bound to a customer's machine fingerprint:
//!    `generate_license()`
//! 3. **Application** checks the license at startup: `check_license()`

use std::path::Path;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{EscpeError, Result, ResultExt as _};
use crate::util;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseFile {
    pub license_id: String,
    pub issued_to: String,
    pub machine_fingerprint: String,
    pub not_before_utc: String,
    pub not_after_utc: String,
    #[serde(default)]
    pub features: Vec<String>,
    /// Base64 Ed25519 signature over the canonical signing message.
    pub signature_b64: String,
}

/// Result of a license validation check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseStatus {
    Valid,
    Expired,
    NotYetValid,
    WrongMachine,
    InvalidSignature,
    Missing,
    MissingFeature(String),
    Malformed(String),
}

impl std::fmt::Display for LicenseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::Expired => write!(f, "expired"),
            Self::NotYetValid => write!(f, "not yet valid"),
            Self::WrongMachine => write!(f, "wrong machine"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::Missing => write!(f, "missing"),
            Self::MissingFeature(feature) => write!(f, "missing feature: {feature}"),
            Self::Malformed(msg) => write!(f, "malformed: {msg}"),
        }
    }
}

/// Default vendor public key (base64) embedded at compile time.
pub const DEFAULT_VENDOR_PUBKEY_B64: &str = env!("ESCPE_VENDOR_PUBKEY_B64");

// ---------------------------------------------------------------------------
// Machine fingerprint
// ---------------------------------------------------------------------------

pub fn machine_fingerprint() -> Result<String> {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let crypto = hklm
            .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
            .ctx_license("open HKLM\\...\\Cryptography")?;
        let guid: String = crypto
            .get_value("MachineGuid")
            .ctx_license("read MachineGuid")?;
        Ok(util::sha256_hex(guid.as_bytes()))
    }

    #[cfg(not(windows))]
    {
        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
        Ok(util::sha256_hex(host.as_bytes()))
    }
}

// ---------------------------------------------------------------------------
// Signing message (deterministic, order-stable)
// ---------------------------------------------------------------------------

pub fn license_signing_message(l: &LicenseFile) -> Vec<u8> {
    let mut msg = String::new();
    msg.push_str("E-SCPE LICENSE v1\n");
    msg.push_str(&format!("license_id={}\n", l.license_id));
    msg.push_str(&format!("issued_to={}\n", l.issued_to));
    msg.push_str(&format!("machine_fingerprint={}\n", l.machine_fingerprint));
    msg.push_str(&format!("not_before_utc={}\n", l.not_before_utc));
    msg.push_str(&format!("not_after_utc={}\n", l.not_after_utc));
    msg.push_str("features=");
    for (i, f) in l.features.iter().enumerate() {
        if i > 0 {
            msg.push(',');
        }
        msg.push_str(f);
    }
    msg.push('\n');
    msg.into_bytes()
}

// ---------------------------------------------------------------------------
// Vendor keypair generation
// ---------------------------------------------------------------------------

/// Generate an Ed25519 keypair for the license vendor.
/// Writes `vendor_private.key` (base64) and `vendor_public.key` (base64)
/// to the specified directory.
pub fn generate_vendor_keypair(out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| EscpeError::License(format!("create dir {}: {e}", out_dir.display())))?;

    let sk = SigningKey::generate(&mut p256::elliptic_curve::rand_core::OsRng);
    let pk = sk.verifying_key();

    let sk_b64 = util::b64_encode(sk.as_bytes());
    let pk_b64 = util::b64_encode(pk.as_bytes());

    let sk_path = out_dir.join("vendor_private.key");
    std::fs::write(&sk_path, &sk_b64)
        .map_err(|e| EscpeError::License(format!("write {}: {e}", sk_path.display())))?;

    let pk_path = out_dir.join("vendor_public.key");
    std::fs::write(&pk_path, &pk_b64)
        .map_err(|e| EscpeError::License(format!("write {}: {e}", pk_path.display())))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// License generation (vendor side)
// ---------------------------------------------------------------------------

/// Create a signed license file.
///
/// `vendor_sk_b64` is the base64-encoded Ed25519 private key.
pub fn generate_license(
    vendor_sk_b64: &str,
    license_id: &str,
    issued_to: &str,
    machine_fp: &str,
    not_before_utc: &str,
    not_after_utc: &str,
    features: &[String],
) -> Result<LicenseFile> {
    let sk_bytes = util::b64_decode(vendor_sk_b64).ctx_license("decode vendor private key")?;
    let sk_arr: [u8; 32] = sk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| EscpeError::License("vendor key must be 32 bytes".into()))?;
    let sk = SigningKey::from_bytes(&sk_arr);

    let mut license = LicenseFile {
        license_id: license_id.to_string(),
        issued_to: issued_to.to_string(),
        machine_fingerprint: machine_fp.to_string(),
        not_before_utc: not_before_utc.to_string(),
        not_after_utc: not_after_utc.to_string(),
        features: features.to_vec(),
        signature_b64: String::new(), // Placeholder; will be set below.
    };

    let msg = license_signing_message(&license);
    let sig = sk.sign(&msg);
    license.signature_b64 = util::b64_encode(&sig.to_bytes());

    Ok(license)
}

// ---------------------------------------------------------------------------
// License verification
// ---------------------------------------------------------------------------

/// Verify a license file against a vendor public key.
pub fn verify_license(license: &LicenseFile, vendor_pubkey_b64: &str) -> Result<()> {
    let expected_fp = machine_fingerprint().ctx_license("compute machine fingerprint")?;
    if license.machine_fingerprint != expected_fp {
        return Err(EscpeError::License("license is not bound to this machine".into()));
    }

    let pubkey_bytes = util::b64_decode(vendor_pubkey_b64).ctx_license("decode vendor pubkey")?;
    let vk = VerifyingKey::from_bytes(
        pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| EscpeError::License("vendor pubkey must be 32 bytes".into()))?,
    )
    .ctx_license("parse vendor ed25519 public key")?;

    let sig_bytes = util::b64_decode(&license.signature_b64).ctx_license("decode license signature")?;
    let sig = Signature::from_slice(&sig_bytes).ctx_license("parse ed25519 signature")?;
    let msg = license_signing_message(license);
    vk.verify_strict(&msg, &sig)
        .ctx_license("license signature verify failed")?;
    Ok(())
}

/// Full license check: load, parse, validate machine, check dates, verify sig.
///
/// Returns [`LicenseStatus`] (never errors for expected conditions like
/// "missing file" or "expired").  Only returns `Err` for truly unexpected
/// failures like filesystem permission errors.
pub fn check_license(license_path: &Path, vendor_pubkey_b64: &str) -> Result<LicenseStatus> {
    if !license_path.exists() {
        return Ok(LicenseStatus::Missing);
    }

    let text = std::fs::read_to_string(license_path)
        .map_err(|e| EscpeError::License(format!("read license {}: {e}", license_path.display())))?;

    let license: LicenseFile = match serde_json::from_str(&text) {
        Ok(l) => l,
        Err(e) => return Ok(LicenseStatus::Malformed(e.to_string())),
    };

    // Machine check.
    let expected_fp = machine_fingerprint()?;
    if license.machine_fingerprint != expected_fp {
        return Ok(LicenseStatus::WrongMachine);
    }

    // Date check (RFC 3339 is lexicographically sortable for UTC).
    let now = util::now_utc_rfc3339();
    if now < license.not_before_utc {
        return Ok(LicenseStatus::NotYetValid);
    }
    if now > license.not_after_utc {
        return Ok(LicenseStatus::Expired);
    }

    // Signature check.
    let pubkey_bytes = match util::b64_decode(vendor_pubkey_b64) {
        Ok(b) => b,
        Err(_) => return Ok(LicenseStatus::InvalidSignature),
    };
    let vk = match VerifyingKey::from_bytes(
        pubkey_bytes
            .as_slice()
            .try_into()
            .unwrap_or(&[0u8; 32]),
    ) {
        Ok(v) => v,
        Err(_) => return Ok(LicenseStatus::InvalidSignature),
    };

    let sig_bytes = match util::b64_decode(&license.signature_b64) {
        Ok(b) => b,
        Err(_) => return Ok(LicenseStatus::InvalidSignature),
    };
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return Ok(LicenseStatus::InvalidSignature),
    };
    let msg = license_signing_message(&license);
    if vk.verify_strict(&msg, &sig).is_err() {
        return Ok(LicenseStatus::InvalidSignature);
    }

    Ok(LicenseStatus::Valid)
}

/// Startup-time license check including feature-flag validation.
pub fn check_license_at_startup(
    license_path: &Path,
    vendor_pubkey_b64: &str,
    required_features: &[&str],
) -> Result<LicenseStatus> {
    if vendor_pubkey_b64.trim().is_empty() {
        return Ok(LicenseStatus::Malformed(
            "vendor public key missing".to_string(),
        ));
    }

    let status = check_license(license_path, vendor_pubkey_b64)?;
    if status != LicenseStatus::Valid || required_features.is_empty() {
        return Ok(status);
    }

    let text = std::fs::read_to_string(license_path).map_err(|e| {
        EscpeError::License(format!("read license {}: {e}", license_path.display()))
    })?;
    let license: LicenseFile = match serde_json::from_str(&text) {
        Ok(l) => l,
        Err(e) => return Ok(LicenseStatus::Malformed(e.to_string())),
    };

    for feature in required_features {
        if !license.features.iter().any(|f| f == feature) {
            return Ok(LicenseStatus::MissingFeature((*feature).to_string()));
        }
    }

    Ok(LicenseStatus::Valid)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn vendor_keypair_round_trip() {
        let dir = tempdir().unwrap();
        generate_vendor_keypair(dir.path()).unwrap();
        let sk_path = dir.path().join("vendor_private.key");
        let pk_path = dir.path().join("vendor_public.key");
        assert!(sk_path.exists());
        assert!(pk_path.exists());

        let sk_b64 = std::fs::read_to_string(&sk_path).unwrap();
        let pk_b64 = std::fs::read_to_string(&pk_path).unwrap();

        // Verify key sizes.
        assert_eq!(util::b64_decode(&sk_b64).unwrap().len(), 32);
        assert_eq!(util::b64_decode(&pk_b64).unwrap().len(), 32);
    }

    #[test]
    fn generate_and_verify_license() {
        let dir = tempdir().unwrap();
        generate_vendor_keypair(dir.path()).unwrap();
        let sk_b64 = std::fs::read_to_string(dir.path().join("vendor_private.key")).unwrap();
        let pk_b64 = std::fs::read_to_string(dir.path().join("vendor_public.key")).unwrap();

        let fp = machine_fingerprint().unwrap();

        let license = generate_license(
            &sk_b64,
            "LIC-001",
            "Test Corp",
            &fp,
            "2020-01-01T00:00:00Z",
            "2099-12-31T23:59:59Z",
            &["full".to_string()],
        )
        .unwrap();

        // Direct verify.
        verify_license(&license, &pk_b64).unwrap();
    }

    #[test]
    fn check_license_missing() {
        let status = check_license(Path::new("nonexistent.json"), "AAAA").unwrap();
        assert_eq!(status, LicenseStatus::Missing);
    }

    #[test]
    fn check_license_valid() {
        let dir = tempdir().unwrap();
        generate_vendor_keypair(dir.path()).unwrap();
        let sk_b64 = std::fs::read_to_string(dir.path().join("vendor_private.key")).unwrap();
        let pk_b64 = std::fs::read_to_string(dir.path().join("vendor_public.key")).unwrap();

        let fp = machine_fingerprint().unwrap();
        let license = generate_license(
            &sk_b64,
            "LIC-002",
            "Test Corp",
            &fp,
            "2020-01-01T00:00:00Z",
            "2099-12-31T23:59:59Z",
            &[],
        )
        .unwrap();

        let license_path = dir.path().join("license.json");
        std::fs::write(&license_path, serde_json::to_string_pretty(&license).unwrap()).unwrap();

        let status = check_license(&license_path, &pk_b64).unwrap();
        assert_eq!(status, LicenseStatus::Valid);
    }

    #[test]
    fn check_license_expired() {
        let dir = tempdir().unwrap();
        generate_vendor_keypair(dir.path()).unwrap();
        let sk_b64 = std::fs::read_to_string(dir.path().join("vendor_private.key")).unwrap();
        let pk_b64 = std::fs::read_to_string(dir.path().join("vendor_public.key")).unwrap();

        let fp = machine_fingerprint().unwrap();
        let license = generate_license(
            &sk_b64,
            "LIC-003",
            "Test Corp",
            &fp,
            "2020-01-01T00:00:00Z",
            "2020-12-31T23:59:59Z", // Already expired.
            &[],
        )
        .unwrap();

        let license_path = dir.path().join("license.json");
        std::fs::write(&license_path, serde_json::to_string_pretty(&license).unwrap()).unwrap();

        let status = check_license(&license_path, &pk_b64).unwrap();
        assert_eq!(status, LicenseStatus::Expired);
    }

    #[test]
    fn check_license_wrong_machine() {
        let dir = tempdir().unwrap();
        generate_vendor_keypair(dir.path()).unwrap();
        let sk_b64 = std::fs::read_to_string(dir.path().join("vendor_private.key")).unwrap();
        let pk_b64 = std::fs::read_to_string(dir.path().join("vendor_public.key")).unwrap();

        let license = generate_license(
            &sk_b64,
            "LIC-004",
            "Test Corp",
            "wrong_fingerprint",
            "2020-01-01T00:00:00Z",
            "2099-12-31T23:59:59Z",
            &[],
        )
        .unwrap();

        let license_path = dir.path().join("license.json");
        std::fs::write(&license_path, serde_json::to_string_pretty(&license).unwrap()).unwrap();

        let status = check_license(&license_path, &pk_b64).unwrap();
        assert_eq!(status, LicenseStatus::WrongMachine);
    }

    #[test]
    fn signing_message_is_deterministic() {
        let l = LicenseFile {
            license_id: "X".into(),
            issued_to: "Y".into(),
            machine_fingerprint: "Z".into(),
            not_before_utc: "A".into(),
            not_after_utc: "B".into(),
            features: vec!["f1".into(), "f2".into()],
            signature_b64: "ignored".into(),
        };
        assert_eq!(license_signing_message(&l), license_signing_message(&l));
    }
}
