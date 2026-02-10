use std::ffi::CString;
use std::ptr;

use anyhow::Result;
use tempfile::tempdir;

use escpe_core::{
    error::FfiErrorCode,
    ledger::Ledger,
    license,
    signing,
};

#[test]
fn corrupt_db_rejected() -> Result<()> {
    let dir = tempdir()?;
    let db_path = dir.path().join("corrupt.db");
    std::fs::write(&db_path, b"not-a-sqlite-db")?;

    let err = Ledger::open_existing(&db_path, None).unwrap_err();
    assert!(err.to_string().contains("database"));
    Ok(())
}

#[test]
fn missing_signing_key_rejected() {
    let err = signing::P256PemSigner::from_key_pem_and_optional_cert_pem(
        "missing_key.pem".as_ref(),
        None,
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("read key"));
}

#[test]
fn invalid_csv_header_rejected() -> Result<()> {
    let dir = tempdir()?;
    let db_path = dir.path().join("ledger.db");
    let keys_dir = dir.path().join("keys");
    let csv_path = dir.path().join("bad.csv");
    let out_dir = dir.path().join("out");

    signing::keygen_p256_self_signed(&keys_dir, "E-SCPE Test")?;
    std::fs::write(&csv_path, "bad_header\nvalue\n")?;

    let db_c = CString::new(db_path.to_string_lossy().to_string())?;
    let csv_c = CString::new(csv_path.to_string_lossy().to_string())?;
    let out_c = CString::new(out_dir.to_string_lossy().to_string())?;
    let key_c = CString::new(keys_dir.join("signing_key.pem").to_string_lossy().to_string())?;
    let cert_c = CString::new(keys_dir.join("signing_cert.pem").to_string_lossy().to_string())?;

    let mut out = ptr::null_mut();
    let code = unsafe {
        escpe_core::ffi::escpe_audit(
            db_c.as_ptr(),
            ptr::null(),
            csv_c.as_ptr(),
            out_c.as_ptr(),
            2.0,
            key_c.as_ptr(),
            cert_c.as_ptr(),
            &mut out,
        )
    };

    assert_eq!(code, FfiErrorCode::InvalidArgument as i32);
    Ok(())
}

#[test]
fn expired_license_detected() -> Result<()> {
    let dir = tempdir()?;
    license::generate_vendor_keypair(dir.path())?;
    let sk_b64 = std::fs::read_to_string(dir.path().join("vendor_private.key"))?;
    let pk_b64 = std::fs::read_to_string(dir.path().join("vendor_public.key"))?;

    let fp = license::machine_fingerprint()?;
    let lic = license::generate_license(
        &sk_b64,
        "LIC-EXPIRED",
        "Expired Corp",
        &fp,
        "2000-01-01T00:00:00Z",
        "2000-12-31T23:59:59Z",
        &[],
    )?;

    let lic_path = dir.path().join("license.json");
    std::fs::write(&lic_path, serde_json::to_string_pretty(&lic)?)?;
    let status = license::check_license(&lic_path, &pk_b64)?;
    assert_eq!(status, license::LicenseStatus::Expired);
    Ok(())
}
