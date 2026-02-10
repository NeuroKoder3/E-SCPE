use anyhow::Result;
use tempfile::tempdir;

use escpe_core::license;

#[test]
fn license_generate_and_verify() -> Result<()> {
    let dir = tempdir()?;
    license::generate_vendor_keypair(dir.path())?;
    let sk_b64 = std::fs::read_to_string(dir.path().join("vendor_private.key"))?;
    let pk_b64 = std::fs::read_to_string(dir.path().join("vendor_public.key"))?;

    let fp = license::machine_fingerprint()?;
    let lic = license::generate_license(
        &sk_b64,
        "LIC-TEST",
        "Integration Test",
        &fp,
        "2020-01-01T00:00:00Z",
        "2099-12-31T23:59:59Z",
        &["full".to_string()],
    )?;

    let lic_path = dir.path().join("license.json");
    std::fs::write(&lic_path, serde_json::to_string_pretty(&lic)?)?;

    let status = license::check_license(&lic_path, &pk_b64)?;
    assert_eq!(status, license::LicenseStatus::Valid);
    Ok(())
}
