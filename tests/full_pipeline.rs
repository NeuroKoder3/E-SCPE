use anyhow::Result;
use tempfile::tempdir;

use escpe_core::{
    chsh,
    ledger::{Ledger, LedgerAppendInput},
    report,
    signing::{self, P256PemSigner, Signer as _},
    tag::{SimulatedTagReader, TagReader as _},
    util,
};

#[test]
fn full_pipeline_smoke() -> Result<()> {
    let dir = tempdir()?;
    let db_path = dir.path().join("ledger.db");
    let keys_dir = dir.path().join("keys");
    let out_dir = dir.path().join("compliance-pack");

    signing::keygen_p256_self_signed(&keys_dir, "E-SCPE Test")?;
    let signer = P256PemSigner::from_key_pem_and_optional_cert_pem(
        &keys_dir.join("signing_key.pem"),
        Some(&keys_dir.join("signing_cert.pem")),
        None,
    )?;

    let mut ledger = Ledger::create_new(&db_path, None)?;
    let mut reader = SimulatedTagReader::default();

    for serial in ["SER-001", "SER-002"] {
        let scan = reader.scan(serial)?;
        let chsh_res = chsh::compute_chsh(&scan, 2.0)?;
        assert!(chsh_res.passed);

        let payload = serde_json::json!({
            "schema": "escpe.payload.v1",
            "ledger_id": ledger.meta().ledger_id.to_string(),
            "scan": scan,
            "chsh": chsh_res,
        });
        let payload_json = serde_json::to_string(&payload)?;
        let payload_hash = util::sha256(payload_json.as_bytes());
        let signature_der = signer.sign(&payload_hash)?;

        ledger.append(LedgerAppendInput {
            ts_utc: util::now_utc_rfc3339(),
            serial: serial.to_string(),
            payload_json,
            signature_der,
            signer: signer.descriptor().clone(),
        })?;
    }

    let entries = ledger.iter_entries()?;
    assert_eq!(entries.len(), 2);

    // Verify hash-chain integrity and signatures fully offline using embedded signer certs.
    ledger.verify_integrity(|e, payload_hash, sig_der| {
        let cert_b64 = e
            .signer
            .cert_der_b64
            .as_deref()
            .ok_or_else(|| escpe_core::error::EscpeError::Ledger(format!(
                "missing signer certificate at seq {}",
                e.seq
            )))?;
        let cert_der = escpe_core::util::b64_decode(cert_b64)?;
        let fp = escpe_core::util::sha256_hex(&cert_der);
        if fp != e.signer.key_id {
            return Err(escpe_core::error::EscpeError::Ledger(format!(
                "signer certificate fingerprint mismatch at seq {}",
                e.seq
            )));
        }
        escpe_core::signing::verify_p256_ecdsa_der_sig_with_cert_der(&cert_der, payload_hash, sig_der)
    })?;

    report::write_compliance_pack(&out_dir, ledger.meta(), &entries)?;
    assert!(out_dir.join("manifest.json").exists());
    assert!(out_dir.join("audit_report.pdf").exists());
    Ok(())
}
