use anyhow::Result;
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use tempfile::tempdir;

use escpe_core::{
    chsh,
    ledger::{Ledger, LedgerAppendInput},
    signing::SignerDescriptor,
    tag::{CoincidenceCounts, TagScan},
    util,
};

#[test]
fn chsh_passes_for_high_visibility_counts() -> Result<()> {
    fn counts_for_e(e: f64) -> CoincidenceCounts {
        let total: u64 = 2000;
        let p_same = (1.0 + e) / 2.0;
        let same = ((total as f64) * p_same).round() as u64;
        let diff = total.saturating_sub(same);
        CoincidenceCounts {
            pp: same / 2,
            mm: same - (same / 2),
            pm: diff / 2,
            mp: diff - (diff / 2),
        }
    }

    let base = std::f64::consts::FRAC_1_SQRT_2;
    let scan = TagScan {
        scan_id: uuid::Uuid::new_v4(),
        serial: "TEST-123".to_string(),
        scanned_at_utc: util::now_utc_rfc3339(),
        a0b0: counts_for_e(base),
        a0b1: counts_for_e(base),
        a1b0: counts_for_e(base),
        a1b1: counts_for_e(-base),
        metadata: serde_json::Value::Null,
    };
    let res = chsh::compute_chsh(&scan, 2.0)?;
    assert!(res.passed);
    assert!(res.s > 2.5);
    Ok(())
}

#[test]
fn ledger_hash_chain_detects_tamper() -> Result<()> {
    let dir = tempdir()?;
    let db_path = dir.path().join("ledger.db");

    let mut ledger = Ledger::create_new(&db_path, None)?;

    // Create a one-off in-memory signer (no cert embedded).
    let sk = SigningKey::random(&mut OsRng);
    let vk = p256::ecdsa::VerifyingKey::from(&sk);
    let key_id = util::sha256_hex(vk.to_encoded_point(false).as_bytes());
    let signer = SignerDescriptor {
        key_id,
        kind: "test-p256".to_string(),
        cert_der_b64: None,
        cert_sha256_hex: None,
    };

    let payload_json = r#"{"schema":"test","v":1}"#.to_string();
    let payload_hash = util::sha256(payload_json.as_bytes());
    let sig: Signature = sk.sign(&payload_hash);
    let sig_der = sig.to_der().as_bytes().to_vec();

    ledger.append(LedgerAppendInput {
        ts_utc: util::now_utc_rfc3339(),
        serial: "SERIAL-1".to_string(),
        payload_json: payload_json.clone(),
        signature_der: sig_der.clone(),
        signer: signer.clone(),
    })?;

    // Integrity should pass (we skip signature verification).
    ledger.verify_integrity(|_, _, _| Ok(()))?;

    // Tamper with payload_json directly in the DB.
    let conn = rusqlite::Connection::open(&db_path)?;
    conn.execute(
        "UPDATE entries SET payload_json=?1 WHERE seq=1",
        ["{\"schema\":\"test\",\"v\":999}"],
    )?;

    let ledger2 = Ledger::open_existing(&db_path, None)?;
    let err = ledger2.verify_integrity(|_, _, _| Ok(())).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("payload_hash mismatch"));
    Ok(())
}

