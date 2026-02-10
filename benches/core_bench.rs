//! Benchmarks for core E-SCPE operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use escpe_core::{
    chsh,
    tag::{CoincidenceCounts, SimulatedTagReader, TagReader as _, TagScan},
    util,
};

fn bench_chsh_computation(c: &mut Criterion) {
    let base = std::f64::consts::FRAC_1_SQRT_2;
    let counts_for_e = |e: f64| -> CoincidenceCounts {
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
    };
    let scan = TagScan {
        scan_id: uuid::Uuid::new_v4(),
        serial: "BENCH-001".into(),
        scanned_at_utc: util::now_utc_rfc3339(),
        a0b0: counts_for_e(base),
        a0b1: counts_for_e(base),
        a1b0: counts_for_e(base),
        a1b1: counts_for_e(-base),
        metadata: serde_json::Value::Null,
    };

    c.bench_function("compute_chsh", |b| {
        b.iter(|| chsh::compute_chsh(black_box(&scan), black_box(2.0)).unwrap())
    });
}

fn bench_sha256(c: &mut Criterion) {
    let data = vec![0u8; 1024];
    c.bench_function("sha256_1kb", |b| {
        b.iter(|| util::sha256(black_box(&data)))
    });
}

fn bench_simulated_scan(c: &mut Criterion) {
    c.bench_function("simulated_scan", |b| {
        let mut reader = SimulatedTagReader::new(42);
        b.iter(|| reader.scan(black_box("BENCH-SERIAL")).unwrap())
    });
}

fn bench_ledger_append(c: &mut Criterion) {
    use escpe_core::ledger::{Ledger, LedgerAppendInput};
    use escpe_core::signing::SignerDescriptor;
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey, VerifyingKey};

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("bench.db");
    let mut ledger = Ledger::create_new(&db_path, None).unwrap();

    let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let vk = VerifyingKey::from(&sk);
    let key_id = util::sha256_hex(vk.to_encoded_point(false).as_bytes());
    let signer = SignerDescriptor {
        key_id,
        cert_der_b64: None,
        kind: "bench".into(),
    };

    let payload = r#"{"bench":true}"#.to_string();
    let h = util::sha256(payload.as_bytes());
    let sig: Signature = sk.sign(&h);
    let sig_der = sig.to_der().as_bytes().to_vec();

    c.bench_function("ledger_append", |b| {
        b.iter(|| {
            ledger
                .append(LedgerAppendInput {
                    ts_utc: util::now_utc_rfc3339(),
                    serial: "BENCH".into(),
                    payload_json: payload.clone(),
                    signature_der: sig_der.clone(),
                    signer: signer.clone(),
                })
                .unwrap()
        })
    });
}

fn bench_ledger_verify(c: &mut Criterion) {
    use escpe_core::ledger::{Ledger, LedgerAppendInput};
    use escpe_core::signing::SignerDescriptor;
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey, VerifyingKey};

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("bench_verify.db");
    let mut ledger = Ledger::create_new(&db_path, None).unwrap();

    let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let vk = VerifyingKey::from(&sk);
    let key_id = util::sha256_hex(vk.to_encoded_point(false).as_bytes());
    let signer = SignerDescriptor {
        key_id,
        cert_der_b64: None,
        kind: "bench".into(),
    };

    for i in 0..50 {
        let payload = format!(r#"{{"bench":{i}}}"#);
        let h = util::sha256(payload.as_bytes());
        let sig: Signature = sk.sign(&h);
        let sig_der = sig.to_der().as_bytes().to_vec();
        ledger
            .append(LedgerAppendInput {
                ts_utc: util::now_utc_rfc3339(),
                serial: format!("BENCH-{i}"),
                payload_json: payload,
                signature_der: sig_der,
                signer: signer.clone(),
            })
            .unwrap();
    }

    c.bench_function("ledger_verify", |b| {
        b.iter(|| ledger.verify_integrity(|_, _, _| Ok(())).unwrap())
    });
}

criterion_group!(
    benches,
    bench_chsh_computation,
    bench_sha256,
    bench_simulated_scan,
    bench_ledger_append,
    bench_ledger_verify,
);
criterion_main!(benches);
