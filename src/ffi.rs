//! C-ABI FFI exports for the E-SCPE DLL (`escpe_core.dll`).
//!
//! Every function returns an `i32` status code (0 = success, negative = error).
//! Output is returned via a `*mut *mut c_char` parameter; the caller must free
//! the string with [`escpe_free_string`].  Detailed error messages are available
//! via [`escpe_last_error`].
//!
//! # Safety
//! All functions that accept raw pointers are `unsafe`.  Callers must ensure
//! that string pointers are valid, null-terminated UTF-8.

#![allow(unsafe_code)]

use std::cell::RefCell;
use std::ffi::{c_char, c_double, c_int, CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{EscpeError, FfiErrorCode};

// ---------------------------------------------------------------------------
// Global rate limiter (token bucket)
// ---------------------------------------------------------------------------

/// Maximum calls per second across all FFI functions.
const FFI_RATE_LIMIT_PER_SEC: u64 = 100;
/// Burst capacity (allows short bursts above the sustained rate).
const FFI_RATE_LIMIT_BURST: u64 = 200;

static TOKENS: AtomicU64 = AtomicU64::new(FFI_RATE_LIMIT_BURST);
static LAST_REFILL_MS: AtomicU64 = AtomicU64::new(0);

fn check_rate_limit() -> bool {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Refill tokens based on elapsed time.
    let last = LAST_REFILL_MS.load(Ordering::Relaxed);
    let elapsed_ms = now_ms.saturating_sub(last);
    if elapsed_ms > 0 {
        let refill = (elapsed_ms * FFI_RATE_LIMIT_PER_SEC) / 1000;
        if refill > 0 {
            LAST_REFILL_MS.store(now_ms, Ordering::Relaxed);
            let current = TOKENS.load(Ordering::Relaxed);
            let new_val = current.saturating_add(refill).min(FFI_RATE_LIMIT_BURST);
            TOKENS.store(new_val, Ordering::Relaxed);
        }
    }

    // Try to consume one token.
    loop {
        let current = TOKENS.load(Ordering::Relaxed);
        if current == 0 {
            return false;
        }
        if TOKENS
            .compare_exchange_weak(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

// ---------------------------------------------------------------------------
// Thread-local last error
// ---------------------------------------------------------------------------

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

fn set_last_error(msg: &str) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() =
            CString::new(msg).unwrap_or_else(|_| CString::new("unknown error (null byte in message)").unwrap());
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

unsafe fn ptr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

fn string_to_ptr(s: String) -> *mut c_char {
    CString::new(s)
        .unwrap_or_else(|_| CString::new("").unwrap())
        .into_raw()
}

fn write_out(out: *mut *mut c_char, val: String) {
    if !out.is_null() {
        unsafe { *out = string_to_ptr(val) };
    }
}

/// Run `body`, catch panics, enforce rate limit, map errors to FFI codes.
fn ffi_run(
    out: *mut *mut c_char,
    body: impl FnOnce() -> crate::error::Result<String> + std::panic::UnwindSafe,
) -> c_int {
    if !check_rate_limit() {
        set_last_error("rate limit exceeded (too many FFI calls per second)");
        return FfiErrorCode::InternalError as c_int;
    }

    match std::panic::catch_unwind(body) {
        Ok(Ok(json)) => {
            write_out(out, json);
            0
        }
        Ok(Err(e)) => {
            let code = FfiErrorCode::from(&e) as c_int;
            set_last_error(&e.to_string());
            code
        }
        Err(_) => {
            set_last_error("internal panic");
            FfiErrorCode::InternalError as c_int
        }
    }
}

// ---------------------------------------------------------------------------
// Public FFI functions
// ---------------------------------------------------------------------------

/// Retrieve the last error message.  Returns the number of bytes written
/// (excluding the null terminator).  If `buf` is null or `buf_len` is 0,
/// returns the required buffer size.
#[no_mangle]
pub unsafe extern "C" fn escpe_last_error(buf: *mut u8, buf_len: usize) -> c_int {
    LAST_ERROR.with(|e| {
        let msg = e.borrow();
        let bytes = msg.as_bytes_with_nul();
        if buf.is_null() || buf_len == 0 {
            return bytes.len() as c_int;
        }
        let copy_len = bytes.len().min(buf_len);
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, copy_len) };
        if copy_len < bytes.len() {
            // Ensure null termination.
            unsafe { *buf.add(copy_len - 1) = 0 };
        }
        copy_len as c_int
    })
}

/// Free a string previously returned by an `escpe_*` function.
#[no_mangle]
pub unsafe extern "C" fn escpe_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

/// Return the library version as a JSON string.
#[no_mangle]
pub unsafe extern "C" fn escpe_version(out_json: *mut *mut c_char) -> c_int {
    ffi_run(out_json, || {
        let info = serde_json::json!({
            "version": crate::util::VERSION,
            "git_hash": crate::util::GIT_HASH,
            "build_ts": crate::util::BUILD_TS,
        });
        Ok(info.to_string())
    })
}

/// Create a new ledger database.
#[no_mangle]
pub unsafe extern "C" fn escpe_init_ledger(
    db_path: *const c_char,
    db_key: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    ffi_run(out_json, || {
        let db = unsafe { ptr_to_str(db_path) }
            .ok_or_else(|| EscpeError::Validation("db_path is null".into()))?;
        let key = unsafe { ptr_to_str(db_key) };
        let secret = key.map(|k| secrecy::SecretString::new(k.to_string().into()));
        let ledger =
            crate::ledger::Ledger::create_new(std::path::Path::new(db), secret.as_ref())?;
        let info = serde_json::json!({
            "ledger_id": ledger.meta().ledger_id.to_string(),
            "created_at_utc": ledger.meta().created_at_utc,
        });
        Ok(info.to_string())
    })
}

/// Scan a tag, verify CHSH, sign, and append to ledger.
#[no_mangle]
pub unsafe extern "C" fn escpe_scan(
    db_path: *const c_char,
    db_key: *const c_char,
    serial: *const c_char,
    chsh_threshold: c_double,
    signing_key_pem: *const c_char,
    signing_cert_pem: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    ffi_run(out_json, || {
        let db = unsafe { ptr_to_str(db_path) }
            .ok_or_else(|| EscpeError::Validation("db_path is null".into()))?;
        let key = unsafe { ptr_to_str(db_key) };
        let ser = unsafe { ptr_to_str(serial) }
            .ok_or_else(|| EscpeError::Validation("serial is null".into()))?;
        let key_pem = unsafe { ptr_to_str(signing_key_pem) }
            .ok_or_else(|| EscpeError::Validation("signing_key_pem is null".into()))?;
        let cert_pem = unsafe { ptr_to_str(signing_cert_pem) };

        crate::util::validate_path(std::path::Path::new(db), "db")?;
        crate::util::validate_path(std::path::Path::new(key_pem), "signing key")?;

        let key_pem =
            crate::util::canonicalize_if_exists(std::path::Path::new(key_pem), "signing key")?;
        let cert_pem = cert_pem
            .map(|p| {
                let path = std::path::Path::new(p);
                // Canonicalize without using utility helpers that may log the raw, tainted path.
                std::fs::canonicalize(path)
                    .map(|pb| pb.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| p.to_string())
            });

        let secret = key.map(|k| secrecy::SecretString::new(k.to_string().into()));
        let db_path = std::path::Path::new(db);

        let mut ledger = crate::ledger::Ledger::open_existing(db_path, secret.as_ref())
            .or_else(|_| crate::ledger::Ledger::create_new(db_path, secret.as_ref()))?;

        let signer = crate::signing::P256PemSigner::from_key_pem_and_optional_cert_pem(
            &key_pem,
            cert_pem.as_deref(),
            None,
        )?;

        let mut reader = crate::tag::SimulatedTagReader::default();
        let scan = crate::tag::TagReader::scan(&mut reader, ser)?;
        let chsh_res = crate::chsh::compute_chsh(&scan, chsh_threshold)?;

        if !chsh_res.passed {
            return Err(EscpeError::Chsh(format!(
                "tag rejected (S={:.4} <= threshold {:.4})",
                chsh_res.s, chsh_threshold
            )));
        }

        let payload = serde_json::json!({
            "schema": "escpe.payload.v1",
            "ledger_id": ledger.meta().ledger_id.to_string(),
            "scan": scan,
            "chsh": chsh_res,
        });
        let payload_json = serde_json::to_string(&payload)
            .map_err(|e| EscpeError::Other(format!("serialize payload: {e}")))?;
        let payload_hash = crate::util::sha256(payload_json.as_bytes());
        let signature_der = crate::signing::Signer::sign(&signer, &payload_hash)?;

        let entry = ledger.append(crate::ledger::LedgerAppendInput {
            ts_utc: crate::util::now_utc_rfc3339(),
            serial: ser.to_string(),
            payload_json,
            signature_der,
            signer: crate::signing::Signer::descriptor(&signer).clone(),
        })?;

        let info = serde_json::json!({
            "seq": entry.seq,
            "entry_hash": entry.entry_hash_hex,
            "chsh_s": chsh_res.s,
            "passed": chsh_res.passed,
        });
        Ok(info.to_string())
    })
}

/// Verify ledger hash-chain integrity.
#[no_mangle]
pub unsafe extern "C" fn escpe_verify_ledger(
    db_path: *const c_char,
    db_key: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    ffi_run(out_json, || {
        let db = unsafe { ptr_to_str(db_path) }
            .ok_or_else(|| EscpeError::Validation("db_path is null".into()))?;
        let key = unsafe { ptr_to_str(db_key) };
        let secret = key.map(|k| secrecy::SecretString::new(k.to_string().into()));

        let ledger =
            crate::ledger::Ledger::open_existing(std::path::Path::new(db), secret.as_ref())?;
        let entry_count = ledger.iter_entries()?.len();

        ledger.verify_integrity(|entry, payload_hash, sig_der| {
            if let Some(cert_b64) = &entry.signer.cert_der_b64 {
                let cert_der = crate::util::b64_decode(cert_b64)?;
                crate::signing::verify_p256_ecdsa_der_sig_with_cert_der(
                    &cert_der,
                    payload_hash,
                    sig_der,
                )?;
            }
            Ok(())
        })?;

        let info = serde_json::json!({
            "status": "ok",
            "ledger_id": ledger.meta().ledger_id.to_string(),
            "entry_count": entry_count,
        });
        Ok(info.to_string())
    })
}

/// Generate a P-256 signing key and self-signed X.509 certificate.
#[no_mangle]
pub unsafe extern "C" fn escpe_keygen(
    out_dir: *const c_char,
    common_name: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    ffi_run(out_json, || {
        let dir = unsafe { ptr_to_str(out_dir) }
            .ok_or_else(|| EscpeError::Validation("out_dir is null".into()))?;
        let cn = unsafe { ptr_to_str(common_name) }.unwrap_or("E-SCPE Dev Signing Cert");

        crate::signing::keygen_p256_self_signed(std::path::Path::new(dir), cn)?;

        let info = serde_json::json!({
            "status": "ok",
            "out_dir": dir,
            "key_file": "signing_key.pem",
            "cert_file": "signing_cert.pem",
        });
        Ok(info.to_string())
    })
}

/// Return the machine fingerprint.
#[no_mangle]
pub unsafe extern "C" fn escpe_machine_fingerprint(
    out_json: *mut *mut c_char,
) -> c_int {
    ffi_run(out_json, || {
        let fp = crate::license::machine_fingerprint()?;
        let info = serde_json::json!({ "fingerprint": fp });
        Ok(info.to_string())
    })
}

/// Check license status.
#[no_mangle]
pub unsafe extern "C" fn escpe_check_license(
    license_path: *const c_char,
    vendor_pubkey_b64: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    ffi_run(out_json, || {
        let path = unsafe { ptr_to_str(license_path) }
            .ok_or_else(|| EscpeError::Validation("license_path is null".into()))?;
        let pk = unsafe { ptr_to_str(vendor_pubkey_b64) }
            .ok_or_else(|| EscpeError::Validation("vendor_pubkey_b64 is null".into()))?;

        let status = crate::license::check_license(std::path::Path::new(path), pk)?;
        let info = serde_json::json!({
            "status": status.to_string(),
            "valid": status == crate::license::LicenseStatus::Valid,
        });
        Ok(info.to_string())
    })
}

/// Batch audit: read CSV, scan each serial, append to ledger, generate compliance pack.
#[no_mangle]
pub unsafe extern "C" fn escpe_audit(
    db_path: *const c_char,
    db_key: *const c_char,
    csv_path: *const c_char,
    out_dir: *const c_char,
    chsh_threshold: c_double,
    signing_key_pem: *const c_char,
    signing_cert_pem: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    ffi_run(out_json, || {
        let db = unsafe { ptr_to_str(db_path) }
            .ok_or_else(|| EscpeError::Validation("db_path is null".into()))?;
        let key = unsafe { ptr_to_str(db_key) };
        let csv = unsafe { ptr_to_str(csv_path) }
            .ok_or_else(|| EscpeError::Validation("csv_path is null".into()))?;
        let out = unsafe { ptr_to_str(out_dir) }
            .ok_or_else(|| EscpeError::Validation("out_dir is null".into()))?;
        let key_pem = unsafe { ptr_to_str(signing_key_pem) }
            .ok_or_else(|| EscpeError::Validation("signing_key_pem is null".into()))?;
        let cert_pem = unsafe { ptr_to_str(signing_cert_pem) };

        let secret = key.map(|k| secrecy::SecretString::new(k.to_string().into()));
        let db_path = std::path::Path::new(db);

        let mut ledger = crate::ledger::Ledger::open_existing(db_path, secret.as_ref())
            .or_else(|_| crate::ledger::Ledger::create_new(db_path, secret.as_ref()))?;

        let signer = crate::signing::P256PemSigner::from_key_pem_and_optional_cert_pem(
            std::path::Path::new(key_pem),
            cert_pem.map(std::path::Path::new),
            None,
        )?;

        let mut reader = crate::tag::SimulatedTagReader::default();

        #[derive(serde::Deserialize)]
        struct CsvRow {
            serial: String,
        }

        let mut rdr = csv::Reader::from_path(&csv)
            .map_err(|e| EscpeError::Report(format!("open csv {csv}: {e}")))?;
        let headers = rdr
            .headers()
            .map_err(|e| EscpeError::Report(format!("read csv headers: {e}")))?
            .clone();
        if !headers.iter().any(|h| h.eq_ignore_ascii_case("serial")) {
            return Err(EscpeError::Validation(
                "csv missing required header 'serial'".into(),
            ));
        }

        let mut scanned = 0u64;
        let mut rejected = 0u64;
        let mut row_count = 0usize;

        for rec in rdr.deserialize::<CsvRow>() {
            row_count += 1;
            if row_count > crate::util::MAX_CSV_ROWS {
                return Err(EscpeError::Validation(format!(
                    "csv exceeds maximum row limit of {}",
                    crate::util::MAX_CSV_ROWS
                )));
            }
            let row = rec.map_err(|e| EscpeError::Report(format!("parse csv row: {e}")))?;
            let scan = crate::tag::TagReader::scan(&mut reader, &row.serial)?;
            let chsh_res = crate::chsh::compute_chsh(&scan, chsh_threshold)?;
            if !chsh_res.passed {
                rejected += 1;
                continue;
            }

            let payload = serde_json::json!({
                "schema": "escpe.payload.v1",
                "ledger_id": ledger.meta().ledger_id.to_string(),
                "scan": scan,
                "chsh": chsh_res,
            });
            let payload_json = serde_json::to_string(&payload)
                .map_err(|e| EscpeError::Other(format!("serialize: {e}")))?;
            let payload_hash = crate::util::sha256(payload_json.as_bytes());
            let signature_der = crate::signing::Signer::sign(&signer, &payload_hash)?;

            let _ = ledger.append(crate::ledger::LedgerAppendInput {
                ts_utc: crate::util::now_utc_rfc3339(),
                serial: row.serial,
                payload_json,
                signature_der,
                signer: crate::signing::Signer::descriptor(&signer).clone(),
            })?;
            scanned += 1;
        }

        let entries = ledger.iter_entries()?;
        let out_path = std::path::Path::new(out);
        crate::report::write_compliance_pack(out_path, ledger.meta(), &entries)?;

        let info = serde_json::json!({
            "status": "ok",
            "scanned": scanned,
            "rejected": rejected,
            "total_entries": entries.len(),
            "out_dir": out,
        });
        Ok(info.to_string())
    })
}

/// Export ledger to a JSON backup file.
#[no_mangle]
pub unsafe extern "C" fn escpe_export_ledger(
    db_path: *const c_char,
    db_key: *const c_char,
    export_path: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    ffi_run(out_json, || {
        let db = unsafe { ptr_to_str(db_path) }
            .ok_or_else(|| EscpeError::Validation("db_path is null".into()))?;
        let key = unsafe { ptr_to_str(db_key) };
        let out = unsafe { ptr_to_str(export_path) }
            .ok_or_else(|| EscpeError::Validation("export_path is null".into()))?;

        let secret = key.map(|k| secrecy::SecretString::new(k.to_string().into()));
        let ledger =
            crate::ledger::Ledger::open_existing(std::path::Path::new(db), secret.as_ref())?;
        crate::ledger::export_ledger_json(&ledger, std::path::Path::new(out))?;

        let info = serde_json::json!({ "status": "ok", "export_path": out });
        Ok(info.to_string())
    })
}

/// Import ledger from a JSON backup file into a new database.
#[no_mangle]
pub unsafe extern "C" fn escpe_import_ledger(
    json_path: *const c_char,
    db_path: *const c_char,
    db_key: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    ffi_run(out_json, || {
        let src = unsafe { ptr_to_str(json_path) }
            .ok_or_else(|| EscpeError::Validation("json_path is null".into()))?;
        let db = unsafe { ptr_to_str(db_path) }
            .ok_or_else(|| EscpeError::Validation("db_path is null".into()))?;
        let key = unsafe { ptr_to_str(db_key) };

        let secret = key.map(|k| secrecy::SecretString::new(k.to_string().into()));
        let ledger = crate::ledger::import_ledger_json(
            std::path::Path::new(src),
            std::path::Path::new(db),
            secret.as_ref(),
        )?;

        let info = serde_json::json!({
            "status": "ok",
            "ledger_id": ledger.meta().ledger_id.to_string(),
            "entry_count": ledger.iter_entries()?.len(),
        });
        Ok(info.to_string())
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use tempfile::tempdir;

    unsafe fn take_string(ptr: *mut c_char) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let s = unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .unwrap_or_default()
            .to_string();
        unsafe { escpe_free_string(ptr) };
        s
    }

    #[test]
    fn version_returns_json() {
        let mut out: *mut c_char = ptr::null_mut();
        let code = unsafe { escpe_version(&mut out) };
        assert_eq!(code, 0);
        let json = unsafe { take_string(out) };
        assert!(json.contains("version"));
    }

    #[test]
    fn init_ledger_rejects_null_path() {
        let mut out: *mut c_char = ptr::null_mut();
        let code = unsafe { escpe_init_ledger(ptr::null(), ptr::null(), &mut out) };
        assert_eq!(code, FfiErrorCode::InvalidArgument as c_int);
    }

    #[test]
    fn machine_fingerprint_returns_value() {
        let mut out: *mut c_char = ptr::null_mut();
        let code = unsafe { escpe_machine_fingerprint(&mut out) };
        assert_eq!(code, 0);
        let json = unsafe { take_string(out) };
        assert!(json.contains("fingerprint"));
    }

    #[test]
    fn init_ledger_creates_db() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("ffi_test.db");
        let db_c = CString::new(db_path.to_string_lossy().to_string()).unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        let code = unsafe { escpe_init_ledger(db_c.as_ptr(), ptr::null(), &mut out) };
        assert_eq!(code, 0);
        let _json = unsafe { take_string(out) };
        assert!(db_path.exists());
    }
}
