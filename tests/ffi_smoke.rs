use std::ffi::CString;
use std::ptr;

use anyhow::Result;
use tempfile::tempdir;

use escpe_core::ffi::{
    escpe_free_string, escpe_init_ledger, escpe_machine_fingerprint, escpe_version,
};

unsafe fn take_string(ptr: *mut std::os::raw::c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let s = unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_str()
        .unwrap_or_default()
        .to_string();
    unsafe { escpe_free_string(ptr) };
    s
}

#[test]
fn ffi_version_and_init() -> Result<()> {
    let mut out = ptr::null_mut();
    let code = unsafe { escpe_version(&mut out) };
    assert_eq!(code, 0);
    let json = unsafe { take_string(out) };
    assert!(json.contains("version"));

    let dir = tempdir()?;
    let db_path = dir.path().join("ffi_smoke.db");
    let db_c = CString::new(db_path.to_string_lossy().to_string())?;
    let mut out2 = ptr::null_mut();
    let code = unsafe { escpe_init_ledger(db_c.as_ptr(), ptr::null(), &mut out2) };
    assert_eq!(code, 0);
    let _json2 = unsafe { take_string(out2) };
    assert!(db_path.exists());
    Ok(())
}

#[test]
fn ffi_machine_fingerprint() {
    let mut out = ptr::null_mut();
    let code = unsafe { escpe_machine_fingerprint(&mut out) };
    assert_eq!(code, 0);
    let json = unsafe { take_string(out) };
    assert!(json.contains("fingerprint"));
}
