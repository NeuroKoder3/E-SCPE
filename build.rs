fn main() {
    // Embed vendor public key (base64) at compile time if provided.
    let vendor_pubkey_b64 = std::env::var("ESCPE_VENDOR_PUBKEY_B64")
        .ok()
        .or_else(|| std::fs::read_to_string("vendor_public.key").ok())
        .unwrap_or_default();
    let trimmed_key = vendor_pubkey_b64.trim();
    if trimmed_key.is_empty() {
        println!("cargo:warning=ESCPE_VENDOR_PUBKEY_B64 is empty! License enforcement will be disabled. Set the env var or place vendor_public.key in the repo root for production builds.");
    }
    println!(
        "cargo:rustc-env=ESCPE_VENDOR_PUBKEY_B64={}",
        trimmed_key
    );

    // Embed git commit hash at compile time.
    let git_hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=ESCPE_GIT_HASH={}", git_hash.trim());

    // Embed build timestamp (epoch seconds).
    let build_ts = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|_| "0".to_string())
    };
    println!("cargo:rustc-env=ESCPE_BUILD_TS={build_ts}");

    // Re-run only when git state or this script changes.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=vendor_public.key");
}
