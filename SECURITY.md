# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in E-SCPE, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities via one of the following channels:

1. **GitHub Security Advisories**: Use the [Security tab](../../security/advisories) on this repository to submit a private advisory.
2. **Email**: Contact the maintainer directly through their GitHub profile.

### What to Include

When reporting a vulnerability, please include:

- A clear description of the vulnerability
- Steps to reproduce the issue
- The potential impact (e.g., data leakage, privilege escalation, ledger tampering)
- Any suggested mitigation or fix (optional)
- Your preferred method of contact for follow-up

### Response Timeline

- **Acknowledgment**: Within 48 hours of receiving the report
- **Initial Assessment**: Within 7 days
- **Fix or Mitigation**: Depends on severity; critical issues are prioritized immediately

### Scope

The following are considered in-scope for security reports:

- Vulnerabilities in the Rust core engine (`escpe` / `escpe_core.dll`)
- Cryptographic weaknesses in signing, hashing, or verification
- Ledger integrity bypass (hash chain tampering, signature forgery)
- License validation bypass
- FFI boundary safety issues (memory corruption, buffer overflow)
- WinUI application security issues (credential handling, DPAPI usage)
- SQLCipher key management issues

### Out of Scope

- Vulnerabilities in third-party dependencies (report upstream; we will update)
- Issues requiring physical access to the machine AND local admin privileges
- Denial of service via resource exhaustion on localhost
- Issues in the simulated tag reader (it is explicitly a development stub)

## Security Architecture

### Cryptographic Primitives

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Ledger entry signing | ECDSA P-256 (secp256r1) | FIPS 186-4 compliant |
| Ledger hash chain | SHA-256 | FIPS 180-4; `prev_hash -> entry_hash` |
| License signing | Ed25519 | RFC 8032; vendor keypair |
| Machine fingerprint | SHA-256(MachineGuid) | Windows registry-based binding |
| DB encryption | AES-256-CBC (via SQLCipher) | Optional; requires SQLCipher linkage |
| DB password storage | DPAPI (CurrentUser scope) | WinUI app only |

### Design Principles

1. **Offline-First**: No network calls. All verification is local and self-contained.
2. **Append-Only Ledger**: Entries cannot be modified or deleted after creation.
3. **Hash Chain Integrity**: Each entry's hash includes the previous entry's hash, forming an immutable chain.
4. **Embedded Certificates**: Entries can carry their signing certificate for offline verification without a PKI.
5. **Defense in Depth**: Multiple layers -- hash chain, digital signatures, and optional encryption at rest.
6. **Least Privilege FFI**: Rate-limited FFI boundary with input validation on every exported function.

### Known Limitations (Planned Hardening)

- **Crypto backend**: Currently uses `ring`/`p256` crates; production deployments targeting FIPS should swap to a FIPS 140-3 validated module (e.g., BoringSSL FIPS, Windows CNG).
- **Key storage**: Signing keys are stored as PEM files on disk; production should use TPM/HSM via Windows CNG or PKCS#11.
- **Simulated reader**: The quantum tag reader is a development stub generating synthetic data. Real deployments must integrate a hardware vendor SDK.
- **PDF/A compliance**: Current LaTeX reports are not PDF/A-2b validated; regulatory submissions should use a validated PDF toolchain.

## Dependency Auditing

This project uses [`cargo deny`](https://github.com/EmbarkStudios/cargo-deny) for dependency auditing. Run:

```powershell
cargo deny check
```

This checks for known vulnerabilities, license compliance, and duplicate dependencies.
