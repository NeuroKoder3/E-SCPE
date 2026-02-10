# E-SCPE Deployment Guide

## Overview

E-SCPE (Entanglement-Enhanced Supply-Chain Provenance Engine) is deployed as:

| Component | File | Purpose |
|-----------|------|---------|
| **CLI** | `escpe.exe` | Command-line interface for all operations |
| **DLL** | `escpe_core.dll` | C-ABI shared library for FFI integration |
| **WinUI App** | `EscpeWinUI.exe` | Graphical interface (Windows 10+) |
| **MSI Installer** | `E-SCPE.msi` | Windows installer (WiX-based) |

---

## Prerequisites

- **OS:** Windows 10 version 1809 (build 17763) or later
- **.NET 8 Desktop Runtime (x64):** Required for WinUI app
- **Visual C++ 2015-2022 Redistributable (x64):** Required for native DLL
- **Disk:** ~50 MB for binaries + space for ledger database

---

## Installation

### Option A: MSI Installer (recommended)

1. Run `E-SCPE.msi` as administrator
2. Default install path: `C:\Program Files\E-SCPE\`
3. Start Menu and Desktop shortcuts are created automatically

### Option B: Manual / xcopy deployment

1. Copy `escpe.exe`, `escpe_core.dll`, and `EscpeWinUI.exe` to a directory
2. Add the directory to `PATH` (for CLI usage)

---

## Configuration

### Config file locations (searched in order)

1. Explicit path via `--config <path>` CLI flag
2. `escpe.toml` next to the executable
3. `%LOCALAPPDATA%\E-SCPE\config.toml`
4. Built-in defaults

### Example config (`escpe.toml`)

```toml
[paths]
db = "C:\\ProgramData\\E-SCPE\\ledger.db"
keys_dir = "C:\\ProgramData\\E-SCPE\\keys"
compliance_out_dir = "C:\\ProgramData\\E-SCPE\\compliance-pack"

[scan]
chsh_threshold = 2.0

[logging]
level = "info"
# JSON-lines log file for SIEM integration (leave empty to disable)
json_log_file = "C:\\ProgramData\\E-SCPE\\logs\\escpe.jsonl"
# Set to true for JSON output on stdout (e.g. container pipelines)
json_stdout = false

[license]
path = "C:\\ProgramData\\E-SCPE\\license.json"
# vendor_pubkey_b64 = "<base64 Ed25519 public key>"

[security]
# db_key = "passphrase"  # Or set ESCPE_DB_KEY env var (preferred)
```

### Environment variables

| Variable | Purpose |
|----------|---------|
| `ESCPE_DB_KEY` | SQLCipher database encryption passphrase |
| `ESCPE_DB` | Override database path |
| `ESCPE_LOG_LEVEL` | Override log level (trace/debug/info/warn/error) |
| `ESCPE_VENDOR_PUBKEY_B64` | Vendor public key for license verification (compile-time) |
| `ESCPE_SIGN_THUMBPRINT` | Authenticode certificate thumbprint (build script only) |

---

## Licensing

### Generate vendor keypair (one-time, vendor side)

```powershell
escpe license-keygen --out-dir vendor-keys
```

This creates `vendor_private.key` and `vendor_public.key` (base64 Ed25519).

**Keep `vendor_private.key` secret.** Place `vendor_public.key` in the repo root
before building so it's embedded at compile time.

### Generate a license for a customer machine

```powershell
# On the customer machine, get the fingerprint:
escpe machine-fingerprint
# Output: <hex string>

# On the vendor machine, generate the license:
escpe license-generate \
  --vendor-key-b64 "<contents of vendor_private.key>" \
  --license-id "LIC-001" \
  --issued-to "Acme Corp" \
  --machine-fingerprint "<hex string from above>" \
  --not-before "2025-01-01T00:00:00Z" \
  --not-after "2026-12-31T23:59:59Z" \
  --features full \
  --out license.json
```

### Deploy the license

Place `license.json` in `%LOCALAPPDATA%\E-SCPE\license.json` on the customer machine.

---

## Database Encryption (SQLCipher)

The ledger database supports transparent encryption via SQLCipher.

1. Set the passphrase via the `ESCPE_DB_KEY` environment variable, or
   the `[security] db_key` config field, or the UI password field.
2. A per-database random salt is generated on first creation and stored
   in the `meta` table.
3. Key derivation: PBKDF2-HMAC-SHA256, 100,000 iterations.

**Note:** Databases created without encryption cannot be retroactively encrypted.
Export and re-import with a key if needed.

---

## Backup & Restore

### Export

```powershell
escpe export-ledger --db ledger.db --out backup.json
```

### Import

```powershell
escpe import-ledger --json backup.json --target-db restored.db
```

Import creates a new database and verifies hash-chain integrity after import.

---

## SIEM / Log Integration

Enable structured JSON logging in `escpe.toml`:

```toml
[logging]
level = "info"
json_log_file = "/var/log/escpe/audit.jsonl"
```

Each log line is a JSON object with `timestamp`, `level`, `target`, `message`,
and structured fields. Compatible with Splunk, Elastic, Datadog, etc.

---

## Build from Source

### Prerequisites

- Rust stable (1.75+, edition 2021)
- .NET 8 SDK
- WiX v4 (optional, for MSI)
- `cargo-deny` (optional, for supply-chain audit)
- `cargo-cyclonedx` (optional, for SBOM generation)

### Build steps

```powershell
# Full build with tests, audit, signing, and packaging:
.\build.ps1

# Or manually:
cargo test
cargo build --release
dotnet test winui.tests\EscpeWinUI.Tests.csproj
dotnet build winui\EscpeWinUI.csproj -c Release
```

### Code signing

Set `ESCPE_SIGN_THUMBPRINT` to your Authenticode certificate thumbprint
before running `build.ps1`. The script signs `escpe.exe`, `escpe_core.dll`,
`EscpeWinUI.exe`, and the MSI installer.

---

## Security Considerations

1. **Vendor key:** The Ed25519 vendor public key is embedded at compile time.
   A build without `vendor_public.key` or `ESCPE_VENDOR_PUBKEY_B64` will emit
   a compiler warning and license enforcement will be disabled.

2. **DB encryption:** Use a strong passphrase. The passphrase is never stored
   in plaintext; the WinUI app offers DPAPI-protected storage.

3. **Hash chain:** The ledger uses SHA-256 hash chaining. Each entry's hash
   covers: previous hash + payload hash + signature + signer key ID.
   Tampering with any field is detectable via `escpe verify-ledger`.

4. **FFI rate limiting:** The DLL enforces a token-bucket rate limiter
   (100 calls/sec sustained, 200 burst) to mitigate abuse from external callers.

5. **Supply chain:** Run `cargo deny check` to audit dependencies for
   known vulnerabilities, license violations, and supply-chain risks.

6. **SBOM:** Generate a CycloneDX SBOM with `cargo cyclonedx --format json`.

---

## Troubleshooting

| Symptom | Solution |
|---------|----------|
| "vendor key missing" | Place `vendor_public.key` next to the app, or rebuild with `ESCPE_VENDOR_PUBKEY_B64` |
| "license check failed" | Ensure `license.json` is present and the machine fingerprint matches |
| "database: unable to open" | Check file permissions; if encrypted, ensure `ESCPE_DB_KEY` is set |
| "rate limit exceeded" | Too many FFI calls per second; reduce call frequency |
| WinUI settings lost | Check `%LOCALAPPDATA%\E-SCPE\settings.json` for file-based fallback |

---

## Architecture Overview

```
                   ┌──────────────────┐
                   │  WinUI App       │
                   │  (EscpeWinUI)    │
                   └─────┬──────┬─────┘
                     P/Invoke  │ CLI fallback
                         │     │
            ┌────────────▼─┐ ┌─▼──────────┐
            │ escpe_core   │ │ escpe.exe   │
            │ (cdylib DLL) │ │ (CLI)       │
            └──────┬───────┘ └──────┬──────┘
                   │                │
                   └───────┬────────┘
                           │
              ┌────────────▼────────────┐
              │   escpe_core (rlib)     │
              │                         │
              │  tag → chsh → signing   │
              │       → ledger (SQLite) │
              │       → report (PDF)    │
              │       → license (Ed25519│
              └─────────────────────────┘
```
