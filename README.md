<p align="center">
  <img src="https://img.shields.io/badge/E--SCPE-v1.0.0-blueviolet?style=for-the-badge" alt="Version" />
  <img src="https://img.shields.io/badge/Rust-1.75%2B-orange?style=for-the-badge&logo=rust" alt="Rust" />
  <img src="https://img.shields.io/badge/.NET_8-WinUI_3-blue?style=for-the-badge&logo=dotnet" alt=".NET 8" />
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows" alt="Windows" />
  <img src="https://img.shields.io/badge/License-Source_Available-green?style=for-the-badge" alt="License" />
</p>

<h1 align="center">E-SCPE</h1>
<h3 align="center">Entanglement-Enhanced Supply-Chain Provenance Engine</h3>

<p align="center">
  <strong>Quantum-secured, offline-first supply chain integrity verification with tamper-evident ledger technology.</strong>
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#quickstart">Quickstart</a> &bull;
  <a href="#winui-desktop-app">Desktop App</a> &bull;
  <a href="#cli-reference">CLI Reference</a> &bull;
  <a href="#security">Security</a> &bull;
  <a href="#license">License</a>
</p>

---

## Overview

**E-SCPE** is a production-grade, **offline** provenance engine designed for air-gapped and on-premises environments. It validates quantum tag scans via a **CHSH/Bell-inequality** test and records every accepted scan into a **tamper-evident, hash-chained, cryptographically signed append-only ledger**.

Built for industries where supply chain integrity is non-negotiable: **aerospace, defense, pharmaceuticals, semiconductor manufacturing, and critical infrastructure**.

## Features

- **Quantum Tag Verification** -- CHSH statistic (S) computed from coincidence counts; accepts when `S > threshold` (Bell inequality violation)
- **Tamper-Evident Ledger** -- SQLite-backed append-only ledger with SHA-256 hash chain (`prev_hash -> entry_hash`), payload hashing, and ECDSA P-256 signature storage
- **Offline-First Architecture** -- Zero network dependency; all cryptographic verification happens locally
- **Hardware-Bound Licensing** -- Ed25519-signed licenses tied to machine fingerprint (Windows MachineGuid)
- **Offline Signature Verification** -- Entries embed X.509 certificates (DER) for self-contained verification
- **Batch Audit & Compliance** -- CSV serials -> sequential scans -> ledger entries -> compliance pack export (manifest + JSON + LaTeX + PDF)
- **SQLCipher Support** -- Optional encryption at rest when linked with SQLCipher
- **FFI / DLL Interface** -- `escpe_core.dll` exposes a full C-ABI for integration with any language
- **WinUI 3 Desktop App** -- Modern Windows desktop GUI for interactive operation
- **SIEM Integration** -- Structured JSON-lines logging for security monitoring pipelines

## Architecture

```
+---------------------+     +-------------------+     +--------------------+
|   Quantum Tag       |     |   CHSH/Bell       |     |   Tamper-Evident   |
|   Reader (HW/Sim)   | --> |   Inequality Test  | --> |   Append-Only      |
|                     |     |   S > threshold    |     |   Ledger (SQLite)  |
+---------------------+     +-------------------+     +--------------------+
                                                              |
                                                              v
                                                    +--------------------+
                                                    |   P-256 ECDSA      |
                                                    |   Signature +      |
                                                    |   X.509 Cert       |
                                                    +--------------------+
                                                              |
                                                              v
                                                    +--------------------+
                                                    |   Compliance Pack  |
                                                    |   (JSON + LaTeX +  |
                                                    |    PDF/A Report)   |
                                                    +--------------------+
```

### Core Components

| Component | Language | Description |
|-----------|----------|-------------|
| `escpe` (CLI) | Rust | Command-line engine for all operations |
| `escpe_core.dll` | Rust (FFI) | Shared library with C-ABI for language interop |
| `EscpeWinUI` | C# / WinUI 3 | Modern Windows desktop application |
| Ledger | SQLite | Hash-chained, signed append-only data store |

## Quickstart

### Prerequisites

- **Rust** 1.75+ with `cargo`
- **Windows 10/11** (19041+)
- **.NET 8 SDK** (for WinUI app only)

### Build

```powershell
git clone https://github.com/NeuroKoder3/E-SCPE.git
cd E-SCPE

# Run tests
cargo test

# Build release binaries
cargo build --release
```

**Artifacts:**
- CLI: `target\release\escpe.exe`
- DLL (FFI): `target\release\escpe_core.dll`

### 1. Generate a Dev Signing Key + Certificate

```powershell
.\target\release\escpe.exe keygen --out-dir .\escpe-keys --common-name "E-SCPE Dev"
```

### 2. Initialize a Ledger

```powershell
.\target\release\escpe.exe init-ledger --db .\escpe-ledger.db
```

### 3. Scan + Verify + Append to Ledger (Simulated Reader)

```powershell
.\target\release\escpe.exe scan `
  --db .\escpe-ledger.db `
  --serial "AERO-ALLOY-000042" `
  --chsh-threshold 2.0 `
  --signing-key-pem .\escpe-keys\signing_key.pem `
  --signing-cert-pem .\escpe-keys\signing_cert.pem
```

### 4. Verify Ledger Integrity

```powershell
.\target\release\escpe.exe verify-ledger --db .\escpe-ledger.db
```

### 5. Batch Audit from CSV

```powershell
# Create serials.csv with header: serial
.\target\release\escpe.exe audit `
  --db .\escpe-ledger.db `
  --csv .\serials.csv `
  --out-dir .\escpe-compliance-pack `
  --chsh-threshold 2.0 `
  --signing-key-pem .\escpe-keys\signing_key.pem `
  --signing-cert-pem .\escpe-keys\signing_cert.pem
```

**Outputs:** `manifest.json`, `ledger_entries.json`, `audit_report.tex`, `audit_report.pdf` (if `tectonic` is on PATH)

## WinUI Desktop App

The E-SCPE WinUI 3 desktop application provides a modern, interactive interface for all engine operations.

### Build & Run

```powershell
cd winui
dotnet build -c Release
.\bin\Release\net8.0-windows10.0.19041.0\EscpeWinUI.exe
```

### Features

- One-click key generation, ledger initialization, scanning, and verification
- Real-time log output with color-coded severity levels
- Batch audit with progress indicator
- SQLCipher database encryption password management (DPAPI-protected)
- Built-in license activation and validation
- About dialog with version, git hash, and build timestamp

## CLI Reference

| Command | Description |
|---------|-------------|
| `escpe init-ledger` | Create a new empty ledger database |
| `escpe scan` | Scan + verify a quantum tag, append signed entry |
| `escpe verify-ledger` | Verify entire ledger hash chain + signatures |
| `escpe audit` | Batch audit serials from CSV, generate compliance pack |
| `escpe keygen` | Generate P-256 signing key + self-signed X.509 cert |
| `escpe license-keygen` | Generate Ed25519 vendor keypair for licensing |
| `escpe license-generate` | Create a signed, machine-bound license file |
| `escpe license-check` | Validate a license file |
| `escpe machine-fingerprint` | Print this machine's hardware fingerprint |
| `escpe export-ledger` | Export ledger to JSON backup |
| `escpe import-ledger` | Import ledger from JSON backup |
| `escpe version` | Print version, git hash, and build timestamp |

## Configuration

E-SCPE loads configuration from (in order):

1. CLI arguments (highest priority)
2. `escpe.toml` next to the executable
3. `%LOCALAPPDATA%\E-SCPE\config.toml`
4. Environment variables (`ESCPE_DB_KEY`, `ESCPE_DB`, `ESCPE_LOG_LEVEL`)
5. Built-in defaults

See [`escpe.toml.example`](escpe.toml.example) for all available options.

## SQLCipher (Encryption at Rest)

E-SCPE runs with plain SQLite by default. When linked/built with SQLCipher, set the encryption key:

```powershell
$env:ESCPE_DB_KEY = "your-strong-passphrase"
.\target\release\escpe.exe init-ledger --db .\escpe-ledger.db
```

E-SCPE probes `PRAGMA cipher_version;` at startup and logs whether SQLCipher is active.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and security posture details.

### Cryptographic Primitives

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| Ledger entry signing | ECDSA P-256 | FIPS 186-4 |
| Hash chain | SHA-256 | FIPS 180-4 |
| License signing | Ed25519 | RFC 8032 |
| Machine fingerprint | SHA-256(MachineGuid) | -- |
| DB encryption (optional) | AES-256-CBC | SQLCipher / FIPS 197 |

### Hardening Roadmap

- **FIPS 140-3**: Swap crypto backend to a validated module (e.g., BoringSSL FIPS, Windows CNG)
- **TPM/HSM**: Signer implementation for Windows CNG / PKCS#11 with root hash in TPM NV
- **PDF/A-2b**: Validated templates and a PDF/A-compliant toolchain for regulatory reports
- **Hardware Reader Driver**: Replace simulated reader with vendor SDK + Rust FFI wrapper

## License

This project is released under a **Source Available -- No Modifications** license. You are free to use, run, and test the software. You may **not** modify, alter, or create derivative works. See [LICENSE](LICENSE) for full terms.

## Contributing

Due to the license terms, code contributions (pull requests with code changes) are not accepted. However, you are welcome to:

- Open **issues** to report bugs or suggest features
- Share feedback and use cases in **Discussions**
- Star the repo if you find it useful

---

<p align="center">
  Built with Rust and WinUI 3 &mdash; designed for air-gapped, high-assurance environments.
</p>
