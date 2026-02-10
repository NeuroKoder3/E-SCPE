use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use secrecy::SecretString;
use serde::Serialize;
use tracing::{info, warn};

use escpe_core::{
    chsh,
    config::EscpeConfig,
    ledger::{self, Ledger, LedgerAppendInput},
    license,
    report,
    signing::{self, P256PemSigner, Signer as _},
    tag::{SimulatedTagReader, TagReader as _},
    util,
};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "escpe",
    version = util::VERSION,
    about = "Entanglement-Enhanced Supply-Chain Provenance Engine (offline)"
)]
struct Cli {
    /// Path to the ledger database (SQLite / SQLCipher).
    #[arg(long, global = true)]
    db: Option<PathBuf>,

    /// Read the DB encryption key from this environment variable.
    #[arg(long, global = true, default_value = "ESCPE_DB_KEY")]
    db_key_env: String,

    /// Path to a TOML config file.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new, empty ledger database.
    InitLedger,

    /// Scan + verify a quantum tag and append a signed ledger entry.
    Scan {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        chsh_threshold: Option<f64>,
        #[arg(long)]
        signing_key_pem: PathBuf,
        #[arg(long)]
        signing_cert_pem: Option<PathBuf>,
    },

    /// Batch audit serials from a CSV and generate a compliance pack.
    Audit {
        #[arg(long)]
        csv: PathBuf,
        #[arg(long)]
        chsh_threshold: Option<f64>,
        #[arg(long)]
        signing_key_pem: PathBuf,
        #[arg(long)]
        signing_cert_pem: Option<PathBuf>,
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },

    /// Verify the entire ledger hash-chain and signatures.
    VerifyLedger,

    /// Print the machine fingerprint used for hardware-bound licensing.
    MachineFingerprint,

    /// Generate a P-256 signing key + self-signed X.509 certificate (dev/POC).
    Keygen {
        #[arg(long, default_value = "escpe-keys")]
        out_dir: PathBuf,
        #[arg(long, default_value = "E-SCPE Dev Signing Cert")]
        common_name: String,
    },

    /// Generate an Ed25519 vendor keypair for license signing.
    LicenseKeygen {
        #[arg(long, default_value = "escpe-license-keys")]
        out_dir: PathBuf,
    },

    /// Generate a signed license file for a customer machine.
    LicenseGenerate {
        /// Base64-encoded Ed25519 vendor private key.
        #[arg(long)]
        vendor_key_b64: String,
        #[arg(long)]
        license_id: String,
        #[arg(long)]
        issued_to: String,
        #[arg(long)]
        machine_fingerprint: String,
        #[arg(long, default_value = "2020-01-01T00:00:00Z")]
        not_before: String,
        #[arg(long, default_value = "2099-12-31T23:59:59Z")]
        not_after: String,
        #[arg(long, value_delimiter = ',')]
        features: Vec<String>,
        #[arg(long, default_value = "escpe-license.json")]
        out: PathBuf,
    },

    /// Check the status of a license file.
    LicenseCheck {
        #[arg(long)]
        license: PathBuf,
        #[arg(long)]
        vendor_pubkey_b64: String,
    },

    /// Export the ledger to a JSON backup file.
    ExportLedger {
        #[arg(long)]
        out: PathBuf,
    },

    /// Import a ledger from a JSON backup into a new database.
    ImportLedger {
        #[arg(long)]
        json: PathBuf,
        /// Path for the new database (must not already exist).
        #[arg(long)]
        target_db: PathBuf,
    },

    /// Print version information.
    Version,
}

#[derive(Debug, Serialize)]
struct LedgerPayloadV1 {
    schema: &'static str,
    ledger_id: String,
    scan: escpe_core::tag::TagScan,
    chsh: chsh::ChshResult,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load configuration.
    let mut cfg = EscpeConfig::load(cli.config.as_deref())
        .context("load config")?;
    cfg.apply_env();

    init_logging(&cfg.logging);

    let vendor_pubkey_b64 = cfg
        .license
        .vendor_pubkey_b64
        .as_deref()
        .unwrap_or(license::DEFAULT_VENDOR_PUBKEY_B64);

    if command_requires_license(&cli.cmd) {
        let status = license::check_license_at_startup(
            &cfg.license.path,
            vendor_pubkey_b64,
            &[],
        )
        .context("check license at startup")?;
        anyhow::ensure!(
            status == license::LicenseStatus::Valid,
            "license check failed: {status}"
        );
    }

    let db_path = cli.db.unwrap_or(cfg.paths.db.clone());
    util::validate_path(&db_path, "db")?;
    let db_key = std::env::var(&cli.db_key_env)
        .ok()
        .or(cfg.security.db_key.clone())
        .map(|s| SecretString::new(s.into()));

    match cli.cmd {
        Commands::InitLedger => {
            let ledger = Ledger::create_new(&db_path, db_key.as_ref())
                .context("create ledger")?;
            info!(ledger_id = %ledger.meta().ledger_id, "ledger initialized");
        }

        Commands::Scan {
            serial,
            chsh_threshold,
            signing_key_pem,
            signing_cert_pem,
        } => {
            util::validate_path(&signing_key_pem, "signing key")?;
            let signing_key_pem = util::canonicalize_if_exists(&signing_key_pem, "signing key")?;
            let signing_cert_pem = signing_cert_pem
                .as_ref()
                .map(|p| util::canonicalize_if_exists(p, "signing cert"))
                .transpose()?;
            let threshold = chsh_threshold.unwrap_or(cfg.scan.chsh_threshold);

            let mut ledger = Ledger::open_existing(&db_path, db_key.as_ref())
                .or_else(|_| Ledger::create_new(&db_path, db_key.as_ref()))
                .context("open/create ledger")?;

            let signer = P256PemSigner::from_key_pem_and_optional_cert_pem(
                &signing_key_pem,
                signing_cert_pem.as_deref(),
                None,
            )
            .context("load signer")?;

            let mut reader = SimulatedTagReader::default();
            let scan = reader.scan(&serial).context("scan tag")?;
            let chsh_res = chsh::compute_chsh(&scan, threshold).context("compute CHSH")?;

            anyhow::ensure!(chsh_res.passed, "quantum tag rejected (CHSH <= threshold)");

            let payload = LedgerPayloadV1 {
                schema: "escpe.payload.v1",
                ledger_id: ledger.meta().ledger_id.to_string(),
                scan,
                chsh: chsh_res,
            };
            let payload_json = serde_json::to_string(&payload).context("serialize payload")?;
            let payload_hash = util::sha256(payload_json.as_bytes());
            let signature_der = signer.sign(&payload_hash).context("sign payload_hash")?;

            let entry = ledger
                .append(LedgerAppendInput {
                    ts_utc: util::now_utc_rfc3339(),
                    serial: payload.scan.serial.clone(),
                    payload_json,
                    signature_der,
                    signer: signer.descriptor().clone(),
                })
                .context("append ledger entry")?;

            info!(seq = entry.seq, entry_hash = %entry.entry_hash_hex, "appended ledger entry");
        }

        Commands::Audit {
            csv,
            chsh_threshold,
            signing_key_pem,
            signing_cert_pem,
            out_dir,
        } => {
            util::validate_path(&csv, "csv")?;
            util::validate_path(&signing_key_pem, "signing key")?;
            let csv = util::canonicalize_if_exists(&csv, "csv")?;
            let signing_key_pem = util::canonicalize_if_exists(&signing_key_pem, "signing key")?;
            let signing_cert_pem = signing_cert_pem
                .as_ref()
                .map(|p| util::canonicalize_if_exists(p, "signing cert"))
                .transpose()?;
            let threshold = chsh_threshold.unwrap_or(cfg.scan.chsh_threshold);
            let out = out_dir.unwrap_or(cfg.paths.compliance_out_dir.clone());

            let mut ledger = Ledger::open_existing(&db_path, db_key.as_ref())
                .or_else(|_| Ledger::create_new(&db_path, db_key.as_ref()))
                .context("open/create ledger")?;

            let signer = P256PemSigner::from_key_pem_and_optional_cert_pem(
                &signing_key_pem,
                signing_cert_pem.as_deref(),
                None,
            )
            .context("load signer")?;

            let mut reader = SimulatedTagReader::default();

            let mut rdr =
                csv::Reader::from_path(&csv).with_context(|| format!("open csv: {}", csv.display()))?;
            let headers = rdr.headers().context("read csv headers")?.clone();
            if !headers.iter().any(|h| h.eq_ignore_ascii_case("serial")) {
                anyhow::bail!("csv missing required header 'serial'");
            }

            let mut row_count = 0usize;
            for rec in rdr.deserialize::<CsvRow>() {
                row_count += 1;
                if row_count > util::MAX_CSV_ROWS {
                    anyhow::bail!(
                        "csv exceeds maximum row limit of {}",
                        util::MAX_CSV_ROWS
                    );
                }
                let row = rec.context("parse csv row")?;
                let scan = reader.scan(&row.serial).context("scan tag")?;
                let chsh_res = chsh::compute_chsh(&scan, threshold).context("compute CHSH")?;
                if !chsh_res.passed {
                    warn!(serial = %row.serial, s = chsh_res.s, "tag rejected; skipping");
                    continue;
                }

                let payload = LedgerPayloadV1 {
                    schema: "escpe.payload.v1",
                    ledger_id: ledger.meta().ledger_id.to_string(),
                    scan,
                    chsh: chsh_res,
                };
                let payload_json =
                    serde_json::to_string(&payload).context("serialize payload")?;
                let payload_hash = util::sha256(payload_json.as_bytes());
                let signature_der = signer.sign(&payload_hash).context("sign payload_hash")?;

                let _ = ledger
                    .append(LedgerAppendInput {
                        ts_utc: util::now_utc_rfc3339(),
                        serial: payload.scan.serial.clone(),
                        payload_json,
                        signature_der,
                        signer: signer.descriptor().clone(),
                    })
                    .context("append entry")?;
            }

            let entries = ledger.iter_entries().context("read entries")?;
            report::write_compliance_pack(&out, ledger.meta(), &entries)
                .context("write compliance pack")?;
            info!(out_dir = %out.display(), "compliance pack generated");
        }

        Commands::VerifyLedger => {
            let ledger =
                Ledger::open_existing(&db_path, db_key.as_ref()).context("open ledger")?;
            let meta = ledger.meta().clone();
            info!(ledger_id = %meta.ledger_id, schema_version = meta.schema_version, "verifying");

            ledger
                .verify_integrity(|entry, payload_hash, sig_der| {
                    if let Some(cert_b64) = &entry.signer.cert_der_b64 {
                        let cert_der = util::b64_decode(cert_b64)?;
                        signing::verify_p256_ecdsa_der_sig_with_cert_der(
                            &cert_der,
                            payload_hash,
                            sig_der,
                        )?;
                    } else {
                        warn!(seq = entry.seq, "no signer cert; skipping signature verify");
                    }
                    Ok(())
                })
                .context("verify integrity")?;
            info!("ledger verification passed");
        }

        Commands::MachineFingerprint => {
            let fp = license::machine_fingerprint().context("compute machine fingerprint")?;
            println!("{fp}");
        }

        Commands::Keygen { out_dir, common_name } => {
            signing::keygen_p256_self_signed(&out_dir, &common_name).context("keygen")?;
            info!(out_dir = %out_dir.display(), "generated signing_key.pem and signing_cert.pem");
        }

        Commands::LicenseKeygen { out_dir } => {
            license::generate_vendor_keypair(&out_dir).context("license keygen")?;
            info!(out_dir = %out_dir.display(), "generated vendor_private.key and vendor_public.key");
        }

        Commands::LicenseGenerate {
            vendor_key_b64,
            license_id,
            issued_to,
            machine_fingerprint,
            not_before,
            not_after,
            features,
            out,
        } => {
            let lic = license::generate_license(
                &vendor_key_b64,
                &license_id,
                &issued_to,
                &machine_fingerprint,
                &not_before,
                &not_after,
                &features,
            )
            .context("generate license")?;

            let json = serde_json::to_string_pretty(&lic).context("serialize license")?;
            std::fs::write(&out, &json)
                .with_context(|| format!("write {}", out.display()))?;
            info!(out = %out.display(), "license generated");
        }

        Commands::LicenseCheck {
            license,
            vendor_pubkey_b64,
        } => {
            let status =
                license::check_license(&license, &vendor_pubkey_b64).context("check license")?;
            println!("License status: {status}");
            if status != license::LicenseStatus::Valid {
                std::process::exit(1);
            }
        }

        Commands::ExportLedger { out } => {
            let ledger =
                Ledger::open_existing(&db_path, db_key.as_ref()).context("open ledger")?;
            ledger::export_ledger_json(&ledger, &out).context("export ledger")?;
            info!(out = %out.display(), "ledger exported");
        }

        Commands::ImportLedger { json, target_db } => {
            anyhow::ensure!(
                !target_db.exists(),
                "target database {} already exists -- will not overwrite",
                target_db.display()
            );
            let imported = ledger::import_ledger_json(&json, &target_db, db_key.as_ref())
                .context("import ledger")?;
            info!(
                ledger_id = %imported.meta().ledger_id,
                "ledger imported to {}",
                target_db.display()
            );
        }

        Commands::Version => {
            println!("{}", util::version_string());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, serde::Deserialize)]
struct CsvRow {
    serial: String,
}

fn init_logging(cfg: &escpe_core::config::LoggingConfig) {
    use tracing_subscriber::prelude::*;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cfg.level));

    let registry = tracing_subscriber::registry().with(filter);

    if cfg.json_stdout {
        // JSON output to stdout for container / SIEM pipelines.
        let json_layer = tracing_subscriber::fmt::layer().json();
        registry.with(json_layer).init();
    } else if !cfg.json_log_file.is_empty() {
        // JSON-lines output to file for SIEM integration.
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg.json_log_file)
            .expect("failed to open json log file");
        let file_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(std::sync::Mutex::new(log_file));
        let console_layer = tracing_subscriber::fmt::layer();
        registry.with(file_layer).with(console_layer).init();
    } else {
        // Default: human-readable output to stderr.
        let console_layer = tracing_subscriber::fmt::layer();
        registry.with(console_layer).init();
    }
}

fn command_requires_license(cmd: &Commands) -> bool {
    !matches!(
        cmd,
        Commands::LicenseKeygen { .. }
            | Commands::LicenseGenerate { .. }
            | Commands::LicenseCheck { .. }
            | Commands::MachineFingerprint
            | Commands::ExportLedger { .. }
            | Commands::ImportLedger { .. }
            | Commands::Version
    )
}
