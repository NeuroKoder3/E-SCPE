//! Tamper-evident, hash-chained, append-only SQLite ledger.

use std::path::Path;

use pbkdf2::pbkdf2_hmac;
use rusqlite::{params, Connection, OptionalExtension as _, TransactionBehavior};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::info;
use uuid::Uuid;

use crate::error::{EscpeError, Result, ResultExt as _};
use crate::signing::SignerDescriptor;
use crate::util;

pub const LEDGER_SCHEMA_VERSION: i64 = 1;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerMeta {
    pub ledger_id: Uuid,
    pub created_at_utc: String,
    pub schema_version: i64,
    pub sqlcipher_cipher_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub seq: i64,
    pub ts_utc: String,
    pub serial: String,
    pub payload_json: String,
    pub payload_hash_hex: String,
    pub prev_hash_hex: String,
    pub entry_hash_hex: String,
    pub signature_b64: String,
    pub signer: SignerDescriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerAppendInput {
    pub ts_utc: String,
    pub serial: String,
    pub payload_json: String,
    pub signature_der: Vec<u8>,
    pub signer: SignerDescriptor,
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

pub struct Ledger {
    conn: Connection,
    meta: LedgerMeta,
}

impl std::fmt::Debug for Ledger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ledger")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

impl Ledger {
    pub fn create_new(db_path: &Path, db_key: Option<&SecretString>) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| EscpeError::Ledger(format!("create db parent dir {}: {e}", parent.display())))?;
        }

        let conn = Connection::open(db_path)
            .map_err(|e| EscpeError::Ledger(format!("open db {}: {e}", db_path.display())))?;
        // For new encrypted databases, generate a single per-database salt and use it
        // consistently for both key derivation and persistence.
        let new_salt = db_key.map(|_| generate_db_salt());
        let cipher_version = apply_sqlcipher_key_and_probe(
            &conn,
            db_key,
            new_salt.as_ref().map(|s| s.as_slice()),
        )?;

        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS meta(
              k TEXT PRIMARY KEY,
              v TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entries(
              seq INTEGER PRIMARY KEY,
              ts_utc TEXT NOT NULL,
              serial TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              payload_hash BLOB NOT NULL,
              prev_hash BLOB NOT NULL,
              entry_hash BLOB NOT NULL,
              signature_der BLOB NOT NULL,
              signer_key_id TEXT NOT NULL,
              signer_kind TEXT NOT NULL,
              signer_cert_der BLOB,
              signer_cert_fp TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_entries_serial ON entries(serial);
            "#,
        )
        .ctx_ledger("create tables")?;

        let meta = LedgerMeta {
            ledger_id: Uuid::new_v4(),
            created_at_utc: crate::util::now_utc_rfc3339(),
            schema_version: LEDGER_SCHEMA_VERSION,
            sqlcipher_cipher_version: cipher_version.clone(),
        };
        conn.execute(
            "INSERT OR REPLACE INTO meta(k,v) VALUES (?1,?2)",
            params!["ledger_id", meta.ledger_id.to_string()],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO meta(k,v) VALUES (?1,?2)",
            params!["created_at_utc", &meta.created_at_utc],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO meta(k,v) VALUES (?1,?2)",
            params!["schema_version", meta.schema_version.to_string()],
        )?;
        if let Some(ref cv) = cipher_version {
            conn.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES (?1,?2)",
                params!["sqlcipher_cipher_version", cv],
            )?;
        }

        // Persist the per-database salt used for key derivation.
        if let Some(salt) = new_salt {
            conn.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES (?1,?2)",
                params!["db_salt", hex::encode(salt)],
            )?;
        }

        Ok(Self { conn, meta })
    }

    pub fn open_existing(db_path: &Path, db_key: Option<&SecretString>) -> Result<Self> {
        let conn = Connection::open(db_path)
            .map_err(|e| EscpeError::Ledger(format!("open db {}: {e}", db_path.display())))?;
        // Try to read the stored salt; legacy databases may not have one.
        let stored_salt = read_db_salt(&conn);
        let cipher_version = apply_sqlcipher_key_and_probe(
            &conn,
            db_key,
            stored_salt.as_deref(),
        )?;

        let ledger_id: String = conn
            .query_row("SELECT v FROM meta WHERE k='ledger_id'", [], |row| row.get(0))
            .ctx_ledger("read ledger_id")?;
        let created_at_utc: String = conn
            .query_row("SELECT v FROM meta WHERE k='created_at_utc'", [], |row| row.get(0))
            .ctx_ledger("read created_at_utc")?;
        let schema_version: i64 = conn
            .query_row("SELECT v FROM meta WHERE k='schema_version'", [], |row| row.get::<_, String>(0))
            .ctx_ledger("read schema_version")?
            .parse()
            .ctx_ledger("parse schema_version")?;

        if schema_version != LEDGER_SCHEMA_VERSION {
            return Err(EscpeError::Ledger(format!(
                "unsupported schema_version {schema_version} (expected {LEDGER_SCHEMA_VERSION})"
            )));
        }

        let stored_cipher: Option<String> = conn
            .query_row("SELECT v FROM meta WHERE k='sqlcipher_cipher_version'", [], |row| row.get(0))
            .optional()?;

        let meta = LedgerMeta {
            ledger_id: Uuid::parse_str(&ledger_id).ctx_ledger("parse ledger_id uuid")?,
            created_at_utc,
            schema_version,
            sqlcipher_cipher_version: cipher_version.or(stored_cipher),
        };
        Ok(Self { conn, meta })
    }

    pub fn meta(&self) -> &LedgerMeta {
        &self.meta
    }

    pub fn append(&mut self, input: LedgerAppendInput) -> Result<LedgerEntry> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .ctx_ledger("begin tx")?;

        let (last_seq, last_hash): (i64, Vec<u8>) = tx
            .query_row(
                "SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .unwrap_or((0, vec![0u8; 32]));

        let next_seq = last_seq + 1;
        let prev_hash = last_hash;

        let payload_hash = util::sha256(input.payload_json.as_bytes());
        let mut entry_preimage = Vec::with_capacity(32 + 32 + input.signature_der.len() + 64);
        entry_preimage.extend_from_slice(&prev_hash);
        entry_preimage.extend_from_slice(&payload_hash);
        entry_preimage.extend_from_slice(&input.signature_der);
        entry_preimage.extend_from_slice(input.signer.key_id.as_bytes());
        let entry_hash = util::sha256(&entry_preimage);

        // Persist signer certificate material if available (enables offline signature verification).
        let signer_cert_der: Option<Vec<u8>> = input
            .signer
            .cert_der_b64
            .as_deref()
            .map(util::b64_decode)
            .transpose()?;
        let signer_cert_fp: Option<String> = if let Some(ref der) = signer_cert_der {
            Some(util::sha256_hex(der))
        } else {
            None
        };
        if let Some(ref fp) = signer_cert_fp {
            // Enforce consistency: when a cert is present, `key_id` must equal the cert fingerprint.
            if input.signer.key_id != *fp {
                return Err(EscpeError::Ledger(
                    "signer key_id does not match signer certificate fingerprint".into(),
                ));
            }
            if let Some(ref explicit_fp) = input.signer.cert_sha256_hex {
                if explicit_fp != fp {
                    return Err(EscpeError::Ledger(
                        "signer cert_sha256_hex does not match signer certificate fingerprint".into(),
                    ));
                }
            }
        }

        tx.execute(
            r#"
            INSERT INTO entries(
              seq, ts_utc, serial, payload_json, payload_hash, prev_hash, entry_hash,
              signature_der, signer_key_id, signer_kind, signer_cert_der, signer_cert_fp
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
            "#,
            params![
                next_seq,
                input.ts_utc,
                input.serial,
                input.payload_json,
                payload_hash.to_vec(),
                prev_hash,
                entry_hash.to_vec(),
                input.signature_der,
                input.signer.key_id,
                input.signer.kind,
                signer_cert_der,
                signer_cert_fp,
            ],
        )
        .ctx_ledger("insert ledger entry")?;

        tx.commit().ctx_ledger("commit tx")?;

        Ok(LedgerEntry {
            seq: next_seq,
            ts_utc: input.ts_utc,
            serial: input.serial,
            payload_json: input.payload_json,
            payload_hash_hex: hex::encode(payload_hash),
            prev_hash_hex: hex::encode(&prev_hash),
            entry_hash_hex: hex::encode(entry_hash),
            signature_b64: util::b64_encode(&input.signature_der),
            signer: input.signer,
        })
    }

    pub fn latest_seq(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COALESCE(MAX(seq),0) FROM entries", [], |row| row.get(0))
            .ctx_ledger("latest seq")
    }

    pub fn iter_entries(&self) -> Result<Vec<LedgerEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT seq, ts_utc, serial, payload_json, payload_hash, prev_hash, entry_hash,
                       signature_der, signer_key_id, signer_kind, signer_cert_der, signer_cert_fp
                FROM entries
                ORDER BY seq ASC
                "#,
            )
            .ctx_ledger("prepare select entries")?;

        let mut rows = stmt.query([]).ctx_ledger("query entries")?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().ctx_ledger("next row")? {
            let seq: i64 = row.get(0)?;
            let ts_utc: String = row.get(1)?;
            let serial: String = row.get(2)?;
            let payload_json: String = row.get(3)?;
            let payload_hash: Vec<u8> = row.get(4)?;
            let prev_hash: Vec<u8> = row.get(5)?;
            let entry_hash: Vec<u8> = row.get(6)?;
            let signature_der: Vec<u8> = row.get(7)?;
            let signer_key_id: String = row.get(8)?;
            let signer_kind: String = row.get(9)?;
            let signer_cert_der: Option<Vec<u8>> = row.get(10)?;
            let signer_cert_fp: Option<String> = row.get(11)?;

            out.push(LedgerEntry {
                seq,
                ts_utc,
                serial,
                payload_json,
                payload_hash_hex: hex::encode(payload_hash),
                prev_hash_hex: hex::encode(prev_hash),
                entry_hash_hex: hex::encode(entry_hash),
                signature_b64: util::b64_encode(&signature_der),
                signer: SignerDescriptor {
                    key_id: signer_key_id,
                    kind: signer_kind,
                    cert_der_b64: signer_cert_der.as_deref().map(util::b64_encode),
                    cert_sha256_hex: signer_cert_fp,
                },
            });
        }
        Ok(out)
    }

    /// Verify hash-chain integrity and (optionally) signatures for every entry.
    pub fn verify_integrity<F>(&self, mut verify_sig: F) -> Result<()>
    where
        F: FnMut(&LedgerEntry, &[u8], &[u8]) -> Result<()>,
    {
        let entries = self.iter_entries()?;
        let mut prev_hash = vec![0u8; 32];
        for e in &entries {
            let payload_hash = util::sha256(e.payload_json.as_bytes());
            let sig_der = util::b64_decode(&e.signature_b64)?;

            let mut preimage = Vec::with_capacity(32 + 32 + sig_der.len() + 64);
            preimage.extend_from_slice(&prev_hash);
            preimage.extend_from_slice(&payload_hash);
            preimage.extend_from_slice(&sig_der);
            preimage.extend_from_slice(e.signer.key_id.as_bytes());
            let entry_hash = util::sha256(&preimage);

            if hex::encode(payload_hash) != e.payload_hash_hex {
                return Err(EscpeError::Ledger(format!(
                    "payload_hash mismatch at seq {}", e.seq
                )));
            }
            if hex::encode(&prev_hash) != e.prev_hash_hex {
                return Err(EscpeError::Ledger(format!(
                    "prev_hash mismatch at seq {}", e.seq
                )));
            }
            if hex::encode(entry_hash) != e.entry_hash_hex {
                return Err(EscpeError::Ledger(format!(
                    "entry_hash mismatch at seq {}", e.seq
                )));
            }

            verify_sig(e, &payload_hash, &sig_der)
                .map_err(|e| EscpeError::Ledger(format!("signature verify: {e}")))?;

            prev_hash = entry_hash.to_vec();
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Backup / restore
// ---------------------------------------------------------------------------

/// Export the full ledger (meta + entries) to a JSON file for backup.
pub fn export_ledger_json(ledger: &Ledger, out_path: &Path) -> Result<()> {
    let meta = ledger.meta().clone();
    let entries = ledger.iter_entries()?;
    let export = serde_json::json!({
        "format": "escpe-ledger-backup-v1",
        "exported_at_utc": crate::util::now_utc_rfc3339(),
        "meta": meta,
        "entries": entries,
    });
    let json = serde_json::to_vec_pretty(&export)
        .map_err(|e| EscpeError::Ledger(format!("serialize ledger export: {e}")))?;
    std::fs::write(out_path, json)
        .map_err(|e| EscpeError::Ledger(format!("write export {}: {e}", out_path.display())))?;
    info!(path = %out_path.display(), entries = entries.len(), "ledger exported");
    Ok(())
}

/// Import a ledger from a JSON backup into a new database.
///
/// Creates a fresh database and replays all entries (preserving the original
/// hashes and signatures).  Verifies hash-chain integrity after import.
pub fn import_ledger_json(
    json_path: &Path,
    db_path: &Path,
    db_key: Option<&SecretString>,
) -> Result<Ledger> {
    let json_bytes = std::fs::read(json_path)
        .map_err(|e| EscpeError::Ledger(format!("read import {}: {e}", json_path.display())))?;

    #[derive(Deserialize)]
    struct LedgerExport {
        meta: LedgerMeta,
        entries: Vec<LedgerEntry>,
    }

    let export: LedgerExport = serde_json::from_slice(&json_bytes)
        .map_err(|e| EscpeError::Ledger(format!("parse ledger backup: {e}")))?;

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| EscpeError::Ledger(format!("create dir {}: {e}", parent.display())))?;
    }

    let conn = Connection::open(db_path)
        .map_err(|e| EscpeError::Ledger(format!("open db {}: {e}", db_path.display())))?;
    let new_salt = db_key.map(|_| generate_db_salt());
    let cipher_version = apply_sqlcipher_key_and_probe(
        &conn,
        db_key,
        new_salt.as_ref().map(|s| s.as_slice()),
    )?;

    conn.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS meta(
          k TEXT PRIMARY KEY,
          v TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS entries(
          seq INTEGER PRIMARY KEY,
          ts_utc TEXT NOT NULL,
          serial TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          payload_hash BLOB NOT NULL,
          prev_hash BLOB NOT NULL,
          entry_hash BLOB NOT NULL,
          signature_der BLOB NOT NULL,
          signer_key_id TEXT NOT NULL,
          signer_kind TEXT NOT NULL,
          signer_cert_der BLOB,
          signer_cert_fp TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_entries_serial ON entries(serial);
        "#,
    )
    .ctx_ledger("create tables for import")?;

    // Restore metadata.
    let meta = export.meta;
    conn.execute(
        "INSERT OR REPLACE INTO meta(k,v) VALUES (?1,?2)",
        params!["ledger_id", meta.ledger_id.to_string()],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO meta(k,v) VALUES (?1,?2)",
        params!["created_at_utc", &meta.created_at_utc],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO meta(k,v) VALUES (?1,?2)",
        params!["schema_version", meta.schema_version.to_string()],
    )?;
    if let Some(ref cv) = cipher_version {
        conn.execute(
            "INSERT OR REPLACE INTO meta(k,v) VALUES (?1,?2)",
            params!["sqlcipher_cipher_version", cv],
        )?;
    }
    if let Some(salt) = new_salt {
        conn.execute(
            "INSERT OR REPLACE INTO meta(k,v) VALUES (?1,?2)",
            params!["db_salt", hex::encode(salt)],
        )?;
    }

    // Replay entries.
    for e in &export.entries {
        let payload_hash = hex::decode(&e.payload_hash_hex)
            .map_err(|err| EscpeError::Ledger(format!("decode payload_hash: {err}")))?;
        let prev_hash = hex::decode(&e.prev_hash_hex)
            .map_err(|err| EscpeError::Ledger(format!("decode prev_hash: {err}")))?;
        let entry_hash = hex::decode(&e.entry_hash_hex)
            .map_err(|err| EscpeError::Ledger(format!("decode entry_hash: {err}")))?;
        let sig_der = crate::util::b64_decode(&e.signature_b64)?;

        let signer_cert_der: Option<Vec<u8>> = e
            .signer
            .cert_der_b64
            .as_deref()
            .map(crate::util::b64_decode)
            .transpose()?;
        let signer_cert_fp: Option<String> = signer_cert_der
            .as_deref()
            .map(crate::util::sha256_hex);
        if let Some(ref fp) = signer_cert_fp {
            if e.signer.key_id != *fp {
                return Err(EscpeError::Ledger(format!(
                    "import entry seq {}: signer key_id does not match certificate fingerprint",
                    e.seq
                )));
            }
        }

        conn.execute(
            r#"
            INSERT INTO entries(
              seq, ts_utc, serial, payload_json, payload_hash, prev_hash, entry_hash,
              signature_der, signer_key_id, signer_kind, signer_cert_der, signer_cert_fp
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
            "#,
            params![
                e.seq,
                e.ts_utc,
                e.serial,
                e.payload_json,
                payload_hash,
                prev_hash,
                entry_hash,
                sig_der,
                e.signer.key_id,
                e.signer.kind,
                signer_cert_der,
                signer_cert_fp,
            ],
        )
        .ctx_ledger("insert imported entry")?;
    }

    let ledger = Ledger {
        conn,
        meta: LedgerMeta {
            sqlcipher_cipher_version: cipher_version,
            ..meta
        },
    };

    // Verify integrity of imported data (hash-chain + signatures).
    ledger.verify_integrity(|e, payload_hash, sig_der| {
        let cert_b64 = e
            .signer
            .cert_der_b64
            .as_deref()
            .ok_or_else(|| EscpeError::Ledger(format!("missing signer certificate at seq {}", e.seq)))?;
        let cert_der = crate::util::b64_decode(cert_b64)?;
        let fp = crate::util::sha256_hex(&cert_der);
        if fp != e.signer.key_id {
            return Err(EscpeError::Ledger(format!(
                "signer certificate fingerprint mismatch at seq {}",
                e.seq
            )));
        }
        crate::signing::verify_p256_ecdsa_der_sig_with_cert_der(&cert_der, payload_hash, sig_der)
    })?;
    info!(entries = export.entries.len(), "ledger imported and verified");
    Ok(ledger)
}

// ---------------------------------------------------------------------------
// SQLCipher helpers
// ---------------------------------------------------------------------------

fn apply_sqlcipher_key_and_probe(
    conn: &Connection,
    db_key: Option<&SecretString>,
    stored_salt: Option<&[u8]>,
) -> Result<Option<String>> {
    if let Some(key) = db_key {
        let salt = stored_salt
            .ok_or_else(|| EscpeError::Ledger("missing db_salt for encrypted database".into()))?
            .to_vec();
        let derived = derive_db_key(key.expose_secret(), &salt);
        let key_hex = hex::encode(derived);
        let pragma_key = format!("x'{}'", key_hex);
        let _ = conn.execute("PRAGMA key = ?1;", params![pragma_key]);
        let _ = conn.execute_batch(
            r#"
            PRAGMA cipher_compatibility = 4;
            PRAGMA cipher_memory_security = ON;
            PRAGMA cipher_default_kdf_iter = 64000;
            "#,
        );
    }

    let cipher_version: Option<String> = conn
        .query_row("PRAGMA cipher_version;", [], |row| row.get(0))
        .optional()
        .unwrap_or(None);

    if db_key.is_some() && cipher_version.is_none() {
        return Err(EscpeError::Ledger(
            "SQLCipher key provided but SQLCipher not active (cipher_version probe failed)".into(),
        ));
    }
    if let Some(ref cv) = cipher_version {
        info!(sqlcipher_cipher_version = %cv, "SQLCipher detected");
    }

    Ok(cipher_version)
}

/// Read the per-database salt from the meta table.  Returns `None` if not present (legacy DB).
fn read_db_salt(conn: &Connection) -> Option<Vec<u8>> {
    conn.query_row("SELECT v FROM meta WHERE k='db_salt'", [], |row| {
        let hex_str: String = row.get(0)?;
        Ok(hex::decode(&hex_str).ok())
    })
    .optional()
    .ok()
    .flatten()
    .flatten()
}

/// Salt length for per-database key derivation.
const DB_SALT_LEN: usize = 16;

fn derive_db_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    const ITERATIONS: u32 = 100_000;
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, ITERATIONS, &mut out);
    out
}

/// Generate a random salt for a new database.
fn generate_db_salt() -> [u8; DB_SALT_LEN] {
    use rand::RngCore as _;
    let mut salt = [0u8; DB_SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    salt
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn create_and_open_ledger() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("test.db");
        let ledger = Ledger::create_new(&db, None).unwrap();
        let meta = ledger.meta().clone();
        drop(ledger);

        let ledger2 = Ledger::open_existing(&db, None).unwrap();
        assert_eq!(ledger2.meta().ledger_id, meta.ledger_id);
    }

    #[test]
    fn append_and_read_entry() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("test.db");
        let mut ledger = Ledger::create_new(&db, None).unwrap();

        let sk = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let vk = p256::ecdsa::VerifyingKey::from(&sk);
        let key_id = util::sha256_hex(vk.to_encoded_point(false).as_bytes());

        let payload = r#"{"test":true}"#.to_string();
        let payload_hash = util::sha256(payload.as_bytes());
        let sig: p256::ecdsa::Signature =
            <p256::ecdsa::SigningKey as p256::ecdsa::signature::Signer<p256::ecdsa::Signature>>::sign(
                &sk,
                &payload_hash,
            );

        ledger
            .append(LedgerAppendInput {
                ts_utc: util::now_utc_rfc3339(),
                serial: "SER-001".to_string(),
                payload_json: payload,
                signature_der: sig.to_der().as_bytes().to_vec(),
                signer: SignerDescriptor {
                    key_id,
                    kind: "test".to_string(),
                    cert_der_b64: None,
                    cert_sha256_hex: None,
                },
            })
            .unwrap();

        let entries = ledger.iter_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].seq, 1);
        assert_eq!(entries[0].serial, "SER-001");
    }

    #[test]
    fn hash_chain_detects_tamper() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("test.db");
        let mut ledger = Ledger::create_new(&db, None).unwrap();

        let sk = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let vk = p256::ecdsa::VerifyingKey::from(&sk);
        let key_id = util::sha256_hex(vk.to_encoded_point(false).as_bytes());
        let signer = SignerDescriptor {
            key_id,
            kind: "test".to_string(),
            cert_der_b64: None,
            cert_sha256_hex: None,
        };

        let payload = r#"{"v":1}"#.to_string();
        let h = util::sha256(payload.as_bytes());
        let sig: p256::ecdsa::Signature =
            <p256::ecdsa::SigningKey as p256::ecdsa::signature::Signer<p256::ecdsa::Signature>>::sign(&sk, &h);

        ledger
            .append(LedgerAppendInput {
                ts_utc: util::now_utc_rfc3339(),
                serial: "S1".to_string(),
                payload_json: payload,
                signature_der: sig.to_der().as_bytes().to_vec(),
                signer,
            })
            .unwrap();

        // Integrity should pass.
        ledger.verify_integrity(|_, _, _| Ok(())).unwrap();

        // Tamper.
        let conn = Connection::open(&db).unwrap();
        conn.execute("UPDATE entries SET payload_json='{\"v\":999}' WHERE seq=1", [])
            .unwrap();

        let ledger2 = Ledger::open_existing(&db, None).unwrap();
        let err = ledger2.verify_integrity(|_, _, _| Ok(())).unwrap_err();
        assert!(err.to_string().contains("payload_hash mismatch"));
    }

    #[test]
    fn latest_seq_empty_ledger() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("test.db");
        let ledger = Ledger::create_new(&db, None).unwrap();
        assert_eq!(ledger.latest_seq().unwrap(), 0);
    }
}
