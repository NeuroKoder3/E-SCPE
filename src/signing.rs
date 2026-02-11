//! Cryptographic signing and verification primitives.

use std::path::Path;

use p256::ecdsa::{
    signature::{Signer as _, Verifier as _},
    Signature, SigningKey, VerifyingKey,
};
use p256::pkcs8::DecodePrivateKey;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use x509_parser::{pem::parse_x509_pem, prelude::parse_x509_certificate};

use crate::error::{EscpeError, Result, ResultExt as _};
use crate::util;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerDescriptor {
    /// Stable signer identifier (SHA-256 hex).
    ///
    /// - If a signing certificate is provided, this is the SHA-256 fingerprint of the cert DER.
    /// - Otherwise, this is the SHA-256 fingerprint of the uncompressed public key bytes.
    pub key_id: String,
    /// Human-readable descriptor (e.g., "p256-ecdsa/pkcs8-pem").
    pub kind: String,
}

/// Trait boundary for all signer implementations.
///
/// Production: TPM/HSM via Windows CNG / PKCS#11.
/// Development: [`P256PemSigner`] using local PEM files.
pub trait Signer {
    fn descriptor(&self) -> &SignerDescriptor;
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// PEM-file signer
// ---------------------------------------------------------------------------

pub struct P256PemSigner {
    signing_key: SigningKey,
    descriptor: SignerDescriptor,
}

impl std::fmt::Debug for P256PemSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P256PemSigner")
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

impl P256PemSigner {
    pub fn from_key_pem_and_optional_cert_pem(
        key_pem_path: &Path,
        cert_pem_path: Option<&Path>,
        key_passphrase: Option<&SecretString>,
    ) -> Result<Self> {
        let key_pem = std::fs::read_to_string(key_pem_path)
            // Avoid including key paths in error strings (CodeQL cleartext logging).
            .map_err(|e| EscpeError::Signing(format!("read key pem failed: {e}")))?;

        if key_passphrase.is_some() {
            return Err(EscpeError::Signing(
                "encrypted PEM not supported in this build (provide unencrypted PKCS#8 PEM)".into(),
            ));
        }

        let signing_key = SigningKey::from_pkcs8_pem(&key_pem)
            .ctx_signing("parse P-256 PKCS#8 private key")?;

        let key_id = if let Some(cert_pem_path) = cert_pem_path {
            let cert_pem_bytes = std::fs::read(cert_pem_path)
                // Avoid including cert paths in error strings (CodeQL cleartext logging).
                .map_err(|e| EscpeError::Signing(format!("read cert pem failed: {e}")))?;
            let (_, pem) = parse_x509_pem(&cert_pem_bytes).ctx_signing("parse x509 pem")?;
            let cert_der = pem.contents;
            util::sha256_hex(&cert_der)
        } else {
            let vk = VerifyingKey::from(&signing_key);
            let pubkey = vk.to_encoded_point(false);
            util::sha256_hex(pubkey.as_bytes())
        };

        Ok(Self {
            signing_key,
            descriptor: SignerDescriptor {
                key_id,
                kind: "p256-ecdsa/pkcs8-pem".to_string(),
            },
        })
    }
}

impl Signer for P256PemSigner {
    fn descriptor(&self) -> &SignerDescriptor {
        &self.descriptor
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let sig: Signature = self.signing_key.sign(msg);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

// ---------------------------------------------------------------------------
// Standalone verification
// ---------------------------------------------------------------------------

pub fn verify_p256_ecdsa_der_sig_with_cert_der(
    cert_der: &[u8],
    msg: &[u8],
    sig_der: &[u8],
) -> Result<()> {
    let (_, cert) = parse_x509_certificate(cert_der).ctx_signing("parse x509 cert")?;
    let spki = cert.tbs_certificate.subject_pki;
    let pk = spki.subject_public_key.data;
    let vk = VerifyingKey::from_sec1_bytes(pk.as_ref()).ctx_signing("parse sec1 pubkey from cert")?;
    let sig = Signature::from_der(sig_der).ctx_signing("parse ECDSA DER signature")?;
    vk.verify(msg, &sig)
        .ctx_signing("ECDSA signature verification failed")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Key generation (dev / POC)
// ---------------------------------------------------------------------------

/// Generate a P-256 signing key and self-signed X.509 certificate.
/// Writes `signing_key.pem` and `signing_cert.pem` to `out_dir`.
pub fn keygen_p256_self_signed(out_dir: &Path, common_name: &str) -> Result<()> {
    use p256::pkcs8::EncodePrivateKey as _;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use rustls_pki_types::PrivatePkcs8KeyDer;

    std::fs::create_dir_all(out_dir)
        .map_err(|e| EscpeError::Signing(format!("create {}: {e}", out_dir.display())))?;

    let sk = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let pkcs8_der = sk
        .to_pkcs8_der()
        .ctx_signing("encode pkcs8 der")?
        .as_bytes()
        .to_vec();
    let pkcs8_pem = sk
        .to_pkcs8_pem(Default::default())
        .ctx_signing("encode pkcs8 pem")?;

    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8_der.as_slice()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .ctx_signing("rcgen keypair from pkcs8 der")?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);

    let mut params = CertificateParams::new(vec![]).ctx_signing("rcgen params")?;
    params.distinguished_name = dn;
    let cert = params.self_signed(&key_pair).ctx_signing("rcgen self-signed")?;
    let cert_pem = cert.pem();

    let key_path = out_dir.join("signing_key.pem");
    std::fs::write(&key_path, pkcs8_pem.as_bytes())
        .map_err(|e| EscpeError::Signing(format!("write {}: {e}", key_path.display())))?;

    let cert_path = out_dir.join("signing_cert.pem");
    std::fs::write(&cert_path, cert_pem.as_bytes())
        .map_err(|e| EscpeError::Signing(format!("write {}: {e}", cert_path.display())))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip() {
        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let vk = VerifyingKey::from(&sk);
        let msg = b"test message";
        let sig: Signature = sk.sign(msg);
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn bad_signature_rejected() {
        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let vk = VerifyingKey::from(&sk);
        let msg = b"test message";
        let sig: Signature = sk.sign(msg);
        // Verify with a different message should fail.
        assert!(vk.verify(b"different message", &sig).is_err());
    }

    #[test]
    fn invalid_der_signature_rejected() {
        let result = verify_p256_ecdsa_der_sig_with_cert_der(
            b"not a cert",
            b"msg",
            b"not a sig",
        );
        assert!(result.is_err());
    }
}
