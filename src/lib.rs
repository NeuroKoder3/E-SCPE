//! Entanglement-Enhanced Supply-Chain Provenance Engine (E-SCPE)
//!
//! This crate provides:
//! - CHSH/Bell-inequality verification over scanned quantum-tag data
//! - An append-only, hash-chained SQLite ledger (SQLCipher-compatible)
//! - Offline-capable signing/verification primitives
//! - Hardware-bound licensing with Ed25519 signatures
//! - Compliance pack generation (JSON + LaTeX + PDF)
//! - C-ABI FFI exports for integration with WinUI / any native caller
//!
//! The CLI wrapper lives in `src/main.rs`.

#![deny(unsafe_code)]

pub mod error;
pub mod config;

pub mod chsh;
pub mod ledger;
pub mod license;
pub mod report;
pub mod signing;
pub mod tag;
pub mod util;

#[allow(unsafe_code)]
pub mod ffi;
