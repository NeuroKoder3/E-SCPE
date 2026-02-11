//! Quantum-tag data structures and the simulated tag reader.

use rand::{Rng as _, SeedableRng as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{EscpeError, Result};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CoincidenceCounts {
    pub pp: u64,
    pub pm: u64,
    pub mp: u64,
    pub mm: u64,
}

impl CoincidenceCounts {
    pub fn total(&self) -> u64 {
        self.pp + self.pm + self.mp + self.mm
    }

    /// Expectation value E = <ab> for outcomes in {+1,-1}.
    pub fn expectation(&self) -> Result<f64> {
        let n = self.total();
        if n == 0 {
            return Err(EscpeError::Chsh("zero total counts".into()));
        }
        let num = (self.pp as i128 + self.mm as i128) - (self.pm as i128 + self.mp as i128);
        Ok((num as f64) / (n as f64))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagScan {
    pub scan_id: Uuid,
    pub serial: String,
    pub scanned_at_utc: String,

    pub a0b0: CoincidenceCounts,
    pub a0b1: CoincidenceCounts,
    pub a1b0: CoincidenceCounts,
    pub a1b1: CoincidenceCounts,

    /// Optional opaque metadata produced by a proprietary reader/driver.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Tag reader trait (hardware abstraction)
// ---------------------------------------------------------------------------

/// Trait that every tag reader driver must implement.
///
/// In production, this is backed by a USB/PCIe vendor SDK via Rust FFI.
/// For development and CI, [`SimulatedTagReader`] provides deterministic
/// output consistent with a configurable entanglement visibility.
pub trait TagReader {
    fn scan(&mut self, serial: &str) -> Result<TagScan>;
}

// ---------------------------------------------------------------------------
// Simulated reader
// ---------------------------------------------------------------------------

/// A deterministic simulated reader for development and CI.
#[derive(Debug)]
pub struct SimulatedTagReader {
    /// Total coincidence counts per setting.
    pub counts_per_setting: u64,
    /// Visibility multiplier in [0, 1]; 1 approximates maximal entanglement.
    pub visibility: f64,
    /// Random jitter applied to each setting's expectation.
    pub jitter: f64,
    rng: rand::rngs::StdRng,
}

impl Default for SimulatedTagReader {
    fn default() -> Self {
        Self::new(0xE5C0E_u64)
    }
}

impl SimulatedTagReader {
    pub fn new(seed: u64) -> Self {
        Self {
            counts_per_setting: 2000,
            visibility: 0.95,
            jitter: 0.02,
            rng: rand::rngs::StdRng::seed_from_u64(seed),
        }
    }

    fn gen_counts_for_expectation(&mut self, e: f64) -> CoincidenceCounts {
        let n = self.counts_per_setting as f64;
        let e = e.clamp(-0.999_999, 0.999_999);
        let p_same = (1.0 + e) / 2.0;

        let same = (n * p_same).round() as i64;
        let diff = (n * (1.0 - p_same)).round() as i64;

        let mut pp = same / 2;
        let pm = diff / 2;
        let mp = diff - pm;

        let tweak = (self.rng.random::<f64>() - 0.5) * 0.02 * n;
        let tweak = tweak.round() as i64;
        pp = (pp + tweak).clamp(0, same);
        let mm = same - pp;

        CoincidenceCounts {
            pp: pp as u64,
            pm: pm.max(0) as u64,
            mp: mp.max(0) as u64,
            mm: mm as u64,
        }
    }

    fn target_expectations(&mut self) -> (f64, f64, f64, f64) {
        let base = std::f64::consts::FRAC_1_SQRT_2 * self.visibility;
        let mut e00 = base;
        let mut e01 = base;
        let mut e10 = base;
        let mut e11 = -base;

        let j = self.jitter.abs();
        let mut jitter = || (self.rng.random::<f64>() - 0.5) * 2.0 * j;
        e00 += jitter();
        e01 += jitter();
        e10 += jitter();
        e11 += jitter();
        (e00, e01, e10, e11)
    }
}

impl TagReader for SimulatedTagReader {
    fn scan(&mut self, serial: &str) -> Result<TagScan> {
        let serial = serial.trim();
        // Validate serial format.
        crate::util::validate_serial(serial)?;

        let (e00, e01, e10, e11) = self.target_expectations();
        let a0b0 = self.gen_counts_for_expectation(e00);
        let a0b1 = self.gen_counts_for_expectation(e01);
        let a1b0 = self.gen_counts_for_expectation(e10);
        let a1b1 = self.gen_counts_for_expectation(e11);

        // Sanity-check the generated data.
        let _ = a0b0.expectation()?;
        let _ = a0b1.expectation()?;
        let _ = a1b0.expectation()?;
        let _ = a1b1.expectation()?;

        Ok(TagScan {
            scan_id: Uuid::new_v4(),
            serial: serial.to_string(),
            scanned_at_utc: crate::util::now_utc_rfc3339(),
            a0b0,
            a0b1,
            a1b0,
            a1b1,
            metadata: serde_json::json!({
                "reader": "simulated",
                "counts_per_setting": self.counts_per_setting,
                "visibility": self.visibility,
                "jitter": self.jitter,
            }),
        })
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulated_reader_deterministic() {
        let mut r1 = SimulatedTagReader::new(42);
        let mut r2 = SimulatedTagReader::new(42);
        let s1 = r1.scan("SERIAL-A").unwrap();
        let s2 = r2.scan("SERIAL-A").unwrap();
        assert_eq!(s1.a0b0.pp, s2.a0b0.pp);
        assert_eq!(s1.a1b1.mm, s2.a1b1.mm);
    }

    #[test]
    fn empty_serial_rejected() {
        let mut r = SimulatedTagReader::default();
        assert!(r.scan("").is_err());
    }

    #[test]
    fn invalid_serial_rejected() {
        let mut r = SimulatedTagReader::default();
        assert!(r.scan("has space").is_err());
    }

    #[test]
    fn counts_are_positive() {
        let mut r = SimulatedTagReader::default();
        let s = r.scan("VALID-123").unwrap();
        assert!(s.a0b0.total() > 0);
        assert!(s.a0b1.total() > 0);
        assert!(s.a1b0.total() > 0);
        assert!(s.a1b1.total() > 0);
    }

    #[test]
    fn expectation_value_in_range() {
        let mut r = SimulatedTagReader::default();
        let s = r.scan("VALID-123").unwrap();
        let e = s.a0b0.expectation().unwrap();
        assert!((-1.0..=1.0).contains(&e));
    }

    #[test]
    fn zero_counts_error() {
        let c = CoincidenceCounts {
            pp: 0,
            pm: 0,
            mp: 0,
            mm: 0,
        };
        assert!(c.expectation().is_err());
    }
}
