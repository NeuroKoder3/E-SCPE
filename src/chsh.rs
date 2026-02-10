//! CHSH/Bell-inequality verification.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::tag::TagScan;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChshResult {
    pub s: f64,
    pub threshold: f64,
    pub passed: bool,
    pub e_a0b0: f64,
    pub e_a0b1: f64,
    pub e_a1b0: f64,
    pub e_a1b1: f64,
}

/// Compute the CHSH statistic:
///   S = E(A0,B0) + E(A0,B1) + E(A1,B0) - E(A1,B1)
///
/// Returns an error if any expectation value cannot be computed
/// (e.g. zero coincidence counts) or if the threshold is out of range.
pub fn compute_chsh(scan: &TagScan, threshold: f64) -> Result<ChshResult> {
    crate::util::validate_chsh_threshold(threshold)?;

    let e00 = scan.a0b0.expectation()?;
    let e01 = scan.a0b1.expectation()?;
    let e10 = scan.a1b0.expectation()?;
    let e11 = scan.a1b1.expectation()?;
    let s = e00 + e01 + e10 - e11;
    Ok(ChshResult {
        s,
        threshold,
        passed: s > threshold,
        e_a0b0: e00,
        e_a0b1: e01,
        e_a1b0: e10,
        e_a1b1: e11,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tag::CoincidenceCounts;
    use uuid::Uuid;

    fn counts_for_e(e: f64) -> CoincidenceCounts {
        let total: u64 = 2000;
        let p_same = (1.0 + e) / 2.0;
        let same = ((total as f64) * p_same).round() as u64;
        let diff = total.saturating_sub(same);
        CoincidenceCounts {
            pp: same / 2,
            mm: same - (same / 2),
            pm: diff / 2,
            mp: diff - (diff / 2),
        }
    }

    fn make_scan(e00: f64, e01: f64, e10: f64, e11: f64) -> TagScan {
        TagScan {
            scan_id: Uuid::new_v4(),
            serial: "TEST-123".to_string(),
            scanned_at_utc: crate::util::now_utc_rfc3339(),
            a0b0: counts_for_e(e00),
            a0b1: counts_for_e(e01),
            a1b0: counts_for_e(e10),
            a1b1: counts_for_e(e11),
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn passes_for_high_visibility() {
        let base = std::f64::consts::FRAC_1_SQRT_2;
        let scan = make_scan(base, base, base, -base);
        let res = compute_chsh(&scan, 2.0).unwrap();
        assert!(res.passed);
        assert!(res.s > 2.5);
    }

    #[test]
    fn fails_below_threshold() {
        // Classical-like correlations: all expectations ~0.5
        let scan = make_scan(0.5, 0.5, 0.5, 0.5);
        let res = compute_chsh(&scan, 2.0).unwrap();
        assert!(!res.passed);
    }

    #[test]
    fn threshold_out_of_range() {
        let scan = make_scan(0.5, 0.5, 0.5, -0.5);
        assert!(compute_chsh(&scan, 5.0).is_err());
        assert!(compute_chsh(&scan, -1.0).is_err());
    }

    #[test]
    fn threshold_boundary_value() {
        let scan = make_scan(0.5, 0.5, 0.5, -0.5);
        // S = 0.5+0.5+0.5-(-0.5) = 2.0, threshold=2.0, NOT strictly greater
        let res = compute_chsh(&scan, 2.0).unwrap();
        assert!(!res.passed); // requires S > threshold, not >=
    }
}
