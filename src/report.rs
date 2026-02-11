//! Compliance pack generation: JSON, LaTeX, and PDF reports.

use std::path::Path;
use std::process::Command;

use printpdf::{BuiltinFont, Mm, PdfDocument};
use serde::{Deserialize, Serialize};

use crate::error::{EscpeError, Result, ResultExt as _};
use crate::ledger::{LedgerEntry, LedgerMeta};

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompliancePackManifest {
    pub format: String,
    pub generated_at_utc: String,
    pub ledger: LedgerMeta,
    pub entry_count: usize,
    pub notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Compliance pack writer
// ---------------------------------------------------------------------------

pub fn write_compliance_pack(
    out_dir: &Path,
    ledger: &LedgerMeta,
    entries: &[LedgerEntry],
) -> Result<()> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| EscpeError::Report(format!("create out dir {}: {e}", out_dir.display())))?;

    let manifest = CompliancePackManifest {
        format: "E-SCPE compliance-pack v1".to_string(),
        generated_at_utc: crate::util::now_utc_rfc3339(),
        ledger: ledger.clone(),
        entry_count: entries.len(),
        notes: vec![
            "Offline reference pack: JSON + LaTeX + PDF.".to_string(),
            "PDF/A-2b XMP metadata is emitted alongside audit_report.pdf.".to_string(),
        ],
    };

    // JSON manifest.
    let manifest_path = out_dir.join("manifest.json");
    let manifest_json = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| EscpeError::Report(format!("serialize manifest: {e}")))?;
    std::fs::write(&manifest_path, manifest_json)
        .map_err(|e| EscpeError::Report(format!("write {}: {e}", manifest_path.display())))?;

    // JSON entries.
    let entries_path = out_dir.join("ledger_entries.json");
    let entries_json = serde_json::to_vec_pretty(entries)
        .map_err(|e| EscpeError::Report(format!("serialize entries: {e}")))?;
    std::fs::write(&entries_path, entries_json)
        .map_err(|e| EscpeError::Report(format!("write {}: {e}", entries_path.display())))?;

    // LaTeX report.
    let tex = render_latex_report(&manifest, entries);
    let tex_path = out_dir.join("audit_report.tex");
    std::fs::write(&tex_path, &tex)
        .map_err(|e| EscpeError::Report(format!("write {}: {e}", tex_path.display())))?;

    // Pure-Rust PDF (no external dependencies).
    let pdf_path = out_dir.join("audit_report.pdf");
    let pdf_bytes = build_audit_pdf(&manifest, entries);
    std::fs::write(&pdf_path, pdf_bytes)
        .map_err(|e| EscpeError::Report(format!("write {}: {e}", pdf_path.display())))?;

    // XMP metadata (PDF/A-2b sidecar).
    let xmp_path = out_dir.join("audit_report.xmp");
    let xmp = build_xmp_metadata(&manifest);
    std::fs::write(&xmp_path, xmp)
        .map_err(|e| EscpeError::Report(format!("write {}: {e}", xmp_path.display())))?;

    // Best-effort tectonic-based PDF (higher quality, if available).
    let _ = try_compile_pdf_with_tectonic(out_dir).ok();

    Ok(())
}

// ---------------------------------------------------------------------------
// LaTeX report
// ---------------------------------------------------------------------------

fn escape_tex(s: &str) -> String {
    s.replace('\\', "\\textbackslash{}")
        .replace('&', "\\&")
        .replace('%', "\\%")
        .replace('$', "\\$")
        .replace('#', "\\#")
        .replace('_', "\\_")
        .replace('{', "\\{")
        .replace('}', "\\}")
        .replace('~', "\\textasciitilde{}")
        .replace('^', "\\textasciicircum{}")
}

pub fn render_latex_report(manifest: &CompliancePackManifest, entries: &[LedgerEntry]) -> String {
    let mut out = String::new();
    out.push_str(
        r#"\documentclass[11pt]{article}
\usepackage[a4paper,margin=1in]{geometry}
\usepackage{longtable}
\usepackage{hyperref}
\begin{document}
"#,
    );
    out.push_str(&format!(
        "\\section*{{E-SCPE Audit Report}}\\noindent Generated at (UTC): {}\\\\\n",
        escape_tex(&manifest.generated_at_utc)
    ));
    out.push_str(&format!(
        "Ledger ID: {}\\\\\n",
        escape_tex(&manifest.ledger.ledger_id.to_string())
    ));
    out.push_str(&format!("Entries: {}\\\\\n", manifest.entry_count));
    out.push_str(&format!(
        "Software: E-SCPE v{}\\\\\n",
        escape_tex(crate::util::VERSION)
    ));

    out.push_str("\\subsection*{Entries (hash-chained, signed)}\n");
    out.push_str(
        r#"\begin{longtable}{r l l}
\textbf{Seq} & \textbf{Serial} & \textbf{Entry hash (SHA-256)}\\ \hline
"#,
    );
    for e in entries {
        out.push_str(&format!(
            "{} & {} & \\texttt{{{}}}\\\\\n",
            e.seq,
            escape_tex(&e.serial),
            escape_tex(&e.entry_hash_hex)
        ));
    }
    out.push_str("\\end{longtable}\n");
    out.push_str("\\end{document}\n");
    out
}

fn try_compile_pdf_with_tectonic(out_dir: &Path) -> Result<()> {
    let status = Command::new("tectonic")
        .arg("audit_report.tex")
        .current_dir(out_dir)
        .status()
        .ctx_report("invoke tectonic")?;
    if !status.success() {
        return Err(EscpeError::Report(format!(
            "tectonic failed with status {status}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PrintPDF-based PDF generation (fallback when tectonic unavailable)
// ---------------------------------------------------------------------------

fn build_audit_pdf(manifest: &CompliancePackManifest, entries: &[LedgerEntry]) -> Vec<u8> {
    let lines = build_pdf_lines(manifest, entries);
    let (doc, page1, layer1) =
        PdfDocument::new("E-SCPE Audit Report", Mm(210.0), Mm(297.0), "Layer 1");
    let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica).unwrap();
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold).unwrap();

    let mut current_page = page1;
    let mut layer = doc.get_page(current_page).get_layer(layer1);
    let mut y = 280.0_f64;
    let x = 15.0_f64;
    let line_height = 6.0_f64;

    for (bold, size, text) in lines {
        if y < 20.0 {
            let (new_page, new_layer) = doc.add_page(Mm(210.0), Mm(297.0), "Layer");
            current_page = new_page;
            layer = doc.get_page(current_page).get_layer(new_layer);
            y = 280.0;
        }
        let font = if bold { &font_bold } else { &font_regular };
        layer.use_text(text, size, Mm(x), Mm(y), font);
        y -= line_height;
    }

    let mut buffer = Vec::new();
    let mut writer = std::io::BufWriter::new(&mut buffer);
    if doc.save(&mut writer).is_err() {
        return Vec::new();
    }
    drop(writer);
    buffer
}

fn build_pdf_lines(
    manifest: &CompliancePackManifest,
    entries: &[LedgerEntry],
) -> Vec<(bool, f64, String)> {
    let mut lines: Vec<(bool, f64, String)> = Vec::new();
    lines.push((true, 16.0, "E-SCPE Audit Report".to_string()));
    lines.push((false, 10.0, String::new()));
    lines.push((false, 10.0, format!("Generated: {}", manifest.generated_at_utc)));
    lines.push((false, 10.0, format!("Ledger ID: {}", manifest.ledger.ledger_id)));
    lines.push((false, 10.0, format!("Total entries: {}", manifest.entry_count)));
    lines.push((false, 10.0, format!("Software: E-SCPE v{}", crate::util::VERSION)));
    lines.push((false, 10.0, String::new()));
    lines.push((true, 12.0, "Entries".to_string()));
    lines.push((true, 9.0, format!("{:<6} {:<30} {}", "Seq", "Serial", "Entry Hash (SHA-256)")));

    for e in entries {
        let hash_short = if e.entry_hash_hex.len() > 48 {
            &e.entry_hash_hex[..48]
        } else {
            &e.entry_hash_hex
        };
        lines.push((false, 9.0, format!(
            "{:<6} {:<30} {}",
            e.seq,
            truncate_str(&e.serial, 28),
            hash_short
        )));
    }

    lines.push((false, 10.0, String::new()));
    lines.push((false, 8.0, "This report was generated by E-SCPE. Hash chain integrity can be verified offline.".to_string()));
    lines
}

fn build_xmp_metadata(manifest: &CompliancePackManifest) -> String {
    format!(
        r#"<?xpacket begin=" " id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about=""
        xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/"
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:xmp="http://ns.adobe.com/xap/1.0/">
      <pdfaid:part>2</pdfaid:part>
      <pdfaid:conformance>B</pdfaid:conformance>
      <dc:title>
        <rdf:Alt>
          <rdf:li xml:lang="x-default">E-SCPE Audit Report</rdf:li>
        </rdf:Alt>
      </dc:title>
      <xmp:CreatorTool>E-SCPE</xmp:CreatorTool>
      <xmp:CreateDate>{}</xmp:CreateDate>
      <xmp:ModifyDate>{}</xmp:ModifyDate>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#,
        manifest.generated_at_utc, manifest.generated_at_utc
    )
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn sample_manifest() -> CompliancePackManifest {
        CompliancePackManifest {
            format: "test".into(),
            generated_at_utc: "2025-01-01T00:00:00Z".into(),
            ledger: LedgerMeta {
                ledger_id: Uuid::new_v4(),
                created_at_utc: "2025-01-01T00:00:00Z".into(),
                schema_version: 1,
                sqlcipher_cipher_version: None,
            },
            entry_count: 0,
            notes: vec![],
        }
    }

    #[test]
    fn latex_escape_special_chars() {
        let escaped = escape_tex("foo_bar & 100% $x$ #1 {ok}");
        assert!(escaped.contains("\\_"));
        assert!(escaped.contains("\\&"));
        assert!(escaped.contains("\\%"));
        assert!(escaped.contains("\\$"));
        assert!(escaped.contains("\\#"));
        assert!(escaped.contains("\\{"));
        assert!(escaped.contains("\\}"));
    }

    #[test]
    fn latex_report_contains_header() {
        let manifest = sample_manifest();
        let report = render_latex_report(&manifest, &[]);
        assert!(report.contains("E-SCPE Audit Report"));
        assert!(report.contains("\\begin{document}"));
        assert!(report.contains("\\end{document}"));
    }

    #[test]
    fn pdf_generation_produces_valid_header() {
        let manifest = sample_manifest();
        let pdf = build_audit_pdf(&manifest, &[]);
        assert!(pdf.starts_with(b"%PDF-"));
        assert!(pdf.windows(5).any(|w| w == b"%%EOF"));
    }

    #[test]
    fn pdf_generation_with_entries() {
        let manifest = CompliancePackManifest {
            entry_count: 2,
            ..sample_manifest()
        };
        let entries = vec![
            LedgerEntry {
                seq: 1,
                ts_utc: "2025-01-01T00:00:00Z".into(),
                serial: "SER-001".into(),
                payload_json: "{}".into(),
                payload_hash_hex: "a".repeat(64),
                prev_hash_hex: "0".repeat(64),
                entry_hash_hex: "b".repeat(64),
                signature_b64: "sig".into(),
                signer: crate::signing::SignerDescriptor {
                    key_id: "kid".into(),
                    kind: "test".into(),
                },
            },
            LedgerEntry {
                seq: 2,
                ts_utc: "2025-01-01T00:00:01Z".into(),
                serial: "SER-002".into(),
                payload_json: "{}".into(),
                payload_hash_hex: "c".repeat(64),
                prev_hash_hex: "b".repeat(64),
                entry_hash_hex: "d".repeat(64),
                signature_b64: "sig2".into(),
                signer: crate::signing::SignerDescriptor {
                    key_id: "kid".into(),
                    kind: "test".into(),
                },
            },
        ];
        let pdf = build_audit_pdf(&manifest, &entries);
        assert!(pdf.starts_with(b"%PDF-"));
        assert!(!pdf.is_empty());
    }

    #[test]
    fn truncate_str_short() {
        assert_eq!(truncate_str("abc", 10), "abc");
    }

    #[test]
    fn truncate_str_long() {
        let s = "a".repeat(50);
        let t = truncate_str(&s, 10);
        assert!(t.len() <= 10);
        assert!(t.ends_with("..."));
    }
}
