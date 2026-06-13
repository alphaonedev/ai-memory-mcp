// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Parity invariant — every `attest_level` string written by production code
// MUST parse via `AttestLevel::from_str`. Pins the canonical surface
// {unsigned, self_signed, peer_attested, signed_by_peer, daemon_signed}
// and prevents recurrence of the #1438 orphan `"signed"` literal
// downgrading silently to None at verify time.
//
// Approach: walks production sources for `attest_level = "..."` and
// `attest_level: "..."` and `, "<value>", Some` write-tuple shapes,
// extracts the literal, and asserts `AttestLevel::from_str` is `Some`.
//
// Production-vs-test boundary mirrors `scripts/check-vendor-literals.sh`:
// skip `*test*.rs` / `tests.rs` / lines at-or-below the first
// `mod tests {` / `pub mod tests {` occurrence in each file.

use ai_memory::models::AttestLevel;
use std::fs;
use std::path::Path;

const SRC_DIRS: &[&str] = &["src"];

/// Find the line number of the first `mod tests {` or `pub mod tests {`
/// in `content`, returning `usize::MAX` when absent.
fn tests_mod_boundary(content: &str) -> usize {
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("mod tests {")
            || trimmed.starts_with("pub mod tests {")
            || trimmed.starts_with("pub(crate) mod tests {")
            || trimmed.starts_with("pub(super) mod tests {")
        {
            return i;
        }
    }
    usize::MAX
}

fn is_skip_file(name: &str) -> bool {
    name.contains("test") || name == "tests.rs"
}

fn walk_rs_files(root: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = fs::read_dir(root) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk_rs_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs")
            && !is_skip_file(p.file_name().unwrap_or_default().to_string_lossy().as_ref())
        {
            out.push(p);
        }
    }
}

/// Extract literal strings from `attest_level = "X"` and
/// `attest_level: "X"` patterns on a production line.
fn extract_attest_level_literals(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    for marker in ["attest_level = \"", "attest_level: \""] {
        let mut rest = line;
        while let Some(idx) = rest.find(marker) {
            let after = &rest[idx + marker.len()..];
            if let Some(end) = after.find('"') {
                found.push(after[..end].to_string());
                rest = &after[end..];
            } else {
                break;
            }
        }
    }
    found
}

#[test]
fn every_production_attest_level_literal_parses_via_from_str() {
    let mut files = Vec::new();
    for dir in SRC_DIRS {
        walk_rs_files(Path::new(dir), &mut files);
    }
    assert!(
        !files.is_empty(),
        "expected to find production .rs files under src/"
    );

    let mut violations: Vec<String> = Vec::new();

    for path in &files {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        let boundary = tests_mod_boundary(&content);
        for (lineno, line) in content.lines().enumerate() {
            if lineno >= boundary {
                break;
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("///") {
                continue;
            }
            for lit in extract_attest_level_literals(line) {
                if AttestLevel::from_str(&lit).is_none() {
                    violations.push(format!(
                        "{}:{}: attest_level literal {:?} is NOT a valid AttestLevel variant",
                        path.display(),
                        lineno + 1,
                        lit
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Found {} attest_level literal(s) in production code that don't parse via \
         AttestLevel::from_str — every such write silently downgrades to None at \
         verify time. Canonical variants: unsigned, self_signed, peer_attested, \
         signed_by_peer, daemon_signed.\n\nViolations:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}

#[test]
fn attest_level_canonical_variants_round_trip() {
    for variant in [
        AttestLevel::Unsigned,
        AttestLevel::SelfSigned,
        AttestLevel::PeerAttested,
        AttestLevel::SignedByPeer,
        AttestLevel::DaemonSigned,
    ] {
        let s = variant.as_str();
        let parsed = AttestLevel::from_str(s)
            .unwrap_or_else(|| panic!("AttestLevel::from_str({s:?}) returned None — variant {variant:?} as_str() drifted from from_str arm"));
        assert_eq!(parsed.as_str(), s, "round-trip mismatch for {variant:?}");
    }
}
