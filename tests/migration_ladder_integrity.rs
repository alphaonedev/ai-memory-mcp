// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Runtime fail-closed assertion for the silent migration-ladder-collision
//! class (guardrail-D, 2x5-vote decision memory `b682c76a`).
//!
//! This is the `cargo test` twin of `scripts/check-migration-ladder.sh`: it
//! walks the ACTUAL on-disk migration ladder + the in-code
//! `MIGRATION_LADDER` matrix and asserts the same invariants, so a collision
//! (the #2036-vs-#2192 same-numeric-prefix shape) or a version/tip drift is
//! caught even if the shell gate is bypassed. DATA-INTEGRITY posture (North
//! Star): a mixed / ambiguous schema ladder is a corruption vector — this
//! test makes it a loud failing test, never a silent pass.
//!
//! The migration TEXT is the durable truth; enforcing that its ladder is
//! unambiguous is a first-order guardrail on that truth.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use ai_memory::storage::migration_meta::MIGRATION_LADDER;
use ai_memory::storage::migrations::current_schema_version;

const BACKENDS: [&str; 2] = ["sqlite", "postgres"];

/// Documented historical prefix gaps, mirroring `KNOWN_PREFIX_GAPS` in
/// `scripts/check-migration-ladder.sh`. `sqlite:48` — the removed
/// `0048_v58_recall_observations_identity.sql` (folded into an inline arm;
/// only a comment reference survives). A NEW gap still fails.
const KNOWN_PREFIX_GAPS: &[(&str, i64)] = &[("sqlite", 48)];

fn migrations_dir(backend: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("migrations")
        .join(backend)
}

/// `(numeric_prefix, filename)` for every `NNNN_*.sql` file in a backend dir.
fn ladder_files(backend: &str) -> Vec<(i64, String)> {
    let dir = migrations_dir(backend);
    let mut out: Vec<(i64, String)> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let is_sql = std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("sql"));
            if !is_sql {
                return None;
            }
            let prefix_str = name.split('_').next()?;
            let prefix: i64 = prefix_str.parse().ok()?;
            Some((prefix, name))
        })
        .collect();
    out.sort();
    out
}

/// Extract the schema version from the first `_vNN_` tag in a filename.
fn vtag_of(filename: &str) -> Option<i64> {
    let bytes = filename.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'_' && bytes[i + 1] == b'v' {
            let mut j = i + 2;
            let start = j;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            // Require the tag to be `_v<digits>_` (a following underscore).
            if j > start && j < bytes.len() && bytes[j] == b'_' {
                return filename[start..j].parse().ok();
            }
        }
        i += 1;
    }
    None
}

fn is_known_gap(backend: &str, prefix: i64) -> bool {
    KNOWN_PREFIX_GAPS
        .iter()
        .any(|&(b, p)| b == backend && p == prefix)
}

/// Rule (a): no two migration files in a backend share a numeric prefix — the
/// EXACT #2036/#2192 collision shape. This is THE structural guard.
#[test]
fn guardrail_d_no_duplicate_prefix_per_backend() {
    for backend in BACKENDS {
        let files = ladder_files(backend);
        let mut seen: BTreeSet<i64> = BTreeSet::new();
        for (prefix, name) in &files {
            assert!(
                seen.insert(*prefix),
                "guardrail-D [{backend}]: DUPLICATE migration prefix {prefix:04} \
                 (offender: {name}) — the #2036/#2192 same-prefix-different-name \
                 collision. Two files at one number = an ambiguous ladder that \
                 ships silently. Renumber one.",
            );
        }
    }
}

/// Rule (c): the migration-file prefix sequence is gap-free per backend
/// (outside the documented `KNOWN_PREFIX_GAPS`).
#[test]
fn guardrail_d_prefix_sequence_gap_free() {
    for backend in BACKENDS {
        let files = ladder_files(backend);
        let present: BTreeSet<i64> = files.iter().map(|(p, _)| *p).collect();
        if present.is_empty() {
            continue;
        }
        let min = *present.iter().next().unwrap();
        let max = *present.iter().next_back().unwrap();
        for p in min..=max {
            if present.contains(&p) || is_known_gap(backend, p) {
                continue;
            }
            panic!(
                "guardrail-D [{backend}]: GAP in migration prefix sequence at {p:04} \
                 (present {min:04}..{max:04}). A skipped number hides a lost/renamed \
                 migration; renumber contiguously or add it to KNOWN_PREFIX_GAPS.",
            );
        }
    }
}

/// Rule (b)+(c): the in-code `MIGRATION_LADDER` matrix has NO duplicate
/// version and is strictly monotonically increasing.
#[test]
fn guardrail_d_ladder_matrix_strictly_monotonic() {
    let mut prev: Option<i64> = None;
    for meta in MIGRATION_LADDER {
        if let Some(p) = prev {
            assert!(
                meta.version > p,
                "guardrail-D: MIGRATION_LADDER version {} is not strictly greater \
                 than the preceding {p} (duplicate or out-of-order ladder entry).",
                meta.version,
            );
        }
        prev = Some(meta.version);
    }
}

/// Rule (d): the ladder terminates at `CURRENT_SCHEMA_VERSION`, and the
/// highest-prefix migration file in EACH backend carries that same `vNN` tag
/// — cross-adapter tip agreement, in `cargo test`.
#[test]
fn guardrail_d_tip_agrees_with_current_schema_version() {
    let current = current_schema_version();

    let tail = MIGRATION_LADDER
        .last()
        .expect("MIGRATION_LADDER is non-empty")
        .version;
    assert_eq!(
        tail, current,
        "guardrail-D: MIGRATION_LADDER tail {tail} != CURRENT_SCHEMA_VERSION {current}.",
    );

    for backend in BACKENDS {
        let files = ladder_files(backend);
        let (tip_prefix, tip_name) = files
            .last()
            .unwrap_or_else(|| panic!("guardrail-D [{backend}]: no migration files found"));
        let tip_v = vtag_of(tip_name).unwrap_or_else(|| {
            panic!("guardrail-D [{backend}]: tip file {tip_name} carries no vNN tag")
        });
        assert_eq!(
            tip_v, current,
            "guardrail-D [{backend}]: highest-prefix file {tip_name} (prefix {tip_prefix:04}) \
             is v{tip_v} but CURRENT_SCHEMA_VERSION={current} — bump the const AND the \
             tip migration file in lockstep.",
        );
    }
}
