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

/// Const-phrased ladder-arm cohort pins — the `cargo test` twin of the
/// `EXPECTED_CONST_ARMS_*` pins in `scripts/check-migration-ladder.sh` (#2198,
/// Fable audit of #2197). The TAIL migration arms gate on the symbolic
/// `CURRENT_SCHEMA_VERSION` rather than a literal, so they are INVISIBLE to a
/// literal-`N` duplicate/monotonic scan (that is the arm-lane escape the audit
/// demonstrated). Pin the exact count so a silent add moves it and fails; bump
/// in lockstep with a dated comment (and the shell-gate pin), the same
/// discipline as the `qual_10` module-size ceilings.
/// 2026-07-18 (#2198): sqlite=8, postgres=1.
const EXPECTED_CONST_ARMS_SQLITE: usize = 8;
const EXPECTED_CONST_ARMS_POSTGRES: usize = 1;

/// Read a repo-relative source file (the migration ladder sources) to a String.
fn read_src(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Walk the ladder arms of a migration source file, classifying each
/// `if <var> < … {` arm. Returns `(literal_and_resolved_versions, bare_const_count)`:
/// literal `if <var> < N {` and arithmetic `if <var> < CURRENT_SCHEMA_VERSION ± K {`
/// arms resolve to a concrete version (the NORMALIZATION pass); bare
/// `if <var> < CURRENT_SCHEMA_VERSION {` arms are the count-pinned tip cohort.
/// Mirrors the shell gate's `collect_literal_arm_versions` +
/// `count_bare_const_arms` + `collect_resolved_arithmetic_arms`.
fn scan_arms(src: &str, var: &str, csv: i64) -> (Vec<i64>, usize) {
    let prefix = format!("if {var} < ");
    let mut literals: Vec<i64> = Vec::new();
    let mut const_count = 0usize;
    for line in src.lines() {
        let t = line.trim();
        if !t.starts_with(&prefix) || !t.ends_with('{') {
            continue;
        }
        // Strip the `if <var> < ` prefix and the trailing `{`.
        let middle = t[prefix.len()..t.len() - 1].trim();
        if let Ok(n) = middle.parse::<i64>() {
            literals.push(n);
        } else if middle == "CURRENT_SCHEMA_VERSION" {
            const_count += 1;
        } else if let Some(rest) = middle.strip_prefix("CURRENT_SCHEMA_VERSION") {
            // Arithmetic form `CURRENT_SCHEMA_VERSION - K` / `+ K` — resolve.
            let rest = rest.trim();
            if let Some(k) = rest
                .strip_prefix('-')
                .and_then(|s| s.trim().parse::<i64>().ok())
            {
                literals.push(csv - k);
            } else if let Some(k) = rest
                .strip_prefix('+')
                .and_then(|s| s.trim().parse::<i64>().ok())
            {
                literals.push(csv + k);
            }
        }
    }
    (literals, const_count)
}

/// Every numeric version that appears in a `fn migrate_v<digits>` definition —
/// the BROADENED scan that also catches a name-variant like `migrate_v85_extra`
/// (precedent in-tree: `migrate_v29_stamp`) which the exact-name `fn migrate_vN(`
/// dup regex misses. Mirrors the shell gate's rule-(b3) numeric-dup scan.
fn migrate_fn_versions(src: &str) -> Vec<i64> {
    const NEEDLE: &str = "fn migrate_v";
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(pos) = rest.find(NEEDLE) {
        let after = &rest[pos + NEEDLE.len()..];
        let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(n) = digits.parse::<i64>() {
            out.push(n);
        }
        rest = after;
    }
    out
}

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

/// Rule (b) arm-lane hardening (#2198): the sqlite ladder's const-phrased tip
/// cohort is count-pinned, and no literal / resolved-arithmetic arm may sit AT
/// OR ABOVE `CURRENT_SCHEMA_VERSION` (which would duplicate the const-phrased
/// tip). This is the runtime twin of the shell gate's rule (b1)+(b2) — it fails
/// even if the shell gate is bypassed. Catches the D1a (extra const arm) and
/// D1b (literal duplicate of the const tip) escapes.
#[test]
fn guardrail_d_sqlite_arm_lane_const_phrase_hardened() {
    let current = current_schema_version();
    let src = read_src("src/storage/migrations.rs");
    let (literals, const_count) = scan_arms(&src, "version", current);

    assert_eq!(
        const_count, EXPECTED_CONST_ARMS_SQLITE,
        "guardrail-D [sqlite]: bare `if version < CURRENT_SCHEMA_VERSION {{` arm count is \
         {const_count} but the pin is {EXPECTED_CONST_ARMS_SQLITE} — a const-phrased tail arm \
         (invisible to the literal-arm scan) was added or removed. Renumber the previous tip arm \
         to a literal, or bump EXPECTED_CONST_ARMS_SQLITE in lockstep with a dated comment \
         (and the shell-gate pin in scripts/check-migration-ladder.sh).",
    );

    for v in &literals {
        assert!(
            *v < current,
            "guardrail-D [sqlite]: ladder arm `if version < {v}` is at/above \
             CURRENT_SCHEMA_VERSION={current} — it duplicates the const-phrased tip cohort. \
             Renumber below the tip, or bump the const AND the tip migration in lockstep.",
        );
    }
}

/// Rule (b) arm-lane hardening (#2198): the postgres twin of the sqlite check —
/// the `if current_version < …` const-phrased cohort is count-pinned + ceiling-
/// checked, AND `fn migrate_v<N>` versions are unique even under a name-variant
/// like `migrate_v85_extra` (rule b3). Catches the D2 escape.
#[test]
fn guardrail_d_postgres_arm_lane_const_phrase_hardened() {
    let current = current_schema_version();
    let src = read_src("src/store/postgres.rs");
    let (literals, const_count) = scan_arms(&src, "current_version", current);

    assert_eq!(
        const_count, EXPECTED_CONST_ARMS_POSTGRES,
        "guardrail-D [postgres]: bare `if current_version < CURRENT_SCHEMA_VERSION {{` arm count \
         is {const_count} but the pin is {EXPECTED_CONST_ARMS_POSTGRES} — bump \
         EXPECTED_CONST_ARMS_POSTGRES in lockstep with a dated comment (and the shell-gate pin), \
         or renumber the previous tip arm to a literal.",
    );

    for v in &literals {
        assert!(
            *v < current,
            "guardrail-D [postgres]: ladder arm `if current_version < {v}` is at/above \
             CURRENT_SCHEMA_VERSION={current} — it duplicates the const-phrased tip cohort.",
        );
    }

    // Rule (b3): no duplicate migrate fn VERSION, even across name-variants.
    let mut seen: BTreeSet<i64> = BTreeSet::new();
    for v in migrate_fn_versions(&src) {
        assert!(
            seen.insert(v),
            "guardrail-D [postgres]: DUPLICATE `fn migrate_v{v}` VERSION — a name-variant like \
             `fn migrate_v{v}_extra(` escapes the exact-name dup check but still corrupts the \
             ladder tip. Renumber one.",
        );
    }
}

/// Fail-closed mirror (#2198): the shell gate FLAGS a `.sql` migration file that
/// does not match the `NNNN_*` convention, but `ladder_files` above silently
/// DROPS it (the `filter_map` parse). Assert directly that every `.sql` file in
/// each backend dir carries a 4-digit numeric prefix, so a non-convention file
/// cannot slip past the runtime twin the way it would past `ladder_files`.
#[test]
fn guardrail_d_all_sql_files_follow_nnnn_convention() {
    for backend in BACKENDS {
        let dir = migrations_dir(backend);
        for entry in
            fs::read_dir(&dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        {
            let entry = entry.expect("dir entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_sql = std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("sql"));
            if !is_sql {
                continue;
            }
            let prefix = name.split('_').next().unwrap_or("");
            let ok = prefix.len() == 4 && prefix.bytes().all(|b| b.is_ascii_digit());
            assert!(
                ok,
                "guardrail-D [{backend}]: migration file {name} does not match the `NNNN_*` \
                 convention. The shell gate flags this, but the runtime `ladder_files` scan would \
                 silently drop it — fail closed instead.",
            );
        }
    }
}
