// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 (issue #3510) — the STRUCTURAL gate for `PRAGMA integrity_check`,
//! plus the migration-ladder proof that the control it funnels through is
//! actually load-bearing on a freshly migrated database.
//!
//! # The defect this gate makes unrepresentable
//!
//! `PRAGMA integrity_check` answering the single word `ok` stopped meaning
//! "every page in this file was examined". SQLite builds the check's root-page
//! list from the schema's table hash, every root-LESS object (a `VIEW`, a
//! `VIRTUAL TABLE`) contributes root page **0**, and `btree.c` reads a leading
//! zero as "this is a PARTIAL check" — skipping BOTH the freelist scan AND the
//! every-page-referenced pass while still answering `ok` (bundled SQLite
//! 3.46.0; see the module header of `src/storage/sqlite_integrity.rs` for the
//! quoted source). The schema v98 `inbox_namespace_aliases` VIEW (#3401) moved
//! a zero-root entry to the head of the ai-memory schema and `restore`
//! PUBLISHED a snapshot carrying unaccounted pages over the live corpus with
//! the #3131 gate reporting nothing.
//!
//! #3508 fixed the ONE call site that had already fired. #3510 makes the
//! class unrepresentable: the page-accounting control lives in
//! [`ai_memory::storage::sqlite_integrity`], and THIS gate asserts that every
//! production `PRAGMA integrity_check` in `src/**/*.rs` is inside that module.
//! A future surface that reaches for the raw PRAGMA — which reads perfectly
//! reasonable, and is exactly how `src/recover/durability.rs` acquired the
//! same latent fail-open — fails here instead of shipping.
//!
//! # NOT policed
//!
//! [`ai_memory::storage::fts_integrity_check`] is a DIFFERENT mechanism: the
//! FTS5 `'integrity-check'` command, which validates the full-text index
//! against the `memories` table. It does not go through
//! `PRAGMA integrity_check`, is not affected by the partial-check hazard, and
//! is deliberately left alone. The marker below is the literal PRAGMA text, so
//! the FTS command never matches it.
//!
//! # The two halves, and why both are needed
//!
//! A source-walking gate on its own can pass VACUOUSLY (M-TAUTOLOGICAL-TESTS:
//! a detector that never matches anything is green on every tree), so the
//! `detector_*` tests drive [`raw_pragma_sites`] over synthetic buffers. And a
//! detector proven to fire still says nothing about whether the helper it
//! funnels through DOES anything, so
//! [`a_freshly_migrated_database_is_page_accounted_not_partially_checked_3510`]
//! constructs the exact damage the partial check skips — unreferenced pages —
//! against a REAL migrated corpus and asserts the verdict is a refusal.

use std::path::{Path, PathBuf};

/// The literal this gate polices: the PRAGMA text at the START of a Rust
/// string literal, i.e. where it is handed to SQLite rather than merely NAMED.
///
/// Two exclusions are load-bearing, and both come from the #2629 SDK-gate
/// lesson that a path is a CLAIM only where it is a CALL. The FTS5
/// `'integrity-check'` command (a different mechanism, out of scope per #3510)
/// spells its verb with a hyphen and can never collide. And the operator-facing
/// `restore` consent line NAMES the pragma in prose — a gate that forbade
/// explaining the control would force the explanation out of the product.
const PRAGMA_MARKER: &str = "\"PRAGMA integrity_check";

/// The ONE module allowed to issue the PRAGMA — the shared whole-database
/// check every product surface routes through.
const CANONICAL_MODULE: &str = "src/storage/sqlite_integrity.rs";

/// Sanctioned sites outside [`CANONICAL_MODULE`], as `(path, fn name)`.
///
/// The single entry is the #3508 regression test, which must observe SQLite's
/// OWN verdict on a damaged file in order to assert against it: the test
/// asserts on the OBSERVED verdict so a future SQLite that restores the full
/// pass still passes, and it cannot do that through the helper (which is the
/// thing under test). It is a `#[cfg(test)]` site, so it never ships.
const ALLOWLISTED_SITES: [(&str, &str); 1] = [(
    "src/cli/backup.rs",
    "stage_and_verify_refuses_pages_integrity_check_no_longer_reports_3508",
)];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Dot-prefixed scratch files are never compiled (they are the
        // `scripts/check-*.sh` self-test fixtures).
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("*/")
}

/// Does this line START a function definition? Skips the leading
/// visibility/qualifier tokens and asks whether the next token is `fn`.
/// Line-based, like every sibling gate: brace counting mis-parses
/// `format!("{x}")`.
fn fn_name_at(line: &str) -> Option<&str> {
    let mut tokens = line.split_whitespace();
    loop {
        let token = tokens.next()?;
        if token == "fn" {
            break;
        }
        let is_qualifier = token == "async"
            || token == "unsafe"
            || token == "const"
            || token == "extern"
            || token == "pub"
            || token.starts_with("pub(")
            || token.starts_with('"');
        if !is_qualifier {
            return None;
        }
    }
    let rest = tokens.next()?;
    let name: &str = rest.split(['(', '<']).next().unwrap_or(rest);
    (!name.is_empty()).then_some(name)
}

/// The gate detector, factored out of the filesystem walk so the self-tests can
/// drive it over synthetic buffers (M-TAUTOLOGICAL-TESTS).
///
/// Returns one `"<line-number>: fn <name>"` entry per UNSANCTIONED raw
/// `PRAGMA integrity_check`.
fn raw_pragma_sites(rel_path: &str, source: &str) -> Vec<String> {
    if rel_path == CANONICAL_MODULE {
        return Vec::new();
    }
    let lines: Vec<&str> = source.lines().collect();
    let fn_starts: Vec<usize> = (0..lines.len())
        .filter(|&i| fn_name_at(lines[i]).is_some())
        .collect();

    let mut findings = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if is_comment_line(line.trim_start()) || !line.contains(PRAGMA_MARKER) {
            continue;
        }
        let Some(&start) = fn_starts.iter().rev().find(|&&s| s <= i) else {
            findings.push(format!("{}: <no enclosing fn>", i + 1));
            continue;
        };
        let name = fn_name_at(lines[start]).unwrap_or("<unnamed>");
        if ALLOWLISTED_SITES
            .iter()
            .any(|&(p, f)| p == rel_path && f == name)
        {
            continue;
        }
        findings.push(format!("{}: fn {name}", i + 1));
    }
    findings
}

/// THE GATE. Every `PRAGMA integrity_check` in `src/**/*.rs` is inside the ONE
/// shared module (or the single allowlisted regression test).
#[test]
fn every_integrity_check_call_site_is_the_shared_helper_3510() {
    let root = repo_root();
    let mut files = Vec::new();
    collect_rs_files(&root.join("src"), &mut files);
    assert!(!files.is_empty(), "no src/**/*.rs files found");

    let mut violations = Vec::new();
    for file in &files {
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(file.as_path())
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for finding in raw_pragma_sites(&rel, &source) {
            violations.push(format!("  {rel}:{finding}"));
        }
    }

    assert!(
        violations.is_empty(),
        "RAW `PRAGMA integrity_check` outside the shared helper (#3510):\n{}\n\n\
         A verdict of `ok` does NOT mean every page was examined: a root-less\n\
         schema object (a VIEW, a virtual table) downgrades SQLite's check to a\n\
         PARTIAL one that skips the freelist scan and the every-page-referenced\n\
         pass and still answers `ok` (#3508). Route the check through the ONE\n\
         implementation that re-asserts the skipped page accounting:\n\n  \
         match crate::storage::sqlite_integrity::check(&conn)? {{\n      \
         Soundness::Sound(coverage) => {{ /* say which control covered it */ }}\n      \
         Soundness::Unsound(reason) => {{ /* refuse, naming `reason` */ }}\n  \
         }}\n\n\
         `storage::fts_integrity_check` is a DIFFERENT mechanism (the FTS5\n\
         index-vs-table check) and is deliberately NOT policed here.",
        violations.join("\n")
    );
}

/// POSITIVE pin for the two product surfaces #3510 converted. If either
/// reverts to the raw PRAGMA the gate above still fires — this test names
/// WHICH one and why, so the failure is diagnosable rather than a wall of
/// paths.
#[test]
fn the_two_converted_surfaces_cite_the_shared_helper_3510() {
    let root = repo_root();
    for rel in ["src/cli/backup.rs", "src/recover/durability.rs"] {
        let source =
            std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        assert!(
            source.contains("sqlite_integrity::"),
            "{rel} must route its integrity verdict through \
             `storage::sqlite_integrity` (#3510)"
        );
    }
}

// ---------------------------------------------------------------------------
// The migration-ladder proof. The gate above says WHERE the check lives; this
// says the check DOES something on a freshly migrated database — the half a
// call-site census cannot cover.
// ---------------------------------------------------------------------------

/// A freshly migrated ai-memory database carries root-less schema objects
/// (`memories_fts`, the schema v98 `inbox_namespace_aliases` VIEW), so
/// SQLite's own `integrity_check` may run as a PARTIAL check on it. Construct
/// the exact damage that check skips — pages the file DECLARES but no b-tree,
/// freelist entry or reserved page accounts for — and assert the shared helper
/// REFUSES it.
///
/// Asserted against the OBSERVED SQLite verdict rather than a hard-coded
/// expectation, so this stays honest in both directions: if a future SQLite
/// (or a schema shuffle that moves the zero-root entry off the head) restores
/// the full pass, the primary verdict fires instead and the file is still
/// refused. Either way the invariant holds — a freshly migrated database's
/// integrity verdict is never a partial `ok`.
#[test]
fn a_freshly_migrated_database_is_page_accounted_not_partially_checked_3510() {
    use ai_memory::storage::sqlite_integrity::{Coverage, Soundness, check};

    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let path = tmp.path().to_path_buf();

    // A real migrated corpus at the current ladder tip.
    {
        let conn = ai_memory::db::open(&path).expect("open + migrate");
        let root_less: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type IN ('view', 'table') AND COALESCE(rootpage, 0) = 0",
                [],
                |r| r.get(0),
            )
            .expect("count root-less schema objects");
        assert!(
            root_less > 0,
            "the migrated ai-memory schema is expected to carry root-less \
             objects (memories_fts, the v98 inbox_namespace_aliases view); \
             without one the partial-check hazard would not apply and this \
             proof would be vacuous"
        );
        match check(&conn).expect("the check completes on a sound corpus") {
            Soundness::Sound(Coverage::WholeFileByPageAccounting(_)) => {}
            other => panic!(
                "a freshly migrated corpus must be sound AND covered by the \
                 page-accounting control, got {other:?}"
            ),
        }
    }

    // Now the damage the PARTIAL check skips: pages the header declares that
    // nothing references.
    append_unreferenced_pages(&path, 5);

    let observed: String = {
        let conn = ai_memory::db::open_read_only(&path).expect("reopen read-only");
        conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .expect("integrity_check answers")
    };
    let conn = ai_memory::db::open_read_only(&path).expect("reopen read-only");
    let verdict = check(&conn).expect("the check completes on a damaged corpus");
    match verdict {
        Soundness::Unsound(reason) => {
            if observed.eq_ignore_ascii_case("ok") {
                assert!(
                    reason.contains("are accounted for"),
                    "SQLite answered `ok` on a file carrying unreferenced pages \
                     (the #3508 PARTIAL check), so the page-accounting control \
                     must be the one refusing; got: {reason}"
                );
            } else {
                assert!(
                    reason.contains("FAILED PRAGMA integrity_check"),
                    "SQLite itself reported the damage ({observed}), so the \
                     primary verdict must be the one refusing; got: {reason}"
                );
            }
        }
        Soundness::Sound(coverage) => panic!(
            "a freshly migrated database carrying unreferenced pages must be \
             refused; SQLite answered `{observed}` and the shared helper \
             answered Sound({coverage:?}) — the integrity verdict is PARTIAL \
             and nothing re-asserts the skipped pass (#3508/#3510)"
        ),
    }
}

/// Make a real SQLite file carry unreferenced pages while it still opens and
/// answers schema queries: append whole pages and raise the header's page-count
/// field (offset 28), stamping the "version-valid-for" counter (offset 92) to
/// match the change counter (offset 24) so SQLite trusts the declared size.
/// Deterministic — unlike flipping bytes in a page whose role depends on the
/// layout of the day.
fn append_unreferenced_pages(path: &Path, pages: usize) {
    let mut bytes = std::fs::read(path).expect("read db file");
    let page_size = match u16::from_be_bytes([bytes[16], bytes[17]]) {
        1 => 65_536_usize,
        n => usize::from(n),
    };
    let declared = u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
    bytes.extend(std::iter::repeat_n(0u8, page_size * pages));
    let grown = declared + u32::try_from(pages).expect("page delta fits u32");
    bytes[28..32].copy_from_slice(&grown.to_be_bytes());
    let change_counter = [bytes[24], bytes[25], bytes[26], bytes[27]];
    bytes[92..96].copy_from_slice(&change_counter);
    std::fs::write(path, &bytes).expect("write damaged db file");
}

// ---------------------------------------------------------------------------
// Detector self-tests. Without these the gate above could pass VACUOUSLY — a
// detector that never matches anything is green on every tree
// (M-TAUTOLOGICAL-TESTS). Each case is a separate `#[test]` so a regression
// names the SHAPE it broke.
// ---------------------------------------------------------------------------

/// The probe path is never a real file; only the allowlist compares against it.
const PROBE: &str = "src/contrived.rs";

/// NAKED — a raw PRAGMA in a fresh product surface is caught.
#[test]
fn detector_catches_a_raw_pragma_in_a_new_surface_3510() {
    let src = r#"
fn some_new_health_probe(conn: &Connection) -> Result<bool> {
    let verdict: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    Ok(verdict == "ok")
}
"#;
    assert_eq!(
        raw_pragma_sites(PROBE, src).len(),
        1,
        "a raw PRAGMA integrity_check outside the shared helper must be caught"
    );
}

/// The CANONICAL module is spared — it is the one place the PRAGMA belongs.
#[test]
fn detector_spares_the_canonical_module_3510() {
    let src = r#"
pub fn check(conn: &Connection) -> Result<Soundness> {
    let verdict: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    Ok(Soundness::Sound(Coverage::WholeFileBySqlite))
}
"#;
    assert!(
        raw_pragma_sites(CANONICAL_MODULE, src).is_empty(),
        "the shared helper itself must be spared"
    );
}

/// A COMMENT naming the PRAGMA — every converted surface's doc comment does
/// exactly this — must not be a violation, or the gate would forbid explaining
/// itself.
#[test]
fn detector_spares_a_commented_mention_3510() {
    let src = r#"
/// The verdict comes from the shared helper; `PRAGMA integrity_check` alone
/// answers `ok` on a partially-checked file.
fn stage_and_verify(conn: &Connection) -> Result<()> {
    // A bare PRAGMA integrity_check would be the #3508 fail-open.
    crate::storage::sqlite_integrity::check(conn)
        .context("verifying the staged restore")?;
    Ok(())
}
"#;
    assert!(
        raw_pragma_sites(PROBE, src).is_empty(),
        "a commented mention of the PRAGMA is documentation, not a call site"
    );
}

/// The FTS5 `'integrity-check'` command is a DIFFERENT mechanism and is
/// explicitly out of scope (#3510). It must never be swept in.
#[test]
fn detector_spares_the_fts_integrity_command_3510() {
    let src = r#"
pub fn fts_integrity_check(conn: &Connection) -> Result<()> {
    conn.execute("INSERT INTO memories_fts(memories_fts) VALUES('integrity-check')", [])?;
    Ok(())
}
"#;
    assert!(
        raw_pragma_sites(PROBE, src).is_empty(),
        "the FTS5 index check is a different mechanism and must not be policed"
    );
}

/// PROSE — the operator-facing consent line NAMES the pragma inside a longer
/// sentence. It is a description, not a call, and forbidding it would push the
/// explanation of the control out of the product.
#[test]
fn detector_spares_prose_that_names_the_pragma_3510() {
    let src = r#"
fn confirm(out: &mut CliOutput<'_>) -> Result<()> {
    writeln!(
        out.stdout,
        "The current database is copied aside first, and the replacement is \
         published only if it passes PRAGMA integrity_check plus the page \
         accounting that check skips on this schema."
    )?;
    Ok(())
}
"#;
    assert!(
        raw_pragma_sites(PROBE, src).is_empty(),
        "prose NAMING the pragma is a description, not a call site"
    );
}

/// The ALLOWLIST is keyed on `(path, fn)`, so the same fn name in another file
/// is still a violation — the exemption cannot be laundered by copying a name.
#[test]
fn detector_allowlist_is_scoped_to_its_file_3510() {
    let src = r#"
fn stage_and_verify_refuses_pages_integrity_check_no_longer_reports_3508() {
    let verdict: String = probe.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
}
"#;
    assert!(
        raw_pragma_sites(ALLOWLISTED_SITES[0].0, src).is_empty(),
        "the allowlisted site in its own file must be spared"
    );
    assert_eq!(
        raw_pragma_sites(PROBE, src).len(),
        1,
        "the same fn name in a DIFFERENT file must NOT inherit the exemption"
    );
}
