// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2515 (GA Wave-1 data-integrity blocker) — the TTL-FLOOR STATIC
//! GUARD for LOCAL memory write funnels.
//!
//! ## The defect this pins closed
//!
//! Every LOCAL create/upsert funnel merges an incoming row onto an existing
//! `(title, namespace)` row via `INSERT … ON CONFLICT … DO UPDATE`. The
//! `expires_at` arm used to be the bare lattice-BLIND form
//!
//! ```text
//! expires_at = CASE WHEN … tier = 'long' … THEN NULL
//!                   ELSE COALESCE(excluded.expires_at, memories.expires_at) END
//! ```
//!
//! which adopts the INCOMING row's expiry verbatim. Re-storing the same
//! `(title, namespace)` with an EARLIER expiry therefore silently rolled a
//! live row's TTL BACKWARDS — a #1596 never-move-expiry-earlier violation and
//! unintentional DATA LOSS (premature GC reap → permanent link-edge loss under
//! the v70 auto-eviction posture). The North Star forbids exactly this: a
//! re-store may FLOOR a TTL (extend / keep), never SHORTEN it.
//!
//! The shipped #2335 federation `apply_remote_memory` mirror already floors
//! expiry with the tier-aware lattice join
//!
//! ```text
//! expires_at = CASE WHEN … tier = 'long' … THEN NULL
//!                   ELSE <MAX|GREATEST>(COALESCE(excluded.expires_at, memories.expires_at),
//!                                       COALESCE(memories.expires_at, excluded.expires_at)) END
//! ```
//!
//! (`MAX` on sqlite, `GREATEST` on postgres — a commutative/idempotent CRDT
//! join). #2515 applies that SAME floor to every LOCAL write funnel:
//! `storage::insert_inner` (sqlite) and the five postgres funnels
//! (`store`, `store_batch`, `capture_turn_idempotent`,
//! `recover_turn_idempotent`, `store_with_embedding_inner`).
//!
//! ## Why a source-inspection guard
//!
//! The regression is invisible without a live merge race, and the postgres
//! arms need a real database to observe at all. This guard closes the class
//! MECHANICALLY the way the `append_only_spine_guard_g6` family does: it reads
//! every production `.rs` off disk, strips BOTH Rust (`//`, `/* */`) AND SQL
//! (`--`) comments — the guard inspects EXECUTABLE SQL only, never prose that
//! happens to quote the forbidden token — and forbids the EXCLUDED-first bare
//! floor `COALESCE(excluded.expires_at, memories.expires_at)` unless it is
//! immediately wrapped by `MAX(` / `GREATEST(` (i.e. it is the floored lattice
//! join). A newly-added bare funnel re-reds
//! [`no_bare_coalesce_expiry_floor_on_local_write_funnels_2515`].
//!
//! ## Honest scope
//!
//! * The EXPLICIT-shortening `memory_update` / `db::update` path is DELIBERATELY
//!   out of scope: it spells expiry `COALESCE($N, expires_at)` (a positional
//!   bind, NOT an `excluded.`-referencing merge), so this guard's EXCLUDED-first
//!   needle never matches it. That path is the ONLY sanctioned TTL-shortener.
//! * The archive-restore `COALESCE(original_expires_at, expires_at)` projection
//!   is likewise not an `excluded.`-referencing floor and never matches.
//! * The canonical floored form keeps the `MAX(` / `GREATEST(` wrapper on the
//!   SAME source line as the wrapped `COALESCE` (matching both #2335 mirrors);
//!   splitting the wrapper onto its own line trips this guard (fail-CLOSED /
//!   over-strict — it forces the canonical single-line form, never a silent
//!   pass of a bare floor).

#![allow(clippy::missing_panics_doc)]

use std::path::{Path, PathBuf};

/// Recursively visit every `.rs` file under `dir`. Copied (not shared) from the
/// `append_only_spine_guard_g6` helper — an integration test links the crate as
/// an external library and cannot reach `#[cfg(test)]`-private helpers.
fn walk_rs_files(dir: &Path, visit: &mut dyn FnMut(&Path, &str)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs_files(&path, visit);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs")
            && let Ok(contents) = std::fs::read_to_string(&path)
        {
            visit(&path, &contents);
        }
    }
}

/// Strip Rust line comments (`//…`), single-line block comments (`/* … */`),
/// AND SQL line comments (`--…`), preserving line structure (one output line
/// per input line) so a reported line number maps to the SAME line as the raw
/// source. SQL `--` comments live INSIDE the Rust SQL string literals and are
/// not executed, so a `-- COALESCE(excluded.expires_at, …)` explanatory
/// comment must NOT be scanned as if it were live SQL. `--` always begins a
/// comment-to-EOL in both sqlite and postgres, so trimming from its first
/// occurrence is safe for this class of file (no SQL string literal in these
/// upsert templates embeds a literal `--`).
fn strip_all_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let mut buf = match line.find("//") {
            Some(idx) => line[..idx].to_string(),
            None => line.to_string(),
        };
        while let (Some(start), Some(end_rel)) = (buf.find("/*"), buf.find("*/").map(|i| i + 2)) {
            if end_rel <= start {
                break;
            }
            buf.replace_range(start..end_rel, "");
        }
        if let Some(idx) = buf.find("--") {
            buf.truncate(idx);
        }
        out.push_str(&buf);
        out.push('\n');
    }
    out
}

/// The EXCLUDED-first bare floor, whitespace-collapsed + lowercased. The
/// #2335 floored form places this EXACT token immediately after `MAX(` /
/// `GREATEST(`; the bare (forbidden) form places it after `ELSE`. The
/// arg-REVERSED partner `COALESCE(memories.expires_at, excluded.expires_at)`
/// (the second operand of the floor) deliberately does NOT match this needle,
/// so the floored form yields exactly one match — the wrapped one.
const EXCLUDED_FIRST_COALESCE: &str = "coalesce(excluded.expires_at, memories.expires_at)";

/// A single forbidden hit: `src/…:LINE` plus the offending trimmed line.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BareFloorSite {
    file_line: String,
    snippet: String,
}

/// Does `line` contain the EXCLUDED-first `COALESCE(...)` floor NOT wrapped by
/// `MAX(` / `GREATEST(`? Operates on ONE comment-stripped line: the canonical
/// floored form keeps the wrapper on the same line as the `COALESCE`, so a
/// same-line lookbehind is sufficient and a wrapper split across lines fails
/// CLOSED (flags as bare).
fn line_has_bare_excluded_floor(line: &str) -> bool {
    let collapsed = line.split_whitespace().collect::<Vec<_>>().join(" ");
    let low = collapsed.to_ascii_lowercase();
    let mut from = 0;
    while let Some(rel) = low[from..].find(EXCLUDED_FIRST_COALESCE) {
        let start = from + rel;
        from = start + EXCLUDED_FIRST_COALESCE.len();
        let before = low[..start].trim_end();
        if !(before.ends_with("max(") || before.ends_with("greatest(")) {
            return true;
        }
    }
    false
}

/// Scan every production `.rs` under `src/` for bare (un-floored) EXCLUDED-first
/// expiry merges. `#[cfg(test)]` code is not scanned via a scope carve-out here
/// because the forbidden token is a production-SQL construct that appears only
/// in the two storage adapters; any test fixture reproducing it lives in THIS
/// file, which is not under `src/`.
fn collect_bare_floor_sites() -> Vec<BareFloorSite> {
    let src_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sites: Vec<BareFloorSite> = Vec::new();
    walk_rs_files(&src_root, &mut |path, raw| {
        let stripped = strip_all_comments(raw);
        let raw_lines: Vec<&str> = raw.lines().collect();
        let path_str = path.to_string_lossy().replace('\\', "/");
        let short = path_str
            .rsplit_once("/src/")
            .map_or(path_str.as_str(), |(_, rest)| rest);
        for (idx, line) in stripped.lines().enumerate() {
            if line_has_bare_excluded_floor(line) {
                let snippet = raw_lines
                    .get(idx)
                    .map_or_else(|| line.trim().to_string(), |l| l.trim().to_string());
                sites.push(BareFloorSite {
                    file_line: format!("src/{short}:{}", idx + 1),
                    snippet,
                });
            }
        }
    });
    sites.sort();
    sites.dedup();
    sites
}

/// ENFORCED: no LOCAL write funnel may floor `expires_at` with the bare
/// `COALESCE(excluded.expires_at, memories.expires_at)` — it silently shortens
/// a live TTL on re-store (#2515). Every such arm must use the #2335 tier-aware
/// lattice floor (`MAX` / `GREATEST` over the COALESCE'd pair).
#[test]
fn no_bare_coalesce_expiry_floor_on_local_write_funnels_2515() {
    let sites = collect_bare_floor_sites();
    if !sites.is_empty() {
        eprintln!(
            "\n=== #2515 bare TTL-floor WORKLIST ({} site(s)) ===",
            sites.len()
        );
        for s in &sites {
            eprintln!("  {}\n      {}", s.file_line, s.snippet);
        }
        eprintln!("=== end worklist ===\n");
    }
    assert!(
        sites.is_empty(),
        "#2515: {} LOCAL write funnel(s) floor expires_at with the bare \
         COALESCE(excluded.expires_at, memories.expires_at) form, which SHORTENS \
         a live TTL on re-store (data loss). Wrap it in the #2335 tier-aware \
         lattice floor: ELSE MAX/GREATEST(COALESCE(excluded.expires_at, \
         memories.expires_at), COALESCE(memories.expires_at, excluded.expires_at)). \
         See the printed worklist.",
        sites.len()
    );
}

// ---------------------------------------------------------------------------
// The detector is the load-bearing part of the assertion above — prove it
// FIRES on the bare form and stays SILENT on the floored form / commented
// token / sanctioned db::update shape, or the guard could pass vacuously.
// ---------------------------------------------------------------------------

#[test]
fn detector_flags_the_bare_sqlite_and_pg_forms() {
    assert!(
        line_has_bare_excluded_floor(
            "ELSE COALESCE(excluded.expires_at, memories.expires_at) END,"
        ),
        "the bare sqlite floor must be flagged"
    );
    assert!(
        line_has_bare_excluded_floor("ELSE COALESCE(EXCLUDED.expires_at, memories.expires_at)"),
        "the bare postgres floor (EXCLUDED upper-case) must be flagged"
    );
}

#[test]
fn detector_passes_the_floored_2335_forms() {
    // sqlite scalar-MAX floor (first COALESCE wrapped; the reversed partner
    // never matches the EXCLUDED-first needle).
    assert!(
        !line_has_bare_excluded_floor(
            "ELSE MAX(COALESCE(excluded.expires_at, memories.expires_at),"
        ),
        "the sqlite MAX floor must NOT be flagged"
    );
    // postgres GREATEST floor.
    assert!(
        !line_has_bare_excluded_floor(
            "ELSE GREATEST(COALESCE(EXCLUDED.expires_at, memories.expires_at),"
        ),
        "the postgres GREATEST floor must NOT be flagged"
    );
    // The reversed second operand alone is not the EXCLUDED-first needle.
    assert!(
        !line_has_bare_excluded_floor("COALESCE(memories.expires_at, excluded.expires_at)) END,"),
        "the reversed floor operand must NOT be flagged"
    );
}

#[test]
fn detector_ignores_commented_and_sanctioned_shapes() {
    // A `--` SQL comment quoting the forbidden token (like #2515's own rationale
    // comment) is not executable SQL and must be stripped before scanning.
    let commented = strip_all_comments(
        "                -- COALESCE(excluded.expires_at, memories.expires_at) shortens TTL\n",
    );
    assert!(
        !commented.lines().any(line_has_bare_excluded_floor),
        "a --commented occurrence of the token must be stripped, not flagged"
    );
    // A `//` Rust comment quoting it, likewise.
    let rust_commented =
        strip_all_comments("        // ELSE COALESCE(excluded.expires_at, memories.expires_at)\n");
    assert!(
        !rust_commented.lines().any(line_has_bare_excluded_floor),
        "a //commented occurrence of the token must be stripped, not flagged"
    );
    // The sanctioned db::update explicit-shorten shape (positional bind, no
    // `excluded.` reference) must never match.
    assert!(
        !line_has_bare_excluded_floor("ELSE COALESCE($12, expires_at)"),
        "the sanctioned memory_update/db::update shortener must NOT be flagged"
    );
    // The archive-restore projection is not an excluded.-referencing floor.
    assert!(
        !line_has_bare_excluded_floor(
            "COALESCE(original_expires_at, expires_at) AS expires_at, metadata,"
        ),
        "the archive-restore projection must NOT be flagged"
    );
}

#[test]
fn detector_sees_the_real_floored_funnels_in_src() {
    // Belt-and-braces: prove the FLOORED form is actually present in production
    // (so a refactor that hides the funnels from the scan can't silently
    // disable the invariant while the enforced test passes vacuously).
    let src_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut floored = 0usize;
    walk_rs_files(&src_root, &mut |_path, raw| {
        let stripped = strip_all_comments(raw);
        for line in stripped.lines() {
            let low = line.to_ascii_lowercase();
            let collapsed = low.split_whitespace().collect::<Vec<_>>().join(" ");
            if (collapsed.contains("max(") || collapsed.contains("greatest("))
                && collapsed.contains(EXCLUDED_FIRST_COALESCE)
            {
                floored += 1;
            }
        }
    });
    // 1 sqlite insert_inner + 5 pg local funnels + the 2 #2335 federation
    // mirrors (sqlite apply_remote_memory + pg mirror) = 8 floored arms.
    assert!(
        floored >= 6,
        "the #2335 floored expiry form must be present on every LOCAL write \
         funnel in src/ (>=6 expected: sqlite insert_inner + 5 pg funnels); \
         found {floored}"
    );
}
