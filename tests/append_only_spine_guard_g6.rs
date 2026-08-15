// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G6 (#1823) — the append-only spine STATIC GUARD.
//!
//! This source-static test enumerates every production memory MUTATION site
//! that DESTROYS durable authored content and so must route through the signed
//! `memory_revisions` ledger (each enclosing `fn` carrying the
//! `// APPEND-ONLY-SANCTIONED` marker). The invariant protects exactly ONE
//! thing — the operator-authored memory TEXT (`content` and `title`), the
//! durable source of truth. The three content-DESTROYING SQL shapes:
//!
//!   * P1 — `DELETE FROM memories` (a physical delete of a memory row).
//!   * P2 — `UPDATE memories SET ... (content|title) = ...` (an in-place
//!     rewrite of durable authored TEXT — a new version must be written and
//!     the prior one archived, never mutated in place). PR-2 (#1823) widened
//!     the assignment probe from `content` only to `content` OR `title`.
//!   * P3 — `INSERT OR REPLACE INTO memories` (PR-2 #1823) — REPLACE deletes
//!     the conflicting row before re-inserting, annihilating the prior
//!     version's content OUTSIDE the ledger; a bypass P1 + P2 do not catch.
//!
//! DELIBERATELY OUT OF SCOPE (the North-Star content-vs-derived-artifact line):
//! a bare new-row `INSERT INTO memories` destroys nothing, and an in-place
//! `UPDATE` of ONLY disposable derived / pointer / temporal columns
//! (`metadata`, `embedding*`, `lifecycle_state`, `*_cid`, `valid_*`,
//! `access_count`, `expires_at`, `priority`, `tier`, `atom_*`, `memory_kind`,
//! `version`, `confidence*`, …) is regenerable-or-non-destructive. Widening
//! the ENFORCED guard to the literal
//! "any UPDATE / bare INSERT" flags 65 such legitimate production sites (the
//! primary `db::insert` upsert, `set_row_metadata`, recall touch/promote,
//! embedding backfill, lifecycle tombstones, every postgres store write) and
//! reds CI while protecting nothing — so it is scoped to durable-TEXT
//! destruction (5-agent vote `4d3ea1c5`, PR-2). DOCUMENTED RESIDUAL: an
//! `INSERT … ON CONFLICT … DO UPDATE SET content = …` on the sanctioned create
//! funnel and a future durable-TEXT column beyond `content`/`title` are NOT
//! caught by these three shapes.
//!
//! A site is considered ROUTED (sanctioned) when its enclosing `fn`
//! carries the `// APPEND-ONLY-SANCTIONED` marker on raw source. The two
//! file-local `SQL_DELETE_MEMORY_BY_ID` const definitions
//! (`src/store/postgres.rs`, `src/storage/mod.rs`) are allow-listed —
//! they are the single SQL SSOT the sanctioned delete paths reference, not
//! independent call sites. `#[cfg(test)]` scope is excluded (test code is
//! never compiled into the daemon).
//!
//! STATUS: ENFORCED in CI. Site conversion (step 2+) is complete and the
//! worklist is drained to empty; a new un-routed content-destroying mutation
//! re-reds the [`append_only_spine_all_memory_mutations_routed`] assertion.
//! Print the (currently empty) worklist with:
//!
//! ```text
//! cargo test --test append_only_spine_guard_g6 -- --nocapture
//! ```

use std::path::{Path, PathBuf};

/// Recursively visit every `.rs` file under `dir`, handing each
/// `(path, contents)` to `visit`. Copied (not shared) from the
/// `signed_events` guard helper: an integration test links the crate as an
/// external library and cannot reach `#[cfg(test)]`-private helpers.
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

/// Strip Rust line comments (`//...`) and single-line block comments
/// (`/* ... */`), preserving line structure (one output line per input
/// line) so byte offsets map to the SAME line numbers as the raw source.
/// Copied from the `signed_events` guard helper.
fn strip_rust_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let line_no_line_comment = match line.find("//") {
            Some(idx) => &line[..idx],
            None => line,
        };
        let mut buf = String::from(line_no_line_comment);
        while let (Some(start), Some(end_rel)) = (buf.find("/*"), buf.find("*/").map(|i| i + 2)) {
            if end_rel <= start {
                break;
            }
            buf.replace_range(start..end_rel, "");
        }
        out.push_str(&buf);
        out.push('\n');
    }
    out
}

/// 1-based line number of a byte offset within `s`.
fn line_of_offset(s: &str, offset: usize) -> usize {
    s[..offset.min(s.len())]
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
        + 1
}

/// Does the line look like a Rust `fn` declaration? (`fn NAME(` after
/// optional `pub` / `async` / `pub(crate)` / `const` / `unsafe` qualifiers.)
fn is_fn_decl_line(line: &str) -> bool {
    let Some(idx) = line.find("fn ") else {
        return false;
    };
    // Require a word boundary before `fn` (start-of-trim or whitespace).
    let before_ok = idx == 0 || line.as_bytes()[idx - 1].is_ascii_whitespace();
    // Require an identifier char right after `fn `.
    let after = &line[idx + 3..];
    let ident_ok = after
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_');
    before_ok && ident_ok && line.contains('(')
}

/// Walk backward from `hit_line` (0-based) to the nearest enclosing `fn`
/// declaration, brace-count to its end, and report whether the
/// `// APPEND-ONLY-SANCTIONED` marker appears anywhere in that fn's RAW
/// span. Returns `false` when no enclosing fn is found (module-scope
/// item — never sanctioned).
fn enclosing_fn_has_marker(raw_lines: &[&str], hit_line: usize) -> bool {
    const MARKER: &str = "APPEND-ONLY-SANCTIONED";
    let mut fn_start = None;
    for i in (0..=hit_line.min(raw_lines.len().saturating_sub(1))).rev() {
        if is_fn_decl_line(raw_lines[i]) {
            fn_start = Some(i);
            break;
        }
    }
    let Some(start) = fn_start else {
        return false;
    };
    // Brace-count from fn_start to the matching close.
    let mut depth: i32 = 0;
    let mut opened = false;
    let mut fn_end = raw_lines.len() - 1;
    for (i, line) in raw_lines.iter().enumerate().skip(start) {
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
                opened = true;
            } else if ch == '}' {
                depth -= 1;
            }
        }
        if opened && depth <= 0 {
            fn_end = i;
            break;
        }
    }
    raw_lines[start..=fn_end.min(raw_lines.len() - 1)]
        .iter()
        .any(|l| l.contains(MARKER))
}

/// Hand-rolled match for the P2 pattern
/// `UPDATE\s+memories\s+SET\b[^;]*(\bcontent\b|\btitle\b)\s*=` over
/// comment-stripped source (the `regex` crate is not a dependency). Returns
/// the byte offsets of each match start. PR-2 (#1823) widened the assignment
/// probe from `content` only to any durable AUTHORED-TEXT column
/// (`content` OR `title`) — see [`stmt_rewrites_durable_text`].
fn p2_update_memories_durable_text(stripped: &str) -> Vec<usize> {
    let mut hits = Vec::new();
    let hay = stripped;
    let mut from = 0;
    while let Some(rel) = hay[from..].find("UPDATE") {
        let start = from + rel;
        from = start + "UPDATE".len();
        let rest = &hay[start + "UPDATE".len()..];
        // \s+ memories
        let after_ws = rest.trim_start();
        if after_ws.len() == rest.len() {
            continue; // no whitespace after UPDATE
        }
        let Some(after_mem) = after_ws.strip_prefix("memories") else {
            continue;
        };
        // \s+ SET
        let after_mem_ws = after_mem.trim_start();
        if after_mem_ws.len() == after_mem.len() {
            continue; // no whitespace after memories
        }
        let Some(after_set) = after_mem_ws.strip_prefix("SET") else {
            continue;
        };
        // \b after SET (next char must not be ident-continuation).
        if after_set
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            continue;
        }
        // [^;]* up to the statement terminator, then (\bcontent\b|\btitle\b)\s*=
        let stmt_end = after_set.find(';').unwrap_or(after_set.len());
        if stmt_rewrites_durable_text(&after_set[..stmt_end]) {
            hits.push(start);
        }
    }
    hits
}

/// Within a single statement body, is there an assignment to `column`
/// (the word with both boundaries, followed by optional whitespace and `=`)?
fn stmt_assigns_column(stmt: &str, column: &str) -> bool {
    let bytes = stmt.as_bytes();
    let mut from = 0;
    while let Some(rel) = stmt[from..].find(column) {
        let idx = from + rel;
        from = idx + column.len();
        let before_ok = idx == 0 || {
            let b = bytes[idx - 1];
            !(b.is_ascii_alphanumeric() || b == b'_')
        };
        let after = &stmt[idx + column.len()..];
        // boundary after the column word
        let boundary_ok = after
            .chars()
            .next()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        if before_ok && boundary_ok {
            let trimmed = after.trim_start();
            if trimmed.starts_with('=') {
                return true;
            }
        }
    }
    false
}

/// PR-2 (#1823) — does the statement rewrite a durable AUTHORED-TEXT column
/// (`content` OR `title`)? These are the operator-authored bytes the
/// append-only invariant protects. Every OTHER `memories` column — `metadata`,
/// `embedding` / `embedding_dim` / `embedding_space`, `lifecycle_state`,
/// `cid` / `cid_genesis`, `valid_from` / `valid_until`, `access_count`,
/// `expires_at`, `last_accessed_at`, `priority`, `tier`, `atom_of` /
/// `atomised_into`, `mentioned_entity_id`, `memory_kind`, `version`,
/// `confidence*`, `encrypted_envelope` — is a DISPOSABLE derived / pointer /
/// temporal artifact regenerable-from-text or non-destructive under the North
/// Star, so an in-place update of ONLY those columns destroys nothing of
/// record and is deliberately OUT of the invariant's scope (widening the guard
/// to "any UPDATE" would flag 65 such legitimate sites — the primary
/// `db::insert` upsert, `set_row_metadata`, recall touch/promote, embedding
/// backfill, lifecycle tombstones, every postgres store write — and red CI
/// while protecting nothing; 5-agent vote `4d3ea1c5`).
fn stmt_rewrites_durable_text(stmt: &str) -> bool {
    stmt_assigns_column(stmt, "content") || stmt_assigns_column(stmt, "title")
}

/// Brace-counted line spans (`[start, end]`, 0-based, inclusive) of every
/// `#[cfg(test)]`-annotated braced item (`mod`, `fn`, `impl`, …) in a file.
/// The append-only invariant governs the PRODUCTION mutation surface only —
/// `#[cfg(test)]` code is never compiled into the daemon, so a delete/update
/// inside a test module or test helper is out of scope and MUST NOT appear in
/// the worklist. A `#[cfg(test)] use/const/static/type …;` statement carries
/// no body, so it bounds no scope and is skipped (it would otherwise capture
/// the next real item's braces and over-exclude).
fn cfg_test_spans(raw_lines: &[&str]) -> Vec<(usize, usize)> {
    let n = raw_lines.len();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < n {
        if raw_lines[i].contains("#[cfg(test)]") {
            // The annotated item: skip blank / further-attribute / comment
            // lines to reach the item declaration itself.
            let mut j = i + 1;
            while j < n {
                let t = raw_lines[j].trim_start();
                if t.is_empty() || t.starts_with("#[") || t.starts_with("//") {
                    j += 1;
                } else {
                    break;
                }
            }
            if j < n {
                let item = raw_lines[j].trim_start();
                let stmt_only = item.starts_with("use ")
                    || item.starts_with("const ")
                    || item.starts_with("static ")
                    || item.starts_with("type ");
                let braced = ["mod ", "fn ", "impl", "struct ", "enum ", "trait "]
                    .iter()
                    .any(|kw| item.contains(kw));
                if braced && !stmt_only {
                    // Brace COUNTING is unreliable here: a `#[cfg(test)] mod
                    // tests` body holds thousands of `{`/`}` inside JSON
                    // string literals (`json!({...})`) and comments that a
                    // raw char scan miscounts. Instead, rustfmt emits the
                    // item's CLOSING brace alone on a line at the SAME
                    // indentation as the item declaration — match that. This
                    // is literal/comment-brace-proof.
                    let indent = raw_lines[j].len() - raw_lines[j].trim_start().len();
                    let mut end = j;
                    for (k, line) in raw_lines.iter().enumerate().skip(j + 1) {
                        let this_indent = line.len() - line.trim_start().len();
                        let t = line.trim_start();
                        if this_indent == indent && (t == "}" || t.starts_with("} ")) {
                            end = k;
                            break;
                        }
                    }
                    spans.push((i, end));
                    i = end + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    spans
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct UnroutedSite {
    file_line: String,
    snippet: String,
}

/// The authoritative scan. Returns the sorted list of forbidden mutation
/// sites that are NOT inside an `APPEND-ONLY-SANCTIONED` fn and NOT
/// allow-listed.
fn collect_unrouted_sites() -> Vec<UnroutedSite> {
    let src_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");

    // P1 / P3 needles assembled at runtime (split/concat) so this guard file's
    // own literal cannot self-trip a future copy of the guard.
    let p1_needle = format!("{}{}", "DELETE FROM", " memories");
    let p3_needle = format!("{}{}", "INSERT OR REPLACE", " INTO memories");

    let mut sites: Vec<UnroutedSite> = Vec::new();

    walk_rs_files(&src_root, &mut |path, raw| {
        let stripped = strip_rust_comments(raw);
        let raw_lines: Vec<&str> = raw.lines().collect();
        let path_str = path.to_string_lossy().replace('\\', "/");
        // Test-scope spans are out of the append-only invariant's reach.
        let test_spans = cfg_test_spans(&raw_lines);

        let mut record = |offset: usize, pattern: &str| {
            let line_no = line_of_offset(&stripped, offset);
            let line_idx = line_no.saturating_sub(1);
            // EXCLUDE: hits inside any `#[cfg(test)]` item — test code is
            // never compiled into the daemon, so it is not a production
            // mutation site.
            if test_spans
                .iter()
                .any(|&(s, e)| line_idx >= s && line_idx <= e)
            {
                return;
            }
            // ALLOWLIST: the two SQL_DELETE_MEMORY_BY_ID const SSOTs.
            if raw_lines
                .get(line_idx)
                .is_some_and(|l| l.contains("SQL_DELETE_MEMORY_BY_ID"))
            {
                return;
            }
            // ROUTED when the enclosing fn carries the sanction marker.
            if enclosing_fn_has_marker(&raw_lines, line_idx) {
                return;
            }
            let snippet = raw_lines
                .get(line_idx)
                .map_or_else(|| pattern.to_string(), |l| l.trim().to_string());
            // Suffix the file path so the file:line is operator-clickable.
            let short = path_str
                .rsplit_once("/src/")
                .map_or(path_str.as_str(), |(_, rest)| rest);
            sites.push(UnroutedSite {
                file_line: format!("src/{short}:{line_no}"),
                snippet,
            });
        };

        // P1 — physical memory-row deletes.
        let mut from = 0;
        while let Some(rel) = stripped[from..].find(&p1_needle) {
            let off = from + rel;
            from = off + p1_needle.len();
            record(off, &p1_needle);
        }

        // P2 — in-place durable-TEXT rewrites (content OR title).
        for off in p2_update_memories_durable_text(&stripped) {
            record(off, "UPDATE memories SET ... content|title =");
        }

        // P3 (PR-2 #1823) — row-DESTROYING `INSERT OR REPLACE INTO memories`.
        // REPLACE deletes the conflicting row before re-inserting, annihilating
        // the prior version's content OUTSIDE the ledger — a bypass P1 (bare
        // DELETE) + P2 (in-place UPDATE) miss. A bare `INSERT INTO memories`
        // (new row) and an `INSERT … ON CONFLICT … DO UPDATE` upsert are NOT
        // flagged: a new row destroys nothing, and the ON-CONFLICT create
        // funnel is the documented residual (see the module header).
        let mut from = 0;
        while let Some(rel) = stripped[from..].find(&p3_needle) {
            let off = from + rel;
            from = off + p3_needle.len();
            // Boundary after `memories` so `memories_fts` / `memory_*` cannot
            // false-trip (tighter than P1's simple-needle precedent).
            let after = &stripped[off + p3_needle.len()..];
            if after
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                continue;
            }
            record(off, "INSERT OR REPLACE INTO memories");
        }
    });

    sites.sort();
    sites.dedup();
    sites
}

/// STEP 2 (#1823): every production memory-mutation site now routes through
/// the signed `memory_revisions` ledger (each enclosing fn carries the
/// `APPEND-ONLY-SANCTIONED` marker), `#[cfg(test)]` scope is excluded, and
/// the worklist has drained to empty — so this guard is now ENFORCED in CI.
/// A new un-routed delete / in-place content rewrite re-fails it.
#[test]
fn append_only_spine_all_memory_mutations_routed() {
    let sites = collect_unrouted_sites();

    eprintln!(
        "\n=== G6 #1823 append-only spine — UN-ROUTED MUTATION WORKLIST ({} sites) ===",
        sites.len()
    );
    for s in &sites {
        eprintln!("  {}\n      {}", s.file_line, s.snippet);
    }
    eprintln!("=== end worklist ({} sites) ===\n", sites.len());

    assert!(
        sites.is_empty(),
        "append-only invariant: {} memory-mutation site(s) are not routed through the \
         signed memory_revisions ledger (and not APPEND-ONLY-SANCTIONED). See the printed \
         worklist above — this is the authoritative step-2 conversion list.",
        sites.len()
    );
}
