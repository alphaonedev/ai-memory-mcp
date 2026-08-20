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
//!   * P4 — `INSERT … ON CONFLICT(title, namespace) DO UPDATE SET
//!     (content|title) = excluded.…` (PR-3 #2948, extended #2954) — an upsert
//!     that rewrites an existing memory's durable authored TEXT in place on a
//!     `(title, namespace)` collision, taking the new value from the
//!     `excluded` conflict row. P2 misses it because the assignment sits behind
//!     `DO UPDATE SET`, not `UPDATE memories SET`. Scoped to the memories-only
//!     `(title, namespace)` conflict target so upserts on other tables are not
//!     flagged. TWO content-destroying shapes qualify under the SAME invariant:
//!     the UNCONDITIONAL create-funnel overwrite (`content = excluded.content`
//!     — `db::insert` / `PostgresStore::store*`, #2948) AND the federation
//!     newer-wins LWW merge (`content = CASE WHEN excluded.updated_at >
//!     memories.updated_at … THEN excluded.content …` — `insert_if_newer` /
//!     `apply_remote_memory`, #2954). #2948 first closed the unconditional
//!     residual (5-agent vote `4d3ea1c5`); #2954 folded the newer-wins merge in
//!     so the source-static guard mechanically forbids a federation overwrite
//!     that skips the ledger too.
//!
//! DELIBERATELY OUT OF SCOPE (the North-Star content-vs-derived-artifact line):
//! a bare new-row `INSERT INTO memories` destroys nothing, and an in-place
//! `UPDATE` of ONLY disposable derived / pointer / temporal columns
//! (`metadata`, `embedding*`, `lifecycle_state`, `*_cid`, `valid_*`,
//! `access_count`, `expires_at`, `priority`, `tier`, `atom_*`, `memory_kind`,
//! `version`, `confidence*`, …) is regenerable-or-non-destructive. Widening
//! the ENFORCED guard to the literal
//! "any UPDATE / bare INSERT" flags 65 such legitimate production sites
//! (`set_row_metadata`, recall touch/promote, embedding backfill, lifecycle
//! tombstones, every postgres store write) and reds CI while protecting nothing
//! — so it is scoped to durable-TEXT destruction (5-agent vote `4d3ea1c5`,
//! PR-2). RESIDUAL: a future durable-TEXT column beyond `content`/`title` is
//! not caught by these four shapes.
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

/// Case-insensitive substring search (the `regex`/`memmem` crates are not
/// dependencies). Empty needle never matches.
fn contains_ignore_ascii_case(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    hay.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// PR-3 (#2948) + PR (#2954) — within a statement body, is a durable-TEXT
/// column (`content` / `title`) overwritten with a value TAKEN FROM the
/// `excluded` / `EXCLUDED` conflict row? Two content-destroying shapes both
/// qualify:
///
///  * `content = excluded.content` — the UNCONDITIONAL create-funnel overwrite
///    (`db::insert` / `PostgresStore::store*`, #2948); AND
///  * `content = CASE WHEN excluded.updated_at > memories.updated_at …
///    THEN excluded.content …` — the federation newer-wins LWW merge
///    (`insert_if_newer` / `apply_remote_memory`, #2954). The winning arm
///    replaces the prior version's durable text in place exactly as the
///    unconditional form does, so its ledger coverage is the SAME invariant,
///    not a separate class.
///
/// A purely self-preserving arm (`content = memories.content`, with NO
/// `excluded.<col>` anywhere in the assignment) is NOT flagged — it destroys
/// nothing.
fn stmt_overwrites_durable_text_from_excluded(stmt: &str) -> bool {
    column_takes_excluded_value(stmt, "content") || column_takes_excluded_value(stmt, "title")
}

/// A durable-TEXT `column` is assigned (`column = …`) AND the statement takes
/// that column's value from `excluded.<column>` somewhere in the assignment —
/// either DIRECTLY (`= excluded.content`) or inside a `CASE … THEN
/// excluded.content …` newer-wins arm. Case-insensitive on the `excluded`
/// keyword (sqlite `excluded`, postgres `EXCLUDED`). The self-preserving
/// `= memories.<col>` arm carries no `excluded.<col>` and so is not flagged.
fn column_takes_excluded_value(stmt: &str, column: &str) -> bool {
    stmt_assigns_column(stmt, column)
        && contains_ignore_ascii_case(stmt, &format!("excluded.{column}"))
}

/// PR-3 (#2948) — the P4 pattern
/// `INSERT … ON CONFLICT(title, namespace) DO UPDATE SET (content|title) =
/// excluded.…` over comment-stripped source. The primary CREATE funnel's
/// upsert-merge (`db::insert` / `PostgresStore::{store,store_batch,
/// store_with_embedding_inner,capture_turn_idempotent,recover_turn_idempotent,
/// reflect_with_hooks,consolidate}`) UNCONDITIONALLY rewrites an existing
/// memory's durable authored TEXT IN PLACE on a `(title, namespace)` collision
/// — a content destruction the P1 (bare `DELETE`), P2 (`UPDATE memories SET`)
/// and P3 (`INSERT OR REPLACE`) shapes all MISS, because the assignment sits
/// behind `DO UPDATE SET`, not `UPDATE memories SET`. This closes the residual
/// the module header used to document as deliberately un-caught.
///
/// SCOPING (two filters, both load-bearing):
///  * the conflict target is the memories-specific `(title, namespace)` unique
///    index (whitespace-tolerant) — no other table upserts on that target
///    (`peer_state` → `(agent_id, peer_id)`, `namespace_meta` → `(namespace)`,
///    `actions`/`pending` → `(id)`); AND
///  * the durable-TEXT column is assigned from `excluded.…` — either the
///    UNCONDITIONAL create overwrite (`= excluded.content`, #2948) OR the
///    federation newer-wins merge (`content = CASE WHEN excluded.updated_at >
///    memories.updated_at … THEN excluded.content …`, #2954). Both replace the
///    prior version's durable text on the winning arm, so #2954 folded the
///    federation LWW merge (`insert_if_newer` / `apply_remote_memory`) into
///    this SAME P4 invariant — it is no longer a carved-out separate class.
///
/// Returns the byte offsets of each matching `ON CONFLICT`.
fn p4_on_conflict_do_update_durable_text(stripped: &str) -> Vec<usize> {
    let mut hits = Vec::new();
    let hay = stripped;
    let mut from = 0;
    while let Some(rel) = hay[from..].find("ON CONFLICT") {
        let start = from + rel;
        from = start + "ON CONFLICT".len();
        let rest = &hay[start..];
        // Require the memories-specific conflict target `(title, namespace)`
        // (whitespace-tolerant) so only the `memories` upsert is in scope.
        let after_kw = rest["ON CONFLICT".len()..].trim_start();
        let Some(after_paren) = after_kw.strip_prefix('(') else {
            continue;
        };
        let target: String = after_paren
            .chars()
            .take_while(|&c| c != ')')
            .filter(|c| !c.is_whitespace())
            .collect();
        if target != "title,namespace" {
            continue;
        }
        // Within this statement (to the Rust `;` that terminates the SQL
        // string literal — SQL upsert bodies carry no `;`), is a durable-TEXT
        // column UNCONDITIONALLY overwritten from `excluded.…`?
        let stmt_end = rest.find(';').unwrap_or(rest.len());
        if stmt_overwrites_durable_text_from_excluded(&rest[..stmt_end]) {
            hits.push(start);
        }
    }
    hits
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

        // P4 (PR-3 #2948) — `ON CONFLICT(title, namespace) DO UPDATE SET
        // content|title =`. The create-funnel upsert-merge rewrites an existing
        // memory's durable TEXT in place on a `(title, namespace)` collision;
        // the P2 needle misses it because the assignment is behind `DO UPDATE
        // SET`, not `UPDATE memories SET`. Closes the former documented residual.
        for off in p4_on_conflict_do_update_durable_text(&stripped) {
            record(
                off,
                "ON CONFLICT(title, namespace) DO UPDATE SET ... content|title =",
            );
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

// ---------------------------------------------------------------------------
// PR-3 (#2948) — the P4 detector must be LOAD-BEARING: it fires on the
// create-funnel upsert-merge content overwrite and stays silent on the shapes
// that destroy nothing / touch other tables. Without these, a broken P4 could
// silently pass while the #2948 bypass re-opened.
// ---------------------------------------------------------------------------

#[test]
fn p4_flags_on_conflict_do_update_set_content() {
    // The exact sqlite `db::insert` upsert shape #2948 closes.
    let sql = "INSERT INTO memories (id, title, content) VALUES (?1, ?2, ?3)\n\
               ON CONFLICT(title, namespace) DO UPDATE SET\n\
               content = excluded.content,\n\
               version = memories.version + 1\n\
               RETURNING id";
    assert_eq!(
        p4_on_conflict_do_update_durable_text(sql).len(),
        1,
        "P4 must flag an ON CONFLICT(title, namespace) DO UPDATE SET content = ..."
    );
}

#[test]
fn p4_flags_postgres_spaced_conflict_target_and_title_assignment() {
    // Postgres spells it `ON CONFLICT (title, namespace)` (space before paren)
    // and a hypothetical title rewrite must also be caught.
    let sql = "ON CONFLICT (title, namespace) DO UPDATE SET title = EXCLUDED.title;";
    assert_eq!(p4_on_conflict_do_update_durable_text(sql).len(), 1);
}

#[test]
fn p4_ignores_do_nothing_and_non_durable_and_other_tables() {
    // DO NOTHING destroys nothing.
    let do_nothing = "ON CONFLICT(title, namespace) DO NOTHING RETURNING id;";
    assert!(p4_on_conflict_do_update_durable_text(do_nothing).is_empty());

    // A memories upsert that touches ONLY derived/temporal columns is out of
    // scope (content/title are untouched).
    let derived_only =
        "ON CONFLICT(title, namespace) DO UPDATE SET version = memories.version + 1;";
    assert!(p4_on_conflict_do_update_durable_text(derived_only).is_empty());

    // A `content`-bearing upsert on a DIFFERENT conflict target (not the
    // memories `(title, namespace)` index) must NOT be flagged.
    let other_table = "ON CONFLICT(agent_id, peer_id) DO UPDATE SET content = excluded.content;";
    assert!(p4_on_conflict_do_update_durable_text(other_table).is_empty());
}

#[test]
fn p4_flags_federation_newer_wins_case_merge() {
    // #2954 — the federation LWW merge (`insert_if_newer` / `apply_remote_memory`)
    // overwrites content CONDITIONALLY via `CASE WHEN excluded.updated_at >
    // memories.updated_at … THEN excluded.content …`. This IS a durable-text
    // destruction on the winning arm, so #2954 folded it into the P4 invariant:
    // the source-static guard now flags it, forcing a ledger route (the leaf
    // emission + `APPEND-ONLY-SANCTIONED` marker the two funnels now carry).
    let fed = "ON CONFLICT(title, namespace) DO UPDATE SET \
               content = CASE WHEN excluded.updated_at > memories.updated_at \
               THEN excluded.content ELSE memories.content END, \
               version = memories.version + 1;";
    assert_eq!(
        p4_on_conflict_do_update_durable_text(fed).len(),
        1,
        "P4 must flag the federation newer-wins CASE merge that takes \
         excluded.content on the winning arm (#2954)"
    );

    // The self-preserving arm (`content = memories.content`) carries no
    // `excluded.content` and must NOT be flagged — it destroys nothing.
    let keep = "ON CONFLICT(title, namespace) DO UPDATE SET content = memories.content;";
    assert!(
        p4_on_conflict_do_update_durable_text(keep).is_empty(),
        "the self-preserving `= memories.content` arm is not a durable-text overwrite"
    );

    // A derived-only newer-wins CASE (e.g. lifecycle_state) that never touches
    // `content`/`title` must NOT be flagged — only durable AUTHORED-TEXT is
    // in scope.
    let derived = "ON CONFLICT(title, namespace) DO UPDATE SET \
                   lifecycle_state = CASE WHEN excluded.updated_at > memories.updated_at \
                   THEN excluded.lifecycle_state ELSE memories.lifecycle_state END;";
    assert!(
        p4_on_conflict_do_update_durable_text(derived).is_empty(),
        "a newer-wins CASE on a derived column is out of the durable-text scope"
    );
}

#[test]
fn p4_matches_the_real_insert_inner_and_pg_store_are_sanctioned() {
    // Belt-and-braces: prove the enforced scan sees the P4 shape in production
    // (so the detector is wired against real source, not just fixtures) AND
    // that every such site is routed — collect_unrouted_sites() is empty above,
    // which already covers routing; here we assert the detector finds the
    // production upserts at all, so a future refactor that hides them from the
    // scan can't silently disable the invariant.
    let src_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut p4_total = 0usize;
    walk_rs_files(&src_root, &mut |_path, raw| {
        let stripped = strip_rust_comments(raw);
        p4_total += p4_on_conflict_do_update_durable_text(&stripped).len();
    });
    assert!(
        p4_total >= 4,
        "the P4 detector must see the real durable-text upserts in src/: the \
         UNCONDITIONAL create funnel (sqlite `insert_inner` + a PostgresStore \
         upsert, #2948) AND the federation newer-wins CASE merge (sqlite \
         `insert_if_newer` + pg `apply_remote_memory`, #2954); found {p4_total}"
    );
}
