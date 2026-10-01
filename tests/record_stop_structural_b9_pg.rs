// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Wave-2 B9 — POSTGRES-side structural record-stop completeness.
//!
//! Every `PostgresStore` method whose body contains INSERT/UPDATE/DELETE
//! against a record-plane table must call `gate_record_stop`, except a
//! minimal bookkeeping allowlist (touch / confidence-decay /
//! recall-observation / `refund_update_growth` / `mark_recall_consumed`).
//! `fold_recall_accesses` GATES (the fold's access-count / TTL
//! bookkeeping is a record-plane mutation). In-tx free functions (no `&self`) are out of
//! scope here — they cannot call the SAL gate; the B7 allowlist names
//! their gated callers. `append_signed_event` stays ungated so resume
//! can persist the attestation (ERRORS-09).

use std::collections::{HashMap, HashSet};

// #4023: ONE shared loader reads `postgres.rs` AND every child module under
// `src/store/postgres/` (fail closed on an empty / short file set).
#[path = "common/pg_sources.rs"]
mod pg_sources;

const GATE_MARKERS: &[&str] = &["gate_record_stop", "refuse_if_record_stopped"];

/// Record-plane tables named in the B9 brief, plus the quota /
/// tombstone / observation tables that are durable writes.
const RECORD_PLANE: &[&str] = &[
    "memories",
    "memory_links",
    "actions",
    "leases",
    "signals",
    "checkpoints",
    "routines",
    "archived_memories",
    "archived_memory_links",
    "pending_actions",
    "entity_aliases",
    "agent_pubkeys",
    "namespace_standard",
    "agent_api_keys",
    "agent_quotas",
    "forget_tombstones",
    "recall_observations",
    "memory_revisions",
];

/// Genuine read-bookkeeping. A write-SQL method not in this set must gate.
const BOOKKEEPING: &[&str] = &[
    "touch_after_recall",
    "apply_confidence_decay_stamp",
    "recall_observation_insert",
    "recall_observation_prune_guarded",
    "refund_update_growth",
    "mark_recall_consumed",
];

/// Multi-line UPDATE methods that the B9 same-line scanner missed.
/// Must surface as write-SQL after the B10 body scan (or the scanner
/// silently regressed).
const MUST_SURFACE_AS_WRITE: &[&str] = &["refund_update_growth", "mark_recall_consumed"];

/// Round-6 named siblings. Must gate even if someone re-allowlists them.
const MUST_BE_GATED: &[&str] = &["reflect_with_hooks", "update_embedding", "link_internal"];

fn next_ident(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    let n = s
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .count();
    if n == 0 {
        None
    } else {
        Some((&s[..n], &s[n..]))
    }
}

/// Body-level write-SQL table names. Understands multi-line
/// `UPDATE <table>\\n SET` (the dominant postgres style).
fn tables_written(body: &str) -> HashSet<String> {
    let cleaned: String = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let upper = cleaned.to_ascii_uppercase();
    let mut tables = HashSet::new();
    let mut rest = upper.as_str();
    while let Some(at) = ["INSERT", "DELETE", "UPDATE"]
        .iter()
        .filter_map(|kw| rest.find(kw))
        .min()
    {
        let slice = &rest[at..];
        if let Some(after) = slice.strip_prefix("INSERT") {
            if let Some(into_at) = slice.find(" INTO ")
                && let Some((name, _)) = next_ident(&slice[into_at + 6..])
            {
                tables.insert(name.to_ascii_lowercase());
            }
            rest = after;
        } else if let Some(after) = slice.strip_prefix("DELETE") {
            if let Some(from_at) = slice.find(" FROM ")
                && let Some((name, _)) = next_ident(&slice[from_at + 6..])
            {
                tables.insert(name.to_ascii_lowercase());
            }
            rest = after;
        } else if let Some(after) = slice.strip_prefix("UPDATE") {
            // SET may be on a later line.
            if let Some((name, after_name)) = next_ident(after.trim_start())
                && after_name.trim_start().starts_with("SET")
            {
                tables.insert(name.to_ascii_lowercase());
            }
            rest = after;
        } else {
            rest = &slice[1..];
        }
    }
    tables
}

fn strip_fn_prefixes(mut t: &str) -> &str {
    loop {
        let n = t.trim_start();
        if let Some(rest) = n.strip_prefix("pub(")
            && let Some(idx) = rest.find(')')
        {
            t = rest[idx + 1..].trim_start();
            continue;
        }
        if let Some(rest) = n.strip_prefix("pub ") {
            t = rest;
            continue;
        }
        if let Some(rest) = n.strip_prefix("const ") {
            t = rest;
            continue;
        }
        if let Some(rest) = n.strip_prefix("async ") {
            t = rest;
            continue;
        }
        if let Some(rest) = n.strip_prefix("unsafe ") {
            t = rest;
            continue;
        }
        if let Some(rest) = n.strip_prefix("extern ") {
            t = rest.trim_start();
            if let Some(quoted) = t.strip_prefix('"')
                && let Some(end) = quoted.find('"')
            {
                t = quoted[end + 1..].trim_start();
            }
            continue;
        }
        return n;
    }
}

fn is_fn_start(line: &str) -> Option<(usize, String)> {
    let indent = line.len() - line.trim_start().len();
    let t = strip_fn_prefixes(line.trim_start());
    let rest = t.strip_prefix("fn ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some((indent, name))
    }
}

fn strip_test_mod(src: &str) -> &str {
    let needle = "\n#[cfg(test)]\nmod tests {";
    if let Some(idx) = src.rfind(needle) {
        return &src[..idx];
    }
    src
}

fn signature_has_self(lines: &[&str], start: usize) -> bool {
    let end = lines.len().min(start.saturating_add(30));
    for line in &lines[start..end] {
        if line.contains("&self") || line.contains("&mut self") {
            return true;
        }
        if line.contains('{') {
            break;
        }
    }
    false
}

/// A top-level SQL `const` / `static` item: its name, its inclusive line range
/// and the record-plane tables its text writes.
struct ConstItem {
    name: String,
    start: usize,
    end: usize,
    tables: HashSet<String>,
}

/// `const SQL_X: &str = ...;` / `pub(super) static NAME: ...` at column 0 ->
/// `NAME`. Requires a `SCREAMING_SNAKE` name followed by a `:` type annotation,
/// so an ordinary line inside a string literal is not mistaken for an item.
fn const_item_name(line: &str) -> Option<String> {
    let mut t = line;
    if let Some(rest) = t.strip_prefix("pub(")
        && let Some(idx) = rest.find(')')
    {
        t = rest[idx + 1..].trim_start();
    } else if let Some(rest) = t.strip_prefix("pub ") {
        t = rest;
    }
    let t = t
        .strip_prefix("const ")
        .or_else(|| t.strip_prefix("static "))?;
    let name: String = t
        .chars()
        .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
        .collect();
    if name.is_empty() || !t[name.len()..].starts_with(':') {
        return None;
    }
    Some(name)
}

/// Every top-level const/static item in `lines`, with the record-plane tables
/// its own text writes. An item runs from its first line to the first line
/// that ends in `;`.
fn const_items(lines: &[&str], record_plane: &HashSet<&str>) -> Vec<ConstItem> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if let Some(name) = const_item_name(lines[i]) {
            let mut end = i;
            while end + 1 < lines.len() && !lines[end].trim_end().ends_with(';') {
                end += 1;
            }
            let tables = tables_written(&lines[i..=end].join("\n"))
                .into_iter()
                .filter(|t| record_plane.contains(t.as_str()))
                .collect();
            out.push(ConstItem {
                name,
                start: i,
                end,
                tables,
            });
            i = end + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Whole-word containment, so `SQL_A` does not match inside `SQL_AB`.
fn names_ident(body: &str, name: &str) -> bool {
    let is_id = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(pos) = body[from..].find(name) {
        let at = from + pos;
        let before = body[..at].chars().next_back();
        let after = body[at + name.len()..].chars().next();
        if !before.is_some_and(is_id) && !after.is_some_and(is_id) {
            return true;
        }
        from = at + name.len();
    }
    false
}

/// What one scan of the adapter sources found.
struct Scan {
    /// `(file:method, 1-based line, tables)` for each ungated, non-bookkeeping writer.
    ungated: Vec<(String, usize, String)>,
    /// Every method that surfaced as a record-plane writer.
    surfaced: HashSet<String>,
    /// Every surfaced method that carries a gate marker.
    gated: HashSet<String>,
}

/// The B9 scan, over `(crate-relative path, source text)` pairs.
///
/// A method's span runs from its signature to the next fn start (the original
/// B9 span, unchanged). Two additions, neither of which narrows it:
/// * top-level SQL `const`/`static` items are lifted OUT of every span (so a
///   const that merely sits between two impls is not charged to the method
///   above it), and
/// * each const's written tables are credited to EVERY method that names it,
///   in any file. A method whose write SQL lives in a const (e.g.
///   `pg_merge_inbound`) is therefore seen, and a const that belongs to a
///   gated method stays attributed to that method (#4023).
fn scan(sources: &[(String, String)]) -> Scan {
    let bookkeeping: HashSet<&str> = BOOKKEEPING.iter().copied().collect();
    let record_plane: HashSet<&str> = RECORD_PLANE.iter().copied().collect();

    let prepared: Vec<(String, Vec<&str>)> = sources
        .iter()
        .map(|(rel, text)| {
            (
                rel.rsplit('/').next().unwrap_or(rel.as_str()).to_string(),
                strip_test_mod(text).lines().collect(),
            )
        })
        .collect();

    let mut const_tables: HashMap<String, HashSet<String>> = HashMap::new();
    let per_file_consts: Vec<Vec<ConstItem>> = prepared
        .iter()
        .map(|(_, lines)| const_items(lines, &record_plane))
        .collect();
    for items in &per_file_consts {
        for item in items {
            const_tables
                .entry(item.name.clone())
                .or_default()
                .extend(item.tables.iter().cloned());
        }
    }
    let writing_consts: Vec<(&String, &HashSet<String>)> =
        const_tables.iter().filter(|(_, t)| !t.is_empty()).collect();

    let mut out = Scan {
        ungated: Vec::new(),
        surfaced: HashSet::new(),
        gated: HashSet::new(),
    };
    for ((file, lines), items) in prepared.iter().zip(&per_file_consts) {
        let mut starts: Vec<(usize, String)> = Vec::new();
        for (idx, line) in lines.iter().enumerate() {
            if let Some((_, name)) = is_fn_start(line) {
                starts.push((idx, name));
            }
        }
        for (i, (start, name)) in starts.iter().enumerate() {
            if !signature_has_self(lines, *start) {
                continue;
            }
            if name.starts_with("migrate_v") || name.starts_with("test_") {
                continue;
            }
            let end = starts.get(i + 1).map_or(lines.len(), |(s, _)| *s);
            let body = lines[*start..end]
                .iter()
                .enumerate()
                .filter(|(off, _)| {
                    let idx = start + off;
                    !items.iter().any(|it| it.start <= idx && idx <= it.end)
                })
                .map(|(_, l)| *l)
                .collect::<Vec<_>>()
                .join("\n");
            let mut tables: HashSet<String> = tables_written(&body)
                .into_iter()
                .filter(|t| record_plane.contains(t.as_str()))
                .collect();
            for (cname, ctables) in &writing_consts {
                if names_ident(&body, cname) {
                    tables.extend(ctables.iter().cloned());
                }
            }
            if tables.is_empty() {
                continue;
            }
            out.surfaced.insert(name.clone());
            // The gate marker is looked for in the method's own span, consts
            // lifted out as for the tables.
            if GATE_MARKERS.iter().any(|g| body.contains(g)) {
                out.gated.insert(name.clone());
                continue;
            }
            if bookkeeping.contains(name.as_str()) {
                continue;
            }
            let mut tv: Vec<String> = tables.into_iter().collect();
            tv.sort();
            out.ungated
                .push((format!("{file}:{name}"), start + 1, tv.join(",")));
        }
    }
    out.ungated.sort();
    out
}

fn assert_clean(scan: &Scan) {
    let mut missing_required: Vec<String> = MUST_BE_GATED
        .iter()
        .filter(|n| !scan.gated.contains(**n))
        .map(|n| (*n).to_string())
        .collect();
    missing_required.sort();

    assert!(
        missing_required.is_empty(),
        "B9 required PostgresStore methods are not gated: {}",
        missing_required.join(", ")
    );
    assert!(
        scan.ungated.is_empty(),
        "B9 pg-write structural: PostgresStore methods write record-plane tables without gate_record_stop:\n  {}\n(add a gate, or justify as bookkeeping in BOOKKEEPING)",
        scan.ungated
            .iter()
            .map(|(n, line, table)| format!("{n}:{line} writes {table}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    let mut missed_surface: Vec<&str> = MUST_SURFACE_AS_WRITE
        .iter()
        .copied()
        .filter(|n| !scan.surfaced.contains(*n))
        .collect();
    missed_surface.sort_unstable();
    assert!(
        missed_surface.is_empty(),
        "B10 multi-line UPDATE scanner missed: {} (the body scan must see these writes)",
        missed_surface.join(", ")
    );
}

#[test]
fn record_stop_pg_write_methods_gate_or_bookkeeping_b9() {
    let sources: Vec<(String, String)> = pg_sources::pg_adapter_sources()
        .into_iter()
        .map(|s| (s.rel, s.text))
        .collect();
    assert_clean(&scan(&sources));
}

// ---------------------------------------------------------------------------
// #4023 red-proof cells: the scanner must see each shape below as an UNGATED
// write. They run on synthetic sources, so they prove the scanner itself, and
// were each shown RED against the earlier "cut the span at the first column-0
// `}`" version of this scan.
// ---------------------------------------------------------------------------

/// A synthetic one-file adapter: `body` is the text of an `impl` block, `tail`
/// follows the impl. The two `MUST_BE_GATED` / `MUST_SURFACE_AS_WRITE` names are not needed
/// because these cells inspect `Scan` directly rather than `assert_clean`.
fn synth(impl_body: &str, tail: &str) -> Scan {
    let src = format!("impl PostgresStore {{\n{impl_body}}}\n{tail}");
    scan(&[("src/store/postgres/synth.rs".to_string(), src)])
}

fn names_ungated(scan: &Scan, method: &str) -> bool {
    scan.ungated
        .iter()
        .any(|(n, _, _)| n.ends_with(&format!(":{method}")))
}

#[test]
fn const_sql_defined_after_the_impl_is_credited_to_its_method_4023_p5a() {
    let s = synth(
        "    async fn writer(&self) {\n        sqlx::query(SQL_PLANT).execute(&self.pool);\n    }\n",
        "const SQL_PLANT: &str = \"UPDATE memories SET title = 'x' WHERE id = $1\";\n",
    );
    assert!(names_ungated(&s, "writer"), "P5a: {:?}", s.ungated);
}

#[test]
fn const_sql_defined_before_the_impl_is_credited_to_its_method_4023_p5b() {
    let src = "const SQL_PLANT: &str = \"DELETE FROM memories WHERE id = $1\";\n\
               impl PostgresStore {\n    async fn writer(&self) {\n        \
               sqlx::query(SQL_PLANT).execute(&self.pool);\n    }\n}\n";
    let s = scan(&[("src/store/postgres/synth.rs".to_string(), src.to_string())]);
    assert!(names_ungated(&s, "writer"), "P5b: {:?}", s.ungated);
}

#[test]
fn const_sql_is_credited_across_files_4023() {
    // The pg_merge_inbound shape: the write SQL const lives in postgres.rs,
    // the method that runs it in a child module.
    let root = "const SQL_PLANT: &str = \"UPDATE memories SET title = 'x'\";\n".to_string();
    let child = "impl PostgresStore {\n    async fn writer(&self) {\n        \
                 sqlx::query(SQL_PLANT).execute(&self.pool);\n    }\n}\n"
        .to_string();
    let s = scan(&[
        ("src/store/postgres.rs".to_string(), root),
        ("src/store/postgres/synth.rs".to_string(), child),
    ]);
    assert!(names_ungated(&s, "writer"), "cross-file: {:?}", s.ungated);
}

#[test]
fn gated_method_with_const_sql_is_green_and_const_is_not_charged_to_a_neighbour_4023() {
    // The apply_remote_restore_pg shape: method A (no SQL) is followed, after
    // its impl, by a const used only by the gated method B.
    let src = "impl PostgresStore {\n    async fn a_no_sql(&self) {\n        let _ = 1;\n    }\n}\n\
               const SQL_B: &str = \"UPDATE checkpoints SET state = $1\";\n\
               impl PostgresStore {\n    async fn b_gated(&self) {\n        \
               self.gate_record_stop().await?;\n        sqlx::query(SQL_B);\n    }\n}\n";
    let s = scan(&[("src/store/postgres/synth.rs".to_string(), src.to_string())]);
    assert!(s.ungated.is_empty(), "false red: {:?}", s.ungated);
    assert!(s.gated.contains("b_gated"), "B must surface as gated");
    assert!(
        !s.surfaced.contains("a_no_sql"),
        "const charged to neighbour"
    );
}

#[test]
fn column_zero_brace_in_a_string_does_not_hide_a_later_write_4023_p6() {
    let s = synth(
        "    async fn writer(&self) {\n        let _j = r#\"\n}\n\"#;\n        \
         sqlx::query(\"UPDATE memories SET title = 'x'\");\n    }\n",
        "",
    );
    assert!(names_ungated(&s, "writer"), "P6: {:?}", s.ungated);
}

#[test]
fn removing_the_gate_from_a_const_sql_method_is_red_4023() {
    // pg_merge_inbound shape: the only write SQL is a const; the method gates.
    let gated = "const SQL_M: &str = \"UPDATE memories SET title = 'x'\";\n\
                 impl PostgresStore {\n    async fn m(&self) {\n        \
                 self.gate_record_stop().await?;\n        sqlx::query(SQL_M);\n    }\n}\n";
    let ungated = gated.replace("self.gate_record_stop().await?;", "");
    let g = scan(&[("a.rs".to_string(), gated.to_string())]);
    let u = scan(&[("a.rs".to_string(), ungated)]);
    assert!(
        g.ungated.is_empty(),
        "gated form must be green: {:?}",
        g.ungated
    );
    assert!(
        names_ungated(&u, "m"),
        "ungated form must be red: {:?}",
        u.ungated
    );
}
