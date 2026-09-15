// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 Consolidation Unit 1 (#3690 #3695 #3696 #3712) — the DERIVED
//! structural pin over every `(title, namespace)` write funnel on both
//! adapters. The Conductor's ruling: a test that asserts N NAMED sites are
//! correct cannot see the (N+1)th — it passes precisely because someone
//! forgot. So nothing here is spelled by hand: the target set is DERIVED from
//! the source on every run, and the pin FAILS when it finds a funnel that is
//! not routed through the ONE admission predicate.
//!
//! Two derivations, both over `src/**` code lines (comment lines skipped):
//!
//! 1. STATEMENTS — every `ON CONFLICT` / `{conflict_target}` occurrence,
//!    attributed to its table by walking back to the nearest `INSERT INTO`
//!    (textually, so a statement assembled in a `static` or a `format!` is
//!    followed — the shape a string-boundary heuristic loses). Every
//!    `memories` target must spell `TITLE_SLOT_CONFLICT_TARGET` (the v100
//!    PARTIAL index is matched only by repeating its predicate; the bare form
//!    fails every store on that funnel) or be the `ON CONFLICT (id)` re-target
//!    of the same-id tombstone restore. The derived count is reported.
//!
//! 2. FUNNELS — every function that CONSTRUCTS a title-collision conflict
//!    (`ConflictError {`, `StoreError::Conflict {`, or one of the two
//!    renderers) must, in its own body, consult the admission predicate
//!    (`title_slot_admission` / `pg_title_slot_admission` / the holder probes
//!    / `find_by_title_namespace`, which is the holder probe filtered to the
//!    viewer) — or be one of the REVIEWED CONSUMERS below, each with its
//!    reason (a mapper / renderer / delegate of a routed funnel, or a
//!    conflict that is not a title collision at all). A new constructor that
//!    is neither routed nor reviewed FAILS here.
//!
//! The arm × occupant matrix itself (all three `InsertConflictArm`s,
//! including the same-id `RestoreSameId` CAS and the #2894 same-id
//! tombstone) lives ONCE in `visibility::title_slot_disposition`; both
//! adapters only route. That is pinned by the unit tests beside it and by
//! `tests/title_slot_admission_3690{,_pg}.rs`.

use std::collections::BTreeMap;
use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn src_files() -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let p = entry.expect("entry").path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p.to_string_lossy().into_owned());
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out.sort();
    out
}

fn is_comment_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("--")
}

/// Strip the visibility / `async` / `unsafe` prefixes off an item header.
fn item_header(line: &str) -> Option<(&'static str, String)> {
    let mut t = line.trim_start();
    if let Some(rest) = t.strip_prefix("pub") {
        t = if let Some(rest) = rest.strip_prefix('(') {
            rest.split_once(')').map_or(rest, |(_, r)| r).trim_start()
        } else {
            rest.trim_start()
        };
    }
    for pre in ["async ", "unsafe ", "const fn "] {
        if let Some(rest) = t.strip_prefix(pre) {
            t = if pre == "const fn " {
                rest
            } else {
                rest.trim_start()
            };
            if pre == "const fn " {
                let name: String = t
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                return (!name.is_empty()).then_some(("fn", name));
            }
        }
    }
    for kw in ["fn ", "static ", "const "] {
        if let Some(rest) = t.strip_prefix(kw) {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some((kw.trim_end(), name));
            }
        }
    }
    None
}

/// The name of the `fn` / `static` / `const` item enclosing line `i`
/// (nearest preceding item header), and its line index.
fn enclosing_item(lines: &[&str], i: usize) -> Option<(String, usize)> {
    (0..=i)
        .rev()
        .find_map(|j| item_header(lines[j]).map(|(_, name)| (name, j)))
}

/// The body text of the item that starts at `start` (up to the next item
/// header at the same or lower indentation).
fn item_body(lines: &[&str], start: usize) -> String {
    let end = (start + 1..lines.len())
        .find(|&j| item_header(lines[j]).is_some())
        .unwrap_or(lines.len());
    lines[start..end].join("\n")
}

const ROUTED_MARKERS: &[&str] = &[
    "title_slot_admission(",
    "pg_title_slot_admission(",
    "title_slot_holder(",
    "pg_title_slot_holder(",
    "find_by_title_namespace(",
];

/// Routed = a CODE line (comments stripped — a comment that names the
/// predicate is not a call to it) invokes one of the admission entry points.
fn is_routed(body: &str) -> bool {
    body.lines()
        .filter(|l| !is_comment_line(l))
        .any(|l| ROUTED_MARKERS.iter().any(|m| l.contains(m)))
}

// ---------------------------------------------------------------------------
// Derivation 1 — statements
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Statement {
    file: String,
    line: usize,
    table: Option<String>,
    text: String,
}

fn derive_statements() -> Vec<Statement> {
    let mut out = Vec::new();
    for file in src_files() {
        let text = std::fs::read_to_string(&file).expect("read");
        let lines: Vec<&str> = text.lines().collect();
        for (i, l) in lines.iter().enumerate() {
            if is_comment_line(l) {
                continue;
            }
            let compact = l.replace(' ', "");
            let mentions = l.contains("ON CONFLICT")
                || l.contains("{conflict_target}")
                || compact.contains("ONCONFLICT");
            if !mentions || l.contains("pub const TITLE_SLOT_CONFLICT_TARGET") {
                continue;
            }
            let mut table = None;
            for j in (i.saturating_sub(400)..=i).rev() {
                if let Some(pos) = lines[j].find("INSERT ") {
                    let rest = &lines[j][pos..];
                    if let Some(after) = rest.find("INTO ") {
                        let name: String = rest[after + 5..]
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect();
                        if !name.is_empty() {
                            table = Some(name);
                            break;
                        }
                    }
                }
            }
            out.push(Statement {
                file: file.clone(),
                line: i + 1,
                table,
                text: l.trim().to_string(),
            });
        }
    }
    out
}

/// Every `memories` conflict target spells the ONE const or is the same-id
/// PRIMARY-KEY re-target; the bare `(title, namespace)` form is refused.
#[test]
fn every_derived_memories_conflict_target_spells_the_one_const_3690() {
    let statements = derive_statements();
    let memories: Vec<&Statement> = statements
        .iter()
        .filter(|s| s.table.as_deref() == Some("memories"))
        .collect();
    let mut bare = Vec::new();
    let mut placeholders = 0usize;
    for s in &memories {
        let compact = s.text.replace(' ', "");
        if compact.contains("ONCONFLICT(title,namespace)")
            && !s.text.contains("TITLE_SLOT_CONFLICT_TARGET")
        {
            bare.push(format!("{}:{}: {}", s.file, s.line, s.text));
        }
        if s.text.contains("{conflict_target} DO") {
            placeholders += 1;
        }
    }
    assert!(
        bare.is_empty(),
        "#3690: a bare `ON CONFLICT (title, namespace)` target on `memories` no longer matches \
         the v100 PARTIAL index and fails every store on that funnel — spell \
         `crate::models::TITLE_SLOT_CONFLICT_TARGET`:\n{}",
        bare.join("\n")
    );
    // The DERIVED statement count (reported, not hand-spelled): the Unit 1
    // census measured TEN `(title, namespace)` statements on `memories`. A
    // drop below it means a funnel stopped spelling the const (the bare form
    // is caught above; a target that vanished entirely lands here).
    assert!(
        placeholders >= 10,
        "derived `memories` `{{conflict_target}}` statements = {placeholders}, expected >= 10 \
         (census 2026-09-15); derived memories-attributed lines:\n{}",
        memories
            .iter()
            .map(|s| format!("  {}:{}: {}", s.file, s.line, s.text))
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprintln!(
        "derived `memories` conflict statements: {placeholders} (of {} memories-attributed lines)",
        memories.len()
    );
}

// ---------------------------------------------------------------------------
// Derivation 2 — funnels
// ---------------------------------------------------------------------------

const CONSTRUCT_MARKERS: &[&str] = &[
    "ConflictError {",
    "StoreError::Conflict {",
    "conflict_error_message(",
    "conflict_409_response(",
];

/// REVIEWED consumers: functions that construct a conflict value but do not
/// DECIDE one — mappers / renderers / delegates of a routed funnel, or a
/// conflict that is not a `(title, namespace)` collision. Keyed `file suffix
/// -> fn name -> reason`. A new constructor absent from this table and not
/// routed FAILS the pin; a stale entry (fn gone) FAILS too.
fn reviewed_consumers() -> BTreeMap<(&'static str, &'static str), &'static str> {
    BTreeMap::from([
        (
            ("src/storage/mod.rs", "fmt"),
            "the `ConflictError` Display impl renders a value a routed funnel built",
        ),
        (
            ("src/handlers/create.rs", "conflict_409_response"),
            "renders the id `resolve_create_conflict_title` obtained from the viewer-scoped probe",
        ),
        (
            ("src/handlers/create.rs", "insert_create_with_quota"),
            "maps the typed error `db::insert_as` / `insert_no_overwrite_as` (routed) returned",
        ),
        (
            ("src/handlers/create.rs", "create_pg_store_err_to_response"),
            "maps `StoreError::Conflict` from the routed pg `store` funnel to a 409",
        ),
        (
            ("src/handlers/postgres_gate.rs", "store_err_to_response"),
            "generic StoreError → HTTP mapper; the value comes from a routed funnel",
        ),
        (
            (
                "src/mcp/tools/store/validation.rs",
                "conflict_error_message",
            ),
            "renders the id `parse_and_build_memory` obtained from the viewer-scoped probe",
        ),
        (
            ("src/mcp/tools/store/mod.rs", "handle_store_inner"),
            "maps the typed error `db::insert_as` / `insert_no_overwrite_as` (routed) returned",
        ),
        (
            ("src/store/sqlite.rs", "restore_or_conflict"),
            "delegates to `db::insert_restore_same_id` (the routed `insert_inner`, RestoreSameId arm) and maps its error",
        ),
        (
            ("src/store/sqlite.rs", "store_with_embedding_no_overwrite"),
            "delegates to `db::insert_no_overwrite` (the routed `insert_inner`, Refuse arm) and maps its error",
        ),
        (
            ("src/autonomy.rs", "restore_snapshot"),
            "consumes `restore_or_conflict` (routed on both adapters) — the rollback refusal message",
        ),
        (
            ("src/curator/compaction.rs", "rollback_consolidation"),
            "consumes `restore_or_conflict` (routed on both adapters) — skip + warn per original",
        ),
        (
            ("src/store/postgres.rs", "archive_restore"),
            "an ID collision (the archived id is already live), not a title collision; the title-key INSERT…SELECT has no ON CONFLICT and surfaces a unique violation",
        ),
        (
            ("src/store/postgres.rs", "lease_acquire"),
            "a `leases` row conflict, not a `memories` title collision",
        ),
        (
            ("src/store/sqlite.rs", "lease_acquire"),
            "a `leases` row conflict, not a `memories` title collision",
        ),
    ])
}

/// A `#[test]` / `#[tokio::test]` fn (attribute within the five lines above
/// its header), or a fn that lies inside a `#[cfg(test)] mod … {` block.
///
/// Module membership is read off INDENTATION, which `cargo fmt --check`
/// makes load-bearing in this repository: every item inside a module is
/// indented one level deeper than the `mod` line, and the module ends at the
/// first non-blank line back at the module's own indent (its closing `}` or
/// the next sibling item). No brace lexing — a lexer that mis-reads one
/// string literal would silently classify every later funnel as "test" and
/// turn this pin off (which is exactly what happened to the first draft).
fn in_test_module(lines: &[&str], idx: usize) -> bool {
    let attr_window = &lines[idx.saturating_sub(5)..idx];
    if attr_window.iter().any(|l| {
        l.trim_start().starts_with("#[test]") || l.trim_start().starts_with("#[tokio::test")
    }) {
        return true;
    }
    let indent = |l: &str| l.len() - l.trim_start().len();
    let fn_indent = indent(lines[idx]);
    for j in (0..idx).rev() {
        let t = lines[j].trim_start();
        let is_mod = (t.starts_with("mod ")
            || t.starts_with("pub mod ")
            || t.starts_with("pub(crate) mod "))
            && t.trim_end().ends_with('{');
        let mod_indent = indent(lines[j]);
        if !is_mod || mod_indent >= fn_indent {
            continue;
        }
        // Still inside this module at `idx`? Leave as soon as a non-blank
        // line returns to the module's indent (or shallower).
        let inside = lines[j + 1..idx]
            .iter()
            .all(|l| l.trim().is_empty() || indent(l) > mod_indent);
        if !inside {
            continue;
        }
        let above = &lines[j.saturating_sub(3)..j];
        return above
            .iter()
            .any(|l| l.trim_start().starts_with("#[cfg(test)]"));
    }
    false
}

#[test]
fn every_derived_conflict_funnel_routes_through_the_admission_predicate_3690() {
    let reviewed = reviewed_consumers();
    let mut seen_reviewed = std::collections::BTreeSet::new();
    let mut unrouted = Vec::new();
    let mut routed = 0usize;
    for file in src_files() {
        let text = std::fs::read_to_string(&file).expect("read");
        let lines: Vec<&str> = text.lines().collect();
        let mut done = std::collections::BTreeSet::new();
        for (i, l) in lines.iter().enumerate() {
            if is_comment_line(l) || !CONSTRUCT_MARKERS.iter().any(|m| l.contains(m)) {
                continue;
            }
            let Some((name, start)) = enclosing_item(&lines, i) else {
                continue;
            };
            if !done.insert(start) {
                continue;
            }
            if in_test_module(&lines, start) {
                continue;
            }
            let body = item_body(&lines, start);
            // A renderer's own definition line contains its marker; skip
            // definitions of the marker fns themselves via the reviewed table.
            let suffix = reviewed
                .keys()
                .find(|(f, n)| file.ends_with(f) && *n == name.as_str())
                .copied();
            if let Some(key) = suffix {
                seen_reviewed.insert(key);
                continue;
            }
            if is_routed(&body) {
                routed += 1;
            } else {
                unrouted.push(format!("{file}:{}: fn {name}", start + 1));
            }
        }
    }
    assert!(
        unrouted.is_empty(),
        "#3690/#3696: these functions construct a title-collision conflict but consult neither the \
         admission predicate (`visibility::title_slot_admission` via the holder probes / \
         `find_by_title_namespace`) nor appear in the REVIEWED consumers table with a reason:\n{}",
        unrouted.join("\n")
    );
    let stale: Vec<String> = reviewed
        .keys()
        .filter(|k| !seen_reviewed.contains(k))
        .map(|(f, n)| format!("{f}::{n}"))
        .collect();
    assert!(
        stale.is_empty(),
        "stale reviewed-consumer entries (the fn no longer constructs a conflict, or was renamed): {stale:?}"
    );
    eprintln!(
        "derived conflict funnels: {routed} routed, {} reviewed consumers",
        seen_reviewed.len()
    );
    assert!(
        routed >= 12,
        "derived routed funnels = {routed}, expected >= 12 (census 2026-09-15)"
    );
}

/// Both v100 rungs and the const agree on the ONE predicate, and the
/// bootstrap schemas keep the FULL index (guardrail-D rule (f): a bootstrap
/// index must not reference a ladder-added column — `lifecycle_state` is
/// v64 — so the partial form is the LADDER's, rebuilt under the same name).
#[test]
fn v100_rungs_and_bootstrap_agree_on_the_predicate_3690() {
    let pred = ai_memory::models::TITLE_SLOT_INDEX_PREDICATE;
    for rel in [
        "migrations/sqlite/0084_v100_title_slot_live_rows.sql",
        "migrations/postgres/0057_v100_title_slot_live_rows.sql",
    ] {
        let ddl = read(rel);
        assert!(
            ddl.contains(&format!("WHERE {pred}")),
            "{rel} must rebuild the index PARTIAL on `{pred}`"
        );
        assert!(
            ddl.to_ascii_uppercase().contains("UNIQUE INDEX"),
            "{rel} keeps the index unique"
        );
    }
    for (rel, name) in [
        ("src/store/postgres_schema.sql", "memories_title_ns_uidx"),
        ("src/storage/migrations.rs", "idx_memories_title_ns"),
    ] {
        let text = read(rel);
        let start = text
            .find(&format!("CREATE UNIQUE INDEX IF NOT EXISTS {name}"))
            .unwrap_or_else(|| panic!("{rel}: bootstrap defines {name}"));
        let def = &text[start..text[start..].find(';').map_or(text.len(), |i| start + i)];
        assert!(
            !def.contains("WHERE"),
            "{rel}: the BOOTSTRAP {name} must stay FULL (rule (f)); the v100 rung makes it partial: {def}"
        );
    }
    assert_eq!(
        ai_memory::models::TITLE_SLOT_CONFLICT_TARGET,
        format!("ON CONFLICT (title, namespace) WHERE {pred}")
    );
}
