// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8341 - ratchet over every raw SQLite write to the `memories` table.
//!
//! The v102 guard aborts any `_agents` write that does not carry the
//! authoritative projection, so a new raw write site cannot corrupt the FTS
//! index; it can still start failing writes. This ratchet makes every new
//! site a visible decision: a site added, moved to another fn or removed
//! changes the table below, and the author classifies it (projects through
//! `storage::agent_projection`, or never writes the projected columns of a
//! bound registration row).
//!
//! The scan covers non-test production code under `src/` outside the
//! postgres adapter (PG has no rewriting trigger; see the PR body for the
//! backend difference). Test regions are tracked by brace depth.

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use std::collections::BTreeMap;
use std::path::Path;

/// (file under src/, enclosing fn or const/static, raw write count).
///
/// Projecting funnels: `insert_inner` via `INSERT_UPSERT_SQL`,
/// `insert_with_conflict`, `update_with_expected_version_in_txn` (#9405),
/// `consolidate_with_expected_versions` (insert), `restore_archived_impl`,
/// `restore_archived_for_caller`, `insert_if_newer` via `INSERT_IF_NEWER_SQL`,
/// `overwrite_full_row_by_id`, `bind_agent_pubkey_no_tx` (ledger values),
/// `revoke_agent_pubkey_no_tx` (no open row after the supersede). Every
/// other site writes columns outside the projection or merges metadata with
/// the reserved keys kept, so the guard predicate is unchanged by it.
const PINNED_WRITE_SITES_8341: &[(&str, &str, usize)] = &[
    ("atomisation/mod.rs", "archive_source", 1),
    ("atomisation/mod.rs", "write_atom", 1),
    ("confidence/decay.rs", "apply_decay_touch", 1),
    ("curator/reports.rs", "stamp_backlog_chunk", 1),
    (
        "handlers/consolidate_federation.rs",
        "sqlite_finalize_and_disposition",
        1,
    ),
    ("handlers/memories.rs", "promote_memory", 1),
    ("storage/decontaminate.rs", "observe_and_release_sqlite", 1),
    ("storage/lifecycle_write.rs", "set_lifecycle_state", 1),
    ("storage/migrations.rs", "backfill_memory_cids", 1),
    ("storage/migrations.rs", "migrate", 5),
    ("storage/mod.rs", "INSERT_IF_NEWER_SQL", 1),
    ("storage/mod.rs", "INSERT_UPSERT_SQL", 1),
    ("storage/mod.rs", "SQL_UPDATE_EMBEDDING_NULL_DIM", 1),
    ("storage/mod.rs", "SQL_UPDATE_EMBEDDING_WITH_DIM", 1),
    (
        "storage/mod.rs",
        "SQL_UPDATE_METADATA_AND_UPDATED_AT_BY_ID",
        1,
    ),
    ("storage/mod.rs", "adopt_legacy_embedding_space", 1),
    ("storage/mod.rs", "consolidate_with_expected_versions", 2),
    ("storage/mod.rs", "crypto_erase_record_envelope", 1),
    ("storage/mod.rs", "dequarantine", 1),
    ("storage/mod.rs", "fold_recall_accesses", 1),
    ("storage/mod.rs", "forget_scrub_cid_genesis", 1),
    ("storage/mod.rs", "insert_with_conflict", 1),
    ("storage/mod.rs", "operator_dequarantine", 1),
    ("storage/mod.rs", "overwrite_full_row_by_id", 1),
    ("storage/mod.rs", "reconcile_envelope_owner", 1),
    ("storage/mod.rs", "reown", 1),
    ("storage/mod.rs", "restore_archived_for_caller", 1),
    ("storage/mod.rs", "restore_archived_impl", 1),
    ("storage/mod.rs", "revoke_agent_pubkey_no_tx", 1),
    ("storage/mod.rs", "set_row_metadata", 1),
    ("storage/mod.rs", "stamp_contaminated_descendants_as", 1),
    ("storage/mod.rs", "stamp_embedding_space_attested", 2),
    ("storage/mod.rs", "swarm_rewind", 1),
    ("storage/mod.rs", "touch", 1),
    ("storage/mod.rs", "touch_many", 1),
    ("storage/pubkey_history.rs", "bind_agent_pubkey_no_tx", 1),
    (
        "storage/versioned_update_txn.rs",
        "update_with_expected_version_in_txn",
        1,
    ),
    ("store/sqlite.rs", "reclassify_memory_kind", 1),
    ("store/sqlite/owner_gate_txn_3957.rs", "arm_interloper", 1),
];
/// Total of [`PINNED_WRITE_SITES_8341`]; a second pin so a table edit that
/// drops a row is visible in review.
const PINNED_WRITE_SITE_TOTAL_8341: usize = 45;
/// Source size ceiling for the scanner time bound (bytes).
const SCAN_BOUND_BYTES: usize = 200_000;
/// Wall-clock ceiling for scanning [`SCAN_BOUND_BYTES`].
const SCAN_BOUND_MS: u128 = 2_000;

fn is_test_file(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name.ends_with("tests.rs")
        || name.contains("_test")
        || name.starts_with("test_")
        || rel.split('/').any(|part| part == "tests")
}

/// The identifier after `keyword` (`fn`, `const`, `static`) in `code`.
fn ident_after(code: &str, keyword: &str) -> Option<String> {
    let mut search = code;
    while let Some(at) = search.find(keyword) {
        let before_ok = search[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_');
        let rest = &search[at + keyword.len()..];
        if before_ok && rest.starts_with(char::is_whitespace) {
            let ident: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !ident.is_empty() {
                return Some(ident);
            }
        }
        search = rest;
    }
    None
}

/// `INSERT [OR x] INTO memories`, `REPLACE INTO memories`, `UPDATE [OR x]
/// memories` (not `memories_fts` or any other `memories_` table).
fn is_raw_memories_write(code: &str) -> bool {
    let words: Vec<String> = code
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_uppercase)
        .collect();
    words.iter().enumerate().any(|(i, w)| {
        if w != "MEMORIES" || i == 0 {
            return false;
        }
        let prev = words[i - 1].as_str();
        let prev2 = i.checked_sub(2).map(|j| words[j].as_str());
        let prev3 = i.checked_sub(3).map(|j| words[j].as_str());
        match prev {
            "INTO" => matches!(prev2, Some("INSERT" | "REPLACE")) || prev3 == Some("INSERT"),
            "UPDATE" => true,
            _ => prev2 == Some("OR") && prev3 == Some("UPDATE"),
        }
    })
}

/// (enclosing label, count) of raw writes in one non-test file's text.
fn scan_source(text: &str) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    let mut depth: usize = 0;
    let mut pending_cfg_test = false;
    let mut test_until: Option<usize> = None;
    let mut fn_stack: Vec<(usize, String)> = Vec::new();
    let mut pending_fn: Option<String> = None;
    let mut last_item: String = String::new();
    for line in text.lines() {
        let code = line.split("//").next().unwrap_or("");
        if code.contains("#[cfg(test") || code.contains("#[cfg(all(test") {
            pending_cfg_test = true;
        }
        if let Some(name) = ident_after(code, "fn") {
            pending_fn = Some(name);
        }
        for keyword in ["const", "static"] {
            if let Some(name) = ident_after(code, keyword) {
                last_item = name;
            }
        }
        if test_until.is_none() && is_raw_memories_write(code) {
            let label = pending_fn
                .clone()
                .or_else(|| fn_stack.last().map(|(_, n)| n.clone()))
                .unwrap_or_else(|| last_item.clone());
            *out.entry(label).or_insert(0) += 1;
        }
        for ch in code.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    if pending_cfg_test && test_until.is_none() {
                        test_until = Some(depth);
                    }
                    pending_cfg_test = false;
                    if let Some(name) = pending_fn.take() {
                        fn_stack.push((depth, name));
                    }
                }
                '}' => {
                    if fn_stack.last().is_some_and(|(d, _)| *d == depth) {
                        fn_stack.pop();
                    }
                    if test_until == Some(depth) {
                        test_until = None;
                    }
                    depth = depth.saturating_sub(1);
                }
                ';' if pending_cfg_test && test_until.is_none() => pending_cfg_test = false,
                _ => {}
            }
        }
    }
    out
}

fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<(String, String), usize>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            walk(&path, root, out);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        if rel.contains("postgres") || is_test_file(&rel) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read source");
        for (label, count) in scan_source(&text) {
            out.insert((rel.clone(), label), count);
        }
    }
}

#[test]
fn raw_memories_write_sites_are_pinned_8341() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut actual = BTreeMap::new();
    walk(&root, &root, &mut actual);
    let pinned: BTreeMap<(String, String), usize> = PINNED_WRITE_SITES_8341
        .iter()
        .map(|(f, l, n)| (((*f).to_string(), (*l).to_string()), *n))
        .collect();
    let added: Vec<_> = actual
        .iter()
        .filter(|(k, v)| pinned.get(*k) != Some(*v))
        .collect();
    let removed: Vec<_> = pinned
        .iter()
        .filter(|(k, v)| actual.get(*k) != Some(*v))
        .collect();
    assert!(
        added.is_empty() && removed.is_empty(),
        "raw `memories` write sites changed. New or changed: {added:?}. Gone: {removed:?}. \
         Route a write of a bound _agents row through storage::agent_projection, then update \
         PINNED_WRITE_SITES_8341"
    );
    assert_eq!(
        PINNED_WRITE_SITES_8341
            .iter()
            .map(|(_, _, n)| n)
            .sum::<usize>(),
        PINNED_WRITE_SITE_TOTAL_8341
    );
}

/// Mutation proof: a new raw write in a fn is found, one in a test module
/// or a comment is not, and `memories_fts` is not `memories`.
#[test]
fn scanner_finds_a_new_raw_write_8341() {
    let source = r#"
fn sneaky_writer(conn: &Connection) {
    conn.execute("UPDATE memories SET content = ?1", [x]);
    conn.execute("INSERT OR REPLACE INTO memories (id) VALUES (?1)", [x]);
    conn.execute("INSERT INTO memories_fts(memories_fts) VALUES('rebuild')", []);
    // UPDATE memories SET content = 'in a comment'
}
static SNEAKY_SQL: &str = "UPDATE OR IGNORE memories SET title = ?1";
#[cfg(test)]
mod tests {
    fn t() { conn.execute("UPDATE memories SET content = 'test'", []); }
}
"#;
    let found = scan_source(source);
    assert_eq!(
        found,
        BTreeMap::from([
            ("SNEAKY_SQL".to_string(), 1),
            ("sneaky_writer".to_string(), 2)
        ])
    );
}

/// The scanner is linear: a 200K-byte source scans under the bound.
#[test]
fn scanner_is_bounded_on_large_input_8341() {
    let line = "    conn.execute(\"UPDATE memories SET x = 1\", []); { }\n";
    let mut source = String::from("fn big() {\n");
    while source.len() < SCAN_BOUND_BYTES {
        source.push_str(line);
    }
    source.push_str("}\n");
    let started = std::time::Instant::now();
    let found = scan_source(&source);
    assert!(started.elapsed().as_millis() < SCAN_BOUND_MS);
    assert_eq!(found.len(), 1);
}
