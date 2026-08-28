// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Wave-2 B9 — POSTGRES-side structural record-stop completeness.
//!
//! Every `PostgresStore` method whose body contains INSERT/UPDATE/DELETE
//! against a record-plane table must call `gate_record_stop`, except a
//! minimal bookkeeping allowlist (touch / `fold_recall` / confidence-decay /
//! recall-observation). In-tx free functions (no `&self`) are out of
//! scope here — they cannot call the SAL gate; the B7 allowlist names
//! their gated callers. `append_signed_event` stays ungated so resume
//! can persist the attestation (ERRORS-09).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

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
    "fold_recall_accesses",
    "apply_confidence_decay_stamp",
    "recall_observation_insert",
    "recall_observation_prune_guarded",
];

/// Round-6 named siblings. Must gate even if someone re-allowlists them.
const MUST_BE_GATED: &[&str] = &["reflect_with_hooks", "update_embedding", "link_internal"];

fn write_sql_table(line: &str) -> Option<String> {
    let t = line.trim_start();
    if t.starts_with("//") {
        return None;
    }
    let upper = line.to_ascii_uppercase();
    let extract_after = |needle: &str| -> Option<String> {
        let idx = upper.find(needle)?;
        let rest = &line[idx + needle.len()..];
        let name: String = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            None
        } else {
            Some(name.to_ascii_lowercase())
        }
    };
    if upper.contains("INSERT") && upper.contains(" INTO ") {
        return extract_after(" INTO ");
    }
    if upper.contains("DELETE FROM") {
        return extract_after(" FROM ");
    }
    if upper.contains("UPDATE ") && upper.contains(" SET") {
        return extract_after("UPDATE ");
    }
    None
}

fn is_fn_start(line: &str) -> Option<(usize, String)> {
    let indent = line.len() - line.trim_start().len();
    let t = line.trim_start();
    let t = t
        .strip_prefix("pub(crate) ")
        .or_else(|| t.strip_prefix("pub "))
        .unwrap_or(t);
    let t = t.strip_prefix("async ").unwrap_or(t);
    if let Some(rest) = t.strip_prefix("fn ") {
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            return None;
        }
        return Some((indent, name));
    }
    None
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

#[test]
fn record_stop_pg_write_methods_gate_or_bookkeeping_b9() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/store/postgres.rs");
    let raw = fs::read_to_string(&path).expect("postgres.rs");
    let text = strip_test_mod(&raw);
    let lines: Vec<&str> = text.lines().collect();

    let mut starts: Vec<(usize, String)> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if let Some((_, name)) = is_fn_start(line) {
            starts.push((idx, name));
        }
    }

    let bookkeeping: HashSet<&str> = BOOKKEEPING.iter().copied().collect();
    let record_plane: HashSet<&str> = RECORD_PLANE.iter().copied().collect();
    let mut gated_hits: HashMap<String, bool> = MUST_BE_GATED
        .iter()
        .map(|n| ((*n).to_string(), false))
        .collect();
    let mut ungated: Vec<(String, usize, String)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for (idx, line) in lines.iter().enumerate() {
        let Some(table) = write_sql_table(line) else {
            continue;
        };
        if !record_plane.contains(table.as_str()) {
            continue;
        }
        let Some(&(start, ref name)) = starts.iter().rev().find(|(s, _)| *s <= idx) else {
            continue;
        };
        if !signature_has_self(&lines, start) {
            continue;
        }
        if name.starts_with("migrate_v") || name.starts_with("test_") {
            continue;
        }
        if !seen.insert(name.clone()) {
            continue;
        }
        let end = starts
            .iter()
            .find(|(s, _)| *s > start)
            .map_or(lines.len(), |(s, _)| *s);
        let body = &lines[start..end];
        let has_gate = body
            .iter()
            .any(|l| GATE_MARKERS.iter().any(|g| l.contains(g)));
        if has_gate {
            if let Some(flag) = gated_hits.get_mut(name) {
                *flag = true;
            }
            continue;
        }
        if bookkeeping.contains(name.as_str()) {
            continue;
        }
        ungated.push((name.clone(), start + 1, table));
    }

    let mut missing_required: Vec<String> = gated_hits
        .iter()
        .filter_map(|(n, hit)| if *hit { None } else { Some(n.clone()) })
        .collect();
    missing_required.sort();
    ungated.sort();

    assert!(
        missing_required.is_empty(),
        "B9 required PostgresStore methods are not gated: {}",
        missing_required.join(", ")
    );
    assert!(
        ungated.is_empty(),
        "B9 pg-write structural: PostgresStore methods write record-plane tables without gate_record_stop:\n  {}\n(add a gate, or justify as bookkeeping in BOOKKEEPING)",
        ungated
            .iter()
            .map(|(n, line, table)| format!("postgres.rs:{line} {n} writes {table}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}
