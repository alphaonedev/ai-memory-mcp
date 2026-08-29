// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Wave-2 B9 — POSTGRES-side structural record-stop completeness.
//!
//! Every `PostgresStore` method whose body contains INSERT/UPDATE/DELETE
//! against a record-plane table must call `gate_record_stop`, except a
//! minimal bookkeeping allowlist (touch / confidence-decay /
//! recall-observation / `refund_update_growth` / `mark_recall_consumed`).
//! `fold_recall_accesses` GATES (mid→long promote is a record-plane
//! mutation). In-tx free functions (no `&self`) are out of
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
    let mut surfaced: HashSet<String> = HashSet::new();

    for (i, (start, name)) in starts.iter().enumerate() {
        if !signature_has_self(&lines, *start) {
            continue;
        }
        if name.starts_with("migrate_v") || name.starts_with("test_") {
            continue;
        }
        let end = starts.get(i + 1).map_or(lines.len(), |(s, _)| *s);
        let body = lines[*start..end].join("\n");
        let tables: Vec<String> = tables_written(&body)
            .into_iter()
            .filter(|t| record_plane.contains(t.as_str()))
            .collect();
        if tables.is_empty() {
            continue;
        }
        surfaced.insert(name.clone());
        let has_gate = GATE_MARKERS.iter().any(|g| body.contains(g));
        if has_gate {
            if let Some(flag) = gated_hits.get_mut(name) {
                *flag = true;
            }
            continue;
        }
        if bookkeeping.contains(name.as_str()) {
            continue;
        }
        ungated.push((name.clone(), start + 1, tables.join(",")));
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

    let mut missed_surface: Vec<&str> = MUST_SURFACE_AS_WRITE
        .iter()
        .copied()
        .filter(|n| !surfaced.contains(*n))
        .collect();
    missed_surface.sort_unstable();
    assert!(
        missed_surface.is_empty(),
        "B10 multi-line UPDATE scanner missed: {} (the body scan must see these writes)",
        missed_surface.join(", ")
    );
}
