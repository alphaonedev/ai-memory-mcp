// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3175 — structural guard: every mutating `MemoryStore` method the
//! SQLITE adapter gates behind the record-stop MUST also be gated on the
//! POSTGRES adapter.
//!
//! # Why a source-scanning guard rather than a behavioural test
//!
//! The #3175 defect was not a wrong gate, it was a MISSING one:
//! `undo_in_place_edit` (a destructive content restore that also appends a
//! signed audit event) and `recover_turn_idempotent` (L2 transcript recovery)
//! ran to completion on postgres while the fleet-wide write kill switch was
//! engaged, because nobody noticed the pg twin had never grown the call the
//! sqlite twin makes on its first line. A behavioural test proves the two
//! methods that were found; only an enumeration over the WHOLE adapter proves
//! there is not a third. Adding a mutating method to `SqliteStore` without its
//! pg twin now fails here instead of in production.
//!
//! # The rule
//!
//! For each method whose `SqliteStore` body contains `self.gate_record_stop()`,
//! the `PostgresStore` body of the same name must EITHER
//!
//! * contain `self.gate_record_stop()` itself, OR
//! * delegate to another `PostgresStore` method that does.
//!
//! The delegation arm is checked, not assumed: the test resolves the callee
//! name and requires IT to be in the directly-gated set. (`restore_or_conflict`
//! and `store_with_embedding_no_overwrite` are the two real cases — both are
//! thin wrappers over the gated `store_with_embedding_inner`.)
//!
//! Text-scanning, not compiled against the adapters, so it runs on every
//! feature leg and needs no database.

#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use std::collections::{BTreeMap, BTreeSet};

/// Split an adapter source file into `method name -> method body`, for
/// methods declared at `impl`-block indentation (four spaces).
fn methods(src: &str) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut body = String::new();
    for line in src.lines() {
        if let Some(name) = method_name(line) {
            if let Some(prev) = current.take() {
                out.insert(prev, std::mem::take(&mut body));
            }
            current = Some(name);
        }
        if current.is_some() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some(prev) = current {
        out.insert(prev, body);
    }
    out
}

/// `    async fn foo(` / `    fn foo(` / `    pub(crate) async fn foo<` → `foo`.
fn method_name(line: &str) -> Option<String> {
    let rest = line.strip_prefix("    ")?;
    if rest.starts_with(' ') {
        return None; // deeper indentation: a nested fn/closure, not a method
    }
    let rest = rest
        .strip_prefix("pub(crate) ")
        .or_else(|| rest.strip_prefix("pub(super) "))
        .or_else(|| rest.strip_prefix("pub "))
        .unwrap_or(rest);
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    let rest = rest.strip_prefix("fn ")?;
    let end = rest.find(['(', '<', ' '])?;
    let name = &rest[..end];
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    Some(name.to_string())
}

const GATE_CALL: &str = "self.gate_record_stop()";

fn read(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn every_sqlite_record_stop_gated_method_is_gated_on_postgres_3175() {
    let sqlite = methods(&read("src/store/sqlite.rs"));
    let postgres = methods(&read("src/store/postgres.rs"));

    let sqlite_gated: BTreeSet<&String> = sqlite
        .iter()
        .filter(|(_, body)| body.contains(GATE_CALL))
        .map(|(name, _)| name)
        .collect();
    assert!(
        sqlite_gated.len() >= 20,
        "sqlite gate scan found only {} methods — the parser drifted from the \
         source shape, so this guard would silently pass on an ungated pg twin",
        sqlite_gated.len()
    );

    let pg_directly_gated: BTreeSet<&String> = postgres
        .iter()
        .filter(|(_, body)| body.contains(GATE_CALL))
        .map(|(name, _)| name)
        .collect();

    let mut ungated: Vec<String> = Vec::new();
    for name in &sqlite_gated {
        if pg_directly_gated.contains(*name) {
            continue;
        }
        let Some(pg_body) = postgres.get(*name) else {
            ungated.push(format!(
                "{name}: sqlite gates it, postgres does not implement it at all \
                 (the trait default would run UNGATED)"
            ));
            continue;
        };
        // Delegation arm — RESOLVED, not assumed: the callee must itself be a
        // directly-gated PostgresStore method.
        let delegates_to_gated = pg_directly_gated
            .iter()
            .any(|target| pg_body.contains(&format!("self.{target}(")));
        if !delegates_to_gated {
            ungated.push(format!(
                "{name}: sqlite gates it; the postgres twin neither calls \
                 {GATE_CALL} nor delegates to a gated PostgresStore method"
            ));
        }
    }

    assert!(
        ungated.is_empty(),
        "#3175 — the record-stop kill switch must cover BOTH backends. \
         Ungated postgres write paths:\n  {}",
        ungated.join("\n  ")
    );
}

/// Column-0 sqlite SSOT free-fns (`pub fn foo` in `storage/mod.rs`).
fn ssot_free_fns(src: &str) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut body = String::new();
    for line in src.lines() {
        if let Some(rest) = line
            .strip_prefix("pub(crate) fn ")
            .or_else(|| line.strip_prefix("pub fn "))
        {
            let end = rest.find(['(', '<', ' ']).unwrap_or(rest.len());
            let name = &rest[..end];
            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                if let Some(prev) = current.take() {
                    out.insert(prev, std::mem::take(&mut body));
                }
                current = Some(name.to_string());
            }
        }
        if current.is_some() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some(prev) = current {
        out.insert(prev, body);
    }
    out
}

#[test]
fn ssot_gated_inherent_pg_twins_must_gate_3175() {
    // B8 extension: #3175 originally only compared SAL *trait* method
    // names across adapters, so inherent PostgresStore writes whose
    // sqlite SSOT twin gates (update_with_expected_version — the
    // If-Match path) were invisible. Pair storage/mod.rs gated free-fns
    // with same-named PostgresStore methods.
    let ssot = ssot_free_fns(&read("src/storage/mod.rs"));
    let postgres = methods(&read("src/store/postgres.rs"));
    let pg_directly_gated: BTreeSet<&String> = postgres
        .iter()
        .filter(|(_, body)| body.contains(GATE_CALL))
        .map(|(name, _)| name)
        .collect();

    let mut ungated = Vec::new();
    for (name, body) in &ssot {
        if !body.contains("gate_storage_conn") {
            continue;
        }
        let Some(pg_body) = postgres.get(name) else {
            continue; // no pg method of this name — not a twin
        };
        if pg_directly_gated.contains(name) {
            continue;
        }
        let delegates = pg_directly_gated
            .iter()
            .any(|target| pg_body.contains(&format!("self.{target}(")));
        if !delegates {
            ungated.push(format!(
                "{name}: sqlite SSOT gates via gate_storage_conn; pg twin \
                 neither calls {GATE_CALL} nor delegates to a gated method"
            ));
        }
    }
    assert!(
        ungated.is_empty(),
        "#3175 B8 inherent-pg/SSOT parity:\n  {}",
        ungated.join("\n  ")
    );
}

#[test]
fn pg_if_match_and_dequarantine_raw_gate_directly_b8() {
    // Direct pins so a parser regression cannot drop the If-Match /
    // dequarantine_raw paths that #3175's original twin-matching missed.
    let postgres = methods(&read("src/store/postgres.rs"));
    for name in [
        "update_with_expected_version",
        "update_with_expected_version_once",
        "dequarantine",
        "dequarantine_raw",
    ] {
        let body = postgres
            .get(name)
            .unwrap_or_else(|| panic!("PostgresStore::{name} not found"));
        assert!(
            body.contains(GATE_CALL),
            "#3175 B8: PostgresStore::{name} must call {GATE_CALL}"
        );
    }
}

#[test]
fn the_two_methods_3175_fixed_gate_directly_on_postgres() {
    // Regression pin for the exact pair the R-405 scout found. Kept separate
    // from the enumeration above so a parser regression cannot mask it.
    let postgres = methods(&read("src/store/postgres.rs"));
    for name in ["undo_in_place_edit", "recover_turn_idempotent"] {
        let body = postgres
            .get(name)
            .unwrap_or_else(|| panic!("PostgresStore::{name} not found"));
        assert!(
            body.contains(GATE_CALL),
            "#3175: PostgresStore::{name} must call {GATE_CALL} — it writes \
             (undo restores content + appends a signed audit event; recover \
             inserts durable turn rows) and must refuse on a STOPPED plane"
        );
    }
}
