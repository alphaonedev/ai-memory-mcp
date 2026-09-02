// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3464 — STRUCTURAL pin: every postgres migration arm stamps its OWN
//! literal version, never `CURRENT_SCHEMA_VERSION`.
//!
//! ## The hazard
//!
//! `PostgresStore::migrate_vN` applies vN's DDL and then records the schema
//! version in the same transaction. If it records `CURRENT_SCHEMA_VERSION`
//! instead of the literal `N`, the arm stamps whatever the ladder tip happens
//! to be *at compile time* — which is correct on the day it lands and silently
//! WRONG the moment a later arm is added above it. A node that crashes between
//! the vN and vN+1 commits then restarts stamped at the tip, believes it is
//! fully migrated, and every later arm is skipped FOREVER. The DDL those arms
//! carry never runs, on a database that reports itself current.
//!
//! That is a data-integrity defect, not a cosmetic one: for #3464 specifically
//! it would mean `agent_pubkey_history` — the append-only ledger that keeps an
//! agent's superseded keys verifiable — silently absent on a node claiming to
//! be at v97.
//!
//! ## Why a structural test and not a convention
//!
//! The convention was already written down in EIGHTEEN separate arm comments
//! ("stamp the LITERAL N, not `CURRENT_SCHEMA_VERSION`") and it still got
//! violated twice in one release train: once on #3419's `migrate_v95` (fixed
//! when #3464 took v97) and once on #3344's `migrate_v96`. A comment on each
//! arm cannot fail a build; this test can.
//!
//! ## What is asserted
//!
//! For every `async fn migrate_vN(&self)` in `src/store/postgres.rs`, each
//! `record_schema_version(&mut tx, X)` inside its body must have `X == N` as a
//! bare integer literal. That is strictly stronger than banning
//! `CURRENT_SCHEMA_VERSION`: it also catches a copy-pasted neighbour's number.
//!
//! Source-text based, deliberately — the property is about what the ladder
//! SAYS, and it must hold on every feature leg including those that do not
//! compile the postgres adapter at all.

#![allow(clippy::doc_markdown)]

use std::path::Path;

/// Arms that legitimately record no version of their own (their stamp is
/// carried by a neighbouring arm or the caller). Enumerated so a NEW stampless
/// arm trips this test and gets a deliberate decision rather than passing in
/// silence.
const KNOWN_STAMPLESS_ARMS: &[&str] = &["migrate_v57", "migrate_v67", "migrate_v89"];

fn postgres_source() -> String {
    let path = Path::new("src/store/postgres.rs");
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Split the adapter source into `(arm_name, body)` pairs, one per
/// `async fn migrate_vN(&self)`. The body runs to the next line that is
/// exactly four-space-indented `}`, which is the rustfmt-canonical close of a
/// method inside an `impl` block.
fn migration_arms(src: &str) -> Vec<(String, String)> {
    let mut arms = Vec::new();
    let lines: Vec<&str> = src.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let Some(rest) = line.trim_start().strip_prefix("async fn migrate_v") else {
            continue;
        };
        let Some(num) = rest.split('(').next() else {
            continue;
        };
        if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let name = format!("migrate_v{num}");
        let mut body = String::new();
        for l in &lines[i + 1..] {
            if *l == "    }" {
                break;
            }
            body.push_str(l);
            body.push('\n');
        }
        arms.push((name, body));
    }
    arms
}

#[test]
fn every_pg_migration_arm_stamps_its_own_literal_version_3464() {
    let src = postgres_source();
    let arms = migration_arms(&src);
    assert!(
        arms.len() > 60,
        "the arm parser found only {} arms — it has drifted from the source shape \
         and would pass vacuously; fix the parser, do not relax the test",
        arms.len()
    );

    let mut violations = Vec::new();
    let mut stampless = Vec::new();
    for (name, body) in &arms {
        let expected = name
            .strip_prefix("migrate_v")
            .expect("arm names start with migrate_v");
        let mut stamps = Vec::new();
        for (idx, _) in body.match_indices("record_schema_version(&mut tx, ") {
            let tail = &body[idx + "record_schema_version(&mut tx, ".len()..];
            let arg: String = tail.chars().take_while(|c| *c != ')').collect();
            stamps.push(arg.trim().to_string());
        }
        if stamps.is_empty() {
            stampless.push(name.clone());
            continue;
        }
        for arg in stamps {
            if arg != expected {
                violations.push(format!(
                    "{name} stamps `{arg}` but must stamp the literal `{expected}`"
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "#3464: every postgres migration arm must record the version it ACTUALLY \
         applied, as a bare literal. An arm stamping `CURRENT_SCHEMA_VERSION` is \
         correct only until the next arm lands above it, after which a node that \
         crashes mid-ladder restarts stamped at the tip and skips every later arm \
         forever — the DDL never runs on a database reporting itself current. \
         Violations:\n  {}",
        violations.join("\n  ")
    );

    let mut unexpected: Vec<&String> = stampless
        .iter()
        .filter(|n| !KNOWN_STAMPLESS_ARMS.contains(&n.as_str()))
        .collect();
    unexpected.sort();
    assert!(
        unexpected.is_empty(),
        "#3464: these migration arms record NO schema version at all, and are not \
         in the documented KNOWN_STAMPLESS_ARMS allowlist. An arm that applies DDL \
         without stamping leaves the ladder unable to tell whether it ran. Decide \
         deliberately — add the stamp, or add the arm to the allowlist with a \
         reason: {unexpected:?}"
    );
}

/// The specific regression that motivated this pin: #3464's own arm.
#[test]
fn migrate_v97_stamps_the_literal_97_3464() {
    let src = postgres_source();
    let arms = migration_arms(&src);
    let (_, body) = arms
        .iter()
        .find(|(n, _)| n == "migrate_v97")
        .expect("migrate_v97 must exist — #3464 adds the v97 agent_pubkey_history arm");
    assert!(
        body.contains("record_schema_version(&mut tx, 97)"),
        "#3464: migrate_v97 must stamp the LITERAL 97. It is the tip arm today, so \
         `CURRENT_SCHEMA_VERSION` happens to be equal — and would silently become \
         wrong the moment v98 lands above it."
    );
    assert!(
        !body.contains("record_schema_version(&mut tx, CURRENT_SCHEMA_VERSION)"),
        "#3464: migrate_v97 must not stamp CURRENT_SCHEMA_VERSION"
    );
}
