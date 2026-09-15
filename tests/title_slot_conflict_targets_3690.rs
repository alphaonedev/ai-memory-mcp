// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 Consolidation Unit 1 (#3690) — STRUCTURAL pin over every
//! `(title, namespace)` upsert target on both adapters.
//!
//! At schema v100 the `(title, namespace)` unique index is PARTIAL
//! (`WHERE lifecycle_state <> 'tombstoned'`), and an upsert only matches a
//! partial index whose predicate its conflict target repeats. A target that
//! drifts back to the bare `ON CONFLICT (title, namespace)` form therefore
//! fails EVERY store on that funnel at runtime (postgres: "there is no unique
//! or exclusion constraint matching the ON CONFLICT specification"; sqlite:
//! "ON CONFLICT clause does not match any PRIMARY KEY or UNIQUE constraint").
//! Ten literals carry the target (the #3690 census: sqlite `insert_inner` +
//! `insert_if_newer`; postgres `store`, `store_batch`,
//! `store_with_embedding_inner` (+ its no-overwrite arm),
//! `apply_remote_memory`, `reflect_with_hooks`, `capture_turn_idempotent`,
//! `recover_turn_idempotent`, `consolidate`) and FIVE of them are named by no
//! issue, so this pin — not the issue list — is what binds the surface: every
//! target spells `crate::models::TITLE_SLOT_CONFLICT_TARGET`, no code line
//! under `src/` spells the bare form, and both v100 rungs carry the ONE
//! predicate.

use std::path::Path;

const ADAPTER_FILES: &[&str] = &["src/storage/mod.rs", "src/store/postgres.rs"];

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn is_comment_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("--")
}

/// Every CODE line that spells a `(title, namespace)` conflict target must
/// spell it through the ONE const; the bare form is refused anywhere under
/// the two adapter files.
#[test]
fn no_code_line_spells_a_bare_title_namespace_conflict_target_3690() {
    let mut bare = Vec::new();
    for rel in ADAPTER_FILES {
        for (n, line) in read(rel).lines().enumerate() {
            if is_comment_line(line) {
                continue;
            }
            let compact = line.replace(' ', "");
            if compact.contains("ONCONFLICT(title,namespace)") {
                bare.push(format!("{rel}:{}: {}", n + 1, line.trim()));
            }
        }
    }
    assert!(
        bare.is_empty(),
        "#3690: a bare `ON CONFLICT (title, namespace)` target no longer matches the v100 \
         PARTIAL index and fails every store on that funnel. Spell \
         `crate::models::TITLE_SLOT_CONFLICT_TARGET` instead:\n{}",
        bare.join("\n")
    );
}

/// The ten census literals reference the const — a count bound to the tree
/// the census was taken on. A NEW funnel that claims a title must raise this
/// number deliberately (and spell the target through the const, per the pin
/// above); a funnel that silently stops using it is a drift back to the bare
/// form the first pin refuses, so the two pins together close both directions.
// sqlite: `INSERT_UPSERT_SQL`, `INSERT_IF_NEWER_SQL`, the derived Refuse arm
// and the by-id restore re-target (`replacen`) = 4; postgres adds its own.
const SQLITE_USES: usize = 4;

#[test]
fn every_census_target_spells_the_one_const_3690() {
    let mut uses = 0usize;
    for rel in ADAPTER_FILES {
        for line in read(rel).lines() {
            if is_comment_line(line) {
                continue;
            }
            uses += line.matches("TITLE_SLOT_CONFLICT_TARGET").count();
        }
    }
    assert!(
        uses >= SQLITE_USES,
        "#3690: expected at least {SQLITE_USES} code references to TITLE_SLOT_CONFLICT_TARGET \
         across {ADAPTER_FILES:?}, found {uses}"
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
