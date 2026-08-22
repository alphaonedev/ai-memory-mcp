// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 (#3113) — migration core-relation integrity, REPORT-ONLY posture.
//!
//! The sqlite ladder's existence-probe arms (v34 `signed_events`, v66
//! `governance_rules`, v73 `signed_events.cause_hash`) SKIP when the relation
//! is absent, and the tail of `migrate` then stamps the tip regardless — so a
//! populated database that LOST a core relation "upgraded successfully" with
//! the integrity controls that stamp implies never applied.
//!
//! This file pins the DEFAULT posture: the loss is DETECTED and reported, and
//! behaviour is otherwise byte-identical to pre-#3113 (the open still
//! succeeds, the stamp still advances, no row is touched). The refusal leg
//! lives in `migration_core_relation_refusal_3113.rs`, alone in its own test
//! binary so its env var cannot leak into a concurrent test.

use ai_memory::db;
use ai_memory::storage::schema_integrity;
use rusqlite::Connection;
use tempfile::TempDir;

fn schema_version(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

fn memory_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
        .unwrap()
}

/// Build a real, fully-migrated database holding one row, then rewind it into
/// the shape the finding describes: a POPULATED database that lost a
/// ladder-only core relation while keeping a high schema stamp.
fn populated_db_missing(tmp: &TempDir, dropped: &str, stamp: i64) -> std::path::PathBuf {
    let path = tmp.path().join("ai-memory.db");
    {
        let conn = db::open(&path).unwrap();
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at) \
             VALUES ('m-3113', 'long', 'ns', 't', 'durable source of truth', \
                     '2026-08-21T00:00:00Z', '2026-08-21T00:00:00Z')",
            [],
        )
        .unwrap();
    }
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch(&format!(
        "DROP TABLE IF EXISTS {dropped};\n\
         DELETE FROM schema_version;\n\
         INSERT INTO schema_version (version) VALUES ({stamp});"
    ))
    .unwrap();
    drop(raw);
    path
}

#[test]
fn a_fully_migrated_database_is_missing_no_core_relation() {
    // The baseline the whole check rests on: a genuine ladder upgrade creates
    // every CORE_TABLES relation, so a healthy database reports nothing. If
    // this ever fails, an `introduced_at` in the SSOT is wrong.
    let tmp = TempDir::new().unwrap();
    let conn = db::open(&tmp.path().join("ai-memory.db")).unwrap();
    let stamped = schema_version(&conn);
    let missing = schema_integrity::missing_core_tables(&conn, stamped).unwrap();
    assert!(
        missing.is_empty(),
        "a fully-migrated v{stamped} database must contain every core relation, missing: {}",
        schema_integrity::describe(&missing),
    );
}

#[test]
fn every_core_table_is_actually_created_by_its_ladder_arm() {
    // Stronger form: probe each SSOT entry by name against a real database.
    let tmp = TempDir::new().unwrap();
    let conn = db::open(&tmp.path().join("ai-memory.db")).unwrap();
    for entry in schema_integrity::CORE_TABLES {
        assert!(
            schema_integrity::table_present(&conn, entry.name).unwrap(),
            "{} is declared introduced at v{} but a fresh full migration did not create it",
            entry.name,
            entry.introduced_at,
        );
    }
}

#[test]
fn a_lost_relation_on_a_populated_database_is_detected() {
    // The finding's exact scenario: governance_rules (v30) dropped from a
    // database still claiming v89. Pre-#3113 this was completely silent.
    let tmp = TempDir::new().unwrap();
    let path = populated_db_missing(&tmp, schema_integrity::TABLE_GOVERNANCE_RULES, 89);

    let conn = Connection::open(&path).unwrap();
    let missing = schema_integrity::missing_core_tables(&conn, 89).unwrap();
    let names: Vec<&str> = missing.iter().map(|t| t.name).collect();
    assert_eq!(names, vec![schema_integrity::TABLE_GOVERNANCE_RULES]);
    // The diagnostic must name the control that is NOT in force, not merely
    // the table — that is what makes the WARN actionable.
    assert!(
        schema_integrity::describe(&missing).contains("severity CHECK"),
        "diagnostic must name the integrity control: {}",
        schema_integrity::describe(&missing),
    );
    // And the populated-vs-fixture discriminator must be readable.
    assert_eq!(schema_integrity::corpus_row_count(&conn), Some(1));
}

#[test]
fn report_only_posture_preserves_legacy_behaviour_exactly() {
    // DEFAULT posture (env unset): the open still succeeds, the ladder still
    // stamps the tip, and the durable row is untouched. #3113 adds detection,
    // it does not change what happens.
    let tmp = TempDir::new().unwrap();
    let path = populated_db_missing(&tmp, schema_integrity::TABLE_SIGNED_EVENTS, 73);

    let conn = db::open(&path).expect("report-only posture must not refuse the open");
    assert_eq!(
        schema_version(&conn),
        db::migrations::current_schema_version_for_tests(),
        "the ladder still advances to the tip under the default posture",
    );
    assert_eq!(
        memory_count(&conn),
        1,
        "the durable source of truth is never touched by the integrity check",
    );
}

/// #3159 — the contract, asserted for EVERY relation in the SSOT rather than
/// once per hand-written copy. Table-driven so a relation added later is
/// covered the moment it lands in `CORE_TABLES`, with no test to remember to
/// write: drop it, restamp the tip, and the loss must be detected, must
/// warrant refusal under enforcement on a POPULATED corpus, must NOT refuse
/// under the default posture, and must NEVER refuse on an empty corpus.
#[test]
fn every_core_relation_when_lost_is_detected_and_obeys_the_refusal_contract() {
    for entry in schema_integrity::CORE_TABLES {
        let tmp = TempDir::new().unwrap();
        let path = populated_db_missing(&tmp, entry.name, 89);
        let conn = Connection::open(&path).unwrap();

        let missing = schema_integrity::missing_core_tables(&conn, 89).unwrap();
        assert!(
            missing.iter().any(|t| t.name == entry.name),
            "losing {} must be detected at the tip stamp",
            entry.name,
        );

        let rows = schema_integrity::corpus_row_count(&conn);
        assert_eq!(
            rows,
            Some(1),
            "precondition: {} case is populated",
            entry.name
        );
        assert!(
            schema_integrity::refusal_required_with(&missing, true, rows),
            "a populated corpus missing {} must refuse under enforcement",
            entry.name,
        );
        assert!(
            !schema_integrity::refusal_required_with(&missing, false, rows),
            "the default posture must report, never refuse, for {}",
            entry.name,
        );
        assert!(
            !schema_integrity::refusal_required_with(&missing, true, Some(0)),
            "an EMPTY corpus missing {} must never be refused (asi-hard pins \
             enforcement ON, so this is the anti-brick invariant)",
            entry.name,
        );
    }
}

#[test]
fn relations_above_the_stamp_are_not_reported_as_lost() {
    // A database legitimately BELOW a relation's introduction version is not
    // missing it. This is what keeps a genuine mid-ladder database quiet.
    let tmp = TempDir::new().unwrap();
    let path = populated_db_missing(&tmp, schema_integrity::TABLE_GOVERNANCE_RULES, 29);
    let conn = Connection::open(&path).unwrap();
    assert!(
        schema_integrity::missing_core_tables(&conn, 29)
            .unwrap()
            .is_empty(),
        "governance_rules is introduced at v30 and must not be expected at v29",
    );
}

#[test]
fn the_check_issues_no_ddl_and_no_dml() {
    // Data-integrity contract: the gate reads sqlite_master and COUNT(*) only.
    // Prove it by round-tripping the full catalogue + row count across a probe.
    let tmp = TempDir::new().unwrap();
    let path = populated_db_missing(&tmp, schema_integrity::TABLE_GOVERNANCE_RULES, 89);
    let conn = Connection::open(&path).unwrap();

    let catalogue_before: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let rows_before = memory_count(&conn);

    let _ = schema_integrity::report(&conn, 89).unwrap();

    let catalogue_after: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        catalogue_before, catalogue_after,
        "the check must not alter the schema"
    );
    assert_eq!(
        rows_before,
        memory_count(&conn),
        "the check must not alter any row"
    );
}
