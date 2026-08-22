// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 (#3113) — migration core-relation integrity, ENFORCED posture.
//!
//! This file holds the ONE test that sets
//! `AI_MEMORY_MIGRATION_REQUIRE_CORE_TABLES`. `std::env::set_var` is
//! process-global and integration tests in a single binary run concurrently,
//! so the enforcement leg lives alone in its own test binary — the
//! `2905-posture-test-env-leak` lesson, applied up front rather than after CI
//! goes red.
//!
//! What it pins is the data-integrity contract of a REFUSAL: the migration
//! declines to stamp, and because the check is sited inside the migrate
//! transaction BEFORE the stamp, the database is left EXACTLY as found —
//! old version, every row intact, still openable — and the refusal is
//! REVERSIBLE by unsetting the flag. A fail-closed gate that bricked the
//! database would be a worse outcome than the fail-open hole it replaces.

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

#[test]
fn enforced_posture_refuses_the_stamp_and_leaves_the_database_untouched() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("ai-memory.db");

    // A real, fully-migrated database holding one durable row.
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
    // Rewind to the finding's shape: a lost core relation under a stamp that
    // is BELOW the tip, so the ladder genuinely re-runs and reaches the gate.
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch(
        "DROP TABLE IF EXISTS governance_rules;\n\
         DELETE FROM schema_version;\n\
         INSERT INTO schema_version (version) VALUES (80);",
    )
    .unwrap();
    drop(raw);

    // SAFETY: this test binary contains exactly one test, so no concurrent
    // test in this process can observe the mutation.
    unsafe {
        std::env::set_var(ai_memory::config::ENV_MIGRATION_REQUIRE_CORE_TABLES, "1");
    }

    let err = db::open(&path).expect_err("enforced posture must refuse a lost core relation");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(schema_integrity::TABLE_GOVERNANCE_RULES),
        "the refusal must name the missing relation: {msg}",
    );
    assert!(
        msg.contains("UNCHANGED"),
        "the refusal must state that the database was not mutated: {msg}",
    );

    // THE load-bearing assertions. A refusal must not be a mutation:
    let raw = Connection::open(&path).unwrap();
    assert_eq!(
        schema_version(&raw),
        80,
        "the stamp must NOT have advanced — that is the entire point of siting \
         the gate before the stamp, inside the transaction",
    );
    assert_eq!(
        raw.query_row("SELECT COUNT(*) FROM memories", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1,
        "the durable source of truth must survive a refusal intact",
    );
    assert_eq!(
        raw.query_row(
            "SELECT content FROM memories WHERE id = 'm-3113'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "durable source of truth",
        "content must be byte-identical after a refused migration",
    );
    drop(raw);

    // And the refusal is REVERSIBLE: clearing the flag restores the
    // report-only posture and the database opens and migrates normally. An
    // operator is never stranded.
    // SAFETY: single-test binary, as above.
    unsafe {
        std::env::remove_var(ai_memory::config::ENV_MIGRATION_REQUIRE_CORE_TABLES);
    }
    let conn = db::open(&path).expect("clearing the flag must restore the report-only posture");
    assert_eq!(
        schema_version(&conn),
        db::migrations::current_schema_version_for_tests(),
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM memories", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1,
    );
}
