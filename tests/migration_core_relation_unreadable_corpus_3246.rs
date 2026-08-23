// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 (#3246) — an unreadable `memories` COUNT is not "no corpus".
//!
//! #3113's refusal predicate treated `corpus_row_count`'s `None` (the
//! `.ok()`-coerced `COUNT(*)` failure) as the same no-brick path as
//! `Some(0)`. `memories` ships in the bootstrap `SCHEMA` and is replayed
//! by `db::open` before `migrate`, so `None` never means "fixture without
//! a corpus" — it means the count FAILED (corruption / I/O / BUSY). Under
//! `AI_MEMORY_MIGRATION_REQUIRE_CORE_TABLES=1` (pinned ON by `asi-hard`)
//! that stamped the tip with only a WARN.
//!
//! This binary forces the count to fail under enforcement and asserts the
//! data-integrity contract of the gate as `migrate` sites it: INSIDE a
//! transaction, BEFORE the stamp. A refusal rolls back; the database is
//! left EXACTLY as found. Alone in its own test binary: it mutates
//! process-global env (`2905-posture-test-env-leak`).
//!
//! The full ladder is not driven here. Several arms between v74 and the
//! tip still gate on `version < CURRENT_SCHEMA_VERSION` and query
//! `memories` (`backfill_memory_cids` among them); dropping the table to
//! fail COUNT(*) would error in those arms before the gate. The contract
//! under test is the gate itself, not those arms.

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

/// The migrate tail: report → refuse-or-stamp, inside BEGIN EXCLUSIVE.
/// Byte-equivalent control flow to `migrations::migrate`'s pre-stamp gate.
fn run_gate_and_stamp(conn: &Connection, target: i64) -> anyhow::Result<()> {
    conn.execute_batch("BEGIN EXCLUSIVE")?;
    let result = (|| -> anyhow::Result<()> {
        let missing_core = schema_integrity::report(conn, target)?;
        if schema_integrity::refusal_required(conn, &missing_core)? {
            anyhow::bail!(schema_integrity::refusal_message(&missing_core, target));
        }
        conn.execute("DELETE FROM schema_version", [])?;
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            rusqlite::params![target],
        )?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

#[test]
fn enforced_posture_refuses_an_unreadable_corpus_and_leaves_the_stamp_unchanged() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("ai-memory.db");

    // A real, fully-migrated database holding one durable row.
    {
        let conn = db::open(&path).unwrap();
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at) \
             VALUES ('m-3246', 'long', 'ns', 't', 'durable source of truth', \
                     '2026-08-23T00:00:00Z', '2026-08-23T00:00:00Z')",
            [],
        )
        .unwrap();
    }

    // Lost core relation under a high-but-not-tip stamp, then DROP memories
    // so COUNT(*) fails. `db::open` cannot be used for the refusal: SCHEMA
    // would recreate `memories` via CREATE TABLE IF NOT EXISTS and turn
    // the failed COUNT into Ok(0).
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch(
        "DROP TABLE IF EXISTS governance_rules;\n\
         DROP TABLE IF EXISTS memories;\n\
         DELETE FROM schema_version;\n\
         INSERT INTO schema_version (version) VALUES (87);",
    )
    .unwrap();
    assert_eq!(schema_version(&raw), 87, "precondition: stamp is 87");
    assert!(
        schema_integrity::corpus_row_count(&raw).is_err(),
        "precondition: COUNT(*) must fail after DROP TABLE memories"
    );
    let missing = schema_integrity::missing_core_tables(&raw, 89).unwrap();
    assert!(
        missing
            .iter()
            .any(|t| t.name == schema_integrity::TABLE_GOVERNANCE_RULES),
        "precondition: governance_rules must be missing"
    );
    drop(raw);

    // SAFETY: this test binary contains exactly one test, so no concurrent
    // test in this process can observe the mutation.
    unsafe {
        std::env::set_var(ai_memory::config::ENV_MIGRATION_REQUIRE_CORE_TABLES, "1");
    }

    let conn = Connection::open(&path).unwrap();
    let target = db::migrations::current_schema_version_for_tests();
    let err = run_gate_and_stamp(&conn, target)
        .expect_err("enforced posture must refuse an unreadable corpus");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(schema_integrity::TABLE_GOVERNANCE_RULES),
        "the refusal must name the missing relation: {msg}"
    );
    assert!(
        msg.contains("UNCHANGED"),
        "the refusal must state that the database was not mutated: {msg}"
    );
    drop(conn);

    // THE load-bearing assertion. A refusal must not be a mutation:
    let raw = Connection::open(&path).unwrap();
    assert_eq!(
        schema_version(&raw),
        87,
        "the stamp must NOT have advanced — that is the entire point of siting \
         the gate before the stamp, inside the transaction"
    );
    assert!(
        schema_integrity::corpus_row_count(&raw).is_err(),
        "the gate must not recreate memories — it issues no DDL"
    );
    drop(raw);

    // SAFETY: single-test binary, as above.
    unsafe {
        std::env::remove_var(ai_memory::config::ENV_MIGRATION_REQUIRE_CORE_TABLES);
    }
}
