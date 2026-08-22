// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 (#3113) — the ANTI-BRICK invariant of the enforced posture.
//!
//! `AI_MEMORY_MIGRATION_REQUIRE_CORE_TABLES` is PINNED ON by the `asi-hard`
//! security profile, so the refusal path runs in every certified deployment.
//! That makes one property load-bearing: a database with an EMPTY corpus must
//! NEVER be refused, however high its stamp and however many ladder-only
//! relations it lacks. An empty database with a high stamp is the ordinary
//! fixture / archive-less shape — there is no lost data there, because there
//! is no data — so refusing it would brick a fresh hardened deployment for no
//! integrity gain, making `asi-hard` strictly more fragile than `standard`.
//!
//! Alone in its own test binary: it mutates process-global env, and
//! integration tests within one binary run concurrently (the
//! `2905-posture-test-env-leak` lesson).

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
fn enforced_posture_never_bricks_an_empty_corpus() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("ai-memory.db");

    // A real migrated database, then rewound to the finding's shape — a lost
    // ladder-only relation under a high stamp — but with NO rows.
    drop(db::open(&path).unwrap());
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch(&format!(
        "DROP TABLE IF EXISTS {};\n\
         DROP TABLE IF EXISTS {};\n\
         DELETE FROM schema_version;\n\
         INSERT INTO schema_version (version) VALUES (80);",
        schema_integrity::TABLE_GOVERNANCE_RULES,
        schema_integrity::TABLE_SIGNED_EVENTS,
    ))
    .unwrap();
    assert_eq!(
        raw.query_row("SELECT COUNT(*) FROM memories", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0,
        "precondition: the corpus is empty",
    );
    drop(raw);

    // SAFETY: this test binary contains exactly one test, so no concurrent
    // test in this process can observe the mutation.
    unsafe {
        std::env::set_var(ai_memory::config::ENV_MIGRATION_REQUIRE_CORE_TABLES, "1");
    }

    // Enforcement is ON and relations ARE missing — but the corpus is empty,
    // so there is no demonstrable loss and the open MUST succeed.
    let conn = db::open(&path).expect(
        "an empty corpus must never be refused: asi-hard pins enforcement ON, so refusing \
         here would brick every fresh hardened deployment",
    );
    assert_eq!(
        schema_version(&conn),
        db::migrations::current_schema_version_for_tests(),
        "the ladder still advances to the tip for an empty corpus",
    );

    // SAFETY: single-test binary, as above.
    unsafe {
        std::env::remove_var(ai_memory::config::ENV_MIGRATION_REQUIRE_CORE_TABLES);
    }
}
