// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Campaign X cell X4 (#7094) - `forget` error-variant parity.
//!
//! A non-transient crypto-erase attestation failure used to surface as
//! `StoreError::Backend` on sqlite and `StoreError::BackendUnavailable` on
//! postgres. `BackendUnavailable` means "retry later"; the fault is permanent
//! (the signed-event append is rejected), so callers saw different retry
//! semantics for the same fault.
//!
//! Scenario (identical on both backends): store [`VICTIM_COUNT`] memories in
//! one namespace, inject a permanent fault on the `substrate.crypto_erase`
//! signed-event append, run `forget` on the namespace. Expected outcome on
//! both backends: `StoreError::Backend`, and the whole forget rolled back
//! (every victim row still present).
//!
//! The postgres cell is `#[ignore]` and soft-skips without
//! `AI_MEMORY_TEST_POSTGRES_URL`, like every other live-postgres test.
//!
//! The postgres cell injects its fault on the victim `DELETE` (a permanent
//! plpgsql `RAISE`, SQLSTATE `P0001`) rather than on the `signed_events`
//! append: on an AGE-enabled server the transaction's `SET LOCAL search_path`
//! (#7101) moves every statement after the AGE unprojection into `public`,
//! so a trigger on the isolated schema's `signed_events` never fires. Both
//! faults share the one error mapping the fix changes (a permanent statement
//! failure inside the forget transaction), so the delete fault pins the same
//! contract as the attestation fault, which the sqlite cells cover directly.

#![cfg(feature = "sal")]

mod common;

use ai_memory::models::{Memory, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};

const VICTIM_COUNT: usize = 3;
const NAMESPACE: &str = "x4/forget";
const AGENT: &str = "ai:x4-forget";
#[cfg(feature = "sal-postgres")]
const FAULT_MESSAGE: &str = "x4 injected permanent fault";
const TS: &str = "2026-09-01T00:00:00+00:00";

fn victim(i: usize) -> Memory {
    Memory {
        id: format!("x4-victim-{i}"),
        tier: Tier::Long,
        namespace: NAMESPACE.to_string(),
        title: format!("x4 victim {i}"),
        content: format!("x4 forget victim body {i}"),
        priority: 5,
        confidence: 1.0,
        source: "x4".to_string(),
        created_at: TS.to_string(),
        updated_at: TS.to_string(),
        metadata: serde_json::json!({ "agent_id": AGENT }),
        ..Default::default()
    }
}

/// The variant NAME of a store error, the thing a caller branches on.
fn variant(e: &StoreError) -> &'static str {
    match e {
        StoreError::Backend(_) => "Backend",
        StoreError::BackendUnavailable { .. } => "BackendUnavailable",
        _ => "other",
    }
}

/// The attestation-append fault (the issue's reproduction).
const SQLITE_ATTEST_FAULT_SQL: &str = "CREATE TRIGGER x4_fault BEFORE INSERT ON signed_events \
     WHEN NEW.event_type = 'substrate.crypto_erase' \
     BEGIN SELECT RAISE(ABORT, 'x4 injected attestation fault'); END;";
/// The victim-delete fault: the same cell as the postgres one.
const SQLITE_DELETE_FAULT_SQL: &str = "CREATE TRIGGER x4_fault BEFORE DELETE ON memories \
     BEGIN SELECT RAISE(ABORT, 'x4 injected attestation fault'); END;";

#[tokio::test]
async fn sqlite_forget_attestation_failure_is_backend_and_atomic_7094() {
    sqlite_forget_fault_case(SQLITE_ATTEST_FAULT_SQL).await;
}

#[tokio::test]
async fn sqlite_forget_delete_failure_is_backend_and_atomic_7094() {
    sqlite_forget_fault_case(SQLITE_DELETE_FAULT_SQL).await;
}

async fn sqlite_forget_fault_case(trigger_sql: &str) {
    common::permissive_attestation_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("x4.db");
    let store = SqliteStore::open(&db_path).expect("open");
    let ctx = CallerContext::for_admin("operator:x4");
    for i in 0..VICTIM_COUNT {
        store.store(&ctx, &victim(i)).await.expect("store");
    }
    let raw = rusqlite::Connection::open(&db_path).expect("raw");
    raw.execute_batch(trigger_sql).expect("trigger");

    let err = store
        .forget(&ctx, Some(NAMESPACE), None, None, false)
        .await
        .expect_err("forget must fail on the injected attestation fault");
    assert_eq!(variant(&err), "Backend", "sqlite variant: {err:?}");

    let remaining: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
            [NAMESPACE],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        usize::try_from(remaining).expect("count fits"),
        VICTIM_COUNT,
        "all-or-nothing: a failed forget leaves every victim"
    );
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn postgres_forget_permanent_failure_is_backend_and_atomic_7094() {
    use ai_memory::store::postgres::PostgresStore;
    use common::postgres_env::PostgresTestEnv;

    common::permissive_attestation_for_tests();
    let Some(env) = PostgresTestEnv::new("x4_forget").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = PostgresStore::connect(env.url()).await.expect("connect");
    let ctx = CallerContext::for_admin("operator:x4");
    for i in 0..VICTIM_COUNT {
        store.store(&ctx, &victim(i)).await.expect("store");
    }
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(env.url())
        .await
        .expect("inspection pool");
    sqlx::query(&format!(
        "CREATE FUNCTION x4_fault() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION '{FAULT_MESSAGE}'; END $$"
    ))
    .execute(&pool)
    .await
    .expect("fn");
    sqlx::query(&format!(
        "CREATE TRIGGER x4_fault BEFORE DELETE ON memories FOR EACH ROW \
         EXECUTE FUNCTION x4_fault()"
    ))
    .execute(&pool)
    .await
    .expect("trigger");

    let err = store
        .forget(&ctx, Some(NAMESPACE), None, None, false)
        .await
        .expect_err("forget must fail on the injected permanent fault");
    assert_eq!(variant(&err), "Backend", "postgres variant: {err:?}");

    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE namespace = $1")
        .bind(NAMESPACE)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        usize::try_from(remaining).expect("count fits"),
        VICTIM_COUNT,
        "all-or-nothing: a failed forget leaves every victim"
    );
}
