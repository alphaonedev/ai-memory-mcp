// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Campaign X cell X7 (#7097) - archive family contract parity.
//!
//! Two cells, identical scenario on both backends:
//!
//! * X7a `archive_by_ids` with one foreign-owned id in the batch. Postgres
//!   refuses the whole batch with `StoreError::PermissionDenied` and rolls
//!   back; sqlite used to skip the foreign id silently and archive the rest,
//!   so the same call returned a count on one backend and a typed error on
//!   the other. Expected on both: `PermissionDenied`, nothing archived.
//! * X7b `archive_purge` with a permanent fault part-way through the delete.
//!   Expected on both: an error and every archived row still present (the
//!   purge is all-or-nothing whether or not a cold tier exists).
//!
//! The postgres cells are `#[ignore]` and soft-skip without
//! `AI_MEMORY_TEST_POSTGRES_URL`, like every other live-postgres test.

#![cfg(feature = "sal")]

mod common;

use ai_memory::models::{Memory, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};

const BATCH_SIZE: usize = 3;
/// Batch position of the foreign id in the shared cells: the lowest id, so it
/// is the first row both backends visit (postgres visits ids in sorted order
/// and, on an AGE-enabled server, a later id in the same transaction runs in
/// the wrong schema after the first unprojection - #7101, fixed by #7120).
const FOREIGN_FIRST: usize = 0;
/// Batch position of the foreign id in the sqlite prefix-rollback cell: an
/// owned row is visited (and archived) before the refusal.
const FOREIGN_MIDDLE: usize = 1;
const NAMESPACE: &str = "x7/archive";
const CALLER_AGENT: &str = "ai:x7-caller";
const OTHER_AGENT: &str = "ai:x7-other";
const ADMIN: &str = "operator:x7";
#[cfg(feature = "sal-postgres")]
const FAULT_MESSAGE: &str = "x7 injected permanent fault";
const TS: &str = "2026-09-01T00:00:00+00:00";

fn row_id(i: usize) -> String {
    format!("x7-row-{i}")
}

fn owner_of(i: usize, foreign: usize) -> &'static str {
    if i == foreign {
        OTHER_AGENT
    } else {
        CALLER_AGENT
    }
}

fn row(i: usize, foreign: usize) -> Memory {
    Memory {
        id: row_id(i),
        tier: Tier::Long,
        namespace: NAMESPACE.to_string(),
        title: format!("x7 row {i}"),
        content: format!("x7 archive row body {i}"),
        priority: 5,
        confidence: 1.0,
        source: "x7".to_string(),
        created_at: TS.to_string(),
        updated_at: TS.to_string(),
        metadata: serde_json::json!({ "agent_id": owner_of(i, foreign) }),
        ..Default::default()
    }
}

fn batch_ids() -> Vec<String> {
    (0..BATCH_SIZE).map(row_id).collect()
}

/// The variant NAME of a store error, the thing a caller branches on.
fn variant(e: &StoreError) -> &'static str {
    match e {
        StoreError::PermissionDenied { .. } => "PermissionDenied",
        StoreError::Backend(_) => "Backend",
        StoreError::BackendUnavailable { .. } => "BackendUnavailable",
        _ => "other",
    }
}

/// A foreign index no row matches: every row is owned by the caller.
const NO_FOREIGN: usize = BATCH_SIZE;

#[tokio::test]
async fn sqlite_archive_by_ids_foreign_id_refuses_whole_batch_7097() {
    sqlite_foreign_case(FOREIGN_FIRST).await;
}

#[tokio::test]
async fn sqlite_archive_by_ids_foreign_after_owned_rolls_back_prefix_7097() {
    sqlite_foreign_case(FOREIGN_MIDDLE).await;
}

async fn sqlite_foreign_case(foreign: usize) {
    common::permissive_attestation_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("x7a.db");
    let store = SqliteStore::open(&db_path).expect("open");
    let admin = CallerContext::for_admin(ADMIN);
    for i in 0..BATCH_SIZE {
        store.store(&admin, &row(i, foreign)).await.expect("store");
    }

    let caller = CallerContext::for_agent(CALLER_AGENT);
    let err = store
        .archive_by_ids(&caller, &batch_ids(), None)
        .await
        .expect_err("a foreign-owned id must refuse the batch");
    assert_eq!(variant(&err), "PermissionDenied", "sqlite variant: {err:?}");

    let raw = rusqlite::Connection::open(&db_path).expect("raw");
    let live: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
            [NAMESPACE],
            |r| r.get(0),
        )
        .expect("live count");
    let archived: i64 = raw
        .query_row("SELECT COUNT(*) FROM archived_memories", [], |r| r.get(0))
        .expect("archived count");
    assert_eq!(usize::try_from(live).expect("fits"), BATCH_SIZE, "all live");
    assert_eq!(archived, 0, "all-or-nothing: nothing archived");
}

/// The refusal reason of a `PermissionDenied`, the SSOT string callers match.
fn denied_reason(e: &StoreError) -> &str {
    match e {
        StoreError::PermissionDenied { reason, .. } => reason,
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
}

/// #7596: one live row the caller does not own, one unstamped live row.
const UNSTAMPED_ID: &str = "x7-unstamped";

#[tokio::test]
async fn sqlite_archive_by_ids_foreign_reason_is_ssot_7596() {
    common::permissive_attestation_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SqliteStore::open(dir.path().join("x7r.db")).expect("open");
    let admin = CallerContext::for_admin(ADMIN);
    store
        .store(&admin, &row(0, FOREIGN_FIRST))
        .await
        .expect("store");
    let caller = CallerContext::for_agent(CALLER_AGENT);
    let err = store
        .archive_by_ids(&caller, &[row_id(0)], None)
        .await
        .expect_err("foreign row must refuse");
    assert_eq!(
        denied_reason(&err),
        ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY
    );
}

/// The unstamped-row refusal needs the `refuse` posture on sqlite (the
/// default `warn` posture admits a legacy unstamped row, #3124); postgres
/// refuses in both postures. The env guard is held outside the runtime so
/// it is never held across an `.await`.
#[test]
fn sqlite_archive_by_ids_unstamped_reason_is_ssot_7596() {
    let _posture = common::EnvVarGuard::set(
        ai_memory::identity::owner_stamp::ENV_UNSTAMPED_MUTATION,
        "refuse".to_string(),
    );
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(sqlite_unstamped_reason_case());
}

async fn sqlite_unstamped_reason_case() {
    common::permissive_attestation_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("x7u.db");
    let store = SqliteStore::open(&db_path).expect("open");
    let admin = CallerContext::for_admin(ADMIN);
    let mut unstamped = row(0, NO_FOREIGN);
    unstamped.id = UNSTAMPED_ID.to_string();
    store.store(&admin, &unstamped).await.expect("store");
    let raw = rusqlite::Connection::open(&db_path).expect("raw");
    raw.execute(
        "UPDATE memories SET metadata = '{}' WHERE id = ?1",
        [UNSTAMPED_ID],
    )
    .expect("strip the owner stamp");

    let caller = CallerContext::for_agent(CALLER_AGENT);
    let err = store
        .archive_by_ids(&caller, &[UNSTAMPED_ID.to_string()], None)
        .await
        .expect_err("unstamped row must refuse");
    assert_eq!(
        denied_reason(&err),
        ai_memory::errors::msg::REASON_UNSTAMPED_TENANT_ARCHIVE
    );
    let live: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = ?1",
            [UNSTAMPED_ID],
            |r| r.get(0),
        )
        .expect("live count");
    assert_eq!(live, 1, "a refused archive leaves the row live");
}

#[tokio::test]
async fn sqlite_archive_by_ids_missing_id_is_skipped_7097() {
    common::permissive_attestation_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SqliteStore::open(dir.path().join("x7m.db")).expect("open");
    let admin = CallerContext::for_admin(ADMIN);
    store
        .store(&admin, &row(0, NO_FOREIGN))
        .await
        .expect("store");

    let caller = CallerContext::for_agent(CALLER_AGENT);
    let ids = vec![row_id(0), "x7-absent".to_string()];
    let moved = store
        .archive_by_ids(&caller, &ids, None)
        .await
        .expect("a missing id is skipped, not refused");
    assert_eq!(moved, 1, "only the live owned row counts");
}

/// X7b fault: refuse the delete of one archived row, part-way through.
const SQLITE_PURGE_FAULT_SQL: &str = "CREATE TRIGGER x7_fault BEFORE DELETE ON archived_memories \
     WHEN OLD.id = 'x7-row-2' \
     BEGIN SELECT RAISE(ABORT, 'x7 injected permanent fault'); END;";

#[tokio::test]
async fn sqlite_archive_purge_fault_is_all_or_nothing_7097() {
    common::permissive_attestation_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("x7b.db");
    let store = SqliteStore::open(&db_path).expect("open");
    let admin = CallerContext::for_admin(ADMIN);
    for i in 0..BATCH_SIZE {
        store
            .store(&admin, &row(i, NO_FOREIGN))
            .await
            .expect("store");
    }
    archive_one_by_one(&store, &admin).await;
    let raw = rusqlite::Connection::open(&db_path).expect("raw");
    raw.execute_batch(SQLITE_PURGE_FAULT_SQL).expect("trigger");

    store
        .archive_purge(&admin, None)
        .await
        .expect_err("purge must fail on the injected fault");

    let archived: i64 = raw
        .query_row("SELECT COUNT(*) FROM archived_memories", [], |r| r.get(0))
        .expect("count");
    assert_eq!(
        usize::try_from(archived).expect("fits"),
        BATCH_SIZE,
        "all-or-nothing: a failed purge deletes no archived row"
    );
}

/// Archive every row with its own single-id call: one transaction per row, so
/// the setup does not depend on multi-id batch behaviour (#7101 on postgres).
async fn archive_one_by_one<S: MemoryStore>(store: &S, admin: &CallerContext) {
    for id in batch_ids() {
        let moved = store
            .archive_by_ids(admin, &[id], None)
            .await
            .expect("archive");
        assert_eq!(moved, 1);
    }
}

#[cfg(feature = "sal-postgres")]
async fn pg_store_and_pool(
    env: &common::postgres_env::PostgresTestEnv,
    foreign: usize,
) -> (ai_memory::store::postgres::PostgresStore, sqlx::PgPool) {
    use ai_memory::store::postgres::PostgresStore;

    let store = PostgresStore::connect(env.url()).await.expect("connect");
    let admin = CallerContext::for_admin(ADMIN);
    for i in 0..BATCH_SIZE {
        store.store(&admin, &row(i, foreign)).await.expect("store");
    }
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(env.url())
        .await
        .expect("inspection pool");
    (store, pool)
}

// The postgres refusal cells use the multi-thread flavor: a refused batch drops
// its transaction, and sqlx rolls the connection back on a spawned task. On a
// current-thread test runtime that is dropped when the test ends, the task has
// not run, so the connection stays idle in transaction until a server timeout;
// the multi-thread runtime lets the rollback run (#7596 cell timing).
#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn postgres_archive_by_ids_foreign_id_refuses_whole_batch_7097() {
    use common::postgres_env::PostgresTestEnv;

    common::permissive_attestation_for_tests();
    let Some(env) = PostgresTestEnv::new("x7_by_ids").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let (store, pool) = pg_store_and_pool(&env, FOREIGN_FIRST).await;
    let caller = CallerContext::for_agent(CALLER_AGENT);
    let err = store
        .archive_by_ids(&caller, &batch_ids(), None)
        .await
        .expect_err("a foreign-owned id must refuse the batch");
    assert_eq!(
        variant(&err),
        "PermissionDenied",
        "postgres variant: {err:?}"
    );

    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE namespace = $1")
        .bind(NAMESPACE)
        .fetch_one(&pool)
        .await
        .expect("live count");
    let archived: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM archived_memories")
        .fetch_one(&pool)
        .await
        .expect("archived count");
    assert_eq!(usize::try_from(live).expect("fits"), BATCH_SIZE, "all live");
    assert_eq!(archived, 0, "all-or-nothing: nothing archived");
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn postgres_archive_by_ids_foreign_reason_is_ssot_7596() {
    use common::postgres_env::PostgresTestEnv;

    common::permissive_attestation_for_tests();
    let Some(env) = PostgresTestEnv::new("x7_reason_f").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let (store, _pool) = pg_store_and_pool(&env, FOREIGN_FIRST).await;
    let caller = CallerContext::for_agent(CALLER_AGENT);
    let err = store
        .archive_by_ids(&caller, &[row_id(0)], None)
        .await
        .expect_err("foreign row must refuse");
    assert_eq!(
        denied_reason(&err),
        ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY
    );
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn postgres_archive_by_ids_unstamped_reason_is_ssot_7596() {
    use common::postgres_env::PostgresTestEnv;

    common::permissive_attestation_for_tests();
    let Some(env) = PostgresTestEnv::new("x7_reason_u").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let (store, pool) = pg_store_and_pool(&env, NO_FOREIGN).await;
    sqlx::query("UPDATE memories SET metadata = '{}'::jsonb WHERE id = $1")
        .bind(row_id(1))
        .execute(&pool)
        .await
        .expect("strip the owner stamp");
    let caller = CallerContext::for_agent(CALLER_AGENT);
    let err = store
        .archive_by_ids(&caller, &[row_id(1)], None)
        .await
        .expect_err("unstamped row must refuse");
    assert_eq!(
        denied_reason(&err),
        ai_memory::errors::msg::REASON_UNSTAMPED_TENANT_ARCHIVE
    );
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn postgres_archive_purge_fault_is_all_or_nothing_7097() {
    use common::postgres_env::PostgresTestEnv;

    common::permissive_attestation_for_tests();
    let Some(env) = PostgresTestEnv::new("x7_purge").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let (store, pool) = pg_store_and_pool(&env, NO_FOREIGN).await;
    let admin = CallerContext::for_admin(ADMIN);
    archive_one_by_one(&store, &admin).await;
    sqlx::query(&format!(
        "CREATE FUNCTION x7_fault() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN IF OLD.id = 'x7-row-2' THEN RAISE EXCEPTION '{FAULT_MESSAGE}'; END IF; \
         RETURN OLD; END $$"
    ))
    .execute(&pool)
    .await
    .expect("fn");
    sqlx::query(
        "CREATE TRIGGER x7_fault BEFORE DELETE ON archived_memories FOR EACH ROW \
         EXECUTE FUNCTION x7_fault()",
    )
    .execute(&pool)
    .await
    .expect("trigger");

    store
        .archive_purge(&admin, None)
        .await
        .expect_err("purge must fail on the injected fault");

    let archived: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM archived_memories")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        usize::try_from(archived).expect("fits"),
        BATCH_SIZE,
        "all-or-nothing: a failed purge deletes no archived row"
    );
}
