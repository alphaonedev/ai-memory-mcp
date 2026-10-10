// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7030 campaign X, cells X1a (sqlite) / X1b (postgres): `store_batch`
//! failure semantics. Row `k` of the batch is poisoned (its `(title,
//! namespace)` slot is held by a QUARANTINED row of another agent); the batch
//! must be all-or-nothing on both backends, and a healthy retry must leave the
//! same durable state, including the caller's quota row.
//!
//! Ignore-gated: `x1_parity_quota` (postgres charges the quota row on a
//! committed batch, sqlite does not, #7090) and `x1_parity_error_variant`
//! (sqlite flattens the slot conflict to `Backend`, postgres returns
//! `Conflict`, #7099).
//!
//! Postgres cells skip with a reason when `AI_MEMORY_TEST_POSTGRES_URL` is unset.

#![cfg(feature = "sal")]

mod common;
#[path = "common/parity_fault.rs"]
mod parity_fault;
#[path = "common/parity_oracle.rs"]
mod parity_oracle;

use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};
use parity_fault::{CALLER, OWNER, PoisonKind, poison_row};
use parity_oracle::{RawDb, StateDigest, exec, state_digest};

const N: usize = 4;
const K: usize = 2;
const PREFIX: &str = "x1";
const NS: &str = "parity/x1";

/// What one backend did across the fault phase and the healthy retry.
struct Run {
    seeded: StateDigest,
    fault_err: Option<StoreError>,
    after_fault: StateDigest,
    retry: Result<Vec<String>, StoreError>,
    after_retry: StateDigest,
}

async fn run_x1(store: &dyn MemoryStore, raw: &RawDb) -> Run {
    let poison = poison_row(K, PoisonKind::HiddenHolder);
    let owner = CallerContext::for_agent(OWNER);
    store
        .store_batch(&owner, &poison.holder_seed(PREFIX, NS))
        .await
        .expect("seed holder");
    if let Some(sql) = poison.quarantine_sql(PREFIX) {
        exec(raw, &sql).await;
    }
    let seeded = state_digest(raw).await;

    let caller = CallerContext::for_agent(CALLER);
    let fault_err = store
        .store_batch(&caller, &poison.batch_rows(PREFIX, NS, N, true))
        .await
        .err();
    let after_fault = state_digest(raw).await;

    let retry = store
        .store_batch(&caller, &poison.batch_rows(PREFIX, NS, N, false))
        .await;
    let after_retry = state_digest(raw).await;
    Run {
        seeded,
        fault_err,
        after_fault,
        retry,
        after_retry,
    }
}

fn assert_atomic(run: &Run, backend: &str) {
    assert!(
        run.fault_err.is_some(),
        "{backend}: a batch with a poisoned row {K} must fail"
    );
    assert_eq!(
        run.after_fault, run.seeded,
        "{backend}: a failed batch must leave NO durable change (all-or-nothing)"
    );
    let ids = run.retry.as_ref().expect("healthy retry must commit");
    assert_eq!(ids.len(), N, "{backend}: retry returns one id per row");
    let landed = run
        .after_retry
        .section("memories")
        .iter()
        .filter(|r| r[0].starts_with("x1-row-"))
        .count();
    assert_eq!(landed, N, "{backend}: retry lands every row");
}

async fn sqlite_run() -> Run {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x1.db");
    let store = SqliteStore::open(&path).expect("open sqlite");
    run_x1(&store, &RawDb::Sqlite(path)).await
}

#[cfg(feature = "sal-postgres")]
async fn pg_run() -> Option<Run> {
    use ai_memory::store::postgres::PostgresStore;
    let Some(env) = common::postgres_env::PostgresTestEnv::new("x1_store_batch").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset (X1b needs a live postgres)");
        return None;
    };
    let store = PostgresStore::connect(env.url()).await.expect("connect pg");
    let raw = RawDb::Pg(store.pool().clone());
    Some(run_x1(&store, &raw).await)
}

/// X1a: sqlite is all-or-nothing and retry-clean.
#[tokio::test]
async fn x1a_sqlite_store_batch_atomic() {
    assert_atomic(&sqlite_run().await, "sqlite");
}

/// X1b: postgres is all-or-nothing and retry-clean.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn x1b_postgres_store_batch_atomic() {
    if let Some(run) = pg_run().await {
        assert_atomic(&run, "postgres");
    }
}

/// Cross-backend: same state after fault and after retry
/// (everything except the quota row, which `x1_parity_quota` owns).
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn x1_parity() {
    let Some(pg) = pg_run().await else { return };
    let sq = sqlite_run().await;
    assert_eq!(
        sq.after_fault.without(&["quota"]),
        pg.after_fault.without(&["quota"]),
        "X1 state after the faulted batch"
    );
    assert_eq!(
        sq.after_retry.without(&["quota"]),
        pg.after_retry.without(&["quota"]),
        "X1 state after the healthy retry"
    );
}

/// Cross-backend error variant for the poisoned row (#7099).
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "X1 divergence tracked in issue #7099 — un-ignore when fixed"]
async fn x1_parity_error_variant() {
    let Some(pg) = pg_run().await else { return };
    let sq = sqlite_run().await;
    assert_eq!(
        parity_oracle::err_variant(sq.fault_err.as_ref().expect("sqlite err")).0,
        parity_oracle::err_variant(pg.fault_err.as_ref().expect("pg err")).0,
        "X1 error variant for a poisoned store_batch row (sqlite vs postgres)"
    );
}

/// Cross-backend quota row after the committed retry (#7090).
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "X1 divergence tracked in issue #7090 — un-ignore when fixed"]
async fn x1_parity_quota() {
    let Some(pg) = pg_run().await else { return };
    let sq = sqlite_run().await;
    assert_eq!(
        sq.after_retry.section("quota"),
        pg.after_retry.section("quota"),
        "X1 quota row after a committed store_batch (sqlite vs postgres)"
    );
}
