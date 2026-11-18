// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8912 / PR #9282 (N-2): the two `FOR UPDATE` decide-reads on the Postgres
//! update funnels hold the row the write is computed from until commit, so
//! the in-place-edit archive snapshot and the write are one atomic unit with
//! the read:
//!
//! * L2: trait `update` (`SELECT title, content, ... FOR UPDATE`).
//! * L1: `update_with_expected_version_once` (`SELECT version, ... FOR
//!   UPDATE`), reached through the public `update_with_expected_version`.
//!
//! Both locks carry the invariant only when the owner gate is bypassed (the
//! gate's own `FOR UPDATE` holds the row otherwise), so every cell writes
//! with an admin (bypass) context.
//!
//! Interleaving (deterministic, no sleep race): raw transaction B bumps the
//! row's content and version and stays open (row locked); writer A's update
//! (a title-only patch) is spawned; the cell waits until a backend is blocked
//! behind B (`pg_blocking_pids`), then commits B and joins A.
//!
//! * locked: A waits for B at its decide-read (the barrier records the
//!   statement A is blocked on and every cell asserts it is the
//!   `... FOR UPDATE` read), so A's prior-content snapshot
//!   (`archive_reason = in_place_edit`) holds B's content and A's version
//!   lands on top of B's.
//! * L2 lock removed: A reads the pre-B row, snapshots the ORIGINAL content
//!   and blocks only at the UPDATE, so undoing A would revert B's write.
//! * L1 lock removed: A blocks only at its version-guarded UPDATE (#1641,
//!   `version = $11` with the pre-read version), which then matches 0 rows,
//!   rolls back and is retried on a fresh read, so the stored row is the same
//!   as with the lock; the only observable difference is where A waits,
//!   which is why the blocked statement is asserted.
//!
//! Run through the ci-v2-pg per-binary wrapper (one cloned database per
//! binary); skipped when `AI_MEMORY_TEST_POSTGRES_URL` is unset, as in
//! `tests/cov_postgres_core.rs`.
#![cfg(feature = "sal-postgres")]
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

#[path = "common/pg_barrier.rs"]
mod pg_barrier;

use std::sync::Arc;
use std::time::Duration;

use ai_memory::models::field_names::ARCHIVE_REASON_IN_PLACE_EDIT;
use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, UpdatePatch};
use serde_json::json;

const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";
const OWNER: &str = "ai:lostupdate9282-owner";
/// The admin (bypass) principal: skips the owner gate so the funnel's own
/// decide-read lock is the only thing holding the row.
const OPERATOR: &str = "ai:lostupdate9282-operator";
const ORIGINAL_TITLE: &str = "lost-update original title (#9282)";
const ORIGINAL_CONTENT: &str = "original body (#9282)";
const B_CONTENT: &str = "writer B committed body (#9282)";
const A_TITLE: &str = "writer A title patch (#9282)";
/// Seed version, then B's bump, then A's write on top of B.
const SEED_VERSION: i64 = 1;
const VERSION_AFTER_A: i64 = 3;
/// Poll interval of the `pg_blocking_pids` barrier.
const BARRIER_POLL: Duration = Duration::from_millis(20);

/// B's raw write: content and version change, uncommitted (row locked).
const B_WRITE_SQL: &str = "UPDATE memories SET content = $2, version = version + 1 WHERE id = $1";
const BACKEND_PID_SQL: &str = "SELECT pg_backend_pid()";
const BLOCKED_BEHIND_SQL: &str =
    "SELECT query FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) LIMIT 1";
/// The tail both decide-reads share: A must be waiting on the held read, not
/// on its UPDATE.
const DECIDE_READ_TAIL: &str = "FROM memories WHERE id = $1 FOR UPDATE";
const LIVE_ROW_SQL: &str = "SELECT title, content, version FROM memories WHERE id = $1";
const SNAPSHOT_SQL: &str =
    "SELECT content FROM archived_memories WHERE id = $1 AND archive_reason = $2";

/// Cells identify waiters by "blocked behind pid X", so they run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn seed_memory() -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: format!("lostupdate9282-{}", uuid::Uuid::new_v4().simple()),
        title: ORIGINAL_TITLE.to_string(),
        content: ORIGINAL_CONTENT.to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": OWNER}),
        version: SEED_VERSION,
        ..Memory::default()
    }
}

async fn connect() -> Option<(Arc<PostgresStore>, tokio::sync::MutexGuard<'static, ()>)> {
    let Ok(url) = std::env::var(PG_URL_ENV) else {
        eprintln!("skip: {PG_URL_ENV} not set");
        return None;
    };
    let serial = SERIAL.lock().await;
    let pg = Arc::new(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    );
    Some((pg, serial))
}

async fn seed(pg: &PostgresStore) -> String {
    let m = seed_memory();
    pg.store(&CallerContext::for_agent(OWNER), &m)
        .await
        .expect("seed");
    m.id
}

fn title_patch() -> UpdatePatch {
    UpdatePatch {
        title: Some(A_TITLE.to_string()),
        ..UpdatePatch::default()
    }
}

/// Block until some backend waits directly on `holder_pid`; return the
/// statement that backend is blocked on.
async fn wait_blocked_by(pg: &PostgresStore, holder_pid: i32) -> String {
    let end = pg_barrier::deadline();
    loop {
        let waiter: Option<String> = sqlx::query_scalar(BLOCKED_BEHIND_SQL)
            .bind(holder_pid)
            .fetch_optional(pg.pool())
            .await
            .expect("barrier probe");
        if let Some(statement) = waiter {
            return statement;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "barrier not reached: nothing blocked behind pid {holder_pid}"
        );
        tokio::time::sleep(BARRIER_POLL).await;
    }
}

/// Run writer A (`write`) against an open writer-B transaction, commit B once
/// A is blocked behind it, and return A's result and the statement A waited on.
async fn race_against_b<T, F>(pg: &PostgresStore, id: &str, write: F) -> (T, String)
where
    T: Send + 'static,
    F: std::future::Future<Output = T> + Send + 'static,
{
    let mut b = pg.pool().begin().await.expect("tx B");
    let b_pid: i32 = sqlx::query_scalar(BACKEND_PID_SQL)
        .fetch_one(&mut *b)
        .await
        .expect("tx B pid");
    let touched = sqlx::query(B_WRITE_SQL)
        .bind(id)
        .bind(B_CONTENT)
        .execute(&mut *b)
        .await
        .expect("tx B write")
        .rows_affected();
    assert_eq!(touched, 1, "tx B must lock the seeded row");

    let writer = tokio::spawn(write);
    let blocked_on = wait_blocked_by(pg, b_pid).await;
    b.commit().await.expect("tx B commit");
    let result = tokio::time::timeout(pg_barrier::barrier_budget(), writer)
        .await
        .expect("writer A finishes after B commits")
        .expect("writer A task");
    (result, blocked_on)
}

/// A waited for B at its decide-read, so the read the write is computed from
/// was held (not at the UPDATE after a stale read).
fn assert_waited_on_decide_read(blocked_on: &str) {
    assert!(
        blocked_on.starts_with("SELECT ") && blocked_on.ends_with(DECIDE_READ_TAIL),
        "writer A must wait for B at its `... {DECIDE_READ_TAIL}` decide-read; \
         it waited on: {blocked_on}"
    );
}

/// Live row (title, content, version) and the in_place_edit snapshot content.
async fn observe(pg: &PostgresStore, id: &str) -> ((String, String, i64), Option<String>) {
    let live: (String, String, i64) = sqlx::query_as(LIVE_ROW_SQL)
        .bind(id)
        .fetch_one(pg.pool())
        .await
        .expect("live row");
    let snapshot: Option<String> = sqlx::query_scalar(SNAPSHOT_SQL)
        .bind(id)
        .bind(ARCHIVE_REASON_IN_PLACE_EDIT)
        .fetch_optional(pg.pool())
        .await
        .expect("archive snapshot");
    (live, snapshot)
}

/// L2: trait `update`. The decide-read holds the row, so A's prior-content
/// snapshot is B's committed content, never the pre-B original.
#[tokio::test]
async fn l2_trait_update_read_lock_snapshots_committed_concurrent_write_9282() {
    let Some((pg, _serial)) = connect().await else {
        return;
    };
    let id = seed(&pg).await;
    let store = Arc::clone(&pg);
    let a_id = id.clone();
    let (result, blocked_on) = race_against_b(&pg, &id, async move {
        store
            .update(&CallerContext::for_admin(OPERATOR), &a_id, title_patch())
            .await
            .map_err(|e| e.to_string())
    })
    .await;
    assert_waited_on_decide_read(&blocked_on);
    if let Err(e) = result {
        panic!("writer A trait update must succeed on top of B: {e}");
    }

    let ((title, content, version), snapshot) = observe(&pg, &id).await;
    assert_eq!(
        snapshot.as_deref(),
        Some(B_CONTENT),
        "A's in_place_edit snapshot must hold B's committed content (a pre-B \
         snapshot means A's decide-read was not held: undo would revert B)"
    );
    assert_eq!(content, B_CONTENT, "B's committed content survives A");
    assert_eq!(title, A_TITLE, "A's title patch applied");
    assert_eq!(version, VERSION_AFTER_A, "A's write lands on B's version");
}

/// L1: `update_with_expected_version` (last-write-wins, `expected_version =
/// None`). B's committed content survives and A's write is applied on top of
/// B, with a snapshot of B's content, never of the pre-B row.
#[tokio::test]
async fn l1_expected_version_read_lock_applies_on_top_of_committed_write_9282() {
    let Some((pg, _serial)) = connect().await else {
        return;
    };
    let id = seed(&pg).await;
    let store = Arc::clone(&pg);
    let a_id = id.clone();
    let (result, blocked_on) = race_against_b(&pg, &id, async move {
        store
            .update_with_expected_version(
                &CallerContext::for_admin(OPERATOR),
                &a_id,
                title_patch(),
                None,
            )
            .await
            .map_err(|e| e.to_string())
    })
    .await;
    assert_waited_on_decide_read(&blocked_on);
    let new_version = match result {
        Ok(v) => v,
        Err(e) => panic!("writer A last-write-wins update must apply on top of B: {e}"),
    };

    let ((title, content, version), snapshot) = observe(&pg, &id).await;
    assert_eq!(
        snapshot.as_deref(),
        Some(B_CONTENT),
        "A's in_place_edit snapshot must hold B's committed content (a pre-B \
         snapshot means A's write was computed from a stale copy)"
    );
    assert_eq!(
        new_version, VERSION_AFTER_A,
        "returned version is A's write on B"
    );
    assert_eq!(version, VERSION_AFTER_A, "stored version is A's write on B");
    assert_eq!(
        content, B_CONTENT,
        "B's committed content is never reverted"
    );
    assert_eq!(title, A_TITLE, "A's title patch applied");
}
