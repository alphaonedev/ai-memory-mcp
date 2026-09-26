// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! #3953 — the Postgres caller-owns gate must hold its row lock from the
//! owner check to the write, on `update` (trait + If-Match) and hard
//! `delete`.
//!
//! Pre-fix the gate's `SELECT … FOR UPDATE` ran on the autocommit POOL, so
//! the lock was released at statement end. `update`'s `WHERE id = $1` and
//! hard delete's `DELETE … WHERE id = $1` carry no owner predicate, so a
//! re-own committed between check and write let the caller's write land on
//! a row it no longer owned — for hard delete, an irreversible erase.
//!
//! Every interleaving is deterministic: the caller's write is parked AFTER
//! its owner check and BEFORE its first `memories` row write, by a held
//! table lock on the first other table it touches past the gate
//! (`archived_memories` for a content update, `namespace_meta` for a hard
//! delete), found with a `pg_blocking_pids` barrier. A re-own is
//! then attempted on its own connection:
//!
//! * fixed — the re-own blocks behind the CALLER's row lock (observed via
//!   `pg_blocking_pids`, then cancelled); the caller's write lands on a row
//!   it still owns.
//! * pre-fix (pool gate, or an in-tx gate without `FOR UPDATE`) — the re-own
//!   commits inside the window and the caller's write hits the re-owned row.
//!
//! Controls: the owner still succeeds, a non-owner is still refused, and a
//! re-own that commits FIRST (the caller's gate queued behind it) is refused
//! with the same envelope as a plain owner mismatch.
//!
//! Live-PG cells: `#[ignore]`-gated (the postgres-ignored tier) and skipped
//! when `AI_MEMORY_TEST_POSTGRES_URL` is unset.
#![cfg(all(feature = "sal", feature = "sal-postgres"))]

use std::sync::Arc;
use std::time::Duration;

use ai_memory::models::{LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};
use serde_json::json;

const ALICE: &str = "ai:toctou3953-alice";
const MALLORY: &str = "ai:toctou3953-mallory";
const NEW_CONTENT: &str = "alice's edit (#3953)";
/// First table a content `update` touches past the owner gate.
const UPDATE_PARK_TABLE: &str = "archived_memories";
/// First table a hard `delete` touches past the owner gate (the
/// `namespace_meta` sever probe), BEFORE its first `memories` row write.
const DELETE_PARK_TABLE: &str = "namespace_meta";

fn mem(owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: format!("toctou3953-{}", uuid::Uuid::new_v4().simple()),
        title: "owner gate toctou".to_string(),
        content: "original body".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": owner}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
    }
}

/// The barriers identify backends by "blocked behind pid X", and a parked
/// table lock would also stall a sibling cell's writes — so cells in this
/// binary run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn connect() -> Option<(Arc<PostgresStore>, tokio::sync::MutexGuard<'static, ()>)> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    let serial = SERIAL.lock().await;
    let pg = Arc::new(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    );
    Some((pg, serial))
}

async fn seed(pg: &PostgresStore, owner: &str) -> Memory {
    let m = mem(owner);
    pg.store(&CallerContext::for_agent(owner), &m)
        .await
        .expect("seed");
    m
}

fn content_patch() -> UpdatePatch {
    UpdatePatch {
        content: Some(NEW_CONTENT.to_string()),
        ..UpdatePatch::default()
    }
}

/// `(owner, content)` of the live row, `None` when it is gone.
async fn row(pg: &PostgresStore, id: &str) -> Option<(Option<String>, String)> {
    sqlx::query_as("SELECT metadata->>'agent_id', content FROM memories WHERE id = $1")
        .bind(id)
        .fetch_optional(pg.pool())
        .await
        .expect("read row")
}

/// The production re-own statement shape (`reown_3124`): stamp a new
/// `agent_id` and bump `version`.
const REOWN_SQL: &str = "UPDATE memories SET metadata = jsonb_set(metadata, '{agent_id}', \
     to_jsonb($2::text)), version = version + 1, updated_at = NOW() WHERE id = $1";

async fn backend_pid<'c, E>(executor: E) -> i32
where
    E: sqlx::Executor<'c, Database = sqlx::Postgres>,
{
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(executor)
        .await
        .expect("pid")
}

/// Open a transaction holding `ACCESS EXCLUSIVE` on `table`: the writer's
/// first statement touching it parks. Returns it + its pid.
async fn hold_table_lock(
    pg: &PostgresStore,
    table: &str,
) -> (sqlx::Transaction<'static, sqlx::Postgres>, i32) {
    let mut tx = pg.pool().begin().await.expect("lock tx");
    let pid = backend_pid(&mut *tx).await;
    sqlx::query(&format!("LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut *tx)
        .await
        .expect("lock table");
    (tx, pid)
}

/// Pid of the (single) backend currently blocked directly by `holder_pid`.
async fn wait_blocked_by(pg: &PostgresStore, holder_pid: i32) -> i32 {
    let end = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let waiter: Option<i32> = sqlx::query_scalar(
            "SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) LIMIT 1",
        )
        .bind(holder_pid)
        .fetch_optional(pg.pool())
        .await
        .expect("barrier probe");
        if let Some(pid) = waiter {
            return pid;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "barrier not reached: nothing blocked behind pid {holder_pid}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn is_blocked_by(pg: &PostgresStore, waiter: i32, holder: i32) -> bool {
    sqlx::query_scalar("SELECT $2 = ANY(pg_blocking_pids($1))")
        .bind(waiter)
        .bind(holder)
        .fetch_one(pg.pool())
        .await
        .expect("blocking probe")
}

/// What a re-own attempted inside the caller's check→write window did.
#[derive(Debug, PartialEq, Eq)]
enum Reown {
    /// It queued behind the caller's row lock (the fix): cancelled here.
    BlockedByWriter,
    /// It committed inside the window (the #3953 defect).
    Committed,
}

/// Attempt a re-own of `id` to MALLORY while the caller (`writer_pid`) is
/// parked between its owner check and its write.
async fn attempt_reown_in_window(pg: &Arc<PostgresStore>, id: &str, writer_pid: i32) -> Reown {
    let mut conn = pg.pool().acquire().await.expect("reown conn");
    let reown_pid = backend_pid(&mut *conn).await;
    let id_owned = id.to_string();
    let task = tokio::spawn(async move {
        sqlx::query(REOWN_SQL)
            .bind(&id_owned)
            .bind(MALLORY)
            .execute(&mut *conn)
            .await
            .map(|r| r.rows_affected())
    });
    let end = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if task.is_finished() {
            let rows = task.await.expect("join reown").expect("reown statement");
            assert_eq!(rows, 1, "the re-own matched the row");
            return Reown::Committed;
        }
        if is_blocked_by(pg, reown_pid, writer_pid).await {
            let cancelled: bool = sqlx::query_scalar("SELECT pg_cancel_backend($1)")
                .bind(reown_pid)
                .fetch_one(pg.pool())
                .await
                .expect("cancel reown");
            assert!(cancelled, "cancel the parked re-own");
            let res = task.await.expect("join reown");
            assert!(
                res.is_err(),
                "the cancelled re-own must not commit: {res:?}"
            );
            return Reown::BlockedByWriter;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "re-own neither committed nor queued behind the writer"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn assert_owner_refusal(res: &Result<impl std::fmt::Debug, StoreError>, what: &str) {
    match res {
        Err(StoreError::PermissionDenied { reason, .. }) => assert_eq!(
            reason,
            ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY,
            "{what}: the owner-mismatch envelope"
        ),
        other => panic!("{what}: expected PermissionDenied, got {other:?}"),
    }
}

// ------------------------------------------------------------ RED pins ----

/// #3953 (update) — a re-own cannot commit between the trait `update`'s
/// owner check and its UPDATE.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_update_owner_gate_lock_spans_check_to_write_3953() {
    let Some((pg, _serial)) = connect().await else {
        return;
    };
    let m = seed(&pg, ALICE).await;
    let (park, park_pid) = hold_table_lock(&pg, UPDATE_PARK_TABLE).await;
    let writer = {
        let (pg, id) = (Arc::clone(&pg), m.id.clone());
        tokio::spawn(async move {
            pg.update(&CallerContext::for_agent(ALICE), &id, content_patch())
                .await
        })
    };
    let writer_pid = wait_blocked_by(&pg, park_pid).await;
    let reown = attempt_reown_in_window(&pg, &m.id, writer_pid).await;
    park.commit().await.expect("release park");
    let res = writer.await.expect("join writer");
    let after = row(&pg, &m.id).await;
    assert_eq!(
        reown,
        Reown::BlockedByWriter,
        "#3953: a re-own committed between update's owner check and its write; \
         the caller's update returned {res:?} and the row is now {after:?}"
    );
    res.expect("the owner's update lands");
    assert_eq!(
        after,
        Some((Some(ALICE.to_string()), NEW_CONTENT.to_string())),
        "the write landed on a row the caller still owned"
    );
}

/// #3953 (If-Match update) — same property on
/// `update_with_expected_version`: its pool gate ran BEFORE the version
/// pre-read, so the version CAS could not see a re-own in that gap.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_if_match_update_owner_gate_lock_spans_check_to_write_3953() {
    let Some((pg, _serial)) = connect().await else {
        return;
    };
    let m = seed(&pg, ALICE).await;
    let (park, park_pid) = hold_table_lock(&pg, UPDATE_PARK_TABLE).await;
    let writer = {
        let (pg, id) = (Arc::clone(&pg), m.id.clone());
        tokio::spawn(async move {
            pg.update_with_expected_version(
                &CallerContext::for_agent(ALICE),
                &id,
                content_patch(),
                None,
            )
            .await
        })
    };
    let writer_pid = wait_blocked_by(&pg, park_pid).await;
    let reown = attempt_reown_in_window(&pg, &m.id, writer_pid).await;
    park.commit().await.expect("release park");
    let res = writer.await.expect("join writer");
    let after = row(&pg, &m.id).await;
    assert_eq!(
        reown,
        Reown::BlockedByWriter,
        "#3953: a re-own committed between the If-Match update's owner check and \
         its write; the update returned {res:?} and the row is now {after:?}"
    );
    res.expect("the owner's If-Match update lands");
    assert_eq!(
        after,
        Some((Some(ALICE.to_string()), NEW_CONTENT.to_string())),
        "the write landed on a row the caller still owned"
    );
}

/// #3953 (hard delete) — a re-own cannot commit between hard `delete`'s
/// owner check and its irreversible erase.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_hard_delete_owner_gate_lock_spans_check_to_erase_3953() {
    let Some((pg, _serial)) = connect().await else {
        return;
    };
    let m = seed(&pg, ALICE).await;
    let (park, park_pid) = hold_table_lock(&pg, DELETE_PARK_TABLE).await;
    let writer = {
        let (pg, id) = (Arc::clone(&pg), m.id.clone());
        tokio::spawn(async move { pg.delete(&CallerContext::for_agent(ALICE), &id).await })
    };
    let writer_pid = wait_blocked_by(&pg, park_pid).await;
    let reown = attempt_reown_in_window(&pg, &m.id, writer_pid).await;
    park.commit().await.expect("release park");
    let res = writer.await.expect("join writer");
    let after = row(&pg, &m.id).await;
    assert_eq!(
        reown,
        Reown::BlockedByWriter,
        "#3953: a re-own committed between hard delete's owner check and its \
         erase; the delete returned {res:?} and the row is now {after:?}"
    );
    res.expect("the owner's hard delete lands");
    assert_eq!(after, None, "the owner's row is erased");
}

// ------------------------------------------------------------- controls ----

/// A re-own that commits FIRST — the caller's gate queued behind it — is
/// refused with the same envelope as a plain owner mismatch, and nothing is
/// written.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_reown_committed_first_is_an_owner_refusal_3953() {
    let Some((pg, _serial)) = connect().await else {
        return;
    };
    for verb in ["update", "delete"] {
        let m = seed(&pg, ALICE).await;
        let mut reown = pg.pool().begin().await.expect("reown tx");
        let reown_pid = backend_pid(&mut *reown).await;
        sqlx::query(REOWN_SQL)
            .bind(&m.id)
            .bind(MALLORY)
            .execute(&mut *reown)
            .await
            .expect("reown");
        let writer = {
            let (pg, id) = (Arc::clone(&pg), m.id.clone());
            tokio::spawn(async move {
                let ctx = CallerContext::for_agent(ALICE);
                if verb == "update" {
                    pg.update(&ctx, &id, content_patch()).await
                } else {
                    pg.delete(&ctx, &id).await
                }
            })
        };
        wait_blocked_by(&pg, reown_pid).await;
        reown.commit().await.expect("commit reown");
        let res = writer.await.expect("join writer");
        assert_owner_refusal(&res, &format!("{verb} after a committed re-own"));
        assert_eq!(
            row(&pg, &m.id).await,
            Some((Some(MALLORY.to_string()), "original body".to_string())),
            "{verb}: a refused write changes nothing"
        );
    }
}

/// The owner's update and hard delete still succeed; a non-owner is still
/// refused on both and changes nothing.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_owner_gate_controls_owner_passes_non_owner_refused_3953() {
    let Some((pg, _serial)) = connect().await else {
        return;
    };
    let (alice, mallory) = (
        CallerContext::for_agent(ALICE),
        CallerContext::for_agent(MALLORY),
    );

    let m = seed(&pg, ALICE).await;
    assert_owner_refusal(
        &pg.update(&mallory, &m.id, content_patch()).await,
        "non-owner update",
    );
    assert_owner_refusal(
        &pg.update_with_expected_version(&mallory, &m.id, content_patch(), None)
            .await,
        "non-owner If-Match update",
    );
    assert_owner_refusal(&pg.delete(&mallory, &m.id).await, "non-owner delete");
    assert_eq!(
        row(&pg, &m.id).await,
        Some((Some(ALICE.to_string()), "original body".to_string())),
        "refused writes change nothing"
    );

    pg.update(&alice, &m.id, content_patch())
        .await
        .expect("owner update");
    assert_eq!(
        row(&pg, &m.id).await,
        Some((Some(ALICE.to_string()), NEW_CONTENT.to_string()))
    );
    pg.update_with_expected_version(
        &alice,
        &m.id,
        UpdatePatch {
            title: Some("retitled".to_string()),
            ..UpdatePatch::default()
        },
        None,
    )
    .await
    .expect("owner If-Match update");
    pg.delete(&alice, &m.id).await.expect("owner delete");
    assert_eq!(row(&pg, &m.id).await, None, "owner delete erases");

    let missing = uuid::Uuid::new_v4().to_string();
    assert!(
        matches!(
            pg.delete(&alice, &missing).await,
            Err(StoreError::NotFound { .. })
        ),
        "an absent id stays NotFound, never success with 0 rows"
    );
}
