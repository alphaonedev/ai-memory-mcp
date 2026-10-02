// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! #4053 (fixed by #3152) — the #3953 residual: on Postgres the optional lifecycle change of
//! an `update` (trait + If-Match) must be applied inside the SAME owner-locked
//! transaction as the content write.
//!
//! Pre-fix the owner-gated transaction committed and the lifecycle change ran
//! in a SECOND, owner-unaware transaction. An ownership transfer that
//! committed between the two let the former owner's request change the new
//! owner's row, and the call still reported success. An illegal transition
//! also left the content write committed while the call returned 409 (the
//! #3152 split).
//!
//! The interleaving is deterministic, never a sleep race: an `AFTER UPDATE OF
//! content` trigger parks the caller's content UPDATE on an advisory lock
//! (the caller then holds the row lock), a transfer is queued behind that row
//! lock (observed with `pg_blocking_pids`), and the park is released.
//!
//! * fixed — the caller's whole update, lifecycle included, commits before
//!   the transfer acquires the row, so the transfer sees the new lifecycle.
//! * pre-fix — the content tx commits, the transfer acquires the row while the
//!   lifecycle is still the old value, and the lifecycle SELECT then queues
//!   behind the transfer: the former owner writes the new owner's row.
//!
//! Controls: an illegal transition rolls the WHOLE update back (content,
//! prior-content archive and version), and If-Match returns the version that
//! reflects the complete update.
//!
//! Live-PG cells: `#[ignore]`-gated (the postgres-ignored tier) and skipped
//! when `AI_MEMORY_TEST_POSTGRES_URL` is unset.
#![cfg(all(feature = "sal", feature = "sal-postgres"))]

#[path = "common/pg_barrier.rs"]
mod pg_barrier;

use std::sync::Arc;
use std::time::Duration;

use ai_memory::models::{LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};
use serde_json::json;

const ALICE: &str = "ai:lifecycle4053-alice";
const NEW_OWNER: &str = "ai:lifecycle4053-new";
/// Advisory key the barrier trigger waits on.
const PARK_KEY: i64 = 4053;
const NEW_CONTENT: &str = "alice's edit (#4053)";

/// The production re-own statement shape (`reown_3124`), returning the
/// lifecycle it observed when it acquired the row.
const REOWN_SQL: &str = "UPDATE memories SET metadata = jsonb_set(metadata, '{agent_id}', \
     to_jsonb($2::text)), version = version + 1, updated_at = NOW() WHERE id = $1 \
     RETURNING lifecycle_state";

/// Cells install a trigger on the shared `memories` table and identify
/// backends by "blocked behind pid X", so they run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn mem(owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: format!("lifecycle4053-{}", uuid::Uuid::new_v4().simple()),
        title: "lifecycle under owner lock".to_string(),
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

async fn seed(pg: &PostgresStore) -> Memory {
    let m = mem(ALICE);
    pg.store(&CallerContext::for_agent(ALICE), &m)
        .await
        .expect("seed");
    m
}

/// Alice's content + lifecycle update through the trait `update`
/// (`explicit = false`) or the If-Match funnel (`explicit = true`, version 1).
/// Returns the If-Match version, `None` for the trait path.
async fn alice_update(
    pg: &PostgresStore,
    id: &str,
    explicit: bool,
    target: LifecycleState,
) -> Result<Option<i64>, StoreError> {
    let patch = UpdatePatch {
        content: Some(NEW_CONTENT.to_string()),
        lifecycle_state: Some(target),
        ..UpdatePatch::default()
    };
    let ctx = CallerContext::for_agent(ALICE);
    if explicit {
        pg.update_with_expected_version(&ctx, id, patch, Some(1))
            .await
            .map(Some)
    } else {
        pg.update(&ctx, id, patch).await.map(|()| None)
    }
}

async fn backend_pid<'c, E>(executor: E) -> i32
where
    E: sqlx::Executor<'c, Database = sqlx::Postgres>,
{
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(executor)
        .await
        .expect("pid")
}

/// Pid of the (single) backend currently blocked directly by `holder_pid`.
async fn wait_blocked_by(pg: &PostgresStore, holder_pid: i32) -> i32 {
    let end = pg_barrier::deadline();
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

async fn install_park_trigger(pg: &PostgresStore) {
    sqlx::raw_sql(
        "CREATE OR REPLACE FUNCTION lifecycle_4053_park() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN PERFORM pg_advisory_xact_lock(4053); RETURN NEW; END $$; \
         DROP TRIGGER IF EXISTS lifecycle_4053_park ON memories; \
         CREATE TRIGGER lifecycle_4053_park AFTER UPDATE OF content ON memories \
         FOR EACH ROW EXECUTE FUNCTION lifecycle_4053_park();",
    )
    .execute(pg.pool())
    .await
    .expect("install barrier trigger");
}

async fn drop_park_trigger(pg: &PostgresStore) {
    sqlx::raw_sql(
        "DROP TRIGGER IF EXISTS lifecycle_4053_park ON memories; \
         DROP FUNCTION IF EXISTS lifecycle_4053_park();",
    )
    .execute(pg.pool())
    .await
    .expect("remove barrier trigger");
}

/// What [`race`] reports: `(lifecycle the transfer observed, Alice's result,
/// final (owner, lifecycle))`.
type RaceOutcome = (
    String,
    Result<Option<i64>, StoreError>,
    (Option<String>, String),
);

/// Park Alice's content write, queue an ownership transfer behind her row
/// lock, release, and report what the transfer saw.
///
/// The barrier trigger sits on the SHARED `memories` table, so it must never
/// outlive this call (f2r review of 9b101e875): a leaked trigger would make
/// every later content UPDATE in every test binary take advisory key 4053.
/// So it is dropped before install (healing a leak from an earlier crashed
/// run) and dropped again unconditionally after the body, which runs in its
/// own task so a failing assertion inside it cannot skip the cleanup.
async fn race(pg: &Arc<PostgresStore>, explicit: bool) -> RaceOutcome {
    drop_park_trigger(pg).await;
    let body = tokio::spawn(race_body(Arc::clone(pg), explicit)).await;
    drop_park_trigger(pg).await;
    match body {
        Ok(outcome) => outcome,
        Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
        Err(join) => panic!("race body did not complete: {join}"),
    }
}

async fn race_body(pg: Arc<PostgresStore>, explicit: bool) -> RaceOutcome {
    let pg = &pg;
    let m = seed(pg).await;
    install_park_trigger(pg).await;

    let mut park = pg.pool().begin().await.expect("park tx");
    let park_pid = backend_pid(&mut *park).await;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(PARK_KEY)
        .execute(&mut *park)
        .await
        .expect("hold park");

    let writer = {
        let (pg, id) = (Arc::clone(pg), m.id.clone());
        tokio::spawn(async move { alice_update(&pg, &id, explicit, LifecycleState::Active).await })
    };
    // Alice passed her owner gate and is inside her content UPDATE, holding
    // the row lock, parked on the advisory key.
    let writer_pid = wait_blocked_by(pg, park_pid).await;

    let mut reown = pg.pool().begin().await.expect("reown tx");
    let reown_pid = backend_pid(&mut *reown).await;
    let id = m.id.clone();
    let transfer = tokio::spawn(async move {
        let seen: String = sqlx::query_scalar(REOWN_SQL)
            .bind(&id)
            .bind(NEW_OWNER)
            .fetch_one(&mut *reown)
            .await
            .expect("transfer owner");
        (reown, seen)
    });
    assert_eq!(
        wait_blocked_by(pg, writer_pid).await,
        reown_pid,
        "the transfer must queue behind the caller's row lock"
    );
    park.commit().await.expect("release the content writer");

    let (reown, seen) = tokio::time::timeout(pg_barrier::barrier_budget(), transfer)
        .await
        .expect("transfer acquired the row")
        .expect("join transfer");
    reown.commit().await.expect("commit transfer");
    let result = tokio::time::timeout(pg_barrier::barrier_budget(), writer)
        .await
        .expect("writer completed")
        .expect("join writer");
    let after: (Option<String>, String) =
        sqlx::query_as("SELECT metadata->>'agent_id', lifecycle_state FROM memories WHERE id = $1")
            .bind(&m.id)
            .fetch_one(pg.pool())
            .await
            .expect("read result");
    (seen, result, after)
}

async fn race_cell(explicit: bool) {
    let Some((pg, _serial)) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let (seen, result, after) = race(&pg, explicit).await;
    eprintln!("#4053 explicit={explicit} transfer_saw={seen} result={result:?} final={after:?}");
    result.expect("the owner's update was authorised before the transfer");
    assert_eq!(
        seen, "active",
        "the ownership transfer must follow the COMPLETE update: a transfer that \
         sees the old lifecycle means the former owner's lifecycle write lands on \
         the new owner's row"
    );
    assert_eq!(after, (Some(NEW_OWNER.to_string()), "active".to_string()));
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL"]
async fn pg_trait_update_lifecycle_holds_owner_lock_4053() {
    race_cell(false).await;
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL"]
async fn pg_if_match_update_lifecycle_holds_owner_lock_4053() {
    race_cell(true).await;
}

/// Controls on both funnels: an illegal edge rolls the whole update back;
/// a legal one lands with the version the caller is told about.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL"]
async fn pg_update_lifecycle_is_atomic_with_content_4053() {
    let Some((pg, _serial)) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    drop_park_trigger(&pg).await;
    for explicit in [false, true] {
        let m = seed(&pg).await;
        // open -> done is not a legal edge.
        let refused = alice_update(&pg, &m.id, explicit, LifecycleState::Done).await;
        assert!(
            matches!(refused, Err(StoreError::InvalidTransition { .. })),
            "explicit={explicit}: {refused:?}"
        );
        let row: (String, String, i64) =
            sqlx::query_as("SELECT content, lifecycle_state, version FROM memories WHERE id = $1")
                .bind(&m.id)
                .fetch_one(pg.pool())
                .await
                .expect("read after refusal");
        assert_eq!(
            row,
            (m.content.clone(), "open".to_string(), 1),
            "explicit={explicit}: a refused transition must roll the content write back"
        );
        let archives: i64 =
            sqlx::query_scalar("SELECT count(*) FROM archived_memories WHERE id = $1")
                .bind(&m.id)
                .fetch_one(pg.pool())
                .await
                .expect("read archives");
        assert_eq!(
            archives, 0,
            "explicit={explicit}: a refused transition leaves no prior-content archive"
        );

        let returned = alice_update(&pg, &m.id, explicit, LifecycleState::Active)
            .await
            .expect("legal transition");
        let row: (String, String, i64) =
            sqlx::query_as("SELECT content, lifecycle_state, version FROM memories WHERE id = $1")
                .bind(&m.id)
                .fetch_one(pg.pool())
                .await
                .expect("read after update");
        assert_eq!(
            (row.0.as_str(), row.1.as_str()),
            (NEW_CONTENT, "active"),
            "explicit={explicit}"
        );
        if explicit {
            assert_eq!(
                returned,
                Some(row.2),
                "If-Match must return the version of the COMPLETE update"
            );
        }
        // A lifecycle no-op adds no second bump.
        let v = pg
            .update_with_expected_version(
                &CallerContext::for_agent(ALICE),
                &m.id,
                UpdatePatch {
                    lifecycle_state: Some(LifecycleState::Active),
                    ..UpdatePatch::default()
                },
                Some(row.2),
            )
            .await
            .expect("idempotent transition");
        assert_eq!(v, row.2 + 1, "explicit={explicit}: no bump for a no-op");
    }
}
