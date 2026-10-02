// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]
//! #4010 / #4184: the postgres `swarm_rewind` vs auto-stamp lock order.
//!
//! Lives in its OWN test binary (cargo runs binaries one at a time) because the
//! cell installs a trigger on the shared `memories` table: `CREATE`/`DROP
//! TRIGGER` need an `ACCESS EXCLUSIVE` lock that would otherwise queue behind,
//! and stall, every sibling cell's DML (55P03). The trigger and its function
//! are removed on EVERY exit path (success, assertion failure, panic), with the
//! lock timeout lifted for the cleanup so it cannot itself time out (#4184).
//!
//! `#[ignore]`-gated (postgres-ignored tier); fails closed when
//! `AI_MEMORY_TEST_POSTGRES_URL` is unset.
#![cfg(feature = "sal-postgres")]

use ai_memory::models::{LifecycleState, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

const ISSUER: &str = "ai:rewind-admin";
const DEPTH: usize = ai_memory::storage::LINEAGE_MAX_DEPTH;
/// Prefix of the test-only trigger and function; leak checks query on it.
const TRIGGER_PREFIX: &str = "barrier_4010_";

fn mem(ns: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "ai:tester"}),
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

async fn connect() -> PostgresStore {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("AI_MEMORY_TEST_POSTGRES_URL required (fail closed)");
    PostgresStore::connect(&url)
        .await
        .expect("connect postgres")
}

async fn state(store: &PostgresStore, id: &str) -> String {
    let (s,): (String,) = sqlx::query_as("SELECT lifecycle_state FROM memories WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .expect("read state");
    s
}

async fn rewind_events(store: &PostgresStore, issuer: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM signed_events WHERE event_type = $1 AND agent_id = $2",
    )
    .bind(ai_memory::signed_events::event_types::SWARM_REWIND)
    .bind(issuer)
    .fetch_one(store.pool())
    .await
    .expect("count events");
    n
}

/// A database lock barrier, not a timing assumption: return the backend
/// currently waiting directly on `holder`. Bounded so a broken fixture fails.
async fn blocked_backend(store: &PostgresStore, holder: i32) -> i32 {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar(
                "SELECT pid FROM pg_stat_activity WHERE datname = current_database() \
                 AND $1 = ANY(pg_blocking_pids(pid)) LIMIT 1",
            )
            .bind(holder)
            .fetch_optional(store.pool())
            .await
            .expect("probe lock barrier");
            if let Some(pid) = pid {
                return pid;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("lock barrier must be reached")
}

/// Remove the test trigger and function. Runs on every exit path. The lock
/// timeout is lifted (`SET LOCAL`, transaction scoped so the pooled connection
/// is not left changed) because the DDL must wait for parked transactions to
/// finish; the wait is bounded by an outer timeout so a stuck cleanup reports
/// loudly instead of hanging.
async fn remove_barrier(store: &PostgresStore, trigger: &str) -> Result<(), String> {
    let work = async {
        let mut tx = store.pool().begin().await.map_err(|e| e.to_string())?;
        sqlx::raw_sql(&format!(
            "SET LOCAL lock_timeout = 0; \
             DROP TRIGGER IF EXISTS {trigger} ON memories; \
             DROP FUNCTION IF EXISTS {trigger}()"
        ))
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())
    };
    tokio::time::timeout(Duration::from_secs(60), work)
        .await
        .map_err(|_| "cleanup timed out".to_string())?
}

/// The scenario proper. Creates the trigger named `trigger`; the caller always
/// removes it afterwards, so this body may assert or panic freely.
async fn scenario(store: Arc<PostgresStore>, trigger: String) {
    let namespace = format!("lock-order-{}", uuid::Uuid::new_v4().simple());
    let issuer = format!("{ISSUER}-{}", uuid::Uuid::new_v4().simple());
    let mut upstream = mem(&namespace, "upstream");
    let mut root = mem(&namespace, "root");
    let mut child = mem(&namespace, "child");
    upstream.id = format!("u-{namespace}");
    root.id = format!("z-{namespace}");
    child.id = format!("a-{namespace}");
    let ctx = CallerContext::for_agent("ai:tester");
    for row in [&upstream, &root, &child] {
        store.store(&ctx, row).await.expect("seed overlap");
    }
    for (c, p) in [(&root, &upstream), (&child, &root)] {
        let link = MemoryLink {
            source_id: c.id.clone(),
            target_id: p.id.clone(),
            relation: MemoryLinkRelation::DerivesFrom,
            created_at: chrono::Utc::now().to_rfc3339(),
            signature: None,
            observed_by: None,
            valid_from: None,
            valid_until: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        };
        store.link(&ctx, &link).await.expect("overlapping lineage");
    }

    // Test-only AFTER UPDATE trigger pauses the production auto-stamp while
    // it owns the first row. All interpolated SQL is generated UUID/id text.
    let mut barrier = store.pool().begin().await.expect("barrier connection");
    let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *barrier)
        .await
        .expect("barrier pid");
    sqlx::query("SELECT pg_advisory_xact_lock(4010, $1)")
        .bind(holder)
        .execute(&mut *barrier)
        .await
        .expect("hold barrier");
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION {trigger}() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN PERFORM pg_advisory_xact_lock(4010, {holder}); RETURN NEW; END $$; \
         CREATE TRIGGER {trigger} AFTER UPDATE ON memories FOR EACH ROW \
         WHEN (NEW.id = '{}') EXECUTE FUNCTION {trigger}()",
        child.id,
    ))
    .execute(store.pool())
    .await
    .expect("install test barrier");

    let stamp_store = Arc::clone(&store);
    let stamp_root = upstream.id.clone();
    let stamp = tokio::spawn(async move {
        stamp_store
            .stamp_contaminated_descendants_pg(&stamp_root, DEPTH)
            .await
    });
    let stamper = blocked_backend(&store, holder).await;
    let rewind_store = Arc::clone(&store);
    let rewind_root = root.id.clone();
    let rewind_issuer = issuer.clone();
    let rewind = tokio::spawn(async move {
        rewind_store
            .swarm_rewind(
                &CallerContext::for_admin_checked(&rewind_issuer, true),
                &rewind_root,
                DEPTH,
                "memory",
                &[],
                false,
            )
            .await
    });
    let rewinder = blocked_backend(&store, stamper).await;
    assert_ne!(stamper, rewinder, "independent transaction connections");
    barrier.commit().await.expect("release auto-stamp barrier");
    let (stamp, rewind) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(stamp, rewind)
    })
    .await
    .expect("both containment writes finish without timeout");
    let stamp = stamp.expect("join auto-stamp");
    let rewind = rewind.expect("join rewind");
    assert!(
        stamp.is_ok() && rewind.is_ok(),
        "both containment writes must succeed: stamp={stamp:?}, rewind={rewind:?}"
    );
    for row in [&root, &child] {
        assert_eq!(state(&store, &row.id).await, "contaminated");
    }
    assert_eq!(state(&store, &upstream.id).await, "open");
    assert_eq!(rewind_events(&store, &issuer).await, 1);
    assert!(rewind.expect("successful rewind").signed_event_id.is_some());
}

/// #4010: upstream <- z-root <- a-child. Auto-stamping holds a-child;
/// rewind then waits on a-child. On the carrier it also holds z-root, so
/// resuming auto-stamping makes the two real transactions deadlock.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_rewind_and_auto_stamp_share_lock_order_4010() {
    let store = Arc::new(connect().await);
    let trigger = format!("{TRIGGER_PREFIX}{}", uuid::Uuid::new_v4().simple());
    // Run the body as its own task so a panic is captured, cleanup ALWAYS
    // runs, and only then is the panic re-raised (#4184).
    let outcome = tokio::spawn(scenario(Arc::clone(&store), trigger.clone())).await;
    let cleanup = remove_barrier(&store, &trigger).await;
    if let Err(join) = outcome {
        match join.try_into_panic() {
            Ok(payload) => std::panic::resume_unwind(payload),
            Err(join) => panic!("scenario task failed: {join}"),
        }
    }
    cleanup.expect("remove test barrier");
    let leaked: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_trigger WHERE tgname = $1")
        .bind(&trigger)
        .fetch_one(store.pool())
        .await
        .expect("leak probe");
    assert_eq!(leaked, 0, "test trigger must not outlive the cell");
}
