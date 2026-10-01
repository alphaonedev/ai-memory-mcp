// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4329 / #4330 — bulk `forget` and the `run_gc` evict sweep lock their
//! `memories` victim rows in ONE canonical order: ascending `id COLLATE "C"`,
//! the order the #4010 containment writers use (CONCURRENCY-04).
//!
//! Each cell holds an ascending-order writer on the lower id `a-…` of an
//! overlapping pair `a-…` < `z-…` whose heap order is the REVERSE of id order,
//! starts the production transaction, waits on a `pg_blocking_pids` barrier
//! (never a sleep) until the production transaction is parked on the writer's
//! lock, and only then lets the writer take `z`. Pre-fix the production
//! transaction already holds `z` (heap order), so the writer's `z` request
//! closes a wait-for cycle and Postgres aborts the writer with 40P01 (the
//! containment write is not applied). Post-fix the production transaction has
//! locked nothing past `a`, the writer takes `z` and commits, and both finish.
//!
//! No trigger, function or other schema object is created: the only state is
//! rows in a per-cell unique namespace, removed on entry and on exit. Cells
//! serialise on an in-process mutex and a Postgres advisory lock, so parallel
//! runs of this binary against one database cannot interfere (the evict sweep
//! reaps EVERY expired row, not just the cell's own).
//!
//! Live Postgres only (`AI_MEMORY_TEST_POSTGRES_URL`); skips when unset.

#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]
#![cfg(feature = "sal-postgres")]

use std::sync::Arc;
use std::time::Duration;

use ai_memory::models::{LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use serde_json::json;

fn mem(ns: &str, id: String, expired: bool) -> Memory {
    let now = chrono::Utc::now();
    let stamp = now.to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id,
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: format!("t-{}", uuid::Uuid::new_v4().simple()),
        content: "lock order body".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: stamp.clone(),
        updated_at: stamp,
        last_accessed_at: None,
        expires_at: expired.then(|| (now - chrono::Duration::hours(1)).to_rfc3339()),
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

/// The backend currently waiting directly on `holder`. A lock barrier, not a
/// timing assumption; bounded so a broken fixture fails instead of hanging.
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

/// Cells share one database and the evict sweep reaps every expired row, so
/// they run one at a time: in-process (this mutex, taken BEFORE connecting
/// because concurrent first connects race the schema bootstrap DDL) and
/// across processes (the advisory lock below).
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Cell {
    store: Arc<PostgresStore>,
    /// Holds the cross-process advisory lock until the cell ends.
    _exclusive: sqlx::Transaction<'static, sqlx::Postgres>,
    ns: String,
    a: String,
    z: String,
}

async fn begin_cell(
    tag: &str,
    expired: bool,
) -> Option<(tokio::sync::MutexGuard<'static, ()>, Cell)> {
    let guard = SERIAL.lock().await;
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    let store = Arc::new(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    );
    let mut exclusive = store.pool().begin().await.expect("exclusive tx");
    sqlx::query("SELECT pg_advisory_xact_lock(4329, 4330)")
        .execute(&mut *exclusive)
        .await
        .expect("cross-process cell lock");
    let ns = format!("lock4329-{tag}-{}", uuid::Uuid::new_v4().simple());
    let (a, z) = (format!("a-{ns}"), format!("z-{ns}"));
    let cell = Cell {
        store,
        _exclusive: exclusive,
        ns,
        a,
        z,
    };
    cell.cleanup().await;
    let ctx = CallerContext::for_agent("ai:tester");
    for id in [&cell.z, &cell.a] {
        cell.store
            .store(&ctx, &mem(&cell.ns, id.clone(), expired))
            .await
            .expect("seed row");
    }
    // `a` becomes the OLDER row: a `(namespace, priority DESC, updated_at
    // DESC)` index scan then yields `z` first, like the ctid order below,
    // whichever access path the planner picks for the namespace predicate.
    sqlx::query("UPDATE memories SET updated_at = updated_at - interval '1 hour' WHERE id = $1")
        .bind(&cell.a)
        .execute(cell.store.pool())
        .await
        .expect("age a");
    // Arrange the heap so `z`'s live tuple precedes `a`'s (ctid order, which a
    // sequential or namespace-index scan follows): the reverse of id order.
    // Rewriting `a` moves its live tuple; verified, not assumed.
    let mut arranged = false;
    for _ in 0..64 {
        let z_first: bool = sqlx::query_scalar(
            "SELECT (SELECT ctid FROM memories WHERE id = $1) \
                  < (SELECT ctid FROM memories WHERE id = $2)",
        )
        .bind(&cell.z)
        .bind(&cell.a)
        .fetch_one(cell.store.pool())
        .await
        .expect("compare heap order");
        if z_first {
            arranged = true;
            break;
        }
        sqlx::query("UPDATE memories SET priority = priority WHERE id = $1")
            .bind(&cell.a)
            .execute(cell.store.pool())
            .await
            .expect("order the heap");
    }
    assert!(arranged, "fixture: could not place z before a in the heap");
    Some((guard, cell))
}

impl Cell {
    /// Remove every row this cell (or a previous aborted run) left behind.
    async fn cleanup(&self) {
        let like = "lock4329-%";
        for sql in [
            "DELETE FROM memories WHERE namespace LIKE $1",
            "DELETE FROM archived_memories WHERE namespace LIKE $1",
            "DELETE FROM forget_tombstones WHERE namespace LIKE $1",
        ] {
            sqlx::query(sql)
                .bind(like)
                .execute(self.store.pool())
                .await
                .expect("cleanup rows");
        }
    }

    /// The #4010 containment-writer shape on the pair: lock `a`, hold it until
    /// the production transaction is parked behind it, then lock `z`, commit.
    async fn interleave(
        &self,
        production: impl std::future::Future<Output = Result<usize, String>> + Send + 'static,
    ) -> (Result<(), String>, Result<usize, String>) {
        let mut writer = self.store.pool().begin().await.expect("writer tx");
        let writer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *writer)
            .await
            .expect("writer pid");
        // The production transaction is already waiting on `a` when the writer
        // asks for `z`; Postgres aborts whichever waiter's deadlock check runs
        // first. A short check delay on the WRITER (transaction-local) makes
        // the writer's check run first, so a cycle surfaces as 40P01 on the
        // writer (the aborted containment write) rather than being absorbed by
        // the production side's bounded 40P01 retry funnel (#3520).
        sqlx::query("SET LOCAL deadlock_timeout = '100ms'")
            .execute(&mut *writer)
            .await
            .expect("writer deadlock check delay");
        sqlx::query("SELECT id FROM memories WHERE id = $1 FOR UPDATE")
            .bind(&self.a)
            .fetch_one(&mut *writer)
            .await
            .expect("writer locks a");
        let prod = tokio::spawn(production);
        let parked = blocked_backend(&self.store, writer_pid).await;
        assert_ne!(parked, writer_pid, "independent transactions");
        let writer_result: Result<(), String> = async {
            sqlx::query("SELECT id FROM memories WHERE id = $1 FOR UPDATE")
                .bind(&self.z)
                .fetch_optional(&mut *writer)
                .await
                .map_err(|e| e.to_string())?;
            sqlx::query("UPDATE memories SET priority = priority WHERE id = ANY($1)")
                .bind([self.a.clone(), self.z.clone()].as_slice())
                .execute(&mut *writer)
                .await
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        .await;
        // On a writer error the transaction is already aborted: dropping it
        // rolls back and frees `a`, so the production side can finish.
        let writer_result = match writer_result {
            Ok(()) => writer.commit().await.map_err(|e| e.to_string()),
            Err(e) => {
                drop(writer);
                Err(e)
            }
        };
        let prod = tokio::time::timeout(Duration::from_secs(60), prod)
            .await
            .expect("production transaction finishes")
            .expect("join production");
        (writer_result, prod)
    }

    async fn count(&self, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE id = ANY($1)"))
            .bind([self.a.clone(), self.z.clone()].as_slice())
            .fetch_one(self.store.pool())
            .await
            .expect("count rows")
    }
}

async fn forget_cell(archive: bool) {
    let tag = if archive { "fa" } else { "fh" };
    let Some((_guard, cell)) = begin_cell(tag, false).await else {
        return;
    };
    let s = Arc::clone(&cell.store);
    let ns = cell.ns.clone();
    let (writer, forget) = cell
        .interleave(async move {
            s.forget(
                &CallerContext::for_agent("ai:operator"),
                Some(&ns),
                None,
                None,
                archive,
            )
            .await
            .map_err(|e| e.to_string())
        })
        .await;
    assert!(
        writer.is_ok() && forget.is_ok(),
        "no lock cycle: writer={writer:?}, forget={forget:?}"
    );
    assert_eq!(forget.expect("forget ok"), 2, "the locked set is erased");
    assert_eq!(cell.count("memories").await, 0, "both rows deleted");
    assert_eq!(
        cell.count("archived_memories").await,
        if archive { 2 } else { 0 },
        "archived set equals the locked set"
    );
    cell.cleanup().await;
}

async fn gc_cell(archive: bool) {
    let tag = if archive { "ga" } else { "gh" };
    let Some((_guard, cell)) = begin_cell(tag, true).await else {
        return;
    };
    let s = Arc::clone(&cell.store);
    let (writer, gc) = cell
        .interleave(async move { s.run_gc(archive).await.map_err(|e| e.to_string()) })
        .await;
    assert!(
        writer.is_ok() && gc.is_ok(),
        "no lock cycle: writer={writer:?}, gc={gc:?}"
    );
    assert!(gc.expect("gc ok") >= 2, "the locked pair is evicted");
    assert_eq!(cell.count("memories").await, 0, "both rows evicted");
    assert_eq!(
        cell.count("archived_memories").await,
        if archive { 2 } else { 0 },
        "archived set equals the locked set"
    );
    cell.cleanup().await;
}

/// #4329 — hard bulk forget (crypto-erase UPDATE + DELETE) vs an ascending writer.
#[tokio::test]
async fn pg_forget_locks_in_id_order_4329() {
    forget_cell(false).await;
}

/// #4329 — archiving bulk forget vs an ascending writer.
#[tokio::test]
async fn pg_forget_archive_locks_in_id_order_4329() {
    forget_cell(true).await;
}

/// #4330 — run_gc evict (victim read + DELETE) vs an ascending writer.
#[tokio::test]
async fn pg_run_gc_evict_locks_in_id_order_4330() {
    gc_cell(false).await;
}

/// #4330 — run_gc archive path (no prior lock pre-fix) vs an ascending writer.
#[tokio::test]
async fn pg_run_gc_archive_locks_in_id_order_4330() {
    gc_cell(true).await;
}
