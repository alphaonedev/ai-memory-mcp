// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4209 / #4210 — every multi-row `memories` lock path takes its locks in ONE
//! canonical order: ascending `id COLLATE "C"`, the order the #4010
//! containment writers (rewind, auto-stamp) use.
//!
//! Each cell interleaves a real production transaction with an
//! ascending-order writer on an overlapping pair `a-…` < `z-…`, using a
//! Postgres trigger that parks the production transaction on an advisory
//! lock and a `pg_blocking_pids` barrier (never a sleep). Pre-fix, releasing
//! the barrier closes a wait-for cycle and Postgres aborts one side with
//! 40P01. Post-fix the production transaction already holds BOTH rows in
//! ascending order, the writer simply waits, and both commit.
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

use ai_memory::models::{LifecycleState, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use serde_json::json;

fn mem(ns: &str, id: String, owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
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

async fn connect() -> Option<Arc<PostgresStore>> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    Some(Arc::new(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    ))
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

/// A parked-transaction barrier: an advisory lock held by an open
/// transaction, plus a test-only trigger that takes the same lock.
struct Barrier {
    tx: sqlx::Transaction<'static, sqlx::Postgres>,
    holder: i32,
    name: String,
    table: &'static str,
}

impl Barrier {
    /// `timing` is `BEFORE UPDATE` / `BEFORE INSERT`; `when` is the trigger's
    /// WHEN condition. All interpolated SQL is generated id/uuid text.
    async fn install(store: &PostgresStore, table: &'static str, timing: &str, when: &str) -> Self {
        let name = format!("barrier_4209_{}", uuid::Uuid::new_v4().simple());
        let mut tx = store.pool().begin().await.expect("barrier connection");
        let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .expect("barrier pid");
        sqlx::query("SELECT pg_advisory_xact_lock(4209, $1)")
            .bind(holder)
            .execute(&mut *tx)
            .await
            .expect("hold barrier");
        sqlx::raw_sql(&format!(
            "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN PERFORM pg_advisory_xact_lock(4209, {holder}); RETURN NEW; END $$; \
             CREATE TRIGGER {name} {timing} ON {table} FOR EACH ROW \
             WHEN ({when}) EXECUTE FUNCTION {name}()"
        ))
        .execute(store.pool())
        .await
        .expect("install test barrier");
        Self {
            tx,
            holder,
            name,
            table,
        }
    }

    async fn release_and_drop(self, store: &PostgresStore) {
        self.tx.commit().await.expect("release barrier");
        sqlx::raw_sql(&format!(
            "DROP TRIGGER {n} ON {t}; DROP FUNCTION {n}()",
            n = self.name,
            t = self.table
        ))
        .execute(store.pool())
        .await
        .expect("remove test barrier");
    }
}

/// The #4010 containment-writer shape: lock the pair ascending by
/// `id COLLATE "C"`, then rewrite both rows, one transaction.
async fn ascending_writer(store: Arc<PostgresStore>, ids: Vec<String>) -> Result<(), String> {
    let mut tx = store.pool().begin().await.map_err(|e| e.to_string())?;
    sqlx::query("SELECT id FROM memories WHERE id = ANY($1) ORDER BY id COLLATE \"C\" FOR UPDATE")
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query("UPDATE memories SET priority = priority WHERE id = ANY($1)")
        .bind(&ids)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())
}

/// The cells install and drop triggers on shared tables; `CREATE`/`DROP
/// TRIGGER` conflict with the row locks another cell's parked transaction
/// holds, so the cells run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn pair(ns: &str) -> (String, String) {
    (format!("a-{ns}"), format!("z-{ns}"))
}

/// #4209 — bulk re-own vs an ascending writer. `a`'s live tuple is placed
/// after `z`'s so heap order is the reverse of id order; a BEFORE UPDATE barrier
/// parks re-own on its first row (a row-level BEFORE trigger fires after that
/// row is locked and before the next one is; an AFTER trigger would only fire
/// at statement end, with every row already locked). Pre-fix re-own then holds only `z`, the writer takes
/// `a` and waits on `z`, and re-own's next row closes the cycle (40P01).
#[tokio::test]
async fn pg_bulk_reown_locks_in_id_order_4209() {
    // Serialised BEFORE connecting: concurrent first connects race the schema
    // bootstrap DDL ("failed to re-find shared lock object", XX000).
    let _serial = SERIAL.lock().await;
    let Some(store) = connect().await else {
        return;
    };
    let ns = format!("lock4209-{}", uuid::Uuid::new_v4().simple());
    let (a, z) = pair(&ns);
    let ctx = CallerContext::for_agent("ai:old-owner");
    // Re-seed BOTH rows until `z` precedes `a` in heap (ctid) order AND in
    // `(namespace, priority DESC, updated_at DESC)` index order: the reverse of
    // id order, whichever access path the planner picks for the UPDATE. Fresh
    // inserts land wherever the free-space map says (a no-op UPDATE of `a`
    // cannot move it once the table has free space, #4412), so the arrangement
    // is retried; verified, not assumed, and bounded.
    let mut arranged = false;
    for _ in 0..200 {
        for id in [&z, &a] {
            store
                .store(&ctx, &mem(&ns, id.clone(), "ai:old-owner"))
                .await
                .expect("seed row");
        }
        // `a` becomes the OLDER row (the index order); this rewrite also moves
        // its live tuple, so the heap order is read AFTER it.
        sqlx::query(
            "UPDATE memories SET updated_at = updated_at - interval '1 hour' WHERE id = $1",
        )
        .bind(&a)
        .execute(store.pool())
        .await
        .expect("age a");
        let z_first: bool = sqlx::query_scalar(
            "SELECT (SELECT ctid FROM memories WHERE id = $1) \
                  < (SELECT ctid FROM memories WHERE id = $2)",
        )
        .bind(&z)
        .bind(&a)
        .fetch_one(store.pool())
        .await
        .expect("compare heap order");
        if z_first {
            arranged = true;
            break;
        }
        sqlx::query("DELETE FROM memories WHERE namespace = $1")
            .bind(&ns)
            .execute(store.pool())
            .await
            .expect("re-seed");
    }
    assert!(
        arranged,
        "fixture: could not place z before a in the heap after 200 re-seeds"
    );
    let barrier = Barrier::install(
        &store,
        "memories",
        "BEFORE UPDATE",
        &format!("NEW.namespace = '{ns}'"),
    )
    .await;

    let s = Arc::clone(&store);
    let ns2 = ns.clone();
    let reown = tokio::spawn(async move {
        s.reown(
            &CallerContext::for_agent("ai:operator"),
            Some(&ns2),
            "ai:new-owner",
            ai_memory::storage::ReownSelect::Owned,
            false,
        )
        .await
    });
    let reowner = blocked_backend(&store, barrier.holder).await;
    let writer = tokio::spawn(ascending_writer(
        Arc::clone(&store),
        vec![a.clone(), z.clone()],
    ));
    let waiting = blocked_backend(&store, reowner).await;
    assert_ne!(reowner, waiting, "independent transactions");
    barrier.release_and_drop(&store).await;

    let (reown, writer) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(reown, writer)
    })
    .await
    .expect("both transactions finish");
    let reown = reown.expect("join reown");
    let writer = writer.expect("join writer");
    assert!(
        reown.is_ok() && writer.is_ok(),
        "no lock cycle: reown={reown:?}, writer={writer:?}"
    );
    let report = reown.expect("reown ok");
    assert_eq!(report.rewritten, 2, "exactly the locked rows are rewritten");
    assert_eq!(report.matched, 2, "the report names the locked set");
    for id in [&a, &z] {
        let owner: Option<String> =
            sqlx::query_scalar("SELECT metadata->>'agent_id' FROM memories WHERE id = $1")
                .bind(id)
                .fetch_one(store.pool())
                .await
                .expect("read owner");
        assert_eq!(owner.as_deref(), Some("ai:new-owner"));
    }
}

/// #4210 — link `z -> a` vs an ascending writer. The barrier parks the link
/// just before its `memory_links` INSERT. Pre-fix the link holds only the
/// SOURCE `z` (owner gate `FOR UPDATE`), the writer takes `a` and waits on
/// `z`, and the INSERT's FK key-share on the TARGET `a` closes the cycle.
#[tokio::test]
async fn pg_link_locks_endpoints_in_id_order_4210() {
    // Serialised BEFORE connecting: concurrent first connects race the schema
    // bootstrap DDL ("failed to re-find shared lock object", XX000).
    let _serial = SERIAL.lock().await;
    let Some(store) = connect().await else {
        return;
    };
    let ns = format!("lock4210-{}", uuid::Uuid::new_v4().simple());
    let (a, z) = pair(&ns);
    let ctx = CallerContext::for_agent("ai:tester");
    for id in [&a, &z] {
        store
            .store(&ctx, &mem(&ns, id.clone(), "ai:tester"))
            .await
            .expect("seed row");
    }
    let barrier = Barrier::install(
        &store,
        "memory_links",
        "BEFORE INSERT",
        &format!("NEW.source_id = '{z}'"),
    )
    .await;

    let s = Arc::clone(&store);
    let link = MemoryLink {
        source_id: z.clone(),
        target_id: a.clone(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: None,
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    };
    let link_task =
        tokio::spawn(async move { s.link(&CallerContext::for_agent("ai:tester"), &link).await });
    let link_pid = blocked_backend(&store, barrier.holder).await;
    let writer = tokio::spawn(ascending_writer(
        Arc::clone(&store),
        vec![a.clone(), z.clone()],
    ));
    let waiting = blocked_backend(&store, link_pid).await;
    assert_ne!(link_pid, waiting, "independent transactions");
    barrier.release_and_drop(&store).await;

    let (link_out, writer) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(link_task, writer)
    })
    .await
    .expect("both transactions finish");
    let link_out = link_out.expect("join link");
    let writer = writer.expect("join writer");
    assert!(
        link_out.is_ok() && writer.is_ok(),
        "no lock cycle: link={link_out:?}, writer={writer:?}"
    );
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM memory_links WHERE source_id = $1 AND target_id = $2",
    )
    .bind(&z)
    .bind(&a)
    .fetch_one(store.pool())
    .await
    .expect("count link");
    assert_eq!(n, 1, "the link committed");
}

/// #4210 sibling — a federation link replay (`apply_remote_link`) parked
/// before its INSERT already holds both endpoints' key-share locks in id
/// order, so an ascending writer waits on it and both commit.
#[tokio::test]
async fn pg_link_replay_locks_endpoints_in_id_order_4210() {
    // Serialised BEFORE connecting: concurrent first connects race the schema
    // bootstrap DDL ("failed to re-find shared lock object", XX000).
    let _serial = SERIAL.lock().await;
    let Some(store) = connect().await else {
        return;
    };
    let ns = format!("lock4210r-{}", uuid::Uuid::new_v4().simple());
    let (a, z) = pair(&ns);
    let ctx = CallerContext::for_agent("ai:tester");
    for id in [&a, &z] {
        store
            .store(&ctx, &mem(&ns, id.clone(), "ai:tester"))
            .await
            .expect("seed row");
    }
    let barrier = Barrier::install(
        &store,
        "memory_links",
        "BEFORE INSERT",
        &format!("NEW.source_id = '{z}'"),
    )
    .await;
    let s = Arc::clone(&store);
    let link = MemoryLink {
        source_id: z.clone(),
        target_id: a.clone(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: Some("ai:peer".to_string()),
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    };
    let replay_task = tokio::spawn(async move {
        s.apply_remote_link(&CallerContext::for_agent("ai:peer"), &link, "unsigned")
            .await
    });
    let replay_pid = blocked_backend(&store, barrier.holder).await;
    let writer = tokio::spawn(ascending_writer(
        Arc::clone(&store),
        vec![a.clone(), z.clone()],
    ));
    let waiting = blocked_backend(&store, replay_pid).await;
    assert_ne!(replay_pid, waiting, "the writer waits on the parked replay");
    barrier.release_and_drop(&store).await;
    let (replay_out, writer) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(replay_task, writer)
    })
    .await
    .expect("both transactions finish");
    let replay_out = replay_out.expect("join replay");
    let writer = writer.expect("join writer");
    assert!(
        replay_out.is_ok() && writer.is_ok(),
        "no lock cycle: replay={replay_out:?}, writer={writer:?}"
    );
}

/// #4459 — consolidate locks its sources in ascending BYTEWISE id order, not the
/// database default collation. `B-…` sorts before `a-…` bytewise but after it in
/// a locale collation (en_US), so a default-collation `ORDER BY id FOR UPDATE`
/// takes `a` first. The ascending (`COLLATE "C"`) writer holds `B` and waits for
/// nothing yet; consolidate (default order) takes `a` and parks on `B`; the
/// writer's next lock, `a`, closes the cycle (40P01 on the writer, which checks
/// first). Bytewise: consolidate parks on `B` holding nothing, the writer takes
/// `a`, commits, and both finish. A bytewise-default database cannot invert, so
/// the cell has nothing to prove there and returns.
#[tokio::test]
async fn pg_consolidate_locks_bytewise_not_default_collation_4459() {
    let _serial = SERIAL.lock().await;
    let Some(store) = connect().await else {
        return;
    };
    let ns = format!("lock4459-{}", uuid::Uuid::new_v4().simple());
    let (lo, hi) = (format!("B-{ns}"), format!("a-{ns}"));
    let locale_inverts: bool = sqlx::query_scalar("SELECT $2::text < $1::text")
        .bind(&lo)
        .bind(&hi)
        .fetch_one(store.pool())
        .await
        .expect("compare default collation");
    if !locale_inverts {
        eprintln!(
            "database default collation is bytewise: no inversion possible, nothing to prove"
        );
        return;
    }
    let ctx = CallerContext::for_agent("ai:tester");
    for id in [&lo, &hi] {
        store
            .store(&ctx, &mem(&ns, id.clone(), "ai:tester"))
            .await
            .expect("seed row");
    }
    // Ascending writer, first half: `B` (the bytewise-lower id).
    let mut writer = store.pool().begin().await.expect("writer tx");
    let writer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await
        .expect("writer pid");
    // The writer asks for its second row while consolidate is already waiting
    // on `B`; a short check delay on the writer makes the writer, not the
    // consolidate retry-free path, surface a cycle as 40P01.
    sqlx::query("SET LOCAL deadlock_timeout = '100ms'")
        .execute(&mut *writer)
        .await
        .expect("writer deadlock check delay");
    sqlx::query("SELECT id FROM memories WHERE id = $1 FOR UPDATE")
        .bind(&lo)
        .fetch_one(&mut *writer)
        .await
        .expect("writer locks the bytewise-lower row");

    let s = Arc::clone(&store);
    let (ids, ns2) = (vec![hi.clone(), lo.clone()], ns.clone());
    let consolidate = tokio::spawn(async move {
        s.consolidate(
            &CallerContext::for_agent("ai:tester"),
            &ids,
            &format!("consolidated-{ns2}"),
            "summary",
            &ns2,
            &Tier::Mid,
            "test",
            "ai:tester",
        )
        .await
        .map_err(|e| e.to_string())
    });
    let parked = blocked_backend(&store, writer_pid).await;
    assert_ne!(parked, writer_pid, "independent transactions");
    // Ascending writer, second half: the bytewise-higher row, then commit.
    let writer_result: Result<(), String> = async {
        sqlx::query("SELECT id FROM memories WHERE id = $1 FOR UPDATE")
            .bind(&hi)
            .fetch_optional(&mut *writer)
            .await
            .map_err(|e| e.to_string())?;
        sqlx::query("UPDATE memories SET priority = priority WHERE id = ANY($1)")
            .bind([lo.clone(), hi.clone()].as_slice())
            .execute(&mut *writer)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    .await;
    let writer_result = match writer_result {
        Ok(()) => writer.commit().await.map_err(|e| e.to_string()),
        Err(e) => {
            drop(writer);
            Err(e)
        }
    };
    let consolidated = tokio::time::timeout(Duration::from_secs(60), consolidate)
        .await
        .expect("consolidate finishes")
        .expect("join consolidate");
    assert!(
        writer_result.is_ok() && consolidated.is_ok(),
        "no lock cycle: writer={writer_result:?}, consolidate={consolidated:?}"
    );
    sqlx::query("DELETE FROM memories WHERE namespace = $1")
        .bind(&ns)
        .execute(store.pool())
        .await
        .expect("cleanup rows");
}
