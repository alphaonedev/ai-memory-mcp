// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, KgBackend, MemoryStore, PoolConfig, StoreError};
use std::sync::Arc;
use std::time::Duration;

async fn fixture() -> (Arc<PostgresStore>, CallerContext, MemoryLink) {
    let _ = ai_memory::identity::test_key_dir::install();
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("isolated TLS fixture required");
    let store = Arc::new(PostgresStore::connect(&url).await.expect("connect"));
    assert_eq!(store.kg_backend(), KgBackend::Age, "healthy AGE required");
    let ctx = CallerContext::for_agent("b4-regression");
    let ns = uuid::Uuid::new_v4().to_string();
    let mut ids = Vec::new();
    for title in ["a", "b"] {
        let m = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: ns.clone(),
            tier: Tier::Long,
            title: title.into(),
            content: "regression".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            ..Memory::default()
        };
        ids.push(store.store(&ctx, &m).await.expect("seed memory"));
    }
    let link = MemoryLink {
        source_id: ids[0].clone(),
        target_id: ids[1].clone(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        valid_from: None,
        valid_until: None,
        observed_by: None,
        signature: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    };
    (store, ctx, link)
}

#[tokio::test]
async fn pool_one_is_explicitly_rejected_4041() {
    let _ = ai_memory::identity::test_key_dir::install();
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("TLS fixture");
    let result = PostgresStore::connect_with_dim_and_timeout(
        &url,
        384,
        10,
        PoolConfig {
            max_connections: 1,
            min_connections: 1,
            acquire_timeout_secs: 1,
        },
    )
    .await;
    assert!(
        matches!(result, Err(StoreError::InvalidInput { ref detail }) if detail.contains("max_connections") && detail.contains('2')),
        "#4041: max=1 must fail explicitly before pool acquisition; got {:?}",
        result.err()
    );
}

#[tokio::test]
async fn duplicate_remote_validity_is_noop_4038() {
    duplicate_validity(true).await;
}
#[tokio::test]
async fn duplicate_local_validity_is_noop_4038() {
    duplicate_validity(false).await;
}
async fn duplicate_validity(remote: bool) {
    let (store, ctx, mut link) = fixture().await;
    if remote {
        store
            .apply_remote_link(&ctx, &link, "unsigned")
            .await
            .expect("first");
    } else {
        store.link(&ctx, &link).await.expect("first");
    }
    assert!(
        store
            .kg_query(&link.source_id, 1)
            .await
            .expect("AGE before")
            .iter()
            .any(|r| r.target_id == link.target_id)
    );
    link.valid_until = Some((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());
    if remote {
        store
            .apply_remote_link(&ctx, &link, "unsigned")
            .await
            .expect("replay");
    } else {
        store.link(&ctx, &link).await.expect("replay");
    }
    let canonical: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT valid_until FROM memory_links WHERE source_id=$1 AND target_id=$2",
    )
    .bind(&link.source_id)
    .bind(&link.target_id)
    .fetch_one(store.pool())
    .await
    .expect("canonical");
    assert!(canonical.is_none());
    assert!(
        store
            .kg_query(&link.source_id, 1)
            .await
            .expect("AGE after")
            .iter()
            .any(|r| r.target_id == link.target_id),
        "#4038: ignored duplicate invalidated the AGE edge"
    );
}

async fn wait_blocked(store: &PostgresStore, owner_pid: i32) {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))")
                .bind(owner_pid).fetch_one(store.pool()).await.expect("blocking probe");
            if blocked { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("operation reached lock barrier");
}

#[tokio::test]
async fn nonforced_dim_conversion_fences_writers_4040() {
    let (store, _, link) = fixture().await;
    // The dimension-migration suite may have left this disposable database
    // at 768. Establish this test's 384-dimensional baseline explicitly.
    store
        .migrate_embedding_dim(384, true)
        .await
        .expect("establish source dimension");
    sqlx::raw_sql(
        "UPDATE memories SET embedding=NULL; UPDATE archived_memories SET embedding=NULL",
    )
    .execute(store.pool())
    .await
    .expect("empty vectors");
    let mut writer = store.pool().begin().await.expect("writer");
    sqlx::query("LOCK TABLE memories IN SHARE MODE")
        .execute(&mut *writer)
        .await
        .expect("hold read-compatible writer fence");
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await
        .expect("pid");
    let other = Arc::clone(&store);
    let migration = tokio::spawn(async move { other.migrate_embedding_dim(768, false).await });
    wait_blocked(&store, pid).await;
    sqlx::query("UPDATE memories SET embedding = $1::vector WHERE id=$2")
        .bind(format!("[{}]", ["0.1"; 384].join(",")))
        .bind(&link.source_id)
        .execute(&mut *writer)
        .await
        .expect("concurrent vector");
    writer.commit().await.expect("writer commit");
    let result = migration.await.expect("join");
    assert!(
        matches!(result, Err(StoreError::InvalidInput { .. })),
        "#4040: nonforced conversion erased a concurrent vector: {result:?}"
    );
    assert_eq!(
        store.current_embedding_dim().await.expect("dimension"),
        Some(384)
    );
    let exists: bool = sqlx::query_scalar("SELECT embedding IS NOT NULL FROM memories WHERE id=$1")
        .bind(&link.source_id)
        .fetch_one(store.pool())
        .await
        .expect("vector survived");
    assert!(exists);
}

async fn barrier(
    store: &PostgresStore,
    table: &str,
    key: i64,
) -> (sqlx::pool::PoolConnection<sqlx::Postgres>, i32) {
    let mut conn = store.pool().acquire().await.expect("barrier connection");
    let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *conn)
        .await
        .expect("pid");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(key)
        .execute(&mut *conn)
        .await
        .expect("hold barrier");
    sqlx::raw_sql(&format!("CREATE OR REPLACE FUNCTION b4_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({key}); RETURN NEW; END $$; CREATE TRIGGER b4_barrier BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION b4_barrier()"))
        .execute(store.pool()).await.expect("install barrier");
    (conn, pid)
}
async fn release_barrier(conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>, key: i64) {
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(key)
        .execute(&mut **conn)
        .await
        .expect("release barrier");
}

#[tokio::test]
async fn archive_gc_keeps_late_arrivals_4037() {
    let (store, ctx, link) = fixture().await;
    sqlx::query("UPDATE memories SET expires_at=now()-interval '1 hour' WHERE id=$1")
        .bind(&link.source_id)
        .execute(store.pool())
        .await
        .expect("expire A");
    let key = 4037_i64;
    let (mut guard, pid) = barrier(&store, "archived_memories", key).await;
    let other = Arc::clone(&store);
    let gc = tokio::spawn(async move { other.run_gc(true).await });
    wait_blocked(&store, pid).await;
    let late = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Short,
        title: "late expired inbound".into(),
        content: "must survive".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        expires_at: Some((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339()),
        ..Memory::default()
    };
    let inserted = store.apply_remote_memory(&ctx, &late).await;
    release_barrier(&mut guard, key).await;
    let result = gc.await.expect("join");
    sqlx::query("DROP TRIGGER b4_barrier ON archived_memories")
        .execute(store.pool())
        .await
        .expect("remove barrier");
    inserted.expect("late remote commit");
    result.expect("gc");
    let survives: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM memories WHERE id=$1 UNION ALL SELECT 1 FROM archived_memories WHERE id=$1)")
        .bind(&late.id).fetch_one(store.pool()).await.expect("survival");
    assert!(
        survives,
        "#4037: GC deleted a late arrival without an archive copy"
    );
}

#[tokio::test]
async fn drain_and_unlink_serialize_4039() {
    use ai_memory::config::{AgeProjectionMode, set_age_projection_mode};
    let (store, ctx, link) = fixture().await;
    // Prime the AGE relation label, then remove its edge.
    store.link(&ctx, &link).await.expect("prime AGE label");
    store
        .delete_link(&ctx, &link.source_id, &link.target_id)
        .await
        .expect("unlink prime");
    set_age_projection_mode(AgeProjectionMode::Deferred);
    store.link(&ctx, &link).await.expect("enqueue");
    set_age_projection_mode(AgeProjectionMode::Sync);
    let key = 4039_i64;
    let mut guard = store.pool().acquire().await.expect("barrier connection");
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *guard)
        .await
        .expect("pid");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(key)
        .execute(&mut *guard)
        .await
        .expect("hold barrier");
    // A simple updatable view pauses the SELECT after its statement snapshot
    // is established. AGE's internal inserts bypass ordinary row triggers.
    sqlx::raw_sql("CREATE OR REPLACE FUNCTION b4_link_read_barrier() RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN IF current_query() LIKE 'SELECT valid_from, valid_until FROM memory_links%' THEN PERFORM pg_advisory_xact_lock(4039); END IF; RETURN true; END $$; ALTER TABLE memory_links RENAME TO b4_memory_links; CREATE VIEW memory_links AS SELECT * FROM b4_memory_links WHERE b4_link_read_barrier()")
        .execute(store.pool()).await.expect("install read barrier");
    let other = Arc::clone(&store);
    let drain = tokio::spawn(async move { other.drain_kg_projection_outbox(10000).await });
    wait_blocked(&store, pid).await;
    let other = Arc::clone(&store);
    let source = link.source_id.clone();
    let target = link.target_id.clone();
    let unlink = tokio::spawn(async move { other.delete_link(&ctx, &source, &target).await });
    // Either unlink completes on the broken implementation, or its SQL
    // delete waits for the drainer's relational lock on the fixed one.
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if unlink.is_finished() { break; }
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE query LIKE 'DELETE FROM memory_links%' AND cardinality(pg_blocking_pids(pid)) > 0)")
                .fetch_one(store.pool()).await.expect("unlink lock probe");
            if blocked { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("unlink completed or blocked");
    release_barrier(&mut guard, key).await;
    let drained = drain.await.expect("drain join");
    let unlinked = unlink.await.expect("unlink join");
    sqlx::raw_sql("DROP VIEW memory_links; ALTER TABLE b4_memory_links RENAME TO memory_links; DROP FUNCTION b4_link_read_barrier()").execute(store.pool()).await.expect("remove barrier");
    drained.expect("drain");
    unlinked.expect("unlink");
    assert!(
        store
            .kg_query(&link.source_id, 1)
            .await
            .expect("AGE after")
            .iter()
            .all(|r| r.target_id != link.target_id),
        "#4039: drainer recreated the deleted edge"
    );
}

#[tokio::test]
async fn reconciliation_clears_stale_age_validity_4038() {
    let (store, ctx, mut link) = fixture().await;
    link.valid_until = Some((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());
    store
        .apply_remote_link(&ctx, &link, "unsigned")
        .await
        .expect("expired edge");
    // Simulate canonical repair of drift left by a formerly ignored replay.
    sqlx::query("UPDATE memory_links SET valid_from=NULL, valid_until=NULL WHERE source_id=$1 AND target_id=$2")
        .bind(&link.source_id).bind(&link.target_id).execute(store.pool()).await.expect("canonical repair");
    sqlx::query("INSERT INTO kg_projection_outbox (source_id,target_id,relation) VALUES ($1,$2,'related_to')")
        .bind(&link.source_id).bind(&link.target_id).execute(store.pool()).await.expect("enqueue repair");
    store
        .drain_kg_projection_outbox(10000)
        .await
        .expect("reconcile");
    assert!(
        store
            .kg_query(&link.source_id, 1)
            .await
            .expect("AGE after repair")
            .iter()
            .any(|r| r.target_id == link.target_id),
        "#4038: canonical NULL must remove a stale AGE validity property"
    );
}

#[tokio::test]
async fn node_unprojection_fences_recreation_4039() {
    let (store, ctx, link) = fixture().await;
    store.link(&ctx, &link).await.expect("prime graph nodes");
    sqlx::query("DELETE FROM memories WHERE id=$1")
        .bind(&link.source_id)
        .execute(store.pool())
        .await
        .expect("simulate deferred node detach");
    sqlx::query("INSERT INTO kg_projection_outbox (source_id,target_id,relation) VALUES ($1,$1,'__ai_memory_unproject__')")
        .bind(&link.source_id).execute(store.pool()).await.expect("enqueue detach marker");
    let mut graph_fence = store.pool().begin().await.expect("graph fence");
    sqlx::query("LOCK TABLE memory_graph.\"Memory\" IN SHARE MODE")
        .execute(&mut *graph_fence)
        .await
        .expect("hold detach");
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *graph_fence)
        .await
        .expect("pid");
    let other = Arc::clone(&store);
    let drain = tokio::spawn(async move { other.drain_kg_projection_outbox(10000).await });
    wait_blocked(&store, pid).await;
    let recreated = Memory {
        id: link.source_id.clone(),
        namespace: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        title: "re-created node".into(),
        content: "new generation".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        ..Memory::default()
    };
    let other = Arc::clone(&store);
    let writer = tokio::spawn(async move { other.store(&ctx, &recreated).await });
    let write_escaped = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if writer.is_finished() { break true; }
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE query LIKE 'INSERT INTO memories%' AND cardinality(pg_blocking_pids(pid))>0)")
                .fetch_one(store.pool()).await.expect("writer lock probe");
            if blocked { break false; }
            tokio::task::yield_now().await;
        }
    }).await.expect("writer completed or fenced");
    graph_fence.commit().await.expect("release detach");
    drain.await.expect("drain join").expect("drain");
    writer.await.expect("writer join").expect("recreate");
    assert!(
        !write_escaped,
        "#4039: re-creation committed after absence check and before node detach"
    );
}
