// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal-postgres")]

use std::sync::Arc;

use serde_json::{Value, json};

use ai_memory::store::{CallerContext, MemoryStore};

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .or_else(|| std::env::var("AI_MEMORY_TEST_PG_URL").ok())
        .filter(|u| !u.trim().is_empty())
}

fn admin_ctx() -> CallerContext {
    CallerContext::for_admin(ai_memory::identity::sentinels::DAEMON_PRINCIPAL)
}

fn memory_3400(
    id: &str,
    namespace: &str,
    tags: &[&str],
    metadata: Value,
) -> ai_memory::models::Memory {
    let timestamp = "2026-09-02T00:00:00Z".to_string();
    ai_memory::models::Memory {
        id: id.to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: namespace.to_string(),
        title: format!("title-{id}"),
        content: format!("content-{id}"),
        tags: tags.iter().map(ToString::to_string).collect(),
        priority: 7,
        confidence: 1.0,
        source: "api".to_string(),
        created_at: timestamp.clone(),
        updated_at: timestamp,
        metadata,
        ..Default::default()
    }
}

fn seed_sqlite_archive(db_path: &std::path::Path) {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    for (id, ns, tags) in [
        ("pgwire-a-1", "stats-a", &["alpha", "beta"] as &[&str]),
        ("pgwire-a-2", "stats-a", &[] as &[&str]),
        ("pgwire-b-1", "stats-b", &[] as &[&str]),
    ] {
        let mem = memory_3400(
            id,
            ns,
            tags,
            json!({"agent_id": "ops:admin", "scope": "collective"}),
        );
        ai_memory::db::insert(&conn, &mem).expect("insert seed memory");
        ai_memory::db::archive_memory(&conn, id, Some("issue-3400")).expect("archive seed memory");
    }
}

async fn seed_pg_archive(store: &Arc<dyn MemoryStore>) {
    let ctx = admin_ctx();
    let mut ids = Vec::new();
    for (id, ns, tags) in [
        ("pgwire-a-1", "stats-a", &["alpha", "beta"] as &[&str]),
        ("pgwire-a-2", "stats-a", &[] as &[&str]),
        ("pgwire-b-1", "stats-b", &[] as &[&str]),
    ] {
        let mem = memory_3400(
            id,
            ns,
            tags,
            json!({"agent_id": "ops:admin", "scope": "collective"}),
        );
        store.store(&ctx, &mem).await.expect("pg store seed memory");
        ids.push(id.to_string());
    }
    let moved = store
        .archive_by_ids(&ctx, &ids, Some("issue-3400"))
        .await
        .expect("pg archive seed memories");
    assert_eq!(moved, ids.len(), "every seeded memory must archive");
}

fn sqlite_envelope(db_path: &std::path::Path) -> (Value, Vec<Value>) {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    let stats = ai_memory::db::archive_stats(&conn).expect("sqlite archive_stats");
    let rows = ai_memory::db::list_archived(&conn, None, 50, 0).expect("sqlite list_archived");
    (stats, rows)
}

#[tokio::test]
async fn pg_archive_stats_matches_sqlite_envelope_3400() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("wire-3400.db");
    seed_sqlite_archive(&db_path);
    let (sqlite_stats, _) = sqlite_envelope(&db_path);
    assert_eq!(
        sqlite_stats,
        json!({
            "archived_total": 3,
            "by_namespace": [
                {"namespace": "stats-a", "count": 2},
                {"namespace": "stats-b", "count": 1},
            ],
        })
    );

    let Some(url) = postgres_url() else {
        eprintln!(
            "skip pg_archive_stats_matches_sqlite_envelope_3400: AI_MEMORY_TEST_POSTGRES_URL unset"
        );
        return;
    };
    let pg: Arc<dyn MemoryStore> =
        match ai_memory::store::postgres::PostgresStore::connect(&url).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                eprintln!("skip: PostgresStore::connect failed: {e}");
                return;
            }
        };
    seed_pg_archive(&pg).await;
    let stats = pg.archive_stats().await.expect("pg archive_stats");
    assert_eq!(
        stats, sqlite_stats,
        "pg stats envelope must equal sqlite, got: {stats}"
    );
    assert!(
        stats.get("total_archived").is_none(),
        "alias key must not exist: {stats}"
    );
    assert!(
        stats.get("by_reason").is_none(),
        "backend-only map must not exist: {stats}"
    );
}

#[tokio::test]
async fn pg_archived_tags_are_arrays_3400() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("wire-3400-tags.db");
    seed_sqlite_archive(&db_path);
    let (_, sqlite_rows) = sqlite_envelope(&db_path);
    let sqlite_tags = sqlite_rows
        .iter()
        .find(|r| r["id"] == "pgwire-a-1")
        .expect("seeded row")["tags"]
        .clone();
    assert_eq!(sqlite_tags, json!(["alpha", "beta"]));

    let Some(url) = postgres_url() else {
        eprintln!("skip pg_archived_tags_are_arrays_3400: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let pg: Arc<dyn MemoryStore> =
        match ai_memory::store::postgres::PostgresStore::connect(&url).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                eprintln!("skip: PostgresStore::connect failed: {e}");
                return;
            }
        };
    seed_pg_archive(&pg).await;
    let rows = pg
        .list_archived(None, 50, 0)
        .await
        .expect("pg list_archived");
    let row = rows
        .iter()
        .find(|r| r["id"] == "pgwire-a-1")
        .expect("seeded pg row");
    assert!(
        row["tags"].is_array(),
        "tags must be an array, got: {}",
        row["tags"]
    );
    assert_eq!(row["tags"], sqlite_tags);
}

#[tokio::test]
async fn pg_namespace_standard_binding_matches_sqlite_3400() {
    let namespace = "policy-3400";
    let id = "standard-3400";
    let metadata = json!({
        "agent_id": "alice",
        "scope": "private",
        "governance": {
            "write": "owner",
            "promote": "approve",
            "delete": "owner",
            "approver": "human",
            "inherit": false,
            "custom_gate": "preserved",
        },
    });
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("wire-3400-std.db");
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let mem = memory_3400(id, namespace, &["standard"], metadata.clone());
    ai_memory::db::insert(&conn, &mem).expect("insert standard memory");
    ai_memory::db::set_namespace_standard(&conn, namespace, id, None).expect("bind standard");
    let sqlite_binding =
        ai_memory::db::get_namespace_standard(&conn, namespace).expect("sqlite get standard");
    assert_eq!(sqlite_binding.as_deref(), Some(id));
    drop(conn);

    let Some(url) = postgres_url() else {
        eprintln!(
            "skip pg_namespace_standard_binding_matches_sqlite_3400: AI_MEMORY_TEST_POSTGRES_URL unset"
        );
        return;
    };
    let pg: Arc<dyn MemoryStore> =
        match ai_memory::store::postgres::PostgresStore::connect(&url).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                eprintln!("skip: PostgresStore::connect failed: {e}");
                return;
            }
        };
    let ctx = admin_ctx();
    let mem = memory_3400(id, namespace, &["standard"], metadata);
    pg.store(&ctx, &mem)
        .await
        .expect("pg store standard memory");
    pg.set_namespace_standard(&ctx, namespace, id, None)
        .await
        .expect("pg bind standard");
    let binding = pg
        .get_namespace_standard(&ctx, namespace)
        .await
        .expect("pg get standard");
    assert_eq!(binding.map(|(sid, _)| sid).as_deref(), Some(id));
    let stored = pg.get(&ctx, id).await.expect("pg get standard memory");
    assert_eq!(
        stored.metadata["governance"]["custom_gate"],
        json!("preserved"),
        "governance blob must round-trip so the non-inherit form can render it"
    );
}

#[test]
fn postgres_url_helper_is_reachable_3400() {
    let _ = postgres_url();
}
