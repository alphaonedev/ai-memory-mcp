// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Archive visibility, paging and restore regression coverage for #3382.

use ai_memory::{
    db,
    models::{Memory, Tier},
};
use serde_json::{Value, json};

fn memory(namespace: &str, metadata: Value) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: namespace.into(),
        title: uuid::Uuid::new_v4().to_string(),
        content: "archive subject".into(),
        tier: Tier::Long,
        created_at: now.clone(),
        updated_at: now,
        metadata,
        ..Memory::default()
    }
}

fn seed(conn: &rusqlite::Connection, namespace: &str, metadata: Value) -> String {
    let id = db::insert(conn, &memory(namespace, metadata)).expect("seed");
    assert!(db::archive_memory(conn, &id, Some("3382")).expect("archive"));
    id
}

#[test]
fn visibility_and_owner_rules_both_apply_before_pagination() {
    let conn = db::open(std::path::Path::new(":memory:")).expect("db");
    let own = seed(
        &conn,
        "notes",
        json!({"agent_id":"ai:bob", "scope":"private"}),
    );
    let unowned = seed(&conn, "notes", json!({"scope":"collective"}));
    seed(&conn, "notes", json!({"scope":"private"}));
    seed(
        &conn,
        "notes",
        json!({"agent_id":"ai:alice", "scope":"collective"}),
    );
    seed(
        &conn,
        "elsewhere/team",
        json!({"agent_id":"ai:bob", "scope":"team"}),
    );
    seed(
        &conn,
        "_agents",
        json!({"agent_id":"ai:bob", "scope":"collective"}),
    );
    // Newest candidates are all hidden; pagination must still find the two
    // readable, owned (or legacy-unowned) rows after them.
    let all = db::list_archived_scoped(&conn, None, Some("ai:bob"), 50, 0).expect("list");
    assert_eq!(all.len(), 2);
    assert!(all.iter().any(|v| v["id"] == own));
    assert!(all.iter().any(|v| v["id"] == unowned));
    let page = db::list_archived_scoped(&conn, None, Some("ai:bob"), 1, 1).expect("page");
    assert_eq!(page, all[1..2]);
    assert!(
        db::list_archived_scoped(&conn, None, Some("ai:bob"), 0, 0)
            .expect("zero")
            .is_empty()
    );
    assert!(
        db::list_archived_scoped(&conn, None, Some("ai:bob"), 1, 2)
            .expect("end")
            .is_empty()
    );
    let stats = db::archive_stats_scoped(&conn, Some("ai:bob")).expect("stats");
    assert_eq!(stats["archived_total"], 2);
    assert_eq!(
        stats["by_namespace"],
        json!([{"namespace":"notes", "count":2}])
    );
    // Existing explicitly unscoped admin storage operations retain all rows.
    assert_eq!(
        db::list_archived(&conn, None, 50, 0).expect("admin").len(),
        6
    );
    assert_eq!(
        db::archive_stats(&conn).expect("admin stats")["archived_total"],
        6
    );
}

#[test]
fn explicit_inbox_namespace_and_legacy_alias_still_work() {
    let conn = db::open(std::path::Path::new(":memory:")).expect("db");
    let id = seed(
        &conn,
        "_inbox/ai:bob",
        json!({"agent_id":"ai:alice", "target_agent_id":"ai:bob"}),
    );
    // Preserve a legacy namespace spelling to exercise the migration alias.
    conn.execute(
        "UPDATE archived_memories SET namespace = '_messages/ai:bob' WHERE id = ?1",
        [&id],
    )
    .expect("legacy spelling");
    assert!(
        db::list_archived_scoped(&conn, None, Some("ai:bob"), 50, 0)
            .expect("ambient")
            .is_empty()
    );
    assert!(
        db::list_archived_scoped(&conn, None, None, 50, 0)
            .expect("singleton ambient")
            .is_empty()
    );
    for caller in [Some("ai:bob"), None] {
        let rows = db::list_archived_scoped(&conn, Some("_inbox/ai:bob"), caller, 50, 0)
            .expect("explicit inbox");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], id);
    }
    assert!(
        db::list_archived_scoped(&conn, Some("_inbox/ai:bob"), Some("ai:mallory"), 50, 0)
            .expect("other")
            .is_empty()
    );
    assert_eq!(
        db::archive_stats_scoped(&conn, Some("ai:bob")).expect("stats")["archived_total"],
        0
    );
    assert!(db::restore_archived_for_caller(&conn, &id, "ai:bob").expect("recipient restore"));
}

#[test]
fn restore_denial_does_not_consume_archive_or_expose_existence() {
    let conn = db::open(std::path::Path::new(":memory:")).expect("db");
    let id = seed(
        &conn,
        "notes",
        json!({"agent_id":"ai:alice", "scope":"collective"}),
    );
    assert!(!db::restore_archived_for_caller(&conn, &id, "ai:bob").expect("denied"));
    assert!(
        !db::restore_archived_for_caller(&conn, &uuid::Uuid::new_v4().to_string(), "ai:bob")
            .expect("absent")
    );
    assert!(db::get(&conn, &id).expect("live").is_none());
    assert_eq!(
        db::archive_stats(&conn).expect("archive intact")["archived_total"],
        1
    );
    assert!(db::restore_archived_for_caller(&conn, &id, "ai:alice").expect("owner"));
    let unowned = seed(&conn, "notes", json!({}));
    assert!(db::restore_archived_for_caller(&conn, &unowned, "ai:bob").expect("legacy"));
}

#[cfg(feature = "sal")]
async fn sal_restore_contract(store: &dyn ai_memory::store::MemoryStore) {
    use ai_memory::store::CallerContext;
    common::permissive_attestation_for_tests();
    let owner = CallerContext::for_agent("ai:archive-owner-3382");
    let other = CallerContext::for_agent("ai:archive-other-3382");
    let namespace = format!("archive-3382-{}", uuid::Uuid::new_v4());
    let m = memory(
        &namespace,
        json!({"agent_id":owner.agent_id, "scope":"private"}),
    );
    let id = store.store(&owner, &m).await.expect("store");
    assert_eq!(
        store
            .archive_by_ids(&owner, std::slice::from_ref(&id), Some("3382"))
            .await
            .expect("archive"),
        1
    );
    assert!(!store.archive_restore(&other, &id).await.expect("deny"));
    assert!(
        !store
            .archive_restore(&other, &uuid::Uuid::new_v4().to_string())
            .await
            .expect("absent")
    );
    assert!(matches!(
        store.get(&owner, &id).await,
        Err(ai_memory::store::StoreError::NotFound { .. })
    ));
    assert!(store.archive_restore(&owner, &id).await.expect("owner"));
    assert_eq!(
        store.get(&owner, &id).await.expect("live").content,
        m.content
    );
    // Inbox recipient remains an explicitly supported mutation owner.
    let mail = memory(
        &namespace,
        json!({"agent_id":owner.agent_id, "target_agent_id":other.agent_id}),
    );
    let id = store.store(&owner, &mail).await.expect("mail");
    assert_eq!(
        store
            .archive_by_ids(&owner, std::slice::from_ref(&id), None)
            .await
            .expect("archive mail"),
        1
    );
    assert!(store.archive_restore(&other, &id).await.expect("recipient"));
    // Explicit operator recovery remains available through the existing SAL
    // bypass; this does not add an MCP as_admin path (#3455).
    let admin = CallerContext::for_admin("archive-operator-3382");
    assert_eq!(
        store
            .archive_by_ids(&owner, std::slice::from_ref(&id), None)
            .await
            .expect("archive again"),
        1
    );
    assert!(
        store
            .archive_restore(&admin, &id)
            .await
            .expect("admin recovery")
    );
}

#[cfg(feature = "sal")]
#[tokio::test]
async fn sqlite_sal_restore_denied_and_allowed() {
    std::fs::create_dir_all(".local-runs").expect("scratch");
    let dir = tempfile::tempdir_in(".local-runs").expect("dir");
    let store =
        ai_memory::store::sqlite::SqliteStore::open(dir.path().join("sqlite.db")).expect("store");
    sal_restore_contract(&store).await;
}

#[cfg(feature = "sal")]
mod common;

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_sal_restore_denied_and_allowed() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    common::permissive_attestation_for_tests();
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("certified pg");
    sal_restore_contract(&store).await;
}
