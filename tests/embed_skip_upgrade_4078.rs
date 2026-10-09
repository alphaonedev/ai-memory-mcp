// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Regression for #4078: real opener upgrades a v96-shaped store, and repairs
//! a previously upgraded store whose derived-cache triggers were lost.

#[path = "common/sqlite_tempfile.rs"]
mod sqlite_tempfile;

use ai_memory::db;
use rusqlite::Connection;

// Reverse the documented additive v97-v99 migrations and the v100 index
// migration, rather than merely stamping an otherwise-current schema v96.
const SQLITE_V96_SHAPE: &str = "
DROP TRIGGER agent_pubkey_history_authoritative_insert_v97;
DROP TRIGGER agent_pubkey_history_authoritative_update_v97;
DROP TABLE agent_pubkey_history;
DROP TABLE agent_pubkey_challenges;
DROP VIEW inbox_namespace_aliases;
DROP TABLE sync_peer_contact;
DROP INDEX idx_memories_title_ns;
CREATE UNIQUE INDEX idx_memories_title_ns ON memories(title, namespace);
DELETE FROM schema_version;
INSERT INTO schema_version(version) VALUES (96);
";

fn seed(conn: &Connection) {
    conn.execute(
        "INSERT INTO memories(id,tier,namespace,title,content,created_at,updated_at)
         VALUES ('upgrade-4078','mid','upgrade-4078','oversize',?1,datetime('now'),datetime('now'))",
        [&"x".repeat(2_000_000)],
    )
    .expect("seed oversize row");
    assert!(
        db::get_unembedded_ids_batch(conn, 10)
            .expect("scan")
            .is_empty()
    );
    let count: i64 = conn
        .query_row("SELECT count(*) FROM embed_skip", [], |r| r.get(0))
        .expect("marker count");
    assert_eq!(count, 1, "scan must naturally persist the oversize marker");
}

fn assert_heals(conn: &Connection) {
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name IN
        ('memories_embed_skip_clear_on_content','memories_embed_skip_clear_on_embed')",
            [],
            |r| r.get(0),
        )
        .expect("trigger count");
    assert_eq!(
        count, 2,
        "upgrade/open must preserve both skip-clearing triggers"
    );
    // The CLI update funnel calls this same storage operation.
    db::update(
        conn,
        "upgrade-4078",
        None,
        Some("short, embeddable"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("shorten through update funnel");
    let count: i64 = conn
        .query_row("SELECT count(*) FROM embed_skip", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0, "content edit must clear the marker");
    let rows = db::get_unembedded_ids_batch(conn, 10).expect("bounded backfill");
    assert!(rows.iter().any(|(id, _, _)| id == "upgrade-4078"));
}

fn sqlite_upgrade_preserves_embed_skip_healing(version: i64) {
    let temp = crate::sqlite_tempfile::SqliteTempFile::new().unwrap();
    let conn = db::open(temp.path()).unwrap();
    conn.execute_batch(SQLITE_V96_SHAPE)
        .expect("restore v96 schema shape");
    for (rung, ddl) in [
        (
            97,
            include_str!("../migrations/sqlite/0081_v97_agent_pubkey_history.sql"),
        ),
        (
            98,
            include_str!("../migrations/sqlite/0082_v98_canonical_inbox_namespace.sql"),
        ),
        (
            99,
            include_str!("../migrations/sqlite/0083_v99_sync_peer_contact.sql"),
        ),
    ] {
        if version >= rung {
            conn.execute_batch(ddl).expect("apply older fixture rung");
        }
    }
    conn.execute("UPDATE schema_version SET version=?1", [version])
        .unwrap();
    seed(&conn);
    drop(conn);
    let conn = db::open(temp.path()).expect("production older-schema upgrade");
    assert_heals(&conn);
    drop(conn);
    let conn = db::open(temp.path()).expect("reopen");
    conn.execute(
        "UPDATE memories SET content=?1 WHERE id='upgrade-4078'",
        [&"x".repeat(2_000_000)],
    )
    .unwrap();
    assert!(db::get_unembedded_ids_batch(&conn, 10).unwrap().is_empty());
    assert_heals(&conn);
}

#[test]
fn sqlite_v96_upgrade_preserves_embed_skip_healing_4078() {
    sqlite_upgrade_preserves_embed_skip_healing(96);
}

#[test]
fn sqlite_v97_upgrade_preserves_embed_skip_healing_4078() {
    sqlite_upgrade_preserves_embed_skip_healing(97);
}

#[test]
fn sqlite_v98_upgrade_preserves_embed_skip_healing_4078() {
    sqlite_upgrade_preserves_embed_skip_healing(98);
}

#[test]
fn sqlite_v99_upgrade_preserves_embed_skip_healing_4078() {
    sqlite_upgrade_preserves_embed_skip_healing(99);
}

#[test]
fn sqlite_current_schema_repairs_missing_embed_skip_triggers_4078() {
    let temp = crate::sqlite_tempfile::SqliteTempFile::new().unwrap();
    let conn = db::open(temp.path()).unwrap();
    seed(&conn);
    conn.execute_batch(
        "DROP TRIGGER memories_embed_skip_clear_on_content;
        DROP TRIGGER memories_embed_skip_clear_on_embed;",
    )
    .unwrap();
    drop(conn);
    assert_heals(&db::open(temp.path()).expect("repair current schema on open"));
}

/// L8 finding on #4078: the repair reinstalls the triggers but must also drop
/// markers orphaned while they were absent. Seed an oversize marker, drop both
/// triggers, shorten the row with a RAW update (no trigger fires), reopen.
#[test]
fn sqlite_repair_clears_markers_stranded_in_the_trigger_gap_4078() {
    let temp = crate::sqlite_tempfile::SqliteTempFile::new().unwrap();
    let conn = db::open(temp.path()).unwrap();
    seed(&conn);
    conn.execute_batch(
        "DROP TRIGGER memories_embed_skip_clear_on_content;
        DROP TRIGGER memories_embed_skip_clear_on_embed;
        UPDATE memories SET content='short, embeddable' WHERE id='upgrade-4078';",
    )
    .unwrap();
    drop(conn);
    let conn = db::open(temp.path()).expect("repair current schema on open");
    let stale: i64 = conn
        .query_row("SELECT count(*) FROM embed_skip", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stale, 0, "repair left a marker for content that changed");
    let rows = db::get_unembedded_ids_batch(&conn, 10).expect("backfill scan");
    assert!(
        rows.iter().any(|(id, _, _)| id == "upgrade-4078"),
        "the edited row must be eligible for embedding again"
    );
}

/// Same gap on the ladder path: a v99 store whose triggers were dropped and
/// whose oversize row was edited before this binary upgraded it.
#[test]
fn sqlite_ladder_upgrade_clears_markers_stranded_in_the_trigger_gap_4078() {
    let temp = crate::sqlite_tempfile::SqliteTempFile::new().unwrap();
    let conn = db::open(temp.path()).unwrap();
    seed(&conn);
    conn.execute_batch(
        "DROP TRIGGER memories_embed_skip_clear_on_content;
        DROP TRIGGER memories_embed_skip_clear_on_embed;
        UPDATE memories SET content='short, embeddable' WHERE id='upgrade-4078';
        UPDATE schema_version SET version = 99;",
    )
    .unwrap();
    drop(conn);
    let conn = db::open(temp.path()).expect("ladder upgrade");
    let stale: i64 = conn
        .query_row("SELECT count(*) FROM embed_skip", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stale, 0, "ladder upgrade left a stranded marker");
}

#[cfg(feature = "sal-postgres")]
mod postgres {
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore, UpdatePatch};

    #[tokio::test]
    async fn postgres_v96_upgrade_preserves_embed_skip_healing_4078() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_UPGRADE_POSTGRES_URL") else {
            eprintln!(
                "SKIP: AI_MEMORY_TEST_UPGRADE_POSTGRES_URL required for live PostgreSQL test"
            );
            return;
        };
        // This test reverses schema rungs. Refuse shared/non-pool databases.
        assert!(url.contains("/ai_memory_pool_b7_fix_install_upgrade_"));
        let store = PostgresStore::connect(&url)
            .await
            .expect("connect isolated database");
        sqlx::raw_sql(
            "\
            DROP TRIGGER agent_pubkey_history_authoritative_v97 ON memories;
            DROP FUNCTION reconcile_agent_pubkey_from_history_v97();
            DROP TABLE agent_pubkey_history;
            DROP TABLE agent_pubkey_challenges;
            DROP VIEW inbox_namespace_aliases;
            DROP TABLE sync_peer_contact;
            DROP INDEX memories_title_ns_uidx;
            CREATE UNIQUE INDEX memories_title_ns_uidx ON memories(title, namespace);
            DELETE FROM schema_version;
            INSERT INTO schema_version(version) VALUES (96);",
        )
        .execute(store.pool())
        .await
        .expect("restore v96 schema shape");
        sqlx::query(
            "INSERT INTO memories
            (id,tier,namespace,title,content,tags,priority,confidence,source,
             access_count,created_at,updated_at,metadata)
            VALUES ('upgrade-4078','mid','upgrade-4078','oversize',$1,'[]',5,1,'test',
                    0,now(),now(),'{\"agent_id\":\"ai:upgrade-4078\"}')",
        )
        .bind("x".repeat(2_000_000))
        .execute(store.pool())
        .await
        .expect("seed oversize");
        let admin = CallerContext::for_admin("ai:upgrade-4078");
        assert!(
            store
                .list_unembedded(&admin, 10)
                .await
                .expect("scan")
                .is_empty()
        );
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM embed_skip WHERE memory_id='upgrade-4078'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(count, 1, "scan naturally records oversize marker");
        store.pool().close().await;
        let store = PostgresStore::connect(&url)
            .await
            .expect("production upgrade");
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_trigger
            WHERE tgrelid='memories'::regclass AND tgname='memories_embed_skip_clear'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(count, 1, "PostgreSQL must retain the clear trigger");
        store
            .update(
                &admin,
                "upgrade-4078",
                UpdatePatch {
                    content: Some("short, embeddable".to_owned()),
                    ..UpdatePatch::default()
                },
            )
            .await
            .expect("shorten through storage update funnel");
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM embed_skip WHERE memory_id='upgrade-4078'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(count, 0, "edit clears skip marker");
        let rows = store
            .list_unembedded(&admin, 10)
            .await
            .expect("bounded backfill");
        assert!(rows.iter().any(|(id, _, _)| id == "upgrade-4078"));
        store.pool().close().await;
        let store = PostgresStore::connect(&url).await.expect("reopen");
        let rows = store
            .list_unembedded(&admin, 10)
            .await
            .expect("scan after reopen");
        assert!(rows.iter().any(|(id, _, _)| id == "upgrade-4078"));
        sqlx::query("DELETE FROM memories WHERE id='upgrade-4078'")
            .execute(store.pool())
            .await
            .unwrap();
        store.pool().close().await;
    }
}
