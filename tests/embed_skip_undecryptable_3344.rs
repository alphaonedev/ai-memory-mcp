// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3344 — durable skip cache for undecryptable / oversize unembedded rows.
//!
//! DENIED: a non-admin caller of `list_unembedded` sees an empty result even
//! when sealed unembedded rows exist (the existing #1586 admin gate).
//! ALLOWED: an admin scan skips an undecryptable sealed row, persists a
//! skip marker, and a second scan does not re-fetch it. Healing: a stale
//! fingerprint is dropped and the next admin scan retries the row.

#![cfg(feature = "sal")]

use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};

#[tokio::test]
async fn list_unembedded_denied_non_admin_sqlite_3344() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let store = SqliteStore::open(tmp.path()).expect("open");
    let tenant = CallerContext::for_agent("ai:tenant-3344");
    let scanned = store
        .list_unembedded(&tenant, 100)
        .await
        .expect("tenant list_unembedded");
    assert!(
        scanned.is_empty(),
        "DENIED: non-admin list_unembedded must be empty, got {scanned:?}"
    );
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::store::postgres::PostgresStore;

    fn postgres_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
    }

    #[tokio::test]
    async fn list_unembedded_denied_non_admin_pg_3344() {
        let Some(url) = postgres_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect");
        let tenant = CallerContext::for_agent("ai:tenant-3344");
        let scanned = store
            .list_unembedded(&tenant, 100)
            .await
            .expect("tenant list_unembedded");
        assert!(
            scanned.is_empty(),
            "DENIED: non-admin list_unembedded must be empty, got {scanned:?}"
        );
    }

    #[tokio::test]
    async fn list_unembedded_persists_skip_and_does_not_reread_pg_3344() {
        let Some(url) = postgres_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect");
        let unique = uuid::Uuid::new_v4();
        let ns = format!("unemb-3344-{unique}");
        let sealed_id = format!("unemb3344-sealed-{unique}");
        let plain_id = format!("unemb3344-plain-{unique}");
        sqlx::query(
            "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
                 confidence, source, access_count, created_at, updated_at, metadata, \
                 encrypted_envelope) \
             VALUES ($1, 'mid', $2, 'sealed row', '', '[]', 5, 1.0, 'test', 0, now(), \
                 now(), '{\"agent_id\":\"ai:sal-test\"}', $3)",
        )
        .bind(&sealed_id)
        .bind(&ns)
        .bind(vec![3u8, 0xde, 0xad, 0xbe, 0xef])
        .execute(store.pool())
        .await
        .expect("insert sealed");
        sqlx::query(
            "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
                 confidence, source, access_count, created_at, updated_at, metadata) \
             VALUES ($1, 'mid', $2, 'plain row', 'plain unencrypted body', '[]', 5, 1.0, \
                 'test', 0, now(), now(), '{\"agent_id\":\"ai:sal-test\"}')",
        )
        .bind(&plain_id)
        .bind(&ns)
        .execute(store.pool())
        .await
        .expect("insert plain");

        let admin = CallerContext::for_admin("ai:sal-test");
        let first = store
            .list_unembedded(&admin, 1_000_000)
            .await
            .expect("first scan");
        assert!(
            !first.iter().any(|(id, _, _)| id == &sealed_id),
            "ALLOWED: undecryptable sealed row must be skipped"
        );
        assert!(
            first
                .iter()
                .any(|(id, _, c)| id == &plain_id && c == "plain unencrypted body"),
            "ALLOWED: plain row is returned verbatim"
        );

        let skip_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM embed_skip WHERE memory_id = $1",
        )
        .bind(&sealed_id)
        .fetch_one(store.pool())
        .await
        .expect("skip count");
        assert_eq!(skip_count, 1, "first scan must persist a skip marker");

        let second = store
            .list_unembedded(&admin, 1_000_000)
            .await
            .expect("second scan");
        assert!(
            !second.iter().any(|(id, _, _)| id == &sealed_id),
            "second scan must not re-fetch the remembered sealed row"
        );

        sqlx::query("UPDATE embed_skip SET key_fingerprint = 'stale-fp' WHERE memory_id = $1")
            .bind(&sealed_id)
            .execute(store.pool())
            .await
            .expect("stale the skip");
        let retried = store
            .list_unembedded(&admin, 1_000_000)
            .await
            .expect("retry scan");
        assert!(
            !retried.iter().any(|(id, _, _)| id == &sealed_id),
            "retry still cannot decrypt, so the row stays omitted"
        );
        let fp: String = sqlx::query_scalar(
            "SELECT key_fingerprint FROM embed_skip WHERE memory_id = $1",
        )
        .bind(&sealed_id)
        .fetch_one(store.pool())
        .await
        .expect("fp after retry");
        assert_ne!(fp, "stale-fp", "healing must re-record under the live key fingerprint");

        let _ = sqlx::query("DELETE FROM embed_skip WHERE memory_id = $1")
            .bind(&sealed_id)
            .execute(store.pool())
            .await;
        let _ = sqlx::query("DELETE FROM memories WHERE namespace = $1")
            .bind(&ns)
            .execute(store.pool())
            .await;
    }
}
