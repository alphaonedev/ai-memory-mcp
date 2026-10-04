// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #5035: the #2445 schema-ahead guard must hold for the LIFETIME of a
//! `PostgresStore`, not only at `connect`. POSTGRES arm; the sqlite twin is
//! `tests/schema_guard_lifetime_5035.rs`.
//!
//! The postgres schema is SHARED by every daemon on the cluster, so one node's
//! upgrade moves it for all of them while their pools stay connected. Before
//! #5035 a pool connected at schema N kept writing after another node migrated
//! the cluster to N+k. The write gate now re-probes the recorded version on
//! the same TTL-bounded, single-flight cadence as the #3276 record-stop
//! re-check, so a schema move is refused within one window.
//!
//! # Gating
//!
//! Requires `feature = "sal-postgres"` and `AI_MEMORY_TEST_POSTGRES_URL`
//! pointing at a live server whose role may `CREATE DATABASE` (each test
//! builds and drops its own throwaway database). Without the env the tests
//! `eprintln!` a skip and return cleanly.

#![cfg(feature = "sal-postgres")]

use std::time::Duration;

use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::{PostgresStore, RECORD_STOP_REFRESH_TTL_MS};
use ai_memory::store::{CallerContext, MemoryStore, StoreError};
use serde_json::json;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

mod common;
use common::postgres_url;

const ENV_ALLOW_SCHEMA_AHEAD: &str = ai_memory::storage::schema_guard::ENV_ALLOW_SCHEMA_AHEAD;
const SCRATCH_PREFIX: &str = "ai_memory_lt5035_";
const NS: &str = "pg-schema-guard-lifetime-5035";

/// Slack past one re-check window so the next write is the elected re-prober.
const TTL_SLACK_MS: u64 = 400;

/// Serialises the process-wide hatch env mutations (async: held across awaits).
async fn env_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

fn url_with_db(url: &str, db: &str) -> String {
    let (base, query) = match url.find('?') {
        Some(i) => (&url[..i], &url[i..]),
        None => (url, ""),
    };
    let scheme_end = base.find("://").map_or(0, |i| i + 3);
    let prefix = match base[scheme_end..].find('/') {
        Some(i) => &base[..=scheme_end + i],
        None => base,
    };
    if prefix.ends_with('/') {
        format!("{prefix}{db}{query}")
    } else {
        format!("{prefix}/{db}{query}")
    }
}

async fn admin_pool(url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(15))
        .connect(url)
        .await
        .expect("admin pool connect")
}

struct ScratchDb {
    admin_url: String,
    name: String,
    url: String,
}

impl ScratchDb {
    /// `tag` is a literal from this file; the rest of the name is synthesized.
    /// Postgres cannot bind an identifier in DDL, so the name is interpolated —
    /// it is never derived from external input.
    async fn create(admin_url: &str, tag: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock");
        let name = format!(
            "{SCRATCH_PREFIX}{tag}_{}_{}",
            now.as_secs(),
            now.subsec_nanos()
        );
        let pool = admin_pool(admin_url).await;
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {name}"))
            .execute(&pool)
            .await;
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&pool)
            .await
            .expect("CREATE DATABASE for the downgrade-guard scratch (role needs CREATEDB)");
        pool.close().await;
        Self {
            admin_url: admin_url.to_string(),
            url: url_with_db(admin_url, &name),
            name,
        }
    }

    async fn destroy(self) {
        let pool = admin_pool(&self.admin_url).await;
        let _ = sqlx::query(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}'",
            self.name
        ))
        .execute(&pool)
        .await;
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {}", self.name))
            .execute(&pool)
            .await;
        pool.close().await;
    }
}

fn tip() -> i64 {
    ai_memory::storage::migrations::current_schema_version()
}

fn mk_memory(title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("durable text for {title}"),
        tags: vec!["t5035".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": "ai:operator"}),
        version: 1,
        ..Memory::default()
    }
}

/// Another node migrates the shared cluster: add a newer stamp row through a
/// separate pool, bypassing this store entirely.
async fn stamp_from_another_node(url: &str, version: i64) {
    let pool = admin_pool(url).await;
    sqlx::query("INSERT INTO schema_version (version) VALUES ($1)")
        .bind(i32::try_from(version).expect("version fits in the int4 column"))
        .execute(&pool)
        .await
        .expect("stamp schema_version ahead");
    pool.close().await;
}

async fn count_rows(url: &str, title: &str) -> i64 {
    let pool = admin_pool(url).await;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE title = $1")
        .bind(title)
        .fetch_one(&pool)
        .await
        .expect("count rows");
    pool.close().await;
    n
}

#[tokio::test]
async fn pg_write_refuses_typed_after_cluster_schema_moves_ahead_5035() {
    let Some(admin_url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset (role needs CREATEDB)");
        return;
    };
    let _g = env_lock().await;
    // SAFETY: process-wide env mutation, serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
    let scratch = ScratchDb::create(&admin_url, "refuse").await;

    let store = PostgresStore::connect(&scratch.url)
        .await
        .expect("greenfield connect must succeed");
    let ctx = CallerContext::for_agent("ai:operator");
    let id = store
        .store(&ctx, &mk_memory("pg-before-move"))
        .await
        .expect("write at tip must succeed");

    stamp_from_another_node(&scratch.url, tip() + 1).await;
    tokio::time::sleep(Duration::from_millis(
        RECORD_STOP_REFRESH_TTL_MS + TTL_SLACK_MS,
    ))
    .await;

    let refused = store.store(&ctx, &mk_memory("pg-after-move")).await;
    let read = store.get(&ctx, &id).await;
    let landed = count_rows(&scratch.url, "pg-after-move").await;
    drop(store);
    scratch.destroy().await;

    let err = refused.expect_err("a write after the cluster schema moved ahead must be REFUSED");
    assert!(
        matches!(err, StoreError::SchemaAheadOfBinary { .. }),
        "postgres must surface the typed SchemaAheadOfBinary (HTTP 503), got {err:?}"
    );
    assert_eq!(landed, 0, "the refused row must not land");
    read.expect("reads must keep working while writes are refused");
}

#[tokio::test]
async fn pg_exact_version_hatch_still_admits_after_move_5035() {
    let Some(admin_url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset (role needs CREATEDB)");
        return;
    };
    let _g = env_lock().await;
    // SAFETY: process-wide env mutation, serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
    let scratch = ScratchDb::create(&admin_url, "hatch").await;

    let store = PostgresStore::connect(&scratch.url)
        .await
        .expect("greenfield connect must succeed");
    let ctx = CallerContext::for_agent("ai:operator");
    let ahead = tip() + 1;
    stamp_from_another_node(&scratch.url, ahead).await;
    // SAFETY: as above.
    unsafe { std::env::set_var(ENV_ALLOW_SCHEMA_AHEAD, ahead.to_string()) };
    tokio::time::sleep(Duration::from_millis(
        RECORD_STOP_REFRESH_TTL_MS + TTL_SLACK_MS,
    ))
    .await;
    let admitted = store.store(&ctx, &mk_memory("pg-hatch")).await;
    // SAFETY: as above.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
    drop(store);
    scratch.destroy().await;

    admitted.expect("the exact-version hatch must admit the write");
}
