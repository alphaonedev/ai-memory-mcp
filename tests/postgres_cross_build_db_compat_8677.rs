// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #8677 — cross-build database safety, POSTGRES arm.
//!
//! The sqlite twin is `tests/cross_build_db_compat_8677.rs`. Postgres has no
//! pre-migration snapshot mechanism (the schema is shared by every daemon on
//! the cluster), so the snapshot clause of cases 2 and 3 does not apply here;
//! what must hold is the data contract: a newer-schema database is refused
//! with the actionable text and every table's contents are unchanged (the
//! postgres equivalent of the sqlite sha256 check), a previous-release
//! database migrates forward with its durable row intact, and a same-version
//! reconnect is a pure no-op.
//!
//! Gated like `tests/postgres_schema_downgrade_guard_2445.rs`: needs
//! `feature = "sal-postgres"` and `AI_MEMORY_TEST_POSTGRES_URL` (a role that may
//! `CREATE DATABASE`); each test builds and drops its own scratch database.

#![cfg(feature = "sal-postgres")]

use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{MemoryStore, StoreError};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

mod common;
use common::pg_barrier::{ScratchDb, quote_ident};
use common::postgres_url;

const ENV_ALLOW_SCHEMA_AHEAD: &str = ai_memory::storage::schema_guard::ENV_ALLOW_SCHEMA_AHEAD;
const SCRATCH_PREFIX: &str = "ai_memory_xbld_";
const SEED_ID: &str = "m-8677";
const SEED_CONTENT: &str = "durable text that must survive every cross-build connect";
/// How far ahead of the ladder tip the "newer build" stamped the database.
const NEWER_BUILD_SCHEMA_LEAD: i64 = 3;
/// Schema versions the previous release sits behind the tip.
const PREVIOUS_RELEASE_LAG: i64 = 1;

/// Serialises the process-wide hatch env reads (async: held across awaits).
async fn env_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

fn tip() -> i64 {
    ai_memory::storage::migrations::current_schema_version()
}

async fn pool(url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(15))
        .connect(url)
        .await
        .expect("pool connect")
}

async fn stamp(url: &str, version: i64) {
    let p = pool(url).await;
    sqlx::query("DELETE FROM schema_version")
        .execute(&p)
        .await
        .expect("clear schema_version");
    sqlx::query("INSERT INTO schema_version (version) VALUES ($1)")
        .bind(i32::try_from(version).expect("version fits int4"))
        .execute(&p)
        .await
        .expect("stamp schema_version");
    p.close().await;
}

async fn seed(url: &str) {
    let p = pool(url).await;
    sqlx::query(
        "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
         confidence, source, metadata, access_count, created_at, updated_at) \
         VALUES ($1, 'long', 'ns', 't', $2, '[]', 5, 1.0, 'api', '{}', 0, \
         '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
    )
    .bind(SEED_ID)
    .bind(SEED_CONTENT)
    .execute(&p)
    .await
    .expect("seed row");
    p.close().await;
}

async fn seeded_content(url: &str) -> String {
    let p = pool(url).await;
    let (content,): (String,) = sqlx::query_as("SELECT content FROM memories WHERE id = $1")
        .bind(SEED_ID)
        .fetch_one(&p)
        .await
        .expect("seed row must survive");
    p.close().await;
    content
}

/// The postgres stand-in for a file sha256: an md5 digest of every row of every
/// public table (rows rendered as text, ordered), plus the column catalog.
async fn content_digest(url: &str) -> Vec<(String, String)> {
    let p = pool(url).await;
    let tables: Vec<(String,)> = sqlx::query_as(
        "SELECT table_name::text FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1",
    )
    .fetch_all(&p)
    .await
    .expect("list tables");
    let mut digest = Vec::new();
    for (table,) in tables {
        let sql = format!(
            "SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY t::text), '')) FROM {} t",
            quote_ident(&table)
        );
        let (md5,): (String,) = sqlx::query_as(&sql)
            .fetch_one(&p)
            .await
            .expect("digest table");
        digest.push((table, md5));
    }
    let columns: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text, data_type::text \
         FROM information_schema.columns WHERE table_schema = 'public' \
         ORDER BY table_name, column_name",
    )
    .fetch_all(&p)
    .await
    .expect("columns");
    digest.push(("<columns>".to_string(), format!("{columns:?}")));
    p.close().await;
    digest
}

#[tokio::test]
async fn pg_older_build_refuses_newer_database_unchanged_with_actionable_text_8677() {
    let Some(admin_url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let _g = env_lock().await;
    // SAFETY: process-wide env mutation, serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
    let scratch = ScratchDb::create(&admin_url, SCRATCH_PREFIX)
        .await
        .expect("scratch db");
    let url = scratch.url();

    drop(PostgresStore::connect(&url).await.expect("greenfield"));
    seed(&url).await;
    let ahead = tip() + NEWER_BUILD_SCHEMA_LEAD;
    stamp(&url, ahead).await;
    let before = content_digest(&url).await;

    let err = PostgresStore::connect(&url)
        .await
        .err()
        .expect("a newer database must be refused");
    assert!(
        matches!(err, StoreError::SchemaAheadOfBinary { .. }),
        "typed refusal: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains(&format!(
            "This database was written by a newer ai-memory build (schema v{ahead})"
        )),
        "{msg}"
    );
    assert!(
        msg.contains(&format!(
            "this binary (ai-memory {}) supports schema v{}",
            ai_memory::PKG_VERSION,
            tip()
        )),
        "{msg}"
    );
    assert!(
        msg.contains("upgrade ai-memory to the build that wrote this database"),
        "{msg}"
    );
    assert!(
        msg.contains("open a backup copy with --store-url <copy-url>"),
        "postgres remediation names the postgres selector: {msg}"
    );
    assert!(
        !msg.contains("--db <copy>"),
        "--db selects a sqlite file and must not be advised on postgres: {msg}"
    );
    assert_eq!(
        content_digest(&url).await,
        before,
        "a refused connect must leave every table's contents and the catalog unchanged"
    );
    assert_eq!(seeded_content(&url).await, SEED_CONTENT);
}

#[tokio::test]
async fn pg_current_build_migrates_previous_release_and_reconnects_cleanly_8677() {
    let Some(admin_url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let _g = env_lock().await;
    // SAFETY: serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
    let scratch = ScratchDb::create(&admin_url, SCRATCH_PREFIX)
        .await
        .expect("scratch db");
    let url = scratch.url();

    drop(PostgresStore::connect(&url).await.expect("greenfield"));
    seed(&url).await;
    stamp(&url, tip() - PREVIOUS_RELEASE_LAG).await;

    let store = PostgresStore::connect(&url)
        .await
        .expect("the previous-release database must migrate forward");
    assert_eq!(store.schema_version().await.unwrap(), tip());
    drop(store);
    assert_eq!(seeded_content(&url).await, SEED_CONTENT);

    // Reopen cleanly: a pure no-op.
    let migrated = content_digest(&url).await;
    let store = PostgresStore::connect(&url).await.expect("reconnect");
    assert_eq!(store.schema_version().await.unwrap(), tip());
    drop(store);
    assert_eq!(content_digest(&url).await, migrated, "reconnect is a no-op");
}

#[tokio::test]
async fn pg_second_build_same_schema_reconnect_changes_nothing_8677() {
    let Some(admin_url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let _g = env_lock().await;
    // SAFETY: serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
    let scratch = ScratchDb::create(&admin_url, SCRATCH_PREFIX)
        .await
        .expect("scratch db");
    let url = scratch.url();

    drop(PostgresStore::connect(&url).await.expect("greenfield"));
    seed(&url).await;
    let before = content_digest(&url).await;

    let store = PostgresStore::connect(&url)
        .await
        .expect("a second build at the same schema connects");
    assert_eq!(store.schema_version().await.unwrap(), tip());
    drop(store);
    assert_eq!(content_digest(&url).await, before);
    assert_eq!(seeded_content(&url).await, SEED_CONTENT);
}
