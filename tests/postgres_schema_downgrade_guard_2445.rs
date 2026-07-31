// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #2445 — the schema DOWNGRADE guard, POSTGRES arm.
//!
//! The sqlite twin is `tests/schema_downgrade_guard_2445.rs`; this file asserts
//! the SAME contract against a REAL postgres so cross-backend parity is proven
//! rather than assumed. `PostgresStore::migrate_locked` carried the identical
//! `if current_version >= CURRENT_SCHEMA_VERSION { return Ok(()) }` fast path,
//! so an older binary connected to a shared cluster whose schema a newer node
//! had already migrated proceeded to write it.
//!
//! Postgres raises the stakes: the schema is SHARED by every daemon on the
//! cluster, so one node's upgrade moves it for all of them. That is exactly why
//! the refusal must be typed and distinguishable (`SchemaAheadOfBinary` ->
//! `SCHEMA_AHEAD_OF_BINARY` -> HTTP 503) — an orchestrator has to be able to
//! park a locked-out node rather than crash-loop it.
//!
//! # Gating
//!
//! Requires `feature = "sal-postgres"` and `AI_MEMORY_TEST_POSTGRES_URL`
//! pointing at a live server whose role may `CREATE DATABASE` (each test builds
//! and drops its own throwaway database, so the pointed-at database is never
//! mutated). Without the env the tests `eprintln!` a skip and return cleanly —
//! matching `tests/postgres_ladder_replay.rs`.

#![cfg(feature = "sal-postgres")]

use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{MemoryStore, StoreError};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

mod common;
use common::postgres_url;

const ENV_ALLOW_SCHEMA_AHEAD: &str = ai_memory::storage::schema_guard::ENV_ALLOW_SCHEMA_AHEAD;
const SCRATCH_PREFIX: &str = "ai_memory_dgrd_";

/// Serialises the process-wide hatch env mutations.
///
/// An ASYNC mutex deliberately: the guard is held across `.await` points (the
/// scratch-database lifecycle), and a `std::sync::MutexGuard` held across an
/// await is the `clippy::await_holding_lock` defect — correct here today only
/// because these are single-threaded `#[tokio::test]` runtimes, which is
/// exactly the kind of accident that stops being true silently.
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

/// Stamp the recorded version directly, bypassing the adapter entirely.
async fn stamp(url: &str, version: i64) {
    let pool = admin_pool(url).await;
    sqlx::query("DELETE FROM schema_version")
        .execute(&pool)
        .await
        .expect("clear schema_version");
    sqlx::query("INSERT INTO schema_version (version) VALUES ($1)")
        .bind(i32::try_from(version).expect("version fits in the int4 column"))
        .execute(&pool)
        .await
        .expect("stamp schema_version");
    pool.close().await;
}

/// Snapshot every column of every public table — the fingerprint a refused
/// connect must not move (the postgres twin of the sqlite `sqlite_master`
/// assertion that proves the gate sits BEFORE the bootstrap DDL replays).
async fn column_fingerprint(url: &str) -> Vec<(String, String, String)> {
    let pool = admin_pool(url).await;
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text, data_type::text \
         FROM information_schema.columns WHERE table_schema = 'public' \
         ORDER BY table_name, column_name",
    )
    .fetch_all(&pool)
    .await
    .expect("read column fingerprint");
    pool.close().await;
    rows
}

#[tokio::test]
async fn pg_guard_refuses_a_newer_database_and_leaves_it_untouched_2445() {
    let Some(admin_url) = postgres_url() else {
        eprintln!(
            "skip: AI_MEMORY_TEST_POSTGRES_URL unset (role needs CREATEDB — each test \
             builds and drops its own throwaway database)"
        );
        return;
    };
    let _g = env_lock().await;
    // SAFETY: process-wide env mutation, serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };

    let scratch = ScratchDb::create(&admin_url, "refuse").await;

    // Greenfield connect brings the scratch database to the tip.
    let store = PostgresStore::connect(&scratch.url)
        .await
        .expect("greenfield connect must succeed");
    assert_eq!(
        store.schema_version().await.expect("schema_version"),
        tip(),
        "greenfield connect must land on the ladder tip"
    );
    drop(store);

    // Now make it NEWER than this binary and try again.
    let ahead = tip() + 5;
    stamp(&scratch.url, ahead).await;
    let before = column_fingerprint(&scratch.url).await;

    let err = PostgresStore::connect(&scratch.url)
        .await
        .err()
        .expect("a newer database must be REFUSED");
    assert!(
        matches!(err, StoreError::SchemaAheadOfBinary { .. }),
        "the refusal must be the TYPED verdict an orchestrator can switch on, \
         not a generic backend fault: {err:?}"
    );
    assert_eq!(
        err.code(),
        ai_memory::errors::error_codes::SCHEMA_AHEAD_OF_BINARY
    );
    let msg = err.to_string();
    assert!(msg.contains(&format!("v{ahead}")), "names observed: {msg}");
    assert!(
        msg.contains(&format!("v{}", tip())),
        "names supported: {msg}"
    );
    assert!(
        msg.contains("SHARED"),
        "the postgres refusal must name the shared-cluster implication — one \
         node's upgrade moves the schema for every daemon on the cluster: {msg}"
    );
    assert!(
        msg.contains(ENV_ALLOW_SCHEMA_AHEAD) && msg.contains("backup"),
        "the refusal must name the hatch AND the surviving egress path: {msg}"
    );

    // CROSS-BACKEND PARITY, asserted rather than assumed: both adapters route
    // through the ONE shared verdict, so for the same (observed, supported,
    // target) the rendered refusal differs ONLY in the backend token. Anything
    // else would mean the two funnels had drifted apart.
    let render = |backend| {
        ai_memory::storage::schema_guard::evaluate(ahead, tip(), backend, "TARGET")
            .expect_err("must refuse")
            .detail
    };
    let pg_render = render(ai_memory::storage::schema_guard::BACKEND_POSTGRES);
    let sqlite_render = render(ai_memory::storage::schema_guard::BACKEND_SQLITE);
    assert_eq!(
        pg_render.replacen("(postgres)", "(BACKEND)", 1),
        sqlite_render.replacen("(sqlite)", "(BACKEND)", 1),
        "sqlite and postgres must emit a byte-identical refusal modulo the \
         backend token"
    );

    // The refusal must not have replayed this binary's bootstrap DDL.
    assert_eq!(
        column_fingerprint(&scratch.url).await,
        before,
        "a refused connect must not mutate the schema"
    );

    scratch.destroy().await;
}

#[tokio::test]
async fn pg_guard_does_not_fire_at_equal_or_older_2445() {
    // R-203 CONTROL — the steady-state and upgrade paths are unchanged.
    let Some(admin_url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let _g = env_lock().await;
    // SAFETY: serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };

    let scratch = ScratchDb::create(&admin_url, "control").await;

    // Fresh (no schema_version relation yet) -> full ladder -> tip.
    let store = PostgresStore::connect(&scratch.url)
        .await
        .expect("fresh connect must succeed");
    assert_eq!(store.schema_version().await.unwrap(), tip());
    let at_tip = column_fingerprint(&scratch.url).await;
    drop(store);

    // `==` — reconnect at the tip is a pure no-op.
    let store = PostgresStore::connect(&scratch.url)
        .await
        .expect("reconnect AT the tip must succeed");
    assert_eq!(store.schema_version().await.unwrap(), tip());
    drop(store);
    assert_eq!(
        column_fingerprint(&scratch.url).await,
        at_tip,
        "the `==` fast path must remain a pure no-op"
    );

    // `<` — the ladder re-runs and still reaches the tip.
    stamp(&scratch.url, tip() - 1).await;
    let store = PostgresStore::connect(&scratch.url)
        .await
        .expect("a database BEHIND the tip must migrate forward");
    assert_eq!(store.schema_version().await.unwrap(), tip());
    drop(store);

    scratch.destroy().await;
}

#[tokio::test]
async fn pg_exact_version_hatch_admits_and_skips_the_bootstrap_replay_2445() {
    let Some(admin_url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let _g = env_lock().await;
    let scratch = ScratchDb::create(&admin_url, "hatch").await;
    drop(
        PostgresStore::connect(&scratch.url)
            .await
            .expect("greenfield connect"),
    );

    let ahead = tip() + 5;
    stamp(&scratch.url, ahead).await;
    let before = column_fingerprint(&scratch.url).await;

    // A boolean — the value an operator reaches for by habit — must NOT work.
    // SAFETY: serialised by `_g`.
    unsafe { std::env::set_var(ENV_ALLOW_SCHEMA_AHEAD, "1") };
    assert!(
        PostgresStore::connect(&scratch.url).await.is_err(),
        "a boolean hatch value must fail CLOSED"
    );

    // The EXACT observed version admits.
    // SAFETY: serialised by `_g`.
    unsafe { std::env::set_var(ENV_ALLOW_SCHEMA_AHEAD, ahead.to_string()) };
    let store = PostgresStore::connect(&scratch.url)
        .await
        .expect("the exact-version hatch must admit");
    assert_eq!(
        store.schema_version().await.unwrap(),
        ahead,
        "the hatched connect must leave the recorded version alone"
    );
    drop(store);
    // SAFETY: serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };

    assert_eq!(
        column_fingerprint(&scratch.url).await,
        before,
        "the hatch must NOT replay this binary's bootstrap DDL over a newer \
         database — that is the window the guard exists to close"
    );

    scratch.destroy().await;
}
