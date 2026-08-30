// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #2555 — the `schema_version` POISON guard + bounding CHECK, POSTGRES
//! arm. The sqlite twin is `tests/schema_version_poison_guard_2555.rs`.
//!
//! Postgres is the WORST case #2555 names: the `schema_version` ledger is SHARED
//! by every daemon on the cluster and the ai-memory role has full DML, so an
//! unconstrained `INSERT INTO schema_version VALUES (2147483647)` by any
//! co-tenant took the whole fleet down via the #2445 schema-ahead DENY with no
//! recovery. This asserts, against a REAL postgres:
//!
//! * the v92 `ADD CONSTRAINT` retrofit / bootstrap inline bounds the stamp, so
//!   an out-of-band write is refused at the boundary;
//! * a stamp already ABOVE the ceiling (a legacy cluster poisoned before the
//!   CHECK shipped) is refused with the NEW typed error
//!   (`SchemaVersionPoisoned` -> `SCHEMA_VERSION_POISONED` -> HTTP 503), NOT
//!   the plain downgrade DENY.
//!
//! # Gating
//!
//! Requires `feature = "sal-postgres"` and `AI_MEMORY_TEST_POSTGRES_URL`
//! pointing at a live server whose role may `CREATE DATABASE`. Without the env
//! the tests `eprintln!` a skip and return cleanly.

#![cfg(feature = "sal-postgres")]

use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{MemoryStore, StoreError};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

mod common;
use common::postgres_url;

const SCRATCH_PREFIX: &str = "ai_memory_poison_";

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
            .expect("CREATE DATABASE for the poison-guard scratch (role needs CREATEDB)");
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

fn ceiling() -> i64 {
    ai_memory::storage::migrations::max_schema_version()
}

async fn has_bound_constraint(url: &str) -> bool {
    let pool = admin_pool(url).await;
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_constraint \
         WHERE conname = 'schema_version_bounded' AND conrelid = 'schema_version'::regclass",
    )
    .fetch_one(&pool)
    .await
    .expect("probe schema_version_bounded");
    pool.close().await;
    n > 0
}

/// Attempt a raw stamp INSERT, returning whether the server accepted it.
async fn try_insert_stamp(url: &str, version: i64) -> Result<(), sqlx::Error> {
    let pool = admin_pool(url).await;
    let r = sqlx::query("INSERT INTO schema_version (version) VALUES ($1)")
        .bind(i32::try_from(version).expect("fits int4"))
        .execute(&pool)
        .await
        .map(|_| ());
    pool.close().await;
    r
}

/// Plant a POISONED ledger: drop the bounding CHECK (simulating a legacy
/// pre-v92 cluster), then stamp `value` above the ceiling.
async fn poison(url: &str, value: i64) {
    let pool = admin_pool(url).await;
    sqlx::query("ALTER TABLE schema_version DROP CONSTRAINT IF EXISTS schema_version_bounded")
        .execute(&pool)
        .await
        .expect("drop the bounding constraint to simulate a legacy cluster");
    sqlx::query("DELETE FROM schema_version")
        .execute(&pool)
        .await
        .expect("clear schema_version");
    sqlx::query("INSERT INTO schema_version (version) VALUES ($1)")
        .bind(i32::try_from(value).expect("fits int4"))
        .execute(&pool)
        .await
        .expect("plant the poison stamp");
    pool.close().await;
}

/// Greenfield connect bounds the ledger: the `schema_version_bounded` CHECK is
/// present and an out-of-band INSERT is refused at the boundary.
#[tokio::test]
async fn pg_greenfield_connect_bounds_schema_version_2555() {
    let Some(admin_url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset (role needs CREATEDB)");
        return;
    };
    let scratch = ScratchDb::create(&admin_url, "bound").await;

    let store = PostgresStore::connect(&scratch.url)
        .await
        .expect("greenfield connect must succeed");
    assert_eq!(
        store.schema_version().await.expect("schema_version"),
        tip(),
        "greenfield connect must land on the ladder tip"
    );
    drop(store);

    assert!(
        has_bound_constraint(&scratch.url).await,
        "greenfield connect must retrofit the schema_version_bounded CHECK"
    );

    // An out-of-band stamp is refused by the CHECK; an at-ceiling value is in band.
    let over = try_insert_stamp(&scratch.url, ceiling() + 1).await;
    assert!(
        over.is_err(),
        "a stamp above the ceiling must be rejected by the CHECK"
    );
    let at = try_insert_stamp(&scratch.url, ceiling()).await;
    assert!(at.is_ok(), "a stamp at the ceiling is in band: {at:?}");

    scratch.destroy().await;
}

/// A POISONED ledger (a stamp above the ceiling on a legacy cluster) is refused
/// with the NEW typed error, NOT the plain #2445 downgrade DENY.
#[tokio::test]
async fn pg_poisoned_ledger_refuses_with_typed_error_2555() {
    let Some(admin_url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset (role needs CREATEDB)");
        return;
    };
    let scratch = ScratchDb::create(&admin_url, "poison").await;

    // Bring it to the tip, then poison it like a legacy pre-CHECK cluster.
    PostgresStore::connect(&scratch.url)
        .await
        .expect("greenfield connect must succeed");
    poison(&scratch.url, 2_147_483_647).await; // i32::MAX

    let err = PostgresStore::connect(&scratch.url)
        .await
        .err()
        .expect("a poisoned ledger must be REFUSED");
    assert!(
        matches!(err, StoreError::SchemaVersionPoisoned { .. }),
        "the refusal must be the TYPED poison verdict, not a schema-ahead downgrade \
         or a generic fault: {err:?}"
    );
    assert_eq!(
        err.code(),
        ai_memory::errors::error_codes::SCHEMA_VERSION_POISONED
    );
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("poison"),
        "names the poison state: {msg}"
    );

    scratch.destroy().await;
}
