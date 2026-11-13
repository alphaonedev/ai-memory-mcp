// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7031 N1: the per-test schema cleanup must not hang the job.
//!
//! `PostgresTestEnv`'s drop-time guard runs `DROP SCHEMA ... CASCADE` while it
//! blocks the single-threaded test runtime. A connection of the same test
//! process that is still `idle in transaction` (sqlx rolls a dropped
//! `Transaction` back lazily) holds a lock that `DROP SCHEMA` needs, so the
//! drop waited forever. These cells pin the three parts of the fix:
//!
//! 1. the hang class itself: a held transaction makes the drop wait on a lock
//!    (the guard drop finishes once the transaction ends);
//! 2. `drop_schema_bounded` fails within its `lock_timeout` instead of waiting;
//! 3. `PostgresTestEnv::finish` closes the pools first, so a lazily rolled
//!    back transaction no longer blocks the drop.

#![cfg(feature = "sal-postgres")]

mod common;

use common::postgres_env::{CleanupError, PostgresTestEnv, drop_schema_bounded};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::time::{Duration, Instant};

const WAIT_CEILING: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(100);

async fn scoped_pool(env: &PostgresTestEnv) -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(env.url())
        .await
        .expect("connect scoped pool");
    sqlx::query("CREATE TABLE held (id int)")
        .execute(&pool)
        .await
        .expect("create table in the test schema");
    pool
}

async fn schema_exists(env: &PostgresTestEnv) -> bool {
    let probe = PgPoolOptions::new()
        .max_connections(1)
        .connect(env.base_url())
        .await
        .expect("connect probe");
    let found: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_namespace WHERE nspname = $1")
        .bind(env.schema_name())
        .fetch_one(&probe)
        .await
        .expect("probe schema");
    probe.close().await;
    found > 0
}

#[tokio::test]
async fn cleanup_7031_n1_a_held_transaction_makes_the_drop_wait_then_it_completes() {
    let Some(env) = PostgresTestEnv::new("cleanup_7031_n1_wait").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let pool = scoped_pool(&env).await;
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT * FROM held")
        .fetch_all(&mut *tx)
        .await
        .expect("take a lock on the test schema");
    let schema = env.schema_name().to_owned();
    let base_url = env.base_url().to_owned();
    let dropper = std::thread::spawn(move || drop(env));

    let probe = PgPoolOptions::new()
        .max_connections(1)
        .connect(&base_url)
        .await
        .expect("connect probe");
    let started = Instant::now();
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE wait_event_type = 'Lock' AND query LIKE $1",
        )
        .bind(format!("DROP SCHEMA IF EXISTS {schema}%"))
        .fetch_one(&probe)
        .await
        .expect("probe waiters");
        if waiting > 0 {
            break;
        }
        assert!(
            started.elapsed() < WAIT_CEILING,
            "the DROP SCHEMA never waited on the held transaction"
        );
        tokio::time::sleep(POLL).await;
    }
    tx.commit().await.expect("release the lock");
    let ended = Instant::now();
    while !dropper.is_finished() {
        assert!(
            ended.elapsed() < WAIT_CEILING,
            "the drop did not finish after the lock was released"
        );
        tokio::time::sleep(POLL).await;
    }
    dropper.join().expect("guard drop");
    let gone: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_namespace WHERE nspname = $1")
        .bind(&schema)
        .fetch_one(&probe)
        .await
        .expect("probe schema");
    assert_eq!(gone, 0, "the schema is dropped once the lock is gone");
    probe.close().await;
    pool.close().await;
}

#[tokio::test]
async fn cleanup_7031_n1_the_bounded_drop_fails_inside_its_lock_timeout() {
    let Some(env) = PostgresTestEnv::new("cleanup_7031_n1_bound").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let pool = scoped_pool(&env).await;
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT * FROM held")
        .fetch_all(&mut *tx)
        .await
        .expect("take a lock on the test schema");

    let started = Instant::now();
    let refused = drop_schema_bounded(env.base_url(), env.schema_name(), "2s").await;
    let waited = started.elapsed();
    match refused {
        Err(CleanupError::Drop(message)) => assert!(
            message.contains("lock timeout"),
            "the failure names the lock timeout: {message}"
        ),
        other => panic!("expected a lock-timeout failure, got {other:?}"),
    }
    assert!(
        waited < Duration::from_secs(20),
        "the drop failed after {waited:?}, not inside the 2s lock_timeout"
    );
    assert!(
        schema_exists(&env).await,
        "a refused drop leaves the schema"
    );

    tx.commit().await.expect("release the lock");
    drop_schema_bounded(env.base_url(), env.schema_name(), "30s")
        .await
        .expect("the drop succeeds once nothing holds the lock");
    env.finish(&[&pool]).await;
}

#[tokio::test]
async fn cleanup_7031_n1_finish_closes_the_pools_so_a_dropped_transaction_cannot_block_the_drop() {
    let Some(env) = PostgresTestEnv::new("cleanup_7031_n1_finish").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let pool = scoped_pool(&env).await;
    {
        let mut tx = pool.begin().await.expect("begin");
        sqlx::query("SELECT * FROM held")
            .fetch_all(&mut *tx)
            .await
            .expect("take a lock on the test schema");
        // Dropped without commit or rollback: sqlx rolls it back lazily.
    }
    let schema_gone = {
        let env_ref = &env;
        let base = env_ref.base_url().to_owned();
        let schema = env_ref.schema_name().to_owned();
        tokio::time::timeout(WAIT_CEILING, async {
            env.finish(&[&pool]).await;
        })
        .await
        .expect("finish must not hang on a dropped transaction");
        let probe = PgPoolOptions::new()
            .max_connections(1)
            .connect(&base)
            .await
            .expect("connect probe");
        let found: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_namespace WHERE nspname = $1")
            .bind(&schema)
            .fetch_one(&probe)
            .await
            .expect("probe schema");
        probe.close().await;
        found == 0
    };
    assert!(schema_gone, "finish dropped the schema");
}
