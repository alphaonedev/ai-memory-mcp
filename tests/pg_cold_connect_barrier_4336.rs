// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! #4336 — the live-Postgres lock-barrier suites must tolerate a cold backend.
//!
//! The interleaving suites (`owner_gate_toctou_pg_3953`, `lifecycle_owner_lock_pg_4053`,
//! `contaminated_stamp_f1_fixes_pg_item3_3266`, `node_local_containment_item3_r2_3266`)
//! park a writer behind a held lock and poll `pg_blocking_pids` until the writer
//! is seen waiting. The writer cannot be seen waiting before it owns a
//! connection, and the first backend started against a freshly created database
//! on a busy host can take far longer than a warm one. The harness gave up after
//! a free-standing 20 s literal while the production pool waits 30 s for a
//! connection, so a healthy first run panicked with `barrier not reached`.
//!
//! Two cells:
//!
//! * the budget is DERIVED from the production pool and lock timeouts and is
//!   strictly larger than the old literal;
//! * a live cell reproduces the cold backend deterministically: a login event
//!   trigger makes every NEW connection to a scratch database take 24 s (more
//!   than the old 20 s deadline, less than the pool's 30 s acquire timeout), and
//!   the barrier must still be reached through the shared budget.
//!
//! Live-PG cell: `#[ignore]`-gated (the postgres-ignored tier), skipped when
//! `AI_MEMORY_TEST_POSTGRES_URL` is unset, scratch database created and dropped
//! by the cell.
#![cfg(all(feature = "sal", feature = "sal-postgres"))]

#[path = "common/pg_barrier.rs"]
mod pg_barrier;

use std::time::{Duration, Instant};

use ai_memory::store::postgres::PostgresStore;
use sqlx::Connection as _;
use sqlx::postgres::PgPoolOptions;

/// The free-standing deadline every barrier used before #4336.
const LEGACY_BARRIER_DEADLINE: Duration = Duration::from_secs(20);
/// Cold-login latency injected for the live cell: past the legacy deadline and
/// inside the pool's 30 s acquire timeout (a legitimate, if slow, connect).
const INJECTED_LOGIN_DELAY_SECS: u64 = 24;
/// Advisory-lock key the holder takes and the writer queues behind.
const LOCK_KEY: i64 = 4336;

/// Swap the database name in a postgres URL, preserving the query string
/// (this tier pins `sslmode=verify-full` + a CA path in it).
fn with_database(url: &str, db: &str) -> String {
    let (base, query) = url.split_once('?').map_or((url, ""), |(b, q)| (b, q));
    let trimmed = base.trim_end_matches('/');
    let cut = trimmed.rfind('/').expect("postgres url has a path segment");
    let mut out = format!("{}/{db}", &trimmed[..cut]);
    if !query.is_empty() {
        out.push('?');
        out.push_str(query);
    }
    out
}

#[test]
fn barrier_budget_covers_the_pool_acquire_and_lock_budgets_4336() {
    let acquire = Duration::from_secs(ai_memory::store::PoolConfig::default().acquire_timeout_secs);
    let lock = Duration::from_secs(ai_memory::store::postgres::DEFAULT_LOCK_TIMEOUT_SECS);
    let budget = pg_barrier::barrier_budget();
    assert!(
        budget > LEGACY_BARRIER_DEADLINE,
        "the budget must exceed the old 20 s literal that failed on a cold backend"
    );
    assert!(
        budget >= acquire + lock,
        "a barrier must outlast a connection the pool is still willing to wait for \
         ({acquire:?}) plus the lock wait ({lock:?}); got {budget:?}"
    );
    assert!(
        Duration::from_secs(INJECTED_LOGIN_DELAY_SECS) < acquire,
        "the injected delay must be a connect the pool still accepts"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn barrier_is_reached_when_the_writer_connects_cold_4336() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("SKIP barrier_is_reached_when_the_writer_connects_cold_4336: no live postgres");
        return;
    };
    let db = format!("ai_memory_4336_{}", uuid::Uuid::new_v4().simple());
    let scratch = with_database(&url, &db);
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect admin pool");
    sqlx::raw_sql(&format!("CREATE DATABASE \"{db}\""))
        .execute(&admin)
        .await
        .expect("create scratch database");

    let outcome = run_case(&scratch).await;

    let dropped = sqlx::raw_sql(&format!("DROP DATABASE IF EXISTS \"{db}\" WITH (FORCE)"))
        .execute(&admin)
        .await;
    if let Err(e) = dropped {
        eprintln!("WARN: could not drop scratch database {db}: {e}");
    }
    admin.close().await;
    if let Err(msg) = outcome {
        panic!("{msg}");
    }
}

async fn run_case(scratch: &str) -> Result<(), String> {
    let store = PostgresStore::connect(scratch)
        .await
        .map_err(|e| format!("connect scratch store: {e}"))?;
    let pool = store.pool().clone();
    // A standalone probe connection opened BEFORE the login delay exists, so the
    // barrier poll itself never needs a cold backend.
    let mut probe = sqlx::PgConnection::connect(scratch)
        .await
        .map_err(|e| format!("probe connect: {e}"))?;

    // Occupy every idle pooled connection so the writer's connection is NEW.
    let mut held = Vec::new();
    while pool.num_idle() > 0 {
        held.push(pool.acquire().await.map_err(|e| format!("acquire: {e}"))?);
    }
    let mut holder = pool
        .begin()
        .await
        .map_err(|e| format!("holder begin: {e}"))?;
    let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *holder)
        .await
        .map_err(|e| format!("holder pid: {e}"))?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(LOCK_KEY)
        .execute(&mut *holder)
        .await
        .map_err(|e| format!("holder lock: {e}"))?;

    // Every NEW login to this database now takes INJECTED_LOGIN_DELAY_SECS.
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION slow_login_4336() RETURNS event_trigger LANGUAGE plpgsql AS \
         $$ BEGIN PERFORM pg_sleep({INJECTED_LOGIN_DELAY_SECS}); END $$; \
         CREATE EVENT TRIGGER slow_login_4336 ON login EXECUTE FUNCTION slow_login_4336();"
    ))
    .execute(&mut probe)
    .await
    .map_err(|e| format!("install login delay (needs a superuser role): {e}"))?;

    let writer = {
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut tx = pool
                .begin()
                .await
                .map_err(|e| format!("writer begin: {e}"))?;
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(LOCK_KEY)
                .execute(&mut *tx)
                .await
                .map_err(|e| format!("writer lock: {e}"))?;
            tx.commit().await.map_err(|e| format!("writer commit: {e}"))
        })
    };

    let started = Instant::now();
    let end = pg_barrier::deadline();
    let blocked_pid = loop {
        let seen: Option<i32> = sqlx::query_scalar(
            "SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) LIMIT 1",
        )
        .bind(holder_pid)
        .fetch_optional(&mut probe)
        .await
        .map_err(|e| format!("barrier probe: {e}"))?;
        if let Some(pid) = seen {
            break pid;
        }
        if tokio::time::Instant::now() >= end {
            return Err(format!(
                "barrier not reached within the shared budget {:?}",
                pg_barrier::barrier_budget()
            ));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let waited = started.elapsed();
    if waited <= LEGACY_BARRIER_DEADLINE {
        return Err(format!(
            "the injected cold login did not delay the writer past the legacy {LEGACY_BARRIER_DEADLINE:?} \
             deadline (observed {waited:?}); the cell proves nothing"
        ));
    }
    if blocked_pid == holder_pid {
        return Err("the holder cannot block itself".to_string());
    }
    holder
        .commit()
        .await
        .map_err(|e| format!("release holder: {e}"))?;
    writer
        .await
        .map_err(|e| format!("join writer: {e}"))?
        .map_err(|e| format!("writer failed: {e}"))?;
    drop(held);
    Ok(())
}
