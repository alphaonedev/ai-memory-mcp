// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#3519] — the migration/bootstrap advisory-lock wait must never pin
//! a transaction snapshot, exercised against a LIVE postgres.
//!
//! # The defect
//!
//! `PostgresStore::connect` (and the `migrate()` twin) took the cluster-wide
//! `MIGRATION_ADVISORY_LOCK_KEY` with a BLOCKING `SELECT pg_advisory_lock($1)`
//! on a dedicated connection. A peer that lost the race therefore sat INSIDE
//! an in-flight statement — and an in-flight statement holds a transaction
//! snapshot for as long as it runs. Meanwhile the holder's bootstrap body runs
//! `CREATE INDEX CONCURRENTLY` (the v88 list-order self-heal) on a SECOND pool
//! connection, and CIC's phase 2/3 waits for every snapshot-holding
//! transaction to end. The cycle — CIC waits for the waiters, the waiters wait
//! for the session lock, the holder cannot release until the CIC finishes —
//! closes through the APPLICATION, so PostgreSQL's deadlock detector never
//! fires and every process in it hangs forever.
//!
//! Reproduced on the certified tier at 8 concurrent boots against one fresh
//! database: holder `idle`, seven peers `active` in `SELECT
//! pg_advisory_lock($1)`, CIC on `idx_archived_ns_archived_at` waiting on
//! them; 40 minutes with no progress.
//!
//! # What this proves that a unit test cannot
//!
//! The mechanism is entirely inside a real server's snapshot bookkeeping:
//! nothing about it is visible to a mocked or sqlite-backed store. Only a live
//! postgres, a genuinely fresh database (so the CIC arms actually have work to
//! do), and genuinely concurrent connects can show it. So:
//!
//! 1. **Wave 1 — the deadlock itself.** N concurrent in-process
//!    `PostgresStore::connect` calls against ONE fresh database, all inside a
//!    test-level `tokio::time::timeout`. Pre-fix this hangs until the timeout;
//!    post-fix every store connects.
//! 2. **The ladder still ran exactly once, to the tip.** The schema version
//!    equals the tip a serial reference bootstrap produces, and both v88
//!    list-order indexes are `indisvalid` — i.e. the CIC that used to wedge
//!    actually COMPLETED, rather than being skipped into a fail-open.
//! 3. **Wave 2 — the already-migrated path stays fast.** A second wave of N
//!    concurrent connects against the now-migrated database completes well
//!    inside a small budget: the poll-based wait adds no meaningful latency to
//!    the overwhelmingly common no-contention case.
//!
//! A second, server-free arm ([`the_lock_wait_never_uses_a_blocking_pg_advisory_lock_3519`])
//! pins the SHAPE of the fix structurally, so a future edit cannot silently
//! reintroduce the blocking form on either lock path.
//!
//! # Why it runs against a scratch DATABASE
//!
//! The whole point is a FRESH database — the shared rehearsal tier is already
//! migrated, so its bootstrap does no CIC work and the race cannot occur. The
//! test creates its own databases, uses them, and drops them, so it is safe to
//! run concurrently with anything else.
//!
//! [#3519]: https://github.com/alphaonedev/ai-memory-mcp/issues/3519

#![cfg(feature = "sal-postgres")]

mod common;

use std::time::{Duration, Instant};

use ai_memory::store::postgres::PostgresStore;
use sqlx::postgres::PgPoolOptions;

/// How many stores boot concurrently against the one fresh database. Eight is
/// the width the issue's live reproduction used (`--test-threads=8`), and it
/// is comfortably inside this tier's `max_connections` even with every store
/// opening its own pool.
const CONCURRENT_BOOTS: usize = 8;

/// Test-level ceiling on the whole concurrent-boot wave. Pre-fix this wave
/// does not finish at all (the issue's reproduction sat for 40 minutes), so
/// the exact value only has to be generously above a healthy fresh-database
/// ladder and far below "forever".
const WAVE_TIMEOUT: Duration = Duration::from_secs(180);

/// Ceiling on the SECOND wave, where every store finds the database already at
/// the ladder tip. Nothing here should take more than a connect + a handful of
/// catalog probes per store; the budget is loose enough not to flake on a busy
/// CI host but tight enough to catch a wait shape that serialises boots behind
/// a coarse fixed sleep.
const MIGRATED_WAVE_BUDGET: Duration = Duration::from_secs(60);

/// The v88 composite ordering indexes built with `CREATE INDEX CONCURRENTLY`
/// inside the bootstrap, under the advisory lock (the adapter's
/// `LIST_ORDER_INDEXES`, whose doc twin is
/// `migrations/postgres/0045_v88_list_composite_indexes.sql`). These are the
/// statements that deadlocked — the issue's `pg_stat_activity` capture caught
/// the second one mid-wait — so asserting both ended up `indisvalid` proves
/// the CIC ran to COMPLETION rather than being skipped by the arm's fail-open
/// path.
const LIST_ORDER_INDEX_NAMES: &[&str] =
    &["idx_memories_ns_list_order", "idx_archived_ns_archived_at"];

/// Swap the database name in a postgres URL, preserving the query string
/// (this tier carries `sslmode=verify-full` + a CA path, so dropping the query
/// would silently change the connection's security posture).
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

/// Boot [`CONCURRENT_BOOTS`] `PostgresStore`s against `url` at the same time
/// and return how long the whole wave took.
///
/// ## Why one OS thread per store
///
/// Two reasons, one structural and one mechanical.
///
/// * It is the faithful shape. #3519 is about N DAEMONS booting against one
///   cluster during an upgrade window; a thread with its own current-thread
///   runtime and its own `PostgresStore` (hence its own pool) is as close to
///   that as an in-process test gets, and it is the same shape
///   `tests/common/postgres_env.rs` uses to own a session-scoped advisory
///   lock.
/// * `tokio::spawn` cannot take this future. `PostgresStore::connect`
///   installs an `after_connect` hook, whose higher-ranked signature trips
///   rustc's "implementation of `Send` is not general enough" on the spawned
///   future — a well-known HRTB limitation, not a real thread-safety problem.
///   Threads need no `Send` bound on the future at all.
///
/// Results come back over a tokio channel so the CALLER can hold the whole
/// wave inside a `tokio::time::timeout`: a wave that deadlocks must fail the
/// test with a legible message, never hang the suite until CI's job cap.
async fn run_boot_wave(url: &str, label: &str, budget: Duration) -> Result<Duration, String> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Result<(), String>>();
    let started = Instant::now();
    let mut threads = Vec::with_capacity(CONCURRENT_BOOTS);
    for idx in 0..CONCURRENT_BOOTS {
        let url = url.to_string();
        let label = label.to_string();
        let tx = tx.clone();
        threads.push(std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Err(format!("{label} {idx}: build runtime: {e}")));
                    return;
                }
            };
            let outcome = rt.block_on(async {
                PostgresStore::connect(&url)
                    .await
                    .map(|store| {
                        drop(store);
                    })
                    .map_err(|e| format!("{label} {idx}: {e}"))
            });
            let _ = tx.send(outcome);
        }));
    }
    // The loop below ends when it has seen every result; drop the spare
    // sender so a panicking booter closes the channel instead of stalling us.
    drop(tx);

    let collected = tokio::time::timeout(budget, async {
        let mut out = Vec::with_capacity(CONCURRENT_BOOTS);
        while let Some(result) = rx.recv().await {
            out.push(result);
        }
        out
    })
    .await
    .map_err(|_| {
        format!(
            "the {label} wave did not finish within {budget:?} — pre-fix this is the #3519 \
             application-level deadlock: peers parked inside a blocking \
             `SELECT pg_advisory_lock($1)` pin transaction snapshots that the holder's \
             CREATE INDEX CONCURRENTLY then waits on forever, a cycle through the \
             APPLICATION that postgres' deadlock detector cannot see"
        )
    })?;
    let elapsed = started.elapsed();
    for t in threads {
        t.join().map_err(|_| format!("a {label} thread panicked"))?;
    }

    let failures: Vec<String> = collected.into_iter().filter_map(Result::err).collect();
    if !failures.is_empty() {
        return Err(format!(
            "every {label} must connect; {} of {CONCURRENT_BOOTS} failed: {}",
            failures.len(),
            failures.join(" | ")
        ));
    }
    Ok(elapsed)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_boots_on_a_fresh_database_do_not_deadlock_the_ladder_3519() {
    let Some(url) = common::postgres_url() else {
        eprintln!(
            "SKIP concurrent_boots_on_a_fresh_database_do_not_deadlock_the_ladder_3519: \
             set AI_MEMORY_TEST_POSTGRES_URL to a live postgres"
        );
        return;
    };

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let race_db = format!("ai_memory_3519_race_{suffix}");
    let ref_db = format!("ai_memory_3519_ref_{suffix}");
    let race_url = with_database(&url, &race_db);
    let ref_url = with_database(&url, &ref_db);

    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect admin pool");
    // `raw_sql` (the SIMPLE query protocol) on purpose: CREATE/DROP DATABASE
    // cannot run inside a transaction block, and the extended protocol is the
    // one that can wrap a statement in one.
    for db in [&race_db, &ref_db] {
        sqlx::raw_sql(&format!("CREATE DATABASE \"{db}\""))
            .execute(&admin)
            .await
            .expect("create scratch database");
    }

    let outcome = run_case(&race_url, &ref_url).await;

    for db in [&race_db, &ref_db] {
        let dropped = sqlx::raw_sql(&format!("DROP DATABASE IF EXISTS \"{db}\" WITH (FORCE)"))
            .execute(&admin)
            .await;
        if let Err(e) = dropped {
            eprintln!("WARN: could not drop scratch database {db}: {e}");
        }
    }
    admin.close().await;

    if let Err(msg) = outcome {
        panic!("{msg}");
    }
}

/// The body, returning `Err(message)` instead of panicking so the caller can
/// always drop the scratch databases first.
async fn run_case(race_url: &str, ref_url: &str) -> Result<(), String> {
    // --- 0. the tip, from a SERIAL reference bootstrap --------------------
    //
    // Read rather than hard-coded: `CURRENT_SCHEMA_VERSION` is private to the
    // adapter, and pinning a literal here would make this test a second SSOT
    // that drifts every time the ladder grows.
    let reference = PostgresStore::connect(ref_url)
        .await
        .map_err(|e| format!("reference bootstrap failed: {e}"))?;
    drop(reference);
    let ref_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(ref_url)
        .await
        .map_err(|e| format!("connect reference pool: {e}"))?;
    let tip: i32 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
        .fetch_one(&ref_pool)
        .await
        .map_err(|e| format!("read reference tip: {e}"))?;
    ref_pool.close().await;

    // --- 1. N concurrent boots against ONE fresh database ----------------
    //
    // Exactly one of them wins the advisory lock and runs the ladder (CIC
    // included); the other seven must WAIT without pinning a snapshot. Pre-fix
    // this wave never returns.
    let wave_elapsed = run_boot_wave(race_url, "fresh-database boot", WAVE_TIMEOUT).await?;
    eprintln!("#3519: {CONCURRENT_BOOTS} concurrent boots completed in {wave_elapsed:?}");

    // --- 2. the ladder ran, exactly once, to the tip ---------------------
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(race_url)
        .await
        .map_err(|e| format!("connect race pool: {e}"))?;

    let reached: i32 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
        .fetch_one(&pool)
        .await
        .map_err(|e| format!("read race tip: {e}"))?;
    if reached != tip {
        pool.close().await;
        return Err(format!(
            "the concurrently-booted database must reach the same ladder tip as a serial \
             bootstrap: expected {tip}, got {reached}"
        ));
    }
    // The lock serialises the ladder, so every version is stamped exactly
    // once — `schema_version` has a unique key on `version`, so a duplicate
    // would have surfaced as an insert error, but count the rows anyway: a
    // ladder that ran twice under a broken lock would show as a row count
    // that no longer matches the distinct-version count.
    let (rows, distinct): (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), COUNT(DISTINCT version) FROM schema_version")
            .fetch_one(&pool)
            .await
            .map_err(|e| format!("count schema_version rows: {e}"))?;
    if rows != distinct {
        pool.close().await;
        return Err(format!(
            "the ladder must run exactly once under the advisory lock: schema_version has \
             {rows} rows over {distinct} distinct versions"
        ));
    }

    // The CIC statements that used to wedge must have COMPLETED, not been
    // skipped by the arm's fail-open path.
    for name in LIST_ORDER_INDEX_NAMES {
        let valid: Option<bool> = sqlx::query_scalar(
            "SELECT i.indisvalid FROM pg_class c \
             JOIN pg_index i ON i.indexrelid = c.oid \
             WHERE c.relname = $1",
        )
        .bind(name)
        .fetch_optional(&pool)
        .await
        .map_err(|e| format!("probe index {name}: {e}"))?;
        if valid != Some(true) {
            pool.close().await;
            return Err(format!(
                "the v88 index `{name}` must be built and valid after the concurrent wave — \
                 that CREATE INDEX CONCURRENTLY is the statement #3519 deadlocked; got \
                 {valid:?}"
            ));
        }
    }

    // --- 3. the already-migrated wave stays fast -------------------------
    //
    // Every store now finds the ladder at its tip, so the lock is taken and
    // released with no work under it. This is the case that must NOT have
    // regressed into a coarse serialising sleep.
    let migrated = run_boot_wave(race_url, "already-migrated boot", WAVE_TIMEOUT).await;
    pool.close().await;
    let migrated_elapsed = migrated?;
    eprintln!("#3519: {CONCURRENT_BOOTS} already-migrated boots completed in {migrated_elapsed:?}");
    if migrated_elapsed > MIGRATED_WAVE_BUDGET {
        return Err(format!(
            "an already-migrated concurrent wave must stay fast (nothing runs under the \
             lock): took {migrated_elapsed:?}, budget {MIGRATED_WAVE_BUDGET:?}"
        ));
    }

    Ok(())
}

/// Structural twin of the live arm: pins the SHAPE of the #3519 fix so a
/// future edit cannot silently reintroduce a blocking wait on either lock
/// path. Needs no server, so it runs on every `sal-postgres` build.
///
/// Only EXECUTED SQL is inspected — the doc comments on
/// `acquire_migration_advisory_lock` and `INDEX_BUILD_TIMEOUT_MS` quote the
/// blocking form on purpose, to explain what it did.
#[test]
fn the_lock_wait_never_uses_a_blocking_pg_advisory_lock_3519() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/store/postgres.rs"
    ))
    .expect("read src/store/postgres.rs");

    let offenders: Vec<(usize, &str)> = src
        .lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.trim()))
        .filter(|(_, line)| !line.starts_with("//"))
        .filter(|(_, line)| line.contains("SELECT pg_advisory_lock("))
        .collect();
    assert!(
        offenders.is_empty(),
        "#3519: the migration/bootstrap lock must be acquired by POLLING \
         `pg_try_advisory_lock` (each probe its own short statement, so a waiter pins no \
         snapshot for the holder's CREATE INDEX CONCURRENTLY to wait on). A blocking \
         `SELECT pg_advisory_lock(...)` reintroduces the application-level deadlock at: \
         {offenders:?}"
    );

    // ...and the poll-based helper is the ONE thing both lock paths reach.
    // Only the CALL/definition shape (name immediately followed by `(`) is
    // counted, so the doc-comment cross-references do not inflate it: one
    // definition + the bootstrap call site + the `migrate()` call site.
    let prepared = src.matches("prepare_migration_lock_connection(").count();
    assert!(
        prepared >= 3,
        "#3519: both the bootstrap and the migrate() lock paths must route through \
         `prepare_migration_lock_connection` (its definition + two call sites); found \
         {prepared} references"
    );
    // ...and that shared preparer is what polls.
    let polled = src.matches("acquire_migration_advisory_lock(").count();
    assert!(
        polled >= 2,
        "#3519: `prepare_migration_lock_connection` must obtain the lock through the \
         polling `acquire_migration_advisory_lock` (its definition + one call site); found \
         {polled} references"
    );
    // Every exit from a prepared lock connection — success, failed ladder,
    // failed SET, timed-out wait — must go through the one release helper, or
    // a timeout-relaxed connection leaks back into the pool (#3074).
    let released = src.matches("release_migration_advisory_lock(").count();
    assert!(
        released >= 5,
        "#3519 x #3074: both lock paths must release AND close on every exit \
         (definition + two success sites + two acquire-failure sites); found {released} \
         references to `release_migration_advisory_lock`"
    );
}
