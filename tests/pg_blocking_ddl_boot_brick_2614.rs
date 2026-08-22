// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#2614] — the blocking-DDL boot-brick class, exercised against a
//! LIVE postgres.
//!
//! # What this proves that a unit test cannot
//!
//! [#2614]'s mechanism is entirely about a real lock manager: a migrate arm
//! that runs blocking DDL on a POOLED connection carries `after_connect`'s
//! `lock_timeout = 5 s`, so ONE ordinary in-flight writer aborts it, the
//! version is never stamped, and `connect()` propagates the error — the daemon
//! cannot boot, identically on every retry. The pure decisions (which SQLSTATE
//! is transient, whether the retry budget fits a supervisor deadline) are
//! pinned by unit tests in `src/store/postgres.rs`. What only a live server can
//! show is the END-TO-END disposition:
//!
//! 1. Under sustained contention the arm REFUSES — bounded, marked, and
//!    naming the operator's moves — instead of hanging or half-applying.
//! 2. NOTHING is half-applied: the DDL and the `schema_version` stamp share
//!    one transaction, so the refused ladder is byte-identically where it was.
//! 3. When the blocking writer goes away, the very next `connect()` succeeds
//!    and the ladder reaches its tip. The refusal is a PAUSE, never a wedge.
//!
//! # Why it runs against a scratch DATABASE
//!
//! The arm under test rewrites `memories`. Doing that on the shared rehearsal
//! tier would take an `ACCESS EXCLUSIVE` lock on a table other suites are
//! using, and would rewind that tier's `schema_version`. The test creates its
//! own database, bootstraps it, and drops it, so it is safe to run
//! concurrently with anything else.
//!
//! # Gating
//!
//! `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL`, and
//! `#[ignore]`d because it deliberately spends the whole bounded
//! lock-acquisition budget (~36 s) proving the refusal is bounded. Run it with
//! `--include-ignored`.
//!
//! [#2614]: https://github.com/alphaonedev/ai-memory-mcp/issues/2614

#![cfg(feature = "sal-postgres")]

mod common;

use std::time::{Duration, Instant};

use ai_memory::store::postgres::PostgresStore;
use sqlx::postgres::PgPoolOptions;

/// Swap the database name in a postgres URL, preserving the query string
/// (this tier carries `sslmode=verify-full` + client-cert paths, so dropping
/// the query would silently change the connection's security posture).
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

#[tokio::test]
#[ignore = "live postgres; deliberately spends the ~36s bounded lock budget"]
async fn a_blocking_ddl_arm_refuses_bounded_under_contention_then_recovers_2614() {
    let Some(url) = common::postgres_url() else {
        eprintln!(
            "SKIP a_blocking_ddl_arm_refuses_bounded_under_contention_then_recovers_2614: \
             set AI_MEMORY_TEST_POSTGRES_URL to a live postgres"
        );
        return;
    };

    let scratch_db = format!("ai_memory_2614_{}", uuid::Uuid::new_v4().simple());
    let scratch_url = with_database(&url, &scratch_db);

    // --- create the scratch database -------------------------------------
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect admin pool");
    // `raw_sql` (the SIMPLE query protocol) on purpose: CREATE/DROP DATABASE
    // cannot run inside a transaction block, and the extended protocol is the
    // one that can wrap a statement in one.
    sqlx::raw_sql(&format!("CREATE DATABASE \"{scratch_db}\""))
        .execute(&admin)
        .await
        .expect("create scratch database");

    let outcome = run_case(&scratch_url).await;

    // --- always drop the scratch database --------------------------------
    let dropped = sqlx::raw_sql(&format!(
        "DROP DATABASE IF EXISTS \"{scratch_db}\" WITH (FORCE)"
    ))
    .execute(&admin)
    .await;
    if let Err(e) = dropped {
        eprintln!("WARN: could not drop scratch database {scratch_db}: {e}");
    }
    admin.close().await;

    if let Err(msg) = outcome {
        panic!("{msg}");
    }
}

/// The body, returning `Err(message)` instead of panicking so the caller can
/// always drop the scratch database first.
#[allow(clippy::too_many_lines)]
async fn run_case(scratch_url: &str) -> Result<(), String> {
    // Hoisted: clippy::items_after_statements. Used when rewinding the
    // ladder in front of `migrate_v67` so a blocking arm has to re-run.
    const REWOUND_TO: i32 = 67;

    // --- 1. bootstrap the scratch database to the ladder tip -------------
    let store = PostgresStore::connect(scratch_url)
        .await
        .map_err(|e| format!("bootstrap connect failed: {e}"))?;
    drop(store);

    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(scratch_url)
        .await
        .map_err(|e| format!("connect scratch pool: {e}"))?;

    let tip: i32 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
        .fetch_one(&pool)
        .await
        .map_err(|e| format!("read tip: {e}"))?;

    // --- 2. rewind the ladder so a BLOCKING arm has to re-run ------------
    //
    // `migrate_locked` selects arms by `MAX(version)`, so removing every stamp
    // at or above 67 puts the ladder back in front of `migrate_v67` — an
    // `ADD COLUMN ... GENERATED ALWAYS AS ... STORED` add, i.e. a full-table
    // rewrite under ACCESS EXCLUSIVE, and the arm whose "pure additive" prose
    // hid it from #2614's own audit list.
    sqlx::query("DELETE FROM schema_version WHERE version >= $1")
        .bind(REWOUND_TO)
        .execute(&pool)
        .await
        .map_err(|e| format!("rewind ladder: {e}"))?;

    // --- 3. hold ONE ordinary in-flight transaction on `memories` --------
    //
    // A held SELECT, i.e. `ACCESS SHARE`. Two reasons it is the right blocker
    // and not a weaker one:
    //
    // * It is SHARPER than the issue's framing. #2614 says "a single ordinary
    //   concurrent writer"; `ACCESS SHARE` shows that an idle-in-transaction
    //   READER is already enough to brick the boot, because `ACCESS EXCLUSIVE`
    //   conflicts with every lock mode there is.
    // * It isolates the arm under test. A held INSERT takes `ROW EXCLUSIVE`,
    //   which also conflicts with the `SHARE` that `CREATE INDEX IF NOT
    //   EXISTS` takes — so it would abort the idempotent BOOTSTRAP replay
    //   before the ladder was ever reached, and this test would be asserting
    //   about a different statement. `ACCESS SHARE` conflicts with `ACCESS
    //   EXCLUSIVE` ONLY, so bootstrap sails through and the blocking-DDL arm
    //   is the first thing that has to wait.
    let mut blocker = pool
        .begin()
        .await
        .map_err(|e| format!("begin blocking reader: {e}"))?;
    let _held: Option<(String,)> = sqlx::query_as("SELECT id FROM memories LIMIT 1")
        .fetch_optional(&mut *blocker)
        .await
        .map_err(|e| format!("blocking select: {e}"))?;

    // --- 4. a boot under contention must REFUSE, bounded and marked ------
    let started = Instant::now();
    let refused = PostgresStore::connect(scratch_url).await;
    let elapsed = started.elapsed();

    let Err(e) = refused else {
        return Err(
            "connect() SUCCEEDED while an open transaction held `memories` — the \
             blocking-DDL arm did not take its ACCESS EXCLUSIVE lock, so this test is \
             no longer exercising #2614"
                .to_string(),
        );
    };
    let detail = e.to_string();
    if !detail.contains("ddl-lock-budget-exhausted") {
        return Err(format!(
            "the refusal must carry the budget-exhausted marker so the ladder-level retry \
             does not re-spend an already-spent budget; got: {detail}"
        ));
    }
    if !detail.contains("lock CONTENTION, not corruption") {
        return Err(format!(
            "the refusal must tell the operator this is contention, not corruption; got: {detail}"
        ));
    }
    // Bounded: 3 attempts x 10 s + 2 s + 4 s backoff = ~36 s. Generous upper
    // bound so a loaded CI host cannot flake it, but far below the unbounded
    // wait the pre-fix `lock_timeout = 0` alternative would have produced.
    if elapsed > Duration::from_secs(90) {
        return Err(format!(
            "the lock-acquisition budget must stay bounded well inside a supervisor start \
             deadline; refusal took {elapsed:?}"
        ));
    }

    // --- 5. NOTHING half-applied -----------------------------------------
    let after_refusal: Option<i32> = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
        .fetch_optional(&pool)
        .await
        .map_err(|e| format!("read version after refusal: {e}"))?
        .flatten();
    if after_refusal >= Some(REWOUND_TO) {
        return Err(format!(
            "a refused arm must leave the ladder exactly where it was (the DDL and the \
             stamp share one transaction); got MAX(version) = {after_refusal:?}"
        ));
    }

    // --- 6. the refusal is a PAUSE, not a wedge --------------------------
    blocker
        .rollback()
        .await
        .map_err(|e| format!("release the blocking transaction: {e}"))?;

    let recovered = PostgresStore::connect(scratch_url)
        .await
        .map_err(|e| format!("connect after the blocker drained must succeed, got: {e}"))?;
    drop(recovered);

    let restored: i32 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
        .fetch_one(&pool)
        .await
        .map_err(|e| format!("read restored version: {e}"))?;
    if restored != tip {
        return Err(format!(
            "the ladder must reach its tip once the writer drains: expected {tip}, got {restored}"
        ));
    }

    pool.close().await;
    Ok(())
}
