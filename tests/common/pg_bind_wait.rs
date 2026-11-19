// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared waiter for sessions parked on the namespace-standard bind lock
//! (#9252).
//!
//! The bind-race suites hold the bind advisory lock in one transaction, start
//! a bind, and must know the bind is PARKED on that lock before they assert
//! that it has not finished. The earlier waiter counted every ungranted
//! advisory lock in the database, so an unrelated advisory waiter satisfied
//! the wait before the bind under test had parked, and the assertion that
//! followed passed without proving anything (the false green #9252 closes).
//!
//! This helper counts only ungranted waits on ONE advisory key. The lock is
//! taken as `pg_advisory_xact_lock(hashtext(key))`, which resolves to the
//! single-bigint form: the `int4` hash is widened to `bigint`, and `pg_locks`
//! stores that `bigint` split over `classid` (high 32 bits), `objid` (low 32
//! bits) and `objsubid = 1`. The probe rebuilds the same split from
//! `hashtext($1)` inside the database, so it matches exactly the lock the
//! production code takes and no other.
//!
//! Take it with the `#[path]` leaf idiom (no `mod common;` weight):
//!
//! ```ignore
//! #[path = "common/pg_bind_wait.rs"]
//! mod pg_bind_wait;
//! ```

#![allow(dead_code)]

use std::time::Duration;

use ai_memory::ns_standard_ancestor::PG_STANDARD_BIND_LOCK_KEY;

/// Poll interval between two `pg_locks` probes.
pub const BIND_WAIT_POLL: Duration = Duration::from_millis(10);

/// Bound on the wait for the bind sessions to park. A ceiling only: the wait
/// returns the moment the count is reached.
pub const BIND_WAIT_DEADLINE: Duration = Duration::from_secs(30);

/// Number of ungranted `pg_locks` entries on the advisory key `hashtext(key)`
/// in the current database. The `bigint` split is described in the module
/// docs; `objsubid = 1` marks the single-bigint form (the two-int form uses 2).
const COUNT_KEYED_WAITERS_SQL: &str = "\
SELECT count(*) FROM pg_locks l \
  JOIN pg_database d ON d.oid = l.database \
 WHERE l.locktype = 'advisory' AND NOT l.granted \
   AND d.datname = current_database() \
   AND l.objsubid = 1 \
   AND l.classid::bigint = ((hashtext($1)::bigint >> 32) & 4294967295) \
   AND l.objid::bigint = (hashtext($1)::bigint & 4294967295)";

/// Waits until at least `want` sessions are parked on the advisory key `key`,
/// or `deadline` passes. Fails with the named `setup error` text; it never
/// returns `Ok` for a wait on any other lock.
///
/// # Errors
/// The `pg_locks` probe failed, or fewer than `want` sessions parked on `key`
/// within `deadline`.
pub async fn await_advisory_waiters(
    pool: &sqlx::PgPool,
    key: &str,
    want: i64,
    deadline: Duration,
) -> anyhow::Result<()> {
    let give_up = tokio::time::Instant::now() + deadline;
    loop {
        let waiting: i64 = sqlx::query_scalar(COUNT_KEYED_WAITERS_SQL)
            .bind(key)
            .fetch_one(pool)
            .await
            .map_err(|e| anyhow::anyhow!("setup error: pg_locks probe failed: {e}"))?;
        if waiting >= want {
            return Ok(());
        }
        if tokio::time::Instant::now() >= give_up {
            anyhow::bail!(
                "setup error: only {waiting} of {want} sessions ever parked on the advisory key"
            );
        }
        tokio::time::sleep(BIND_WAIT_POLL).await;
    }
}

/// [`await_advisory_waiters`] on the namespace-standard bind lock, with the
/// shared [`BIND_WAIT_DEADLINE`]. Panics with the named setup error.
///
/// # Panics
/// The bind sessions did not park on the bind lock within the deadline.
pub async fn await_bind_waiters(pool: &sqlx::PgPool, want: i64) {
    if let Err(setup) =
        await_advisory_waiters(pool, PG_STANDARD_BIND_LOCK_KEY, want, BIND_WAIT_DEADLINE).await
    {
        panic!("{setup}: the binds never parked on the bind lock");
    }
}
