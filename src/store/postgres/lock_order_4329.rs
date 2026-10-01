// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4329 / #4330 — bulk `forget` and the `run_gc` evict sweep lock
//! their `memories` victim rows in ONE canonical order: ascending bytewise id
//! (`ORDER BY id COLLATE "C" FOR UPDATE`), the order the #4010 containment
//! writers (rewind, auto-stamp) and the #4209 / #4210 paths use
//! (CONCURRENCY-04).
//!
//! # The defect this closes
//!
//! Both funnels ran bare predicate statements (`UPDATE` / `DELETE`, and an
//! unordered `SELECT ... FOR UPDATE`) over a caller- or clock-chosen row set.
//! Postgres takes row locks in execution-plan (heap) order, so an ascending
//! writer on an overlapping pair closed a wait-for cycle and one side was
//! aborted with 40P01: the periodic GC tick failed, or a containment write
//! was aborted for that attempt.
//!
//! # The rule
//!
//! The victim set is read AND locked in one ordered statement at the top of
//! the transaction. Every later statement is bound to that locked id set
//! (`id = ANY($locked)`), so the archived, erased, tombstoned and deleted
//! sets are one set and no later statement can lock a row out of order. A
//! lock or serialization error is returned as the typed store error and the
//! caller's transaction is dropped (rolled back): nothing is partially erased.
//!
//! The same ordering is written locally here, in the same form as the #4209
//! helper, so the two compose and either can land first.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;

use crate::store::StoreResult;

use super::to_store_err;

/// `forget`'s victim set: the ids matching the namespace / tier / token-AND
/// pattern predicate, locked `FOR UPDATE` in ascending bytewise id order.
///
/// # Errors
///
/// [`crate::store::StoreError::BackendUnavailable`] on any query error,
/// including a 40P01 / 55P03 (the caller's retry funnel owns 40P01).
pub(super) async fn lock_forget_set(
    conn: &mut PgConnection,
    namespace: Option<&str>,
    tier: Option<&str>,
    pattern: Option<&str>,
) -> StoreResult<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(SQL_LOCK_FORGET_SET)
        .bind(namespace)
        .bind(tier)
        .bind(pattern)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| to_store_err("forget lock victim set", e))?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// `run_gc`'s victim set: every row expired before `now`, as
/// `(id, namespace, agent_id)`, locked `FOR UPDATE` in ascending bytewise id
/// order.
///
/// # Errors
///
/// As [`lock_forget_set`].
pub(super) async fn lock_expired_set(
    conn: &mut PgConnection,
    now: DateTime<Utc>,
) -> StoreResult<Vec<(String, String, Option<String>)>> {
    sqlx::query_as(SQL_LOCK_EXPIRED_SET)
        .bind(now)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| to_store_err("gc lock evict victims", e))
}

/// `$1` namespace, `$2` tier, `$3` pattern: the exact `forget` predicate.
pub(super) const SQL_LOCK_FORGET_SET: &str = "SELECT id FROM memories \
     WHERE ($1::text IS NULL OR namespace = $1) \
       AND ($2::text IS NULL OR tier = $2) \
       AND ($3::text IS NULL OR tsv @@ plainto_tsquery('english', $3)) \
     ORDER BY id COLLATE \"C\" FOR UPDATE";

/// `$1` horizon: the exact `run_gc` expiry predicate.
pub(super) const SQL_LOCK_EXPIRED_SET: &str = "SELECT id, namespace, metadata->>'agent_id' FROM memories \
     WHERE expires_at IS NOT NULL AND expires_at < $1 \
     ORDER BY id COLLATE \"C\" FOR UPDATE";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_statements_order_bytewise_and_lock_4329_4330() {
        for sql in [SQL_LOCK_FORGET_SET, SQL_LOCK_EXPIRED_SET] {
            assert!(sql.contains("ORDER BY id COLLATE \"C\" FOR UPDATE"));
        }
    }
}
