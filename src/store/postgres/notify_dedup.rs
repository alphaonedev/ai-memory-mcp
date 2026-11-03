// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8487 — postgres funnel for the `notify_dedup` table (the sender
//! idempotency key on `memory_notify`). Its own module because `postgres.rs`
//! is near its qual_10 budget.
//!
//! The dedup row is written by [`insert_in_tx`] INSIDE the transaction
//! `store_with_embedding_inner` already holds for the inbox row and the quota
//! records, so the three commit or roll back together. The probe runs on the
//! pool BEFORE that transaction (a hit or conflict charges and writes
//! nothing). A concurrent retry that committed first surfaces as a unique
//! violation (SQLSTATE 23505) on the plain `INSERT`; [`PostgresStore::notify_keyed`]
//! re-probes on a fresh query and answers it as a hit. Any other probe or
//! insert error is a typed store error, the transaction rolls back (the quota
//! with it), and nothing is written: fail closed.

use super::{PostgresStore, StoreError, StoreResult, to_store_err};
use crate::notify_dedup::{DedupVerdict, classify};
use sqlx::{PgPool, Postgres, Row, Transaction};

/// SQLSTATE `unique_violation`.
const SQLSTATE_UNIQUE_VIOLATION: &str = "23505";

const SQL_PROBE: &str = "SELECT memory_id, content_digest FROM notify_dedup \
                         WHERE sender = $1 AND target = $2 AND key = $3";
const SQL_INSERT: &str = "INSERT INTO notify_dedup \
                          (sender, target, key, memory_id, content_digest, created_at) \
                          VALUES ($1, $2, $3, $4, $5, $6)";

/// The sender-scoped identity of one keyed delivery and its fingerprint.
#[derive(Debug, Clone, Copy)]
pub(super) struct DedupRow<'a> {
    /// The server-resolved caller.
    pub sender: &'a str,
    /// The recipient agent id.
    pub target: &'a str,
    /// The validated (trimmed) idempotency key.
    pub key: &'a str,
    /// [`crate::notify_dedup::content_digest`] of the delivery.
    pub digest: &'a str,
}

/// Probe `(sender, target, key)` on the pool.
pub(super) async fn probe(pool: &PgPool, d: &DedupRow<'_>) -> StoreResult<DedupVerdict> {
    let row = sqlx::query(SQL_PROBE)
        .bind(d.sender)
        .bind(d.target)
        .bind(d.key)
        .fetch_optional(pool)
        .await
        .map_err(|e| to_store_err("notify_dedup probe", e))?;
    let found = row
        .map(|r| {
            Ok::<_, sqlx::Error>((
                r.try_get::<String, _>("memory_id")?,
                r.try_get::<String, _>("content_digest")?,
            ))
        })
        .transpose()
        .map_err(|e| to_store_err("notify_dedup probe read", e))?;
    Ok(classify(found, d.digest))
}

/// Insert the dedup row inside the caller's transaction (plain `INSERT`, no
/// `ON CONFLICT`: a duplicate must abort the transaction so the inbox row
/// rolls back with it).
pub(super) async fn insert_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    d: &DedupRow<'_>,
    memory_id: &str,
    created_at: &str,
) -> StoreResult<()> {
    sqlx::query(SQL_INSERT)
        .bind(d.sender)
        .bind(d.target)
        .bind(d.key)
        .bind(memory_id)
        .bind(d.digest)
        .bind(created_at)
        .execute(&mut **tx)
        .await
        .map_err(|e| to_store_err("insert notify_dedup", e))?;
    Ok(())
}

/// `true` when `e` is the dedup insert losing a concurrent-retry race.
fn is_unique_violation(e: &StoreError) -> bool {
    matches!(
        e,
        StoreError::BackendUnavailable {
            sqlstate: Some(code),
            ..
        } if code == SQLSTATE_UNIQUE_VIOLATION
    )
}

/// What a keyed delivery resolved to before any write was attempted, or after
/// a lost race.
pub(super) enum Resolved {
    /// Answer from the stored row.
    Hit(String),
    /// Nothing stored under the key: proceed to insert.
    Miss,
}

fn resolve(v: DedupVerdict) -> StoreResult<Resolved> {
    match v {
        DedupVerdict::Miss => Ok(Resolved::Miss),
        DedupVerdict::Hit { id } => Ok(Resolved::Hit(id)),
        DedupVerdict::Conflict { id } => Err(StoreError::Conflict { id }),
    }
}

impl PostgresStore {
    /// Pre-write probe: a hit or conflict answers without charging or
    /// writing.
    pub(super) async fn notify_dedup_preflight(&self, d: &DedupRow<'_>) -> StoreResult<Resolved> {
        resolve(probe(&self.pool, d).await?)
    }

    /// After a failed keyed insert: a unique violation is a concurrent retry
    /// that committed first, so re-probe and answer it as a hit (or a
    /// conflict); anything else is the original error, unchanged.
    pub(super) async fn notify_dedup_after_failure(
        &self,
        d: &DedupRow<'_>,
        err: StoreError,
    ) -> StoreResult<String> {
        if !is_unique_violation(&err) {
            return Err(err);
        }
        match resolve(probe(&self.pool, d).await?)? {
            Resolved::Hit(id) => Ok(id),
            Resolved::Miss => Err(err),
        }
    }
}
