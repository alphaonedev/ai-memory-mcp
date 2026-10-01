// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4370 — the postgres `apply_remote_signal` override and the signal INSERT it
//! shares with `signal_send`.
//!
//! Own module for the same `qual_10_module_size_ceiling` budget reason as
//! `federation_3075` (the lane brief mandates a submodule over a ceiling bump).
//!
//! ## Why an override exists
//!
//! The trait default composes `signal_get` + `signal_send`. Two deliveries of
//! the SAME signal id can both pass the existence probes (the funnel's and the
//! default's own) and then race to the INSERT; the loser's INSERT fails on the
//! `signals` PRIMARY KEY. Left as an `Err`, the funnel reported a row that
//! exists as `skipped` (a sender keyed on `skipped` keeps resending) and
//! charged quota for storage it never used. The sqlite funnel probes under the
//! single database lock, so its racers serialise and the loser is already a
//! converged no-op. This override makes the postgres loser report the same
//! converged outcome — [`RemoteSignalApply::AlreadyPresent`] — while every
//! other failure still fails closed (CWE-755; rust-1.98 ERRORS-01/ERRORS-15).

use super::{PostgresStore, StoreError, StoreResult, to_store_err};
use crate::store::{CallerContext, MemoryStore, RemoteSignalApply};

/// SQLSTATE `23505` — `unique_violation`.
const SQLSTATE_UNIQUE_VIOLATION: &str = "23505";

/// The name postgres gives the inline `id TEXT NOT NULL PRIMARY KEY` of
/// `signals` (`<table>_pkey`). Asserted against the live catalog by the #4370
/// race cells, so a schema change that renames it fails a test instead of
/// silently turning the loser back into an `Err`.
pub(super) const SIGNALS_PRIMARY_KEY_CONSTRAINT: &str = "signals_pkey";

/// `true` iff `err` is a `unique_violation` raised by the named constraint.
///
/// Precise by construction: the SQLSTATE CODE *and* the constraint NAME the
/// server reports, never a message substring and never "any 23505" (a unique
/// violation on a different index is a genuine failure and stays an error).
pub(super) fn is_unique_violation_on(err: &sqlx::Error, constraint: &str) -> bool {
    err.as_database_error().is_some_and(|db| {
        db.code().as_deref() == Some(SQLSTATE_UNIQUE_VIOLATION)
            && db.constraint() == Some(constraint)
    })
}

impl PostgresStore {
    /// The one `INSERT INTO signals` shared by `signal_send` and
    /// [`Self::apply_remote_signal_pg`]. Returns the raw `sqlx::Error` so the
    /// caller can classify the failure before it is flattened into a
    /// [`StoreError`] (which keeps the SQLSTATE but not the constraint name).
    pub(super) async fn insert_signal_row_pg(
        &self,
        s: &crate::models::Signal,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO signals \
                (id, namespace, from_agent, to_agent, subject, body, signal_type, \
                 in_reply_to, correlation_id, reference_ids, created_at, expires_at, \
                 delivered_at, read_at, acknowledged_at, signature, sender_pubkey) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
        )
        .bind(&s.id)
        .bind(&s.namespace)
        .bind(&s.from_agent)
        .bind(&s.to_agent)
        .bind(&s.subject)
        .bind(s.body.to_string())
        .bind(s.signal_type.as_str())
        .bind(&s.in_reply_to)
        .bind(&s.correlation_id)
        .bind(s.reference_ids.to_string())
        .bind(s.created_at)
        .bind(s.expires_at)
        .bind(s.delivered_at)
        .bind(s.read_at)
        .bind(s.acknowledged_at)
        .bind(&s.signature)
        .bind(&s.sender_pubkey)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    /// #4370 — see [`MemoryStore::apply_remote_signal`]. Same steps and same
    /// errors as the trait default, except that a PRIMARY-KEY loss on the
    /// INSERT (the row exists because a racing delivery stored it first) is the
    /// converged [`RemoteSignalApply::AlreadyPresent`], with nothing written by
    /// THIS call (the failed INSERT is atomic). Any other failure, including a
    /// unique violation on a different constraint, propagates.
    pub(super) async fn apply_remote_signal_pg(
        &self,
        ctx: &CallerContext,
        signal: &crate::models::Signal,
    ) -> StoreResult<RemoteSignalApply> {
        if self.signal_get(ctx, &signal.id).await?.is_some() {
            return Ok(RemoteSignalApply::AlreadyPresent);
        }
        let signed_ok = !signal.signature.is_empty() && crate::signals::verify(signal);
        if !signal.signature.is_empty() && !signed_ok {
            return Err(StoreError::InvalidInput {
                detail: format!("signal {} has an invalid signature", signal.id),
            });
        }
        self.gate_record_stop().await?;
        match self.insert_signal_row_pg(signal).await {
            Ok(()) => Ok(RemoteSignalApply::Inserted(if signed_ok {
                crate::models::AttestLevel::SelfSigned
            } else {
                crate::models::AttestLevel::Unsigned
            })),
            Err(e) if is_unique_violation_on(&e, SIGNALS_PRIMARY_KEY_CONSTRAINT) => {
                Ok(RemoteSignalApply::AlreadyPresent)
            }
            Err(e) => Err(to_store_err("apply_remote_signal", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #4370 — the classifier is precise: SQLSTATE 23505 AND the named
    /// constraint. A unique violation on a DIFFERENT constraint, a non-unique
    /// database error and a non-database error are all "not the loser", so they
    /// stay errors (fail closed). Uses a session-scoped TEMP table on a
    /// single-connection pool, so it leaves nothing behind on any exit path.
    #[tokio::test]
    async fn is_unique_violation_on_matches_code_and_constraint_only_4370() {
        let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
        else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("connect");
        sqlx::query(
            "CREATE TEMP TABLE t4370 (id TEXT NOT NULL PRIMARY KEY, \
             u TEXT CONSTRAINT t4370_u_key UNIQUE, n TEXT NOT NULL)",
        )
        .execute(&pool)
        .await
        .expect("temp table");
        sqlx::query("INSERT INTO t4370 VALUES ('a', 'x', 'n')")
            .execute(&pool)
            .await
            .expect("seed");

        let pk_err = sqlx::query("INSERT INTO t4370 VALUES ('a', 'y', 'n')")
            .execute(&pool)
            .await
            .expect_err("pk violation");
        assert!(is_unique_violation_on(&pk_err, "t4370_pkey"));
        assert!(
            !is_unique_violation_on(&pk_err, "t4370_u_key"),
            "a different constraint name must not match"
        );

        let other_unique = sqlx::query("INSERT INTO t4370 VALUES ('b', 'x', 'n')")
            .execute(&pool)
            .await
            .expect_err("other unique violation");
        assert!(
            !is_unique_violation_on(&other_unique, "t4370_pkey"),
            "a 23505 on another constraint is a genuine failure, not the PK loser"
        );
        assert!(is_unique_violation_on(&other_unique, "t4370_u_key"));

        let not_null = sqlx::query("INSERT INTO t4370 VALUES ('c', 'z', NULL)")
            .execute(&pool)
            .await
            .expect_err("not-null violation");
        assert!(!is_unique_violation_on(&not_null, "t4370_pkey"));

        assert!(!is_unique_violation_on(
            &sqlx::Error::PoolTimedOut,
            "t4370_pkey"
        ));
    }
}
