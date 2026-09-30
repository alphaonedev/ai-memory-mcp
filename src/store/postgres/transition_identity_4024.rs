// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4024 — a federated action transition's operation identity, recorded in
//! the SAME transaction as the compare-and-swap that applies it (the postgres
//! half of `crate::actions::transition_cas_once`).
//!
//! A row in `action_transition_nonces` (schema v101) means exactly one thing:
//! the transition `(action_id, nonce)` WAS applied on this node. The identity
//! is inserted iff the CAS applied, inside the transaction that performs it,
//! so a CAS miss, an illegal edge or a not-found writes nothing (the op stays
//! applicable on a retry) and any error rolls back BOTH the state change and
//! the identity. An identity already present is a replay (#1805) and is
//! refused without a write — durably, across cyclic edges and restarts.
//!
//! Its own module because `postgres.rs` is at its qual_10 module-size budget
//! (ceilings only fall).

use super::{PostgresStore, StoreResult, to_store_err};
use crate::actions::{CasOutcome, RemoteCasOutcome, RemoteTransition};

impl PostgresStore {
    /// Row count of `action_transition_nonces` for `stats` / `doctor` (the
    /// table is never pruned below the replay window, so this is the growth
    /// signal). A substrate error propagates; it is never reported as `0`.
    pub(super) async fn count_transition_nonces(&self) -> StoreResult<usize> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM action_transition_nonces")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| to_store_err("stats action_transition_nonces", e))?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    /// Body of `MemoryStore::action_transition_cas_once` for postgres.
    ///
    /// ONE transaction: `FOR UPDATE` row lock, identity probe, CAS, identity
    /// insert. Every transition of the action (local or remote) takes the row
    /// lock first, so two deliveries of the same op serialize and the second
    /// sees the first's committed identity row. Every early return drops the
    /// transaction, which rolls back — nothing written.
    pub(super) async fn transition_cas_once_tx(
        &self,
        t: &RemoteTransition<'_>,
    ) -> StoreResult<RemoteCasOutcome> {
        self.gate_record_stop().await?;
        let (from, to) = (t.from, t.to);
        if !from.can_transition_to(to) {
            return Ok(RemoteCasOutcome::Fresh(CasOutcome::Illegal { from, to }));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| to_store_err("begin action_transition_cas_once tx", e))?;
        let current: Option<String> = sqlx::query_scalar(super::PG_ACTION_STATE_FOR_UPDATE)
            .bind(t.action_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| to_store_err("action_transition_cas_once select", e))?;
        let Some(cs) = current else {
            return Ok(RemoteCasOutcome::Fresh(CasOutcome::NotFound));
        };
        let seen: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM action_transition_nonces \
             WHERE action_id = $1 AND nonce = $2)",
        )
        .bind(t.action_id)
        .bind(t.nonce.as_bytes())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| to_store_err("action_transition_cas_once identity probe", e))?;
        if seen {
            return Ok(RemoteCasOutcome::AlreadyApplied);
        }
        let cur = crate::models::ActionState::from_str(&cs).unwrap_or_default();
        if cur != from {
            return Ok(RemoteCasOutcome::Fresh(CasOutcome::StateMismatch {
                current: cur,
            }));
        }
        sqlx::query(
            "UPDATE actions SET state = $1, claimed_by = $2, updated_at = $3 WHERE id = $4",
        )
        .bind(to.as_str())
        .bind(t.claimed_by)
        .bind(t.now)
        .bind(t.action_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err("action_transition_cas_once update", e))?;
        sqlx::query(
            "INSERT INTO action_transition_nonces \
             (action_id, nonce, from_state, to_state, recorded_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(t.action_id)
        .bind(t.nonce.as_bytes())
        .bind(from.as_str())
        .bind(to.as_str())
        .bind(chrono::Utc::now().timestamp())
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err("action_transition_cas_once identity insert", e))?;
        let row = sqlx::query(super::PG_ACTION_SELECT_BY_ID)
            .bind(t.action_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| to_store_err("action_transition_cas_once refetch", e))?;
        let action = super::pg_row_to_action(&row)?;
        tx.commit()
            .await
            .map_err(|e| to_store_err("commit action_transition_cas_once", e))?;
        Ok(RemoteCasOutcome::Fresh(CasOutcome::Applied(action)))
    }
}
