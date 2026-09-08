// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3535 — the postgres twin of [`crate::storage::bind_agent_api_key`]:
//! bind a per-agent api-key digest to an agent, REFUSING when that digest is
//! already bound to a DIFFERENT agent.
//!
//! # The defect this closes (#3474 advisory 3)
//!
//! `agent_api_keys` is keyed by `sha256(token)`, and both adapters used to
//! bind with an upsert that overwrote the row's `agent_id` — sqlite
//! `INSERT OR REPLACE`, postgres `ON CONFLICT (token_sha256) DO UPDATE SET
//! agent_id = EXCLUDED.agent_id`. Re-binding a token that already belonged to
//! another principal therefore MOVED the binding: one live bearer credential
//! stopped authenticating as A and started authenticating as B, with no
//! signal to either, no second principal consulted, and nothing on the signed
//! chain recording that a binding had moved. On a fleet-reachable admin route
//! that is a principal-substitution primitive; on the CLI it is a paste error
//! that silently deletes an enrolment. Refusing is the fail-closed side and
//! costs an operator one error message.
//!
//! # Why it is its own module
//!
//! `src/store/postgres.rs` sits at its `qual_10_module_size_ceiling` budget,
//! and the lane brief mandates a submodule over a private ceiling bump — the
//! same reason `postgres/api_key_revoke_3529.rs` and
//! `postgres/federation_3075.rs` exist. The wiring is theirs: an
//! `impl PostgresStore` block whose method the trait arm in `postgres.rs`
//! forwards to.
//!
//! # Why a transaction with the registry advisory lock
//!
//! The decision needs to distinguish THREE outcomes, and a single upsert
//! cannot:
//!
//! * `ON CONFLICT DO NOTHING` reports zero rows for BOTH "already bound to
//!   this same agent" (an idempotent success) and "bound to someone else" (a
//!   refusal), and answering "enrolled" for a token that authenticates as a
//!   different principal is a WRONG answer, not merely an imprecise one;
//! * `ON CONFLICT DO UPDATE … WHERE agent_id = EXCLUDED.agent_id` does
//!   distinguish them by `rows_affected`, but it also WRITES on the
//!   idempotent path, which moves `bound_at` — the recorded enrolment instant
//!   — on every retry. The sqlite SSOT keeps that instant, so this twin must
//!   too or the two backends disagree about a forensic fact.
//!
//! So: read the incumbent owner, branch, and INSERT only when there is none —
//! inside one transaction that first takes
//! [`PG_AGENT_API_KEY_REGISTRY_LOCK_KEY`], the SAME advisory lock the #3529
//! last-key revoke takes. `SELECT … FOR UPDATE` would not do: it locks only
//! rows that already exist, so two concurrent binds of the same NEW digest
//! would both see no row. The advisory lock makes the whole check-and-act
//! mutually exclusive independently of the isolation level, and is released
//! by COMMIT or ROLLBACK with no cleanup path to leak.

use crate::storage::BindApiKeyOutcome;

use super::api_key_revoke_3529::PG_AGENT_API_KEY_REGISTRY_LOCK_KEY;
use super::{PostgresStore, StoreResult, to_store_err};

impl PostgresStore {
    /// #3535 — the transactional bind. Returns
    /// [`BindApiKeyOutcome::DigestBoundToAnotherAgent`] WITHOUT writing
    /// anything when the digest already belongs to a different agent, and
    /// [`BindApiKeyOutcome::AlreadyBoundToSameAgent`] — also without writing —
    /// when the same pair is re-asserted.
    ///
    /// Wave-2 B7' — the record-stop gate is taken HERE, in the function that
    /// owns the `INSERT`, so the structural scan sees it on the write. The
    /// trait arm in `postgres.rs` gates as well: the B7' PARITY scan reads
    /// that file for the twin of the gated sqlite `bind_agent_api_key`, and a
    /// gate it cannot see is a gate it must assume is missing.
    ///
    /// # Errors
    ///
    /// Surfaces the record-stop refusal and any transaction / lock / query
    /// failure.
    pub(super) async fn bind_agent_api_key_pg(
        &self,
        agent_id: &str,
        token_sha256: &str,
    ) -> StoreResult<BindApiKeyOutcome> {
        const CTX: &str = "bind_agent_api_key";
        self.gate_record_stop().await?;
        let now = chrono::Utc::now().to_rfc3339();
        let mut tx = self.pool.begin().await.map_err(|e| to_store_err(CTX, e))?;
        super::pg_advisory_xact_lock_key(&mut tx, PG_AGENT_API_KEY_REGISTRY_LOCK_KEY)
            .await
            .map_err(|e| to_store_err(CTX, e))?;
        let incumbent: Option<(String,)> =
            sqlx::query_as("SELECT agent_id FROM agent_api_keys WHERE token_sha256 = $1")
                .bind(token_sha256)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| to_store_err(CTX, e))?;
        if let Some((owner,)) = incumbent {
            // Explicit rollback on both arms, so "nothing was written" is a
            // decision in the code rather than a side effect of dropping the
            // transaction.
            tx.rollback().await.map_err(|e| to_store_err(CTX, e))?;
            return Ok(if owner == agent_id {
                BindApiKeyOutcome::AlreadyBoundToSameAgent
            } else {
                BindApiKeyOutcome::DigestBoundToAnotherAgent
            });
        }
        sqlx::query(
            "INSERT INTO agent_api_keys (token_sha256, agent_id, bound_at)
             VALUES ($1, $2, $3)",
        )
        .bind(token_sha256)
        .bind(agent_id)
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err(CTX, e))?;
        tx.commit().await.map_err(|e| to_store_err(CTX, e))?;
        Ok(BindApiKeyOutcome::Bound)
    }
}
