// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3529 — the postgres twin of
//! [`crate::storage::revoke_agent_api_key_unless_last`]: revoke every key
//! bound to an agent, but ONLY if that leaves at least one key enrolled
//! somewhere on the deployment.
//!
//! # Why it is its own module
//!
//! `src/store/postgres.rs` sits at its `qual_10_module_size_ceiling` budget,
//! and the lane brief mandates a submodule over a private ceiling bump — the
//! same reason `postgres/parity_3064.rs` and `postgres/federation_3075.rs`
//! exist. The wiring is theirs: an `impl PostgresStore` block whose method the
//! trait arm in `postgres.rs` forwards to.
//!
//! # Why an advisory lock rather than `FOR UPDATE` or one clever statement
//!
//! The hazard (#3474 advisory A1) is a check-then-act race: two concurrent
//! self-revokes by the last two key-holders each observe the other's key,
//! each decide they are not the last, and both apply — leaving ZERO enrolled
//! keys, which makes the identity gate inert in every mode (#1985) with no
//! second approver having authorised it. Closing it on postgres needs the
//! COUNT and the DELETE to be one mutually-exclusive decision.
//!
//! * A single `DELETE … WHERE EXISTS (…)` statement is atomic but cannot
//!   distinguish "the agent had no keys" (an idempotent no-op) from "the
//!   agent held every key" (a refusal): both report zero rows affected, and
//!   answering "revoked, 0 rows" for a credential that is still live is a
//!   WRONG answer, which is strictly worse than a refusal.
//! * A CTE that counts and deletes in one statement shares one snapshot, but
//!   under the pool's `READ COMMITTED` default two concurrent transactions
//!   each see the other's row and both commit — exactly the defect.
//! * `SELECT … FOR UPDATE` locks only rows that already exist; it is no
//!   predicate lock, so it does not serialize against a concurrent INSERT and
//!   the correctness argument rests on `READ COMMITTED` re-check semantics
//!   that a reader has to reconstruct.
//!
//! `pg_advisory_xact_lock` makes the whole check-and-act mutually exclusive
//! across every caller of this seam, independently of the isolation level,
//! and is released by COMMIT or ROLLBACK with no cleanup path to leak. The
//! cost is irrelevant: the table holds at most a few thousand rows and the
//! call rate is "an operator revokes a key". The key is `hashtext`-derived,
//! matching the convention `pg_advisory_lock_action_edges` already uses in
//! `postgres.rs`; a `hashtext` collision with another lock key would only
//! over-serialize two unrelated operators, never admit two concurrent
//! revokes.

use crate::storage::RevokeUnlessLastOutcome;

use super::{PostgresStore, StoreResult, to_store_err};

/// Advisory-lock key serializing the enrolled-api-key registry's
/// check-and-act. Namespaced so it cannot be confused with the per-title /
/// per-namespace create-funnel locks in `postgres.rs`.
const PG_AGENT_API_KEY_REGISTRY_LOCK_KEY: &str = "ai_memory:agent_api_keys:registry";

impl PostgresStore {
    /// #3529 — the transactional check-and-act. Returns
    /// [`RevokeUnlessLastOutcome::WouldEmptyRegistry`] WITHOUT deleting
    /// anything when the target holds every enrolled key.
    ///
    /// Wave-2 B7' — the record-stop gate is taken HERE, in the function that
    /// owns the `DELETE`, so the structural scan sees it on the write and the
    /// sqlite twin (which gates inside the `crate::storage` SSOT) and this one
    /// refuse the same writes.
    ///
    /// # Errors
    ///
    /// Surfaces the record-stop refusal and any transaction / lock / query
    /// failure.
    pub(super) async fn revoke_agent_api_key_unless_last_pg(
        &self,
        agent_id: &str,
    ) -> StoreResult<RevokeUnlessLastOutcome> {
        const CTX: &str = "revoke_agent_api_key_unless_last";
        self.gate_record_stop().await?;
        let mut tx = self.pool.begin().await.map_err(|e| to_store_err(CTX, e))?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(PG_AGENT_API_KEY_REGISTRY_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(|e| to_store_err(CTX, e))?;
        let (total, mine): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE agent_id = $1) FROM agent_api_keys",
        )
        .bind(agent_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| to_store_err(CTX, e))?;
        if mine > 0 && total == mine {
            // Explicit, so the refusal is a decision in the code and not a
            // side effect of dropping the transaction.
            tx.rollback().await.map_err(|e| to_store_err(CTX, e))?;
            return Ok(RevokeUnlessLastOutcome::WouldEmptyRegistry);
        }
        let res = sqlx::query("DELETE FROM agent_api_keys WHERE agent_id = $1")
            .bind(agent_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| to_store_err(CTX, e))?;
        tx.commit().await.map_err(|e| to_store_err(CTX, e))?;
        Ok(RevokeUnlessLastOutcome::Revoked {
            // PERF-07 — a narrowing `as` would silently truncate; the
            // saturating fallback is unreachable for a row count.
            bindings_removed: usize::try_from(res.rows_affected()).unwrap_or(usize::MAX),
        })
    }
}
