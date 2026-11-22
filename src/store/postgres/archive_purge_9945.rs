// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9945 (GA standard 1, no data destruction) — the one postgres funnel of
//! `MemoryStore::archive_purge` (a typed [`RetentionDays`] bound) and
//! `MemoryStore::archive_purge_all` (the explicit operator purge-all).
//!
//! The trait method took `Option<i64>` and ran `None` as an unpredicated
//! `DELETE FROM archived_memories`, so the maintenance loop with an unset
//! `archive_max_days` destroyed the whole archive on every GC tick. The bound
//! is now an [`ArchivePurgeBound`]: [`ArchivePurgeBound::OlderThan`] carries a
//! day count in `1..=36500` and [`ArchivePurgeBound::AllRows`] is reachable
//! only through `archive_purge_all`. Own module for the `qual_10` budget of
//! `postgres.rs`, wired like `parity_3064.rs`.
//!
//! [`RetentionDays`]: crate::validate::RetentionDays

use super::{CallerContext, PostgresStore, StoreError, StoreResult, to_store_err};
use crate::validate::ArchivePurgeBound;

impl PostgresStore {
    /// Delete the archived rows `bound` selects, in the caller's ownership
    /// scope.
    ///
    /// #936 (security-critical, 2026-05-20) — owner-vs-caller gate. The
    /// DELETE is constrained to rows whose `metadata.agent_id` matches the
    /// caller (with the `_inbox/<target>` carve-out: rows where
    /// `metadata.target_agent_id == caller` are also purgeable by the inbox
    /// owner — mirrors the `is_visible_to_caller` visibility predicate). The
    /// operator/admin surface skips the gate by setting
    /// `ctx.bypass_visibility = true` via [`CallerContext::for_admin`], which
    /// the admin role gate at `handlers::admin_role::require_admin`
    /// exclusively controls.
    ///
    /// # Errors
    ///
    /// [`StoreError::Stopped`] when the record plane is stopped,
    /// [`StoreError::InvalidInput`] when the cutoff cannot be formed, and the
    /// mapped sqlx error of the DELETE.
    pub(super) async fn archive_purge_bound(
        &self,
        ctx: &CallerContext,
        bound: ArchivePurgeBound,
    ) -> StoreResult<usize> {
        self.gate_record_stop().await?;
        let cutoff = match bound {
            ArchivePurgeBound::OlderThan(days) => Some(days.cutoff(chrono::Utc::now()).map_err(
                |error| StoreError::InvalidInput {
                    detail: error.to_string(),
                },
            )?),
            ArchivePurgeBound::AllRows => None,
        };
        let caller = ctx.effective_principal();
        let res = match (cutoff, ctx.bypass_visibility) {
            // Admin path — owner-blind. The route's role gate ensures only
            // admin callers reach these arms.
            (Some(cutoff), true) => {
                sqlx::query("DELETE FROM archived_memories WHERE archived_at < $1")
                    .bind(cutoff)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| to_store_err("archive_purge admin", e))?
            }
            (None, true) => sqlx::query("DELETE FROM archived_memories")
                .execute(&self.pool)
                .await
                .map_err(|e| to_store_err("archive_purge admin all", e))?,
            // Owner-scoped path — narrow to rows the caller owns
            // (`metadata.agent_id == caller` OR the inbox-target carve-out
            // `metadata.target_agent_id == caller`).
            (Some(cutoff), false) => sqlx::query(
                "DELETE FROM archived_memories \
                     WHERE archived_at < $1 \
                       AND ( \
                         (metadata->>'agent_id') = $2 OR \
                         (metadata->>'target_agent_id') = $2 \
                       )",
            )
            .bind(cutoff)
            .bind(caller)
            .execute(&self.pool)
            .await
            .map_err(|e| to_store_err("archive_purge owner", e))?,
            (None, false) => sqlx::query(
                "DELETE FROM archived_memories \
                 WHERE \
                   (metadata->>'agent_id') = $1 OR \
                   (metadata->>'target_agent_id') = $1",
            )
            .bind(caller)
            .execute(&self.pool)
            .await
            .map_err(|e| to_store_err("archive_purge owner all", e))?,
        };
        // PERF-07: a DELETE count past usize is unreachable on a 64-bit host;
        // saturate rather than report zero.
        Ok(usize::try_from(res.rows_affected()).unwrap_or(usize::MAX))
    }
}
