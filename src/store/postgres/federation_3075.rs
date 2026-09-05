// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3075 lane L-PGP — postgres SAL implementations for the federation
//! `/sync/push` subcollections that were bucketed `unsupported_on_postgres`.
//!
//! These live in their own module rather than in `src/store/postgres.rs`
//! because that file sits at its `qual_10_module_size_ceiling` budget; the lane
//! brief mandates a submodule over a private ceiling bump. The wiring mirrors
//! `postgres/parity_3064.rs` and `postgres/pubkey_history.rs`: an
//! `impl PostgresStore` block whose methods the trait arms in `postgres.rs`
//! forward to.
//!
//! ## Authorization model on these lanes (read this before adding a method)
//!
//! Every method here is a FEDERATION-RECEIVE apply, reached only after the
//! `/sync/push` funnel has rendered the lane's `receive_auth` verdict on the
//! attested peer's scope. That verdict — not a local owner/tenant predicate —
//! IS the authorization, exactly as on the sqlite receiver, whose inline loops
//! apply these lanes through owner-BLIND `db::*` free functions. An adapter
//! that added a tenant predicate here would make the postgres receiver refuse
//! rows the sqlite receiver applies: a SILENT cross-backend divergence of the
//! #2488 shape, whose symptom is two peers disagreeing about what exists.
//!
//! The bypass is therefore forced STRUCTURALLY (`op_ctx.bypass_visibility =
//! true`) rather than trusted from the caller, so no present or future call
//! site can make one of these lanes owner-scoped on one backend only. It grants
//! no reach a peer did not already have — the peer-scope gate has already run,
//! and nothing here returns a row to the peer.
//!
//! Every write reuses the EXISTING gated funnel (`archive_by_ids` /
//! `archive_restore`), so the link snapshot (#1771/#3161), the namespace-meta
//! sever (#3272), the governance pre-write hook, the cid re-mint (#1825), the
//! AGE unprojection and the record-stop gate all still run. There is no
//! duplicated archive/restore SQL in this module to drift from them.

use super::{PostgresStore, StoreResult, to_store_err};
// `archive_by_ids` / `archive_restore` are TRAIT methods — the trait must be in
// scope to compose them, which is the point: these federated applies reuse the
// already-gated local funnels rather than duplicating archive/restore SQL.
use crate::store::{CallerContext, MemoryStore};

/// The #1821 / G30 forget-tombstone existence probe.
///
/// One SSOT for the three postgres sites that ask it (`apply_remote_memory`'s
/// and `merge_inbound`'s LWW resurrection guards, and the `restores[]` gate
/// below). Hoisted per pm-v3.1: the identical predicate was previously spelled
/// as a literal at each site, and a tombstone probe that drifted between the
/// inbound-write guard and the restore guard would re-open the resurrection
/// vector on whichever site was missed.
pub(super) const SQL_FORGET_TOMBSTONE_EXISTS: &str =
    "SELECT EXISTS(SELECT 1 FROM forget_tombstones WHERE memory_id = $1)";

/// `SELECT namespace FROM archived_memories WHERE id = $1` — the SCALAR
/// projection behind the `restores[]` scope gate. Never a full-row read: the
/// full-row archive mapper is pinned to a fail-closed at-rest decrypt, so a
/// gate built on it would make a row with an unopenable envelope permanently
/// un-restorable by federation (#2488, applied to the archive table).
const SQL_ARCHIVED_NAMESPACE_BY_ID: &str = "SELECT namespace FROM archived_memories WHERE id = $1";

impl PostgresStore {
    /// #3075 — see [`crate::store::MemoryStore::archived_namespace_by_id`].
    ///
    /// FAIL-CLOSED contract: a query error PROPAGATES. Folding it into
    /// `Ok(None)` would report an unresolvable row as "provably no archived
    /// row", which is exactly the input the stored-vs-claimed bypass needs.
    pub(super) async fn archived_namespace_by_id_pg(
        &self,
        id: &str,
    ) -> StoreResult<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(SQL_ARCHIVED_NAMESPACE_BY_ID)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| to_store_err("archived_namespace_by_id", e))?;
        Ok(row.map(|(namespace,)| namespace))
    }

    /// #3075 — see [`crate::store::MemoryStore::apply_remote_archive`].
    ///
    /// Composes the already-gated [`PostgresStore::archive_by_ids`] on a
    /// forced-bypass context with the shared `sync_push` reason marker, so the
    /// federated archive is byte-for-byte the local archive minus the #3193
    /// caller-owns predicate (which this lane must not apply — see the module
    /// doc). `archive_by_ids` counts ONLY ids whose live row was actually
    /// moved, so `moved > 0` is exactly the sqlite `db::archive_memory` boolean:
    /// `false` for an id with no live row, which the receive loop reports as the
    /// lane's documented `noop`.
    pub(super) async fn apply_remote_archive_pg(
        &self,
        ctx: &CallerContext,
        id: &str,
    ) -> StoreResult<bool> {
        let mut op_ctx = ctx.clone();
        op_ctx.bypass_visibility = true;
        let moved = self
            .archive_by_ids(
                &op_ctx,
                std::slice::from_ref(&id.to_string()),
                Some(crate::models::field_names::ARCHIVE_REASON_SYNC_PUSH),
            )
            .await?;
        Ok(moved > 0)
    }

    /// #3075 — see [`crate::store::MemoryStore::apply_remote_restore`].
    ///
    /// The #1848 / G30 forget-tombstone gate runs FIRST and reports a
    /// tombstoned id as the lane's no-op, so a peer cannot undo a local forget
    /// by pushing a restore. That gate lives HERE and NOT in
    /// [`PostgresStore::archive_restore`], which is the OPERATOR un-forget path
    /// (an authorized restore per the #1771 recoverable-delete contract) —
    /// the same split the sqlite twin makes.
    ///
    /// A read fault on the tombstone probe PROPAGATES: treating an unresolvable
    /// probe as "not tombstoned" would resurrect a forgotten row on a storage
    /// hiccup, which is the one outcome this gate exists to prevent.
    pub(super) async fn apply_remote_restore_pg(
        &self,
        ctx: &CallerContext,
        id: &str,
    ) -> StoreResult<bool> {
        let tombstoned: bool = sqlx::query_scalar(SQL_FORGET_TOMBSTONE_EXISTS)
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| to_store_err("apply_remote_restore tombstone check", e))?;
        if tombstoned {
            tracing::info!(
                target: crate::storage::FORGET_TOMBSTONE_TRACE_TARGET,
                memory_id = %id,
                "{}",
                crate::storage::FORGET_TOMBSTONE_DROP_MSG
            );
            return Ok(false);
        }
        let mut op_ctx = ctx.clone();
        op_ctx.bypass_visibility = true;
        self.archive_restore(&op_ctx, id).await
    }
}
