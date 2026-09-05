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

/// The pending->resolved COMPARE-AND-SWAP behind
/// [`PostgresStore::apply_remote_checkpoint_resolution_pg`] — the postgres twin
/// of `checkpoints::APPLY_INBOUND_RESOLUTION_CAS_SQL`.
///
/// The `AND state = $9` guard is what makes first-resolution-wins hold under
/// concurrency: without it the read that decided "local is pending" and the
/// write that acts on that decision are a TOCTOU window in which a
/// concurrently-committed local resolution is silently overwritten (#2396) —
/// and the row being overwritten is a separation-of-duties freeze anchor.
const SQL_APPLY_INBOUND_RESOLUTION_CAS: &str = "UPDATE checkpoints SET state = $1, resolved_by = $2, resolution = $3, \
        resolution_note = $4, resolved_at = $5, signature = $6, resolver_pubkey = $7 \
     WHERE id = $8 AND state = $9";

/// The by-id STORED `(condition_type, namespace)` probe feeding the L5
/// reserved-anchor gate. Scalar-ish (two columns, no JSON/attestation mapping)
/// and FAIL-CLOSED at the call site.
const SQL_CHECKPOINT_KIND_NS_BY_ID: &str =
    "SELECT condition_type, namespace FROM checkpoints WHERE id = $1";

impl PostgresStore {
    /// #3075 / FED-RQ-01 (#1936) — see
    /// [`crate::store::MemoryStore::apply_remote_checkpoint_resolution`].
    ///
    /// Step-for-step the sqlite `checkpoints::apply_inbound_resolution`:
    ///
    /// 0. L5 reserved-anchor refusal on the CLAIMED wire kind AND the STORED
    ///    by-id kind, through the SHARED backend-blind
    ///    `receive_auth::inbound_checkpoint_kind_authorized`. The stored probe
    ///    runs UNCONDITIONALLY (not only when namespace-scope is armed) and
    ///    PROPAGATES a read error, because a peer must not be able to present a
    ///    benign wire kind to resolve a stored `_audit_witness` anchor by id.
    /// 1. CAS the locally-PENDING row.
    /// 2. On a CAS miss: INSERT verbatim when no local row exists, treating a
    ///    lost INSERT race (PRIMARY KEY violation) as the same
    ///    first-resolution-wins disposition; otherwise classify against the
    ///    local row with the SHARED `checkpoints::classify_against_local`.
    ///
    /// The receiver NEVER re-signs: `signature` / `resolver_pubkey` travel on
    /// `incoming` and are written verbatim by both the CAS and the INSERT.
    pub(super) async fn apply_remote_checkpoint_resolution_pg(
        &self,
        ctx: &CallerContext,
        incoming: &crate::models::Checkpoint,
    ) -> StoreResult<crate::checkpoints::InboundResolutionOutcome> {
        use crate::checkpoints::InboundResolutionOutcome;

        self.gate_record_stop().await?;

        // Step 0 — reserved-anchor gate on claimed AND stored kind.
        let stored_kind_ns = self.checkpoint_kind_ns_by_id_pg(&incoming.id).await?;
        let stored_ref = stored_kind_ns
            .as_ref()
            .map(|(kind, ns)| (*kind, ns.as_str()));
        if !crate::federation::receive_auth::inbound_checkpoint_kind_authorized(
            incoming.condition_type,
            &incoming.namespace,
            stored_ref,
        ) {
            return Ok(InboundResolutionOutcome::RefusedReservedKind);
        }

        // Step 1 — CAS the locally-PENDING row.
        let updated = sqlx::query(SQL_APPLY_INBOUND_RESOLUTION_CAS)
            .bind(incoming.state.as_str())
            .bind(&incoming.resolved_by)
            .bind(&incoming.resolution)
            .bind(&incoming.resolution_note)
            .bind(incoming.resolved_at)
            .bind(&incoming.signature)
            .bind(&incoming.resolver_pubkey)
            .bind(&incoming.id)
            .bind(crate::models::CheckpointState::Pending.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| to_store_err("apply_remote_checkpoint_resolution cas", e))?
            .rows_affected();
        if updated > 0 {
            return Ok(InboundResolutionOutcome::Applied);
        }

        // Step 2 — no local row, or already resolved (possibly by a racer).
        let Some(local) = self.checkpoint_row_by_id_pg(&incoming.id).await? else {
            return match self.insert_checkpoint_verbatim_pg(ctx, incoming).await {
                Ok(()) => Ok(InboundResolutionOutcome::Applied),
                // Lost the INSERT race — the winner's row landed between our
                // read and our write. Fall back to first-resolution-wins
                // against whatever is now committed; never overwrite.
                Err(e) if is_unique_violation(&e) => {
                    match self.checkpoint_row_by_id_pg(&incoming.id).await? {
                        Some(local) => {
                            Ok(crate::checkpoints::classify_against_local(&local, incoming))
                        }
                        None => Err(e),
                    }
                }
                Err(e) => Err(e),
            };
        };
        Ok(crate::checkpoints::classify_against_local(&local, incoming))
    }

    /// The STORED `(condition_type, namespace)` probe. FAIL-CLOSED: an
    /// unresolvable read PROPAGATES rather than being reported as "provably no
    /// local row", which is the input the stored-vs-claimed bypass needs.
    async fn checkpoint_kind_ns_by_id_pg(
        &self,
        id: &str,
    ) -> StoreResult<Option<(crate::models::ConditionType, String)>> {
        let row: Option<(String, String)> = sqlx::query_as(SQL_CHECKPOINT_KIND_NS_BY_ID)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| to_store_err("checkpoint_kind_ns_by_id", e))?;
        let Some((kind, namespace)) = row else {
            return Ok(None);
        };
        // An unparseable stored `condition_type` is a CORRUPT row, not an
        // absent one: refuse rather than silently treating it as a benign kind
        // the reserved-anchor gate would wave through.
        let condition_type = crate::models::ConditionType::from_str(&kind).ok_or_else(|| {
            super::StoreError::Backend(crate::store::BoxBackendError::new(format!(
                "checkpoint {id} has an unrecognised stored condition_type {kind:?}"
            )))
        })?;
        Ok(Some((condition_type, namespace)))
    }

    /// Full-row read used by the first-resolution-wins classification. A
    /// checkpoint carries no at-rest envelope, so — unlike the memories lane
    /// (#2488) — a full-row map here cannot fail for a decrypt reason.
    async fn checkpoint_row_by_id_pg(
        &self,
        id: &str,
    ) -> StoreResult<Option<crate::models::Checkpoint>> {
        sqlx::query(super::PG_CHECKPOINT_SELECT_BY_ID)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| to_store_err("checkpoint_row_by_id", e))?
            .as_ref()
            .map(super::pg_row_to_checkpoint)
            .transpose()
    }

    /// The FIRST-LANDING arm: the subject and its resolution arrive together,
    /// so the whole wire row is inserted VERBATIM — attestation columns
    /// included, never re-signed.
    ///
    /// Composes [`PostgresStore::checkpoint_create`], which already binds all
    /// sixteen columns verbatim (including `state` / `resolved_*` /
    /// `signature` / `resolver_pubkey`) and is already record-stop gated. A
    /// second hand-written INSERT here would be a column list to keep in sync
    /// with that one forever — the drift hazard #3075 is deliberately not
    /// creating — and it would need its own gate, which is exactly the class
    /// `tests/record_stop_structural_b7.rs` exists to catch.
    async fn insert_checkpoint_verbatim_pg(
        &self,
        ctx: &CallerContext,
        cp: &crate::models::Checkpoint,
    ) -> StoreResult<()> {
        self.checkpoint_create(ctx, cp).await.map(|_id| ())
    }
}

/// Whether a `StoreError` carries a postgres UNIQUE / PRIMARY-KEY violation —
/// the shape a losing concurrent INSERT of the same checkpoint id takes
/// (`checkpoints.id` is the PRIMARY KEY). The sqlite twin asks the same
/// question of `rusqlite::ErrorCode::ConstraintViolation`; both turn a lost
/// insert race into the documented first-resolution-wins disposition instead of
/// a hard error.
fn is_unique_violation(err: &super::StoreError) -> bool {
    let super::StoreError::Backend(source) = err else {
        return false;
    };
    // sqlx surfaces the SQLSTATE in the rendered message; the class is
    // `23505 unique_violation`. Matching the CODE (not prose) keeps this
    // independent of the server's locale and of sqlx's wrapper wording.
    source.to_string().contains(PG_UNIQUE_VIOLATION_SQLSTATE)
}

/// SQLSTATE `23505` — `unique_violation`.
const PG_UNIQUE_VIOLATION_SQLSTATE: &str = "23505";
