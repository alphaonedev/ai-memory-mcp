// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8741 fed-delivery (#9087 #9005 #9023 #9057) — the ONE federation
//! fan-out funnel every HTTP mutation calls after its local commit, on
//! BOTH backends.
//!
//! The defect class this closes: a mutation was acknowledged locally but
//! its effect never reached the federation peers, because each route
//! carried its own inline `broadcast_*_quorum` call on the SQLite branch
//! only and the PostgreSQL branch returned before it (PUT / DELETE
//! `/api/v1/memories/{id}`, POST `/api/v1/links`, archive, restore), or
//! because the route never fanned out at all (POST `/api/v1/forget`).
//! `decision: one funnel called by every backend branch over per-route
//! inline calls, because the defect is a per-route omission and a
//! per-route fix leaves the next route open.`
//!
//! Contract of [`fanout_into`] / [`fanout_bulk_into`]:
//! 1. No federation configured: `Ok(())`, the receipt is untouched.
//! 2. Quorum met: the receipt is stamped with the three write-receipt
//!    quorum fields (`quorum_acks` / `quorum_n` / `quorum_required`) the
//!    SQLite update path already returned — the values are the tracker's
//!    real ack count and the configured policy, never a constant.
//! 3. Quorum missed OR the broadcast itself errored: `Err(202)` through
//!    the shared [`super::under_replicated_response`] with the exact
//!    `quorum_not_met` payload. The local row is durable (W3 / G12), so it
//!    is never a 5xx, and it is never a silent success either (the
//!    pre-fix `if let Ok(tracker) = broadcast(..)` swallowed the `Err`).
//!
//! Deletions travel as deletions: [`FanoutEffect::Delete`] and the bulk
//! [`fanout_bulk_into`] with [`BulkEffect::Delete`] both use `broadcast_delete_quorum`, the
//! existing `sync_push.deletions` tombstone form. The bulk form fans out
//! one id per call (bounded by [`super::BULK_FANOUT_CONCURRENCY`]) because
//! the push DLQ keys each failure on the bare memory id; a multi-id body
//! would collapse N ids into one DLQ key.

use std::sync::Arc;

use axum::response::Response;
use serde_json::{Value, json};

use crate::federation::{FederationConfig, QuorumNotMetPayload};
use crate::models::{Memory, MemoryLink, NamespaceMetaEntry, PendingDecision};
use crate::replication::{AckTracker, QuorumError};

use super::AppState;
use super::BULK_FANOUT_CONCURRENCY;

/// Detail stamped on the `quorum_not_met` payload when the origin
/// committed a mutation but could not read the committed row back to fan
/// it out. The local write is durable; peers did not receive it, so the
/// response must say so instead of a bare success.
pub(crate) const FANOUT_READBACK_FAILED: &str = "FANOUT_READBACK_FAILED";

/// One locally-committed effect to deliver to the peers.
pub(crate) enum FanoutEffect<'a> {
    /// A stored / updated / promoted row (insert-if-newer on the peer).
    Store(&'a Memory),
    /// A single deletion, delivered as a `sync_push.deletions` tombstone.
    Delete(&'a str),
    /// A created link.
    Link(&'a MemoryLink),
    /// An archived memory id.
    Archive(&'a str),
    /// A restored memory id.
    Restore(&'a str),
    /// A governance decision on a pending action (`sync_push.pending_decisions`).
    PendingDecision(&'a PendingDecision),
    /// A namespace standard binding (`sync_push.namespace_meta`).
    NamespaceMeta(&'a NamespaceMetaEntry),
    /// Cleared namespace standards (`sync_push.namespace_meta_clears`).
    NamespaceMetaClear(&'a [String]),
}

async fn broadcast(
    fed: &FederationConfig,
    effect: &FanoutEffect<'_>,
) -> Result<AckTracker, QuorumError> {
    match effect {
        FanoutEffect::Store(mem) => crate::federation::broadcast_store_quorum(fed, mem).await,
        FanoutEffect::Delete(id) => crate::federation::broadcast_delete_quorum(fed, id).await,
        FanoutEffect::Link(link) => crate::federation::broadcast_link_quorum(fed, link).await,
        FanoutEffect::Archive(id) => crate::federation::broadcast_archive_quorum(fed, id).await,
        FanoutEffect::Restore(id) => crate::federation::broadcast_restore_quorum(fed, id).await,
        FanoutEffect::PendingDecision(decision) => {
            crate::federation::broadcast_pending_decision_quorum(fed, decision).await
        }
        FanoutEffect::NamespaceMeta(entry) => {
            crate::federation::broadcast_namespace_meta_quorum(fed, entry).await
        }
        FanoutEffect::NamespaceMetaClear(namespaces) => {
            crate::federation::broadcast_namespace_meta_clear_quorum(fed, namespaces).await
        }
    }
}

/// Stamp the three write-receipt quorum fields on a JSON object receipt.
/// A non-object receipt (never produced by the callers) is left alone
/// rather than replaced, per ERRORS-19 the caller still gets its body.
pub(crate) fn stamp_quorum(receipt: &mut Value, fed: &FederationConfig, acks: usize) {
    if let Some(obj) = receipt.as_object_mut() {
        obj.insert(
            crate::write_receipt::QUORUM_ACKS_FIELD.to_string(),
            json!(acks),
        );
        obj.insert(
            crate::write_receipt::QUORUM_N_FIELD.to_string(),
            json!(fed.policy.n),
        );
        obj.insert(
            crate::write_receipt::QUORUM_REQUIRED_FIELD.to_string(),
            json!(fed.policy.w),
        );
    }
}

fn under_replicated(err: &QuorumError) -> Response {
    super::under_replicated_response(&QuorumNotMetPayload::from_err(err))
}

/// Settle a broadcast outcome into an ack count or the exact 202.
fn settle(outcome: Result<AckTracker, QuorumError>) -> Result<usize, QuorumError> {
    let tracker = outcome?;
    crate::federation::finalise_quorum(&tracker)
}

/// The funnel. See the module docs for the contract.
///
/// # Errors
///
/// Returns the `202 Accepted` under-replication response when the
/// broadcast errors or does not reach quorum.
pub(crate) async fn fanout_into(
    app: &AppState,
    effect: FanoutEffect<'_>,
    receipt: &mut Value,
) -> Result<(), Response> {
    let Some(fed) = app.federation.as_ref().as_ref() else {
        return Ok(());
    };
    match settle(broadcast(fed, &effect).await) {
        Ok(acks) => {
            stamp_quorum(receipt, fed, acks);
            Ok(())
        }
        Err(err) => {
            tracing::warn!("federation fanout under-replicated (local committed): {err}");
            Err(under_replicated(&err))
        }
    }
}

/// The origin committed a mutation but cannot read the row back to fan
/// it out. Without federation that is a plain success; with federation
/// the peers did not receive it, so report the exact `quorum_not_met`
/// 202 naming [`FANOUT_READBACK_FAILED`] (invariant 4: never a silent
/// success).
///
/// # Errors
///
/// Returns the 202 under-replication response when federation is on.
pub(crate) fn readback_failed(app: &AppState, detail: &str) -> Result<(), Response> {
    if app.federation.as_ref().is_none() {
        return Ok(());
    }
    let err = QuorumError::LocalWriteFailed {
        detail: format!("{FANOUT_READBACK_FAILED}: {detail}"),
    };
    Err(under_replicated(&err))
}

/// #8741 (#9152) — a finalised governance decision: the decision itself
/// (`sync_push.pending_decisions`) and, when the approval executed a
/// `store`, the produced memory, exactly what the SQLite `approve_pending`
/// arm has always sent. Shared by `approve_pending` / `reject_pending` /
/// `approval_decide` on both backends.
///
/// # Errors
///
/// Returns the 202 under-replication response for the first effect that
/// missed quorum.
pub(crate) async fn fanout_decision(
    app: &AppState,
    decision: &PendingDecision,
    produced: Option<&Memory>,
    receipt: &mut Value,
) -> Result<(), Response> {
    fanout_into(app, FanoutEffect::PendingDecision(decision), receipt).await?;
    if let Some(mem) = produced {
        fanout_into(app, FanoutEffect::Store(mem), receipt).await?;
    }
    Ok(())
}

/// The per-id effect a bulk mutation delivers.
#[derive(Clone, Copy)]
pub(crate) enum BulkEffect {
    /// POST `/api/v1/forget`: one `sync_push.deletions` tombstone per id.
    Delete,
    /// POST `/api/v1/archive`: one archive per id.
    Archive,
}

/// One owned effect of a bulk delivery (each runs on its own task).
pub(crate) enum OwnedEffect {
    /// An imported / captured memory row.
    Store(Memory),
    /// An imported link.
    Link(MemoryLink),
    /// One erased id.
    Delete(String),
    /// One archived id.
    Archive(String),
}

impl OwnedEffect {
    fn borrowed(&self) -> FanoutEffect<'_> {
        match self {
            Self::Store(mem) => FanoutEffect::Store(mem),
            Self::Link(link) => FanoutEffect::Link(link),
            Self::Delete(id) => FanoutEffect::Delete(id),
            Self::Archive(id) => FanoutEffect::Archive(id),
        }
    }
}

/// Bulk funnel (POST `/api/v1/forget`, POST `/api/v1/archive`): one
/// broadcast per committed id, at most [`BULK_FANOUT_CONCURRENCY`] in flight. Quorum is reported
/// for the batch as the minimum ack count over every id; any id that
/// misses quorum (or whose broadcast errors) makes the whole response the
/// exact 202, so a partially delivered erasure is never a success.
///
/// # Errors
///
/// Returns the 202 under-replication response for the first id that
/// missed quorum.
pub(crate) async fn fanout_bulk_into(
    app: &AppState,
    kind: BulkEffect,
    ids: &[String],
    receipt: &mut Value,
) -> Result<(), Response> {
    let effects = ids
        .iter()
        .map(|id| match kind {
            BulkEffect::Delete => OwnedEffect::Delete(id.clone()),
            BulkEffect::Archive => OwnedEffect::Archive(id.clone()),
        })
        .collect();
    fanout_effects_into(app, effects, receipt).await
}

/// #8741 (#9153) — the general bulk funnel: every effect is broadcast on
/// its own task, at most [`BULK_FANOUT_CONCURRENCY`] in flight, and the
/// batch reports the minimum ack count, or the exact 202 for the first
/// effect that missed quorum. POST `/api/v1/import` delivers its rows and
/// links through it.
///
/// # Errors
///
/// Returns the 202 under-replication response for the first effect that
/// missed quorum.
pub(crate) async fn fanout_effects_into(
    app: &AppState,
    effects: Vec<OwnedEffect>,
    receipt: &mut Value,
) -> Result<(), Response> {
    let Some(fed) = app.federation.as_ref().as_ref() else {
        return Ok(());
    };
    if effects.is_empty() {
        // Nothing committed: the receipt still carries the configured policy
        // so the caller can tell a federated no-op from a local-only one.
        stamp_quorum(receipt, fed, fed.policy.n);
        return Ok(());
    }
    let sem = Arc::new(tokio::sync::Semaphore::new(BULK_FANOUT_CONCURRENCY));
    let mut joins: tokio::task::JoinSet<Result<usize, QuorumError>> = tokio::task::JoinSet::new();
    for effect in effects {
        let fed = fed.clone();
        let sem = Arc::clone(&sem);
        joins.spawn(async move {
            let Ok(_permit) = sem.acquire_owned().await else {
                return Err(QuorumError::LocalWriteFailed {
                    detail: "fanout semaphore closed".to_string(),
                });
            };
            settle(broadcast(&fed, &effect.borrowed()).await)
        });
    }
    let mut min_acks = usize::MAX;
    let mut first_err: Option<QuorumError> = None;
    while let Some(joined) = joins.join_next().await {
        match joined {
            Ok(Ok(acks)) => min_acks = min_acks.min(acks),
            Ok(Err(err)) => {
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
            Err(join_err) => {
                if first_err.is_none() {
                    first_err = Some(QuorumError::LocalWriteFailed {
                        detail: format!("fanout task join error: {join_err}"),
                    });
                }
            }
        }
    }
    if let Some(err) = first_err {
        tracing::warn!("bulk fanout under-replicated (local committed): {err}");
        return Err(under_replicated(&err));
    }
    stamp_quorum(receipt, fed, min_acks);
    Ok(())
}
