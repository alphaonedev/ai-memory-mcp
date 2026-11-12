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
//! Deletions travel as deletions: [`FanoutEffect::Delete`] uses
//! `broadcast_delete_quorum`, the shipped `sync_push.deletions` tombstone
//! form, and the bulk [`fanout_bulk_into`] with [`BulkEffect::Delete`]
//! ships chunks of at most [`super::MAX_BULK_SIZE`] ids in one body per peer
//! (`broadcast_delete_batch_quorum`), which lands a failed chunk as one DLQ
//! row per bare memory id.
//!
//! Bounds (#8741 round 1, F4): a batch holds at most
//! [`super::BULK_FANOUT_CONCURRENCY`] live tasks (the permit is taken BEFORE
//! the spawn), shares ONE `Arc<FederationConfig>`, and the request waits at
//! most [`FANOUT_BATCH_DEADLINE_ACK_TIMEOUTS`] policy ack timeouts; past it
//! the response is the exact 202 naming [`FANOUT_DEADLINE_EXCEEDED`] while
//! the detached driver finishes every effect, each landing its own DLQ rows.
//!
//! Receipts (#8741 round 1, F5 / F6): every stamp keeps the MINIMUM ack
//! count of all the effects one request delivered, and a batch with nothing
//! to deliver stamps nothing (an ack count no peer gave is never reported).

use std::sync::Arc;

use axum::response::Response;
use serde_json::{Value, json};

use crate::federation::{FederationConfig, QuorumNotMetPayload};
use crate::models::{
    GovernedAction, Memory, MemoryLink, NamespaceMetaEntry, PendingAction, PendingDecision,
};
use crate::replication::{AckTracker, QuorumError};

use super::AppState;
use super::{BULK_FANOUT_CONCURRENCY, MAX_BULK_SIZE};

/// Detail stamped on the `quorum_not_met` payload when the origin
/// committed a mutation but could not read the committed row back to fan
/// it out. The local write is durable; peers did not receive it, so the
/// response must say so instead of a bare success.
pub(crate) const FANOUT_READBACK_FAILED: &str = "FANOUT_READBACK_FAILED";

/// Detail of the 202 a batched delivery returns when it did not settle
/// inside its overall deadline. The detached driver still delivers every
/// effect (each lane lands its own DLQ rows on a peer miss).
pub(crate) const FANOUT_DEADLINE_EXCEEDED: &str = "FANOUT_DEADLINE_EXCEEDED";

/// Detail of the 202 when a delivery task panicked or was cancelled. The
/// join error text stays in the operator log, never in the response.
pub(crate) const FANOUT_TASK_FAILED: &str = "FANOUT_TASK_FAILED";

/// Overall budget of one batched delivery, in policy ack timeouts.
pub(crate) const FANOUT_BATCH_DEADLINE_ACK_TIMEOUTS: u32 = 4;

/// One locally-committed effect to deliver to the peers.
pub(crate) enum FanoutEffect<'a> {
    /// A stored / updated / promoted row (insert-if-newer on the peer).
    Store(&'a Memory),
    /// A single deletion, delivered as a `sync_push.deletions` tombstone.
    Delete(&'a str),
    /// Up to [`super::MAX_BULK_SIZE`] deletions in one tombstone body.
    DeleteBatch(&'a [String]),
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
        FanoutEffect::DeleteBatch(ids) => {
            crate::federation::broadcast_delete_batch_quorum(fed, ids).await
        }
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
/// A receipt already stamped by an earlier effect of the SAME request keeps
/// the MINIMUM ack count (#8741 round 1, F6: a request is delivered only as
/// far as its least-delivered effect). A non-object receipt (never produced
/// by the callers) is left alone rather than replaced, per ERRORS-19 the
/// caller still gets its body.
pub(crate) fn stamp_quorum(receipt: &mut Value, fed: &FederationConfig, acks: usize) {
    if let Some(obj) = receipt.as_object_mut() {
        let acks = obj
            .get(crate::write_receipt::QUORUM_ACKS_FIELD)
            .and_then(Value::as_u64)
            .and_then(|prior| usize::try_from(prior).ok())
            .map_or(acks, |prior| prior.min(acks));
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

/// The exact 202 for a stable local code (never raw backend text, #8741
/// round 1 sec-F4).
fn local_code(detail: &str) -> QuorumError {
    QuorumError::LocalWriteFailed {
        detail: detail.to_string(),
    }
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
    Err(under_replicated(&local_code(&format!(
        "{FANOUT_READBACK_FAILED}: {detail}"
    ))))
}

/// #8741 round 1 (F3 / sec-F2) — what a governance decision produced, as
/// read back from the store. A failed or empty read is [`Produced::Unread`],
/// never `None`: the decision funnel then reports the exact
/// [`FANOUT_READBACK_FAILED`] 202 instead of a delivered ack.
pub(crate) enum Produced {
    /// The decision executed nothing (a reject, or an approval whose
    /// action writes no memory).
    Nothing,
    /// The committed row, read back unfiltered.
    Row(Memory),
    /// The decision committed this memory id but it could not be read back.
    Unread(String),
}

impl Produced {
    /// True when the executed pending action leaves a row to read back: a
    /// `delete` returns the id it erased, so its only effect is the decision
    /// itself. An unknown snapshot counts as a row (fail closed: an empty
    /// read-back is then the exact 202, never a delivered ack).
    pub(crate) fn leaves_row(snapshot: Option<&PendingAction>) -> bool {
        snapshot.is_none_or(|pa| pa.action_type != GovernedAction::Delete.as_str())
    }

    /// Classify the read-back of the produced memory `mid`. The backend
    /// error text goes to the operator log only.
    pub(crate) fn from_read<E: std::fmt::Display>(
        mid: &str,
        read: Result<Option<Memory>, E>,
    ) -> Self {
        match read {
            Ok(Some(mem)) => Self::Row(mem),
            Ok(None) => {
                tracing::warn!("decision produced {mid} but the read-back found no row");
                Self::Unread(mid.to_string())
            }
            Err(e) => {
                tracing::warn!("decision produced {mid} but the read-back failed: {e}");
                Self::Unread(mid.to_string())
            }
        }
    }
}

/// #8741 (#9152) — a finalised governance decision: the decision itself
/// (`sync_push.pending_decisions`) and, when the approval executed a
/// `store`, the produced memory, exactly what the SQLite `approve_pending`
/// arm has always sent. Shared by `approve_pending` / `reject_pending` /
/// `approval_decide` on both backends. The decision is delivered first;
/// a produced row that could not be read back then makes the response the
/// exact [`FANOUT_READBACK_FAILED`] 202 naming its id.
///
/// # Errors
///
/// Returns the 202 under-replication response for the first effect that
/// missed quorum, or for an unread produced row.
pub(crate) async fn fanout_decision(
    app: &AppState,
    decision: &PendingDecision,
    produced: &Produced,
    receipt: &mut Value,
) -> Result<(), Response> {
    fanout_into(app, FanoutEffect::PendingDecision(decision), receipt).await?;
    match produced {
        Produced::Nothing => Ok(()),
        Produced::Row(mem) => fanout_into(app, FanoutEffect::Store(mem), receipt).await,
        Produced::Unread(mid) => readback_failed(app, mid),
    }
}

/// The per-id effect a bulk mutation delivers.
#[derive(Clone, Copy)]
pub(crate) enum BulkEffect {
    /// POST `/api/v1/forget`: tombstones in chunks of [`MAX_BULK_SIZE`].
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
    /// Up to [`MAX_BULK_SIZE`] erased ids, one tombstone body per peer.
    DeleteChunk(Vec<String>),
    /// One archived id.
    Archive(String),
}

impl OwnedEffect {
    fn borrowed(&self) -> FanoutEffect<'_> {
        match self {
            Self::Store(mem) => FanoutEffect::Store(mem),
            Self::Link(link) => FanoutEffect::Link(link),
            Self::DeleteChunk(ids) => FanoutEffect::DeleteBatch(ids),
            Self::Archive(id) => FanoutEffect::Archive(id),
        }
    }
}

/// The owned effects of a bulk mutation: erased ids travel in chunks of at
/// most [`MAX_BULK_SIZE`] (the receiver's default page cap), archived ids
/// one per effect.
pub(crate) fn bulk_effects(kind: BulkEffect, ids: &[String]) -> Vec<OwnedEffect> {
    match kind {
        BulkEffect::Delete => ids
            .chunks(MAX_BULK_SIZE)
            .map(|chunk| OwnedEffect::DeleteChunk(chunk.to_vec()))
            .collect(),
        BulkEffect::Archive => ids.iter().cloned().map(OwnedEffect::Archive).collect(),
    }
}

/// Bulk funnel (POST `/api/v1/forget`, POST `/api/v1/archive`). Quorum is
/// reported for the batch as the minimum ack count over every effect; any
/// effect that misses quorum (or whose broadcast errors) makes the whole
/// response the exact 202, so a partially delivered erasure is never a
/// success.
///
/// # Errors
///
/// Returns the 202 under-replication response for the first effect that
/// missed quorum, or when the batch overran its deadline.
pub(crate) async fn fanout_bulk_into(
    app: &AppState,
    kind: BulkEffect,
    ids: &[String],
    receipt: &mut Value,
) -> Result<(), Response> {
    fanout_effects_into(app, bulk_effects(kind, ids), receipt).await
}

/// The folded outcome of a batched delivery: the minimum ack count over the
/// settled effects and the first failure.
struct BatchOutcome {
    min_acks: Option<usize>,
    first_err: Option<QuorumError>,
}

impl BatchOutcome {
    fn fold(&mut self, joined: Result<Result<usize, QuorumError>, tokio::task::JoinError>) {
        match joined {
            Ok(Ok(acks)) => self.min_acks = Some(self.min_acks.map_or(acks, |m| m.min(acks))),
            Ok(Err(err)) => {
                self.first_err.get_or_insert(err);
            }
            Err(join_err) => {
                tracing::error!("federation fanout task failed: {join_err}");
                self.first_err.get_or_insert(local_code(FANOUT_TASK_FAILED));
            }
        }
    }
}

/// Deliver every effect with at most [`BULK_FANOUT_CONCURRENCY`] live
/// tasks: the permit is acquired BEFORE each spawn, so a batch of any size
/// never holds more than that many tasks, and every task shares `fed`.
async fn drive(fed: Arc<FederationConfig>, effects: Vec<OwnedEffect>) -> BatchOutcome {
    let sem = Arc::new(tokio::sync::Semaphore::new(BULK_FANOUT_CONCURRENCY));
    let mut joins: tokio::task::JoinSet<Result<usize, QuorumError>> = tokio::task::JoinSet::new();
    let mut out = BatchOutcome {
        min_acks: None,
        first_err: None,
    };
    for effect in effects {
        let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
            // The semaphore is local and never closed; fail closed anyway.
            out.first_err.get_or_insert(local_code(FANOUT_TASK_FAILED));
            break;
        };
        let fed = Arc::clone(&fed);
        joins.spawn(async move {
            let settled = settle(broadcast(&fed, &effect.borrowed()).await);
            drop(permit);
            settled
        });
        while let Some(joined) = joins.try_join_next() {
            out.fold(joined);
        }
    }
    while let Some(joined) = joins.join_next().await {
        out.fold(joined);
    }
    out
}

/// #8741 (#9153) — the general bulk funnel: every effect is broadcast on
/// its own task, at most [`BULK_FANOUT_CONCURRENCY`] in flight, and the
/// batch reports the minimum ack count, or the exact 202 for the first
/// effect that missed quorum. POST `/api/v1/import` delivers its rows and
/// links through it. An empty batch stamps no quorum fields (F5): nothing
/// was delivered, so no ack count is reported.
///
/// # Errors
///
/// Returns the 202 under-replication response for the first effect that
/// missed quorum, or naming [`FANOUT_DEADLINE_EXCEEDED`] when the batch
/// did not settle inside its deadline.
pub(crate) async fn fanout_effects_into(
    app: &AppState,
    effects: Vec<OwnedEffect>,
    receipt: &mut Value,
) -> Result<(), Response> {
    let Some(fed) = app.federation.as_ref().as_ref() else {
        return Ok(());
    };
    match deliver_batch(fed, effects).await {
        Ok(Some(acks)) => {
            stamp_quorum(receipt, fed, acks);
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(err) => {
            tracing::warn!("bulk fanout under-replicated (local committed): {err}");
            Err(under_replicated(&err))
        }
    }
}

/// Deliver a batch under its overall deadline. `Ok(None)` is an empty
/// batch. On a deadline overrun the driver is detached, not aborted: every
/// effect is still delivered or DLQ-landed by its own lane.
async fn deliver_batch(
    fed: &FederationConfig,
    effects: Vec<OwnedEffect>,
) -> Result<Option<usize>, QuorumError> {
    if effects.is_empty() {
        return Ok(None);
    }
    let deadline = fed
        .policy
        .ack_timeout
        .saturating_mul(FANOUT_BATCH_DEADLINE_ACK_TIMEOUTS);
    let driver = tokio::spawn(drive(Arc::new(fed.clone()), effects));
    let out = match tokio::time::timeout(deadline, driver).await {
        Ok(Ok(out)) => out,
        Ok(Err(join_err)) => {
            tracing::error!("federation fanout driver failed: {join_err}");
            return Err(local_code(FANOUT_TASK_FAILED));
        }
        Err(_elapsed) => return Err(local_code(FANOUT_DEADLINE_EXCEEDED)),
    };
    if let Some(err) = out.first_err {
        return Err(err);
    }
    out.min_acks
        .map(Some)
        .ok_or_else(|| local_code(FANOUT_TASK_FAILED))
}

#[cfg(test)]
#[path = "fed_fanout_tests.rs"]
mod tests;
