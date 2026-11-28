// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10108 (GA standard 3, D5) — the postgres `memory_link.created` audit row.
//!
//! The sqlite twins (`storage::create_link_signed_with_window`,
//! `storage::create_link_inbound`) append one `memory_link.created` row to
//! `signed_events` for every link INSERT that wrote a row. The postgres link
//! writers (`link_internal`, `apply_remote_link_inner`) appended none, so a
//! link created on postgres left no attributable trace in the chain.
//!
//! decision: append in the link's OWN transaction and fail closed (a failed
//! append rolls the link back) over the sqlite best-effort warn, because the
//! postgres writers already own one transaction for the row and its AGE
//! projection, and an unaudited write is what standard 3 forbids.
//!
//! The row's label and signature come from one
//! [`AgentRowSignature`](crate::signed_events::AgentRowSignature) value
//! (invariant I1): an agent label only with a 64-byte signature, else
//! `unsigned` with a NULL signature.

use super::{
    PgSignedEventInsert, StoreError, pg_append_signed_event_with_chain_in_tx, to_store_err,
};
use crate::governance::audit::PendingAuditAnchor;
use crate::identity::sign::SignableLink;

/// The writer recorded when the link names no observer (sqlite parity).
const UNKNOWN_LINK_AGENT: &str = "unknown";

/// Append the `memory_link.created` row for a link this transaction just
/// inserted. `signable` is the link's canonical pre-image (the bytes its
/// signer signed, or would have signed for an unsigned link);
/// `attest_level` and `signature` are the stored link columns.
///
/// # Errors
///
/// `IntegrityFailed` when the pre-image does not encode, and the mapped
/// store error when the append fails; the caller propagates both so the
/// link transaction rolls back.
pub(super) async fn append_link_created_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    signable: &SignableLink<'_>,
    attest_level: &str,
    signature: Option<&[u8]>,
) -> Result<PendingAuditAnchor, StoreError> {
    let cbor = crate::identity::sign::canonical_cbor(signable).map_err(|e| {
        StoreError::IntegrityFailed {
            detail: format!("memory_link.created canonical_cbor: {e}"),
        }
    })?;
    let payload_hash = crate::signed_events::payload_hash(&cbor);
    let row_sig = crate::signed_events::AgentRowSignature::from_label(attest_level, signature);
    let event_id = uuid::Uuid::new_v4().to_string();
    pg_append_signed_event_with_chain_in_tx(
        tx,
        PgSignedEventInsert {
            id: &event_id,
            agent_id: signable.observed_by.unwrap_or(UNKNOWN_LINK_AGENT),
            event_type: crate::signed_events::event_types::MEMORY_LINK_CREATED,
            payload_hash: &payload_hash,
            signature: row_sig.signature_bytes(),
            attest_level: row_sig.attest_level().as_str(),
            timestamp: chrono::Utc::now(),
            cause_hash: None,
        },
    )
    .await
    .map_err(|e| to_store_err("append memory_link.created signed_event", e))
}

/// The `memory_link.created` row for an UNSIGNED substrate edge (no
/// observer, open window) written at `created_at`: the postgres twin of the
/// row sqlite `create_link` appends for the consolidate `derived_from` edge.
///
/// # Errors
///
/// As [`append_link_created_in_tx`].
pub(super) async fn append_unsigned_edge_created_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    src_id: &str,
    dst_id: &str,
    relation: crate::models::MemoryLinkRelation,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<PendingAuditAnchor, StoreError> {
    let stamp = crate::identity::attest::canonical_created_at_stamp(
        super::truncate_to_microseconds(created_at),
    );
    let signable = SignableLink {
        src_id,
        dst_id,
        relation: relation.as_str(),
        observed_by: None,
        created_at: Some(stamp.as_str()),
        valid_from: Some(stamp.as_str()),
        valid_until: None,
    };
    append_link_created_in_tx(
        tx,
        &signable,
        crate::models::AttestLevel::Unsigned.as_str(),
        None,
    )
    .await
}
