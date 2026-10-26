// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7095 (campaign X, cell X5) - the `memory_link.created` audit row,
//! appended inside the link transaction on postgres.
//!
//! # The defect this closes
//!
//! The sqlite link funnel appends a `memory_link.created` row to
//! `signed_events` for every created edge; the postgres SAL wrote none, so a
//! link created through a postgres node had no tamper-evident trace and the
//! two backends' audit ledgers disagreed.
//!
//! # The rule
//!
//! The row is appended through the shared chain funnel
//! ([`super::pg_append_signed_event_with_chain_in_tx`]) on the SAME
//! transaction as the `memory_links` INSERT, with the SAME pre-image as the
//! sqlite twin (the canonical CBOR of the link's `SignableLink`, hashed with
//! [`crate::signed_events::payload_hash`]). An append error aborts the
//! transaction (fail closed). It runs BEFORE any AGE projection so the
//! tx-local `search_path` is still the configured schema (#7101). The
//! returned anchor is recorded only after COMMIT (#7241).

use chrono::Utc;

use super::{PgSignedEventInsert, pg_append_signed_event_with_chain_in_tx};
use crate::governance::audit::PendingAuditAnchor;
use crate::store::StoreError;

/// Agent attribution when the link carries no signer, matching sqlite.
const UNATTRIBUTED_AGENT: &str = "unknown";

/// The persisted link facts the audit row commits to.
pub(super) struct LinkAuditFacts<'a> {
    pub(super) source_id: &'a str,
    pub(super) target_id: &'a str,
    pub(super) relation: &'a str,
    pub(super) observed_by: Option<&'a str>,
    pub(super) created_at: &'a str,
    pub(super) valid_from: &'a str,
    pub(super) valid_until: Option<&'a str>,
    pub(super) attest_level: &'a str,
    pub(super) signature: Option<&'a [u8]>,
}

/// Append one `memory_link.created` row on `tx`.
///
/// # Errors
/// [`StoreError::IntegrityFailed`] when the pre-image cannot be encoded, or
/// the `sqlx` error of the chain-head read / INSERT mapped by the caller.
pub(super) async fn append_link_created_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    facts: &LinkAuditFacts<'_>,
) -> Result<PendingAuditAnchor, StoreError> {
    let signable = crate::identity::sign::SignableLink {
        src_id: facts.source_id,
        dst_id: facts.target_id,
        relation: facts.relation,
        observed_by: facts.observed_by,
        created_at: Some(facts.created_at),
        valid_from: Some(facts.valid_from),
        valid_until: facts.valid_until,
    };
    let cbor = crate::identity::sign::canonical_cbor(&signable).map_err(|e| {
        StoreError::IntegrityFailed {
            detail: format!("encode memory_link.created audit pre-image: {e}"),
        }
    })?;
    let payload_hash = crate::signed_events::payload_hash(&cbor);
    let id = uuid::Uuid::new_v4().to_string();
    let agent_id = facts.observed_by.unwrap_or(UNATTRIBUTED_AGENT);
    let row = PgSignedEventInsert {
        id: &id,
        agent_id,
        event_type: crate::signed_events::event_types::MEMORY_LINK_CREATED,
        payload_hash: &payload_hash,
        signature: facts.signature,
        attest_level: facts.attest_level,
        timestamp: Utc::now(),
        cause_hash: None,
    };
    pg_append_signed_event_with_chain_in_tx(tx, row)
        .await
        .map_err(|e| super::to_store_err("append memory_link.created audit", e))
}
