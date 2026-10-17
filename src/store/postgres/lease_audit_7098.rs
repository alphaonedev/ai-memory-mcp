// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7098 (campaign X, cell X8) - the lease-lifecycle audit row, appended
//! inside the lease transaction on postgres.
//!
//! # The defect this closes
//!
//! The coordination audit for `lease_acquire` / `lease_renew` /
//! `lease_release` existed only in the MCP handler on the sqlite path, best
//! effort, after the commit; the postgres SAL wrote no row for the voluntary
//! lease ops and wrote the sweep rows after the COMMIT, swallowing an append
//! error. A lease could change hands with no tamper-evident trace.
//!
//! # The rule
//!
//! Every lease mutation appends its row through the SAME chain funnel
//! ([`super::pg_append_signed_event_with_chain_in_tx`]) on the SAME
//! transaction, with the SAME payload pre-image as the sqlite twin
//! ([`crate::coordination_audit::coordination_payload_hash`] over
//! `[action_id, holder]`). An append error aborts the transaction (fail
//! closed). The returned anchor is recorded only after COMMIT (#7241).

use chrono::Utc;

use super::{PgSignedEventInsert, pg_append_signed_event_with_chain_in_tx};
use crate::governance::audit::PendingAuditAnchor;

/// Append one lease-lifecycle audit row on `tx`, attributed to `holder`.
///
/// # Errors
/// Propagates the `sqlx` error of the chain-head read or the INSERT; the
/// caller must drop (roll back) its transaction.
pub(super) async fn append_lease_audit_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event_type: &str,
    action_id: &str,
    holder: &str,
) -> Result<PendingAuditAnchor, sqlx::Error> {
    let ts = Utc::now();
    let event = crate::signed_events::SignedEvent::with_daemon_signature(
        crate::coordination_audit::coordination_payload_hash(&[action_id, holder]),
        holder.to_string(),
        event_type.to_string(),
        ts.to_rfc3339(),
        None,
    );
    let row = PgSignedEventInsert {
        id: &event.id,
        agent_id: &event.agent_id,
        event_type: &event.event_type,
        payload_hash: &event.payload_hash,
        signature: event.signature.as_deref(),
        attest_level: &event.attest_level,
        timestamp: ts,
        cause_hash: None,
    };
    pg_append_signed_event_with_chain_in_tx(tx, row).await
}
