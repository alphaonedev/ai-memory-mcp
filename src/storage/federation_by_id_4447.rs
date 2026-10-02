// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4447 — the sqlite federation by-id lanes (`deletions[]`, `archives[]`,
//! `restores[]`, `links[]`) with the in-transaction peer-scope re-check,
//! the sibling of the #4023 `merge_inbound_authorized` fix.
//!
//! The receive funnel authorizes a target row's STORED namespace on a pre-read,
//! but the write that follows is by id and a broader-scoped writer on a second
//! connection (or process) can move the row out of the peer's scope in
//! between. Each `*_authorized` function here opens (or joins) the write
//! transaction, re-reads the stored namespace UNDER that lock, evaluates the
//! caller's verdict against it, and refuses (rolling the transaction back,
//! nothing written) when the row is no longer in scope. The verdict is a
//! REQUIRED closure, never an `Option`, so there is no literal-`None` bypass to
//! pin: the unchecked free functions (`delete`, `archive_memory`,
//! `restore_archived`, `create_link_inbound`) keep their local-caller meaning.
//!
//! A row that is absent under the lock is not re-checked here (nothing is
//! overwritten, moved or deleted); the funnel's pre-check already reports the
//! absent-row no-op and the write functions are no-ops on a missing id.

use super::*;

/// The per-lane verdict re-evaluated against the STORED namespace of a row
/// locked inside the write transaction: `(row id, stored namespace) -> allowed`.
pub type ByIdNamespaceAuthorizer<'a> = &'a (dyn Fn(&str, &str) -> bool + Send + Sync);

/// The refusal detail when an in-transaction re-check finds the target row in a
/// namespace the pushing peer is not scoped for. One builder shared by both
/// backends so the log line and the error text cannot drift.
#[must_use]
pub fn inbound_by_id_namespace_refused(lane: &str, id: &str, stored_namespace: &str) -> String {
    format!(
        "federation {lane} refused for {id}: the stored row is in namespace \
         {stored_namespace:?}, outside the pushing peer's scope (#4447 in-transaction re-check)"
    )
}

/// The TYPED refusal the `*_authorized` functions return (inside the
/// `anyhow::Error`) so an adapter can map it to `StoreError::PermissionDenied`
/// exactly as the postgres adapter does (error parity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundByIdNamespaceRefused {
    /// The `/sync/push` lane that refused (`deletions`, `archives`, ...).
    pub lane: &'static str,
    /// The id of the row the refusal names.
    pub id: String,
    /// The namespace of the locked row the peer is not scoped for.
    pub stored_namespace: String,
}

impl std::fmt::Display for InboundByIdNamespaceRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&inbound_by_id_namespace_refused(
            self.lane,
            &self.id,
            &self.stored_namespace,
        ))
    }
}

impl std::error::Error for InboundByIdNamespaceRefused {}

/// Re-authorize a live row's stored namespace under the held write lock.
fn recheck_live(
    conn: &Connection,
    lane: &'static str,
    id: &str,
    authorize: ByIdNamespaceAuthorizer<'_>,
) -> Result<()> {
    if let Some(stored) = namespace_by_id(conn, id)?
        && !authorize(id, &stored)
    {
        return Err(anyhow::Error::new(InboundByIdNamespaceRefused {
            lane,
            id: id.to_string(),
            stored_namespace: stored,
        }));
    }
    Ok(())
}

/// Run `f` inside one write transaction: open our own `BEGIN IMMEDIATE` when
/// none is active, otherwise join the caller's (the unchecked writers below are
/// transaction-aware and join ours).
fn in_write_txn<T>(conn: &Connection, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let txn = conn
        .is_autocommit()
        .then(|| connection::WriteTxn::begin(conn))
        .transpose()?;
    match (f(), txn) {
        (Ok(v), Some(t)) => {
            t.commit()?;
            Ok(v)
        }
        (Ok(v), None) => Ok(v),
        (Err(e), Some(t)) => {
            t.rollback();
            Err(e)
        }
        (Err(e), None) => Err(e),
    }
}

/// [`delete`] for the federated `deletions[]` lane: the row's stored namespace
/// is re-authorized inside the delete's own write transaction.
///
/// # Errors
///
/// Everything [`delete`] returns, plus an [`InboundByIdNamespaceRefused`] when
/// the locked row is outside the peer's scope (nothing is written).
pub fn delete_authorized(
    conn: &Connection,
    id: &str,
    authorize: ByIdNamespaceAuthorizer<'_>,
) -> Result<bool> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    in_write_txn(conn, || {
        recheck_live(
            conn,
            crate::federation::receive_auth::LANE_DELETIONS,
            id,
            authorize,
        )?;
        delete(conn, id)
    })
}

/// [`archive_memory`] for the federated `archives[]` lane, re-authorized under
/// the archive transaction's write lock.
///
/// # Errors
///
/// Everything [`archive_memory`] returns, plus an
/// [`InboundByIdNamespaceRefused`] when the locked row is outside the peer's
/// scope (nothing is written).
pub fn archive_memory_authorized(
    conn: &Connection,
    id: &str,
    reason: Option<&str>,
    authorize: ByIdNamespaceAuthorizer<'_>,
) -> Result<bool> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    in_write_txn(conn, || {
        recheck_live(
            conn,
            crate::federation::receive_auth::LANE_ARCHIVES,
            id,
            authorize,
        )?;
        archive_memory(conn, id, reason)
    })
}

/// [`restore_archived`] for the federated `restores[]` lane: the ARCHIVED row's
/// stored namespace is re-authorized inside the restore's own write
/// transaction (after any cold-tier reconstruction, so a reconstructed row is
/// checked too).
///
/// # Errors
///
/// Everything [`restore_archived`] returns, plus an
/// [`InboundByIdNamespaceRefused`] when the locked archived row is outside the
/// peer's scope (nothing is written).
pub fn restore_archived_authorized(
    conn: &Connection,
    id: &str,
    authorize: ByIdNamespaceAuthorizer<'_>,
) -> Result<bool> {
    restore_archived_impl(conn, id, Some(authorize))
}

/// [`create_link_inbound`] for the federated `links[]` lane: BOTH endpoints'
/// stored namespaces are re-authorized under the link transaction's write lock.
///
/// # Errors
///
/// Everything [`create_link_inbound`] returns, plus an
/// [`InboundByIdNamespaceRefused`] when either locked endpoint is outside the
/// peer's scope (nothing is written).
pub fn create_link_inbound_authorized(
    conn: &Connection,
    link: &MemoryLink,
    attest_level: &str,
    authorize: ByIdNamespaceAuthorizer<'_>,
) -> Result<()> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    in_write_txn(conn, || {
        for endpoint in [&link.source_id, &link.target_id] {
            recheck_live(
                conn,
                crate::federation::receive_auth::LANE_LINKS,
                endpoint,
                authorize,
            )?;
        }
        create_link_inbound(conn, link, attest_level)
    })
}
