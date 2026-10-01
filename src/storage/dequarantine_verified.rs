// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4208 — the evidence-bound route-OUT dequarantine-on-attest (sqlite).
//!
//! #1948 releases a quarantined row when a verified `agent_attested` unit for
//! the same id arrives. Pre-#4208 the release keyed on the INBOUND's
//! attestation alone, so a validly signed but OLDER unit that LOST the
//! newer-wins merge released a row still carrying the local, never-attested
//! content. The release now reads the PERSISTED row inside one write
//! transaction and clears the quarantine only when that row shows
//! the verified unit whose signed content won the merge
//! ([`crate::models::persisted_is_verified_unit`]).
//! Anything else leaves the row quarantined (fail closed); an operator release
//! (`operator_dequarantine`) remains the route out.

use anyhow::Result;
use rusqlite::Connection;

use crate::models::{LifecycleState, Memory};

/// Clear `id`'s quarantine only if the stored row shows `verified_inbound`'s signed content.
///
/// `verified_inbound` must be the unit THIS node verified (the receive path's
/// post-`apply_inbound_write_attestation` row). Returns `true` when a
/// quarantine was cleared; `false` when the row is absent, not quarantined, or
/// does not carry the verified surface.
///
/// # Errors
/// Propagates a record-stop refusal, a read/decrypt failure (fail closed: the
/// row stays quarantined) or the UPDATE error.
pub fn dequarantine_if_verified_unit(
    conn: &Connection,
    id: &str,
    verified_inbound: &Memory,
) -> Result<bool> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    // One write lock from the read to the UPDATE: a concurrent writer (another
    // process on this file) cannot swap the content between check and release.
    let txn = crate::storage::connection::WriteTxn::begin(conn)?;
    let Some(persisted) = super::get_any(conn, id)? else {
        return Ok(false);
    };
    if persisted.lifecycle_state != LifecycleState::Quarantined {
        return Ok(false);
    }
    if !crate::models::persisted_is_verified_unit(&persisted, verified_inbound) {
        return Ok(false);
    }
    let released = super::dequarantine(conn, id)?;
    txn.commit()?;
    Ok(released)
}
