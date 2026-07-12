// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1955 [P1][R45] — substrate **record-stop** actuator (SAL surface).
//!
//! The backend-agnostic flag registry + signed-attestation logic lives in
//! the NON-feature-gated [`crate::storage::record_stop`] module so
//! record-stop compiles and works in the default (non-`sal`) sqlite build
//! — the config the stdio MCP server ships. This module is the thin
//! `sal`-gated SAL surface layered on top: it re-exports the shared items
//! and adds the two gates that return the SAL-only
//! [`super::StoreError::Stopped`] (mapped to HTTP 503 via
//! `store_err_to_response`), keeping the SAL `MemoryStore::record_stop`
//! trait method, the CLI `stop` verb, and the postgres store instance flag
//! reading from the SAME single-source-of-truth registry.

use std::path::Path;

// Re-export the shared, non-gated surface so existing
// `crate::store::record_stop::*` call sites (the sqlite/postgres adapters,
// the CLI `stop` verb, the #1955 integration test) keep resolving here.
pub use crate::storage::record_stop::{
    RecordStopFlag, RecordStopStatus, SCOPE_RECORD_PLANE, actuate_sqlite, build_attestation,
    read_state_sqlite, seed_from_conn, status_sqlite,
};

/// SAL write-funnel gate keyed by the store's DB path — the sqlite
/// adapter's gate. Returns [`super::StoreError::Stopped`] when the record
/// plane is stopped so the SAL surface refuses with the typed 503 rather
/// than the `db::`-layer `StorageError::RecordStopped`.
///
/// # Errors
///
/// [`super::StoreError::Stopped`] when the record plane is stopped.
pub fn gate_sqlite_path(path: &Path) -> Result<(), super::StoreError> {
    gate_flag(&crate::storage::record_stop::flag_for_key(path))
}

/// SAL write-funnel gate over a shared [`RecordStopFlag`] — the postgres
/// store instance's gate. Maps the shared stop state to the SAL-only
/// [`super::StoreError::Stopped`].
///
/// # Errors
///
/// [`super::StoreError::Stopped`] when the record plane is stopped.
pub fn gate_flag(flag: &RecordStopFlag) -> Result<(), super::StoreError> {
    match flag.stop_refusal() {
        Some((issued_by, scope)) => Err(super::StoreError::Stopped { issued_by, scope }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sal_gate_running_is_ok_stopped_refuses() {
        let flag = RecordStopFlag::default();
        assert!(!flag.is_stopped());
        assert!(gate_flag(&flag).is_ok(), "running plane must not gate");

        flag.engage("ai:operator", SCOPE_RECORD_PLANE);
        assert!(flag.is_stopped());
        match gate_flag(&flag) {
            Err(super::super::StoreError::Stopped { issued_by, scope }) => {
                assert_eq!(issued_by, "ai:operator");
                assert_eq!(scope, SCOPE_RECORD_PLANE);
            }
            other => panic!("expected Stopped, got {other:?}"),
        }

        flag.release();
        assert!(!flag.is_stopped());
        assert!(gate_flag(&flag).is_ok(), "resume restores the running path");
    }
}
