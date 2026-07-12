// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1955 [P1][R45] — substrate **record-stop** actuator.
//!
//! A record-plane stop primitive: when engaged, every *mutating*
//! record-plane operation (store / update / link / delete / promote /
//! consolidate — plus the federation-receive convergence writes)
//! REFUSES with a typed error ([`super::StoreError::Stopped`] on the SAL
//! trait surface, [`crate::storage::StorageError::RecordStopped`] on the
//! bare-`Connection` `db::` funnel the MCP stdio path uses). **Reads stay
//! live** (get / list / search / recall / verify) so the record remains
//! auditable while stopped.
//!
//! # Vocabulary binding — record-stop, NOT kill-switch (§2.3)
//!
//! Verbatim honest ceiling (ROADMAP §2.3 / the TRACT definitive doc):
//! *Stoppability is record-integrity control, NOT behavioral control of
//! a superintelligence. The Stopper can freeze the append/promote
//! boundary in under a second; it CANNOT pause, redirect, or kill the
//! cognition that uses the substrate. The veto is authority over the
//! **witness**, not the **witnessed**.* This actuator stops **this
//! substrate's own record plane** — it makes no claim over any external
//! cognition, and enumerating ungovernable copies of the substrate is a
//! permanent limit, not a bug.
//!
//! # Mechanism — the signed attestation IS the persisted flag
//!
//! There is no new table and no schema-version bump. Engaging or
//! releasing the stop appends ONE Ed25519-signable row to the
//! append-only [`crate::signed_events`] chain
//! ([`event_types::SUBSTRATE_RECORD_STOP`] /
//! [`event_types::SUBSTRATE_RECORD_RESUME`]), which exists on BOTH the
//! sqlite and postgres backends. The current stop state is *derived*
//! from the latest of those two events by chain `sequence`
//! ([`read_state_sqlite`] / the postgres twin), so the flag survives a
//! daemon restart for free — a reopened store re-derives it from the
//! audit chain.
//!
//! # Hot path — an atomic load behind a per-DB flag
//!
//! The sqlite funnel's stop state is cached in a process-global registry
//! keyed by the DB file path ([`SQLITE_FLAGS`]) so every writer of one
//! DB — the SAL adapter, the MCP-direct `db::` path, the CLI — reads ONE
//! truth, while distinct DBs (distinct test temp files) never
//! cross-contaminate. Postgres holds the flag per [`super::postgres`]
//! store instance. Either way the funnel gate is a single acquire atomic
//! load; engaging/releasing flips it synchronously, so the stop takes
//! effect on the *next* write (the ≤100 ms effect-latency target is
//! measured as: stop issued → next write refused).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Context, Result};

use crate::signed_events::{self, SignedEvent, event_types, payload_hash};

/// The single scope this actuator governs: the substrate's whole
/// mutating record plane. Modelled as a fixed value (there is exactly
/// one record plane) so the scope is invariant across restarts and need
/// not be recovered from the attestation payload — the signed event
/// still commits to it via [`attestation_payload`].
pub const SCOPE_RECORD_PLANE: &str = "record-plane";

/// The `action` field committed inside a `substrate.record_stop`
/// attestation payload.
const ACTION_STOP: &str = "record_stop";
/// The `action` field committed inside a `substrate.record_resume`
/// attestation payload.
const ACTION_RESUME: &str = "record_resume";

/// Metadata backing a live refusal — who engaged the stop and over what
/// scope. Read only on the (cold) refusal path.
#[derive(Debug, Clone, Default)]
struct StopMeta {
    issued_by: String,
    scope: String,
}

/// Shared, cheap-to-clone cache of the record-stop state. The
/// [`AtomicBool`] is the hot-path read; the [`Mutex`] is consulted only
/// when building a refusal.
#[derive(Debug, Clone, Default)]
pub struct RecordStopFlag(Arc<RecordStopInner>);

#[derive(Debug, Default)]
struct RecordStopInner {
    stopped: AtomicBool,
    meta: Mutex<StopMeta>,
}

/// A point-in-time view of the record-stop state, for the CLI/status
/// surface.
#[derive(Debug, Clone)]
pub struct RecordStopStatus {
    /// `true` when the record plane is stopped (mutations refuse).
    pub stopped: bool,
    /// The principal that engaged the current stop (empty when running).
    pub issued_by: String,
    /// The governed scope ([`SCOPE_RECORD_PLANE`]).
    pub scope: String,
}

impl RecordStopFlag {
    /// `true` when the record plane is currently stopped.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.0.stopped.load(Ordering::Acquire)
    }

    /// Flip the cache to STOPPED and record who/scope for the refusal
    /// message. Does NOT persist — the caller emits the signed
    /// attestation.
    pub fn engage(&self, issued_by: &str, scope: &str) {
        {
            let mut meta = self.lock_meta();
            meta.issued_by = issued_by.to_string();
            meta.scope = scope.to_string();
        }
        self.0.stopped.store(true, Ordering::Release);
    }

    /// Flip the cache back to RUNNING.
    pub fn release(&self) {
        self.0.stopped.store(false, Ordering::Release);
        self.lock_meta().issued_by.clear();
    }

    /// Apply a derived [`RecordStopStatus`] to the cache (used when
    /// seeding from the audit chain on open).
    fn apply(&self, status: &RecordStopStatus) {
        if status.stopped {
            self.engage(&status.issued_by, &status.scope);
        } else {
            self.release();
        }
    }

    fn lock_meta(&self) -> std::sync::MutexGuard<'_, StopMeta> {
        self.0
            .meta
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The SAL write-funnel gate. `Ok(())` on the running path (one
    /// atomic load); [`super::StoreError::Stopped`] when engaged.
    ///
    /// # Errors
    ///
    /// Returns [`super::StoreError::Stopped`] when the record plane is
    /// stopped.
    pub fn gate(&self) -> Result<(), super::StoreError> {
        if self.is_stopped() {
            let meta = self.lock_meta();
            Err(super::StoreError::Stopped {
                issued_by: meta.issued_by.clone(),
                scope: meta.scope.clone(),
            })
        } else {
            Ok(())
        }
    }

    /// A [`RecordStopStatus`] snapshot of the cache.
    #[must_use]
    pub fn status(&self) -> RecordStopStatus {
        let stopped = self.is_stopped();
        let meta = self.lock_meta();
        RecordStopStatus {
            stopped,
            issued_by: meta.issued_by.clone(),
            scope: if meta.scope.is_empty() {
                SCOPE_RECORD_PLANE.to_string()
            } else {
                meta.scope.clone()
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Sqlite: process-global per-DB-path flag registry.
// ---------------------------------------------------------------------------

/// Per-DB-path record-stop flags for the sqlite funnel. Keyed by the DB
/// file path so the SAL adapter, the MCP-direct `db::` path, and the CLI
/// share one truth for a given DB while distinct DBs (distinct test temp
/// files) never cross-contaminate.
static SQLITE_FLAGS: LazyLock<Mutex<HashMap<PathBuf, RecordStopFlag>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Resolve a stable registry key for a `Connection`: the DB file path
/// when it has one, else a per-`Connection` sentinel (in-memory DBs) so
/// two in-memory connections in one process do not collide.
fn conn_key(conn: &rusqlite::Connection) -> PathBuf {
    match conn.path() {
        Some(p) if !p.is_empty() && p != ":memory:" => PathBuf::from(p),
        _ => PathBuf::from(format!("mem:{:p}", std::ptr::from_ref(conn))),
    }
}

fn flag_registry() -> std::sync::MutexGuard<'static, HashMap<PathBuf, RecordStopFlag>> {
    SQLITE_FLAGS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Fetch (get-or-create) the flag for a DB path without seeding it from
/// the audit chain — a never-touched DB defaults to RUNNING.
fn flag_for_key(key: &Path) -> RecordStopFlag {
    let mut reg = flag_registry();
    reg.entry(key.to_path_buf()).or_default().clone()
}

/// Seed (or re-seed) the flag for `conn`'s DB from the audit chain. Call
/// on store open / db open so the persisted stop survives restart.
///
/// # Errors
///
/// Propagates the `signed_events` read error.
pub fn seed_from_conn(conn: &rusqlite::Connection) -> Result<()> {
    let status = read_state_sqlite(conn)?;
    let key = conn_key(conn);
    flag_for_key(&key).apply(&status);
    Ok(())
}

/// SAL-surface gate for the sqlite adapter, keyed by the store's DB path.
///
/// # Errors
///
/// [`super::StoreError::Stopped`] when the record plane is stopped.
pub fn gate_sqlite_path(path: &Path) -> Result<(), super::StoreError> {
    flag_for_key(path).gate()
}

/// `db::`-surface gate for the bare-`Connection` funnel (the MCP stdio
/// write path). Lazily seeds the flag from the audit chain the first
/// time a given DB is touched so a freshly-opened `Connection` that
/// never went through the SAL adapter still honors a persisted stop.
///
/// # Errors
///
/// [`crate::storage::StorageError::RecordStopped`] when stopped.
pub fn gate_storage_conn(conn: &rusqlite::Connection) -> Result<(), crate::storage::StorageError> {
    let key = conn_key(conn);
    let (flag, freshly_created) = {
        let mut reg = flag_registry();
        let existed = reg.contains_key(&key);
        let flag = reg.entry(key.clone()).or_default().clone();
        (flag, !existed)
    };
    if freshly_created {
        // First touch of this DB in-process: derive the persisted state.
        // A read failure is non-fatal (leave RUNNING) — never wedge a
        // write on an audit-read hiccup.
        if let Ok(status) = read_state_sqlite(conn) {
            flag.apply(&status);
        }
    }
    let status = flag.status();
    if status.stopped {
        Err(crate::storage::StorageError::RecordStopped {
            issued_by: status.issued_by,
            scope: status.scope,
        })
    } else {
        Ok(())
    }
}

/// Persist + apply a record-stop actuation on the sqlite backend:
/// appends the signed attestation to the chain AND flips the per-DB
/// cache so the very next write in this process refuses (engage) /
/// proceeds (resume). Returns `true` when the state actually changed.
///
/// # Errors
///
/// Propagates the `signed_events` append error.
pub fn actuate_sqlite(
    conn: &rusqlite::Connection,
    engage: bool,
    issued_by: &str,
    scope: &str,
) -> Result<bool> {
    let key = conn_key(conn);
    let flag = flag_for_key(&key);
    if flag.is_stopped() == engage {
        return Ok(false); // already in the desired state — no duplicate event
    }
    append_attestation_sqlite(conn, engage, issued_by, scope)?;
    if engage {
        flag.engage(issued_by, scope);
    } else {
        flag.release();
    }
    Ok(true)
}

/// Current record-stop status for a sqlite `Connection` (seeds from the
/// audit chain if this DB was never touched in-process).
///
/// # Errors
///
/// Propagates the `signed_events` read error.
pub fn status_sqlite(conn: &rusqlite::Connection) -> Result<RecordStopStatus> {
    let key = conn_key(conn);
    let seeded = flag_registry().contains_key(&key);
    if !seeded {
        seed_from_conn(conn)?;
    }
    Ok(flag_for_key(&key).status())
}

// ---------------------------------------------------------------------------
// Backend-agnostic attestation helpers.
// ---------------------------------------------------------------------------

/// Canonical bytes committed by a record-stop / record-resume
/// attestation. The signed event's `payload_hash` is
/// `SHA-256(attestation_payload(..))`, binding `{action, issued_by,
/// timestamp, scope}` into the tamper-evident chain.
#[must_use]
pub fn attestation_payload(action: &str, issued_by: &str, timestamp: &str, scope: &str) -> Vec<u8> {
    let canonical = serde_json::json!({
        "action": action,
        "issued_by": issued_by,
        "timestamp": timestamp,
        "scope": scope,
    });
    // Serializing a `serde_json::Value` of plain strings is infallible.
    serde_json::to_vec(&canonical).unwrap_or_default()
}

/// Build the `SignedEvent` for a stop/resume actuation, signed through
/// the established daemon audit-key ladder
/// ([`SignedEvent::with_daemon_signature`]) — signed when an audit key
/// is installed, honestly `unsigned` otherwise. Returns the event plus
/// the `DateTime` used so the postgres append path can bind the same
/// timestamp.
#[must_use]
pub fn build_attestation(
    engage: bool,
    issued_by: &str,
    scope: &str,
) -> (SignedEvent, chrono::DateTime<chrono::Utc>) {
    let now = chrono::Utc::now();
    let ts = now.to_rfc3339();
    let (event_type, action) = if engage {
        (event_types::SUBSTRATE_RECORD_STOP, ACTION_STOP)
    } else {
        (event_types::SUBSTRATE_RECORD_RESUME, ACTION_RESUME)
    };
    let hash = payload_hash(&attestation_payload(action, issued_by, &ts, scope));
    // `cause_hash = None`: the actuation event stands on its own payload
    // (the record-stop request has no distinct triggering-cause row).
    let event = SignedEvent::with_daemon_signature(
        hash,
        issued_by.to_string(),
        event_type.to_string(),
        ts,
        None,
    );
    (event, now)
}

/// Derive the current record-stop state from the sqlite `signed_events`
/// chain: the latest (highest-`sequence`) stop/resume event wins.
///
/// # Errors
///
/// Propagates the underlying `rusqlite` error if the query fails.
pub fn read_state_sqlite(conn: &rusqlite::Connection) -> Result<RecordStopStatus> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT event_type, agent_id FROM signed_events \
             WHERE event_type IN (?1, ?2) \
             ORDER BY sequence DESC, rowid DESC LIMIT 1",
            rusqlite::params![
                event_types::SUBSTRATE_RECORD_STOP,
                event_types::SUBSTRATE_RECORD_RESUME
            ],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .context("record_stop::read_state_sqlite")?;
    Ok(match row {
        Some((event_type, issued_by)) if event_type == event_types::SUBSTRATE_RECORD_STOP => {
            RecordStopStatus {
                stopped: true,
                issued_by,
                scope: SCOPE_RECORD_PLANE.to_string(),
            }
        }
        _ => RecordStopStatus {
            stopped: false,
            issued_by: String::new(),
            scope: SCOPE_RECORD_PLANE.to_string(),
        },
    })
}

/// Append the signed record-stop attestation event to the sqlite chain.
///
/// # Errors
///
/// Propagates the `signed_events` append error.
pub fn append_attestation_sqlite(
    conn: &rusqlite::Connection,
    engage: bool,
    issued_by: &str,
    scope: &str,
) -> Result<()> {
    let (event, _now) = build_attestation(engage, issued_by, scope);
    signed_events::append_signed_event(conn, &event)
        .context("record_stop::append_attestation_sqlite")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_gate_running_is_ok_stopped_refuses() {
        let flag = RecordStopFlag::default();
        assert!(!flag.is_stopped());
        assert!(flag.gate().is_ok(), "running plane must not gate");

        flag.engage("ai:operator", SCOPE_RECORD_PLANE);
        assert!(flag.is_stopped());
        match flag.gate() {
            Err(super::super::StoreError::Stopped { issued_by, scope }) => {
                assert_eq!(issued_by, "ai:operator");
                assert_eq!(scope, SCOPE_RECORD_PLANE);
            }
            other => panic!("expected Stopped, got {other:?}"),
        }

        flag.release();
        assert!(!flag.is_stopped());
        assert!(flag.gate().is_ok(), "resume restores the running path");
    }

    #[test]
    fn attestation_payload_is_stable_and_commits_fields() {
        let a = attestation_payload(
            "record_stop",
            "ai:operator",
            "2026-07-12T00:00:00+00:00",
            "record-plane",
        );
        let b = attestation_payload(
            "record_stop",
            "ai:operator",
            "2026-07-12T00:00:00+00:00",
            "record-plane",
        );
        assert_eq!(a, b, "canonical bytes are deterministic");
        let differ = attestation_payload(
            "record_resume",
            "ai:operator",
            "2026-07-12T00:00:00+00:00",
            "record-plane",
        );
        assert_ne!(a, differ, "action is committed");
    }

    #[test]
    fn build_attestation_sets_event_type_by_action() {
        let (stop, _) = build_attestation(true, "ai:operator", SCOPE_RECORD_PLANE);
        assert_eq!(stop.event_type, event_types::SUBSTRATE_RECORD_STOP);
        let (resume, _) = build_attestation(false, "ai:operator", SCOPE_RECORD_PLANE);
        assert_eq!(resume.event_type, event_types::SUBSTRATE_RECORD_RESUME);
        assert_eq!(stop.payload_hash.len(), 32, "sha256 payload hash");
    }
}
