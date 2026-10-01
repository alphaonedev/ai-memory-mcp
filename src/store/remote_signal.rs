// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4026 — the outcome type of [`super::MemoryStore::apply_remote_signal`].
//!
//! Its own module so the trait file does not grow (module-size ceilings only
//! fall) and so the type sits apart from unrelated additions to `mod.rs`.

use crate::models::AttestLevel;

/// Outcome of [`super::MemoryStore::apply_remote_signal`]: whether the call
/// persisted the signal or found it already stored.
///
/// The federation receive funnel charges the author's cumulative storage-bytes
/// quota BEFORE the write (the quota lives on the SQLite metadata database even
/// on postgres-backed daemons, so the two cannot share a transaction). It needs
/// this outcome to refund, exactly, a charge that bought no storage.
///
/// # Invariants (#4026, 5-agent vote 4d3ea1c5, memory cc79c670)
///
/// - An `Err` from `apply_remote_signal` means NO row was stored, so the caller
///   may refund its pre-charge on `Err` without under-counting.
/// - An adapter that overrides `apply_remote_signal` with an insert-if-absent
///   statement (`INSERT .. ON CONFLICT DO NOTHING`) MUST map
///   `rows_affected == 0` to [`RemoteSignalApply::AlreadyPresent`], never to
///   `Inserted`; otherwise the caller keeps a charge for storage never used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSignalApply {
    /// The signal was newly persisted by THIS call. Carries its attestation
    /// label: `self_signed` when its embedded signature verifies, else
    /// `unsigned`.
    Inserted(AttestLevel),
    /// A signal with this UUID was already stored: nothing was written (the
    /// idempotent replay no-op), so no storage was consumed.
    AlreadyPresent,
}

impl RemoteSignalApply {
    /// `true` iff this call persisted the signal (consumed storage).
    #[must_use]
    pub fn stored_now(self) -> bool {
        matches!(self, Self::Inserted(_))
    }
}
