// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! The node's own *outbound* federation credential — the one it presents
//! on the wire (`X-Memory-Cred`) so peers verify its per-message signature
//! against the trust bundle instead of a manually enrolled `.pub`.
//!
//! P3a held this in a boot-once `OnceLock<Option<SignedCredential>>` read
//! directly inside `post_once` — correct but frozen at first read, so a
//! renewed credential on disk was never picked up. This module replaces
//! that with a *reloadable* holder: a snapshot is taken per outbound POST
//! ([`current`]), and the P3b renewal worker swaps a fresh credential in
//! ([`store`] / [`reload_from_env`]) without restarting the daemon.
//!
//! The hot-path read returns an `Arc` snapshot so attaching the header
//! never clones the credential bytes and never holds the lock across the
//! network send.

use std::sync::{Arc, OnceLock, RwLock};

use super::credential::SignedCredential;

/// A reloadable slot holding zero-or-one outbound credential.
///
/// Separated from the process-global singleton ([`global`]) so the
/// swap/snapshot semantics are unit-testable without touching global
/// state. The lock is never held across a network send — callers take an
/// `Arc` snapshot and drop the guard immediately.
#[derive(Debug)]
pub struct OutboundCredentialHolder {
    inner: RwLock<Option<Arc<SignedCredential>>>,
}

impl OutboundCredentialHolder {
    /// Construct a holder seeded with an initial credential (or none).
    #[must_use]
    pub fn new(initial: Option<SignedCredential>) -> Self {
        Self {
            inner: RwLock::new(initial.map(Arc::new)),
        }
    }

    /// Take a cheap `Arc` snapshot of the currently-held credential.
    /// `None` = this node holds no credential and presents only its
    /// per-message signature (receiver falls back to per-peer `.pub`).
    #[must_use]
    pub fn current(&self) -> Option<Arc<SignedCredential>> {
        self.read_guard().clone()
    }

    /// Atomically replace the held credential — the renewal worker calls
    /// this after minting / loading a fresh one. A subsequent [`current`]
    /// observes the new value; in-flight snapshots keep their old `Arc`.
    pub fn store(&self, cred: Option<SignedCredential>) {
        *self.write_guard() = cred.map(Arc::new);
    }

    fn read_guard(&self) -> std::sync::RwLockReadGuard<'_, Option<Arc<SignedCredential>>> {
        // Poison from a panic elsewhere must not wedge the federation
        // send path — recover the inner value rather than propagate.
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_guard(&self) -> std::sync::RwLockWriteGuard<'_, Option<Arc<SignedCredential>>> {
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Load the held credential named by `AI_MEMORY_FED_CRED_PATH`, logging
/// (not propagating) a load fault — an unreadable/garbled credential file
/// must degrade to "hold nothing" (legacy per-peer path), never crash the
/// daemon or partition the hive.
fn load_from_env_logged() -> Option<SignedCredential> {
    SignedCredential::load_from_env().unwrap_or_else(|e| {
        tracing::warn!(target: "federation::signing", error = %e,
            "failed to load outbound federation credential; presenting per-message signature only");
        None
    })
}

/// The process-wide outbound credential holder, seeded once from
/// `AI_MEMORY_FED_CRED_PATH` on first access.
fn global() -> &'static OutboundCredentialHolder {
    static GLOBAL: OnceLock<OutboundCredentialHolder> = OnceLock::new();
    GLOBAL.get_or_init(|| OutboundCredentialHolder::new(load_from_env_logged()))
}

/// Snapshot of the node's currently-held outbound credential (hot path,
/// called per outbound federation POST).
#[must_use]
pub fn current() -> Option<Arc<SignedCredential>> {
    global().current()
}

/// Replace the process-wide held credential with `cred` (renewal worker).
pub fn store(cred: Option<SignedCredential>) {
    global().store(cred);
}

/// Reload the process-wide held credential from `AI_MEMORY_FED_CRED_PATH`
/// — the file-refresh renewal path (an external issuer rewrites the file;
/// the worker re-reads it on a timer).
///
/// # Errors
/// Propagates a read/parse fault from [`SignedCredential::load_from_env`]
/// so the caller can log it; the previously-held credential is left
/// untouched on error (no swap to `None`).
pub fn reload_from_env() -> std::io::Result<()> {
    let next = SignedCredential::load_from_env()?;
    global().store(next);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::identity::issuer::{FederationIssuer, IssuerConfig};
    use ed25519_dalek::SigningKey;

    const NOW_UNIX: i64 = 1_900_000_000;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn issuer(seed: u8) -> FederationIssuer {
        FederationIssuer::new(
            signing_key(seed),
            IssuerConfig::new("trust-domain-root", "fleet.example"),
        )
    }

    fn cred_for(subject: &str, subject_seed: u8, issuer_seed: u8) -> SignedCredential {
        let subject_key = signing_key(subject_seed);
        issuer(issuer_seed)
            .issue(subject, &subject_key.verifying_key(), NOW_UNIX)
            .expect("mint")
    }

    #[test]
    fn empty_holder_yields_no_credential() {
        let holder = OutboundCredentialHolder::new(None);
        assert!(holder.current().is_none());
    }

    #[test]
    fn seeded_holder_yields_that_credential() {
        let cred = cred_for("region/nyc/node-1", 7, 1);
        let holder = OutboundCredentialHolder::new(Some(cred.clone()));
        let got = holder.current().expect("present");
        assert_eq!(got.credential(), cred.credential());
    }

    #[test]
    fn store_swaps_the_held_credential() {
        let holder = OutboundCredentialHolder::new(Some(cred_for("node-old", 7, 1)));
        let fresh = cred_for("node-new", 9, 1);
        holder.store(Some(fresh.clone()));
        let got = holder.current().expect("present");
        assert_eq!(got.credential().subject_agent_id, "node-new");
        assert_eq!(got.credential(), fresh.credential());
    }

    #[test]
    fn store_none_clears_the_credential() {
        let holder = OutboundCredentialHolder::new(Some(cred_for("node-x", 7, 1)));
        assert!(holder.current().is_some());
        holder.store(None);
        assert!(holder.current().is_none());
    }

    #[test]
    fn snapshot_taken_before_store_is_unaffected_by_swap() {
        let holder = OutboundCredentialHolder::new(Some(cred_for("node-a", 7, 1)));
        let snapshot = holder.current().expect("present");
        holder.store(Some(cred_for("node-b", 9, 1)));
        // The Arc taken before the swap still observes the old subject.
        assert_eq!(snapshot.credential().subject_agent_id, "node-a");
        assert_eq!(
            holder
                .current()
                .expect("present")
                .credential()
                .subject_agent_id,
            "node-b"
        );
    }
}
