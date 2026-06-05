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

/// A reloadable slot holding zero-or-one outbound credential plus the
/// node's anchor-first intermediate CA certs (empty ⇒ a direct, root-signed
/// leaf — the P2/P3 one-level posture).
///
/// Separated from the process-global singleton ([`global`]) so the
/// swap/snapshot semantics are unit-testable without touching global
/// state. The lock is never held across a network send — callers take an
/// `Arc` snapshot and drop the guard immediately.
///
/// The leaf and intermediates live in independent slots because they rotate
/// on different cadences: the leaf is short-lived (≈1h) and renewed by the
/// file-refresh worker, while an intermediate CA cert is long-lived (≈1d)
/// and stable across many leaf renewals. Swapping the leaf must not clobber
/// the intermediates, so [`store`](Self::store) touches only the leaf slot.
#[derive(Debug)]
pub struct OutboundCredentialHolder {
    inner: RwLock<Option<Arc<SignedCredential>>>,
    intermediates: RwLock<Arc<Vec<SignedCredential>>>,
}

impl OutboundCredentialHolder {
    /// Construct a holder seeded with an initial credential (or none) and no
    /// intermediates (a direct leaf).
    #[must_use]
    pub fn new(initial: Option<SignedCredential>) -> Self {
        Self {
            inner: RwLock::new(initial.map(Arc::new)),
            intermediates: RwLock::new(Arc::new(Vec::new())),
        }
    }

    /// Construct a holder seeded with both a leaf and anchor-first
    /// intermediates (a hierarchical posture).
    #[must_use]
    pub fn with_chain(
        initial: Option<SignedCredential>,
        intermediates: Vec<SignedCredential>,
    ) -> Self {
        Self {
            inner: RwLock::new(initial.map(Arc::new)),
            intermediates: RwLock::new(Arc::new(intermediates)),
        }
    }

    /// Take a cheap `Arc` snapshot of the currently-held credential.
    /// `None` = this node holds no credential and presents only its
    /// per-message signature (receiver falls back to per-peer `.pub`).
    #[must_use]
    pub fn current(&self) -> Option<Arc<SignedCredential>> {
        self.read_guard().clone()
    }

    /// Take a cheap `Arc` snapshot of the held anchor-first intermediates.
    /// An empty list = a direct leaf (no [`CHAIN_HEADER`] is emitted).
    ///
    /// [`CHAIN_HEADER`]: super::chain::CHAIN_HEADER
    #[must_use]
    pub fn current_intermediates(&self) -> Arc<Vec<SignedCredential>> {
        self.intermediates_read_guard().clone()
    }

    /// Atomically replace the held credential — the renewal worker calls
    /// this after minting / loading a fresh one. A subsequent [`current`]
    /// observes the new value; in-flight snapshots keep their old `Arc`.
    /// Leaves the intermediates slot untouched.
    ///
    /// [`current`]: Self::current
    pub fn store(&self, cred: Option<SignedCredential>) {
        *self.write_guard() = cred.map(Arc::new);
    }

    /// Atomically replace the held intermediates (the slower-rotating
    /// intermediate-CA refresh path). Leaves the leaf slot untouched.
    pub fn store_intermediates(&self, intermediates: Vec<SignedCredential>) {
        *self.intermediates_write_guard() = Arc::new(intermediates);
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

    fn intermediates_read_guard(
        &self,
    ) -> std::sync::RwLockReadGuard<'_, Arc<Vec<SignedCredential>>> {
        self.intermediates
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn intermediates_write_guard(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, Arc<Vec<SignedCredential>>> {
        self.intermediates
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

/// Load the held intermediates named by `AI_MEMORY_FED_CRED_CHAIN_PATH`,
/// logging (not propagating) a load fault — an unreadable/garbled chain file
/// must degrade to "hold no intermediates" (direct-leaf path), never crash
/// the daemon.
fn load_intermediates_from_env_logged() -> Vec<SignedCredential> {
    super::chain::load_intermediates_from_env().unwrap_or_else(|e| {
        tracing::warn!(target: "federation::signing", error = %e,
            "failed to load outbound federation intermediate chain; presenting a direct leaf only");
        Vec::new()
    })
}

/// The process-wide outbound credential holder, seeded once from
/// `AI_MEMORY_FED_CRED_PATH` (leaf) + `AI_MEMORY_FED_CRED_CHAIN_PATH`
/// (intermediates) on first access.
fn global() -> &'static OutboundCredentialHolder {
    static GLOBAL: OnceLock<OutboundCredentialHolder> = OnceLock::new();
    GLOBAL.get_or_init(|| {
        OutboundCredentialHolder::with_chain(
            load_from_env_logged(),
            load_intermediates_from_env_logged(),
        )
    })
}

/// The process-wide holder, for the renewal worker to refresh in place.
#[must_use]
pub fn shared() -> &'static OutboundCredentialHolder {
    global()
}

/// Snapshot of the node's currently-held outbound credential (hot path,
/// called per outbound federation POST).
#[must_use]
pub fn current() -> Option<Arc<SignedCredential>> {
    global().current()
}

/// Snapshot of the node's held anchor-first intermediates (hot path, called
/// per outbound POST alongside [`current`] to emit the chain header).
#[must_use]
pub fn current_intermediates() -> Arc<Vec<SignedCredential>> {
    global().current_intermediates()
}

/// Replace the process-wide held credential with `cred` (renewal worker).
pub fn store(cred: Option<SignedCredential>) {
    global().store(cred);
}

/// Replace the process-wide held intermediates (intermediate-CA refresh).
pub fn store_intermediates(intermediates: Vec<SignedCredential>) {
    global().store_intermediates(intermediates);
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

/// Reload the process-wide held intermediates from
/// `AI_MEMORY_FED_CRED_CHAIN_PATH` — the slower-rotating intermediate-CA
/// refresh path. An unset env var or missing file resets to no intermediates
/// (direct leaf).
///
/// # Errors
/// Propagates a read/parse fault from
/// [`super::chain::load_intermediates_from_env`]; the previously-held
/// intermediates are left untouched on error (no reset).
pub fn reload_intermediates_from_env() -> std::io::Result<()> {
    let next = super::chain::load_intermediates_from_env()?;
    global().store_intermediates(next);
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

    fn intermediate_cert(subject: &str, subject_seed: u8, issuer_seed: u8) -> SignedCredential {
        let subject_key = signing_key(subject_seed);
        issuer(issuer_seed)
            .issue_intermediate(subject, &subject_key.verifying_key(), NOW_UNIX)
            .expect("mint intermediate")
    }

    #[test]
    fn new_holder_has_no_intermediates() {
        let holder = OutboundCredentialHolder::new(Some(cred_for("node-1", 7, 1)));
        assert!(holder.current_intermediates().is_empty());
    }

    #[test]
    fn with_chain_seeds_both_leaf_and_intermediates() {
        let leaf = cred_for("region/nyc/node-1", 7, 2);
        let inter = intermediate_cert("region/nyc/ca", 2, 1);
        let holder = OutboundCredentialHolder::with_chain(Some(leaf), vec![inter.clone()]);
        let got = holder.current_intermediates();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].credential(), inter.credential());
    }

    #[test]
    fn store_intermediates_swaps_without_touching_leaf() {
        let leaf = cred_for("region/nyc/node-1", 7, 2);
        let holder = OutboundCredentialHolder::with_chain(Some(leaf.clone()), Vec::new());
        let inter = intermediate_cert("region/nyc/ca", 2, 1);
        holder.store_intermediates(vec![inter.clone()]);
        assert_eq!(holder.current_intermediates().len(), 1);
        // The leaf slot is untouched by the intermediates swap.
        assert_eq!(
            holder.current().expect("leaf present").credential(),
            leaf.credential()
        );
    }

    #[test]
    fn store_leaf_does_not_clobber_intermediates() {
        let inter = intermediate_cert("region/nyc/ca", 2, 1);
        let holder = OutboundCredentialHolder::with_chain(
            Some(cred_for("node-old", 7, 2)),
            vec![inter.clone()],
        );
        holder.store(Some(cred_for("node-new", 9, 2)));
        assert_eq!(
            holder
                .current()
                .expect("present")
                .credential()
                .subject_agent_id,
            "node-new"
        );
        // Renewing the short-lived leaf leaves the long-lived chain intact.
        assert_eq!(holder.current_intermediates().len(), 1);
        assert_eq!(
            holder.current_intermediates()[0].credential(),
            inter.credential()
        );
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
