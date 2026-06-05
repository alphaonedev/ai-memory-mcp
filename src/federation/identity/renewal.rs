// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Renewal worker — keeps this node's held outbound credential fresh so a
//! short-lived credential never lapses on a long-running daemon.
//!
//! ## Why file-refresh (and not self-issuing) is the default
//!
//! The security premise of the whole epic is O(1) trust *without* spreading
//! the CA: receivers trust one issuer key, so a compromised *node* must not
//! be able to mint credentials for other identities. A node that held the
//! issuer signing key in order to renew its own credential would defeat
//! that. So the default worker is **file-refresh**: an external issuer
//! (operated centrally, attesting the node's mTLS identity per ADR-001
//! Decision 4) writes a fresh short-lived credential to
//! `AI_MEMORY_FED_CRED_PATH`; this worker re-reads that file on a timer and
//! swaps it into the live [`OutboundCredentialHolder`] without a restart.
//! Self-issuing (the node holds the issuer key) is a single-trust-domain /
//! dev convenience layered on later, not the enterprise default.
//!
//! Modeled on `spawn_replay_federation_push_dlq`: a spawned task that loops
//! `refresh_once → sleep(interval)`. The decision core ([`apply_refresh`])
//! is pure and unit-tested off the process-global holder.

use std::time::Duration;

use super::credential::SignedCredential;
use super::outbound::{self, OutboundCredentialHolder};

/// Default interval between credential-file refresh checks. One minute is
/// far below any sane credential TTL, so a freshly written credential is
/// picked up long before the old one expires.
pub const DEFAULT_RENEWAL_INTERVAL_SECS: i64 = crate::SECS_PER_MINUTE;

/// Lead window before expiry within which the worker logs that the held
/// credential is nearing expiry and a fresh file has not yet arrived — an
/// operator signal that issuance is falling behind. A quarter of the
/// default 1h TTL leaves comfortable headroom.
pub const DEFAULT_RENEWAL_LEAD_SECS: i64 = crate::SECS_PER_HOUR / 4;

/// Outcome of a single refresh tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalOutcome {
    /// A new credential was read from disk and swapped into the holder.
    Reloaded,
    /// The on-disk credential matched the held one (or none was present);
    /// the holder was left untouched.
    Unchanged,
    /// The credential file could not be read/parsed; the previously-held
    /// credential is left in place (a bad file never drops a valid cred).
    Failed(String),
}

/// Pure decision core: given a freshly-loaded credential (or `None`),
/// decide whether to swap it into `holder`.
///
/// - `None` loaded (env unset OR the file transiently missing) → keep the
///   currently-held credential. A blinking file must never drop a still
///   valid credential and partition the node.
/// - Loaded credential equal to the held one → no swap (avoid churning the
///   `Arc` that in-flight POSTs are reading).
/// - Loaded credential different (or nothing held) → swap it in.
#[must_use]
pub fn apply_refresh(
    holder: &OutboundCredentialHolder,
    loaded: Option<SignedCredential>,
) -> RenewalOutcome {
    let Some(loaded) = loaded else {
        return RenewalOutcome::Unchanged;
    };
    match holder.current() {
        Some(current) if current.credential() == loaded.credential() => RenewalOutcome::Unchanged,
        _ => {
            holder.store(Some(loaded));
            RenewalOutcome::Reloaded
        }
    }
}

/// Reload the held credential from `AI_MEMORY_FED_CRED_PATH` into `holder`,
/// emitting operator telemetry on a reload, a load failure, or a held
/// credential that is at/near expiry.
pub fn refresh_once(holder: &OutboundCredentialHolder, now_unix: i64) -> RenewalOutcome {
    let loaded = match SignedCredential::load_from_env() {
        Ok(loaded) => loaded,
        Err(e) => {
            tracing::warn!(target: "federation::signing", error = %e,
                "outbound credential refresh: load failed; keeping the currently-held credential");
            return RenewalOutcome::Failed(e.to_string());
        }
    };
    let outcome = apply_refresh(holder, loaded);
    if outcome == RenewalOutcome::Reloaded {
        tracing::info!(target: "federation::signing",
            "outbound federation credential reloaded from disk");
    }
    if let Some(current) = holder.current() {
        let not_after = current.credential().not_after;
        if now_unix > not_after {
            tracing::warn!(target: "federation::signing", not_after,
                "held outbound credential has EXPIRED and no fresh credential is on disk; \
                 peers will fall back to per-peer enrollment for this node");
        } else if now_unix + DEFAULT_RENEWAL_LEAD_SECS >= not_after {
            tracing::info!(target: "federation::signing", not_after,
                "held outbound credential nearing expiry; awaiting a fresh credential file");
        }
    }
    outcome
}

/// Spawn the background credential-refresh worker. Mirrors
/// `spawn_replay_federation_push_dlq`: an immediate first tick (so a
/// credential written before boot is honoured at once) followed by
/// `refresh_once → sleep(interval)` forever.
pub fn spawn_refresh_outbound_credential(interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let now_unix = chrono::Utc::now().timestamp();
            let _ = refresh_once(outbound::shared(), now_unix);
            // FED-P4d — refresh the slower-rotating intermediate chain on the
            // same tick. A load/parse fault is logged and the prior chain is
            // retained (no reset), so a transiently-bad file never strips a
            // node of its hierarchical proof.
            if let Err(e) = outbound::reload_intermediates_from_env() {
                tracing::warn!(target: "federation::signing", error = %e,
                    "failed to reload outbound federation intermediate chain; retaining prior");
            }
            tokio::time::sleep(interval).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::identity::issuer::{FederationIssuer, IssuerConfig};
    use ed25519_dalek::SigningKey;

    fn issuer() -> FederationIssuer {
        FederationIssuer::new(
            SigningKey::from_bytes(&[1u8; 32]),
            IssuerConfig::new("trust-domain-root", "fleet.example"),
        )
    }

    fn cred_at(now_unix: i64) -> SignedCredential {
        let subject = SigningKey::from_bytes(&[7u8; 32]);
        issuer()
            .issue("region/nyc/node-1", &subject.verifying_key(), now_unix)
            .expect("mint")
    }

    #[test]
    fn loaded_none_keeps_held_credential() {
        let held = cred_at(1_900_000_000);
        let holder = OutboundCredentialHolder::new(Some(held.clone()));
        assert_eq!(apply_refresh(&holder, None), RenewalOutcome::Unchanged);
        assert_eq!(
            holder.current().expect("still held").credential(),
            held.credential()
        );
    }

    #[test]
    fn loaded_into_empty_holder_reloads() {
        let holder = OutboundCredentialHolder::new(None);
        let fresh = cred_at(1_900_000_000);
        assert_eq!(
            apply_refresh(&holder, Some(fresh.clone())),
            RenewalOutcome::Reloaded
        );
        assert_eq!(
            holder.current().expect("now held").credential(),
            fresh.credential()
        );
    }

    #[test]
    fn identical_loaded_credential_is_unchanged() {
        let held = cred_at(1_900_000_000);
        let holder = OutboundCredentialHolder::new(Some(held.clone()));
        assert_eq!(
            apply_refresh(&holder, Some(held)),
            RenewalOutcome::Unchanged
        );
    }

    #[test]
    fn newer_loaded_credential_swaps_in() {
        let old = cred_at(1_900_000_000);
        let holder = OutboundCredentialHolder::new(Some(old));
        // A re-mint an hour later has a different validity window, so its
        // claims differ and the worker must swap it in.
        let renewed = cred_at(1_900_000_000 + crate::SECS_PER_HOUR);
        assert_eq!(
            apply_refresh(&holder, Some(renewed.clone())),
            RenewalOutcome::Reloaded
        );
        assert_eq!(
            holder.current().expect("held").credential().not_after,
            renewed.credential().not_after
        );
    }
}
