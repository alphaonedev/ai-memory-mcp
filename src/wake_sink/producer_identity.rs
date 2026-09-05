// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3469 — the PRODUCTION join credential: the daemon's own enrolled
//! key, issuing a short-lived `a2a-hub/join/v1` delegation for the reserved
//! producer session.
//!
//! # One identity root
//!
//! There is exactly ONE private key involved on this host and the daemon
//! already has it: its enrolled
//! [`keypair::DAEMON_KEYPAIR_LABEL`] signing key, the same key it signs links
//! and personas with. This module does NOT mint a second enrolled root for
//! [`WAKE_HUB_PRODUCER`], does not read another agent's `.priv`, and writes no
//! key material of its own. `wake-hub-producer` is a scoped NAME the daemon's
//! root may speak under on the wake plane — the operator's allowlist row is
//! the single, revocable grant that says so — not an identity with a secret of
//! its own.
//!
//! # The session key never touches disk
//!
//! Each connection attempt generates a FRESH delegated keypair in memory,
//! mints a short-lived delegation for it with the enrolled root, signs the
//! hub's hello transcript with the delegate, and drops the delegate key. This
//! is strictly stronger than the on-disk bundle
//! [`crate::cli::identity_delegate`] writes for an external wake listener:
//! there is no file to steal and nothing to rotate, and a delegation that
//! outlives its process is not reachable.
//!
//! # Bounded, and revocable by the existing mechanism
//!
//! The delegation is minted for [`PRODUCER_DELEGATION_TTL_SECS`], far inside
//! [`MAX_DELEGATION_TTL_SECS`]. The hub revalidates every established session
//! once a second against its refreshed allowlist snapshot, so removing the
//! `wake-hub-producer` row — or revoking the daemon's root — stops the
//! forwarder within a second and it can never re-join. Expiry alone also ends
//! the session; the forwarder reconnects with a freshly minted delegation, and
//! that reconnect is jittered like every other.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use ed25519_dalek::{Signer as _, SigningKey};

use super::uds::{CredentialError, HelloCredential, JoinCredential};
use crate::identity::hub_delegation::{
    A2A_HUB_SCOPE, DelegationWire, check_ttl, sign_hub_delegation, verify_hub_delegation,
};
use crate::identity::keypair;
use crate::identity::sentinels::WAKE_HUB_PRODUCER;

/// Lifetime of a producer delegation, in seconds.
///
/// Short by design and far inside [`MAX_DELEGATION_TTL_SECS`]: the hub does no
/// store lookup, so a certificate's own expiry is one of the two things that
/// bounds revocation (the other is the allowlist refresh). A fresh one is
/// minted on every connection attempt, so shortening this costs reconnects,
/// never wakes.
pub const PRODUCER_DELEGATION_TTL_SECS: i64 = 3_600;

/// The daemon's enrolled key, issuing producer sessions.
pub struct DaemonIssuedCredential {
    /// The daemon's ENROLLED signing key. Never written anywhere by this type.
    root: SigningKey,
    /// The hub this credential mints for. Bound into the delegation, so a
    /// certificate minted for one hub cannot be presented at another.
    hub_id: String,
}

impl std::fmt::Debug for DaemonIssuedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the root. A Debug line is a log line.
        f.debug_struct("DaemonIssuedCredential")
            .field("agent_id", &WAKE_HUB_PRODUCER)
            .field("hub_id", &self.hub_id)
            .field("root", &"<enrolled signing key>")
            .finish()
    }
}

impl DaemonIssuedCredential {
    /// Load the daemon's enrolled signing key from `key_dir`.
    ///
    /// # Errors
    ///
    /// Refuses — with the exact remediation an operator needs — when the key
    /// directory holds no daemon keypair, or holds a PUBLIC-ONLY one. A
    /// public-only handle can verify but can never mint, and a daemon that
    /// cannot mint must not open a socket it will never be admitted on.
    pub fn from_key_dir(key_dir: &Path, hub_id: impl Into<String>) -> Result<Self> {
        let enrolled =
            keypair::load(keypair::DAEMON_KEYPAIR_LABEL, key_dir).with_context(|| {
                format!(
                    "wake sink: no enrolled `{}` keypair in {} — the daemon has no identity to \
                 issue a `{WAKE_HUB_PRODUCER}` session under. Start the daemon once to \
                 auto-generate it, or pre-stage it, then publish an allowlist row binding \
                 `{WAKE_HUB_PRODUCER}` to that public key with `ai-memory identity \
                 hub-cache --daemon-producer --out <allowlist>`.",
                    keypair::DAEMON_KEYPAIR_LABEL,
                    key_dir.display()
                )
            })?;
        let Some(root) = enrolled.private else {
            bail!(
                "wake sink: the `{}` keypair in {} is PUBLIC-ONLY, so this daemon cannot \
                 issue a `{WAKE_HUB_PRODUCER}` delegation. Restore the private half, or \
                 unset `[wake_hub].sink_socket` — a forwarder that can never authenticate \
                 must not open a socket.",
                keypair::DAEMON_KEYPAIR_LABEL,
                key_dir.display()
            );
        };
        Ok(Self {
            root,
            hub_id: hub_id.into(),
        })
    }

    /// Build directly from an already-loaded enrolled key.
    ///
    /// The seam tests use, so a test never has to stage a key directory to
    /// exercise the minting path.
    #[must_use]
    pub fn from_enrolled_key(root: SigningKey, hub_id: impl Into<String>) -> Self {
        Self {
            root,
            hub_id: hub_id.into(),
        }
    }

    /// The enrolled PUBLIC key an operator must bind to `wake-hub-producer` in
    /// the hub's allowlist. Public material only.
    #[must_use]
    pub fn enrolled_public_base64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(self.root.verifying_key().to_bytes())
    }

    /// Mint one short-lived delegation for a freshly generated delegate key.
    fn mint(&self) -> Result<(SigningKey, bytes::Bytes)> {
        let delegate = keypair::generate(WAKE_HUB_PRODUCER)
            .context("could not generate an ephemeral hub session key")?;
        let Some(delegate_private) = delegate.private else {
            bail!("generated delegate keypair is unexpectedly public-only");
        };
        // WHOLE SECONDS, deliberately. The verifier compares against its own
        // clock rendered at `SecondsFormat::Secs`
        // (`ScopedDelegationVerifier::now`), i.e. TRUNCATED DOWN to the second.
        // A `not_before` carrying sub-second precision is therefore in the
        // FUTURE for the verifier for up to a second — and this credential
        // mints milliseconds before it connects, so a nanosecond stamp would
        // make the handshake fail almost every time and turn the forwarder
        // into a reconnect loop that never authenticates. Truncating our own
        // stamp to the same granularity the verifier reads at removes the race
        // without widening the window: the start moves EARLIER by at most
        // 999 ms, never later, and the end moves with it so the TTL is exact.
        let now = chrono::Utc::now();
        let not_before = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let not_after = (now + chrono::Duration::seconds(PRODUCER_DELEGATION_TTL_SECS))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let mut wire = DelegationWire {
            principal: WAKE_HUB_PRODUCER.to_owned(),
            scope: A2A_HUB_SCOPE.to_owned(),
            delegate_key_id: delegate.public.to_bytes(),
            hub_id: self.hub_id.clone(),
            not_before,
            not_after,
            signature: [0u8; 64],
        };
        wire.signature = sign_hub_delegation(&self.root, &wire.as_delegation())
            .map_err(|e| anyhow::anyhow!("could not mint the producer delegation: {e}"))?;

        // Check the bounds we just claimed to honour rather than trusting the
        // arithmetic, and verify our own signature before presenting it — a
        // mint bug must surface here, not as an opaque hub refusal.
        check_ttl(&wire.as_delegation())
            .map_err(|e| anyhow::anyhow!("minted delegation failed its own window check: {e}"))?;
        verify_hub_delegation(
            &self.root.verifying_key(),
            &wire.as_delegation(),
            &wire.signature,
        )
        .map_err(|e| anyhow::anyhow!("minted delegation does not verify under its issuer: {e}"))?;

        let encoded = wire
            .encode()
            .map_err(|e| anyhow::anyhow!("could not encode the producer delegation: {e}"))?;
        Ok((delegate_private, bytes::Bytes::from(encoded)))
    }
}

impl JoinCredential for DaemonIssuedCredential {
    fn agent_id(&self) -> &str {
        WAKE_HUB_PRODUCER
    }

    fn sign_hello(&self, transcript: &[u8]) -> Result<HelloCredential, CredentialError> {
        let (delegate_private, delegation) = self.mint().map_err(|e| {
            // The boot-time load already refused every ABSENT-material case
            // with an actionable message, so reaching here is a bug, not a
            // misconfiguration. Name it rather than letting the forwarder
            // retry a silent refusal forever.
            tracing::error!("wake sink: could not mint a producer delegation: {e:#}");
            CredentialError::SigningFailed
        })?;
        Ok(HelloCredential {
            pubkey: delegate_private.verifying_key().to_bytes(),
            signature: delegate_private.sign(transcript).to_bytes(),
            delegation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::hub_delegation::{MAX_DELEGATION_TTL_SECS, check_validity};

    fn root() -> SigningKey {
        SigningKey::from_bytes(&[71u8; 32])
    }

    fn credential() -> DaemonIssuedCredential {
        DaemonIssuedCredential::from_enrolled_key(root(), "ai-memory-wake-hub")
    }

    /// ALLOWED: what the credential presents is a real, in-window,
    /// correctly-scoped delegation for the reserved producer name, signed by
    /// the daemon's enrolled root, delegating to the key that signed the hello.
    #[test]
    fn the_minted_delegation_binds_the_producer_name_to_the_daemon_root_3469() {
        let cred = credential();
        assert_eq!(cred.agent_id(), WAKE_HUB_PRODUCER);
        let hello = cred.sign_hello(b"transcript-3469").expect("mint");

        let wire = DelegationWire::decode(&hello.delegation).expect("decode");
        assert_eq!(wire.principal, WAKE_HUB_PRODUCER);
        assert_eq!(wire.scope, A2A_HUB_SCOPE);
        assert_eq!(wire.hub_id, "ai-memory-wake-hub");
        assert_eq!(
            wire.delegate_key_id, hello.pubkey,
            "the delegation must name the key that signs the hello"
        );
        // Signed by the DAEMON's enrolled root — no second root exists.
        verify_hub_delegation(
            &root().verifying_key(),
            &wire.as_delegation(),
            &wire.signature,
        )
        .expect("verifies under the daemon's enrolled root");
        check_validity(
            &wire.as_delegation(),
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        )
        .expect("in window");
        // And the hello signature really is the delegate's.
        let delegate =
            ed25519_dalek::VerifyingKey::from_bytes(&hello.pubkey).expect("delegate key");
        delegate
            .verify_strict(
                b"transcript-3469",
                &ed25519_dalek::Signature::from_bytes(&hello.signature),
            )
            .expect("hello signature is the delegate's");
    }

    /// REGRESSION: a freshly minted delegation must be valid IMMEDIATELY
    /// against the verifier's own second-granular clock.
    ///
    /// `ScopedDelegationVerifier::now` renders `Utc::now()` at
    /// `SecondsFormat::Secs`, i.e. truncated DOWN. A `not_before` with
    /// sub-second precision is in the future for that clock for up to a
    /// second — and this credential mints milliseconds before it connects, so
    /// a nanosecond stamp made the handshake fail essentially every time. The
    /// end-to-end test in `tests/wake_sink_3469.rs` caught it against a real
    /// hub; this pins it without a socket.
    #[test]
    fn a_freshly_minted_delegation_is_valid_against_a_second_truncated_clock_3469() {
        let hello = credential().sign_hello(b"t").expect("mint");
        let wire = DelegationWire::decode(&hello.delegation).expect("decode");
        let truncated_now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        check_validity(&wire.as_delegation(), &truncated_now)
            .expect("a delegation the verifier cannot use the instant it is minted is useless");
        // And the stamps carry no sub-second component at all, so the property
        // does not depend on where in the wall-clock second we happened to be.
        assert!(!wire.not_before.contains('.'), "{}", wire.not_before);
        assert!(!wire.not_after.contains('.'), "{}", wire.not_after);
    }

    /// The window is short by construction, and inside the protocol maximum.
    #[test]
    fn the_producer_delegation_is_short_lived_3469() {
        assert!(PRODUCER_DELEGATION_TTL_SECS > 0);
        assert!(
            PRODUCER_DELEGATION_TTL_SECS <= MAX_DELEGATION_TTL_SECS,
            "a delegation the hub would refuse is not a credential"
        );
        let hello = credential().sign_hello(b"t").expect("mint");
        let wire = DelegationWire::decode(&hello.delegation).expect("decode");
        check_ttl(&wire.as_delegation()).expect("inside the protocol bound");
    }

    /// Every session gets its OWN delegate key: a captured session key is
    /// worth one window, not the identity.
    #[test]
    fn every_session_mints_a_fresh_delegate_key_3469() {
        let cred = credential();
        let a = cred.sign_hello(b"t").expect("mint");
        let b = cred.sign_hello(b"t").expect("mint");
        assert_ne!(
            a.pubkey, b.pubkey,
            "a reused session key would outlive its window"
        );
    }

    /// DENIED: a public-only daemon keypair cannot issue, and the refusal
    /// names the remediation rather than failing later at the socket.
    #[test]
    fn a_public_only_daemon_key_is_refused_with_an_actionable_message_3469() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kp = keypair::generate(keypair::DAEMON_KEYPAIR_LABEL).expect("generate");
        keypair::save(&kp, dir.path()).expect("save");
        std::fs::remove_file(
            dir.path()
                .join(format!("{}.priv", keypair::DAEMON_KEYPAIR_LABEL)),
        )
        .expect("drop the private half");

        let err = DaemonIssuedCredential::from_key_dir(dir.path(), "hub")
            .expect_err("a daemon that cannot sign must not open a socket");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("PUBLIC-ONLY"), "{rendered}");
        assert!(rendered.contains(WAKE_HUB_PRODUCER), "{rendered}");
    }

    /// DENIED: no daemon keypair at all is refused, and the message names the
    /// allowlist step too — the other half an operator must not forget.
    #[test]
    fn an_absent_daemon_key_is_refused_with_an_actionable_message_3469() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = DaemonIssuedCredential::from_key_dir(dir.path(), "hub")
            .expect_err("no identity, no forwarder");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("hub-cache"), "{rendered}");
        assert!(rendered.contains(WAKE_HUB_PRODUCER), "{rendered}");
    }

    #[test]
    fn debug_never_renders_the_enrolled_root_3469() {
        let rendered = format!("{:?}", credential());
        assert!(rendered.contains("<enrolled signing key>"), "{rendered}");
        assert!(!rendered.contains("SigningKey {"), "{rendered}");
    }
}
