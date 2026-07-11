// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1718 — receive-side authorization policy for federated coordination-action
//! state transitions.
//!
//! A coordination-action transition is an **authority-granting** write (it can
//! complete / abandon an action, or claim / release a lease), so — unlike a
//! replicated memory or link, which is data whose worst case is a spurious row
//! — an unauthenticated transition is a privilege-escalation / lease-theft
//! vector (the outer `/sync/push` envelope authenticates the *peer node*, not
//! the *agent* the transition is attributed to). Per the #1718 5-agent vote
//! (memory `4d3ea1c5`), inbound transitions are therefore **fail-closed**:
//! applied only when cryptographically attested to the enrolled key of the
//! claimed actor. Signals and memories/links keep the accept-and-flag-unsigned
//! posture (data, not authority).
//!
//! [`authorize_remote_transition`] is the pure decision function shared by both
//! receive backends (the sqlite inline `/sync/push` loop and the
//! `sync_push_via_store` postgres path) — the DB plumbing (fetch the local
//! action / lease, then apply the CAS) differs per backend, but the
//! authorization verdict does not.

use crate::identity::sign::SignableTransition;
use crate::identity::verify::verify_transition;
use ed25519_dalek::VerifyingKey;

/// Verdict for an inbound federated action transition. Every `Reject*` variant
/// is a non-applied no-op the receive loop counts as `skipped` (with the reason
/// logged) — never a hard error that aborts the rest of the push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionAuthz {
    /// Authenticated (or permissively accepted) — apply the CAS transition.
    Accept,
    /// Unsigned op while signatures are required (fail-closed default).
    RejectUnsigned,
    /// Signed, but the attested actor has no enrolled public key locally.
    RejectNotEnrolled,
    /// Signature present but does not verify against the actor's enrolled key
    /// (forged, wrong key, or tampered surface). Rejected unconditionally.
    RejectForged,
    /// A local lease on the action is held by a different agent than the
    /// attested actor — a theft/conflict attempt.
    RejectLeaseConflict,
}

/// Decide whether an inbound action transition may be applied.
///
/// Pure (no I/O): the caller fetches the local action's namespace (to build
/// `signable`), the actor's enrolled key (`lookup_peer_public_key(claimed_by)`),
/// and any local lease holder, then this function renders the verdict. Order:
///
/// 1. **Lease-holder auth (best-effort, local).** If a local lease record
///    exists for the action and its holder is not the attested actor, reject —
///    regardless of signature. Cross-mesh lease auth (when the receiver holds
///    no lease record) rests on the signature below; full federated-lease auth
///    is tracked separately.
/// 2. **Unsigned →** fail-closed (`RejectUnsigned`) under `require_sig`, else
///    `Accept` (operator opt-out for rollout).
/// 3. **Signed →** the actor MUST have an enrolled key and the signature MUST
///    verify against *that* key (binds `from_agent → enrolled key`; verifying
///    against the wire `signer_pubkey` would let a sender forge identity). A
///    present-but-invalid signature is `RejectForged` **unconditionally** (even
///    under permissive `require_sig == false`).
#[must_use]
pub fn authorize_remote_transition(
    signable: &SignableTransition<'_>,
    signature: &[u8],
    enrolled_key: Option<&VerifyingKey>,
    local_lease_holder: Option<&str>,
    require_sig: bool,
) -> TransitionAuthz {
    if let (Some(holder), Some(actor)) = (local_lease_holder, signable.claimed_by) {
        if holder != actor {
            return TransitionAuthz::RejectLeaseConflict;
        }
    }
    if signature.is_empty() {
        return if require_sig {
            TransitionAuthz::RejectUnsigned
        } else {
            TransitionAuthz::Accept
        };
    }
    let Some(key) = enrolled_key else {
        return if require_sig {
            TransitionAuthz::RejectNotEnrolled
        } else {
            TransitionAuthz::Accept
        };
    };
    if verify_transition(signable, signature, key.as_bytes()) {
        TransitionAuthz::Accept
    } else {
        TransitionAuthz::RejectForged
    }
}

/// Env knob gating the inbound action-transition signature requirement
/// (`require_sig` fed to [`authorize_remote_transition`]).
pub const REQUIRE_TRANSITION_SIG_ENV: &str = "AI_MEMORY_FED_REQUIRE_TRANSITION_SIG";

/// Whether inbound action transitions must be cryptographically attested.
///
/// **Default fail-closed (`true`)** per the #1718 5-agent vote (`4d3ea1c5`) —
/// a transition is an authority-granting write, so an unsigned / non-enrolled
/// one is refused unless the operator opts out for a rollout window by setting
/// `AI_MEMORY_FED_REQUIRE_TRANSITION_SIG` to a falsy value (`0`/`false`/`no`/
/// `off`). Mirrors the escape-hatch shape of `AI_MEMORY_FED_REQUIRE_SIG`
/// (envelope signatures) — a *forged* signature is still rejected
/// unconditionally regardless of this knob (see [`authorize_remote_transition`]).
#[must_use]
pub fn require_transition_sig_enabled() -> bool {
    env_flag_default_on(REQUIRE_TRANSITION_SIG_ENV)
}

/// Shared grammar for federation security knobs that default **ON**
/// (fail-closed): the flag is disabled only by an explicit falsy token
/// (`0`/`false`/`no`/`off`, case- and whitespace-trimmed); every other value
/// — including the empty string or an unknown word — keeps it enabled.
///
/// Centralising this parsing (#1914) stops sibling knobs from diverging, e.g.
/// `require_sig()` historically disabled only on the literal `"0"`, so
/// `AI_MEMORY_FED_REQUIRE_SIG=false` silently stayed ON — an operator footgun.
#[must_use]
pub fn env_flag_default_on(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_none_or(|v| !matches!(v.trim(), "0" | "false" | "no" | "off"))
}

/// Env knob gating the inbound per-write CONTENT-signature requirement on
/// relayed memories (#1464) — the DATA-lane sibling of
/// [`REQUIRE_TRANSITION_SIG_ENV`].
pub const REQUIRE_WRITE_SIG_ENV: &str = "AI_MEMORY_FED_REQUIRE_WRITE_SIG";

/// Whether HONORED third-party relayed memory writes must carry a valid
/// per-write content signature.
///
/// **Default permissive (`false`)** per the #1464 5-agent vote (`4d3ea1c5`):
/// a relayed memory is *data* (replication), not an authority-granting write,
/// so it keeps the documented accept-and-flag posture — an unsigned relayed
/// write lands `attest_level=claimed` rather than being refused (contrast the
/// authority lane [`require_transition_sig_enabled`], default fail-closed).
/// Defaulting this ON would self-DOS a heterogeneous mesh whose authors do
/// not yet emit per-write signatures.
///
/// When the operator opts in (`1`/`true`/`yes`/`on`), a HONORED third-party
/// relayed claim (`attribute_agent != sender`) without a valid signature is
/// refused; self-authored relays (`attribute_agent == sender`, already gated
/// by the #238 envelope attestation + #29 signature + #30 nonce + #43
/// enrollment) stay faith-based. A *forged* signature is rejected
/// unconditionally regardless of this knob (the [`crate::identity::verify::attest_write`]
/// gate). Mirrors the pre-v0.9 secure-opt-in shape of
/// `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` (#48, the local-write sibling,
/// whose store-path default flipped to required in v0.9 per #1751 — this
/// federation knob deliberately keeps its own permissive opt-in default).
#[must_use]
pub fn require_write_sig_enabled() -> bool {
    std::env::var(REQUIRE_WRITE_SIG_ENV)
        .ok()
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
}

/// Env knob gating the inbound per-signal AUTHOR-signature requirement on
/// relayed signals (#1843) — the DATA-lane sibling of [`REQUIRE_WRITE_SIG_ENV`]
/// (#1464) for the signal subcollection.
pub const REQUIRE_SIGNAL_SIG_ENV: &str = "AI_MEMORY_FED_REQUIRE_SIGNAL_SIG";

/// Whether an inbound relayed signal must be cryptographically signed by its
/// `from_agent`'s locally-**enrolled** key.
///
/// **Default permissive (`false`)** per the #1843 5-agent vote (`4d3ea1c5`):
/// a relayed signal is *data* (a message), not an authority-granting write, so
/// it keeps the documented accept-and-flag posture (contrast the authority lane
/// [`require_transition_sig_enabled`], default fail-closed). The always-on base
/// gate (Layer 1, in the `/sync/push` signal loop) already binds `from_agent`
/// to the enrolled peer's authorship allowlist under an enrolled posture;
/// defaulting this ON would self-DOS a heterogeneous mesh whose signal authors
/// are not yet key-enrolled locally.
///
/// When the operator opts in (`1`/`true`/`yes`/`on`), an inbound signal is
/// applied only when `signal.signature` verifies against `from_agent`'s
/// locally-enrolled Ed25519 key (binds `from_agent → enrolled key`; the wire
/// `sender_pubkey` is NOT trusted for this check — verifying against it would
/// let a relayer forge identity). An unenrolled / unverified `from_agent` is
/// skipped per-signal (the batch survives). A *forged* signature (present but
/// invalid against its own wire key) is rejected unconditionally by the
/// existing `crate::signals::verify` check regardless of this knob. Mirrors the
/// secure-opt-in shape of [`require_write_sig_enabled`] (#1464).
#[must_use]
pub fn require_signal_sig_enabled() -> bool {
    std::env::var(REQUIRE_SIGNAL_SIG_ENV)
        .ok()
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
}

/// Env knob gating the v1.0.0 R19/A3 (#1948) route-IN quarantine of
/// provenance-less inbound federation-receive memory writes.
pub const FED_QUARANTINE_UNATTRIBUTED_ENV: &str = "AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED";

/// Whether a provenance-less inbound relayed memory should be **quarantined**
/// (stored with `lifecycle_state='quarantined'`, structurally hidden from
/// every read/egress lane by the fail-closed
/// [`crate::models::lifecycle_visible_clause`] allow-list) rather than landing
/// visible.
///
/// **Default permissive (`false`)** per the #1948 decision (`560c8007`,
/// 2×5-voted): a relayed memory is *data* (replication) — the bytes converge
/// (CRDT-safe) regardless, and only this node's LOCAL VIEW differs. Mirrors the
/// secure-opt-in shape of [`require_write_sig_enabled`] (#1464): unset / any
/// non-truthy value keeps the pre-#1948 accept-visible posture; an operator
/// opts in with `1`/`true`/`yes`/`on`.
///
/// "Provenance-less" here means an inbound write the receive path could NOT
/// attribute to an author with a verified per-write content signature — i.e.
/// it would land `attest_level=claimed` (never `agent_attested`). Honest
/// caveat: a quarantined row does not relay onward (black-hole until
/// dequarantine via the route-out attest / operator paths).
#[must_use]
pub fn quarantine_unattributed_enabled() -> bool {
    std::env::var(FED_QUARANTINE_UNATTRIBUTED_ENV)
        .ok()
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keypair as kp_mod;
    use crate::identity::sign;

    fn fixture<'a>(action_id: &'a str, claimed_by: Option<&'a str>) -> SignableTransition<'a> {
        SignableTransition {
            action_id,
            namespace: "_act",
            from_state: "pending",
            to_state: "claimed",
            claimed_by,
            nonce: b"nonce-0001",
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn signed_with_enrolled_key_accepts() {
        let kp = kp_mod::generate("alice").unwrap();
        let s = fixture("a1", Some("alice"));
        let sig = sign::sign_transition(&kp, &s).unwrap();
        assert_eq!(
            authorize_remote_transition(&s, &sig, Some(&kp.public), None, true),
            TransitionAuthz::Accept
        );
    }

    #[test]
    fn unsigned_rejected_when_required_accepted_when_permissive() {
        let s = fixture("a1", Some("alice"));
        assert_eq!(
            authorize_remote_transition(&s, &[], None, None, true),
            TransitionAuthz::RejectUnsigned
        );
        assert_eq!(
            authorize_remote_transition(&s, &[], None, None, false),
            TransitionAuthz::Accept
        );
    }

    #[test]
    fn signed_but_actor_not_enrolled_rejects_when_required() {
        let kp = kp_mod::generate("alice").unwrap();
        let s = fixture("a1", Some("alice"));
        let sig = sign::sign_transition(&kp, &s).unwrap();
        // No enrolled key for the actor → fail-closed reject; permissive accept.
        assert_eq!(
            authorize_remote_transition(&s, &sig, None, None, true),
            TransitionAuthz::RejectNotEnrolled
        );
        assert_eq!(
            authorize_remote_transition(&s, &sig, None, None, false),
            TransitionAuthz::Accept
        );
    }

    #[test]
    fn forged_signature_rejected_even_when_permissive() {
        let signer = kp_mod::generate("mallory").unwrap();
        let victim = kp_mod::generate("alice").unwrap();
        let s = fixture("a1", Some("alice"));
        // Mallory signs, but we verify against alice's enrolled key → forged.
        let sig = sign::sign_transition(&signer, &s).unwrap();
        assert_eq!(
            authorize_remote_transition(&s, &sig, Some(&victim.public), None, true),
            TransitionAuthz::RejectForged
        );
        // Forged is rejected unconditionally — permissive mode does not relax it.
        assert_eq!(
            authorize_remote_transition(&s, &sig, Some(&victim.public), None, false),
            TransitionAuthz::RejectForged
        );
    }

    #[test]
    fn tampered_surface_rejected() {
        let kp = kp_mod::generate("alice").unwrap();
        let s = fixture("a1", Some("alice"));
        let sig = sign::sign_transition(&kp, &s).unwrap();
        // Same signature, but the to_state was tampered after signing.
        let tampered = SignableTransition {
            to_state: "done",
            ..fixture("a1", Some("alice"))
        };
        assert_eq!(
            authorize_remote_transition(&tampered, &sig, Some(&kp.public), None, true),
            TransitionAuthz::RejectForged
        );
    }

    #[test]
    fn require_signal_sig_default_permissive_and_truthy_opts_in() {
        // #1843 — mirrors the #1464 write-sig knob: default OFF (permissive),
        // truthy (`1`/`true`/`yes`/`on`) opts in. The var is unique to this
        // test so the process-global env mutation cannot race another test.
        // SAFETY: single-threaded mutation of a var no other test reads.
        unsafe { std::env::remove_var(REQUIRE_SIGNAL_SIG_ENV) };
        assert!(!require_signal_sig_enabled(), "unset → permissive default");
        for truthy in ["1", "true", "yes", "on", "  on  "] {
            unsafe { std::env::set_var(REQUIRE_SIGNAL_SIG_ENV, truthy) };
            assert!(require_signal_sig_enabled(), "{truthy:?} → strict");
        }
        for falsy in ["0", "false", "no", "off", ""] {
            unsafe { std::env::set_var(REQUIRE_SIGNAL_SIG_ENV, falsy) };
            assert!(!require_signal_sig_enabled(), "{falsy:?} → permissive");
        }
        unsafe { std::env::remove_var(REQUIRE_SIGNAL_SIG_ENV) };
    }

    #[test]
    fn quarantine_unattributed_default_permissive_and_truthy_opts_in() {
        // #1948 — mirrors the #1464 write-sig knob shape: default OFF
        // (permissive), truthy (`1`/`true`/`yes`/`on`) opts in. SAFETY:
        // single-threaded mutation of a var no other test reads.
        unsafe { std::env::remove_var(FED_QUARANTINE_UNATTRIBUTED_ENV) };
        assert!(
            !quarantine_unattributed_enabled(),
            "unset → permissive default"
        );
        for truthy in ["1", "true", "yes", "on", "  on  "] {
            unsafe { std::env::set_var(FED_QUARANTINE_UNATTRIBUTED_ENV, truthy) };
            assert!(quarantine_unattributed_enabled(), "{truthy:?} → opt-in");
        }
        for falsy in ["0", "false", "no", "off", ""] {
            unsafe { std::env::set_var(FED_QUARANTINE_UNATTRIBUTED_ENV, falsy) };
            assert!(!quarantine_unattributed_enabled(), "{falsy:?} → permissive");
        }
        unsafe { std::env::remove_var(FED_QUARANTINE_UNATTRIBUTED_ENV) };
    }

    #[test]
    fn local_lease_held_by_other_rejects_before_signature() {
        let kp = kp_mod::generate("alice").unwrap();
        let s = fixture("a1", Some("alice"));
        let sig = sign::sign_transition(&kp, &s).unwrap();
        // A valid signature does NOT override a conflicting local lease holder.
        assert_eq!(
            authorize_remote_transition(&s, &sig, Some(&kp.public), Some("bob"), true),
            TransitionAuthz::RejectLeaseConflict
        );
        // Matching holder is fine.
        assert_eq!(
            authorize_remote_transition(&s, &sig, Some(&kp.public), Some("alice"), true),
            TransitionAuthz::Accept
        );
    }
}
