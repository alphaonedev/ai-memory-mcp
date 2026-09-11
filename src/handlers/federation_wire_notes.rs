// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3204 item 6 — the ONE home for what a federation REFUSAL says on the wire
//! versus what it says in the operator log.
//!
//! Every `/sync/push` + `/sync/since` refusal body used to carry a `note` that
//! named the exact environment knob disabling the control that fired
//! (`set AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1 …`, `set =0 to bypass`). The
//! peer on the far end of a refusal is, by construction, the party the control
//! is refusing; handing it the escape hatch by name is a remediation hint for
//! the operator delivered to the attacker. The [`wire`] notes below describe
//! WHAT was refused in closed, non-actionable terms; the [`remediation`] notes
//! name the knob and ride ONLY the `tracing::warn!` at the refusal site (as a
//! structured `remediation` field), where the operator reads them.
//!
//! The invariant is pinned twice: [`tests`] below asserts every wire note is
//! free of an env-var name and every remediation names one, and
//! `tests/federation_wire_notes_3204.rs` scans the two handler files so a
//! future inline `"note": "…AI_MEMORY_…"` cannot bypass this module.

/// Refusal notes that ride the HTTP body to the PEER. Closed-set, non-actionable:
/// they say what was refused, never which knob turns the control off.
pub mod wire {
    /// `X-Memory-Sig` present but did not verify against the enrolled key.
    pub const SIG_INVALID: &str = "the X-Memory-Sig signature over the request body did not \
         verify against the key enrolled for x-peer-id";
    /// `X-Memory-Nonce` already consumed for this peer (#922).
    pub const NONCE_REPLAY: &str = "X-Memory-Nonce was already accepted for this peer; every \
         signed federation request needs a fresh nonce";
    /// `X-Memory-Nonce` absent under the default strict posture (#922).
    pub const NONCE_MISSING: &str = "X-Memory-Nonce header is required on every signed federation \
         request";
    /// `X-Memory-Sig` present but the receiver holds no key for the peer.
    pub const SIG_NO_ENROLLED_KEY: &str = "the peer sent X-Memory-Sig but this receiver holds no \
         enrolled public key for x-peer-id";
    /// An enrolled peer omitted `X-Memory-Sig`.
    pub const SIG_MISSING: &str = "X-Memory-Sig header is required from an enrolled peer";
    /// `x-peer-id` names a peer with no enrolled key (#1088 / #1789).
    pub const PEER_NOT_ENROLLED: &str = "x-peer-id has no enrolled Ed25519 key on this receiver; \
         federation requires peer enrollment (#1789)";
    /// #2045 — client cert fingerprint has no operator binding.
    pub const CERT_UNBOUND: &str = "#2045: this client certificate's fingerprint has no operator \
         peer-id binding, so its identity cannot be cross-checked against the asserted x-peer-id";
    /// #2045 — bound client cert, but no `x-peer-id` header to check against.
    pub const CERT_NO_HEADER: &str = "#2045: this client certificate carries an operator binding \
         but the request asserted no x-peer-id header, so the cross-check cannot run";
    /// #2045 — the cross-check ran and disagreed.
    pub const CERT_MISMATCH: &str = "#2045: the asserted x-peer-id does not match the mTLS client \
         certificate's operator-bound peer identity";
    /// #238 — body `sender_agent_id` does not attest to the wire `x-peer-id`.
    pub const SENDER_ATTESTATION: &str = "#238: the body-claimed sender_agent_id must attest to \
         the wire x-peer-id header; pre-v0.7.0 federation peers must be upgraded to send x-peer-id";
    /// FED-RQ-03 — the receiver could not read its own governance policy.
    pub const POLICY_READ_UNAVAILABLE: &str = "FED-RQ-03: the receiver could not read its own \
         committed governance policy_version after a bounded retry, so this push's staleness is \
         undeterminable and it is refused fail-closed. This is retryable — re-send once the \
         receiver's governance store recovers.";
    /// FED-RQ-03 (#1947) — the sender's governance policy is behind.
    pub const STALE_POLICY: &str = "FED-RQ-03 (#1947): this push is governed by a governance \
         policy_version behind the receiver's committed policy; advance the sender's governance \
         policy (ai-memory rules … --sign) to the current version and retry.";
    /// #1056 — `x-peer-id` absent from the operator peer allowlist.
    pub const PEER_NOT_IN_ALLOWLIST: &str = "#1056: x-peer-id is not in this receiver's operator \
         peer allowlist";

    /// Every wire note, for the no-env-var pin.
    pub const ALL: &[&str] = &[
        SIG_INVALID,
        NONCE_REPLAY,
        NONCE_MISSING,
        SIG_NO_ENROLLED_KEY,
        SIG_MISSING,
        PEER_NOT_ENROLLED,
        CERT_UNBOUND,
        CERT_NO_HEADER,
        CERT_MISMATCH,
        SENDER_ATTESTATION,
        POLICY_READ_UNAVAILABLE,
        STALE_POLICY,
        PEER_NOT_IN_ALLOWLIST,
    ];
}

/// Operator remediation, emitted as the structured `remediation` field of the
/// refusal-site `tracing::warn!` and NEVER on the wire.
pub mod remediation {
    /// The per-message signature gate (#791).
    pub const REQUIRE_SIG: &str = "AI_MEMORY_FED_REQUIRE_SIG=1 (default) enforces per-message \
         Ed25519 signatures; enrol the peer's key (`ai-memory identity import`) or set \
         AI_MEMORY_FED_REQUIRE_SIG=0 to revert to the v0.6.x permissive posture during key \
         enrolment";
    /// The per-message nonce-freshness gate (#922).
    pub const REQUIRE_NONCE: &str = "AI_MEMORY_FED_REQUIRE_NONCE=1 (default) enforces per-message \
         nonce freshness; set AI_MEMORY_FED_REQUIRE_NONCE=0 to accept legacy senders that omit \
         X-Memory-Nonce during rollout";
    /// The peer-enrollment gate (#1088 / #1789) and its two hatches.
    pub const PEER_ENROLLMENT: &str = "enrol the peer's Ed25519 key via the operator workflow, or \
         set AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=0 (v0.7.x permissive) or \
         AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1 (rollout window)";
    /// The mTLS cert ↔ peer-id binding (#2045).
    pub const CERT_PEER_BINDING: &str = "add the fingerprint→peer-id binding to \
         AI_MEMORY_FED_CERT_PEER_BINDING_MAP, or set AI_MEMORY_FED_CERT_PEER_BINDING=warn to \
         downgrade to a WARN during rollout";
    /// The #238 envelope attestation hatch.
    pub const TRUST_BODY_AGENT_ID: &str = "set AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1 to trust the \
         body sender_agent_id from legacy peers that cannot send x-peer-id";
    /// The FED-RQ-03 policy-freshness gate (#1947).
    pub const REQUIRE_POLICY_CURRENT: &str = "set AI_MEMORY_FED_REQUIRE_POLICY_CURRENT=0 to accept \
         stale-policy pushes during a heterogeneous-policy rollout window";
    /// The #1056 peer allowlist.
    pub const PEER_ATTESTATION: &str = "enrol the peer in AI_MEMORY_FED_PEER_ATTESTATION, or unset \
         it to restore the zero-config posture";

    /// Every remediation note, for the names-a-knob pin.
    pub const ALL: &[&str] = &[
        REQUIRE_SIG,
        REQUIRE_NONCE,
        PEER_ENROLLMENT,
        CERT_PEER_BINDING,
        TRUST_BODY_AGENT_ID,
        REQUIRE_POLICY_CURRENT,
        PEER_ATTESTATION,
    ];
}

/// The env-var prefix a wire note must never carry.
pub const ENV_PREFIX: &str = "AI_MEMORY_";

#[cfg(test)]
mod tests {
    use super::*;

    /// #3204 item 6 — DENIED: no wire note names a knob (`AI_MEMORY_*`) or a
    /// `=0` / `=1` toggle. ALLOWED: every remediation names one, so the operator
    /// log still carries the hint the wire no longer does.
    #[test]
    fn wire_notes_carry_no_env_hint_and_remediations_do_3204() {
        assert_eq!(wire::ALL.len(), 13);
        for note in wire::ALL {
            assert!(!note.contains(ENV_PREFIX), "wire note leaks a knob: {note}");
            assert!(
                !note.contains("=0") && !note.contains("=1"),
                "wire note leaks a toggle: {note}"
            );
            assert!(!note.trim().is_empty());
        }
        assert_eq!(remediation::ALL.len(), 7);
        for hint in remediation::ALL {
            assert!(
                hint.contains(ENV_PREFIX),
                "remediation must name the knob: {hint}"
            );
        }
    }
}
