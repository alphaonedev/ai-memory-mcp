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

use crate::identity::sign::{SignableCheckpointResolution, SignableTransition};
use crate::identity::verify::{verify_checkpoint_resolution, verify_transition};
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

/// FED-RQ-01 (#1936) — verdict for an inbound federated checkpoint RESOLUTION.
/// A resolved commit-checkpoint is an **authority-granting** write (the
/// separation-of-duties attestation: who resolved this coordination gate, to
/// what verdict, when — later consumed as the freeze anchor by the epoch-apply
/// verify-only consumer #1878), so it is fail-closed exactly like the
/// action-transition sibling ([`TransitionAuthz`]). Every `Reject*` variant is a
/// per-item no-op the receive loop counts as `skipped` (reason logged) — never
/// a hard error that drops the rest of the push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointResolutionAuthz {
    /// Authenticated (or permissively accepted) — apply the resolution.
    Accept,
    /// Unsigned resolution while signatures are required (fail-closed default).
    RejectUnsigned,
    /// Signed, but the attested resolver has no enrolled public key locally.
    RejectNotEnrolled,
    /// Signature present but does not verify against the resolver's enrolled
    /// key (forged, wrong key, or tampered resolution). Rejected unconditionally.
    RejectForged,
}

/// FED-RQ-01 (#1936) — decide whether an inbound federated checkpoint
/// resolution may be applied. Mirrors [`authorize_remote_transition`] exactly:
/// the outer `/sync/push` envelope authenticates the peer NODE, not the RESOLVER
/// the resolution is attributed to, so the resolution's own Ed25519 attestation
/// must be verified against the resolver's locally-**enrolled** key — NOT the
/// wire `resolver_pubkey` (verifying against the wire key would let a relayer
/// forge resolver identity, the #1718/#87 authority-lane discipline).
///
/// Pure (no I/O): the caller re-derives `signable` from the inbound checkpoint
/// ([`crate::checkpoints::resolution_signable`]) and looks up the resolver's
/// enrolled key (`lookup_peer_public_key(resolved_by)`), then this renders the
/// verdict:
///
/// 1. **Unsigned →** fail-closed ([`CheckpointResolutionAuthz::RejectUnsigned`])
///    under `require_sig`, else [`CheckpointResolutionAuthz::Accept`] (operator
///    opt-out for a heterogeneous-rollout window).
/// 2. **Signed →** the resolver MUST have an enrolled key and the signature MUST
///    verify against *that* key. A present-but-invalid signature is
///    [`CheckpointResolutionAuthz::RejectForged`] **unconditionally** (even under
///    permissive `require_sig == false`).
#[must_use]
pub fn authorize_remote_checkpoint_resolution(
    signable: &SignableCheckpointResolution<'_>,
    signature: &[u8],
    enrolled_key: Option<&VerifyingKey>,
    require_sig: bool,
) -> CheckpointResolutionAuthz {
    if signature.is_empty() {
        return if require_sig {
            CheckpointResolutionAuthz::RejectUnsigned
        } else {
            CheckpointResolutionAuthz::Accept
        };
    }
    let Some(key) = enrolled_key else {
        return if require_sig {
            CheckpointResolutionAuthz::RejectNotEnrolled
        } else {
            CheckpointResolutionAuthz::Accept
        };
    };
    if verify_checkpoint_resolution(signable, signature, key.as_bytes()) {
        CheckpointResolutionAuthz::Accept
    } else {
        CheckpointResolutionAuthz::RejectForged
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

/// FED-RQ-01 (#1936) — env knob gating the inbound checkpoint-RESOLUTION
/// signature requirement (`require_sig` fed to
/// [`authorize_remote_checkpoint_resolution`]).
pub const REQUIRE_CHECKPOINT_SIG_ENV: &str = "AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG";

/// Whether inbound federated checkpoint resolutions must be cryptographically
/// attested to the resolver's enrolled key.
///
/// **Default fail-closed (`true`)** — a resolved commit-checkpoint is an
/// authority-granting write (the separation-of-duties freeze anchor the
/// epoch-apply verify-only consumer #1878 later trusts), so it shares the
/// authority-lane posture of [`require_transition_sig_enabled`] (#1718) rather
/// than the permissive DATA-lane default of [`require_write_sig_enabled`] (#1464)
/// / [`require_signal_sig_enabled`] (#1843). An unsigned / non-enrolled inbound
/// resolution is refused unless the operator opts out for a rollout window by
/// setting `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG` to a falsy value
/// (`0`/`false`/`no`/`off`). A *forged* signature is still rejected
/// unconditionally regardless of this knob (see
/// [`authorize_remote_checkpoint_resolution`]). FED-RQ-01 format spine votes:
/// `4d3ea1c5` (authority-write fail-closed) + #1947 decision `00d599ec`
/// (head-entanglement rides checkpoint resolutions over this transport).
#[must_use]
pub fn require_checkpoint_sig_enabled() -> bool {
    env_flag_default_on(REQUIRE_CHECKPOINT_SIG_ENV)
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

/// **Secure default for the federation per-write CONTENT-signature lane**
/// (#1464, env-table row 94), flipped `false → true` at v1.0.0 (#1801→#1954,
/// 5-agent vote `w9mr01vi8`). v0.10.0 shipped the one-cycle deprecation WARN
/// ([`warn_fed_sig_default_flip_once`]); v1.0.0 lands the flip because
/// **federation inbound IS the network surface** per ruling `9e9c3cf2`
/// condition (7). Split out of the former single `FED_REQUIRE_SIG_DEFAULT`
/// (item 5) so the write and signal lanes flip — and revert — independently.
/// The opt-out `AI_MEMORY_FED_REQUIRE_WRITE_SIG=0` keeps working post-flip
/// because an explicit env value always wins over this default.
pub const FED_REQUIRE_WRITE_SIG_DEFAULT: bool = true;

/// **Secure default for the federation per-signal AUTHOR-signature lane**
/// (#1843, env-table row 96), flipped `false → true` at v1.0.0 (#1801→#1954,
/// item 5). The signal sibling of [`FED_REQUIRE_WRITE_SIG_DEFAULT`]; kept a
/// distinct const so the two lanes are independently revertable.
pub const FED_REQUIRE_SIGNAL_SIG_DEFAULT: bool = true;

/// #1801→#1954 item 7 — closed-set skip/DLQ cause label for a HONORED
/// third-party relayed write refused under the write-sig flip because the
/// ORIGIN author has no locally-enrolled key. Distinct from `unenrolled_peer`
/// (the transport peer IS enrolled; the attributed AUTHOR is not). Emitted in
/// the receiver's structured WARN `cause` field and recognized by the
/// (sal-gated) `push_dlq::classify_quarantine_cause` taxonomy. Lives here (not
/// in the sal-gated `push_dlq`) so the always-compiled receive WARN can name it.
/// Operator remedy: enroll the author's Ed25519 key at the receiving node — the
/// manual substitute for the deferred TOFU key distribution.
pub const CAUSE_UNENROLLED_AUTHOR_STRICT: &str = "unenrolled_author_strict";

/// Closed-set attestation-refusal cause label: an HONORED third-party relay
/// under the strict write-sig flip carried no `metadata.write_signature`.
/// Observability-only (a `tracing` field, NOT matched by
/// [`crate::federation::push_dlq::classify_quarantine_cause`]); the
/// SSOT-shared sibling of [`CAUSE_UNENROLLED_AUTHOR_STRICT`] so the two
/// receive twins (`federation_receive.rs` sqlite + `federation_signing_check.rs`
/// postgres) cannot drift the token.
pub const CAUSE_MISSING_SIGNATURE: &str = "missing_signature";

/// Closed-set attestation-refusal cause label: a `write_signature` was present
/// but failed verification (forged / malformed) against the enrolled key.
/// Observability-only; SSOT-shared across the two receive twins (see
/// [`CAUSE_MISSING_SIGNATURE`]).
pub const CAUSE_FORGED_OR_MALFORMED: &str = "forged_or_malformed";

/// Resolve a DATA-lane fed-sig requirement against its (flip-ready) default:
///
/// - an explicit FALSY token (`0`/`false`/`no`/`off`, trimmed) is the
///   escape-hatch opt-out (permissive) — this is the `=0` bridge named in the
///   flip WARN and the docs;
/// - an explicit TRUTHY token (`1`/`true`/`yes`/`on`) opts in (required);
/// - any OTHER set value, or UNSET, falls through to `default_on` — so a typo
///   never silently WEAKENS a fail-closed default below its floor.
///
/// Explicit env always wins over the default (precedence intact, item 6);
/// under the v1.0.0 flip `default_on = true`, so unset ⇒ required.
fn resolve_fed_sig_flag(name: &str, default_on: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => match v.trim() {
            "0" | "false" | "no" | "off" => false,
            "1" | "true" | "yes" | "on" => true,
            _ => default_on,
        },
        Err(_) => default_on,
    }
}

/// Env knob gating the inbound per-write CONTENT-signature requirement on
/// relayed memories (#1464) — the DATA-lane sibling of
/// [`REQUIRE_TRANSITION_SIG_ENV`].
pub const REQUIRE_WRITE_SIG_ENV: &str = "AI_MEMORY_FED_REQUIRE_WRITE_SIG";

/// Whether HONORED third-party relayed memory writes must carry a valid
/// per-write content signature.
///
/// **Default fail-closed (`true`)** as of the v1.0.0 flip
/// ([`FED_REQUIRE_WRITE_SIG_DEFAULT`], #1801→#1954, 5-agent vote `w9mr01vi8`):
/// federation inbound IS the network surface (ruling `9e9c3cf2` condition 7),
/// so an UNSET env resolves STRICT (v0.10.0 shipped the one-cycle deprecation
/// WARN via [`FED_REQUIRE_WRITE_SIG_FLIP_WARNING`]). Under the flip a HONORED
/// third-party relayed claim (`attribute_agent != sender`) without a valid
/// signature is refused; the staged-rollout opt-out
/// `AI_MEMORY_FED_REQUIRE_WRITE_SIG=0` reverts to the permissive
/// accept-and-flag posture (`attest_level=claimed`) during peer key-enrollment.
/// Self-authored relays (`attribute_agent == sender`, already gated by the
/// #238 envelope attestation + #29 signature + #30 nonce + #43 enrollment)
/// stay faith-based, so the flip never bricks self-authored replication. A
/// *forged* signature is rejected unconditionally regardless of this knob (the
/// [`crate::identity::verify::attest_write`] gate). Contrast the authority lane
/// [`require_transition_sig_enabled`] (also fail-closed); the signal sibling is
/// [`require_signal_sig_enabled`].
#[must_use]
pub fn require_write_sig_enabled() -> bool {
    resolve_fed_sig_flag(REQUIRE_WRITE_SIG_ENV, FED_REQUIRE_WRITE_SIG_DEFAULT)
}

/// Env knob gating the inbound per-signal AUTHOR-signature requirement on
/// relayed signals (#1843) — the DATA-lane sibling of [`REQUIRE_WRITE_SIG_ENV`]
/// (#1464) for the signal subcollection.
pub const REQUIRE_SIGNAL_SIG_ENV: &str = "AI_MEMORY_FED_REQUIRE_SIGNAL_SIG";

/// Whether an inbound relayed signal must be cryptographically signed by its
/// `from_agent`'s locally-**enrolled** key.
///
/// **Default fail-closed (`true`)** as of the v1.0.0 flip
/// ([`FED_REQUIRE_SIGNAL_SIG_DEFAULT`], #1801→#1954 item 5): an UNSET env
/// resolves STRICT and an explicit `=0`/falsy token is the staged-rollout
/// opt-out during peer key-enrollment. The always-on base gate (Layer 1, in
/// the `/sync/push` signal loop) already binds `from_agent` to the enrolled
/// peer's authorship allowlist under an enrolled posture; this knob adds the
/// per-signal enrolled-key verification. Contrast the authority lane
/// [`require_transition_sig_enabled`] (also fail-closed).
///
/// When enabled (the v1.0.0 default; or an explicit `1`/`true`/`yes`/`on`), an inbound signal is
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
    resolve_fed_sig_flag(REQUIRE_SIGNAL_SIG_ENV, FED_REQUIRE_SIGNAL_SIG_DEFAULT)
}

/// v1.0.0 Gate-1' (#1954, #1801→#1954) — one-shot boot NOTICE emitted when
/// `AI_MEMORY_FED_REQUIRE_WRITE_SIG` is UNSET, announcing that the v1.0.0
/// default flip of [`FED_REQUIRE_WRITE_SIG_DEFAULT`] (`false → true`) is now
/// ACTIVE for the #1464 memory data lane. Federation inbound IS the network
/// surface (ruling `9e9c3cf2` condition 7). Names the `=0` opt-out so an
/// operator staging peer key-enrollment can keep the permissive posture
/// explicitly during rollout.
pub const FED_REQUIRE_WRITE_SIG_FLIP_WARNING: &str = "AI_MEMORY_FED_REQUIRE_WRITE_SIG is UNSET: as of the v1.0.0 flip the default \
     for inbound relayed per-write content signatures is now REQUIRED (#1464/#1801→#1954) \
     — federation inbound IS the network surface (ruling 9e9c3cf2 condition 7). An honored \
     third-party relayed write whose ORIGIN author has no locally-enrolled key is refused. \
     Set AI_MEMORY_FED_REQUIRE_WRITE_SIG=0 to keep the permissive accept-and-flag opt-out \
     during peer key-enrollment rollout, or enroll each author's key at every receiving node.";

/// v1.0.0 Gate-1' (#1954, #1801→#1954) — one-shot boot NOTICE emitted when
/// `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` is UNSET, announcing that the v1.0.0
/// default flip of [`FED_REQUIRE_SIGNAL_SIG_DEFAULT`] (`false → true`) is now
/// ACTIVE for the #1843 signal data lane.
pub const FED_REQUIRE_SIGNAL_SIG_FLIP_WARNING: &str = "AI_MEMORY_FED_REQUIRE_SIGNAL_SIG is UNSET: as of the v1.0.0 flip the default \
     for inbound relayed signals is now REQUIRED (#1843/#1801→#1954) — federation inbound \
     IS the network surface (ruling 9e9c3cf2 condition 7). A relayed signal whose from_agent \
     has no locally-enrolled key is skipped. Set AI_MEMORY_FED_REQUIRE_SIGNAL_SIG=0 to keep \
     the permissive opt-out during peer key-enrollment rollout.";

/// Notice gate for [`FED_REQUIRE_WRITE_SIG_FLIP_WARNING`]: `Some` iff the env
/// knob is UNSET. An explicit opt-in OR opt-out suppresses the flip WARN — the
/// operator has already chosen. Testable without touching the process-wide
/// one-shot latch (#1972 E).
#[must_use]
pub fn write_sig_flip_notice() -> Option<&'static str> {
    std::env::var(REQUIRE_WRITE_SIG_ENV)
        .is_err()
        .then_some(FED_REQUIRE_WRITE_SIG_FLIP_WARNING)
}

/// Notice gate for [`FED_REQUIRE_SIGNAL_SIG_FLIP_WARNING`]: `Some` iff the env
/// knob is UNSET (see [`write_sig_flip_notice`]).
#[must_use]
pub fn signal_sig_flip_notice() -> Option<&'static str> {
    std::env::var(REQUIRE_SIGNAL_SIG_ENV)
        .is_err()
        .then_some(FED_REQUIRE_SIGNAL_SIG_FLIP_WARNING)
}

/// v0.10.0 Gate-1' (#1954) — emit the write-sig + signal-sig default-flip
/// WARNs at most once per process, each only when its env knob is UNSET.
/// Called from the daemon boot path
/// ([`crate::daemon_runtime::bootstrap_serve`]); federation inbound is served
/// through the HTTP daemon.
pub fn warn_fed_sig_default_flip_once() {
    use std::sync::atomic::AtomicBool;
    static WRITE_WARNED: AtomicBool = AtomicBool::new(false);
    static SIGNAL_WARNED: AtomicBool = AtomicBool::new(false);
    if write_sig_flip_notice().is_some() && crate::config::one_shot_latch_take(&WRITE_WARNED) {
        tracing::warn!("{FED_REQUIRE_WRITE_SIG_FLIP_WARNING}");
    }
    if signal_sig_flip_notice().is_some() && crate::config::one_shot_latch_take(&SIGNAL_WARNED) {
        tracing::warn!("{FED_REQUIRE_SIGNAL_SIG_FLIP_WARNING}");
    }
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

// ---------------------------------------------------------------------------
// FED-RQ-03 (#1947) — cross-node governance policy_version REFUSE-STALE gate.
//
// A federated push is *governed* by the sender's committed governance
// `policy_version` at push time. When that version is STALE — strictly behind
// the RECEIVER's committed governance policy — accepting the push would apply
// a write under an outdated governance regime the receiver has already moved
// past. This is a receive-path REFUSAL (reject-before-apply): it is decided at
// the push boundary and never reaches any MemoryStore apply path, so it stays
// postgres-clean and backend-identical.
//
// Wire mechanism (design gap, ratified minimal — vote wd8wtmg0n): the
// AUTHORITATIVE, attested source of a peer's policy epoch is the *signed*
// `SignableEpochManifest` (`policy_seq`/`policy_digest_hex`), but
// epoch-manifest-DOC federation is DEFERRED to v1.x (see ADR-002). The
// federated `EpochAdvance` checkpoint that rides the #1936 transport carries
// only `content_hash` on the wire — no policy epoch to derive from today. So
// the minimal correct mechanism is a single ADDITIVE, backward-compatible
// `/sync/push` wire field (`sender_policy_seq`, `#[serde(default)]` → `None`
// on pre-#1947 peers). Attested advertising rides the deferred manifest
// federation; this gate refuses an HONEST peer that advertises a stale epoch.
//
// ROLLOUT SAFETY (there is NO prior v0.10.0 WARN carrier for this gate):
// "fail-closed" means refuse ONLY a DETECTED-stale value. An ABSENT /
// undeterminable epoch is fail-OPEN (accept — staleness cannot be determined),
// so a peer that does not (yet) advertise a policy_version is NEVER hard-
// refused and existing federation is not broken by an un-warned flip. The
// DETECTED-stale refusal itself defaults ON (this is the GA-hard requirement)
// and is gated behind `AI_MEMORY_FED_REQUIRE_POLICY_CURRENT` (default ON, the
// receive_auth knob precedent) so an operator can opt out for a deliberate
// heterogeneous-policy rollout window.
// ---------------------------------------------------------------------------

/// FED-RQ-03 (#1947) — env knob gating the cross-node governance
/// policy_version REFUSE-STALE gate. Default **ON** (fail-closed for a
/// DETECTED-stale value) via the shared [`env_flag_default_on`] grammar,
/// mirroring [`REQUIRE_TRANSITION_SIG_ENV`] / [`REQUIRE_CHECKPOINT_SIG_ENV`].
pub const REQUIRE_POLICY_CURRENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_POLICY_CURRENT";

/// Whether an inbound federated push governed by a DETECTED-stale governance
/// `policy_version` is refused.
///
/// **Default ON (fail-closed for the detected-stale case)** — this is the
/// GA-hard FED-RQ-03 requirement (T3 security/governance posture). It does NOT
/// mean absent→refuse: [`evaluate_inbound_policy_freshness`] reserves refusal
/// for a sender epoch STRICTLY BEHIND local, and an absent epoch is always
/// fail-OPEN. An operator running a deliberate heterogeneous-policy rollout
/// window opts out with a falsy token (`0`/`false`/`no`/`off`), mirroring the
/// escape-hatch shape of [`require_checkpoint_sig_enabled`] (#1936).
#[must_use]
pub fn require_policy_current_enabled() -> bool {
    env_flag_default_on(REQUIRE_POLICY_CURRENT_ENV)
}

/// FED-RQ-03 (#1947) — closed-set error tag rendered in the receive-path
/// refusal envelope (and asserted by the invariant tests) so the string is
/// single-sourced (pm-v3.1 hardcoded-literal discipline).
pub const STALE_POLICY_ERROR_TAG: &str = "stale_policy_version";

/// FED-RQ-03 (#1947) — verdict for the cross-node governance policy_version
/// staleness gate. A typed verdict (rust-microsoft **M-STRONG-TYPES-GUARD**)
/// so the HTTP layer maps exactly one refusal shape and the decision is
/// unit-testable without any I/O — the same pure-decision discipline as
/// [`TransitionAuthz`] / [`CheckpointResolutionAuthz`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyFreshnessVerdict {
    /// Accept — the push is not detectably stale: the sender is at or ahead of
    /// the local committed policy, did NOT advertise a policy epoch (fail-open,
    /// undeterminable), or the gate is opted out.
    Accept,
    /// Refuse — the sender advertised a governance policy_version STRICTLY
    /// behind the local committed policy (DETECTED-stale, fail-closed).
    RefuseStale {
        /// The sender's advertised committed policy sequence.
        sender_seq: i64,
        /// The receiver's local committed policy sequence.
        local_seq: i64,
    },
}

/// FED-RQ-03 (#1947) — pure decision for the cross-node policy_version
/// staleness gate. Reuses the `SignableEpochManifest` comparison surface —
/// the monotonic append-only `PolicyVersion.seq` that `epoch-apply` binds
/// against ([`crate::governance::policy_version::current_policy_version`]) —
/// differing only in comparison operator: `epoch-apply` requires `==` (a
/// manifest must bind the CURRENT policy), while a cross-node peer at an EQUAL
/// or HIGHER seq is legitimately not stale, so staleness is `<` (strictly
/// behind), never `!=`.
///
/// Rollout-safety ordering (both branches deliberately accept BEFORE the
/// staleness compare):
/// 1. `sender_policy_seq == None` → **fail-OPEN** (`Accept`). Staleness cannot
///    be determined for a peer that does not advertise; never hard-refuse it.
/// 2. `!require_policy_current` → **opt-out** (`Accept`), the heterogeneous-
///    policy rollout escape hatch.
/// 3. `sender_seq < local_seq` → **RefuseStale** (the sole refusal).
#[must_use]
pub fn evaluate_inbound_policy_freshness(
    sender_policy_seq: Option<i64>,
    local_seq: i64,
    require_policy_current: bool,
) -> PolicyFreshnessVerdict {
    // (1) Absent / undeterminable → fail-OPEN. Reserve refusal for a DETECTED
    // value so a non-advertising peer is never hard-refused (rollout safety).
    let Some(sender_seq) = sender_policy_seq else {
        return PolicyFreshnessVerdict::Accept;
    };
    // (2) Operator opt-out for a deliberate heterogeneous-policy rollout.
    if !require_policy_current {
        return PolicyFreshnessVerdict::Accept;
    }
    // (3) The sole refusal: the sender is governed by a policy STRICTLY behind
    // the receiver's committed policy.
    if sender_seq < local_seq {
        PolicyFreshnessVerdict::RefuseStale {
            sender_seq,
            local_seq,
        }
    } else {
        PolicyFreshnessVerdict::Accept
    }
}

/// #2340 (FBL-32) — redact an inbound relayed memory to its TO-BE-PERSISTED
/// form BEFORE the per-write content attestation stamps `attest_level`.
///
/// The storage funnels redact under the forced `refuse`→`redact`
/// federation-receive posture (env row #95), so pre-fix the receive path
/// verified + stamped `agent_attested` over the RAW inbound bytes and then
/// persisted DIFFERENT (redacted) bytes — a row whose `write_signature` no
/// longer covers its own stored content, violating the
/// [`crate::identity::attest`] signed-bytes == persisted-bytes contract and
/// env row #94 ("recomputing sha256(content) over the PERSISTED content
/// bytes"). This mirrors the authoring-side redact-before-sign discipline
/// (#1801): attestation is evaluated over exactly the bytes the funnel will
/// store, making the funnel's own later redaction an idempotent no-op.
///
/// Dispositions:
/// - **Same-mode traffic** (the author redacted before signing, or the
///   content carries no credential material): the screen is a no-op or
///   idempotent, the signature still covers the persisted bytes, and
///   `agent_attested` is preserved — byte-identical behavior.
/// - **Cross-mode traffic** (an `off`-mode origin signed + shipped RAW
///   secret-bearing bytes): the SIGNED surface (content and/or title)
///   mutates, so the presented `metadata.write_signature` can no longer
///   cover any bytes this node will persist. The stale signature is DROPPED
///   (with a WARN) so the attestation step lands the row honestly at
///   `claimed` — or refuses an honored third-party relay under the strict
///   flip — instead of stamping a cryptographically false `agent_attested`.
///
/// Returns `true` when the screen mutated the SIGNED surface (any presented
/// raw-bytes `write_signature` was dropped alongside).
pub fn redact_inbound_before_attestation(mem: &mut crate::models::Memory) -> bool {
    let screened = crate::secret_screen::redact_memory_for_storage(mem);
    apply_screened_inbound(mem, screened)
}

/// Pure core of [`redact_inbound_before_attestation`]: fold an
/// already-computed screened clone back onto the inbound row and drop the
/// presented `write_signature` iff the SIGNED surface (content / title — the
/// two [`crate::identity::sign::SignableWrite`] fields the screen can
/// mutate) changed. Split out so the disposition is unit-testable without
/// touching the process-global screen-mode `OnceLock`.
fn apply_screened_inbound(
    mem: &mut crate::models::Memory,
    screened: Option<crate::models::Memory>,
) -> bool {
    let Some(screened) = screened else {
        return false;
    };
    let signed_surface_mutated = screened.content != mem.content || screened.title != mem.title;
    *mem = screened;
    if !signed_surface_mutated {
        return false;
    }
    let dropped = mem.metadata.as_object_mut().is_some_and(|obj| {
        obj.remove(crate::models::field_names::WRITE_SIGNATURE)
            .is_some()
    });
    if dropped {
        tracing::warn!(
            target: crate::handlers::federation_receive::ATTESTATION_TRACE_TARGET,
            memory_id = %mem.id,
            "sync_push: secret screen redacted the SIGNED surface of an inbound \
             relayed memory; dropping the presented write_signature (it covers raw \
             bytes this node will not persist) so the row cannot land falsely \
             agent_attested (#2340). Origin should redact-before-sign (#1801)."
        );
    }
    signed_surface_mutated
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
    fn require_signal_sig_default_strict_and_falsy_opts_out() {
        // #1801→#1954 item 5 — the signal lane flipped `false → true` at
        // v1.0.0: UNSET now resolves STRICT; an explicit FALSY token is the
        // `=0` escape-hatch opt-out; truthy opts in. Any other set value falls
        // through to the (now strict) default — a typo never weakens it.
        // SAFETY: single-threaded mutation of a var no other test reads.
        unsafe { std::env::remove_var(REQUIRE_SIGNAL_SIG_ENV) };
        assert!(require_signal_sig_enabled(), "unset → strict (v1.0.0 flip)");
        // Unset → the boot notice still fires (now announcing the ACTIVE flip).
        assert!(
            signal_sig_flip_notice().is_some(),
            "unset → flip notice armed"
        );
        warn_fed_sig_default_flip_once();
        for truthy in ["1", "true", "yes", "on", "  on  "] {
            unsafe { std::env::set_var(REQUIRE_SIGNAL_SIG_ENV, truthy) };
            assert!(require_signal_sig_enabled(), "{truthy:?} → strict");
        }
        for falsy in ["0", "false", "no", "off"] {
            unsafe { std::env::set_var(REQUIRE_SIGNAL_SIG_ENV, falsy) };
            assert!(
                !require_signal_sig_enabled(),
                "{falsy:?} → permissive opt-out"
            );
            // Any explicit set value (opt-in OR opt-out) suppresses the notice.
            assert!(signal_sig_flip_notice().is_none(), "{falsy:?} → suppressed");
        }
        // An unrecognized set value falls through to the strict default.
        unsafe { std::env::set_var(REQUIRE_SIGNAL_SIG_ENV, "garbage") };
        assert!(
            require_signal_sig_enabled(),
            "garbage → strict default (fail-closed)"
        );
        unsafe { std::env::remove_var(REQUIRE_SIGNAL_SIG_ENV) };
    }

    #[test]
    fn require_write_sig_default_strict_and_falsy_opts_out() {
        // #1801→#1954 item 5/6 — the write lane flipped `false → true` at
        // v1.0.0: UNSET now resolves STRICT; `AI_MEMORY_FED_REQUIRE_WRITE_SIG=0`
        // (or any falsy token) is the byte-identical pre-flip permissive
        // opt-out (regression test (d)); truthy opts in. SAFETY: single-
        // threaded mutation of a var no other test reads.
        unsafe { std::env::remove_var(REQUIRE_WRITE_SIG_ENV) };
        assert!(require_write_sig_enabled(), "unset → strict (v1.0.0 flip)");
        assert!(
            write_sig_flip_notice().is_some(),
            "unset → flip notice armed"
        );
        for truthy in ["1", "true", "yes", "on", "  on  "] {
            unsafe { std::env::set_var(REQUIRE_WRITE_SIG_ENV, truthy) };
            assert!(require_write_sig_enabled(), "{truthy:?} → strict");
        }
        for falsy in ["0", "false", "no", "off"] {
            unsafe { std::env::set_var(REQUIRE_WRITE_SIG_ENV, falsy) };
            assert!(
                !require_write_sig_enabled(),
                "{falsy:?} → permissive opt-out"
            );
            assert!(write_sig_flip_notice().is_none(), "{falsy:?} → suppressed");
        }
        unsafe { std::env::set_var(REQUIRE_WRITE_SIG_ENV, "garbage") };
        assert!(
            require_write_sig_enabled(),
            "garbage → strict default (fail-closed)"
        );
        unsafe { std::env::remove_var(REQUIRE_WRITE_SIG_ENV) };
    }

    #[test]
    fn fed_require_sig_defaults_flipped_strict_at_v1_0_0() {
        // #1801→#1954 item 5 — the v1.0.0 flip: BOTH lane consts are now `true`
        // (required), split out of the former single `FED_REQUIRE_SIG_DEFAULT`
        // so each lane is independently revertable (set its const back to
        // `false`). Federation inbound IS the network surface (ruling 9e9c3cf2).
        assert!(
            FED_REQUIRE_WRITE_SIG_DEFAULT,
            "v1.0.0 flips the write-sig lane to required"
        );
        assert!(
            FED_REQUIRE_SIGNAL_SIG_DEFAULT,
            "v1.0.0 flips the signal-sig lane to required"
        );
    }

    #[test]
    fn fed_sig_flip_warning_messages_cite_ruling_and_opt_out() {
        // #1954: the named-const flip WARNs carry the load-bearing facts —
        // the v1.0.0 flip, the 9e9c3cf2 network-surface ruling, and the =1/=0
        // opt path. Pure (no env mutation): the unset/set gating is asserted
        // in the per-var owner tests so exactly one test mutates each var.
        for msg in [
            FED_REQUIRE_WRITE_SIG_FLIP_WARNING,
            FED_REQUIRE_SIGNAL_SIG_FLIP_WARNING,
        ] {
            assert!(msg.contains("v1.0.0"), "names the flip release");
            assert!(msg.contains("9e9c3cf2"), "cites the network-surface ruling");
            assert!(msg.contains("REQUIRED"), "states the flipped posture");
            assert!(msg.contains("=0"), "names the permissive opt-out");
        }
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

    // ---- FED-RQ-01 (#1936) — authorize_remote_checkpoint_resolution ----

    fn cp_fixture(verdict: &'static str) -> SignableCheckpointResolution<'static> {
        SignableCheckpointResolution {
            checkpoint_id: "cp-1",
            namespace: "_epoch",
            state: "resolved",
            resolved_by: "alice",
            resolution: Some(verdict),
            resolved_at: 1_700_000_900,
        }
    }

    #[test]
    fn checkpoint_signed_with_enrolled_key_accepts() {
        let kp = kp_mod::generate("alice").unwrap();
        let r = cp_fixture("approved");
        let sig = sign::sign_checkpoint_resolution(&kp, &r).unwrap();
        assert_eq!(
            authorize_remote_checkpoint_resolution(&r, &sig, Some(&kp.public), true),
            CheckpointResolutionAuthz::Accept
        );
    }

    #[test]
    fn checkpoint_unsigned_rejected_when_required_accepted_when_permissive() {
        let r = cp_fixture("approved");
        assert_eq!(
            authorize_remote_checkpoint_resolution(&r, &[], None, true),
            CheckpointResolutionAuthz::RejectUnsigned
        );
        assert_eq!(
            authorize_remote_checkpoint_resolution(&r, &[], None, false),
            CheckpointResolutionAuthz::Accept
        );
    }

    #[test]
    fn checkpoint_signed_but_resolver_not_enrolled_rejects_when_required() {
        let kp = kp_mod::generate("alice").unwrap();
        let r = cp_fixture("approved");
        let sig = sign::sign_checkpoint_resolution(&kp, &r).unwrap();
        assert_eq!(
            authorize_remote_checkpoint_resolution(&r, &sig, None, true),
            CheckpointResolutionAuthz::RejectNotEnrolled
        );
        assert_eq!(
            authorize_remote_checkpoint_resolution(&r, &sig, None, false),
            CheckpointResolutionAuthz::Accept
        );
    }

    #[test]
    fn checkpoint_forged_signature_rejected_even_when_permissive() {
        let mallory = kp_mod::generate("mallory").unwrap();
        let alice = kp_mod::generate("alice").unwrap();
        let r = cp_fixture("approved");
        // Mallory signs, but we verify against alice's enrolled key → forged.
        let sig = sign::sign_checkpoint_resolution(&mallory, &r).unwrap();
        assert_eq!(
            authorize_remote_checkpoint_resolution(&r, &sig, Some(&alice.public), true),
            CheckpointResolutionAuthz::RejectForged
        );
        // Forged is rejected unconditionally — permissive mode does not relax it.
        assert_eq!(
            authorize_remote_checkpoint_resolution(&r, &sig, Some(&alice.public), false),
            CheckpointResolutionAuthz::RejectForged
        );
    }

    #[test]
    fn checkpoint_tampered_verdict_rejected() {
        let kp = kp_mod::generate("alice").unwrap();
        let signed_over = cp_fixture("approved");
        let sig = sign::sign_checkpoint_resolution(&kp, &signed_over).unwrap();
        // Same signature, but the verdict was flipped after signing.
        let tampered = cp_fixture("rejected");
        assert_eq!(
            authorize_remote_checkpoint_resolution(&tampered, &sig, Some(&kp.public), true),
            CheckpointResolutionAuthz::RejectForged
        );
    }

    // ---- FED-RQ-03 (#1947) — policy_version REFUSE-STALE gate ----

    #[test]
    fn policy_freshness_refuses_only_detected_stale() {
        use PolicyFreshnessVerdict::{Accept, RefuseStale};
        // Absent sender epoch → fail-OPEN regardless of local seq or require.
        assert_eq!(
            evaluate_inbound_policy_freshness(None, 5, true),
            Accept,
            "absent epoch → fail-open (undeterminable, rollout safety)"
        );
        // Stale (strictly behind) + required → the sole refusal.
        assert_eq!(
            evaluate_inbound_policy_freshness(Some(3), 5, true),
            RefuseStale {
                sender_seq: 3,
                local_seq: 5
            },
            "sender behind local + required → RefuseStale"
        );
        // Equal → not stale → accept (contrast epoch-apply's `==`-bind).
        assert_eq!(
            evaluate_inbound_policy_freshness(Some(5), 5, true),
            Accept,
            "sender == local → not stale"
        );
        // Ahead → not stale → accept.
        assert_eq!(
            evaluate_inbound_policy_freshness(Some(9), 5, true),
            Accept,
            "sender ahead of local → not stale"
        );
        // Opt-out: even a stale sender is accepted when the gate is disabled.
        assert_eq!(
            evaluate_inbound_policy_freshness(Some(3), 5, false),
            Accept,
            "opt-out accepts even a DETECTED-stale sender"
        );
        // Genesis receiver (local seq 0) can never see a strictly-lower seq.
        assert_eq!(
            evaluate_inbound_policy_freshness(Some(0), 0, true),
            Accept,
            "seq 0 vs seq 0 → not stale (genesis, fail-open floor)"
        );
    }

    #[test]
    fn require_policy_current_default_on_and_falsy_opts_out() {
        // Mirrors the #1936 checkpoint knob: default ON (fail-closed for the
        // detected-stale case), falsy opts out. SAFETY: single-threaded
        // mutation of a var no other test reads.
        unsafe { std::env::remove_var(REQUIRE_POLICY_CURRENT_ENV) };
        assert!(
            require_policy_current_enabled(),
            "unset → fail-closed default (GA-hard FED-RQ-03)"
        );
        for falsy in ["0", "false", "no", "off", "  off  "] {
            unsafe { std::env::set_var(REQUIRE_POLICY_CURRENT_ENV, falsy) };
            assert!(!require_policy_current_enabled(), "{falsy:?} → opt-out");
        }
        for truthy in ["1", "true", "yes", "on", ""] {
            unsafe { std::env::set_var(REQUIRE_POLICY_CURRENT_ENV, truthy) };
            assert!(require_policy_current_enabled(), "{truthy:?} → strict");
        }
        unsafe { std::env::remove_var(REQUIRE_POLICY_CURRENT_ENV) };
    }

    #[test]
    fn require_checkpoint_sig_default_fail_closed_and_falsy_opts_out() {
        // FED-RQ-01 — mirrors the #1718 transition knob: default ON
        // (fail-closed), falsy (`0`/`false`/`no`/`off`) opts out. SAFETY:
        // single-threaded mutation of a var no other test reads.
        unsafe { std::env::remove_var(REQUIRE_CHECKPOINT_SIG_ENV) };
        assert!(
            require_checkpoint_sig_enabled(),
            "unset → fail-closed default"
        );
        for falsy in ["0", "false", "no", "off", "  off  "] {
            unsafe { std::env::set_var(REQUIRE_CHECKPOINT_SIG_ENV, falsy) };
            assert!(!require_checkpoint_sig_enabled(), "{falsy:?} → permissive");
        }
        for truthy in ["1", "true", "yes", "on", ""] {
            unsafe { std::env::set_var(REQUIRE_CHECKPOINT_SIG_ENV, truthy) };
            assert!(require_checkpoint_sig_enabled(), "{truthy:?} → strict");
        }
        unsafe { std::env::remove_var(REQUIRE_CHECKPOINT_SIG_ENV) };
    }

    // ---- #2340 (FBL-32) — redact-before-attestation disposition ----
    //
    // These exercise the pure core `apply_screened_inbound` with a
    // hand-built screened clone so they never touch the process-global
    // screen-mode `OnceLock` (lib unit tests share one process; seeding
    // `Redact` here would leak into unrelated storage-funnel tests). The
    // real-screen wiring is pinned by the integration twins in
    // `tests/federation_write_sig_emit_1801.rs` (a Redact-seeded binary).

    use crate::identity::attest;
    use crate::models::Memory;
    use base64::Engine as _;

    fn signed_secret_mem(author: &str) -> (Memory, crate::identity::keypair::AgentKeypair) {
        let kp = kp_mod::generate(author).unwrap();
        let mut mem = Memory {
            id: "m-2340".to_string(),
            namespace: "team/alpha".to_string(),
            title: "deploy notes".to_string(),
            content: "deploy with ghp_abcdefghijklmnopqrstuvwxyz0123456789 then restart"
                .to_string(),
            created_at: "2026-07-01T12:00:00+00:00".to_string(),
            metadata: serde_json::json!({ "agent_id": author }),
            ..Memory::default()
        };
        // Off-mode origin: sign over the RAW bytes and EMIT the signature.
        let sig = attest::sign_memory_write(&kp, &mem, author).unwrap();
        attest::persist_write_signature(&mut mem, &sig);
        (mem, kp)
    }

    fn pk_b64(kp: &crate::identity::keypair::AgentKeypair) -> String {
        base64::engine::general_purpose::STANDARD.encode(kp.public.to_bytes())
    }

    /// Cross-mode: the screen mutated the SIGNED surface, so the stale
    /// raw-bytes signature is dropped and the attestation step lands the
    /// row honestly at `claimed` — never a false `agent_attested` over
    /// bytes that differ from what is stored.
    #[test]
    fn screened_signed_surface_drops_stale_signature_and_lands_claimed_2340() {
        let author = "ai:origin-off-2340";
        let (mut mem, kp) = signed_secret_mem(author);
        let screened = Memory {
            content: "deploy with [REDACTED:github_token] then restart".to_string(),
            ..mem.clone()
        };
        assert!(super::apply_screened_inbound(&mut mem, Some(screened)));
        assert!(
            mem.metadata
                .get(crate::models::field_names::WRITE_SIGNATURE)
                .is_none(),
            "stale raw-bytes write_signature must be dropped"
        );
        // The funnel then attests with NO presented signature (the drop) →
        // permissive lands `claimed`.
        let level =
            attest::stamp_attestation(&mut mem, author, Some(&pk_b64(&kp)), None, false).unwrap();
        assert_eq!(level.as_str(), "claimed");
        assert_eq!(mem.metadata["attest_level"], "claimed");
    }

    /// Same-mode / clean traffic: no screen hit (`None`) keeps the presented
    /// signature intact, and it still verifies to `agent_attested` over the
    /// unchanged (persisted) bytes.
    #[test]
    fn clean_screen_keeps_signature_and_agent_attested_2340() {
        let author = "ai:origin-clean-2340";
        let (mut mem, kp) = signed_secret_mem(author);
        assert!(!super::apply_screened_inbound(&mut mem, None));
        let presented = mem
            .metadata
            .get(crate::models::field_names::WRITE_SIGNATURE)
            .and_then(serde_json::Value::as_str)
            .map(|s| base64::engine::general_purpose::STANDARD.decode(s).unwrap())
            .expect("signature retained");
        let level = attest::stamp_attestation(
            &mut mem,
            author,
            Some(&pk_b64(&kp)),
            Some(&presented),
            false,
        )
        .unwrap();
        assert_eq!(level.as_str(), "agent_attested");
    }

    /// A screen hit that mutates ONLY unsigned surfaces (tags / metadata
    /// values) keeps the signature: the `SignableWrite` envelope commits to
    /// content + title only, so the signature still covers the persisted
    /// signed bytes.
    #[test]
    fn unsigned_surface_only_redaction_keeps_signature_2340() {
        let author = "ai:origin-meta-2340";
        let (mut mem, _kp) = signed_secret_mem(author);
        let mut screened = mem.clone();
        screened.tags = vec!["[REDACTED:bearer_token]".to_string()];
        assert!(!super::apply_screened_inbound(&mut mem, Some(screened)));
        assert!(
            mem.metadata
                .get(crate::models::field_names::WRITE_SIGNATURE)
                .is_some(),
            "signature covering unmutated content+title must be retained"
        );
        assert_eq!(mem.tags, vec!["[REDACTED:bearer_token]".to_string()]);
    }
}
