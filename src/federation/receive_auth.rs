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

// ---------------------------------------------------------------------------
// #2447 (CWE-284) — namespace confinement for the inbound WRITE lane.
// ---------------------------------------------------------------------------

/// Env knob gating the STRICT (default-deny) posture of the #2447 inbound
/// write-lane namespace scope check — the write-lane sibling of
/// [`REQUIRE_SIGNAL_SIG_ENV`] (#1843 Layer 2).
pub const REQUIRE_PUSH_NAMESPACE_SCOPE_ENV: &str = "AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE";

/// Whether an inbound `/sync/push` `memories[]` write from an ENROLLED peer
/// that declares NO `allowed_namespaces` must be REFUSED — full default-deny
/// parity with the `/sync/since` pull lane, where an empty list already means
/// "may pull nothing" (`PeerScope::allowed_namespaces`).
///
/// **Default fail-closed (`true`)**, via the shared [`env_flag_default_on`]
/// grammar every `AI_MEMORY_FED_REQUIRE_*` knob uses (#87/#94/#96/#125/#132 are
/// 7-for-7 default-ON at v1.0.0 — federation inbound IS the network surface,
/// ruling `9e9c3cf2` condition 7). An explicit falsy token
/// (`0`/`false`/`no`/`off`) is the staged-rollout opt-out.
///
/// **This knob CANNOT brick zero-config federation**, because the gate that
/// reads it is itself gated on [`PeerAttestationConfig::has_allowlist`]: with
/// no `AI_MEMORY_FED_PEER_ATTESTATION` configured the check never runs. Its
/// entire blast radius is ONE config shape — the operator wrote the peer JSON,
/// enrolled this peer, and left `allowed_namespaces` empty/absent (it is
/// `#[serde(default)]`, so an omitted field silently yields `[]`).
///
/// **That claim is STRUCTURALLY ENFORCED, not merely asserted (#2497).**
/// [`layer2_unscoped_peer_authorized`] refuses the header-absent and
/// not-in-a-non-empty-allowlist shapes UNCONDITIONALLY, before it consults this
/// knob at all — see [`peer_enrolled_in_allowlist`] for the shape table and the
/// regression that skipping that split caused (a falsy knob plus
/// `AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1` briefly granted an ANONYMOUS peer
/// unbounded federated delete-by-id). An operator who wants an unlisted peer
/// admitted removes the allowlist (zero-config, which short-circuits earlier) or
/// enrolls the peer; this knob is never that lever.
///
/// ## AVAILABILITY NOTE — a falsy value is NOT a general rollout hatch (#2497)
///
/// Because the unconditional refusal lives in the SHARED Layer 2, it applies to
/// every lane that reaches the verdict — not only `deletions[]`. For the
/// `{allowlist configured} × {header-less legacy peer} × {this knob = 0}`
/// combination, `memories[]` / `archives[]` / `restores[]` entries that were
/// APPLIED before #2497 are REFUSED now. That is the correct direction, but an
/// operator sitting on exactly the posture this knob exists to serve loses
/// writes as well as deletes on upgrade — silently, inside an HTTP 200, with no
/// DLQ enqueue (#2498) — so the loss is not retried and not surfaced as an error.
///
/// The remedy is to make the peer IDENTIFIABLE (enroll it, `["**"]` for a
/// deliberate per-peer allow-all) or to remove the allowlist entirely for the
/// zero-config posture. Note that for a header-LESS push "enroll the peer" is
/// not an actionable remedy at all: a per-peer scope cannot be applied to a peer
/// that cannot be identified.
///
/// Two recoveries, both without a restart-blocking rewrite: declare the peer's
/// real scope (or `["**"]` for deliberate allow-all — the PER-PEER escape,
/// [`crate::federation::peer_attestation::namespace_allowed_test_glob`] treats
/// `**` as unconditional match-all), or set this knob falsy for a fleet-wide
/// rollout window. Note `AI_MEMORY_FED_SYNC_TRUST_PEER=1` does NOT rescue this
/// case and never did: `namespace_allowed` consults that bypass only in the
/// `scope_for(peer) == None` arm, so an enrolled peer's declared allowlist
/// always wins over the legacy override.
///
/// 3x3 adversarial vote (`4d3ea1c5` protocol): the permissive-default variant
/// was ranked LAST by both voting lenses — grammar-illegal under a
/// `FED_REQUIRE_*` name, and it would leave the write lane unbounded for a
/// config that already confines reads and deletes.
#[must_use]
pub fn require_push_namespace_scope_enabled() -> bool {
    env_flag_default_on(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV)
}

/// Whether the operator has DECLARED a non-empty `allowed_namespaces` scope
/// for this peer — the predicate that selects Layer 1 over Layer 2 below.
///
/// An enrolled peer whose scope row omits `allowed_namespaces` is a legal
/// shape: `PeerScope::allowed_namespaces` is `#[serde(default)]`, so an
/// operator who enrolls a peer purely to configure `allowed_sender_agent_ids`
/// (the #238 attestation) silently gets `[]`. That peer has declared no scope
/// to match against, so Layer 1 has nothing to enforce and Layer 2 decides.
#[must_use]
pub fn peer_declares_namespace_scope(
    peer_id: Option<&str>,
    attest_cfg: &crate::federation::peer_attestation::PeerAttestationConfig,
) -> bool {
    peer_id
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .and_then(|p| attest_cfg.scope_for(p))
        .is_some_and(|scope| !scope.allowed_namespaces.is_empty())
}

/// Whether this push presents a peer id that is ENROLLED in a non-empty
/// `AI_MEMORY_FED_PEER_ATTESTATION` allowlist — regardless of whether that
/// peer's row declares any `allowed_namespaces`.
///
/// The sibling of [`peer_declares_namespace_scope`], and the predicate that
/// separates the ONE peer shape [`require_push_namespace_scope_enabled`]
/// governs from the two it must NEVER govern.
///
/// # Why this exists (the #2497 regression it closes)
///
/// Under an enrolled posture, THREE distinct peer shapes fall through to
/// Layer 2 — and only ONE of them is the shape the knob was written for:
///
/// | shape | `scope_for(peer)` | governed by knob 147? |
/// |---|---|---|
/// | enrolled, `allowed_namespaces: []` | `Some(empty)` | **YES** — the #2447 Layer-2 shape |
/// | peer id ABSENT (or whitespace-only) | n/a | **NO** — refuse unconditionally |
/// | peer NOT in a non-empty allowlist | `None` | **NO** — refuse unconditionally |
///
/// The first #2488 fix routed all three through the knob, so
/// `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=0` — a documented rollout
/// hatch — granted an ANONYMOUS or UNKNOWN peer unbounded delete-by-id on a
/// node that had declared an allowlist. That both regressed the parent's
/// behaviour for those shapes (`namespace_allowed` refused them via
/// `sync_trust_peer_bypass()`'s default-false) and falsified this module's own
/// documented claim that the knob's blast radius is ONE config shape. A
/// malformed header makes it worse: `extract_peer_id` drops a whitespace-only
/// `X-Peer-Id` to `None`, and the #1056 TOFU enrollment guard is
/// `if let Some(peer_id)`, so "malformed" and "absent" are indistinguishable
/// to that gate and neither is caught there.
///
/// An operator who genuinely wants an unlisted peer admitted removes the
/// allowlist (the zero-config posture, which short-circuits before Layer 2) or
/// enrolls the peer — never a knob whose documented scope is a different shape.
#[must_use]
pub fn peer_enrolled_in_allowlist(
    peer_id: Option<&str>,
    attest_cfg: &crate::federation::peer_attestation::PeerAttestationConfig,
) -> bool {
    peer_id
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .and_then(|p| attest_cfg.scope_for(p))
        .is_some()
}

/// Whether the write-lane gate needs the EXISTING local row's namespace
/// resolved before [`inbound_write_namespace_authorized`] can decide.
///
/// `false` short-circuits a per-memory `get`-by-id on the federation hot path:
/// when Layer 1 is not armed for this peer the stored namespace cannot change
/// the verdict (Layer 2 refuses — or accepts — on the peer's scope alone).
/// Zero-config deployments therefore pay ZERO extra reads.
///
/// # This is an ELISION predicate, never a GATE predicate (#2488)
///
/// It answers "may I skip the probe?", NOT "must I check this peer?". Wrapping
/// a whole gate in it — as the postgres delete lane did between #2447 and
/// #2488 — makes the gate UNREACHABLE for exactly the peer shapes Layer 2 was
/// written to refuse (enrolled-unscoped, header-absent), because those are the
/// shapes for which it returns `false`. The correct structure is
/// `if attest_cfg.has_allowlist() { let stored = if needs { probe()? } else { None };
/// verdict(stored) }` — the enrolled posture gates, this predicate only elides
/// the read whose answer cannot change the verdict.
#[must_use]
pub fn inbound_write_needs_existing_namespace(
    peer_id: Option<&str>,
    attest_cfg: &crate::federation::peer_attestation::PeerAttestationConfig,
) -> bool {
    attest_cfg.has_allowlist() && peer_declares_namespace_scope(peer_id, attest_cfg)
}

/// Lane token for the `/sync/push` `deletions[]` subcollection. Shared by both
/// receive funnels and by the Layer-2 refusal prose (#2488) so the string that
/// selects the delete-lane wording cannot drift from the string the funnels pass.
pub const LANE_DELETIONS: &str = "deletions";

/// #2478 — lane token for the `/sync/push` `pendings[]` subcollection (the
/// inbound governance-row upsert), distinct from [`LANE_PENDING_DECISIONS`]
/// because refusing an INJECTION and refusing an EXECUTION are different
/// operator remedies and must not share a log line.
pub const LANE_PENDINGS: &str = "pendings";

/// #2478 — lane token for the NON-destructive arms of the `/sync/push`
/// `pending_decisions[]` subcollection (`store` / `promote` / `reflect`).
pub const LANE_PENDING_DECISIONS: &str = "pending_decisions";

/// #2478 — lane token for the DESTRUCTIVE arm of `pending_decisions[]`.
///
/// Split from [`LANE_PENDING_DECISIONS`] for one reason only:
/// [`layer2_unscoped_peer_authorized`] selects its `scope_note` prose from the
/// lane token, and the #2488 lesson is that a destructive lane must never be
/// refused with the write-lane wording ("your write scope would be unbounded")
/// — an operator reading that about a hard `DELETE` is being told the wrong
/// thing. Approving a `delete`-typed pending action reaches `storage::delete`
/// exactly as `deletions[]` does, so it takes the same prose.
pub const LANE_PENDING_DECISION_DELETE: &str = "pending_decisions (delete)";

/// #2479 — lane token for the `/sync/push` `namespace_meta[]` subcollection
/// (the inbound governance-STANDARD bind / re-parent).
pub const LANE_NAMESPACE_META: &str = "namespace_meta";

/// #2479 — lane token for the DESTRUCTIVE `/sync/push` `namespace_meta_clears[]`
/// subcollection. Kept distinct from [`LANE_NAMESPACE_META`] because clearing a
/// standard is a bare `DELETE FROM namespace_meta` that DISARMS a namespace's
/// governance (absent policy resolves permissive, the allow-on-silence default),
/// which is a different operator remedy from a refused bind — and because
/// [`lane_is_destructive`] must give it the destructive refusal prose.
pub const LANE_NAMESPACE_META_CLEARS: &str = "namespace_meta_clears";

/// Gate 1 — `/sync/push` `memories[]` subcollection.
pub const LANE_MEMORIES: &str = "memories";

/// Gate 1 — embeddings ride memories; no standalone apply.
pub const LANE_EMBEDDINGS: &str = "embeddings";

/// Gate 1 / #2489 — `/sync/push` `links[]` subcollection (endpoint-namespace confined).
pub const LANE_LINKS: &str = "links";

/// Gate 1 / #2489 — `/sync/push` `signals[]` subcollection (claimed-namespace confined).
pub const LANE_SIGNALS: &str = "signals";

/// Gate 1 / #2649 — `/sync/push` `action_transitions[]` (crypto + namespace).
pub const LANE_ACTION_TRANSITIONS: &str = "action_transitions";

/// Gate 1 / #2650 — `/sync/push` `checkpoints[]` (crypto + namespace).
pub const LANE_CHECKPOINTS: &str = "checkpoints";

/// Gate 1 — `/sync/push` `archives[]`.
pub const LANE_ARCHIVES: &str = "archives";

/// Gate 1 — `/sync/push` `restores[]`.
pub const LANE_RESTORES: &str = "restores";

/// Whether `lane` names a funnel whose refusal prose must describe a
/// DESTRUCTIVE effect rather than a write.
///
/// One predicate rather than an `==` at the branch so that adding a third
/// destructive lane is a single edit here and cannot silently inherit the
/// write-lane wording (#2478, extending the #2488 prose fix).
fn lane_is_destructive(lane: &str) -> bool {
    matches!(
        lane,
        LANE_DELETIONS | LANE_PENDING_DECISION_DELETE | LANE_NAMESPACE_META_CLEARS
    )
}

/// The GLOBAL namespace standard's key — the row
/// `crate::storage::build_namespace_chain` unconditionally prepends to the
/// inheritance chain of EVERY namespace in the substrate.
///
/// Declared here (rather than re-spelled at each branch) because #2479's
/// Amendment E turns it into a security-relevant token: a `namespace_meta` row
/// on this key is not one namespace's policy, it is the substrate-wide default.
pub const GLOBAL_STANDARD_NAMESPACE: &str = "*";

/// The one `allowed_namespaces` pattern that means "this peer may act in EVERY
/// namespace" — the deliberate per-peer allow-all the #2447/#2497 docs name as
/// the recovery for an over-tight scope.
///
/// `crate::federation::peer_attestation::glob_match` gives it that meaning; this
/// const exists so #2479's Amendment E can test for the pattern LITERALLY (see
/// [`peer_scope_is_allow_all`]) instead of asking `namespace_allowed` whether the
/// peer may write the namespace `*`, which is the very question that is unsafe.
pub const ALLOW_ALL_NAMESPACE_PATTERN: &str = "**";

/// #2479 Amendment E — whether the operator DECLARED an unconditional allow-all
/// scope for this peer.
///
/// # Why this is not `namespace_allowed(peer, "*", cfg)`
///
/// `glob_match` treats a bare `*` as "any SINGLE-segment target" (#1902), and
/// the literal string `"*"` contains no `/` — so `glob_match("*", "*")` is
/// `true`. An operator who writes `allowed_namespaces: ["*"]`, documented as
/// "any top-level namespace", would therefore also be granting the GLOBAL
/// standard, whose reach is every DEEP namespace the peer explicitly may NOT
/// write. That is precisely the whole-tree widening #1902 closed inside
/// `glob_match`, re-opened by a different door. So Amendment E asks a different
/// question — "did the operator declare `**`?" — and answers it by literal
/// comparison, with no glob semantics involved.
#[must_use]
pub fn peer_scope_is_allow_all(
    peer_id: Option<&str>,
    attest_cfg: &crate::federation::peer_attestation::PeerAttestationConfig,
) -> bool {
    peer_id
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .and_then(|p| attest_cfg.scope_for(p))
        .is_some_and(|scope| {
            scope
                .allowed_namespaces
                .iter()
                .any(|p| p == ALLOW_ALL_NAMESPACE_PATTERN)
        })
}

/// #2488 — distinguishable refusal cause for a federated deletion that was
/// refused because the target row's namespace could not be RESOLVED, as opposed
/// to resolved-and-out-of-scope.
///
/// Both dispositions increment the same `skipped` counter in a 200 response, so
/// without a cause token an operator cannot tell "your peer lacks scope" (fix
/// the config) from "this node cannot resolve that row" (an un-erasable row —
/// investigate the storage). Emitted as the `cause` field on the refusal WARN
/// and classified by `crate::federation::push_dlq::classify_quarantine_cause`,
/// following the [`CAUSE_UNENROLLED_AUTHOR_STRICT`] precedent.
pub const CAUSE_NAMESPACE_PROBE_UNRESOLVABLE: &str = "namespace_probe_unresolvable";

/// #2447 (CWE-284, security-high) — namespace confinement for an inbound
/// relayed MEMORY write, shared verbatim by the sqlite (`sync_push`) and
/// postgres (`sync_push_via_store`) receive loops so both backends behave
/// identically.
///
/// ## The hole this closes
///
/// The three federation lanes were asymmetric: the PULL lane (`/sync/since`)
/// filters its projection through the peer's `allowed_namespaces`, and the
/// DELETE lane resolves each target row's namespace and refuses out-of-scope
/// ids (#1934) — but the inbound `memories[]` WRITE loop consulted NEITHER.
/// A comment in `federation_receive.rs` asserted the write lane was confined
/// "via `resolve_inbound_attribution`"; that is false. `resolve_inbound_attribution`
/// gates WHO you may claim to be (`metadata.agent_id` against
/// `PeerScope::allowed_sender_agent_ids`), never WHICH namespace you may write
/// into. So a peer attested with `allowed_namespaces: ["public/*"]` could POST
/// a memory whose `namespace` is `secure/ops` and the row was persisted and
/// thereafter served to that tenant's agents as substrate truth.
///
/// ## Both namespaces are checked (the merge-clobber variant)
///
/// Checking only the inbound CLAIMED namespace would leave a trivially
/// equivalent bypass: `merge_memory` resolves the `namespace` field by LWW
/// (`crate::models::crdt_merge`), and `merge_inbound` field-merges ANY inbound
/// row whose `id` matches an existing local row. A `public/*`-scoped peer that
/// pushes `{id: <a known secure/ops row id>, namespace: "public/x", …}` with a
/// fresh `updated_at` would pass a claimed-only check and then RELOCATE the
/// `secure/ops` row into `public/x`, clobbering its title/content — a write
/// into (and destruction of) a namespace the peer was explicitly denied. So
/// when the caller resolved an existing row for this id, its STORED namespace
/// must be in scope too — the same "resolve the target row's namespace" rule
/// the #1934 delete lane applies, unioned with the pull lane's claimed-namespace
/// filter.
///
/// ## Two composed layers (the #1843 shape)
///
/// **Both layers are gated on [`PeerAttestationConfig::has_allowlist`] first**,
/// exactly like [`resolve_inbound_attribution`]'s and
/// [`signal_author_authorized`]'s Layer 1: with no
/// `AI_MEMORY_FED_PEER_ATTESTATION` configured, the ZERO-CONFIG posture, this
/// function is a no-op and replication is byte-identical to pre-#2447. Calling
/// [`crate::federation::peer_attestation::namespace_allowed`] verbatim (as the
/// #1934 delete lane does) would instead have returned `false` for every
/// zero-config push — a silent, total federation outage — because its
/// `scope_for(peer) == None` arm falls through to `sync_trust_peer_bypass()`,
/// which is `false` unless the operator opted out of #239 entirely.
///
/// - **Layer 1 (always-on, no knob)** — the peer DECLARED a non-empty
///   `allowed_namespaces` ([`peer_declares_namespace_scope`]). Both the claimed
///   and the stored namespace must glob-match it, through the shared #239
///   primitive `namespace_allowed` — the same function the #1934 delete lane
///   and the `/sync/since` projection filter call, so all three lanes share one
///   glob semantics and there is no second implementation to drift.
/// - **Layer 2 ([`require_push_namespace_scope_enabled`], default ON)** — the
///   peer is enrolled but declared NO namespace scope. Default-deny, matching
///   what that same config already means on the pull lane; the falsy token is
///   the staged-rollout opt-out and `["**"]` is the per-peer one.
///
/// [`resolve_inbound_attribution`]: crate::handlers::federation_receive::resolve_inbound_attribution
/// [`signal_author_authorized`]: crate::handlers::federation_receive::signal_author_authorized
///
/// Returns `true` when the memory may be applied, `false` (with a
/// namespace-naming WARN already emitted under
/// [`crate::handlers::federation_receive::ATTESTATION_TRACE_TARGET`]) when the
/// caller must `skipped += 1; continue` — a PER-MEMORY skip that never aborts
/// the rest of the batch, matching the #1843 signal-lane disposition.
///
/// `existing_namespace` is the stored namespace of the local row with the same
/// `id` (`None` when no such row exists, or when
/// [`inbound_write_needs_existing_namespace`] said the read was unnecessary).
/// A caller whose existence probe FAILED must fail closed (skip the row)
/// rather than pass `None` — `None` here means "provably no local row".
#[must_use]
pub fn inbound_write_namespace_authorized(
    lane: &str,
    memory_id: &str,
    claimed_namespace: &str,
    existing_namespace: Option<&str>,
    attest_cfg: &crate::federation::peer_attestation::PeerAttestationConfig,
    peer_id: Option<&str>,
    require_push_namespace_scope: bool,
) -> bool {
    use crate::federation::peer_attestation::namespace_allowed;
    use crate::handlers::federation_receive::ATTESTATION_TRACE_TARGET;

    // Zero-config: byte-identical faith-based replication (see the doc above).
    if !attest_cfg.has_allowlist() {
        return true;
    }

    // Layer 1 — enforce the scope the operator actually declared.
    if peer_declares_namespace_scope(peer_id, attest_cfg) {
        for (namespace, source) in [
            (Some(claimed_namespace), "claimed"),
            (existing_namespace, "stored"),
        ] {
            let Some(namespace) = namespace else { continue };
            if !namespace_allowed(peer_id, namespace, attest_cfg) {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    memory_id = %memory_id,
                    namespace = %namespace,
                    namespace_source = source,
                    peer_id = %peer_id.unwrap_or(""),
                    "sync_push: refusing federated {lane} entry outside the peer's \
                     namespace scope (#2447); skipping this entry, batch survives"
                );
                return false;
            }
        }
        return true;
    }

    // Layer 2 — enrolled peer that declared no namespace scope at all.
    layer2_unscoped_peer_authorized(
        lane,
        memory_id,
        Some(claimed_namespace),
        attest_cfg,
        peer_id,
        require_push_namespace_scope,
    )
}

/// Layer 2 of the inbound namespace gate — the disposition of an ENROLLED peer
/// that declared no `allowed_namespaces` at all. Factored out of
/// [`inbound_write_namespace_authorized`] so every lane (`memories[]`,
/// `archives[]`, `restores[]`, `deletions[]`) refuses through ONE site and the
/// refusal prose cannot fork per lane.
///
/// Returns `true` when the entry may proceed (the documented
/// `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=0` rollout window), `false` with
/// the operator-actionable WARN already emitted.
///
/// `namespace` is for the log line only — it is never consulted for the verdict,
/// which is why the caller may legitimately pass `None` after eliding the probe
/// (see [`inbound_write_needs_existing_namespace`]).
///
/// ## Only the ENROLLED-UNSCOPED shape is knob-governed (#2497)
///
/// Three peer shapes reach here under an enrolled posture, and
/// `require_push_namespace_scope` governs exactly ONE of them — see
/// [`peer_enrolled_in_allowlist`] for the table and the regression that
/// conflating them caused. A header-absent or not-in-the-allowlist push is
/// refused UNCONDITIONALLY, so the rollout hatch can never widen into an
/// anonymous-or-unknown-peer grant.
fn layer2_unscoped_peer_authorized(
    lane: &str,
    memory_id: &str,
    namespace: Option<&str>,
    attest_cfg: &crate::federation::peer_attestation::PeerAttestationConfig,
    peer_id: Option<&str>,
    require_push_namespace_scope: bool,
) -> bool {
    use crate::handlers::federation_receive::ATTESTATION_TRACE_TARGET;

    // #2497 — the two shapes the knob must NEVER govern. Refuse UNCONDITIONALLY.
    // `peer_id` here is already the post-`extract_peer_id` value, so a
    // whitespace-only header has collapsed to `None` and lands in the same arm.
    if !peer_enrolled_in_allowlist(peer_id, attest_cfg) {
        let shape = if peer_id.map(str::trim).is_none_or(str::is_empty) {
            "no x-peer-id header was presented (or it was empty/whitespace)"
        } else {
            "the presented x-peer-id is not enrolled in AI_MEMORY_FED_PEER_ATTESTATION"
        };
        tracing::warn!(
            target: ATTESTATION_TRACE_TARGET,
            memory_id = %memory_id,
            namespace = %namespace.unwrap_or(""),
            peer_id = %peer_id.unwrap_or(""),
            "sync_push: refusing federated {lane} entry — this node declares a peer \
             allowlist and {shape}, so the peer has NO namespace scope to act within \
             (#2447/#2497). This refusal is UNCONDITIONAL: \
             AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE governs only an ENROLLED peer \
             that declared no allowed_namespaces, never an anonymous or unenrolled \
             one. Enroll the peer in AI_MEMORY_FED_PEER_ATTESTATION (with a real \
             scope, or [\"**\"] for a deliberate per-peer allow-all), or remove the \
             allowlist entirely for the zero-config posture."
        );
        return false;
    }

    if !require_push_namespace_scope {
        return true;
    }
    // #2488 — the refusal prose must not contradict the lane it is refusing.
    // The pre-#2488 text ("its read + delete scope are already empty — refusing
    // this deletions entry") read as "your delete scope is already empty,
    // therefore I refuse your delete", which is circular on this lane and told
    // the operator nothing actionable. It is also no longer factually true of
    // the delete lane: since #2488 the delete disposition is governed by this
    // very knob rather than hard-coded deny-on-empty.
    let scope_note = if lane_is_destructive(lane) {
        "so its read (/sync/since) and write scopes are both empty — a peer that may \
         neither read nor write in ANY namespace may not hard-DELETE in one either"
    } else {
        "so its write scope would be unbounded while its read (/sync/since) scope is \
         already empty"
    };
    tracing::warn!(
        target: ATTESTATION_TRACE_TARGET,
        memory_id = %memory_id,
        namespace = %namespace.unwrap_or(""),
        peer_id = %peer_id.unwrap_or(""),
        "sync_push: peer is enrolled but declares no allowed_namespaces, {scope_note} — \
         refusing this {lane} entry (#2447). Declare the peer's namespace scope in \
         AI_MEMORY_FED_PEER_ATTESTATION (use [\"**\"] for a deliberate allow-all), or \
         set AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=0 for a rollout window."
    );
    false
}

/// #2447 — the by-id sibling of [`inbound_write_namespace_authorized`], for the
/// `/sync/push` lanes that act on an EXISTING row rather than a caller-supplied
/// one (`archives[]`, `restores[]`, and since #2488 `deletions[]`): there is no
/// claimed namespace to check, only the row's stored one.
///
/// Kept as a thin wrapper rather than a second policy so the two layers — and
/// therefore the disposition of an enrolled peer that declares no scope — stay
/// IDENTICAL across every lane. Before #2488 the `deletions[]` lane was the
/// exception: sqlite called the deny-on-empty
/// [`crate::federation::peer_attestation::namespace_allowed`] verbatim (refusing
/// EVERY zero-config deletion — a silent delete-replication outage, #2491) while
/// postgres wrapped the whole gate in the read-ELISION predicate
/// [`inbound_write_needs_existing_namespace`] (skipping the gate entirely for the
/// enrolled-unscoped peer Layer 2 exists to refuse, #2488). Both now route here,
/// so all four lanes share one verdict on all four peer shapes.
///
/// ## `stored_namespace: Option<&str>` (#2488)
///
/// `None` means "the caller deliberately did NOT read the stored namespace,
/// because [`inbound_write_needs_existing_namespace`] said its answer cannot
/// change the verdict" — i.e. Layer 1 is not armed for this peer and Layer 2
/// decides on the peer's posture alone. The parameter is typed `Option` rather
/// than taking a `&str` the caller fabricates with `unwrap_or("")` so that
/// "unread on the Layer-2 path" is enforced by the compiler instead of by
/// convention: a caller cannot accidentally feed an empty string into a Layer-1
/// glob match, and this function cannot accidentally consult a namespace that
/// was never resolved.
///
/// A caller whose probe FAILED must fail closed at the call site (skip the item)
/// and must never arrive here as `None`; a caller that PROVED there is no such
/// row must count the no-op and never reach here at all. If `None` arrives while
/// Layer 1 IS armed the verdict is a fail-closed `false` — the stored namespace
/// is load-bearing on that path, so an absent value cannot be waved through.
#[must_use]
pub fn inbound_by_id_namespace_authorized(
    lane: &str,
    memory_id: &str,
    stored_namespace: Option<&str>,
    attest_cfg: &crate::federation::peer_attestation::PeerAttestationConfig,
    peer_id: Option<&str>,
    require_push_namespace_scope: bool,
) -> bool {
    // Zero-config: byte-identical faith-based replication (see the doc on
    // `inbound_write_namespace_authorized`).
    if !attest_cfg.has_allowlist() {
        return true;
    }
    match stored_namespace {
        // Layer 1 is (or may be) armed and the caller resolved the row — the
        // stored namespace is the subject of the scope check on a by-id lane.
        Some(namespace) => inbound_write_namespace_authorized(
            lane,
            memory_id,
            namespace,
            None,
            attest_cfg,
            peer_id,
            require_push_namespace_scope,
        ),
        None if peer_declares_namespace_scope(peer_id, attest_cfg) => {
            tracing::warn!(
                target: crate::handlers::federation_receive::ATTESTATION_TRACE_TARGET,
                memory_id = %memory_id,
                peer_id = %peer_id.unwrap_or(""),
                "sync_push: refusing federated {lane} entry — Layer 1 is armed for this \
                 peer, so the target row's stored namespace is load-bearing, but the \
                 caller elided the probe (#2488 fail-closed)"
            );
            false
        }
        // Layer-2-only shape: the stored namespace was never read because it
        // cannot change the verdict.
        None => layer2_unscoped_peer_authorized(
            lane,
            memory_id,
            None,
            attest_cfg,
            peer_id,
            require_push_namespace_scope,
        ),
    }
}

/// #2479 (CWE-284) — namespace confinement for the `/sync/push` GOVERNANCE-
/// STANDARD lanes (`namespace_meta[]` + `namespace_meta_clears[]`), routed
/// through the SAME shared Layer-1/Layer-2 verdict every other confined lane
/// uses so this lane's disposition of all four peer shapes is byte-identical to
/// theirs and the empty-scope case honours
/// `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE` rather than hard-coding one.
///
/// ## The hole this closes
///
/// The two loops validated `validate_namespace` / `validate_id` and nothing
/// else, then called `db::set_namespace_standard` / `db::clear_namespace_standard`
/// directly. Neither consulted the peer's `allowed_namespaces`. That is an
/// authz-CONFIG takeover rather than a data write: the row selects the standard
/// memory whose `metadata.governance` `resolve_governance_policy` returns, so it
/// rewrites the rules every subsequent LOCAL write to that namespace is judged
/// against — approval level, approver identity, delete gating — and the clear
/// lane is the same reach in the destructive direction.
///
/// ## Which namespaces this gates, and which it provably cannot
///
/// The apply-path touches, and this function gates, the UNION of:
///
/// - **`namespace`** — the `namespace_meta` row written or deleted. It is the
///   table's PRIMARY KEY, so unlike `memories[]` there is no id under which a
///   row could be RELOCATED: declared and stored are the same string and the
///   #2447 merge-clobber probe has no subject here. That is why this lane needs
///   no by-id probe at all and this function is backend-blind.
/// - **`declared_parent`** — spliced into that namespace's inheritance chain, so
///   it changes which OTHER namespace's policy governs by reference rather than
///   by value. Gated per the issue's own acceptance criterion ("a peer must not
///   attach a namespace it owns as the parent of one it does not, nor vice
///   versa"). Two honest caveats: (a) `build_namespace_chain` consults the
///   explicit parent only on the ROOT `/` segment of a queried namespace, so a
///   parent stored on `a/b` is inert for `a/b`'s own chain and this gate is
///   behaviour-relevant only for single-segment namespaces; (b) a parent of
///   literal `*` is likewise inert (the chain walk skips it) yet is still gated
///   here for uniformity — an operator hitting that refusal should drop the
///   redundant field, since the global standard is already in every chain.
///
/// It does NOT and cannot gate:
///
/// - **the DESCENDANTS of `namespace`.** `resolve_governance_policy` walks
///   leaf-first and returns the first level carrying a policy, so a peer scoped
///   to an ANCESTOR (e.g. exactly `["secure"]`) sets the DEFAULT policy of every
///   `secure/**` namespace that carries none of its own. Closing that needs
///   pattern-vs-pattern subsumption, which the shared `glob_match` primitive
///   structurally cannot express (it matches a pattern against a CONCRETE
///   target), so a subtree variant was ranked LAST by the #2479 vote and is
///   tracked separately rather than forked off the one #239 glob SSOT.
/// - **the namespace the `standard_id` memory LIVES IN.** `set_namespace_standard`
///   deliberately permits cross-namespace binding ("shared policy"), so gating it
///   would break a documented feature; the read-amplification that binding a
///   foreign memory enables is tracked separately.
///
/// ## Amendment E — the global standard is not just another namespace
///
/// A row on [`GLOBAL_STANDARD_NAMESPACE`] is the substrate-wide default policy,
/// so it is refused UNLESS the operator declared an unconditional allow-all
/// scope ([`peer_scope_is_allow_all`]). That check runs BEFORE the layered
/// verdict and is therefore NOT governed by
/// `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE`: the knob is a per-peer rollout
/// hatch for one config shape, and a hatch that hands a peer the governance
/// default of every namespace on the node is not that. See
/// [`peer_scope_is_allow_all`] for why `glob_match("*", "*") == true` makes the
/// naive check unsafe.
///
/// ## Zero-config
///
/// Short-circuits on [`PeerAttestationConfig::has_allowlist`] exactly like every
/// sibling lane, so a node with no `AI_MEMORY_FED_PEER_ATTESTATION` replicates
/// governance standards byte-identically to pre-#2479. Callers MUST ALSO wrap the
/// call in that same predicate (the #2491 lesson is that a gate which runs
/// unconditionally is how a lane goes silently dark).
///
/// [`PeerAttestationConfig::has_allowlist`]: crate::federation::peer_attestation::PeerAttestationConfig::has_allowlist
///
/// Returns `true` when the entry may proceed; `false` with an
/// operator-actionable WARN already emitted, in which case the caller must count
/// the refusal and `continue`.
#[must_use]
pub fn inbound_namespace_meta_authorized(
    lane: &str,
    namespace: &str,
    declared_parent: Option<&str>,
    attest_cfg: &crate::federation::peer_attestation::PeerAttestationConfig,
    peer_id: Option<&str>,
    require_push_namespace_scope: bool,
) -> bool {
    use crate::handlers::federation_receive::ATTESTATION_TRACE_TARGET;

    // Zero-config: byte-identical faith-based replication.
    if !attest_cfg.has_allowlist() {
        return true;
    }

    // Amendment E — before, and independent of, the layered verdict.
    if namespace == GLOBAL_STANDARD_NAMESPACE && !peer_scope_is_allow_all(peer_id, attest_cfg) {
        tracing::warn!(
            target: ATTESTATION_TRACE_TARGET,
            namespace = %namespace,
            peer_id = %peer_id.unwrap_or(""),
            "sync_push: refusing federated {lane} entry on the GLOBAL standard '*' — that row \
             is not one namespace's policy, it is the substrate-wide default that \
             build_namespace_chain prepends to EVERY namespace's inheritance chain, including \
             deep namespaces this peer may not write (#2479 Amendment E). This refusal is \
             UNCONDITIONAL: AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE does not govern it. \
             Note a bare \"*\" in allowed_namespaces means ONE top-level segment (#1902), not \
             allow-all — declare \"**\" for this peer if it is genuinely trusted to set the \
             substrate-wide governance default."
        );
        return false;
    }

    // The row's own namespace, then the parent it splices above that namespace.
    // `namespace` is the table PRIMARY KEY, so there is no stored-vs-claimed
    // split to resolve and no probe to elide — both subjects are on the wire.
    for candidate in [Some(namespace), declared_parent] {
        let Some(candidate) = candidate else { continue };
        if !inbound_write_namespace_authorized(
            lane,
            namespace,
            candidate,
            None,
            attest_cfg,
            peer_id,
            require_push_namespace_scope,
        ) {
            return false;
        }
    }

    true
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
    fn require_push_namespace_scope_default_strict_and_falsy_opts_out() {
        // #2447 — the write-lane sibling of the two resolver tests above, and
        // the co-located precedence pin the env-table row 147 points at (this
        // is a direct-read knob, so it takes no `config_precedence` entry —
        // the #84/#85/#87/#94/#96/#123/#125/#132 pattern). SAFETY: single-
        // threaded mutation of a var no other test reads.
        unsafe { std::env::remove_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV) };
        assert!(
            require_push_namespace_scope_enabled(),
            "unset → strict; a FED_REQUIRE_* knob defaulting permissive would \
             be grammar-illegal (all 7 siblings are default-ON at v1.0.0)"
        );
        for truthy in ["1", "true", "yes", "on", "  on  "] {
            unsafe { std::env::set_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV, truthy) };
            assert!(
                require_push_namespace_scope_enabled(),
                "{truthy:?} → strict"
            );
        }
        for falsy in ["0", "false", "no", "off", "  off  "] {
            unsafe { std::env::set_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV, falsy) };
            assert!(
                !require_push_namespace_scope_enabled(),
                "{falsy:?} → the staged-rollout opt-out"
            );
        }
        // The shared `env_flag_default_on` grammar trims but does NOT
        // case-fold, so an uppercase token is unrecognised and therefore
        // fail-closed — identical to all 7 sibling FED_REQUIRE_* knobs.
        unsafe { std::env::set_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV, "OFF") };
        assert!(
            require_push_namespace_scope_enabled(),
            "\"OFF\" is not a recognised falsy token → stays strict"
        );
        unsafe { std::env::set_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV, "garbage") };
        assert!(
            require_push_namespace_scope_enabled(),
            "garbage → strict default (a typo must never silently widen scope)"
        );
        unsafe { std::env::remove_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV) };
    }

    /// #2447 — the pure verdict, exercised without any HTTP/DB plumbing. The
    /// zero-config arm is the load-bearing one: a verbatim `namespace_allowed`
    /// call would return `false` here and silently black-hole every inbound
    /// memory on an unconfigured deployment.
    #[test]
    fn inbound_write_namespace_verdict_layers() {
        use crate::federation::peer_attestation::{PeerAttestationConfig, PeerScope};

        let zero_config = PeerAttestationConfig::default();
        assert!(
            inbound_write_namespace_authorized(
                "memories",
                "id-1",
                "secure/ops",
                None,
                &zero_config,
                Some("peer-1"),
                true,
            ),
            "zero-config must be byte-identical to pre-#2447 even under the knob"
        );

        let mut scoped = PeerAttestationConfig::default();
        scoped.peers.insert(
            "peer-1".to_string(),
            PeerScope {
                allowed_sender_agent_ids: vec![],
                allowed_namespaces: vec!["public/*".to_string()],
            },
        );
        assert!(
            inbound_write_namespace_authorized(
                "memories",
                "id-1",
                "public/ok",
                None,
                &scoped,
                Some("peer-1"),
                true,
            ),
            "Layer 1: in-scope claimed namespace accepted"
        );
        assert!(
            !inbound_write_namespace_authorized(
                "memories",
                "id-1",
                "secure/ops",
                None,
                &scoped,
                Some("peer-1"),
                true,
            ),
            "Layer 1: out-of-scope claimed namespace refused"
        );
        assert!(
            !inbound_write_namespace_authorized(
                "memories",
                "id-1",
                "public/loot",
                Some("secure/ops"),
                &scoped,
                Some("peer-1"),
                true,
            ),
            "Layer 1: an in-scope CLAIM cannot launder an out-of-scope STORED \
             namespace — this is the merge-clobber bypass"
        );

        let mut unscoped = PeerAttestationConfig::default();
        unscoped.peers.insert(
            "peer-1".to_string(),
            PeerScope {
                allowed_sender_agent_ids: vec!["a".to_string()],
                allowed_namespaces: vec![],
            },
        );
        assert!(
            !inbound_write_namespace_authorized(
                "memories",
                "id-1",
                "public/ok",
                None,
                &unscoped,
                Some("peer-1"),
                true,
            ),
            "Layer 2 ON: an enrolled peer declaring no scope is refused"
        );
        assert!(
            inbound_write_namespace_authorized(
                "memories",
                "id-1",
                "public/ok",
                None,
                &unscoped,
                Some("peer-1"),
                false,
            ),
            "Layer 2 OFF: the staged-rollout opt-out restores the legacy posture"
        );
    }

    /// #2649 / #2650 — crypto lanes must share the same Layer-1 namespace choke
    /// as memories (authentication is not authorization). Pins the lane tokens
    /// the receive loop passes so a rename cannot silently drop confinement.
    #[test]
    fn inbound_write_namespace_refuses_crypto_lanes_out_of_scope_2649_2650() {
        use crate::federation::peer_attestation::{PeerAttestationConfig, PeerScope};

        let mut scoped = PeerAttestationConfig::default();
        scoped.peers.insert(
            "peer-1".to_string(),
            PeerScope {
                allowed_sender_agent_ids: vec![],
                allowed_namespaces: vec!["public/*".to_string()],
            },
        );

        // #2649 — action_transitions subject is the **stored** action namespace.
        assert!(
            inbound_write_namespace_authorized(
                LANE_ACTION_TRANSITIONS,
                "act-1",
                "public/ok",
                Some("public/ok"),
                &scoped,
                Some("peer-1"),
                true,
            ),
            "in-scope stored action namespace accepted"
        );
        assert!(
            !inbound_write_namespace_authorized(
                LANE_ACTION_TRANSITIONS,
                "act-1",
                "secure/ops",
                Some("secure/ops"),
                &scoped,
                Some("peer-1"),
                true,
            ),
            "#2649: out-of-scope stored action namespace refused"
        );

        // #2650 — checkpoints subject is the wire-claimed freeze-anchor ns.
        assert!(
            inbound_write_namespace_authorized(
                LANE_CHECKPOINTS,
                "cp-1",
                "public/ok",
                None,
                &scoped,
                Some("peer-1"),
                true,
            ),
            "in-scope checkpoint namespace accepted"
        );
        assert!(
            !inbound_write_namespace_authorized(
                LANE_CHECKPOINTS,
                "cp-1",
                "secure/ops",
                None,
                &scoped,
                Some("peer-1"),
                true,
            ),
            "#2650: out-of-scope checkpoint namespace refused"
        );
    }

    /// #2488 — the by-id verdict's `Option<&str>` contract, exercised without
    /// any HTTP/DB plumbing. The `None` arms are the whole point of the type
    /// change: one must reach Layer 2 (the shape whose gate #2488 skipped), the
    /// other must fail CLOSED (the shape a fabricated `unwrap_or("")` would have
    /// silently glob-matched into a Layer-1 accept-or-refuse on an empty string).
    #[test]
    fn inbound_by_id_verdict_option_contract_2488() {
        use crate::federation::peer_attestation::{PeerAttestationConfig, PeerScope};

        // ZERO-CONFIG — #2491. A verbatim `namespace_allowed` call returns false
        // here (its `scope_for == None` arm falls through to the default-off
        // `sync_trust_peer_bypass`), which is exactly the silent
        // delete-replication outage. The verdict must short-circuit to `true`
        // regardless of whether the caller resolved a namespace.
        let zero_config = PeerAttestationConfig::default();
        for stored in [None, Some("secure/ops")] {
            assert!(
                inbound_by_id_namespace_authorized(
                    LANE_DELETIONS,
                    "id-1",
                    stored,
                    &zero_config,
                    Some("peer-1"),
                    true,
                ),
                "zero-config must replicate the deletion (#2491), stored={stored:?}"
            );
        }

        // ENROLLED + UNSCOPED — #2488. Layer 1 is NOT armed, so the caller
        // legitimately elides the probe and passes `None`; the verdict must
        // still reach Layer 2 rather than skipping all checking.
        let mut unscoped = PeerAttestationConfig::default();
        unscoped.peers.insert(
            "peer-1".to_string(),
            PeerScope {
                allowed_sender_agent_ids: vec!["a".to_string()],
                allowed_namespaces: vec![],
            },
        );
        assert!(
            !inbound_by_id_namespace_authorized(
                LANE_DELETIONS,
                "id-1",
                None,
                &unscoped,
                Some("peer-1"),
                true,
            ),
            "#2488: an enrolled peer declaring no scope must be REFUSED on the \
             by-id lane even though the stored namespace was never read — this is \
             the arm the read-elision predicate made unreachable"
        );
        assert!(
            inbound_by_id_namespace_authorized(
                LANE_DELETIONS,
                "id-1",
                None,
                &unscoped,
                Some("peer-1"),
                false,
            ),
            "#2488: the env-row-147 rollout opt-out must be REACHABLE on this lane"
        );

        // ENROLLED + SCOPED — Layer 1 armed. `Some` behaves as before, and
        // `None` (a caller that wrongly elided a load-bearing probe) must fail
        // CLOSED rather than be waved through.
        let mut scoped = PeerAttestationConfig::default();
        scoped.peers.insert(
            "peer-1".to_string(),
            PeerScope {
                allowed_sender_agent_ids: vec![],
                allowed_namespaces: vec!["public/*".to_string()],
            },
        );
        assert!(
            inbound_by_id_namespace_authorized(
                LANE_DELETIONS,
                "id-1",
                Some("public/ok"),
                &scoped,
                Some("peer-1"),
                true,
            ),
            "Layer 1: an in-scope stored namespace is applied"
        );
        assert!(
            !inbound_by_id_namespace_authorized(
                LANE_DELETIONS,
                "id-1",
                Some("secure/ops"),
                &scoped,
                Some("peer-1"),
                true,
            ),
            "Layer 1: an out-of-scope stored namespace is refused (#1934)"
        );
        assert!(
            !inbound_by_id_namespace_authorized(
                LANE_DELETIONS,
                "id-1",
                None,
                &scoped,
                Some("peer-1"),
                true,
            ),
            "#2488 fail-closed: `None` while Layer 1 IS armed means the caller \
             elided a load-bearing probe; the stored namespace decides on that \
             path, so an absent value must never be admitted"
        );

        // #2497 — the two peer shapes the knob must NEVER govern. Under an
        // ENROLLED posture, a header-absent (`None`) or unenrolled peer is
        // refused UNCONDITIONALLY: both knob states, both allowlist shapes,
        // both `stored_namespace` values. The knob-OFF arms are the
        // regression — the first #2488 fix returned `true` for every one of
        // them, granting an anonymous or unknown peer unbounded delete-by-id.
        for cfg in [&unscoped, &scoped] {
            for peer in [None, Some("peer-not-enrolled"), Some("   ")] {
                for require in [true, false] {
                    for stored in [None, Some("public/ok"), Some("secure/ops")] {
                        assert!(
                            !inbound_by_id_namespace_authorized(
                                LANE_DELETIONS,
                                "id-1",
                                stored,
                                cfg,
                                peer,
                                require,
                            ),
                            "#2497: under an enrolled posture a header-absent / \
                             unenrolled / whitespace-only peer must be REFUSED \
                             unconditionally — the rollout knob governs only an \
                             ENROLLED peer that declared no allowed_namespaces. \
                             peer={peer:?} require={require} stored={stored:?}"
                        );
                        // Same contract on the WRITE lane's shared entry point,
                        // so the two lanes cannot disagree about these shapes.
                        assert!(
                            !inbound_write_namespace_authorized(
                                "memories",
                                "id-1",
                                "public/ok",
                                stored,
                                cfg,
                                peer,
                                require,
                            ),
                            "#2497: the write lane must refuse the same shapes \
                             identically. peer={peer:?} require={require}"
                        );
                    }
                }
            }
        }

        // And the ZERO-CONFIG posture is untouched by all of that: with no
        // allowlist configured, a header-absent push still replicates (that is
        // #2491, and it must not be re-broken by the #2497 tightening).
        for peer in [None, Some("peer-not-enrolled")] {
            assert!(
                inbound_by_id_namespace_authorized(
                    LANE_DELETIONS,
                    "id-1",
                    None,
                    &zero_config,
                    peer,
                    true,
                ),
                "#2491: zero-config replicates regardless of the peer header — the \
                 #2497 tightening applies ONLY under an enrolled posture. peer={peer:?}"
            );
        }
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
