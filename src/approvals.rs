// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 K10 — Approval API (HTTP + SSE + MCP).
//!
//! When the governance gate returns `Pending`, an operator must
//! eventually decide. v0.7.0 surfaces three transports for that
//! decision:
//!
//! 1. **HTTP** — `POST /api/v1/approvals/{pending_id}` with the body
//!    `{"decision":"approve|deny","remember":"once|session|forever"}`.
//!    Gated behind the K7 `[hooks.subscription] hmac_secret` server-wide
//!    HMAC: requests without a valid `X-AI-Memory-Signature: sha256=…`
//!    header are rejected `401`.
//! 2. **SSE** — `GET /api/v1/approvals/stream` server-sent events.
//!    Subscribers receive `approval_requested` (one per new
//!    `pending_actions` row) and `approval_decided` (one per
//!    approve/deny outcome) frames, fanned out through a process-wide
//!    `tokio::sync::broadcast` channel so multiple watchers can attach
//!    concurrently without contention on the DB lock.
//! 3. **MCP** — the existing `memory_pending_approve` /
//!    `memory_pending_reject` tools gain an optional `remember`
//!    property. The K10 contract preserves the pre-K10 schema (no new
//!    tools, no removed properties) — so existing callers keep working
//!    unchanged and only opt into `remember` when they want
//!    forever-persisted permission rules.
//!
//! When `remember = "forever"`, K10 stamps a synthetic
//! [`SyntheticPermissionRule`] into the process-wide registry so the
//! same `(action, namespace, agent_id)` tuple auto-decides next time.
//! K9 (the unified permission pipeline) will consult the registry from
//! its rule-evaluation path; until K9 lands on this branch, the
//! registry exists as an isolated K10-internal store that the K10 test
//! suite can introspect to pin the contract.

use std::sync::OnceLock;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Capacity of the process-wide approval broadcast channel.
///
/// Sized to absorb a brief spike of `approval_requested` /
/// `approval_decided` events without forcing a slow SSE subscriber to
/// drop frames. SSE consumers see [`broadcast::error::RecvError::Lagged`]
/// when this is exceeded; the [`approvals_sse`](crate::handlers::approvals_sse)
/// handler turns that into a `lagged` SSE event so clients can re-sync
/// via `GET /api/v1/pending`.
pub const APPROVAL_BROADCAST_CAPACITY: usize = 1024;

/// Decision an operator submits via the K10 transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Approve,
    Deny,
}

/// How long a `remember` choice persists.
///
/// - `Once` — just this decision; no rule recorded.
/// - `Session` — recorded in-memory; cleared on restart.
/// - `Forever` — recorded in-memory AND queued for persistence to the
///   live `config.toml` `[[permissions.rules]]` table on the next
///   config write. (The actual disk write is owned by the K9 rule
///   loader; K10's contract is to populate the registry that K9
///   consults.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Remember {
    Once,
    Session,
    Forever,
}

/// One row in the K10 synthetic-permission-rule registry.
///
/// Mirrors the shape K9's `[[permissions.rules]]` table will use
/// once K9 lands on the same branch — that way K9's loader can
/// promote these in-memory rows into config-file rows without a
/// schema translation step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticPermissionRule {
    /// `pending_actions.action_type` — `"store"`, `"delete"`, or `"promote"`.
    pub action_type: String,
    /// `pending_actions.namespace` — the namespace the original gated
    /// action targeted.
    pub namespace: String,
    /// `pending_actions.requested_by` — the agent the rule auto-decides
    /// for. `None` means "any agent in this namespace" (rare, but the
    /// K10 contract reserves the slot for fleet-wide rules).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// `"approve"` or `"deny"` — the auto-decision the gate should
    /// return next time it sees a matching tuple.
    pub decision: String,
    /// RFC3339 timestamp the rule was recorded. Surfaced in audit
    /// trails and (eventually) in K9's rule-summary doctor surface.
    pub recorded_at: String,
}

/// Process-wide registry of `remember=forever` rules. Populated by
/// the K10 transports; read by K9's rule resolver (when K9 lands).
static SYNTHETIC_RULES: RwLock<Vec<SyntheticPermissionRule>> = RwLock::new(Vec::new());

/// Append a synthetic rule to the registry.
///
/// Idempotent on the `(action_type, namespace, agent_id, decision)`
/// tuple — calling twice with the same tuple is a no-op (the recorded
/// timestamp from the first insert wins). Lock poisoning is treated as
/// fatal-but-recoverable: we drop the poisoned guard and proceed
/// against the inner data, mirroring the K3 `lock_permissions_mode_for_test`
/// posture.
pub fn record_synthetic_rule(rule: SyntheticPermissionRule) {
    let mut guard = SYNTHETIC_RULES
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let already = guard.iter().any(|r| {
        r.action_type == rule.action_type
            && r.namespace == rule.namespace
            && r.agent_id == rule.agent_id
            && r.decision == rule.decision
    });
    if !already {
        guard.push(rule);
    }
}

/// Snapshot the registry. Returns a clone so callers can release the
/// read lock immediately.
#[must_use]
pub fn list_synthetic_rules() -> Vec<SyntheticPermissionRule> {
    SYNTHETIC_RULES
        .read()
        .map(|g| g.clone())
        .unwrap_or_default()
}

/// Test-only: clear the registry. Production code never resets the
/// registry mid-process; tests use this to assert against a clean slate.
#[doc(hidden)]
pub fn clear_synthetic_rules_for_test() {
    if let Ok(mut g) = SYNTHETIC_RULES.write() {
        g.clear();
    }
}

/// One frame on the SSE stream.
///
/// Two variants today:
///   - `ApprovalRequested` — fired when a `pending_actions` row is
///     inserted (governance gate returned `Pending`).
///   - `ApprovalDecided` — fired when an approve/reject decision is
///     finalised (any of the three K10 transports).
///
/// Both carry the pending-action id so subscribers can round-trip back
/// through `GET /api/v1/pending/{id}` for the full row payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ApprovalEvent {
    ApprovalRequested {
        pending_id: String,
        action_type: String,
        namespace: String,
        requested_by: String,
        requested_at: String,
    },
    ApprovalDecided {
        pending_id: String,
        decision: String,
        decided_by: String,
        remember: String,
        /// Originating namespace of the pending row this decision
        /// targets. Required by the K10 SSE filter (review #628
        /// blocker C2): without it the receive-side filter cannot
        /// scope the event to the right tenant.
        #[serde(default)]
        namespace: String,
        /// Original requester for the pending row this decision
        /// targets. Same rationale as `namespace` — the decision
        /// frame is delivered to the original requester even if a
        /// different operator pressed the approve button.
        #[serde(default)]
        requested_by: String,
    },
}

impl ApprovalEvent {
    /// Tenant agent the event belongs to — `requested_by` for both
    /// variants. Used by the SSE handler to scope broadcasts to the
    /// originating agent (review #628 blocker C2).
    #[must_use]
    pub fn tenant_agent_id(&self) -> &str {
        match self {
            ApprovalEvent::ApprovalRequested { requested_by, .. }
            | ApprovalEvent::ApprovalDecided { requested_by, .. } => requested_by.as_str(),
        }
    }

    /// Namespace the event belongs to. Used by the SSE handler in
    /// concert with K9's permission rules to decide whether a
    /// subscriber may see a cross-agent event.
    #[must_use]
    pub fn tenant_namespace(&self) -> &str {
        match self {
            ApprovalEvent::ApprovalRequested { namespace, .. }
            | ApprovalEvent::ApprovalDecided { namespace, .. } => namespace.as_str(),
        }
    }
}

/// Process-wide broadcast channel for [`ApprovalEvent`]. Lazily
/// initialised on first subscribe / publish — the server's HTTP layer
/// touches it from `handlers::approvals_sse` and the publish side fires
/// from `handlers::approve_via_approval_api`,
/// `subscriptions::dispatch_approval_requested`, and the MCP
/// approve/reject handlers.
static APPROVAL_BUS: OnceLock<broadcast::Sender<ApprovalEvent>> = OnceLock::new();

fn bus() -> &'static broadcast::Sender<ApprovalEvent> {
    APPROVAL_BUS.get_or_init(|| {
        let (tx, _rx) = broadcast::channel(APPROVAL_BROADCAST_CAPACITY);
        tx
    })
}

/// Publish an [`ApprovalEvent`] to all SSE subscribers.
///
/// No subscribers → swallowed silently (the `broadcast::Sender::send`
/// `Err(SendError(_))` branch is the documented "no receivers" outcome
/// and is never an error in this codebase: SSE is best-effort and we
/// must not fail the underlying approve/reject path on a missing
/// subscriber).
pub fn publish(event: ApprovalEvent) {
    let _ = bus().send(event);
}

/// Subscribe to the process-wide approval bus. Returns a fresh
/// [`broadcast::Receiver`] that will see every event published AFTER
/// this call (broadcast channels do not replay history — that's what
/// `GET /api/v1/pending` is for).
#[must_use]
pub fn subscribe() -> broadcast::Receiver<ApprovalEvent> {
    bus().subscribe()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialise the unit tests that mutate the global registry —
    /// `cargo test` runs tests in parallel by default and the
    /// `SYNTHETIC_RULES` static is shared across them.
    fn registry_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn record_and_list_round_trip() {
        let _g = registry_lock();
        clear_synthetic_rules_for_test();
        let rule = SyntheticPermissionRule {
            action_type: "store".into(),
            namespace: "scratch".into(),
            agent_id: Some("alice".into()),
            decision: "approve".into(),
            recorded_at: "2026-05-05T00:00:00Z".into(),
        };
        record_synthetic_rule(rule.clone());
        let snap = list_synthetic_rules();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0], rule);
    }

    #[test]
    fn record_synthetic_rule_is_idempotent() {
        let _g = registry_lock();
        clear_synthetic_rules_for_test();
        let rule = SyntheticPermissionRule {
            action_type: "delete".into(),
            namespace: "ns".into(),
            agent_id: Some("bob".into()),
            decision: "deny".into(),
            recorded_at: "2026-05-05T00:00:00Z".into(),
        };
        record_synthetic_rule(rule.clone());
        // Second call with a later timestamp must not double the row.
        let mut later = rule.clone();
        later.recorded_at = "2099-01-01T00:00:00Z".into();
        record_synthetic_rule(later);
        let snap = list_synthetic_rules();
        assert_eq!(snap.len(), 1);
        // First-writer-wins on the timestamp.
        assert_eq!(snap[0].recorded_at, "2026-05-05T00:00:00Z");
    }

    #[tokio::test]
    async fn publish_and_subscribe_round_trip() {
        let mut rx = subscribe();
        let evt = ApprovalEvent::ApprovalRequested {
            pending_id: "pa-1".into(),
            action_type: "store".into(),
            namespace: "scratch".into(),
            requested_by: "alice".into(),
            requested_at: "2026-05-05T00:00:00Z".into(),
        };
        publish(evt.clone());
        let received = rx.recv().await.expect("recv");
        match received {
            ApprovalEvent::ApprovalRequested { pending_id, .. } => assert_eq!(pending_id, "pa-1"),
            _ => panic!("wrong variant"),
        }
    }
}

/// R40 (#1957) — human-key-signed approvals, m-of-n quorum, and typed
/// escalation routing to the approval gate.
///
/// Before R40 a pending/escalated operation cleared on a self-asserted
/// approver *string* ([`crate::storage::approve_with_approver_type`]); this
/// module adds a cryptographic layer where the approval of a
/// pending/escalated operation is authorized by an Ed25519 signature from an
/// **enrolled** operator/approver key.
///
/// # Cryptographically enforced (ATTESTABLE) vs operational
///
/// **Cryptographically enforced.** Every approval carries a detached Ed25519
/// signature over the domain-separated approval pre-image
/// ([`signed::approval_signing_bytes`]), verified with `verify_strict`
/// against an *enrolled* approver public key. A forged signature (bad bytes
/// or wrong key) is rejected ([`signed::QuorumError::Forged`]); a signer whose
/// key is not enrolled is rejected ([`signed::QuorumError::Unenrolled`]). The
/// m-of-n quorum counts *distinct* valid enrolled signers, so a duplicated
/// signature can never inflate the tally.
///
/// **Operational (NOT a cryptographic property).** The enrollment set — WHO
/// is a legitimate approver — is a custody decision the operator controls via
/// `AI_MEMORY_OPERATOR_PUBKEY` / `AI_MEMORY_APPROVER_PUBKEYS`. The
/// "30-minute airgapped operability" claim is an SLO demonstrated by an
/// offline integration test (`tests/r40_airgapped_approval.rs`), not a signed
/// attestation.
pub mod signed {
    use base64::Engine;
    use ed25519_dalek::{Signature, VerifyingKey};
    use std::collections::{BTreeSet, HashSet};

    /// Comma-separated base64 (standard OR url-safe-no-pad) Ed25519 public
    /// keys enrolled as approvers, in ADDITION to `AI_MEMORY_OPERATOR_PUBKEY`
    /// (the governance operator-key custody, always enrolled when resolvable).
    pub const APPROVER_PUBKEYS_ENV: &str = "AI_MEMORY_APPROVER_PUBKEYS";

    /// The m-of-n approval threshold — the minimum count of DISTINCT valid
    /// enrolled approver signatures required before an escalated / pending
    /// operation proceeds. Defaults to 1; a value below 1 clamps to 1.
    pub const APPROVAL_THRESHOLD_ENV: &str = "AI_MEMORY_APPROVAL_THRESHOLD";

    /// Domain-separation tag folded into the approval signing pre-image so an
    /// approval signature can never be replayed as any other Ed25519 signature
    /// the substrate verifies (and vice-versa).
    pub const APPROVAL_DOMAIN: &[u8] = b"ai-memory:approval:v1";

    /// Pending-payload metadata key stamped on a pending action that was
    /// routed from a typed
    /// [`Decision::Escalate`](crate::governance::agent_action::Decision::Escalate)
    /// and therefore REQUIRES a signed (human-key / m-of-n) approval before it
    /// can proceed.
    pub const REQUIRES_SIGNED_APPROVAL_KEY: &str = "requires_signed_approval";
    /// Pending-payload metadata key carrying the governance rule id that
    /// escalated the action.
    pub const ESCALATED_FROM_RULE_KEY: &str = "escalated_from_rule";
    /// Pending-payload metadata key carrying the human-readable escalation
    /// reason.
    pub const ESCALATION_REASON_KEY: &str = "escalation_reason";

    /// One detached approval signature presented by an approver.
    #[derive(Debug, Clone)]
    pub struct SignedApproval {
        /// Base64 (standard or url-safe-no-pad) Ed25519 public key of the
        /// signer.
        pub signer_pubkey_b64: String,
        /// Base64 (standard or url-safe-no-pad) 64-byte Ed25519 signature over
        /// [`approval_signing_bytes`].
        pub signature_b64: String,
    }

    /// Why a signed-approval quorum verification failed.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum QuorumError {
        /// No approver keys are enrolled — the gate can never be satisfied.
        NoEnrolledApprovers,
        /// No signatures were presented.
        NoSignatures,
        /// A presented public key or signature was not valid base64 / had the
        /// wrong byte length.
        BadEncoding(String),
        /// A signature did not verify against its presented public key.
        Forged(String),
        /// A signer's key is not in the enrolled approver set.
        Unenrolled(String),
        /// The distinct valid enrolled signer count did not reach `threshold`.
        ThresholdNotMet { distinct: usize, threshold: usize },
    }

    impl std::fmt::Display for QuorumError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NoEnrolledApprovers => write!(f, "no approver keys are enrolled"),
                Self::NoSignatures => write!(f, "no approver signatures presented"),
                Self::BadEncoding(s) => write!(f, "un-decodable approval material: {s}"),
                Self::Forged(pk) => write!(f, "forged approval signature for key {pk}"),
                Self::Unenrolled(pk) => write!(f, "approver key {pk} is not enrolled"),
                Self::ThresholdNotMet {
                    distinct,
                    threshold,
                } => write!(
                    f,
                    "signed approval quorum not met: {distinct} of {threshold} distinct signers"
                ),
            }
        }
    }

    impl std::error::Error for QuorumError {}

    /// A met quorum: the distinct enrolled signer keys that satisfied it.
    #[derive(Debug, Clone)]
    pub struct QuorumMet {
        /// The threshold that was in force.
        pub threshold: usize,
        /// The number of distinct valid enrolled signers (>= `threshold`).
        pub distinct_signers: usize,
        /// Base64 (standard) of each distinct signer that counted, sorted.
        pub signer_pubkeys_b64: Vec<String>,
    }

    /// The canonical, domain-separated bytes an approver signs to authorize a
    /// decision on `pending_id`. Both the signer (offline) and the verifier
    /// reconstruct these identically.
    #[must_use]
    pub fn approval_signing_bytes(pending_id: &str, decision: super::Decision) -> Vec<u8> {
        let decision_tag: &[u8] = match decision {
            super::Decision::Approve => b"approve",
            super::Decision::Deny => b"deny",
        };
        let mut out =
            Vec::with_capacity(APPROVAL_DOMAIN.len() + pending_id.len() + decision_tag.len() + 2);
        out.extend_from_slice(APPROVAL_DOMAIN);
        out.push(0);
        out.extend_from_slice(pending_id.as_bytes());
        out.push(0);
        out.extend_from_slice(decision_tag);
        out
    }

    fn decode_b64(s: &str) -> Option<Vec<u8>> {
        let t = s.trim();
        base64::engine::general_purpose::STANDARD
            .decode(t)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(t))
            .ok()
    }

    fn verifying_key_from_b64(s: &str) -> Option<VerifyingKey> {
        let bytes = decode_b64(s)?;
        let arr: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = bytes.as_slice().try_into().ok()?;
        VerifyingKey::from_bytes(&arr).ok()
    }

    fn signature_from_b64(s: &str) -> Option<Signature> {
        let bytes = decode_b64(s)?;
        let arr: [u8; ed25519_dalek::SIGNATURE_LENGTH] = bytes.as_slice().try_into().ok()?;
        Some(Signature::from_bytes(&arr))
    }

    fn pk_b64(pk: &VerifyingKey) -> String {
        base64::engine::general_purpose::STANDARD.encode(pk.to_bytes())
    }

    /// Resolve the enrolled approver key set: the governance operator key
    /// (`AI_MEMORY_OPERATOR_PUBKEY` / on-disk `operator.key.pub`) plus every
    /// key in `AI_MEMORY_APPROVER_PUBKEYS`. Duplicates collapse.
    #[must_use]
    pub fn enrolled_approver_keys() -> Vec<VerifyingKey> {
        let mut keys: Vec<VerifyingKey> = Vec::new();
        let mut seen: HashSet<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]> = HashSet::new();
        // Operator-key custody — always enrolled when resolvable.
        if let Some(op) = crate::governance::rules_store::resolve_operator_pubkey()
            && seen.insert(op.to_bytes())
        {
            keys.push(op);
        }
        if let Ok(v) = std::env::var(APPROVER_PUBKEYS_ENV) {
            for tok in v.split(',') {
                let tok = tok.trim();
                if tok.is_empty() {
                    continue;
                }
                match verifying_key_from_b64(tok) {
                    Some(pk) => {
                        if seen.insert(pk.to_bytes()) {
                            keys.push(pk);
                        }
                    }
                    None => tracing::warn!(
                        target: "approvals.signed",
                        "ignoring un-decodable enrolled approver pubkey in {APPROVER_PUBKEYS_ENV}"
                    ),
                }
            }
        }
        keys
    }

    /// Resolve the m-of-n threshold from `AI_MEMORY_APPROVAL_THRESHOLD`
    /// (default 1, clamped to at least 1).
    #[must_use]
    pub fn approval_threshold() -> usize {
        std::env::var(APPROVAL_THRESHOLD_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map_or(1, |n| n.max(1))
    }

    /// Verify an m-of-n signed-approval quorum over `(pending_id, decision)`.
    ///
    /// Each presented signature is verified with `verify_strict` against its
    /// presented public key, AND that key must be a member of `enrolled`.
    /// Distinct valid enrolled signers are counted (a duplicated signer key
    /// collapses to one). The quorum is met when the distinct count reaches
    /// `threshold`.
    ///
    /// # Errors
    ///
    /// Returns the first failing [`QuorumError`]: an empty enrolled set
    /// ([`QuorumError::NoEnrolledApprovers`]), no presented signatures
    /// ([`QuorumError::NoSignatures`]), un-decodable material
    /// ([`QuorumError::BadEncoding`]), an unenrolled signer
    /// ([`QuorumError::Unenrolled`]), a forged signature
    /// ([`QuorumError::Forged`]), or an unmet threshold
    /// ([`QuorumError::ThresholdNotMet`]).
    pub fn verify_quorum(
        pending_id: &str,
        decision: super::Decision,
        presented: &[SignedApproval],
        enrolled: &[VerifyingKey],
        threshold: usize,
    ) -> Result<QuorumMet, QuorumError> {
        if enrolled.is_empty() {
            return Err(QuorumError::NoEnrolledApprovers);
        }
        if presented.is_empty() {
            return Err(QuorumError::NoSignatures);
        }
        let msg = approval_signing_bytes(pending_id, decision);
        let enrolled_set: HashSet<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]> =
            enrolled.iter().map(VerifyingKey::to_bytes).collect();
        let mut distinct: BTreeSet<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]> = BTreeSet::new();
        for sa in presented {
            let pk = verifying_key_from_b64(&sa.signer_pubkey_b64)
                .ok_or_else(|| QuorumError::BadEncoding(sa.signer_pubkey_b64.clone()))?;
            let sig = signature_from_b64(&sa.signature_b64)
                .ok_or_else(|| QuorumError::BadEncoding(sa.signature_b64.clone()))?;
            // Enrollment gate BEFORE signature verify so an unenrolled key is
            // reported as unenrolled (not conflated with a forgery).
            if !enrolled_set.contains(&pk.to_bytes()) {
                return Err(QuorumError::Unenrolled(pk_b64(&pk)));
            }
            pk.verify_strict(&msg, &sig)
                .map_err(|_| QuorumError::Forged(pk_b64(&pk)))?;
            distinct.insert(pk.to_bytes());
        }
        if distinct.len() < threshold {
            return Err(QuorumError::ThresholdNotMet {
                distinct: distinct.len(),
                threshold,
            });
        }
        let signer_pubkeys_b64 = distinct
            .iter()
            .map(|b| base64::engine::general_purpose::STANDARD.encode(b))
            .collect();
        Ok(QuorumMet {
            threshold,
            distinct_signers: distinct.len(),
            signer_pubkeys_b64,
        })
    }

    /// [`verify_quorum`] with the enrolled set + threshold resolved from the
    /// environment ([`enrolled_approver_keys`] + [`approval_threshold`]).
    ///
    /// # Errors
    ///
    /// Propagates [`verify_quorum`]'s [`QuorumError`].
    pub fn verify_quorum_from_env(
        pending_id: &str,
        decision: super::Decision,
        presented: &[SignedApproval],
    ) -> Result<QuorumMet, QuorumError> {
        verify_quorum(
            pending_id,
            decision,
            presented,
            &enrolled_approver_keys(),
            approval_threshold(),
        )
    }

    /// Whether a pending action's payload was routed from a typed escalation
    /// and therefore requires a signed approval.
    #[must_use]
    pub fn pending_requires_signed_approval(payload: &serde_json::Value) -> bool {
        payload
            .get(REQUIRES_SIGNED_APPROVAL_KEY)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }

    /// Route a typed governance
    /// [`Decision::Escalate`](crate::governance::agent_action::Decision::Escalate)
    /// to the approval gate: queue a `pending_actions` row whose payload is
    /// stamped [`REQUIRES_SIGNED_APPROVAL_KEY`] so the escalated op cannot
    /// proceed until a signed (human-key / m-of-n) approval quorum is met.
    ///
    /// The escalation `rule_id` + `reason` are folded into the pending payload
    /// so an operator inspecting the queue sees WHY the op was escalated.
    /// Returns the new pending action id.
    ///
    /// # Errors
    ///
    /// Propagates the storage error from queueing the pending action.
    pub fn route_escalation_to_approval_gate(
        conn: &rusqlite::Connection,
        action: crate::models::GovernedAction,
        namespace: &str,
        memory_id: Option<&str>,
        requested_by: &str,
        payload: &serde_json::Value,
        rule_id: &str,
        reason: &str,
    ) -> anyhow::Result<String> {
        // Fold the escalation provenance + the signed-approval requirement into
        // the pending payload. A non-object payload is wrapped so the metadata
        // keys always have an object to live on.
        let mut enriched = if payload.is_object() {
            payload.clone()
        } else {
            serde_json::json!({ "payload": payload.clone() })
        };
        if let Some(obj) = enriched.as_object_mut() {
            obj.insert(
                REQUIRES_SIGNED_APPROVAL_KEY.to_string(),
                serde_json::Value::Bool(true),
            );
            obj.insert(
                ESCALATED_FROM_RULE_KEY.to_string(),
                serde_json::Value::String(rule_id.to_string()),
            );
            obj.insert(
                ESCALATION_REASON_KEY.to_string(),
                serde_json::Value::String(reason.to_string()),
            );
        }
        crate::storage::queue_pending_action(
            conn,
            action,
            namespace,
            memory_id,
            requested_by,
            &enriched,
        )
    }

    /// Emit a signed, chained `approval_quorum_met` event into the audit chain
    /// (`signed_events`) recording the distinct approver signers that satisfied
    /// the m-of-n gate. The chaining + per-row signature come from the audit
    /// subsystem (per-row signed only when a daemon audit key is enrolled — the
    /// same posture as every other audit row); the operator approval
    /// SIGNATURES captured in the payload are the cryptographic anchor.
    pub fn record_quorum_event(pending_id: &str, decision: super::Decision, quorum: &QuorumMet) {
        let decision_label = match decision {
            super::Decision::Approve => "approve",
            super::Decision::Deny => "deny",
        };
        crate::governance::audit::record_decision(
            "operator",
            decision_label,
            "approval_quorum_met",
            "",
            serde_json::json!({
                "pending_id": pending_id,
                "threshold": quorum.threshold,
                "distinct_signers": quorum.distinct_signers,
                "signer_pubkeys": quorum.signer_pubkeys_b64,
            }),
        );
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ed25519_dalek::{Signer, SigningKey};

        /// Deterministic, rng-free keypair from a 32-byte seed. Distinct seeds
        /// within a test yield distinct keys; no `rand` dependency needed.
        fn kp(seed: u8) -> SigningKey {
            SigningKey::from_bytes(&[seed; 32])
        }
        fn pk_str(sk: &SigningKey) -> String {
            base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes())
        }
        fn sign(sk: &SigningKey, pending_id: &str) -> SignedApproval {
            let msg = approval_signing_bytes(pending_id, super::super::Decision::Approve);
            SignedApproval {
                signer_pubkey_b64: pk_str(sk),
                signature_b64: base64::engine::general_purpose::STANDARD
                    .encode(sk.sign(&msg).to_bytes()),
            }
        }

        #[test]
        fn human_key_approval_accepted() {
            let op = kp(1);
            let enrolled = vec![op.verifying_key()];
            let sa = sign(&op, "pa-accept");
            let met = verify_quorum(
                "pa-accept",
                super::super::Decision::Approve,
                &[sa],
                &enrolled,
                1,
            )
            .expect("quorum met");
            assert_eq!(met.distinct_signers, 1);
        }

        #[test]
        fn forged_signature_rejected() {
            let op = kp(1);
            let enrolled = vec![op.verifying_key()];
            let mut sa = sign(&op, "pa-forge");
            // Replace the signature with the operator key's signature over
            // DIFFERENT bytes: valid length + enrolled signer, but wrong message.
            let msg = approval_signing_bytes("pa-DIFFERENT", super::super::Decision::Approve);
            sa.signature_b64 =
                base64::engine::general_purpose::STANDARD.encode(op.sign(&msg).to_bytes());
            let err = verify_quorum(
                "pa-forge",
                super::super::Decision::Approve,
                &[sa],
                &enrolled,
                1,
            )
            .unwrap_err();
            assert!(matches!(err, QuorumError::Forged(_)), "got {err:?}");
        }

        #[test]
        fn unenrolled_signer_rejected() {
            let op = kp(1);
            let stranger = kp(2);
            let enrolled = vec![op.verifying_key()];
            let sa = sign(&stranger, "pa-unenrolled");
            let err = verify_quorum(
                "pa-unenrolled",
                super::super::Decision::Approve,
                &[sa],
                &enrolled,
                1,
            )
            .unwrap_err();
            assert!(matches!(err, QuorumError::Unenrolled(_)), "got {err:?}");
        }

        #[test]
        fn m_of_n_threshold_semantics() {
            let a = kp(1);
            let b = kp(2);
            let c = kp(3);
            let enrolled = vec![a.verifying_key(), b.verifying_key(), c.verifying_key()];
            let pid = "pa-mofn";
            // M-1 (1 of 2) stays pending.
            let err = verify_quorum(
                pid,
                super::super::Decision::Approve,
                &[sign(&a, pid)],
                &enrolled,
                2,
            )
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    QuorumError::ThresholdNotMet {
                        distinct: 1,
                        threshold: 2
                    }
                ),
                "got {err:?}"
            );
            // M (2 of 2) proceeds.
            let met = verify_quorum(
                pid,
                super::super::Decision::Approve,
                &[sign(&a, pid), sign(&b, pid)],
                &enrolled,
                2,
            )
            .expect("quorum met");
            assert_eq!(met.distinct_signers, 2);
            // Duplicate signer is not double-counted: two sigs from `a` = 1 distinct.
            let err = verify_quorum(
                pid,
                super::super::Decision::Approve,
                &[sign(&a, pid), sign(&a, pid)],
                &enrolled,
                2,
            )
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    QuorumError::ThresholdNotMet {
                        distinct: 1,
                        threshold: 2
                    }
                ),
                "duplicate signer must not double-count: {err:?}"
            );
        }

        #[test]
        fn empty_inputs_rejected() {
            let op = kp(1);
            let enrolled = vec![op.verifying_key()];
            assert!(matches!(
                verify_quorum("pa", super::super::Decision::Approve, &[], &enrolled, 1)
                    .unwrap_err(),
                QuorumError::NoSignatures
            ));
            assert!(matches!(
                verify_quorum(
                    "pa",
                    super::super::Decision::Approve,
                    &[sign(&op, "pa")],
                    &[],
                    1
                )
                .unwrap_err(),
                QuorumError::NoEnrolledApprovers
            ));
        }

        #[test]
        fn escalation_stamps_signed_requirement() {
            let payload = serde_json::json!({ "k": "v" });
            let mut enriched = payload.clone();
            // Mirror route_escalation_to_approval_gate's payload enrichment.
            if let Some(obj) = enriched.as_object_mut() {
                obj.insert(
                    REQUIRES_SIGNED_APPROVAL_KEY.to_string(),
                    serde_json::Value::Bool(true),
                );
            }
            assert!(pending_requires_signed_approval(&enriched));
            assert!(!pending_requires_signed_approval(&payload));
        }
    }
}
