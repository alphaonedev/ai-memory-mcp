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

/// v1.0.0 #3448 — what the PURE approver-eligibility rules decided, before
/// any agent-registry I/O.
///
/// Split out of #3388's `crate::storage::evaluate_approver_eligibility` so the
/// SQLite substrate and the PostgreSQL adapter share ONE statement of the
/// rules instead of two hand-maintained copies (the #2538 trap: postgres does
/// not see `SqliteStore`'s override, so a fix landed on one side alone ships
/// half-closed). The registry lookup is deliberately NOT performed here —
/// each backend does its own (sync `rusqlite` vs `async sqlx`), and keeping it
/// out preserves the pre-existing LAZINESS: an arm that refuses on identity
/// alone never touches the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproverEligibilityStep {
    /// Eligible outright; no registry lookup required.
    Eligible,
    /// Refused outright; no registry lookup required.
    Refused(String),
    /// Eligible IFF the decider is a REGISTERED agent. When it is not, the
    /// caller must refuse with `refusal` (already rendered for the arm that
    /// produced it, so the wire text stays byte-identical per arm).
    RequiresRegisteredAgent {
        /// The refusal to return when the registry lookup says "no".
        refusal: String,
    },
}

/// v1.0.0 #3448 — the ONE statement of the approver-eligibility rules, shared
/// by every backend and every decision (approve AND reject).
///
/// `enforce_identity_gate` is the surface posture: the multi-tenant HTTP /
/// PostgreSQL surfaces pass `true` unconditionally (#1793 / #2538 — per-request
/// `X-Agent-Id` principals, no single-operator self-lock to avoid), while the
/// single-operator MCP/CLI surfaces pass
/// `crate::storage::ApproveSurface::LocalOperator`'s
/// `AI_MEMORY_AGENT_ID` opt-in (#1796). The `Consensus` registry requirement
/// (#216) is outside that posture and applies unconditionally.
///
/// Arms, in order, with the historical per-arm wire text preserved:
/// - `Human` (the default when a namespace pins no policy): under the gate,
///   the requester may not decide their own action, and the decider must be a
///   registered agent (#1787).
/// - `Agent(required)`: the named-approver equality is UNCONDITIONAL, then the
///   same self / registered pair under the gate (#2538).
/// - `Consensus(_)`: the decider must be a registered agent, unconditionally
///   (#216). This arm carries no self-refusal on the approve side, and that is
///   preserved rather than "improved" — eligibility PARITY across decisions
///   and backends is the contract; changing a rule here changes it everywhere,
///   which is the point.
#[must_use]
pub fn approver_eligibility_step(
    approver: &crate::models::ApproverType,
    requested_by: &str,
    approver_agent_id: &str,
    enforce_identity_gate: bool,
) -> ApproverEligibilityStep {
    use crate::models::ApproverType;
    match approver {
        ApproverType::Human => {
            if enforce_identity_gate {
                if approver_agent_id == requested_by {
                    return ApproverEligibilityStep::Refused(
                        crate::errors::msg::SELF_APPROVAL_REFUSED.to_string(),
                    );
                }
                return ApproverEligibilityStep::RequiresRegisteredAgent {
                    refusal: format!(
                        "Human approver '{approver_agent_id}' is not a registered agent"
                    ),
                };
            }
            ApproverEligibilityStep::Eligible
        }
        ApproverType::Agent(required) => {
            if approver_agent_id != required {
                return ApproverEligibilityStep::Refused(format!(
                    "designated approver is '{required}'; got '{approver_agent_id}'"
                ));
            }
            if enforce_identity_gate {
                if approver_agent_id == requested_by {
                    return ApproverEligibilityStep::Refused(
                        crate::errors::msg::SELF_APPROVAL_REFUSED.to_string(),
                    );
                }
                return ApproverEligibilityStep::RequiresRegisteredAgent {
                    refusal: format!(
                        "designated approver '{approver_agent_id}' is not a registered agent"
                    ),
                };
            }
            ApproverEligibilityStep::Eligible
        }
        ApproverType::Consensus(_) => ApproverEligibilityStep::RequiresRegisteredAgent {
            refusal: format!("consensus voter '{approver_agent_id}' is not a registered agent"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =================================================================
    // v1.0.0 #3448 — the shared approver-eligibility RULES.
    //
    // These pin the rules ONCE, independent of any backend: the SQLite
    // substrate (`storage::evaluate_approver_eligibility`) and the
    // PostgreSQL adapter (`PostgresStore::approver_refusal_reason`) are
    // both thin I/O bindings over `approver_eligibility_step`, so a rule
    // change that breaks one backend breaks these first. The per-backend
    // suites then prove each binding actually calls them.
    // =================================================================

    use crate::models::ApproverType;

    /// Human arm, gate OFF (the single-operator trust-all default): the lone
    /// operator decides their own queued action, with no registry lookup.
    #[test]
    fn human_arm_unarmed_is_eligible_3448() {
        assert_eq!(
            approver_eligibility_step(&ApproverType::Human, "ai:alice", "ai:alice", false),
            ApproverEligibilityStep::Eligible
        );
    }

    /// Human arm, gate ON: the requester may not decide their own action, and
    /// the refusal short-circuits BEFORE any registry lookup is requested.
    #[test]
    fn human_arm_armed_refuses_self_3448() {
        let step = approver_eligibility_step(&ApproverType::Human, "ai:alice", "ai:alice", true);
        assert_eq!(
            step,
            ApproverEligibilityStep::Refused(crate::errors::msg::SELF_APPROVAL_REFUSED.to_string())
        );
    }

    /// Human arm, gate ON, distinct decider: eligible ONLY IF registered.
    #[test]
    fn human_arm_armed_requires_registration_3448() {
        let step = approver_eligibility_step(&ApproverType::Human, "ai:alice", "ai:bob", true);
        match step {
            ApproverEligibilityStep::RequiresRegisteredAgent { refusal } => {
                assert!(
                    refusal.contains("Human approver 'ai:bob'"),
                    "got: {refusal}"
                );
                assert!(
                    refusal.contains("is not a registered agent"),
                    "got: {refusal}"
                );
            }
            other => panic!("expected a registration requirement, got {other:?}"),
        }
    }

    /// Agent(required) arm: the named-approver equality is UNCONDITIONAL — it
    /// refuses a non-designated decider even with the gate OFF.
    #[test]
    fn agent_arm_named_equality_is_unconditional_3448() {
        let approver = ApproverType::Agent("ai:carol".to_string());
        for armed in [false, true] {
            match approver_eligibility_step(&approver, "ai:alice", "ai:bob", armed) {
                ApproverEligibilityStep::Refused(reason) => assert!(
                    reason.contains("designated approver is 'ai:carol'; got 'ai:bob'"),
                    "armed={armed} got: {reason}"
                ),
                other => panic!("armed={armed}: expected a refusal, got {other:?}"),
            }
        }
    }

    /// Agent(required) arm, gate ON, decider IS the designated approver AND
    /// the requester: separation of duties still refuses (#2538).
    #[test]
    fn agent_arm_armed_refuses_designated_self_3448() {
        let approver = ApproverType::Agent("ai:alice".to_string());
        assert_eq!(
            approver_eligibility_step(&approver, "ai:alice", "ai:alice", true),
            ApproverEligibilityStep::Refused(crate::errors::msg::SELF_APPROVAL_REFUSED.to_string())
        );
    }

    /// Consensus arm: the registered-voter requirement is UNCONDITIONAL
    /// (#216) — it does not depend on the surface posture, and this arm
    /// carries no self-refusal, matching the approve side exactly.
    #[test]
    fn consensus_arm_requires_registration_unconditionally_3448() {
        for armed in [false, true] {
            match approver_eligibility_step(
                &ApproverType::Consensus(2),
                "ai:alice",
                "ai:alice",
                armed,
            ) {
                ApproverEligibilityStep::RequiresRegisteredAgent { refusal } => assert!(
                    refusal.contains("consensus voter 'ai:alice' is not a registered agent"),
                    "armed={armed} got: {refusal}"
                ),
                other => {
                    panic!("armed={armed}: expected a registration requirement, got {other:?}")
                }
            }
        }
    }

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

    /// #2355 — the shared `reason` text a signed-approval funnel returns when
    /// the m-of-n quorum has been partially met but not yet reached. One
    /// definition, referenced by every approve funnel (MCP + 4 HTTP + CLI) so
    /// the wire message never drifts between surfaces.
    pub const SIGNED_QUORUM_NOT_YET_MET: &str = "signed approval quorum not yet met";
    /// #2355 — response field name: the distinct valid enrolled signer count
    /// accumulated so far toward the m-of-n threshold.
    pub const SIGNED_VOTES_FIELD: &str = "signed_votes";
    /// #2355 — response field name: the m-of-n signed-approval threshold.
    pub const SIGNED_QUORUM_FIELD: &str = "signed_quorum";

    /// #2355 — the shared refusal message a signed-approval funnel returns when
    /// the gate fails closed (missing-when-required / forged / unenrolled /
    /// un-decodable). A helper (not a `const`) because the `QuorumError` detail
    /// is interpolated; every funnel (MCP tool error, HTTP 403 body, CLI
    /// `bail!`) formats it ONE way here.
    #[must_use]
    pub fn signed_approval_rejected(e: &QuorumError) -> String {
        format!("signed approval rejected: {e}")
    }

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

    /// Parse presented approver signatures from an `approvals` JSON array
    /// (`[{"pubkey":"<b64>","signature":"<b64>"}, …]`). Shared by every approve
    /// funnel — MCP (`params["approvals"]`) and the HTTP branches (request-body
    /// `approvals`) — so the wire contract is one place. Non-array / malformed
    /// entries yield an empty slice (the gate then fails closed when signatures
    /// are REQUIRED).
    #[must_use]
    pub fn parse_presented_approvals(approvals: &serde_json::Value) -> Vec<SignedApproval> {
        let Some(arr) = approvals.as_array() else {
            return Vec::new();
        };
        arr.iter()
            .filter_map(|entry| {
                let pubkey = entry.get("pubkey").and_then(serde_json::Value::as_str)?;
                let signature = entry.get("signature").and_then(serde_json::Value::as_str)?;
                Some(SignedApproval {
                    signer_pubkey_b64: pubkey.to_string(),
                    signature_b64: signature.to_string(),
                })
            })
            .collect()
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

    /// R40 (#2991/#2355) — the PURE verdict a signed-approval quorum
    /// evaluation yields, returned by [`evaluate_signed_approval_gate`]. It is
    /// the single chokepoint every approve funnel (MCP + the four HTTP
    /// branches, both backends) consults so the gate cannot be enforced on one
    /// surface and bypassed on another. The verdict carries NO side effects —
    /// the caller finalizes (`approve_with_approver_type` /
    /// `governance_approve_with_consensus`) and, on [`Self::Approved`], wraps
    /// the downstream execute in a single-use [`register_execution_exemption`].
    #[derive(Debug)]
    pub enum GateVerdict {
        /// Signed approval was NOT required (no stored escalation flag, no
        /// namespace-policy escalation) and no approver signatures were
        /// presented. The caller proceeds with the ordinary approver-type
        /// finalizer and issues NO execution exemption.
        NotRequired,
        /// The m-of-n signed-approval quorum was MET. The caller MUST bind an
        /// execution exemption (`register_execution_exemption(pending_id,
        /// cid)`) around the downstream `execute_pending_action` so the
        /// already-approved write is not re-escalated by the L1-6 producer
        /// (the exemption is CID-bound + single-use — never namespace-scoped).
        Approved(QuorumMet),
        /// Signatures accepted so far but the distinct-signer count has not
        /// reached the threshold — respond `{approved:false,status:"pending"}`.
        Pending { distinct: usize, threshold: usize },
        /// Fail-closed refusal: signed approval required but missing, or a
        /// presented signature was forged / unenrolled / un-decodable. Maps to
        /// HTTP `403` (MCP: a tool error).
        Refused(QuorumError),
    }

    /// R40 (#2991/#2355) — THE single pure chokepoint. Given the SERVER-SIDE
    /// stored pending payload, the target `pending_id`+`decision`, the presented
    /// approver signatures, and the caller-resolved namespace-policy term,
    /// return a [`GateVerdict`]. No DB reads, no writes, no audit emit — purely
    /// `inputs -> verdict`, so the four HTTP funnels and the MCP funnel share
    /// byte-identical enforcement.
    ///
    /// # Requirement predicate (the anti-bypass core)
    ///
    /// The gate engages when signed approval is REQUIRED **or** any signature
    /// is presented. "Required" is the server-side OR of:
    /// 1. the STORED escalation flag on the pending payload
    ///    ([`pending_requires_signed_approval`] — read from the DB snapshot, not
    ///    a caller-supplied request field), and
    /// 2. `namespace_requires_signed` — the caller re-derives this from the
    ///    live governance rule engine ([`namespace_requires_signed_approval`])
    ///    so a payload whose flag was stripped is still gated.
    ///
    /// Never trusting term (1)'s `unwrap_or(false)` ALONE is the fix for the
    /// #2355 bypass: a pending that SHOULD require signing but lost its flag is
    /// still convicted by term (2).
    #[must_use]
    pub fn evaluate_signed_approval_gate(
        stored_payload: &serde_json::Value,
        pending_id: &str,
        decision: super::Decision,
        presented: &[SignedApproval],
        namespace_requires_signed: bool,
    ) -> GateVerdict {
        let required =
            pending_requires_signed_approval(stored_payload) || namespace_requires_signed;
        // Back-compat: an ordinary (non-escalated) pending with no signatures
        // skips the gate entirely — the ordinary approver-type path decides.
        if !required && presented.is_empty() {
            return GateVerdict::NotRequired;
        }
        match verify_quorum_from_env(pending_id, decision, presented) {
            Ok(quorum) => GateVerdict::Approved(quorum),
            Err(QuorumError::ThresholdNotMet {
                distinct,
                threshold,
            }) => GateVerdict::Pending {
                distinct,
                threshold,
            },
            Err(e) => GateVerdict::Refused(e),
        }
    }

    /// R40 (#2355) — term (2) of the requirement predicate: re-derive, from the
    /// LIVE governance rule engine, whether a `memory_write` by `requested_by`
    /// into `namespace` escalates (and therefore requires a signed approval).
    ///
    /// This defends the gate against a stored payload whose
    /// [`REQUIRES_SIGNED_APPROVAL_KEY`] flag is absent/false (the strippable
    /// term (1)): if the namespace's resolved rules STILL escalate the write,
    /// the pending is gated regardless of the flag.
    ///
    /// Fails SAFE toward term (1): a rule-consultation error resolves to
    /// `false` (the stored server-side flag remains the enforcing gate) and is
    /// logged — the escalated pending always carries the stored flag, so a
    /// transient rule-store error never drops the primary gate, and never
    /// blocks an approve the operator has no signatures to satisfy.
    #[must_use]
    pub fn namespace_requires_signed_approval(
        conn: &rusqlite::Connection,
        requested_by: &str,
        namespace: &str,
    ) -> bool {
        use crate::governance::agent_action::{AgentAction, RuleEngine};
        let action = AgentAction::Custom {
            custom_kind: "memory_write".to_string(),
            payload: serde_json::json!({ "namespace": namespace }),
        };
        // PURE evaluation — `RuleEngine::load_for_action` reads the rule set and
        // `evaluate` matches it in memory. Deliberately NOT
        // `check_agent_action`, whose `emit_check_event` / `emit_forensic_decision`
        // would WRITE a spurious `governance.check` audit row on every approve.
        match RuleEngine::load_for_action(conn, &action) {
            Ok(engine) => engine.evaluate(requested_by, &action).is_escalation(),
            Err(e) => {
                tracing::warn!(
                    target: "approvals.signed",
                    "namespace_requires_signed_approval: rule load failed for \
                     namespace={namespace:?} requested_by={requested_by:?}: {e}; \
                     relying on the stored escalation flag (term 1)"
                );
                false
            }
        }
    }

    /// Process-wide single-use execution-exemption registry (R40 #2991).
    ///
    /// When a signed-approval quorum is met and the approved pending is
    /// replayed via `execute_pending_action`, the `store` write re-enters the
    /// L1-6 producer ([`crate::storage::GOVERNANCE_PRE_WRITE`]), whose rule
    /// STILL escalates — which, without an exemption, would re-queue the
    /// already-approved write forever. The exemption lets that ONE write
    /// through.
    ///
    /// The set holds `cid`s ([`execution_exemption_cid`]) that are content- +
    /// identity-bound (agent_id, namespace, title, kind, content — NOT the
    /// volatile id / timestamps `execute_pending_action` re-stamps). It is
    /// NEVER namespace-scoped and NEVER "any approved store": an exemption
    /// admits only a write whose content hashes to exactly the approved
    /// pending's payload, and is CONSUMED on first match
    /// ([`consume_execution_exemption`]) — closing the CWE-306 replay class the
    /// ballot flagged (residual risk #1).
    static EXECUTION_EXEMPTIONS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, String>>,
    > = std::sync::OnceLock::new();

    fn exemptions() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
        EXECUTION_EXEMPTIONS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
    }

    /// The content- + identity-bound exemption key for a memory about to be
    /// (re-)written. Deliberately EXCLUDES `created_at` (and the id / updated_at
    /// / access_count fields) because [`crate::storage::execute_pending_action`]
    /// re-stamps those on replay — so the key computed at approve time
    /// (over the stored payload) matches the key the L1-6 producer computes
    /// over the re-stamped memory. `content` enters via the SHA-256 digest term
    /// of [`crate::identity::cid::canonical_cid_preimage`], so two writes that
    /// differ in ANY of (agent_id, namespace, title, kind, content) get
    /// distinct keys — an exemption can never leak to a different write.
    #[must_use]
    pub fn execution_exemption_cid(mem: &crate::models::Memory) -> String {
        let agent_id = mem
            .metadata
            .get("agent_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let preimage = crate::identity::cid::canonical_cid_preimage(
            agent_id,
            &mem.namespace,
            &mem.title,
            mem.memory_kind.as_str(),
            // created_at deliberately omitted — see doc above.
            "",
            &mem.content,
        );
        crate::identity::cid::compute_cid(&preimage)
    }

    /// RAII guard that removes the execution exemption it registered when it
    /// drops — guaranteeing SINGLE-USE even if the L1-6 producer never consumed
    /// it (e.g. the replay took a non-`store` arm, or execute errored before
    /// the write). Held across the `execute_pending_action` call and dropped
    /// immediately after.
    #[must_use = "the exemption is removed when this guard drops; hold it across execute_pending_action"]
    pub struct ExemptionGuard {
        cid: String,
    }

    impl Drop for ExemptionGuard {
        fn drop(&mut self) {
            if let Ok(mut g) = exemptions().lock() {
                g.remove(&self.cid);
            }
        }
    }

    /// Register a single-use execution exemption bound to `(pending_id, cid)`.
    /// The returned [`ExemptionGuard`] MUST be held across the downstream
    /// `execute_pending_action` and dropped right after. The `pending_id` is
    /// retained for forensic attribution; the L1-6 producer matches on `cid`.
    #[must_use]
    pub fn register_execution_exemption(pending_id: &str, cid: &str) -> ExemptionGuard {
        if let Ok(mut g) = exemptions().lock() {
            g.insert(cid.to_string(), pending_id.to_string());
        }
        ExemptionGuard {
            cid: cid.to_string(),
        }
    }

    /// Build the single-use [`ExemptionGuard`] a funnel must hold across
    /// `execute_pending_action` after a signed-approval quorum is met. Returns
    /// `None` when the stored payload is not a replayable `store` memory (a
    /// non-`store` action's replay never re-enters the L1-6 `store` producer,
    /// so it needs no exemption). The guard is CID-bound to exactly this
    /// pending's content, so it can admit only the approved write.
    #[must_use]
    pub fn exemption_guard_for_pending(
        pending_id: &str,
        stored_payload: &serde_json::Value,
    ) -> Option<ExemptionGuard> {
        let mem: crate::models::Memory = serde_json::from_value(stored_payload.clone()).ok()?;
        let cid = execution_exemption_cid(&mem);
        Some(register_execution_exemption(pending_id, &cid))
    }

    /// Consume the execution exemption for `cid`: returns `true` (and REMOVES
    /// the entry — single-use) iff a matching exemption was registered. Called
    /// by the L1-6 producer's `Escalate` arm to let an already-approved,
    /// quorum-met write replay through exactly once. A write whose `cid` is not
    /// registered returns `false` and is escalated normally — this
    /// discrimination is the load-bearing control proven by
    /// `scripts/check-cert-removal-proof.sh` (mutating it to `return true`
    /// re-opens the replay-bypass class and reds the negative-control test).
    #[must_use]
    pub fn consume_execution_exemption(cid: &str) -> bool {
        match exemptions().lock() {
            Ok(mut g) => g.remove(cid).is_some(),
            // Fail-closed: a poisoned registry never grants an exemption.
            Err(_) => false,
        }
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

        // --- R40 (#2991/#2355) chokepoint helper ---

        // These verdict-mapping tests are ENV-INDEPENDENT: they assert the
        // variant-agnostic `Refused(_)` / `NotRequired`, so whether or not a
        // concurrent `--lib` test has enrolled approver keys, the outcome is the
        // same (a required-but-unsatisfied gate is `Refused` either as
        // `NoSignatures` or `NoEnrolledApprovers`). The met-quorum / pending /
        // forged mappings — which need enrolled keys — are proven end-to-end by
        // the integration funnel suite (`tests/r40_approval_chokepoint.rs`),
        // each in its OWN process (no libtest env bleed).

        #[test]
        fn gate_not_required_when_no_flag_no_sigs() {
            let payload = serde_json::json!({ "k": "v" });
            assert!(matches!(
                evaluate_signed_approval_gate(
                    &payload,
                    "pa-x",
                    super::super::Decision::Approve,
                    &[],
                    false,
                ),
                GateVerdict::NotRequired
            ));
        }

        #[test]
        fn gate_fails_closed_when_stored_flag_requires_but_no_sigs() {
            let _ = crate::identity::test_key_dir::install();
            let payload = serde_json::json!({ REQUIRES_SIGNED_APPROVAL_KEY: true });
            let v = evaluate_signed_approval_gate(
                &payload,
                "pa-req",
                super::super::Decision::Approve,
                &[],
                false,
            );
            assert!(
                matches!(v, GateVerdict::Refused(_)),
                "missing-when-required (stored flag) must fail closed: {v:?}"
            );
        }

        #[test]
        fn gate_fails_closed_when_namespace_term_requires_but_no_sigs() {
            let _ = crate::identity::test_key_dir::install();
            // No stored flag on the payload — term (2) alone engages the gate.
            let payload = serde_json::json!({ "k": "v" });
            let v = evaluate_signed_approval_gate(
                &payload,
                "pa-ns",
                super::super::Decision::Approve,
                &[],
                true,
            );
            assert!(
                matches!(v, GateVerdict::Refused(_)),
                "namespace-policy term must engage the gate without the stored flag: {v:?}"
            );
        }

        #[test]
        fn gate_engages_when_sig_presented_even_if_not_required() {
            let _ = crate::identity::test_key_dir::install();
            // No requirement, but a signature IS presented → the gate runs
            // (never silently ignored) and fails closed absent a met quorum.
            let stranger = kp(2);
            let payload = serde_json::json!({ "k": "v" });
            let v = evaluate_signed_approval_gate(
                &payload,
                "pa-str",
                super::super::Decision::Approve,
                &[sign(&stranger, "pa-str")],
                false,
            );
            assert!(
                matches!(v, GateVerdict::Refused(_)),
                "a presented signature must engage the gate fail-closed: {v:?}"
            );
        }

        // --- R40 (#2991) single-use execution exemption ---

        fn mem_fixture(ns: &str, content: &str) -> crate::models::Memory {
            crate::models::Memory {
                namespace: ns.to_string(),
                title: "t".to_string(),
                content: content.to_string(),
                metadata: serde_json::json!({ "agent_id": "ai:alice" }),
                ..crate::models::Memory::default()
            }
        }

        #[test]
        fn exemption_cid_stable_across_execute_restamp() {
            let mut a = mem_fixture("proj", "the body");
            a.id = "id-A".to_string();
            a.created_at = "2026-01-01T00:00:00Z".to_string();
            a.updated_at = "2026-01-01T00:00:00Z".to_string();
            a.access_count = 0;
            let cid_before = execution_exemption_cid(&a);
            // Mimic execute_pending_action's replay re-stamp.
            a.id = "id-B".to_string();
            a.created_at = "2026-09-09T09:09:09Z".to_string();
            a.updated_at = "2026-09-09T09:09:09Z".to_string();
            a.access_count = 42;
            assert_eq!(
                cid_before,
                execution_exemption_cid(&a),
                "re-stamp must not change the cid"
            );
        }

        #[test]
        fn exemption_cid_differs_on_different_content() {
            let x = mem_fixture("proj", "alpha");
            let y = mem_fixture("proj", "beta");
            assert_ne!(execution_exemption_cid(&x), execution_exemption_cid(&y));
        }

        #[test]
        fn exemption_is_single_use_and_discriminates() {
            let m = mem_fixture("exempt-ns", "unique-content-xyz");
            let cid = execution_exemption_cid(&m);
            // Unregistered → not exempt.
            assert!(!consume_execution_exemption(&cid));
            let guard = register_execution_exemption("pa-1", &cid);
            // A DIFFERENT cid is never exempt.
            assert!(!consume_execution_exemption("b3:different"));
            // Registered cid consumes exactly once.
            assert!(consume_execution_exemption(&cid));
            assert!(
                !consume_execution_exemption(&cid),
                "single-use: second consume is denied"
            );
            drop(guard);
        }

        #[test]
        fn exemption_guard_drop_removes_unconsumed() {
            let m = mem_fixture("exempt-ns2", "another-body");
            let cid = execution_exemption_cid(&m);
            {
                let _g = register_execution_exemption("pa-2", &cid);
            } // guard drops here without consume
            assert!(
                !consume_execution_exemption(&cid),
                "an unconsumed exemption must be removed on guard drop"
            );
        }
    }
}
