// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 L1-6 — typed-cognition substrate boundary (Boundary §16.2).
//!
//! Pillar 2 typed-cognition minimum slice: a `Reflection` memory may
//! NOT autonomously `supersede` a `Goal` memory. Boundary §16.2
//! ("no autonomous goal modification") was policy-only across v0.6.x
//! and the pre-fix v0.7.0 cuts; L1-6 makes it substrate-enforced.
//!
//! Two callsites consult [`validate_supersede_kinds`]:
//!   * `mcp::tools::link::handle_link` — the canonical write path for
//!     `relation = "supersedes"` edges.
//!   * `mcp::tools::reflect::handle_reflect` — when the new optional
//!     `supersedes` argument is provided alongside `memory_reflect`.
//!
//! Defence-in-depth: the SAL layer (`storage::create_link_signed`)
//! also calls into this module so a non-MCP caller (HTTP REST,
//! federation `sync_push`) cannot bypass the gate by going around
//! the MCP handler.

use crate::models::MemoryKind;

/// L1-6 governance config — per-namespace knob controlling whether the
/// `Reflection → Goal` supersede refusal is active.
///
/// Default `true` per Boundary §16.2: the substrate refuses
/// `Reflection → Goal` supersedes unless the operator explicitly opts
/// out by setting `namespace.governance.refuse_supersede_goal = false`.
///
/// Even on the opt-out path the substrate emits a high-severity WARN
/// (see [`validate_supersede_kinds`]) so the operator override leaves a
/// loud trace in the daemon log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypedCognitionPolicy {
    /// `true` (default) → refuse `Reflection → Goal` supersede edges.
    /// `false` → allow with a high-severity WARN.
    pub refuse_supersede_goal: bool,
}

impl Default for TypedCognitionPolicy {
    fn default() -> Self {
        Self {
            // Boundary §16.2 default: substrate-enforced refusal.
            refuse_supersede_goal: true,
        }
    }
}

impl TypedCognitionPolicy {
    /// Extract the policy from a namespace standard's
    /// `metadata.governance` blob.  Returns the default policy when
    /// the blob is absent / null / lacks the key.  Operator-side
    /// override only — the structural shape lives in
    /// `governance.refuse_supersede_goal`.
    ///
    /// Mirrors the pattern used by
    /// [`crate::storage::resolve_require_approval_above_depth`]: the
    /// L1-6 field is a free key in the existing JSON blob, not a
    /// required field on [`crate::models::GovernancePolicy`] (adding a
    /// required field would force every `GovernancePolicy { ... }`
    /// literal in the codebase to update — a churn the L1-8 review
    /// already flagged).
    #[must_use]
    pub fn from_metadata(metadata: &serde_json::Value) -> Self {
        let gov = match metadata.get("governance") {
            Some(g) if !g.is_null() => g,
            _ => return Self::default(),
        };
        match gov.get("refuse_supersede_goal").and_then(|v| v.as_bool()) {
            Some(b) => Self {
                refuse_supersede_goal: b,
            },
            None => Self::default(),
        }
    }
}

/// L1-6 substrate refusal outcome.  Returned by
/// [`validate_supersede_kinds`] when a `Reflection → Goal` supersede
/// is denied by Boundary §16.2.
///
/// Callers translate this into:
///   * a `Reflection → Goal supersede refused` error string at the MCP
///     surface (`mcp::tools::link.rs`, `mcp::tools::reflect.rs`);
///   * a `signed_events` row with `event_type =
///     "supersede_goal_refused"` and reason
///     `"reflection memories cannot supersede goal memories"`;
///   * the typed HTTP error
///     [`crate::errors::MemoryError::SupersedesGoalRefused`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupersedesGoalRefusal {
    pub source: String,
    pub target: String,
    pub source_kind: MemoryKind,
    pub target_kind: MemoryKind,
    pub reason: String,
}

impl SupersedesGoalRefusal {
    /// Canonical refusal reason — matches the playbook §2.6 wire shape
    /// so the signed_events audit row reads identically regardless of
    /// which callsite raised it.
    pub const REASON: &'static str = "reflection memories cannot supersede goal memories";

    fn new(source: &str, target: &str, source_kind: MemoryKind, target_kind: MemoryKind) -> Self {
        Self {
            source: source.to_string(),
            target: target.to_string(),
            source_kind,
            target_kind,
            reason: Self::REASON.to_string(),
        }
    }
}

/// L1-6 substrate gate.  Returns `Err(SupersedesGoalRefusal)` when:
///
///   1. `source_kind == Reflection`, AND
///   2. `target_kind == Goal`, AND
///   3. `policy.refuse_supersede_goal == true` (the Boundary §16.2
///      default).
///
/// Returns `Ok(())` in every other case — including the
/// `Observation → Goal` shape, which is intentionally permitted (only
/// reflections are constrained per the playbook §2.6 acceptance
/// criteria).
///
/// When `policy.refuse_supersede_goal == false` (operator opt-out) the
/// function returns `Ok(())` **and** emits a high-severity `tracing::warn!`
/// log line tagged `target = "governance::typed_cognition"` so the
/// override leaves a loud trace.  Callers do not need to repeat the
/// log themselves.
///
/// `source` and `target` carry the memory ids purely for the log /
/// refusal-payload shape; they are not consulted by the kind check
/// itself.
pub fn validate_supersede_kinds(
    source: &str,
    target: &str,
    source_kind: MemoryKind,
    target_kind: MemoryKind,
    policy: TypedCognitionPolicy,
) -> Result<(), SupersedesGoalRefusal> {
    let triggers = source_kind == MemoryKind::Reflection && target_kind == MemoryKind::Goal;

    if !triggers {
        // Out of scope — observation→goal, reflection→observation,
        // anything→anything-non-goal etc.
        return Ok(());
    }

    if policy.refuse_supersede_goal {
        return Err(SupersedesGoalRefusal::new(
            source,
            target,
            source_kind,
            target_kind,
        ));
    }

    // Operator-disabled path: emit a high-severity WARN so the
    // override is visible in the daemon log.  Boundary §16.2 is the
    // substrate-enforced default; an opt-out is a deliberate operator
    // decision that should be auditable in real time.
    tracing::warn!(
        target: "governance::typed_cognition",
        source_id = %source,
        target_id = %target,
        boundary = "§16.2",
        "substrate boundary §16.2 explicitly disabled by operator override \
         (namespace.governance.refuse_supersede_goal = false): \
         reflection→goal supersede ALLOWED with override"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_refuses() {
        let policy = TypedCognitionPolicy::default();
        assert!(policy.refuse_supersede_goal);
    }

    #[test]
    fn reflection_supersedes_goal_is_refused() {
        let policy = TypedCognitionPolicy::default();
        let res = validate_supersede_kinds(
            "src",
            "tgt",
            MemoryKind::Reflection,
            MemoryKind::Goal,
            policy,
        );
        let err = res.expect_err("must refuse");
        assert_eq!(err.source, "src");
        assert_eq!(err.target, "tgt");
        assert_eq!(err.source_kind, MemoryKind::Reflection);
        assert_eq!(err.target_kind, MemoryKind::Goal);
        assert_eq!(err.reason, SupersedesGoalRefusal::REASON);
    }

    #[test]
    fn observation_supersedes_goal_is_allowed() {
        let policy = TypedCognitionPolicy::default();
        let res = validate_supersede_kinds(
            "src",
            "tgt",
            MemoryKind::Observation,
            MemoryKind::Goal,
            policy,
        );
        assert!(res.is_ok(), "only reflection→goal is constrained");
    }

    #[test]
    fn reflection_supersedes_observation_is_allowed() {
        let policy = TypedCognitionPolicy::default();
        let res = validate_supersede_kinds(
            "src",
            "tgt",
            MemoryKind::Reflection,
            MemoryKind::Observation,
            policy,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn reflection_supersedes_goal_with_override_is_allowed() {
        let policy = TypedCognitionPolicy {
            refuse_supersede_goal: false,
        };
        // We can't easily capture the WARN here without a tracing
        // subscriber dependency; the wire-shape contract is the Ok
        // return, not the log line itself.
        let res = validate_supersede_kinds(
            "src",
            "tgt",
            MemoryKind::Reflection,
            MemoryKind::Goal,
            policy,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn policy_from_metadata_default_when_empty() {
        let meta = serde_json::json!({});
        let p = TypedCognitionPolicy::from_metadata(&meta);
        assert!(p.refuse_supersede_goal);
    }

    #[test]
    fn policy_from_metadata_default_when_no_governance() {
        let meta = serde_json::json!({ "agent_id": "test" });
        let p = TypedCognitionPolicy::from_metadata(&meta);
        assert!(p.refuse_supersede_goal);
    }

    #[test]
    fn policy_from_metadata_default_when_governance_null() {
        let meta = serde_json::json!({ "governance": null });
        let p = TypedCognitionPolicy::from_metadata(&meta);
        assert!(p.refuse_supersede_goal);
    }

    #[test]
    fn policy_from_metadata_default_when_field_absent() {
        let meta = serde_json::json!({ "governance": { "write": "any" } });
        let p = TypedCognitionPolicy::from_metadata(&meta);
        assert!(p.refuse_supersede_goal);
    }

    #[test]
    fn policy_from_metadata_picks_up_false() {
        let meta = serde_json::json!({ "governance": { "refuse_supersede_goal": false } });
        let p = TypedCognitionPolicy::from_metadata(&meta);
        assert!(!p.refuse_supersede_goal);
    }

    #[test]
    fn policy_from_metadata_picks_up_true() {
        let meta = serde_json::json!({ "governance": { "refuse_supersede_goal": true } });
        let p = TypedCognitionPolicy::from_metadata(&meta);
        assert!(p.refuse_supersede_goal);
    }

    #[test]
    fn refusal_reason_is_canonical() {
        assert_eq!(
            SupersedesGoalRefusal::REASON,
            "reflection memories cannot supersede goal memories"
        );
    }
}
