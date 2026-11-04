//! #8577 / #8564 — the row-owner rule of an approved `delete` / tier-bump
//! `promote` execute, as a PURE precondition.
//!
//! One implementation of the rule: the SQLite execute arms
//! ([`super::execute_pending_action_gated`] through its owner gate) and the
//! tenant decide entries (which run it BEFORE the approval vote is written,
//! so a refusal leaves the pending row `pending` instead of `approved` with
//! no effect) both call [`check_execute_owner`]. The Postgres twin reuses
//! [`execute_arm_target`] and its own `FOR UPDATE` owner probe, the same gate
//! its `delete` / `update` funnels run.
//!
//! A bypass context (the federated decide path, after its peer-scope check;
//! parity doc `federation_signing_check.rs:86-112`) never reaches this rule:
//! the callers decide on the context they receive.

use super::{ExecuteArm, PendingAction, emit_pending_action_event};
use crate::identity::owner_stamp::{MutationSite, OwnerStamp, funnel};
use crate::models::{Memory, field_names};
use rusqlite::Connection;

/// The audit-chain event type written when the owner precondition refuses
/// (the forensic row; the pending row stays `pending`).
pub const EVENT_REFUSED_OWNER_GATE: &str = "pending_action.refused_owner_gate";

/// Why the row-owner rule refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecuteOwnerRefusal {
    /// The target row carries no owner stamp (`metadata.agent_id`).
    Unstamped,
    /// The target row is stamped with another agent than the requester.
    NotOwner {
        /// The stamped owner, for the structured trace only (never the wire).
        owner: String,
    },
}

impl ExecuteOwnerRefusal {
    /// The wire-safe refusal reason (never names the row owner, #3426).
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Unstamped => crate::identity::owner_stamp::REASON_UNSTAMPED_REFUSED,
            Self::NotOwner { .. } => crate::errors::msg::CALLER_DOES_NOT_OWN_MEMORY,
        }
    }
}

/// The gated verb name and mutation funnel of an execute arm.
#[must_use]
pub fn arm_labels(arm: ExecuteArm) -> (&'static str, &'static str) {
    match arm {
        ExecuteArm::Delete => ("delete", funnel::DELETE),
        ExecuteArm::TierBump => ("update", funnel::UPDATE),
    }
}

/// The execute arm and target memory id of a pending action the owner rule
/// governs: a `delete`, or a `promote` that is a tier bump (a cross-namespace
/// promote carries `to_namespace` and runs its own destination gate).
#[must_use]
pub fn execute_arm_target(pa: &PendingAction) -> Option<(ExecuteArm, &str)> {
    let mid = pa.memory_id.as_deref()?;
    match pa.action_type.as_str() {
        "delete" => Some((ExecuteArm::Delete, mid)),
        "promote" if pa.payload.get(field_names::TO_NAMESPACE).is_none() => {
            Some((ExecuteArm::TierBump, mid))
        }
        _ => None,
    }
}

/// The row-owner rule: the target must be stamped and owned by the agent
/// that REQUESTED the action (the approver only admits it). An unstamped row
/// is refused in every posture; the inbox carve-out is off.
///
/// # Errors
///
/// [`ExecuteOwnerRefusal`] when the rule refuses.
pub fn check_execute_owner(
    target: &Memory,
    requested_by: &str,
    arm: ExecuteArm,
) -> Result<(), ExecuteOwnerRefusal> {
    let stamp = OwnerStamp::of(&target.metadata);
    if stamp.is_unstamped() {
        return Err(ExecuteOwnerRefusal::Unstamped);
    }
    let (_, arm_funnel) = arm_labels(arm);
    if crate::visibility::caller_owns_for_mutation(
        target,
        requested_by,
        false,
        MutationSite::sqlite(arm_funnel),
    ) {
        return Ok(());
    }
    Err(ExecuteOwnerRefusal::NotOwner {
        owner: stamp.owner_for_display().to_string(),
    })
}

/// Write the forensic row for a refusal of the owner precondition.
/// Best-effort like every pending-action audit emit (the chain may gap, the
/// refusal may not).
pub fn record_owner_refusal(conn: &Connection, pa: &PendingAction) {
    emit_pending_action_event(conn, pa, EVENT_REFUSED_OWNER_GATE, None);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory(metadata: serde_json::Value) -> Memory {
        Memory {
            metadata,
            ..Memory::default()
        }
    }

    #[test]
    fn owner_rule_admits_only_the_stamped_requester_8577() {
        let row = memory(serde_json::json!({"agent_id": "alice"}));
        assert_eq!(
            check_execute_owner(&row, "alice", ExecuteArm::Delete),
            Ok(())
        );
        assert_eq!(
            check_execute_owner(&row, "bob", ExecuteArm::TierBump),
            Err(ExecuteOwnerRefusal::NotOwner {
                owner: "alice".to_string()
            })
        );
        assert_eq!(
            check_execute_owner(&memory(serde_json::json!({})), "alice", ExecuteArm::Delete),
            Err(ExecuteOwnerRefusal::Unstamped)
        );
    }

    #[test]
    fn arm_target_skips_cross_namespace_promote_8577() {
        let mut pa = PendingAction {
            id: "p1".to_string(),
            action_type: "promote".to_string(),
            memory_id: Some("m1".to_string()),
            namespace: "ns".to_string(),
            payload: serde_json::json!({}),
            requested_by: "alice".to_string(),
            requested_at: String::new(),
            status: "pending".to_string(),
            decided_by: None,
            decided_at: None,
            approvals: Vec::new(),
        };
        assert_eq!(execute_arm_target(&pa), Some((ExecuteArm::TierBump, "m1")));
        pa.payload = serde_json::json!({ field_names::TO_NAMESPACE: "ns" });
        assert_eq!(execute_arm_target(&pa), None);
        pa.action_type = "store".to_string();
        assert_eq!(execute_arm_target(&pa), None);
    }
}
