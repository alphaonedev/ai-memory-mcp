// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Reconciler diff core — the pure decision function that turns a desired
//! [`FederationInventory`] plus the observed live state of the fleet into
//! an ordered [`ReconcilePlan`].
//!
//! This module is deliberately I/O-free: no network, no `/proc`, no shell.
//! It is the testable heart of the §7 reconciler contract. The side-effecting
//! half — capturing argv+environ, atomic binary swap, the mTLS health probe,
//! and rollback — is the shell artifact (P3c-4) that *executes* the plan this
//! function produces. Keeping the decision pure means every partition-safety
//! property below is provable in a unit test with no daemon running.
//!
//! ## The partition-safety invariant (the manual footgun this prevents)
//!
//! The historical failure mode: an operator flips a fleet to "reject unsigned
//! posts" (`require_sig`) *before* every node can actually present a valid
//! signature, and the fleet partitions — every still-unsigned sender is now
//! `401`'d. The reconciler must NEVER recreate that footgun. So
//! [`reconcile`] enables strict enforcement ONLY on a pass where every desired
//! node is *observed* sign-capable — grounded in reality, not in the optimism
//! that this pass's enroll/issue actions will succeed. Relaxing enforcement is
//! always safe and is emitted immediately.
//!
//! ## Idempotence
//!
//! A converged fleet yields an empty plan ([`ReconcilePlan::is_noop`]). Re-running
//! the reconciler against state it already produced is a no-op — the controller
//! loop can call it on a timer without thrashing.

use std::collections::BTreeMap;

use super::inventory::FederationInventory;

/// What the reconciler actually sees for one node in the live fleet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedNode {
    /// The node's federation identity (matches [`super::inventory::NodeSpec::id`]).
    pub id: String,
    /// The node is known to the fleet (enrolled / reachable). A desired node
    /// that is `present == false` (or simply absent from the observed set)
    /// still needs bring-up.
    pub present: bool,
    /// The node currently holds a valid credential and can sign its posts.
    /// A `present` node that cannot sign still needs a credential issued
    /// before strict enforcement is safe fleet-wide.
    pub can_sign: bool,
}

/// A snapshot of the live fleet the reconciler diffs the inventory against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservedState {
    /// Observed nodes. Order is preserved for deterministic decommission
    /// sequencing; lookups go through [`Self::node`].
    pub nodes: Vec<ObservedNode>,
    /// Receivers currently reject unsigned posts (the live `require_sig`
    /// posture). The reconciler diffs this against
    /// [`super::inventory::EnforcementSpec::require_sig`].
    pub strict_enforced: bool,
}

impl ObservedState {
    /// Look up an observed node by id.
    #[must_use]
    pub fn node(&self, id: &str) -> Option<&ObservedNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Whether the named node is observed both present AND sign-capable.
    fn is_sign_capable(&self, id: &str) -> bool {
        self.node(id).is_some_and(|n| n.present && n.can_sign)
    }
}

/// One step the reconciler wants applied to converge the fleet toward the
/// inventory. Ordering within a [`ReconcilePlan`] is load-bearing — see
/// [`reconcile`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAction {
    /// A desired node is absent from the observed fleet — bring it up /
    /// register it (enrollment carries its first credential).
    EnrollNode { id: String },
    /// A desired node is present but cannot sign — issue (or re-issue) its
    /// credential so it becomes sign-capable.
    IssueCredential { id: String },
    /// An observed node is not in the inventory — decommission it.
    DecommissionNode { id: String },
    /// Flip the fleet to reject unsigned posts. Emitted ONLY when every
    /// desired node is observed sign-capable, and always ordered LAST so a
    /// plan that also enrolls/issues never strict-enforces ahead of
    /// capability.
    EnableStrictEnforcement,
    /// Relax the fleet to accept unsigned posts. Always partition-safe;
    /// emitted immediately when the inventory wants permissive but the fleet
    /// is observed strict.
    DisableStrictEnforcement,
}

/// The ordered set of actions that converges the observed fleet toward the
/// desired inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcilePlan {
    /// Actions in apply order: enrollments → credential issuance →
    /// decommissions → enforcement relaxation → enforcement tightening (last).
    pub actions: Vec<ReconcileAction>,
}

impl ReconcilePlan {
    /// A converged fleet needs no actions.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.actions.is_empty()
    }
}

/// Diff a desired inventory against the observed fleet state and produce an
/// ordered, partition-safe, idempotent [`ReconcilePlan`].
///
/// Action ordering (the partition-safety guarantee):
/// 1. `EnrollNode` for every desired node absent from the observed fleet.
/// 2. `IssueCredential` for every desired node present-but-not-sign-capable.
/// 3. `DecommissionNode` for every observed node not in the inventory.
/// 4. `DisableStrictEnforcement` when the inventory wants permissive but the
///    fleet is strict (always safe).
/// 5. `EnableStrictEnforcement` — LAST, and ONLY when the inventory wants
///    strict, the fleet is not yet strict, AND every desired node is observed
///    sign-capable. If any desired node still lacks signing capability this
///    pass only does the enroll/issue work; a later pass (after credentials
///    propagate) emits the enforcement flip.
#[must_use]
pub fn reconcile(desired: &FederationInventory, observed: &ObservedState) -> ReconcilePlan {
    let mut actions = Vec::new();

    let desired_ids: BTreeMap<&str, ()> = desired.nodes().map(|n| (n.id.as_str(), ())).collect();

    // 1+2 — bring desired nodes to sign-capable, in inventory order.
    for node in desired.nodes() {
        match observed.node(&node.id) {
            None => actions.push(ReconcileAction::EnrollNode {
                id: node.id.clone(),
            }),
            Some(obs) if !obs.present => actions.push(ReconcileAction::EnrollNode {
                id: node.id.clone(),
            }),
            Some(obs) if !obs.can_sign => actions.push(ReconcileAction::IssueCredential {
                id: node.id.clone(),
            }),
            Some(_) => {}
        }
    }

    // 3 — decommission observed nodes the inventory no longer lists.
    for obs in &observed.nodes {
        if !desired_ids.contains_key(obs.id.as_str()) {
            actions.push(ReconcileAction::DecommissionNode { id: obs.id.clone() });
        }
    }

    // 4+5 — enforcement transition, gated on observed capability.
    let want_strict = desired.enforcement.require_sig;
    if want_strict && !observed.strict_enforced {
        let all_sign_capable = desired.nodes().all(|n| observed.is_sign_capable(&n.id));
        if all_sign_capable {
            actions.push(ReconcileAction::EnableStrictEnforcement);
        }
    } else if !want_strict && observed.strict_enforced {
        actions.push(ReconcileAction::DisableStrictEnforcement);
    }

    ReconcilePlan { actions }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inv(yaml: &str) -> FederationInventory {
        FederationInventory::from_yaml_str(yaml).expect("valid inventory")
    }

    /// Two sign-capable nodes, strict desired + strict observed.
    const TWO_NODE_STRICT: &str = "\
trust_domain: fleet
regions:
  - name: r
    nodes:
      - id: node-1
        attestor: mtls-cert
        cred_ttl: 1h
        renew_before: 5m
      - id: node-2
        attestor: mtls-cert
        cred_ttl: 1h
        renew_before: 5m
quorum:
  width: 2
enforcement:
  require_sig: true
";

    fn signing(id: &str) -> ObservedNode {
        ObservedNode {
            id: id.to_string(),
            present: true,
            can_sign: true,
        }
    }

    #[test]
    fn converged_fleet_is_a_noop() {
        let desired = inv(TWO_NODE_STRICT);
        let observed = ObservedState {
            nodes: vec![signing("node-1"), signing("node-2")],
            strict_enforced: true,
        };
        let plan = reconcile(&desired, &observed);
        assert!(plan.is_noop(), "converged state must produce no actions");
    }

    #[test]
    fn absent_desired_node_is_enrolled() {
        let desired = inv(TWO_NODE_STRICT);
        let observed = ObservedState {
            nodes: vec![signing("node-1")],
            strict_enforced: false,
        };
        let plan = reconcile(&desired, &observed);
        assert!(plan.actions.contains(&ReconcileAction::EnrollNode {
            id: "node-2".to_string()
        }));
    }

    #[test]
    fn not_present_node_is_enrolled_not_issued() {
        let desired = inv(TWO_NODE_STRICT);
        let observed = ObservedState {
            nodes: vec![
                signing("node-1"),
                ObservedNode {
                    id: "node-2".to_string(),
                    present: false,
                    can_sign: false,
                },
            ],
            strict_enforced: false,
        };
        let plan = reconcile(&desired, &observed);
        assert!(plan.actions.contains(&ReconcileAction::EnrollNode {
            id: "node-2".to_string()
        }));
        assert!(!plan.actions.contains(&ReconcileAction::IssueCredential {
            id: "node-2".to_string()
        }));
    }

    #[test]
    fn present_node_without_credential_gets_issue() {
        let desired = inv(TWO_NODE_STRICT);
        let observed = ObservedState {
            nodes: vec![
                signing("node-1"),
                ObservedNode {
                    id: "node-2".to_string(),
                    present: true,
                    can_sign: false,
                },
            ],
            strict_enforced: false,
        };
        let plan = reconcile(&desired, &observed);
        assert!(plan.actions.contains(&ReconcileAction::IssueCredential {
            id: "node-2".to_string()
        }));
    }

    #[test]
    fn observed_node_not_in_inventory_is_decommissioned() {
        let desired = inv(TWO_NODE_STRICT);
        let observed = ObservedState {
            nodes: vec![signing("node-1"), signing("node-2"), signing("ghost")],
            strict_enforced: true,
        };
        let plan = reconcile(&desired, &observed);
        assert_eq!(
            plan.actions,
            vec![ReconcileAction::DecommissionNode {
                id: "ghost".to_string()
            }]
        );
    }

    #[test]
    fn strict_enforcement_is_deferred_until_all_nodes_sign_capable() {
        let desired = inv(TWO_NODE_STRICT);
        // node-2 not yet sign-capable.
        let observed = ObservedState {
            nodes: vec![
                signing("node-1"),
                ObservedNode {
                    id: "node-2".to_string(),
                    present: true,
                    can_sign: false,
                },
            ],
            strict_enforced: false,
        };
        let plan = reconcile(&desired, &observed);
        assert!(
            !plan
                .actions
                .contains(&ReconcileAction::EnableStrictEnforcement),
            "must NOT strict-enforce while a desired node cannot sign"
        );
        // It still does the capability work this pass.
        assert!(plan.actions.contains(&ReconcileAction::IssueCredential {
            id: "node-2".to_string()
        }));
    }

    #[test]
    fn strict_enforcement_enabled_and_ordered_last_when_all_sign_capable() {
        let desired = inv(TWO_NODE_STRICT);
        let observed = ObservedState {
            nodes: vec![signing("node-1"), signing("node-2")],
            strict_enforced: false,
        };
        let plan = reconcile(&desired, &observed);
        assert_eq!(
            plan.actions.last(),
            Some(&ReconcileAction::EnableStrictEnforcement),
            "enforcement tightening must be the final action"
        );
    }

    #[test]
    fn enable_strict_is_last_even_with_enroll_and_decommission_in_same_pass() {
        // node-2 sign-capable, but an extra ghost to decommission; node-1
        // sign-capable. All DESIRED nodes are sign-capable, so enforcement flips.
        let desired = inv(TWO_NODE_STRICT);
        let observed = ObservedState {
            nodes: vec![signing("node-1"), signing("node-2"), signing("ghost")],
            strict_enforced: false,
        };
        let plan = reconcile(&desired, &observed);
        assert_eq!(
            plan.actions.last(),
            Some(&ReconcileAction::EnableStrictEnforcement)
        );
        // The decommission precedes the enforcement flip.
        let decomm_idx = plan
            .actions
            .iter()
            .position(|a| matches!(a, ReconcileAction::DecommissionNode { .. }))
            .expect("decommission present");
        let enforce_idx = plan
            .actions
            .iter()
            .position(|a| matches!(a, ReconcileAction::EnableStrictEnforcement))
            .expect("enforce present");
        assert!(decomm_idx < enforce_idx);
    }

    #[test]
    fn relaxing_enforcement_is_immediate() {
        let permissive = inv("\
trust_domain: fleet
regions:
  - name: r
    nodes:
      - id: node-1
        attestor: mtls-cert
        cred_ttl: 1h
        renew_before: 5m
quorum:
  width: 1
enforcement:
  require_sig: false
");
        let observed = ObservedState {
            nodes: vec![signing("node-1")],
            strict_enforced: true,
        };
        let plan = reconcile(&permissive, &observed);
        assert_eq!(
            plan.actions,
            vec![ReconcileAction::DisableStrictEnforcement]
        );
    }

    #[test]
    fn already_permissive_desired_permissive_is_noop() {
        let permissive = inv("\
trust_domain: fleet
quorum:
  width: 1
");
        let observed = ObservedState::default();
        let plan = reconcile(&permissive, &observed);
        assert!(plan.is_noop());
    }
}
