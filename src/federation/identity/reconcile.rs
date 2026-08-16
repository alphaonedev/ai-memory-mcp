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
//! ## The enforcement tri-state (#2975) — omission is UNMANAGED
//!
//! The mirror-image footgun is a downgrade nobody asked for. The runtime gate
//! (`AI_MEMORY_FED_REQUIRE_SIG`, env #29) is fail-closed / ON by default at
//! v1.0.0, so while
//! [`EnforcementSpec::require_sig`](super::inventory::EnforcementSpec::require_sig)
//! was a plain `bool`, an inventory that simply OMITTED the field declared
//! *desired = permissive* and this function planned `DisableStrictEnforcement`
//! — silently turning the secure default OFF. `require_sig` is now
//! `Option<bool>` and consumed by an exhaustive `match`:
//!
//! | desired `require_sig` | meaning | enforcement action planned |
//! |---|---|---|
//! | `None` (omitted) | **unmanaged** | NONE, in either direction |
//! | `Some(true)` | desired strict | `EnableStrictEnforcement`, gated on all-sign-capable |
//! | `Some(false)` | desired permissive | `DisableStrictEnforcement`, immediately |
//!
//! Deleting the line is therefore a no-op; weakening the fleet requires
//! ADDING an explicit `require_sig: false` **and** a non-empty
//! `disable_reason`. That acknowledgement is enforced entirely at inventory
//! load/validate — this module NEVER suppresses a planned action, because a
//! suppressed action would make [`ReconcilePlan::is_noop`] falsely report
//! convergence.
//!
//! Unmanaged is not the same as *fine*, so the plan carries a non-action
//! [`ReconcileAdvisory`] channel: a fleet observed permissive while the
//! inventory declines to manage enforcement emits
//! [`ReconcileAdvisory::EnforcementUnmanagedDrift`], so an
//! unmanaged-permissive fleet is VISIBLE rather than silently "converged".
//!
//! ## Idempotence
//!
//! A converged fleet yields an empty ACTION list ([`ReconcilePlan::is_noop`]).
//! Re-running the reconciler against state it already produced is a no-op —
//! the controller loop can call it on a timer without thrashing. `is_noop` is
//! deliberately **actions-only**: an advisory is an observation, not work, and
//! does NOT block convergence.

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
    /// Flip the fleet to reject unsigned posts. Emitted ONLY when the
    /// inventory declares `require_sig: Some(true)` AND every desired node is
    /// observed sign-capable, and always ordered LAST so a plan that also
    /// enrolls/issues never strict-enforces ahead of capability.
    EnableStrictEnforcement,
    /// Relax the fleet to accept unsigned posts. Always partition-safe;
    /// emitted immediately when the inventory declares an EXPLICIT
    /// `require_sig: Some(false)` (which validation required a
    /// `disable_reason` for) but the fleet is observed strict. An inventory
    /// that merely omits `require_sig` NEVER produces this action (#2975).
    DisableStrictEnforcement,
}

/// A non-action observation the reconciler surfaces alongside the plan
/// (#2975).
///
/// An advisory reports a state an operator probably wants to know about but
/// that the inventory has NOT asked the reconciler to change. It is
/// deliberately excluded from [`ReconcilePlan::is_noop`] and from the applier
/// contract: an advisory NEVER blocks convergence and is never "applied".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAdvisory {
    /// The inventory declines to manage enforcement
    /// (`require_sig` omitted ⇒ `None`) AND the fleet is observed permissive
    /// (`strict_enforced == false`).
    ///
    /// This is the visibility mitigation for omission-is-unmanaged: without
    /// it, an unmanaged fleet sitting permissive would report as cleanly
    /// converged and nobody would learn that the highest-value posture field
    /// is going ungoverned. Resolve it by declaring intent —
    /// `require_sig: true` to have the reconciler flip it on, or an explicit
    /// `require_sig: false` + `disable_reason` to record that permissive is
    /// deliberate.
    EnforcementUnmanagedDrift,
}

/// The ordered set of actions that converges the observed fleet toward the
/// desired inventory, plus any non-action advisories.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcilePlan {
    /// Actions in apply order: enrollments → credential issuance →
    /// decommissions → enforcement relaxation → enforcement tightening (last).
    pub actions: Vec<ReconcileAction>,
    /// Non-action observations (#2975). Carrying an advisory does NOT make a
    /// plan non-converged — see [`Self::is_noop`].
    pub advisories: Vec<ReconcileAdvisory>,
}

impl ReconcilePlan {
    /// A converged fleet needs no actions.
    ///
    /// **Actions-only, by design.** Advisories are observations, not work: a
    /// plan carrying only an advisory IS converged and the controller loop
    /// must not thrash on it. Report advisories separately via
    /// [`Self::advisories`].
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
/// 4. `DisableStrictEnforcement` when the inventory declares an EXPLICIT
///    `require_sig: Some(false)` but the fleet is strict (always safe).
/// 5. `EnableStrictEnforcement` — LAST, and ONLY when the inventory declares
///    `require_sig: Some(true)`, the fleet is not yet strict, AND every
///    desired node is observed sign-capable. If any desired node still lacks
///    signing capability this pass only does the enroll/issue work; a later
///    pass (after credentials propagate) emits the enforcement flip.
///
/// Steps 4 and 5 are mutually exclusive arms of ONE exhaustive `match` on the
/// tri-state desired value, so at most one enforcement action is ever planned
/// and `require_sig: None` (unmanaged) plans neither (#2975). An unmanaged
/// fleet observed permissive instead yields
/// [`ReconcileAdvisory::EnforcementUnmanagedDrift`] on
/// [`ReconcilePlan::advisories`], which does not affect
/// [`ReconcilePlan::is_noop`].
#[must_use]
pub fn reconcile(desired: &FederationInventory, observed: &ObservedState) -> ReconcilePlan {
    let mut actions = Vec::new();
    let mut advisories = Vec::new();

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

    // 4+5 — enforcement transition. EXHAUSTIVE match on the #2975 tri-state:
    // an omitted `require_sig` is UNMANAGED and must never be collapsed to
    // `false` by an `unwrap_or`, which is exactly the bug this closes.
    match desired.enforcement.require_sig {
        // Desired strict — tighten LAST, and only grounded in observed
        // capability, never in the optimism that this pass's enroll/issue
        // actions will succeed.
        Some(true) => {
            if !observed.strict_enforced && desired.nodes().all(|n| observed.is_sign_capable(&n.id))
            {
                actions.push(ReconcileAction::EnableStrictEnforcement);
            }
        }
        // Desired permissive, EXPLICITLY (validation already required a
        // non-empty `disable_reason`). Relaxing is always partition-safe.
        Some(false) => {
            if observed.strict_enforced {
                actions.push(ReconcileAction::DisableStrictEnforcement);
            }
        }
        // Unmanaged — plan NOTHING in either direction. Surface the drift so
        // an unmanaged-permissive fleet is visible rather than silently
        // "converged".
        None => {
            if !observed.strict_enforced {
                advisories.push(ReconcileAdvisory::EnforcementUnmanagedDrift);
            }
        }
    }

    ReconcilePlan {
        actions,
        advisories,
    }
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

    /// The SAME two nodes, but the inventory says nothing about
    /// enforcement — the #2975 unmanaged state (`require_sig: None`).
    const TWO_NODE_UNMANAGED: &str = "\
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
";

    /// The SAME two nodes with an EXPLICIT, acknowledged downgrade.
    const TWO_NODE_EXPLICIT_DISABLE: &str = "\
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
  require_sig: false
  disable_reason: staged peer key enrollment, ticket OPS-42
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
  disable_reason: staged peer key enrollment, ticket OPS-42
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
        assert!(
            plan.advisories.is_empty(),
            "an explicitly-managed downgrade is not unmanaged drift"
        );
    }

    // ---------------------------------------------------------------
    // #2975 — enforcement is a TRI-STATE; omission is UNMANAGED.
    // ---------------------------------------------------------------

    /// **The regression test for the footgun.** Under the v1.0.0 secure
    /// default the live posture IS strict. An inventory that simply OMITS
    /// `require_sig` must NOT plan `DisableStrictEnforcement` — before
    /// #2975 it did, silently downgrading the fail-closed default.
    #[test]
    fn omitted_enforcement_never_disables_observed_strict_2975() {
        let desired = inv(TWO_NODE_UNMANAGED);
        let observed = ObservedState {
            nodes: vec![signing("node-1"), signing("node-2")],
            strict_enforced: true,
        };
        let plan = reconcile(&desired, &observed);
        assert!(
            !plan
                .actions
                .contains(&ReconcileAction::DisableStrictEnforcement),
            "omission is UNMANAGED — it must never plan a downgrade: {:?}",
            plan.actions
        );
        assert!(
            plan.actions.is_empty(),
            "an unmanaged, otherwise-converged fleet plans nothing at all: {:?}",
            plan.actions
        );
        assert!(
            plan.advisories.is_empty(),
            "an unmanaged fleet observed STRICT is not permissive drift"
        );
        assert!(plan.is_noop());
    }

    /// Omitted + observed permissive: still no action in either direction,
    /// but the plan carries the visibility advisory so an
    /// unmanaged-permissive fleet is not silently "converged".
    #[test]
    fn omitted_enforcement_permissive_fleet_emits_drift_advisory_2975() {
        let desired = inv(TWO_NODE_UNMANAGED);
        let observed = ObservedState {
            nodes: vec![signing("node-1"), signing("node-2")],
            strict_enforced: false,
        };
        let plan = reconcile(&desired, &observed);
        assert!(
            plan.actions.is_empty(),
            "unmanaged plans NO enforcement action in either direction: {:?}",
            plan.actions
        );
        assert_eq!(
            plan.advisories,
            vec![ReconcileAdvisory::EnforcementUnmanagedDrift]
        );
        assert!(
            plan.is_noop(),
            "an advisory must NOT block convergence — is_noop stays actions-only"
        );
    }

    /// Explicit `Some(false)` (with its mandatory `disable_reason`) still
    /// downgrades an observed-strict fleet — the deliberate staged-rollout
    /// path is preserved, only the ACCIDENTAL one is closed.
    #[test]
    fn explicit_disable_still_downgrades_observed_strict_2975() {
        let desired = inv(TWO_NODE_EXPLICIT_DISABLE);
        let observed = ObservedState {
            nodes: vec![signing("node-1"), signing("node-2")],
            strict_enforced: true,
        };
        let plan = reconcile(&desired, &observed);
        assert_eq!(
            plan.actions,
            vec![ReconcileAction::DisableStrictEnforcement]
        );
        assert!(plan.advisories.is_empty());
    }

    /// Idempotence across ALL THREE desired states: a fleet already at its
    /// declared posture yields an empty action list every time.
    #[test]
    fn converged_fleet_is_a_noop_in_every_desired_state_2975() {
        // Some(true) converged: fleet strict.
        let strict_plan = reconcile(
            &inv(TWO_NODE_STRICT),
            &ObservedState {
                nodes: vec![signing("node-1"), signing("node-2")],
                strict_enforced: true,
            },
        );
        assert!(strict_plan.is_noop(), "{:?}", strict_plan.actions);

        // Some(false) converged: fleet permissive.
        let disable_plan = reconcile(
            &inv(TWO_NODE_EXPLICIT_DISABLE),
            &ObservedState {
                nodes: vec![signing("node-1"), signing("node-2")],
                strict_enforced: false,
            },
        );
        assert!(disable_plan.is_noop(), "{:?}", disable_plan.actions);

        // None: converged by definition — BOTH observed postures are no-ops.
        for strict_enforced in [true, false] {
            let plan = reconcile(
                &inv(TWO_NODE_UNMANAGED),
                &ObservedState {
                    nodes: vec![signing("node-1"), signing("node-2")],
                    strict_enforced,
                },
            );
            assert!(
                plan.is_noop(),
                "unmanaged must be a no-op at strict_enforced={strict_enforced}: {:?}",
                plan.actions
            );
        }
    }

    /// Re-running the reconciler against the state its own plan produced
    /// must converge to a no-op — the controller-loop-on-a-timer contract.
    #[test]
    fn replanning_after_applying_the_enable_action_converges_2975() {
        let desired = inv(TWO_NODE_STRICT);
        let before = ObservedState {
            nodes: vec![signing("node-1"), signing("node-2")],
            strict_enforced: false,
        };
        let first = reconcile(&desired, &before);
        assert_eq!(
            first.actions.last(),
            Some(&ReconcileAction::EnableStrictEnforcement)
        );
        // Apply it, then replan.
        let after = ObservedState {
            strict_enforced: true,
            ..before
        };
        assert!(reconcile(&desired, &after).is_noop());
    }

    /// An empty inventory that omits enforcement is unmanaged, not
    /// permissive. (Renamed from `already_permissive_desired_permissive_is_noop`
    /// — the old name asserted the semantics #2975 removed.)
    #[test]
    fn empty_inventory_is_unmanaged_and_a_noop_2975() {
        let unmanaged = inv("\
trust_domain: fleet
quorum:
  width: 1
");
        assert_eq!(unmanaged.enforcement.require_sig, None);
        let observed = ObservedState::default();
        let plan = reconcile(&unmanaged, &observed);
        assert!(plan.is_noop());
        assert!(plan.actions.is_empty());
        // Empty node list + observed permissive ⇒ the drift advisory fires.
        assert_eq!(
            plan.advisories,
            vec![ReconcileAdvisory::EnforcementUnmanagedDrift]
        );
    }

    /// The #2975 vote's grounded kill of "just default it to `true`": an
    /// empty desired node list makes `.all(..)` VACUOUSLY true, so a
    /// default-true inventory would immediately plan
    /// `EnableStrictEnforcement` and 401-partition every unlisted legacy
    /// sender. Under the tri-state, the minimal inventory plans nothing.
    #[test]
    fn empty_node_list_does_not_vacuously_enable_strict_2975() {
        let unmanaged = inv("\
trust_domain: fleet
quorum:
  width: 1
");
        let plan = reconcile(
            &unmanaged,
            &ObservedState {
                nodes: Vec::new(),
                strict_enforced: false,
            },
        );
        assert!(
            !plan
                .actions
                .contains(&ReconcileAction::EnableStrictEnforcement),
            "a node-less unmanaged inventory must not vacuously strict-enforce"
        );

        // Contrast: an EXPLICIT `require_sig: true` on a node-less inventory
        // DOES flip — that is the operator asking for it, in writing.
        let explicit_strict = inv("\
trust_domain: fleet
quorum:
  width: 1
enforcement:
  require_sig: true
");
        let plan = reconcile(
            &explicit_strict,
            &ObservedState {
                nodes: Vec::new(),
                strict_enforced: false,
            },
        );
        assert_eq!(plan.actions, vec![ReconcileAction::EnableStrictEnforcement]);
    }
}
