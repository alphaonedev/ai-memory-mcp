// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1862 (TRACT-gap G10.2) — [`RefusalClaim`], the read-only Claim-shape a
//! governance refusal WOULD persist as.
//!
//! # This is NOT a persisted, recallable Claim
//!
//! TRACT L1 wants a governance refusal to be a first-class **recallable Claim**
//! (`docs/spec/TRACT-L1-CLAIM-CONTRACT.md` §12) so a refused agent can recall
//! "was I denied X?" and let it inform later reasoning / governance review. The
//! substrate does NOT persist refusals: a [`GovernanceRefusal`] is minted (in
//! three independent lanes — the stateless `Permissions::evaluate`, the
//! conn-bearing `storage::enforce_governance`, and the `wire_check`
//! pre-action hook) and returned as a typed error via
//! [`crate::governance::deny_message`], never written to `memories`.
//! [`REFUSAL_PERSISTED_AS_CLAIM`] is `false`.
//!
//! This module ships NO persistence. It is the machine-checked projection of a
//! refusal onto the Claim fields the gap enumerates (identity + action +
//! namespace + denied level + reason), giving the deferred v1.x persist path a
//! typed target and pinning the honest state. The projection has a live
//! constructor: [`GovernanceRefusal`]'s `Display` renders through it.
//!
//! # Why persistence is deferred to v1.x — the safety model does not exist
//!
//! Persisting a refusal-memory re-enters the write path's
//! `consult_governance_pre_write` gate UNCONDITIONALLY, and
//! `CallerContext::for_admin` does **not** bypass it (it sets only
//! `bypass_visibility`; the gate takes no caller context). So a naive persist
//! can be refused (silent audit loss) or recurse, with no guard; the daily
//! write quota makes it either self-DOSing (tool-layer) or unbounded (bypassed);
//! and the refusal-Claim's visibility/ownership scope is undesigned. The full
//! safety model is v1.x — see §12.

use crate::governance::refusal::GovernanceRefusal;
use crate::models::MemoryKind;

/// `true` only when governance refusals are persisted as recallable Claim-kind
/// memories. They are NOT at v1.0.0 (TRACT G10.2, #1862) — a refusal is a typed
/// error, not a row. Pinned as a const so the honesty state is machine-checked;
/// flipping it is a deliberate edit here + a §12 ledger update + a real,
/// re-entrancy-safe persist path.
pub const REFUSAL_PERSISTED_AS_CLAIM: bool = false;

/// The read-only Claim-shape a [`GovernanceRefusal`] WOULD persist as under
/// TRACT G10.2. A **projection**, NOT a persisted memory. `#[non_exhaustive]`
/// because the eventual persisted shape (owner/scope/timestamps) is still being
/// designed (§12).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefusalClaim {
    /// The Claim asserter — the caller principal that failed the gate
    /// (`GovernanceRefusal::agent_id`). The identity that WOULD own + recall the
    /// refusal-Claim (v1.x acceptance criterion: `scope=private`, owned by this
    /// agent, so no cross-agent "who-was-denied-what" leak).
    pub asserter: String,
    /// The governed action that was denied.
    pub action: String,
    /// The namespace the action targeted, when scoped.
    pub namespace: Option<String>,
    /// The governance level that denied the action
    /// (`any` / `registered` / `owner` / `approve`).
    pub denied_level: String,
    /// The principal who WOULD have satisfied an Owner-level gate, when relevant.
    pub owner: Option<String>,
    /// The human-readable refusal reason. Structurally identity/action/namespace/
    /// level ONLY — never the refused payload; any future persist re-enters the
    /// secret screen regardless.
    pub reason: String,
}

impl RefusalClaim {
    /// Project a [`GovernanceRefusal`] onto its would-be Claim shape. Read-only,
    /// total, never persists.
    #[must_use]
    pub fn of_refusal(r: &GovernanceRefusal) -> Self {
        Self {
            asserter: r.agent_id.clone(),
            action: r.action.as_str().to_string(),
            namespace: r.namespace.clone(),
            denied_level: r.denied_level.as_str().to_string(),
            owner: r.owner.clone(),
            reason: r.reason.clone(),
        }
    }

    /// The `MemoryKind` a persisted refusal-Claim would carry (G10.2 says
    /// Claim-kind). Fixed today; here so the v1.x persist path has one source of
    /// truth rather than re-deciding the kind at the write site.
    #[must_use]
    pub fn would_be_memory_kind() -> MemoryKind {
        MemoryKind::Claim
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::GovernedAction;
    use crate::models::namespace::GovernanceLevel;

    fn sample() -> GovernanceRefusal {
        GovernanceRefusal::new(
            GovernedAction::Store,
            GovernanceLevel::Owner,
            "ai:bob",
            "caller 'ai:bob' is not the owner ('ai:alice')",
        )
        .with_namespace("team/eng")
        .with_owner("ai:alice")
    }

    /// The projection round-trips every field of the real, live-constructed
    /// `GovernanceRefusal`. If a future edit drops a field, this fails and forces
    /// a deliberate spec + ledger update.
    #[test]
    fn projection_round_trips_every_refusal_field() {
        let r = sample();
        let c = RefusalClaim::of_refusal(&r);
        assert_eq!(c.asserter, "ai:bob");
        assert_eq!(c.action, r.action.as_str());
        assert_eq!(c.namespace.as_deref(), Some("team/eng"));
        assert_eq!(c.denied_level, r.denied_level.as_str());
        assert_eq!(c.owner.as_deref(), Some("ai:alice"));
        assert_eq!(c.reason, r.reason);
    }

    /// #1862 / G10.2 honesty pin: refusals are NOT persisted as recallable
    /// Claims at v1.0.0. If a future edit flips this without a real persist path
    /// + §12 update, the const change is caught here.
    #[test]
    fn g10_2_refusals_are_not_persisted_as_claims() {
        assert!(
            !REFUSAL_PERSISTED_AS_CLAIM,
            "refusals are typed errors, not recallable Claim rows (G10.2)"
        );
        assert_eq!(RefusalClaim::would_be_memory_kind(), MemoryKind::Claim);
    }

    /// The projection is the live constructor behind `GovernanceRefusal`'s
    /// `Display`, so the rendered error is byte-identical whether or not it
    /// routes through the projection (the anchor is wired, not floating).
    #[test]
    fn display_is_byte_identical_through_the_projection() {
        let r = sample();
        let c = RefusalClaim::of_refusal(&r);
        let via_projection = crate::governance::deny_message(
            &c.action,
            crate::governance::DenyGate::Governance,
            &c.reason,
        );
        assert_eq!(via_projection, r.to_string());
    }
}
