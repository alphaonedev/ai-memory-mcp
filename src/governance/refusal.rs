// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Typed governance refusal envelope (issue #963).
//!
//! Before #963 the gate-refusal path was a 4-layer string chain:
//!
//! ```text
//!   substrate `evaluate_level` → GovernanceDecision::Deny(String)
//!         ↓
//!   handler refusal Response   → HTTP 403 body (free-form message)
//!         ↓
//!   MCP tool                   → JSON error blob (free-form message)
//!         ↓
//!   CLI                        → stderr line (free-form message)
//! ```
//!
//! Each layer lost structured context (which policy fired, which level
//! denied, the owner who would have satisfied the gate, the namespace
//! the refusal applies to). The free-form string was the only carrier;
//! clients that wanted to react programmatically had to grep
//! [`crate::governance::deny_message`]-produced substrings.
//!
//! #963 lands the typed envelope: [`GovernanceRefusal`] is the
//! canonical payload that every gate refusal carries through the
//! [`crate::models::GovernanceDecision::Deny`] variant. Display is
//! byte-identical to the pre-#963 `Deny(String)` shape (uses
//! [`crate::governance::deny_message`] with `DenyGate::Governance`) so
//! the existing test-suite substring matches keep working, and the
//! struct fields expose the typed info to handlers that want a richer
//! response than the wire string.
//!
//! See `src/storage/error.rs` ([`crate::storage::StorageError`]) for
//! the sister pattern landed under #962 — that envelope is also
//! Display-back-compat + typed-field-rich; same design ethos here.

use serde::{Deserialize, Serialize};

use crate::models::{GovernedAction, namespace::GovernanceLevel};

/// Typed governance gate refusal. Carried by
/// [`crate::models::GovernanceDecision::Deny`] (was `Deny(String)`
/// pre-#963).
///
/// `Display` produces the canonical wire string
/// `"<action> denied by governance: <reason>"` via
/// [`crate::governance::deny_message`] with
/// [`crate::governance::DenyGate::Governance`] — byte-identical to
/// the pre-#963 `Deny(String)` shape so substring-matching consumers
/// (`tests/...starts_with("denied by governance")`, MCP error-blob
/// asserts) keep matching through the typed envelope.
///
/// The struct fields surface the structured info handlers want to
/// react on (policy lookup, retry hint based on owner, structured
/// error-blob projection):
///
/// - `action`   — the [`GovernedAction`] that was attempted.
/// - `denied_level` — the [`GovernanceLevel`] (`Any` / `Registered` /
///   `Owner` / `Approve`) that produced the refusal.
/// - `agent_id` — the caller principal that failed the gate.
/// - `namespace` — the namespace the gated action targeted (None
///   when the caller passes an unscoped action).
/// - `owner` — the principal who WOULD have satisfied an Owner-level
///   gate (memory's `metadata.agent_id` or the namespace standard's
///   owner). None for non-Owner refusals.
/// - `reason` — the human-readable refusal explanation. Carries the
///   exact string the pre-#963 `Deny(String)` carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceRefusal {
    pub action: GovernedAction,
    pub denied_level: GovernanceLevel,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    pub reason: String,
}

impl GovernanceRefusal {
    /// Construct a [`GovernanceRefusal`] with the canonical fields. The
    /// `reason` should be the human-readable explanation the gate
    /// surfaces; callers SHOULD use a phrase that round-trips through
    /// [`crate::governance::deny_message`] cleanly (i.e. no leading
    /// `"<action> denied by governance: "` — that prefix is added by
    /// `Display`).
    #[must_use]
    pub fn new(
        action: GovernedAction,
        denied_level: GovernanceLevel,
        agent_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            action,
            denied_level,
            agent_id: agent_id.into(),
            namespace: None,
            owner: None,
            reason: reason.into(),
        }
    }

    /// Attach the namespace the gated action targeted.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Attach the principal who WOULD have satisfied an Owner-level
    /// gate (no-op for non-Owner refusals; the field stays `None`).
    #[must_use]
    pub fn with_owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = Some(owner.into());
        self
    }
}

impl std::fmt::Display for GovernanceRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Byte-identical to pre-#963 `Deny(String)` Display: routes
        // through the canonical deny_message helper so the wire shape
        // ("<action> denied by governance: <reason>") cannot drift.
        let msg = crate::governance::deny_message(
            self.action.as_str(),
            crate::governance::DenyGate::Governance,
            &self.reason,
        );
        f.write_str(&msg)
    }
}

impl std::error::Error for GovernanceRefusal {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_matches_canonical_deny_message_shape() {
        let r = GovernanceRefusal::new(
            GovernedAction::Store,
            GovernanceLevel::Owner,
            "ai:bob",
            "caller 'ai:bob' is not the owner ('ai:alice')",
        );
        // The deny_message contract: "<action> denied by governance: <reason>".
        // Pre-#963 the legacy GovernanceDecision::Deny(reason) callers
        // formatted as "store denied by governance: …"; the typed
        // refusal MUST round-trip to the same string so existing
        // substring-matching consumers keep working.
        assert_eq!(
            r.to_string(),
            "store denied by governance: caller 'ai:bob' is not the owner ('ai:alice')",
        );
    }

    #[test]
    fn display_starts_with_canonical_deny_prefix() {
        // Wire-shape pin — clients grep for "denied by governance" to
        // detect a substrate gate refusal. The prefix MUST survive any
        // future Display refactor.
        let r = GovernanceRefusal::new(
            GovernedAction::Delete,
            GovernanceLevel::Registered,
            "anon:x",
            "not a registered agent",
        );
        let s = r.to_string();
        assert!(
            s.contains("denied by governance"),
            "canonical prefix missing: {s}",
        );
        assert!(s.starts_with("delete"), "action verb missing: {s}");
    }

    #[test]
    fn builder_records_namespace_and_owner() {
        let r = GovernanceRefusal::new(
            GovernedAction::Promote,
            GovernanceLevel::Owner,
            "ai:bob",
            "caller 'ai:bob' is not the owner ('ai:alice')",
        )
        .with_namespace("team/prod")
        .with_owner("ai:alice");
        assert_eq!(r.namespace.as_deref(), Some("team/prod"));
        assert_eq!(r.owner.as_deref(), Some("ai:alice"));
        assert_eq!(r.agent_id, "ai:bob");
        assert_eq!(r.denied_level, GovernanceLevel::Owner);
    }

    #[test]
    fn serde_roundtrip_preserves_all_fields() {
        let r = GovernanceRefusal::new(
            GovernedAction::Store,
            GovernanceLevel::Owner,
            "ai:bob",
            "owner-level refusal",
        )
        .with_namespace("ns")
        .with_owner("ai:alice");
        let json = serde_json::to_string(&r).expect("ser");
        let back: GovernanceRefusal = serde_json::from_str(&json).expect("deser");
        assert_eq!(back, r);
    }

    #[test]
    fn serde_skips_none_optional_fields_for_compact_wire() {
        // namespace + owner are skip_serializing_if=Option::is_none so
        // pre-#963 wire-shape consumers that pick the refusal envelope
        // out of an MCP JSON error blob don't see absent fields.
        let r = GovernanceRefusal::new(
            GovernedAction::Reflect,
            GovernanceLevel::Any,
            "ai:x",
            "trivially allowed in this fixture",
        );
        let json = serde_json::to_string(&r).expect("ser");
        assert!(!json.contains("namespace"));
        assert!(!json.contains("owner"));
    }

    #[test]
    fn error_trait_impl_allows_anyhow_chain() {
        // The `std::error::Error` impl is what lets callers wrap the
        // refusal via `anyhow::Error::new(refusal)` and downcast on the
        // other side — same pattern as `crate::storage::StorageError`
        // (#962) + `crate::storage::GovernanceRefusal` (pre-write hook).
        let r = GovernanceRefusal::new(
            GovernedAction::Delete,
            GovernanceLevel::Owner,
            "ai:x",
            "not the owner",
        );
        let any: anyhow::Error = anyhow::Error::new(r.clone());
        let back = any
            .downcast_ref::<GovernanceRefusal>()
            .expect("typed refusal must survive anyhow round-trip");
        assert_eq!(back, &r);
    }
}
