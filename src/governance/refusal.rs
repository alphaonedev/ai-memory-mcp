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

    /// #3292 M7 — `Owner` level with no resolvable standard owner. The
    /// same state is unowned-PASS in `clear_namespace_standard`; MCP
    /// `memory_update` / `memory_capture_turn` use this to avoid locking
    /// the namespace for every caller. Store still fail-closes at
    /// `evaluate_level`.
    #[must_use]
    pub fn is_unowned_owner_lock(&self) -> bool {
        self.denied_level == GovernanceLevel::Owner && self.reason.contains("no resolvable owner")
    }
}

/// OPT-IN strict admission posture: under `permissions.mode = "enforce"`,
/// refuse a `Store`/`Delete`/`Promote` whose namespace chain resolves NO
/// governance policy.
///
/// **Default OFF — unset is byte-identical to the legacy behaviour.**
///
/// # Why this is opt-in rather than the default
///
/// "Absence of policy == Allow" looks like a classic fail-open admission
/// gate, and structurally it is one. But in this substrate it is a
/// deliberate, multiply-pinned product contract, not an oversight:
///
/// - `tests/ship_gate_governance_inheritance.rs` is CUTLINE-PROTECTED
///   ("failures here are release blockers") and asserts that an ungoverned
///   subtree still Allows *while a sibling subtree IS governed* —
///   "ungoverned subtrees remain opt-in (compatibility preserved)".
/// - `tests/governance_postgres_inheritance.rs` (S60) asserts the same
///   across siblings, as the proof that a parent's policy does not LEAK
///   into an unrelated namespace.
/// - The shipped runtime mode is `enforce`
///   ([`crate::governance::default_v07_secure_mode`] — the serde-derived
///   `Advisory` on the config struct is bypassed by
///   `AppConfig::effective_permissions_mode`), so opt-in enforcement is
///   precisely what makes that secure default shippable: flipping the
///   default here would refuse every write on a fresh install, and on a
///   multi-tenant substrate would let one tenant's governance config
///   refuse writes into another tenant's ungoverned subtree.
///
/// Flipping the default is therefore a product-semantics decision (an
/// owner ruling / T3 vote), not remediation — **deferred to #3125**, filed
/// alongside #3111. This knob delivers the fail-closed posture NOW to
/// operators — and to the certified enterprise-federation deployment — who
/// genuinely mean "govern everything", with zero behaviour change for
/// everyone else.
///
/// Deliberately NOT pinned in [`crate::security_profile`]'s `asi-hard`
/// KNOBS table: every entry there already defaults fail-closed, so pinning
/// is a no-op for a compliant deployment (the #3033 invariant). This knob
/// defaults OFF, so pinning it would be a behaviour change for existing
/// `asi-hard` deployments — i.e. it would pre-empt #3125 for a subset of
/// the fleet. Revisit as part of #3125: if the default flips ON, the pin
/// becomes a no-op and belongs in the table.
pub const ENV_REQUIRE_GOVERNED_NAMESPACE: &str = "AI_MEMORY_PERMISSIONS_REQUIRE_GOVERNED_NAMESPACE";

/// Is the OPT-IN strict admission posture engaged? See
/// [`ENV_REQUIRE_GOVERNED_NAMESPACE`]. Grammar is the shared house truthy
/// set (`1` / `true` / `yes` / `on`, case-insensitive) via
/// [`crate::governance::audit::env_flag_enabled`] — a `=yes` must never
/// silently stay FAIL-OPEN (Fable HIGH #3133). Default UNSET = legacy Allow.
#[must_use]
pub fn require_governed_namespace() -> bool {
    crate::governance::audit::env_flag_enabled(ENV_REQUIRE_GOVERNED_NAMESPACE)
}

/// The operator-facing reason carried by an ungoverned-namespace refusal.
///
/// Deliberately names EVERY remedy so a refused write is actionable from the
/// wire message alone — the gate must degrade manageably, never silently
/// brick a fleet.
pub const UNGOVERNED_NAMESPACE_REASON: &str = concat!(
    "no governance policy resolves for this namespace or any of its ",
    "ancestors, and the strict admission posture ",
    "AI_MEMORY_PERMISSIONS_REQUIRE_GOVERNED_NAMESPACE=1 is engaged under ",
    "permissions.mode=enforce (fail-closed: absence of a policy is not ",
    "treated as Allow). Remedies: (1) declare a policy for this namespace ",
    "\u{2014} or a substrate-wide default on the '*' namespace, which covers ",
    "every namespace at once \u{2014} with `memory_namespace_set_standard`; ",
    "(2) unset AI_MEMORY_PERMISSIONS_REQUIRE_GOVERNED_NAMESPACE to restore ",
    "the default opt-in-enforcement posture, in which ungoverned namespaces ",
    "are allowed; (3) run permissions.mode=advisory to log rather than block",
);

/// FAIL-CLOSED admission refusal for a namespace whose governance chain
/// resolves NO policy while `permissions.mode = "enforce"` **and the opt-in
/// strict posture [`ENV_REQUIRE_GOVERNED_NAMESPACE`] is engaged**.
///
/// SSOT shared by the sqlite (`storage::enforce_governance`) and postgres
/// (`PostgresStore::enforce_governance_action`) gates so the two backends
/// cannot drift — the same reason for the two adapters to share
/// [`required_scope_refusal`].
///
/// `denied_level` is [`GovernanceLevel::Owner`], matching the #2503
/// SEVERED-FLOOR convention: an unresolvable policy floors the required
/// authority at owner rather than pretending a level was evaluated.
///
/// # Why the gates return this EARLY, before the capability-grant joiner
///
/// Both gates return this refusal before
/// [`crate::governance::capability::apply_at_gate`] runs, so a presented
/// capability token cannot flip it to `Allow`. Two reasons: (1) fail-closed
/// — a token's caveats say what its holder may do, they say nothing about
/// whether the namespace is governed at all, so letting one satisfy an
/// admission gate that could not evaluate ANY policy would re-open exactly
/// the hole this refusal closes; (2) scope — whether a rule-derived `Deny`
/// should be token-flippable at all is an open design decision (#3111), and
/// this refusal deliberately does not depend on how that is resolved.
#[must_use]
pub fn ungoverned_namespace_refusal(
    action: GovernedAction,
    agent_id: &str,
    namespace: &str,
) -> GovernanceRefusal {
    GovernanceRefusal::new(
        action,
        GovernanceLevel::Owner,
        agent_id,
        UNGOVERNED_NAMESPACE_REASON,
    )
    .with_namespace(namespace)
}

/// #1720 C — build the per-namespace `required_scope` refusal for a
/// `Store` when the write's effective scope does not match the policy's
/// pinned scope. Refuse-only: this NEVER mutates the write; it only
/// produces the typed refusal (or `None` when the scope satisfies the
/// requirement). Shared by the sqlite (`storage::enforce_governance`) and
/// postgres (`PostgresStore::enforce_governance_action`) Store gates so
/// the fail-closed semantics + message cannot drift between adapters.
///
/// The effective scope is read from `payload["metadata"]["scope"]`
/// (the Store call sites pass the full serialized `Memory` as the
/// governance payload); an absent/null/unparseable value defaults to
/// [`crate::models::MemoryScope::Private`] — matching the query-layer
/// convention for unmarked rows.
#[must_use]
pub fn required_scope_refusal(
    required: crate::models::MemoryScope,
    payload: &serde_json::Value,
    action: GovernedAction,
    denied_level: GovernanceLevel,
    agent_id: &str,
    namespace: &str,
) -> Option<GovernanceRefusal> {
    let effective = payload
        .get("metadata")
        .and_then(|m| m.get("scope"))
        .and_then(serde_json::Value::as_str)
        .and_then(crate::models::MemoryScope::from_str)
        .unwrap_or(crate::models::MemoryScope::Private);
    if effective == required {
        return None;
    }
    Some(
        GovernanceRefusal::new(
            action,
            denied_level,
            agent_id,
            format!(
                "namespace requires scope '{}' but write declared scope '{}'",
                required.as_str(),
                effective.as_str()
            ),
        )
        .with_namespace(namespace),
    )
}

impl std::fmt::Display for GovernanceRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Byte-identical to pre-#963 `Deny(String)` Display: routes
        // through the canonical deny_message helper so the wire shape
        // ("<action> denied by governance: <reason>") cannot drift.
        //
        // v1.0.0 #1862 (TRACT-gap G10.2) — the render goes THROUGH the
        // read-only `crate::claim::refusal::RefusalClaim` projection so the
        // G10.2 anchor has a live constructor on every refusal-format path
        // (wired, not floating). The projection copies `action.as_str()` and
        // `reason` verbatim, so the wire string is byte-identical — pinned by
        // `claim::refusal::tests::display_is_byte_identical_through_the_projection`.
        let claim_shape = crate::claim::refusal::RefusalClaim::of_refusal(self);
        let msg = crate::governance::deny_message(
            &claim_shape.action,
            crate::governance::DenyGate::Governance,
            &claim_shape.reason,
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
    fn required_scope_refusal_none_when_scope_matches() {
        use crate::models::MemoryScope;
        let payload = serde_json::json!({ "metadata": { "scope": "private" } });
        let r = required_scope_refusal(
            MemoryScope::Private,
            &payload,
            GovernedAction::Store,
            GovernanceLevel::Any,
            "ai:bob",
            "team/prod",
        );
        assert!(r.is_none(), "matching scope must not refuse");
    }

    #[test]
    fn required_scope_refusal_absent_scope_defaults_private() {
        use crate::models::MemoryScope;
        // No scope key ⇒ defaults to private ⇒ matches a private requirement.
        let payload = serde_json::json!({ "metadata": {} });
        assert!(
            required_scope_refusal(
                MemoryScope::Private,
                &payload,
                GovernedAction::Store,
                GovernanceLevel::Any,
                "ai:bob",
                "team/prod",
            )
            .is_none()
        );
        // …but a collective requirement is unsatisfied by the private default.
        let refusal = required_scope_refusal(
            MemoryScope::Collective,
            &payload,
            GovernedAction::Store,
            GovernanceLevel::Any,
            "ai:bob",
            "team/prod",
        )
        .expect("absent-scope (private) must refuse a collective requirement");
        assert!(refusal.reason.contains("requires scope 'collective'"));
        assert!(refusal.reason.contains("private"));
        assert_eq!(refusal.namespace.as_deref(), Some("team/prod"));
    }

    #[test]
    fn required_scope_refusal_refuses_mismatch() {
        use crate::models::MemoryScope;
        let payload = serde_json::json!({ "metadata": { "scope": "collective" } });
        let refusal = required_scope_refusal(
            MemoryScope::Private,
            &payload,
            GovernedAction::Store,
            GovernanceLevel::Owner,
            "ai:bob",
            "team/prod",
        )
        .expect("scope mismatch must refuse");
        assert_eq!(refusal.denied_level, GovernanceLevel::Owner);
        assert_eq!(refusal.action, GovernedAction::Store);
        assert!(
            refusal.reason.contains("requires scope 'private'")
                && refusal.reason.contains("collective")
        );
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
