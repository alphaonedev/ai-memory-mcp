// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
#![allow(clippy::doc_lazy_continuation)]

//
// v0.7.0 K3 — `permissions.mode` consulted by gate.
//
// Closes the v0.6.3.1 honest-Capabilities-v2 disclosure that
// `permissions.mode = "advisory"` was advertised but the gate itself
// returned `Deny`/`Pending` regardless of the knob.
//
// Each scenario seeds the same parent governance policy (`Approve`-
// gated write at `alphaone/secure`) and walks the same payload
// through `db::enforce_governance` against a child namespace. The
// only thing that varies is the active `PermissionsMode`, and each
// mode is asserted to produce its documented outcome:
//
//   - `Enforce`   → `Pending(_)` returned, `pending_actions` row queued
//   - `Advisory`  → `Allow` returned, no `pending_actions` row, warn log
//   - `Off`       → `Allow` returned, no policy resolution, no log
//
// CUTLINE-PROTECTED: K3 is the load-bearing demonstration that the
// permission gate honors the advertised mode. Failures here regress
// the v0.7.0 honest-disclosure remediation.

use ai_memory::config::{
    PermissionsMode, clear_permissions_mode_override_for_test, lock_permissions_mode_for_test,
    override_active_permissions_mode_for_test, permissions_decision_counts,
    reset_permissions_decision_counts_for_test,
};
use ai_memory::db;
use ai_memory::models::ConfidenceSource;
use ai_memory::models::{
    ApproverType, CorePolicy, GovernanceDecision, GovernanceLevel, GovernancePolicy,
    GovernedAction, Memory, Tier, default_metadata,
};
use rusqlite::Connection;

fn seed_policy(
    conn: &Connection,
    namespace: &str,
    policy: &GovernancePolicy,
    owner_agent_id: &str,
) {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert(
            "agent_id".to_string(),
            serde_json::Value::String(owner_agent_id.to_string()),
        );
        obj.insert(
            "governance".to_string(),
            serde_json::to_value(policy).unwrap(),
        );
    }
    let standard = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: format!("_standards-{namespace}"),
        title: format!("standard for {namespace}"),
        content: "policy".to_string(),
        tags: vec![],
        priority: 9,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    };
    let standard_id = db::insert(conn, &standard).unwrap();
    db::set_namespace_standard(conn, namespace, &standard_id, None).unwrap();
}

fn approve_write_policy() -> GovernancePolicy {
    GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Approve,
            promote: GovernanceLevel::Any,
            delete: GovernanceLevel::Owner,
            approver: ApproverType::Human,
            inherit: true,
            max_reflection_depth: None,
            required_scope: None,
        },
        ..Default::default()
    }
}

/// `enforce` mode is the historical strict path — the K1 cutline
/// codifies it. K3 reaffirms it from the mode-matrix angle: gate
/// returns `Pending(_)` and a `pending_actions` row lands.
#[test]
fn k3_enforce_mode_blocks_with_pending() {
    let _guard = lock_permissions_mode_for_test();
    override_active_permissions_mode_for_test(PermissionsMode::Enforce);
    reset_permissions_decision_counts_for_test();

    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    seed_policy(&conn, "alphaone/secure", &approve_write_policy(), "alice");

    let leaf = "alphaone/secure/team-a";
    let payload = serde_json::json!({"title": "k3-enforce"});
    let decision = db::enforce_governance(
        &conn,
        GovernedAction::Store,
        leaf,
        "bob",
        None,
        None,
        &payload,
        None,
    )
    .expect("gate must not error in Enforce mode");

    match decision {
        GovernanceDecision::Pending(pid) => {
            assert!(!pid.is_empty(), "Enforce queues a pending_id");
            let pending = db::list_pending_actions(&conn, Some("pending"), 10).unwrap();
            assert!(
                pending
                    .iter()
                    .any(|pa| pa.id == pid && pa.namespace == leaf),
                "Enforce mode must persist the pending_actions row"
            );
        }
        other => panic!("Enforce mode must return Pending(_), got {other:?}"),
    }

    let counts = permissions_decision_counts();
    assert_eq!(counts.enforce, 1, "Enforce decision counter must increment");
    assert_eq!(counts.advisory, 0);
    assert_eq!(counts.off, 0);

    clear_permissions_mode_override_for_test();
}

/// REGRESSION (fail-open fix) — with the OPT-IN strict admission posture
/// engaged, a namespace whose chain resolves NO policy must be REFUSED under
/// `enforce`, not silently allowed.
///
/// `enforce_governance` returns `Allow` from the
/// `resolve_governance_policy == None` arm unconditionally, so a namespace
/// the operator BELIEVED was covered (a typo, or a sibling of a governed
/// tree) skips the approval / owner / `required_scope` gates entirely. That
/// remains the DEFAULT (see `ungoverned_namespace_allows_by_default_under_enforce`
/// below — it is a cutline-protected ship-gate contract); this knob is how an
/// operator who means "govern everything" gets the fail-closed posture.
#[test]
fn enforce_mode_ungoverned_namespace_is_deny_under_strict_posture() {
    let _guard = lock_permissions_mode_for_test();
    override_active_permissions_mode_for_test(PermissionsMode::Enforce);
    // SAFETY-of-scope: single-threaded within the mode lock; removed below.
    unsafe { std::env::set_var(ai_memory::governance::ENV_REQUIRE_GOVERNED_NAMESPACE, "1") };

    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    // NOTHING seeded for this namespace — that IS the reproduction.
    let payload = serde_json::json!({"title": "ungoverned"});
    let decision = db::enforce_governance(
        &conn,
        GovernedAction::Store,
        "brand-new-tenant/scratch",
        "mallory",
        None,
        None,
        &payload,
        None,
    )
    .expect("gate must not error");

    unsafe { std::env::remove_var(ai_memory::governance::ENV_REQUIRE_GOVERNED_NAMESPACE) };

    match decision {
        GovernanceDecision::Deny(refusal) => {
            assert_eq!(
                refusal.reason,
                ai_memory::governance::UNGOVERNED_NAMESPACE_REASON
            );
            assert_eq!(
                refusal.namespace.as_deref(),
                Some("brand-new-tenant/scratch")
            );
            // The message must be ACTIONABLE — every remedy named.
            assert!(refusal.reason.contains("memory_namespace_set_standard"));
            assert!(refusal.reason.contains("advisory"));
            assert!(
                refusal
                    .reason
                    .contains(ai_memory::governance::ENV_REQUIRE_GOVERNED_NAMESPACE)
            );
        }
        other => panic!("enforce + strict posture + no policy must REFUSE, got {other:?}"),
    }

    clear_permissions_mode_override_for_test();
}

/// THE DEFAULT MUST NOT CHANGE — with the knob unset, an ungoverned namespace
/// still ALLOWS under `enforce`.
///
/// This is load-bearing, not a nicety. `AppConfig::effective_permissions_mode`
/// resolves an unconfigured `[permissions]` block to `Enforce`
/// (`governance::default_v07_secure_mode`), so `enforce` + no policy IS the
/// out-of-the-box posture; and `tests/ship_gate_governance_inheritance.rs` is
/// CUTLINE-PROTECTED on "ungoverned subtrees remain opt-in (compatibility
/// preserved)" even while a sibling subtree IS governed. Flipping this default
/// is a product-semantics decision, not remediation.
#[test]
fn ungoverned_namespace_allows_by_default_under_enforce() {
    let _guard = lock_permissions_mode_for_test();
    unsafe { std::env::remove_var(ai_memory::governance::ENV_REQUIRE_GOVERNED_NAMESPACE) };
    override_active_permissions_mode_for_test(PermissionsMode::Enforce);

    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    // A GOVERNED sibling subtree — the multi-tenant shape the ship gate pins.
    seed_policy(&conn, "alphaone/secure", &approve_write_policy(), "alice");
    let payload = serde_json::json!({"title": "ungoverned-default"});
    let decision = db::enforce_governance(
        &conn,
        GovernedAction::Store,
        "betatwo/free",
        "mallory",
        None,
        None,
        &payload,
        None,
    )
    .expect("gate must not error");
    assert!(
        matches!(decision, GovernanceDecision::Allow),
        "opt-in enforcement is preserved verbatim by default, even with a governed \
         sibling subtree present; got {decision:?}"
    );

    clear_permissions_mode_override_for_test();
}

/// `advisory` is UNCHANGED even with the strict posture engaged: it logs
/// rather than blocks, by contract.
#[test]
fn advisory_mode_no_policy_still_allows_under_strict_posture() {
    let _guard = lock_permissions_mode_for_test();
    override_active_permissions_mode_for_test(PermissionsMode::Advisory);
    // SAFETY-of-scope: single-threaded within the mode lock; removed below.
    unsafe { std::env::set_var(ai_memory::governance::ENV_REQUIRE_GOVERNED_NAMESPACE, "1") };

    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let payload = serde_json::json!({"title": "ungoverned-advisory"});
    let decision = db::enforce_governance(
        &conn,
        GovernedAction::Store,
        "brand-new-tenant/scratch",
        "mallory",
        None,
        None,
        &payload,
        None,
    )
    .expect("gate must not error");

    unsafe { std::env::remove_var(ai_memory::governance::ENV_REQUIRE_GOVERNED_NAMESPACE) };
    assert!(matches!(decision, GovernanceDecision::Allow));

    clear_permissions_mode_override_for_test();
}

/// Fable HIGH (#3133): the strict-admission resolver must accept the house
/// truthy grammar (`1`/`true`/`yes`/`on`), not only `1`/`true`. A `=yes`
/// that silently stays FAIL-OPEN is the defect.
#[test]
fn require_governed_namespace_uses_shared_truthy_grammar() {
    let _guard = lock_permissions_mode_for_test();
    let env = ai_memory::governance::ENV_REQUIRE_GOVERNED_NAMESPACE;
    unsafe { std::env::remove_var(env) };
    assert!(
        !ai_memory::governance::require_governed_namespace(),
        "unset must stay the legacy Allow posture"
    );
    for truthy in ["1", "true", "TRUE", "yes", "on", "Yes", "ON"] {
        unsafe { std::env::set_var(env, truthy) };
        assert!(
            ai_memory::governance::require_governed_namespace(),
            "truthy token {truthy:?} must engage the strict posture"
        );
    }
    for falsy in ["0", "false", "enable", "enabled", "", "2"] {
        unsafe { std::env::set_var(env, falsy) };
        assert!(
            !ai_memory::governance::require_governed_namespace(),
            "non-truthy token {falsy:?} must NOT engage the strict posture"
        );
    }
    unsafe { std::env::remove_var(env) };
}

/// `advisory` mode is the v0.7.0 default for upgrading operators —
/// governance metadata is recorded but the gate logs and allows. The
/// would-be `Pending` is suppressed: no `pending_actions` row is
/// queued (so the approver pipeline does not see phantom work) and
/// the caller observes `Allow`.
#[test]
fn k3_advisory_mode_logs_and_allows_no_pending_row() {
    let _guard = lock_permissions_mode_for_test();
    override_active_permissions_mode_for_test(PermissionsMode::Advisory);
    reset_permissions_decision_counts_for_test();

    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    seed_policy(&conn, "alphaone/secure", &approve_write_policy(), "alice");

    let leaf = "alphaone/secure/team-a";
    let payload = serde_json::json!({"title": "k3-advisory"});

    let pending_before = db::list_pending_actions(&conn, Some("pending"), 10)
        .unwrap()
        .len();

    let decision = db::enforce_governance(
        &conn,
        GovernedAction::Store,
        leaf,
        "bob",
        None,
        None,
        &payload,
        None,
    )
    .expect("gate must not error in Advisory mode");

    assert!(
        matches!(decision, GovernanceDecision::Allow),
        "Advisory mode must Allow even when policy would have queued: got {decision:?}"
    );

    let pending_after = db::list_pending_actions(&conn, Some("pending"), 10)
        .unwrap()
        .len();
    assert_eq!(
        pending_before, pending_after,
        "Advisory mode must NOT queue a pending_actions row"
    );

    let counts = permissions_decision_counts();
    assert_eq!(
        counts.advisory, 1,
        "Advisory decision counter must increment"
    );
    assert_eq!(counts.enforce, 0);
    assert_eq!(counts.off, 0);

    clear_permissions_mode_override_for_test();
}

/// `off` mode skips the gate entirely — no policy resolution, no
/// pending row, no warn log. This is the freeze-thaw escape hatch
/// for incident response.
#[test]
fn k3_off_mode_skips_gate_entirely() {
    let _guard = lock_permissions_mode_for_test();
    override_active_permissions_mode_for_test(PermissionsMode::Off);
    reset_permissions_decision_counts_for_test();

    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    seed_policy(&conn, "alphaone/secure", &approve_write_policy(), "alice");

    let leaf = "alphaone/secure/team-a";
    let payload = serde_json::json!({"title": "k3-off"});

    let pending_before = db::list_pending_actions(&conn, Some("pending"), 10)
        .unwrap()
        .len();

    let decision = db::enforce_governance(
        &conn,
        GovernedAction::Store,
        leaf,
        "bob",
        None,
        None,
        &payload,
        None,
    )
    .expect("gate must not error in Off mode");

    assert!(
        matches!(decision, GovernanceDecision::Allow),
        "Off mode must Allow without consulting policy: got {decision:?}"
    );

    let pending_after = db::list_pending_actions(&conn, Some("pending"), 10)
        .unwrap()
        .len();
    assert_eq!(
        pending_before, pending_after,
        "Off mode must NOT touch pending_actions"
    );

    let counts = permissions_decision_counts();
    assert_eq!(counts.off, 1, "Off decision counter must increment");
    assert_eq!(counts.enforce, 0);
    assert_eq!(counts.advisory, 0);

    clear_permissions_mode_override_for_test();
}

/// Capabilities surface — the active mode + decision counts must be
/// observable through the canonical capabilities response so doctor
/// + remote operators can verify the gate posture. With the mode
///   pinned to `enforce` and one decision recorded, the shape is:
///   `{ mode: "enforce", decision_counts: { enforce: 1, ... } }`.
#[test]
fn k3_capabilities_reports_active_mode_and_decision_counts() {
    let _guard = lock_permissions_mode_for_test();
    override_active_permissions_mode_for_test(PermissionsMode::Enforce);
    reset_permissions_decision_counts_for_test();

    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    seed_policy(&conn, "alphaone/secure", &approve_write_policy(), "alice");
    let _ = db::enforce_governance(
        &conn,
        GovernedAction::Store,
        "alphaone/secure",
        "bob",
        None,
        None,
        &serde_json::json!({"title": "caps-probe"}),
        None,
    )
    .unwrap();

    let caps = ai_memory::config::FeatureTier::Keyword
        .config()
        .capabilities();
    let v: serde_json::Value = serde_json::to_value(&caps).unwrap();
    assert_eq!(v["permissions"]["mode"], "enforce");
    assert_eq!(v["permissions"]["decision_counts"]["enforce"], 1);
    assert_eq!(v["permissions"]["decision_counts"]["advisory"], 0);
    assert_eq!(v["permissions"]["decision_counts"]["off"], 0);

    clear_permissions_mode_override_for_test();
}
