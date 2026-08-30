// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! G10.1 (#1827) — §26.5 capability-token matrix (public-API integration).
//!
//! Exercises the re-exported `ai_memory::governance::capability` surface end
//! to end: attenuation-cannot-escalate, every reject variant leaving the base
//! decision UNCHANGED with a capability-reject outcome, the wire round-trip,
//! and the legacy byte-identical posture when the feature is off.
//!
//! G10.1-WIRING (T7/T10): the gate-level matrix below exercises the WIRED
//! check point — `db::enforce_governance` (sqlite; every SAL / handler /
//! MCP / CLI path funnels through it) and, behind `--features
//! sal-postgres` with a live `AI_MEMORY_TEST_POSTGRES_URL`, the postgres
//! inline gate — asserting identical `(token, request) → decision` on
//! both backends. Because `apply_at_gate` is applied INSIDE the two
//! gates (not at call sites), covering the two gates covers every
//! wrapped caller by construction.

#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::similar_names,
    clippy::uninlined_format_args
)]

use std::collections::BTreeMap;

use ai_memory::governance::Decision;
use ai_memory::governance::capability::{
    CapReject, CapRequest, CapabilityConfig, CapabilityToken, Caveat, GrantOutcome, IssuerConfig,
    OpLevel, apply_capability_grant, attenuate, mint_with_secret, resolve_capability_issuer_pubkey,
    verify,
};
use ed25519_dalek::SigningKey;

const ISSUER: &str = "ai:issuer";
const SECRET: &[u8] = b"integration-root-secret";

fn key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn config(max_op: OpLevel, enabled: bool) -> CapabilityConfig {
    let mut issuers = BTreeMap::new();
    issuers.insert(
        ISSUER.to_string(),
        IssuerConfig {
            pubkey: key().verifying_key(),
            root_secret: SECRET.to_vec(),
            max_op,
            namespace_prefix: None,
        },
    );
    CapabilityConfig { enabled, issuers }
}

fn token(caveats: Vec<Caveat>) -> CapabilityToken {
    mint_with_secret(&key(), SECRET, ISSUER, "root-int", caveats).unwrap()
}

fn request(action: &str, ns: &str, now: i64) -> CapRequest {
    CapRequest {
        action: action.to_string(),
        namespace: ns.to_string(),
        agent_id: "ai:principal".to_string(),
        now,
    }
}

#[test]
fn wire_round_trip_is_stable() {
    let t = token(vec![
        Caveat::OpCeiling(OpLevel::Write),
        Caveat::ExpiresAt(9_999_999_999),
    ]);
    let wire = t.to_wire().unwrap();
    assert!(wire.starts_with("cap1:"));
    assert!(!wire.contains('='), "base64url must be un-padded");
    let back = CapabilityToken::from_wire(&wire).unwrap();
    assert_eq!(t, back);
    // second round trip is byte-identical
    assert_eq!(wire, back.to_wire().unwrap());
}

#[test]
fn attenuation_cannot_escalate_forge_by_removal_is_bad_chain() {
    let base = token(vec![
        Caveat::OpCeiling(OpLevel::Write),
        Caveat::ExpiresAt(9_999_999_999),
    ]);
    let cfg = config(OpLevel::Admin, true);
    // narrow to Read
    let narrowed = attenuate(&base, Caveat::OpCeiling(OpLevel::Read)).unwrap();
    // a Write op now fails on the narrowed token
    assert_eq!(
        verify(&narrowed, &cfg, &request("Store", "n", 1)),
        Err(CapReject::Caveat("op_ceiling"))
    );
    // dropping the narrowing caveat but keeping the tag → BadChain
    let mut forged = narrowed.clone();
    forged.ext_caveats.clear();
    assert_eq!(
        verify(&forged, &cfg, &request("Store", "n", 1)),
        Err(CapReject::BadChain)
    );
}

#[test]
fn every_reject_leaves_base_unchanged_and_audits_reject() {
    let cfg = config(OpLevel::Write, true);
    // #3111 — the reject path is exercised from an `Ask` (pending court)
    // base, the only flippable base; a `Deny` short-circuits to NoOp before
    // `verify` and so never produces a Rejected outcome (see
    // `deny_base_is_terminal_before_verify`).
    let base = Decision::Ask("court".to_string());

    // Build one representative token for each reject class.
    let good = token(vec![Caveat::ExpiresAt(9_999_999_999)]);

    // Expired
    let expired = token(vec![Caveat::ExpiresAt(10)]);
    // Wrong namespace
    let wrong_ns = token(vec![
        Caveat::NamespacePrefix("team".to_string()),
        Caveat::ExpiresAt(9_999_999_999),
    ]);
    // Unknown issuer (empty config)
    let empty_cfg = CapabilityConfig {
        enabled: true,
        issuers: BTreeMap::new(),
    };
    // Unsupported version
    let mut v2 = good.clone();
    v2.v = 2;
    // Tamper the chain
    let mut tampered = good.clone();
    tampered.tag = vec![0u8; tampered.tag.len()];

    let cases: Vec<(
        &str,
        &CapabilityConfig,
        &CapabilityToken,
        CapRequest,
        CapReject,
    )> = vec![
        (
            "expired",
            &cfg,
            &expired,
            request("Store", "n", 100),
            CapReject::Expired,
        ),
        (
            "wrong_ns",
            &cfg,
            &wrong_ns,
            request("Store", "other", 1),
            CapReject::Caveat("namespace_prefix"),
        ),
        (
            "unknown_issuer",
            &empty_cfg,
            &good,
            request("Store", "n", 1),
            CapReject::UnknownIssuer,
        ),
        (
            "bad_version",
            &cfg,
            &v2,
            request("Store", "n", 1),
            CapReject::UnsupportedVersion,
        ),
        (
            "bad_chain",
            &cfg,
            &tampered,
            request("Store", "n", 1),
            CapReject::BadChain,
        ),
    ];

    for (name, c, tok, req, expected) in cases {
        let (decision, outcome) = apply_capability_grant(base.clone(), c, true, Some(tok), &req);
        assert_eq!(
            decision, base,
            "{name}: base decision must be UNCHANGED on reject"
        );
        assert_eq!(
            outcome,
            GrantOutcome::Rejected(expected),
            "{name}: expected a capability-reject outcome"
        );
    }
}

#[test]
fn valid_token_lifts_ask_only_deny_is_terminal() {
    // #3111 — a token that verifies AND covers the tuple lifts only an `Ask`
    // (pending human court). An operator/rule-derived `Deny` is terminal and
    // is NEVER flipped by any token.
    let cfg = config(OpLevel::Write, true);
    let t = token(vec![
        Caveat::OpCeiling(OpLevel::Write),
        Caveat::ExpiresAt(9_999_999_999),
    ]);
    let r = request("Store", "n", 1);

    // Deny stays Deny — the covering token is not even consulted (NoOp).
    let (d, o) = apply_capability_grant(Decision::Deny("x".into()), &cfg, true, Some(&t), &r);
    assert_eq!(d, Decision::Deny("x".into()));
    assert_eq!(o, GrantOutcome::NoOp);

    // Ask lifts to Allow (no regression).
    let (d2, o2) = apply_capability_grant(Decision::Ask("court".into()), &cfg, true, Some(&t), &r);
    assert_eq!(d2, Decision::Allow);
    assert!(matches!(o2, GrantOutcome::Granted { .. }));
}

#[test]
fn deny_base_is_terminal_before_verify() {
    // #3111 — regardless of the token's validity (a perfect covering token,
    // an expired one, or a forged one), a `Deny` base returns NoOp with the
    // base byte-identical: the joiner short-circuits before `verify`, so no
    // token class can ever turn a `Deny` into `Allow` or even a `Rejected`.
    let cfg = config(OpLevel::Write, true);
    let r = request("Store", "n", 1);
    let good = token(vec![
        Caveat::OpCeiling(OpLevel::Write),
        Caveat::ExpiresAt(9_999_999_999),
    ]);
    let expired = token(vec![Caveat::ExpiresAt(10)]);
    let mut forged = good.clone();
    forged.root_sig[0] ^= 0xFF;
    for (name, tok) in [("good", &good), ("expired", &expired), ("forged", &forged)] {
        let (d, o) =
            apply_capability_grant(Decision::Deny("secrets".into()), &cfg, true, Some(tok), &r);
        assert_eq!(
            d,
            Decision::Deny("secrets".into()),
            "{name}: Deny must stand"
        );
        assert_eq!(o, GrantOutcome::NoOp, "{name}: Deny must not reach verify");
    }
}

#[test]
fn legacy_byte_identical_when_disabled_and_no_token() {
    // enabled=false + token=None ⇒ the joiner is pure identity and emits no
    // audit (NoOp), so a legacy deployment is byte-identical.
    let cfg = config(OpLevel::Admin, false);
    let r = request("Store", "n", 1);
    for base in [
        Decision::Allow,
        Decision::Deny("d".into()),
        Decision::Ask("a".into()),
    ] {
        let (d, o) = apply_capability_grant(base.clone(), &cfg, true, None, &r);
        assert_eq!(d, base);
        assert_eq!(o, GrantOutcome::NoOp);
    }
    // Even a presented token is inert while disabled.
    let t = token(vec![Caveat::ExpiresAt(9_999_999_999)]);
    let (d, o) = apply_capability_grant(Decision::Deny("d".into()), &cfg, true, Some(&t), &r);
    assert_eq!(d, Decision::Deny("d".into()));
    assert_eq!(o, GrantOutcome::NoOp);
}

#[test]
fn issuer_resolver_is_a_closed_allowlist() {
    let cfg = config(OpLevel::Admin, true);
    assert!(resolve_capability_issuer_pubkey(&cfg, ISSUER).is_some());
    // an arbitrary agent id (as would live in db::agent_pubkey) is NOT resolvable
    assert!(resolve_capability_issuer_pubkey(&cfg, "ai:random-registered-agent").is_none());
}

#[test]
fn pending_flip_requires_adequate_ceiling() {
    // Write-ceiling issuer + Admin op under an Ask base must NOT flip.
    let cfg = config(OpLevel::Write, true);
    let t = token(vec![
        Caveat::OpCeiling(OpLevel::Admin),
        Caveat::ExpiresAt(9_999_999_999),
    ]);
    let r = request("ns-admin-op", "n", 1); // op_level_of => Admin
    let (d, o) = apply_capability_grant(Decision::Ask("court".into()), &cfg, true, Some(&t), &r);
    assert_eq!(d, Decision::Ask("court".into()));
    assert!(matches!(o, GrantOutcome::Rejected(_)));
}

// ===========================================================================
// G10.1-WIRING (T7/T10) — gate-level matrix on the WIRED check point
// ===========================================================================

mod gate_wiring {
    use super::*;
    use ai_memory::config::{
        PermissionsMode, clear_capability_config_for_test, lock_capability_config_for_test,
        lock_permissions_mode_for_test, override_active_permissions_mode_for_test,
        set_active_capability_config,
    };
    use ai_memory::db;
    use ai_memory::models::{
        ApproverType, ConfidenceSource, CorePolicy, GovernanceDecision, GovernanceLevel,
        GovernancePolicy, GovernedAction, Memory, Tier, default_metadata,
    };
    use rusqlite::Connection;

    /// Seed a namespace-standard policy (same shape as the K3 mode-matrix
    /// suite) so the coarse gate produces a real Deny / Pending base.
    fn seed_policy(conn: &Connection, namespace: &str, policy: &GovernancePolicy, owner: &str) {
        let now = chrono::Utc::now().to_rfc3339();
        let mut metadata = default_metadata();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert("agent_id".into(), serde_json::Value::String(owner.into()));
            obj.insert(
                "governance".into(),
                serde_json::to_value(policy).expect("policy json"),
            );
        }
        let standard = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: format!("_standards-{namespace}"),
            title: format!("standard for {namespace}"),
            content: "policy".into(),
            tags: vec![],
            priority: 9,
            confidence: 1.0,
            source: "test".into(),
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
        let standard_id = db::insert(conn, &standard).expect("insert standard");
        db::set_namespace_standard(conn, namespace, &standard_id, None).expect("set standard");
    }

    fn policy(write: GovernanceLevel) -> GovernancePolicy {
        GovernancePolicy {
            core: CorePolicy {
                write,
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

    /// Acquire both process-global gates in a FIXED order (permissions
    /// first, then capability) so parallel tests cannot deadlock, pin
    /// Enforce, and install the capability config.
    fn pin_gates(
        cap_cfg: CapabilityConfig,
    ) -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        let perm = lock_permissions_mode_for_test();
        override_active_permissions_mode_for_test(PermissionsMode::Enforce);
        let cap = lock_capability_config_for_test();
        set_active_capability_config(cap_cfg);
        (perm, cap)
    }

    fn pending_rows(conn: &Connection, ns: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM pending_actions WHERE namespace = ?1",
            [ns],
            |r| r.get(0),
        )
        .expect("count pending")
    }

    /// #3111 — an operator/rule-derived owner-policy Deny is TERMINAL at the
    /// WIRED sqlite gate: NEITHER a valid, in-caveat covering token NOR any
    /// reject-class token flips it; the base Deny stays byte-identical to the
    /// no-token decision. (The legitimate `Pending→Allow` court lift is
    /// covered by `sqlite_gate_pending_flip_and_ceiling_court_guard`.)
    #[test]
    fn sqlite_gate_operator_deny_is_terminal_even_with_valid_token() {
        let (_perm, _cap) = pin_gates(config(OpLevel::Admin, true));
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        let ns = "g10gate/owner";
        seed_policy(&conn, ns, &policy(GovernanceLevel::Owner), "ai:alice");
        let payload = serde_json::json!({"title": "x"});

        // Baseline: no token ⇒ the coarse Deny stands.
        let base = db::enforce_governance(
            &conn,
            GovernedAction::Store,
            ns,
            "ai:mallory",
            None,
            None,
            &payload,
            None,
        )
        .unwrap();
        let base_reason = match &base {
            GovernanceDecision::Deny(refusal) => refusal.reason.clone(),
            other => panic!("owner policy must deny a non-owner store, got {other:?}"),
        };

        // #3111 — a valid, fully in-caveat covering token must NOT flip the
        // operator Deny: it is terminal, so the base refusal stands
        // byte-identical (same reason) as with no token at all.
        let good = token(vec![
            Caveat::OpCeiling(OpLevel::Write),
            Caveat::ExpiresAt(9_999_999_999),
        ]);
        let with_good = db::enforce_governance(
            &conn,
            GovernedAction::Store,
            ns,
            "ai:mallory",
            None,
            None,
            &payload,
            Some(&good),
        )
        .unwrap();
        match with_good {
            GovernanceDecision::Deny(refusal) => assert_eq!(
                refusal.reason, base_reason,
                "a valid covering token must leave the operator Deny byte-identical (#3111)"
            ),
            other => panic!("operator Deny must be terminal, got {other:?}"),
        }

        // Reject classes ⇒ base decision UNCHANGED (same refusal reason).
        let expired = token(vec![Caveat::ExpiresAt(10)]);
        let wrong_ns = token(vec![
            Caveat::NamespacePrefix("other".into()),
            Caveat::ExpiresAt(9_999_999_999),
        ]);
        let mut tampered = good.clone();
        tampered.tag = vec![0u8; tampered.tag.len()];
        let mut forged = good.clone();
        forged.root_sig[0] ^= 0xFF;
        let mut v2 = good.clone();
        v2.v = 2;
        for (name, tok) in [
            ("expired", &expired),
            ("wrong_ns", &wrong_ns),
            ("tampered_chain", &tampered),
            ("forged_root", &forged),
            ("unsupported_version", &v2),
        ] {
            let d = db::enforce_governance(
                &conn,
                GovernedAction::Store,
                ns,
                "ai:mallory",
                None,
                None,
                &payload,
                Some(tok),
            )
            .unwrap();
            match d {
                GovernanceDecision::Deny(refusal) => assert_eq!(
                    refusal.reason, base_reason,
                    "{name}: rejected token must leave the base refusal byte-identical"
                ),
                other => panic!("{name}: expected the base Deny to stand, got {other:?}"),
            }
        }
        clear_capability_config_for_test();
    }

    /// The Pending→Allow flip is explicit: a granted Approve-gated write
    /// queues NO pending row; an inadequate issuer ceiling leaves the
    /// Pending base (and its queued row) untouched.
    #[test]
    fn sqlite_gate_pending_flip_and_ceiling_court_guard() {
        let (_perm, _cap) = pin_gates(config(OpLevel::Write, true));
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        let ns = "g10gate/approve";
        seed_policy(&conn, ns, &policy(GovernanceLevel::Approve), "ai:alice");
        let payload = serde_json::json!({"title": "x"});
        let good = token(vec![
            Caveat::OpCeiling(OpLevel::Write),
            Caveat::ExpiresAt(9_999_999_999),
        ]);

        // Granted flip: Allow, and NO stray pending_actions row.
        let d = db::enforce_governance(
            &conn,
            GovernedAction::Store,
            ns,
            "ai:mallory",
            None,
            None,
            &payload,
            Some(&good),
        )
        .unwrap();
        assert!(matches!(d, GovernanceDecision::Allow), "got {d:?}");
        assert_eq!(
            pending_rows(&conn, ns),
            0,
            "a granted Pending must NOT queue an approval row"
        );

        // Issuer ceiling below the op ⇒ no flip; the court still queues.
        set_active_capability_config(config(OpLevel::Read, true));
        let d2 = db::enforce_governance(
            &conn,
            GovernedAction::Store,
            ns,
            "ai:mallory",
            None,
            None,
            &payload,
            Some(&good),
        )
        .unwrap();
        assert!(
            matches!(d2, GovernanceDecision::Pending(ref id) if !id.is_empty()),
            "a Read-ceiling issuer cannot flip a Write op past the court, got {d2:?}"
        );
        assert_eq!(pending_rows(&conn, ns), 1, "the pending row must queue");
        clear_capability_config_for_test();
    }

    /// (c) legacy byte-identical: with the feature DISABLED (even with a
    /// token presented) or with NO token (feature enabled), the decision
    /// matrix matches the committed pre-G10 baseline and the forensic
    /// audit dir gains ZERO capability rows.
    #[test]
    fn legacy_golden_matrix_disabled_or_no_token_and_audit_bytes() {
        let (_perm, _cap) = pin_gates(config(OpLevel::Admin, false));
        let audit_dir = tempfile::tempdir().expect("audit dir");
        ai_memory::governance::audit::init(audit_dir.path(), None).expect("init forensic sink");

        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        let owner_ns = "g10golden/owner";
        let approve_ns = "g10golden/approve";
        let any_ns = "g10golden/any";
        seed_policy(&conn, owner_ns, &policy(GovernanceLevel::Owner), "ai:alice");
        seed_policy(
            &conn,
            approve_ns,
            &policy(GovernanceLevel::Approve),
            "ai:alice",
        );
        seed_policy(&conn, any_ns, &policy(GovernanceLevel::Any), "ai:alice");
        let payload = serde_json::json!({"title": "x"});
        let good = token(vec![Caveat::ExpiresAt(9_999_999_999)]);

        // The committed golden baseline: (ns, agent) → decision kind.
        let golden: Vec<(&str, &str, &str)> = vec![
            (owner_ns, "ai:alice", "allow"),
            (owner_ns, "ai:mallory", "deny"),
            (approve_ns, "ai:mallory", "pending"),
            (any_ns, "ai:anyone", "allow"),
        ];
        let kind = |d: &GovernanceDecision| match d {
            GovernanceDecision::Allow => "allow",
            GovernanceDecision::Deny(_) => "deny",
            GovernanceDecision::Pending(_) => "pending",
        };

        // Pass 1 — feature DISABLED, token PRESENTED: byte-identical legacy.
        for (ns, agent, want) in &golden {
            let d = db::enforce_governance(
                &conn,
                GovernedAction::Store,
                ns,
                agent,
                None,
                None,
                &payload,
                Some(&good),
            )
            .unwrap();
            assert_eq!(kind(&d), *want, "disabled+token: {ns}/{agent}");
        }
        // Pass 2 — feature ENABLED, NO token: byte-identical legacy.
        set_active_capability_config(config(OpLevel::Admin, true));
        for (ns, agent, want) in &golden {
            let d = db::enforce_governance(
                &conn,
                GovernedAction::Store,
                ns,
                agent,
                None,
                None,
                &payload,
                None,
            )
            .unwrap();
            assert_eq!(kind(&d), *want, "enabled+no-token: {ns}/{agent}");
        }
        // Pass 3 — edge parse while DISABLED emits nothing and yields
        // Ok(None) WITHOUT parsing (the feature-off leg is unchanged by the
        // fail-closed fix: a disabled feature must stay byte-inert).
        set_active_capability_config(config(OpLevel::Admin, false));
        assert_eq!(
            ai_memory::governance::capability::parse_presented_token(
                Some("cap1:!!!garbage"),
                "ai:mallory"
            ),
            Ok(None)
        );

        // ZERO capability-* audit rows across all three passes.
        ai_memory::governance::audit::flush_blocking();
        let rows = read_forensic_rows(audit_dir.path());
        let cap_rows: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| {
                r["kind"]
                    .as_str()
                    .is_some_and(|k| k.starts_with("capability-"))
            })
            .collect();
        assert!(
            cap_rows.is_empty(),
            "legacy passes must emit ZERO capability audit bytes, got {cap_rows:?}"
        );
        ai_memory::governance::audit::shutdown();
        clear_capability_config_for_test();
    }

    /// A grant and a reject at the wired gate each land a forensic audit row
    /// (capability-grant / capability-reject) — both from an `Approve`
    /// (pending court) base, the only flippable base (#3111). A malformed
    /// edge presentation (feature ON) lands a DENY capability-reject
    /// (fail-closed fix: the edge parse now refuses the request, so the
    /// forensic decision is `deny`, not the pre-fix advisory `warn`). And a
    /// terminal operator `Deny` (owner policy) emits ZERO capability rows even
    /// with a perfect covering token.
    #[test]
    fn audit_rows_for_grant_reject_and_edge_parse() {
        let (_perm, _cap) = pin_gates(config(OpLevel::Admin, true));
        let audit_dir = tempfile::tempdir().expect("audit dir");
        ai_memory::governance::audit::init(audit_dir.path(), None).expect("init forensic sink");

        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        // Grant / reject rows come from a pending (approve) base.
        let ns = "g10audit/approve";
        seed_policy(&conn, ns, &policy(GovernanceLevel::Approve), "ai:alice");
        // Terminal-Deny namespace: an owner policy that must emit NO cap rows.
        let deny_ns = "g10audit/owner";
        seed_policy(&conn, deny_ns, &policy(GovernanceLevel::Owner), "ai:alice");
        let payload = serde_json::json!({"title": "x"});

        let good = token(vec![
            Caveat::OpCeiling(OpLevel::Write),
            Caveat::ExpiresAt(9_999_999_999),
        ]);
        let expired = token(vec![Caveat::ExpiresAt(10)]);
        // Grant: good token lifts the pending court → capability-grant row.
        let _ = db::enforce_governance(
            &conn,
            GovernedAction::Store,
            ns,
            "ai:mallory",
            None,
            None,
            &payload,
            Some(&good),
        )
        .unwrap();
        // Reject: expired token against the pending base → capability-reject.
        let _ = db::enforce_governance(
            &conn,
            GovernedAction::Store,
            ns,
            "ai:mallory",
            None,
            None,
            &payload,
            Some(&expired),
        )
        .unwrap();
        // Terminal Deny: even a perfect covering token emits NO capability
        // row (the joiner short-circuits to NoOp before any audit).
        let _ = db::enforce_governance(
            &conn,
            GovernedAction::Store,
            deny_ns,
            "ai:mallory",
            None,
            None,
            &payload,
            Some(&good),
        )
        .unwrap();
        // Malformed edge presentation with the feature ON is now a TYPED
        // REFUSAL (fail-closed) rather than a silent downgrade to `None`.
        assert!(
            ai_memory::governance::capability::parse_presented_token(
                Some("cap1:!!!garbage"),
                "ai:mallory"
            )
            .is_err()
        );

        ai_memory::governance::audit::flush_blocking();
        let rows = read_forensic_rows(audit_dir.path());
        let grant = rows.iter().find(|r| {
            r["kind"].as_str() == Some("capability-grant") && r["payload"]["namespace"] == ns
        });
        let grant = grant.expect("a capability-grant row must land");
        assert_eq!(grant["decision"], "allow");
        assert_eq!(grant["payload"]["flipped_from"], "pending");
        assert_eq!(grant["payload"]["issuer"], ISSUER);
        assert_eq!(grant["actor"], "ai:mallory");

        let reject = rows.iter().find(|r| {
            r["kind"].as_str() == Some("capability-reject")
                && r["payload"]["namespace"] == ns
                && r["rule_id"] == "expired"
        });
        assert!(reject.is_some(), "a capability-reject row must land");

        // #3111 — the terminal-Deny namespace emitted ZERO capability rows.
        let deny_cap_rows: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| {
                r["payload"]["namespace"] == deny_ns
                    && r["kind"]
                        .as_str()
                        .is_some_and(|k| k.starts_with("capability-"))
            })
            .collect();
        assert!(
            deny_cap_rows.is_empty(),
            "a terminal operator Deny must emit ZERO capability rows, got {deny_cap_rows:?}"
        );

        let parse_deny = rows.iter().find(|r| {
            r["kind"].as_str() == Some("capability-reject")
                && r["decision"] == "deny"
                && r["payload"]["stage"] == "edge-parse"
        });
        assert!(
            parse_deny.is_some(),
            "malformed edge parse must DENY-audit (fail-closed)"
        );

        ai_memory::governance::audit::shutdown();
        clear_capability_config_for_test();
    }

    /// Read every forensic JSONL row under `dir`.
    fn read_forensic_rows(dir: &std::path::Path) -> Vec<serde_json::Value> {
        let mut rows = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return rows;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !std::path::Path::new(name)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"))
            {
                continue;
            }
            let Ok(contents) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            for line in contents.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(v) = serde_json::from_str(line) {
                    rows.push(v);
                }
            }
        }
        rows
    }
}

// ===========================================================================
// G10.1-WIRING (T10 parity) — dual-backend matrix: identical
// (token, request) → decision on sqlite AND postgres. Both gates carry the
// capability joiner INSIDE (`apply_at_gate`), so this matrix covers every
// wrapped call site on both backends by construction.
// ===========================================================================

#[cfg(feature = "sal-postgres")]
mod pg_parity {
    use super::*;
    use ai_memory::config::{
        PermissionsMode, clear_capability_config_for_test, lock_capability_config_for_test,
        lock_permissions_mode_for_test, override_active_permissions_mode_for_test,
        set_active_capability_config,
    };
    use ai_memory::models::GovernanceDecision;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::sqlite::SqliteStore;
    use ai_memory::store::{GovernedAction, MemoryStore};

    fn postgres_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
    }

    /// Seed the same standard/policy shape on postgres that the sqlite
    /// side seeds via `db::set_namespace_standard`.
    async fn seed_standard_pg(
        pool: &sqlx::PgPool,
        namespace: &str,
        owner: &str,
        policy: serde_json::Value,
    ) {
        let standard_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let metadata = serde_json::json!({ "agent_id": owner, "governance": policy });
        sqlx::query(
            "INSERT INTO memories (
                id, tier, namespace, title, content, tags, priority, confidence,
                source, access_count, created_at, updated_at, metadata
            ) VALUES ($1, 'long', $2, $3, 'standard', '[]'::jsonb, 5, 1.0,
                      'test', 0, $4, $4, $5)",
        )
        .bind(&standard_id)
        .bind(namespace)
        .bind(format!("standard:{namespace}"))
        .bind(now)
        .bind(&metadata)
        .execute(pool)
        .await
        .expect("seed standard memory");
        sqlx::query(
            "INSERT INTO namespace_meta (namespace, standard_id, parent_namespace) \
             VALUES ($1, $2, NULL) \
             ON CONFLICT (namespace) DO UPDATE SET standard_id = EXCLUDED.standard_id",
        )
        .bind(namespace)
        .bind(&standard_id)
        .execute(pool)
        .await
        .expect("seed namespace_meta");
    }

    fn seed_standard_sqlite(conn: &rusqlite::Connection, namespace: &str, owner: &str) {
        use ai_memory::models::{
            ApproverType, ConfidenceSource, CorePolicy, GovernanceLevel, GovernancePolicy, Memory,
            Tier, default_metadata,
        };
        let policy = GovernancePolicy {
            core: CorePolicy {
                write: GovernanceLevel::Owner,
                promote: GovernanceLevel::Any,
                delete: GovernanceLevel::Owner,
                approver: ApproverType::Human,
                inherit: true,
                max_reflection_depth: None,
                required_scope: None,
            },
            ..Default::default()
        };
        let now = chrono::Utc::now().to_rfc3339();
        let mut metadata = default_metadata();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert("agent_id".into(), serde_json::Value::String(owner.into()));
            obj.insert(
                "governance".into(),
                serde_json::to_value(&policy).expect("policy json"),
            );
        }
        let standard = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: format!("_standards-{namespace}"),
            title: format!("standard for {namespace}"),
            content: "policy".into(),
            tags: vec![],
            priority: 9,
            confidence: 1.0,
            source: "test".into(),
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
        let standard_id = ai_memory::db::insert(conn, &standard).expect("insert standard");
        ai_memory::db::set_namespace_standard(conn, namespace, &standard_id, None)
            .expect("set standard");
    }

    fn kind(d: &GovernanceDecision) -> &'static str {
        match d {
            GovernanceDecision::Allow => "allow",
            GovernanceDecision::Deny(_) => "deny",
            GovernanceDecision::Pending(_) => "pending",
        }
    }

    /// The §26.5 parity matrix: identical `(token, request) → decision`
    /// behind the sqlite SAL gate, the sqlite free-fn gate, and the
    /// postgres inline gate.
    // The two process-global guards are deliberately held across awaits:
    // they serialize the permissions-mode + capability-config globals for
    // the whole matrix (single test on a current-thread runtime — no
    // executor-level deadlock is possible).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn capability_matrix_identical_on_sqlite_and_postgres() {
        let Some(url) = postgres_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let _perm = lock_permissions_mode_for_test();
        override_active_permissions_mode_for_test(PermissionsMode::Enforce);
        let _cap = lock_capability_config_for_test();
        set_active_capability_config(config(OpLevel::Write, true));

        // Same namespace string on BOTH backends so one token covers both.
        let suffix = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let ns = format!("g10parity-{suffix}/owner");
        let owner = "ai:parity-owner";
        let intruder = "ai:parity-intruder";

        // sqlite side (temp file DB behind the SAL adapter).
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("parity.db");
        {
            let conn = ai_memory::db::open(&db_path).expect("open sqlite");
            seed_standard_sqlite(&conn, &ns, owner);
        }
        let sqlite_store = SqliteStore::open(&db_path).expect("open SqliteStore");

        // postgres side.
        let pg_store = PostgresStore::connect(&url).await.expect("connect pg");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("test pool");
        seed_standard_pg(
            &pool,
            &ns,
            owner,
            serde_json::json!({ "write": "owner", "promote": "any", "delete": "owner" }),
        )
        .await;

        let good = token(vec![
            Caveat::NamespacePrefix(format!("g10parity-{suffix}")),
            Caveat::OpCeiling(OpLevel::Write),
            Caveat::ExpiresAt(9_999_999_999),
        ]);
        let expired = token(vec![Caveat::ExpiresAt(10)]);
        let wrong_ns = token(vec![
            Caveat::NamespacePrefix("elsewhere".into()),
            Caveat::ExpiresAt(9_999_999_999),
        ]);
        let mut tampered = good.clone();
        tampered.tag = vec![0u8; tampered.tag.len()];
        let agent_bound_other = token(vec![
            Caveat::Agent("ai:someone-else".into()),
            Caveat::ExpiresAt(9_999_999_999),
        ]);

        let payload = serde_json::json!({"title": "parity"});
        let cases: Vec<(&str, Option<&CapabilityToken>, &str, &str)> = vec![
            ("no_token", None, intruder, "deny"),
            // #3111 — the owner-policy Deny is a terminal operator refusal; a
            // valid, fully covering token must NOT flip it on EITHER backend.
            ("valid", Some(&good), intruder, "deny"),
            ("expired", Some(&expired), intruder, "deny"),
            ("wrong_ns", Some(&wrong_ns), intruder, "deny"),
            ("tampered", Some(&tampered), intruder, "deny"),
            (
                "agent_bound_other",
                Some(&agent_bound_other),
                intruder,
                "deny",
            ),
            ("owner_no_token", None, owner, "allow"),
        ];

        for (name, tok, agent, want) in cases {
            let sq = sqlite_store
                .enforce_governance_action(
                    GovernedAction::Store,
                    &ns,
                    agent,
                    None,
                    None,
                    &payload,
                    tok,
                )
                .await
                .expect("sqlite SAL gate");
            let pg = pg_store
                .enforce_governance_action(
                    GovernedAction::Store,
                    &ns,
                    agent,
                    None,
                    None,
                    &payload,
                    tok,
                )
                .await
                .expect("postgres gate");
            assert_eq!(kind(&sq), want, "{name}: sqlite decision drifted");
            assert_eq!(
                kind(&sq),
                kind(&pg),
                "{name}: sqlite/postgres parity broke (sqlite={sq:?}, pg={pg:?})"
            );
            // The free-fn sqlite gate (the path every handler/MCP/CLI
            // caller funnels through) must agree with the SAL surface.
            let conn = ai_memory::db::open(&db_path).expect("open sqlite");
            let free = ai_memory::db::enforce_governance(
                &conn,
                ai_memory::models::GovernedAction::Store,
                &ns,
                agent,
                None,
                None,
                &payload,
                tok,
            )
            .expect("free-fn gate");
            assert_eq!(kind(&sq), kind(&free), "{name}: SAL vs free-fn drifted");
        }

        // cleanup pg rows
        let _ = sqlx::query("DELETE FROM pending_actions WHERE namespace LIKE $1")
            .bind(format!("g10parity-{suffix}%"))
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM namespace_meta WHERE namespace LIKE $1")
            .bind(format!("g10parity-{suffix}%"))
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM memories WHERE namespace LIKE $1")
            .bind(format!("g10parity-{suffix}%"))
            .execute(&pool)
            .await;
        clear_capability_config_for_test();
    }
}
