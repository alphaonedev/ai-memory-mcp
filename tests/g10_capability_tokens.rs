// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! G10.1 (#1827) — §26.5 capability-token matrix (public-API integration).
//!
//! Exercises the re-exported `ai_memory::governance::capability` surface end
//! to end: attenuation-cannot-escalate, every reject variant leaving the base
//! decision UNCHANGED with a capability-reject outcome, the wire round-trip,
//! and the legacy byte-identical posture when the feature is off.
//!
//! NOTE (scope): the DUAL-BACKEND parity matrix asserting `apply_capability_grant`
//! fires at every WIRED check-point on sqlite + postgres is DEFERRED with the
//! gate-integration wiring (T6/T7); #1827 stays open for it. This file covers
//! the stateless primitive that wiring will call.

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
    let base = Decision::Deny("policy".to_string());

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
fn valid_token_flips_deny_and_ask() {
    let cfg = config(OpLevel::Write, true);
    let t = token(vec![
        Caveat::OpCeiling(OpLevel::Write),
        Caveat::ExpiresAt(9_999_999_999),
    ]);
    let r = request("Store", "n", 1);

    let (d, o) = apply_capability_grant(Decision::Deny("x".into()), &cfg, true, Some(&t), &r);
    assert_eq!(d, Decision::Allow);
    assert!(matches!(o, GrantOutcome::Granted { .. }));

    let (d2, o2) = apply_capability_grant(Decision::Ask("court".into()), &cfg, true, Some(&t), &r);
    assert_eq!(d2, Decision::Allow);
    assert!(matches!(o2, GrantOutcome::Granted { .. }));
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
