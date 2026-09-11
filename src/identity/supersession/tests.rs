// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use super::*;
use serde_json::json;

const OWNER: &str = "ai:supersession-3587";

fn principal(id: &str) -> SupersessionPrincipal {
    let mut headers = HeaderMap::new();
    headers.insert("x-agent-id", id.parse().expect("header"));
    SupersessionPrincipal::from_http_headers(&headers)
        .expect("valid header")
        .expect("present")
}

fn pair() -> (Memory, Memory) {
    let old = Memory {
        id: "old-3587".into(),
        namespace: "rulings-3587".into(),
        title: "previous ruling".into(),
        content: "previous content".into(),
        created_at: "2026-09-10T00:00:00+00:00".into(),
        metadata: json!({"agent_id": OWNER, "ruling_key": "release-policy"}),
        ..Memory::default()
    };
    let new = Memory {
        id: "new-3587".into(),
        title: "replacement ruling".into(),
        content: "replacement content".into(),
        created_at: "2026-09-11T00:00:00+00:00".into(),
        ..old.clone()
    };
    (old, new)
}

fn assert_refused(decision: SupersessionDecision<'_>, expected: SupersessionRefusal) {
    assert!(
        matches!(decision, SupersessionDecision::Refused(actual) if actual == expected),
        "expected {expected:?}, got {decision:?}"
    );
}

#[test]
fn owner_allowed_and_untrusted_claims_refused_3587() {
    let (old, mut new) = pair();
    new.metadata["attest_level"] = json!("agent_attested");
    new.metadata["clientInfo"] = json!({"name": OWNER});
    new.priority = 10;
    assert_refused(
        authorize_supersession(None, false, &[], &old, &new),
        SupersessionRefusal::UnauthenticatedPrincipal,
    );
    let owner = principal(OWNER);
    let SupersessionDecision::Authorized(token) =
        authorize_supersession(Some(&owner), false, &[], &old, &new)
    else {
        panic!("owner must be authorized");
    };
    assert_eq!(token.old().id, old.id);
    assert_eq!(token.new_memory().id, new.id);
    assert_eq!(token.principal().agent_id(), OWNER);
    assert_eq!(token.principal().source(), PrincipalSource::HttpHeader);
    assert!(!token.as_admin());
}

#[test]
fn header_absent_invalid_and_ambiguous_are_not_principals_3587() {
    let mut headers = HeaderMap::new();
    assert!(
        SupersessionPrincipal::from_http_headers(&headers)
            .expect("absent")
            .is_none()
    );
    for invalid in [
        "",
        " ",
        "not an agent",
        "anonymous:invalid",
        "anonymous:req-123",
    ] {
        headers.insert("x-agent-id", invalid.parse().expect("header"));
        assert!(
            SupersessionPrincipal::from_http_headers(&headers).is_err(),
            "{invalid}"
        );
    }
    headers.insert("x-agent-id", OWNER.parse().expect("header"));
    headers.append("x-agent-id", OWNER.parse().expect("header"));
    assert!(SupersessionPrincipal::from_http_headers(&headers).is_err());
}

#[test]
fn nonowner_and_unowned_legacy_refused_even_with_inbox_target_3587() {
    let (mut old, new) = pair();
    let other = principal("ai:other-3587");
    old.metadata["target_agent_id"] = json!(other.agent_id());
    assert_refused(
        authorize_supersession(Some(&other), false, &[], &old, &new),
        SupersessionRefusal::OwnerMismatch,
    );
    for invalid in [json!(null), json!(""), json!(17), json!("not an agent")] {
        old.metadata["agent_id"] = invalid;
        assert_refused(
            authorize_supersession(Some(&other), true, &[other.agent_id().into()], &old, &new),
            SupersessionRefusal::UnownedPredecessor,
        );
    }
}

#[test]
fn admin_requires_both_explicit_mode_and_exact_allowlist_3587() {
    let (old, new) = pair();
    let admin = principal("ai:admin-3587");
    let allowed = vec![admin.agent_id().to_owned()];
    assert_refused(
        authorize_supersession(Some(&admin), false, &allowed, &old, &new),
        SupersessionRefusal::OwnerMismatch,
    );
    assert_refused(
        authorize_supersession(Some(&admin), true, &[], &old, &new),
        SupersessionRefusal::AdminNotAllowed,
    );
    assert_refused(
        authorize_supersession(Some(&admin), true, &["ai:admin-*".into()], &old, &new),
        SupersessionRefusal::AdminNotAllowed,
    );
    assert!(
        matches!(authorize_supersession(Some(&admin), true, &allowed, &old, &new),
        SupersessionDecision::Authorized(token) if token.as_admin())
    );
}

#[test]
fn actual_id_alias_and_namespace_prefix_refused_3587() {
    let (old, mut new) = pair();
    let owner = principal(OWNER);
    new.id.clone_from(&old.id);
    assert_refused(
        authorize_supersession(Some(&owner), false, &[], &old, &new),
        SupersessionRefusal::SameId,
    );
    new.id = "fresh-3587".into();
    new.namespace.push_str("/child");
    assert_refused(
        authorize_supersession(Some(&owner), false, &[], &old, &new),
        SupersessionRefusal::NamespaceMismatch,
    );
}

#[test]
fn timestamps_compare_instants_not_offset_strings_3587() {
    let (old, mut new) = pair();
    let owner = principal(OWNER);
    for not_newer in [
        "invalid",
        "2026-09-09T23:59:59Z",
        "2026-09-10T01:00:00+01:00",
    ] {
        new.created_at = not_newer.into();
        assert_refused(
            authorize_supersession(Some(&owner), false, &[], &old, &new),
            SupersessionRefusal::NotStrictlyNewer,
        );
    }
    new.created_at = "2026-09-09T23:00:01-01:00".into();
    assert!(matches!(
        authorize_supersession(Some(&owner), false, &[], &old, &new),
        SupersessionDecision::Authorized(_)
    ));
    let mut old = old;
    old.created_at = "invalid".into();
    assert_refused(
        authorize_supersession(Some(&owner), false, &[], &old, &new),
        SupersessionRefusal::NotStrictlyNewer,
    );
}

#[test]
fn existing_marker_is_noop_only_after_authority_checks_3587() {
    let (mut old, new) = pair();
    old.metadata[field_names::SUPERSEDED_BY] = json!(new.id);
    let owner = principal(OWNER);
    assert!(matches!(
        authorize_supersession(Some(&owner), false, &[], &old, &new),
        SupersessionDecision::AlreadySuperseded
    ));
    assert_refused(
        authorize_supersession(None, false, &[], &old, &new),
        SupersessionRefusal::UnauthenticatedPrincipal,
    );
    let other = principal("ai:other-3587");
    assert_refused(
        authorize_supersession(Some(&other), false, &[], &old, &new),
        SupersessionRefusal::OwnerMismatch,
    );
}

#[test]
fn ruling_keys_require_exact_nonempty_strings_and_namespace_3587() {
    let (old, mut new) = pair();
    assert!(same_ruling_key(&old, &new));
    for invalid in [
        json!(null),
        json!(false),
        json!(42),
        json!(""),
        json!("release-policy-child"),
    ] {
        new.metadata[field_names::RULING_KEY] = invalid;
        assert!(!same_ruling_key(&old, &new));
    }
    new.metadata = old.metadata.clone();
    new.namespace.push_str("/child");
    assert!(!same_ruling_key(&old, &new));
    let mut old = old;
    old.metadata = json!({});
    new.metadata = json!({});
    assert!(!same_ruling_key(&old, &new));
}

#[test]
fn verified_v1_cannot_be_reused_for_another_write_3587() {
    let _no_pass = crate::test_support::no_passphrase_guard();
    let conn = crate::db::open(std::path::Path::new(":memory:")).expect("open");
    let (old, new) = pair();
    let key = crate::identity::keypair::generate(OWNER).expect("key");
    crate::db::register_agent(&conn, OWNER, "ai", &[]).expect("register");
    crate::db::bind_agent_pubkey_with_keypair(&conn, OWNER, &key).expect("bind");
    let signature = crate::identity::attest::sign_memory_write(&key, &new, OWNER).expect("sign");
    let verified =
        SupersessionPrincipal::verify_v1_sync(&conn, &new, OWNER, &signature).expect("verified");
    assert_eq!(verified.source(), PrincipalSource::VerifiedV1);
    assert!(matches!(
        authorize_supersession(Some(&verified), false, &[], &old, &new),
        SupersessionDecision::Authorized(_)
    ));
    let mut changed = new.clone();
    changed.id.push_str("-other");
    assert_refused(
        authorize_supersession(Some(&verified), false, &[], &old, &changed),
        SupersessionRefusal::VerifiedWriteMismatch,
    );
    changed = new.clone();
    changed.content.push_str(" forged");
    assert_refused(
        authorize_supersession(Some(&verified), false, &[], &old, &changed),
        SupersessionRefusal::VerifiedWriteMismatch,
    );
    assert!(SupersessionPrincipal::verify_v1_sync(&conn, &changed, OWNER, &signature).is_err());
    let mut forged = signature;
    forged[0] ^= 1;
    assert!(SupersessionPrincipal::verify_v1_sync(&conn, &new, OWNER, &forged).is_err());
    assert!(SupersessionPrincipal::verify_v1_sync(&conn, &new, OWNER, &[]).is_err());
}

#[test]
fn verified_v1_requires_the_store_binding_not_presented_key_metadata_3587() {
    let _no_pass = crate::test_support::no_passphrase_guard();
    let conn = crate::db::open(std::path::Path::new(":memory:")).expect("open");
    let (_, mut new) = pair();
    let attacker = crate::identity::keypair::generate(OWNER).expect("key");
    new.metadata["agent_pubkey"] = json!(attacker.public_base64());
    new.metadata["attest_level"] = json!("agent_attested");
    let signature =
        crate::identity::attest::sign_memory_write(&attacker, &new, OWNER).expect("sign");
    assert!(SupersessionPrincipal::verify_v1_sync(&conn, &new, OWNER, &signature).is_err());
}

#[test]
fn verified_v2_requires_valid_signature_and_nonrevoked_cert_3587() {
    use crate::identity::cbor_array::{
        HashCodec, Multihash, SUITE_ED25519_SHA256, SignableWriteV2, canonical_cbor_write_v2,
    };
    use crate::identity::subkey_cert::{SubkeyCert, sign_subkey_cert};
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use ed25519_dalek::{Signer as _, SigningKey};

    let _no_pass = crate::test_support::no_passphrase_guard();
    let conn = crate::db::open(std::path::Path::new(":memory:")).expect("open");
    let (old, mut new) = pair();
    new.created_at = crate::identity::attest::now_attestable_rfc3339();
    crate::db::register_agent(&conn, OWNER, "ai", &[]).expect("register");
    let root = SigningKey::from_bytes(&[17; 32]);
    let sub = SigningKey::from_bytes(&[18; 32]);
    crate::db::bind_agent_pubkey_with_signing_key(&conn, OWNER, &root).expect("bind");
    let instance = sub.verifying_key().to_bytes();
    let model = [19; 32];
    let now = chrono::Utc::now();
    let not_before = (now - chrono::Duration::hours(1)).to_rfc3339();
    let not_after = (now + chrono::Duration::hours(1)).to_rfc3339();
    let cert = SubkeyCert {
        principal: OWNER,
        instance_key_id: &instance,
        model_version_ref: &model,
        not_before: &not_before,
        not_after: &not_after,
    };
    let cert_signature = sign_subkey_cert(&root, &cert);
    let write = SignableWriteV2 {
        agent_id: OWNER,
        namespace: &new.namespace,
        title: &new.title,
        kind: new.memory_kind.as_str(),
        created_at: &new.created_at,
        content_digest: Multihash::new(
            HashCodec::Sha2_256,
            crate::identity::attest::content_sha256(&new.content),
        ),
        instance_key_id: &instance,
        model_version_ref: &model,
        session_id: None,
        suite_tag: SUITE_ED25519_SHA256,
    };
    let signature = sub.sign(&canonical_cbor_write_v2(&write)).to_bytes();
    let wire = json!({"write_v2": {
        "cert": {"principal": OWNER, "instance_key_id": B64.encode(instance),
            "model_version_ref": B64.encode(model), "not_before": not_before, "not_after": not_after},
        "cert_signature": B64.encode(cert_signature), "write_signature": B64.encode(signature),
        "suite_tag": SUITE_ED25519_SHA256, "created_at": new.created_at,
    }});
    let presentation = crate::identity::attest_v2::parse_presented(&wire)
        .expect("parse")
        .expect("present");
    let verified = SupersessionPrincipal::verify_v2_sync(&conn, &mut new, OWNER, &presentation)
        .expect("verified");
    assert_eq!(verified.source(), PrincipalSource::VerifiedV2);
    assert!(matches!(
        authorize_supersession(Some(&verified), false, &[], &old, &new),
        SupersessionDecision::Authorized(_)
    ));
    let mut forged = wire;
    forged["write_v2"]["write_signature"] = json!(B64.encode([0; 64]));
    let forged = crate::identity::attest_v2::parse_presented(&forged)
        .expect("parse")
        .expect("present");
    assert!(SupersessionPrincipal::verify_v2_sync(&conn, &mut new, OWNER, &forged).is_err());
    let certs = crate::db::list_subkey_certs(&conn, Some(OWNER)).expect("certs");
    assert_eq!(certs.len(), 1);
    assert!(crate::db::revoke_subkey_cert(&conn, &certs[0].id).expect("revoke"));
    assert!(SupersessionPrincipal::verify_v2_sync(&conn, &mut new, OWNER, &presentation).is_err());
}
