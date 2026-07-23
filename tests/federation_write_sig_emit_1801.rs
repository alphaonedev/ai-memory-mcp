// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1801→#1954 (v1.0.0) — sender-EMIT of the author's per-write signature +
//! the secret-screen ordering guarantee (ratified MINIMAL scope, 5-agent vote
//! `w9mr01vi8`, item 8f + the store-time EMIT round-trip).
//!
//! These are integration-level tests (separate binary) because the credential
//! screen mode is a process-global `OnceLock` (`set_screen_mode`) that must be
//! seeded exactly once; an isolated test binary owns that seed. Both tests here
//! run under `Redact` mode.

use ai_memory::identity::{attest, keypair, sign::SignableWrite, verify};
use ai_memory::models::{Memory, MemoryKind, field_names::WRITE_SIGNATURE};
use ai_memory::secret_screen::{SecretScreenMode, redact_for_storage, set_screen_mode};
use base64::Engine as _;

/// A GitHub PAT the credential detector reliably flags (mirrors
/// `secret_screen::tests::detects_github_pat`).
const SECRET_TOKEN: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

fn mem_with(content: &str) -> Memory {
    Memory {
        id: "m-1801-emit".to_string(),
        namespace: "team/alpha".to_string(),
        title: "kubernetes deployment guide".to_string(),
        content: content.to_string(),
        created_at: "2026-06-01T12:00:00+00:00".to_string(),
        memory_kind: MemoryKind::Observation,
        metadata: serde_json::json!({}),
        ..Memory::default()
    }
}

/// Reconstruct the exact `SignableWrite` the receiver rebuilds from a persisted
/// row — `agent_id + namespace + title + kind + created_at + sha256(content)`.
fn signable<'a>(mem: &'a Memory, author: &'a str, content_hash: &'a [u8; 32]) -> SignableWrite<'a> {
    SignableWrite {
        agent_id: author,
        namespace: &mem.namespace,
        title: &mem.title,
        kind: mem.memory_kind.as_str(),
        created_at: &mem.created_at,
        content_sha256: content_hash,
    }
}

/// (f) THE ORDERING BUG: signing over the ORIGINAL content and letting the
/// storage funnel redact AFTERWARDS yields a signature that is unconditionally
/// Forged against the PERSISTED (redacted) bytes — exactly the failure the
/// corrected design (item 4) exists to prevent.
#[test]
fn naive_sign_before_redact_is_forged_against_persisted_bytes_1801() {
    set_screen_mode(SecretScreenMode::Redact);
    let author = "ai:curator";
    let kp = keypair::generate(author).unwrap();
    let mem = mem_with(&format!("deploy with {SECRET_TOKEN} then restart"));

    // Naive: sign over the original (pre-redaction) content.
    let naive_sig = attest::sign_memory_write(&kp, &mem, author).unwrap();

    // The storage funnel would persist the REDACTED content instead.
    let persisted = redact_for_storage(&mem.content).expect("secret detected → redacted copy");
    assert_ne!(persisted, mem.content, "redaction must change the bytes");

    let persisted_hash = attest::content_sha256(&persisted);
    let sw = signable(&mem, author, &persisted_hash); // title is clean → unchanged
    assert!(
        verify::verify_write(&kp.public, &sw, &naive_sig).is_err(),
        "sign-before-redact MUST be Forged against the persisted bytes"
    );
}

/// (f) THE FIX: `redact_before_sign` folds the storage-funnel redaction in
/// FIRST, so the signature commits to the persisted bytes and verifies — and
/// the store-time EMIT then persists that signature for propagation.
#[test]
fn redact_before_sign_then_emit_verifies_against_persisted_bytes_1801() {
    set_screen_mode(SecretScreenMode::Redact);
    let author = "ai:curator";
    let kp = keypair::generate(author).unwrap();
    let mut mem = mem_with(&format!("deploy with {SECRET_TOKEN} then restart"));

    // Item 4: redact to storage form BEFORE signing.
    attest::redact_before_sign(&mut mem);
    assert!(
        !mem.content.contains(SECRET_TOKEN),
        "content must be redacted before signing"
    );
    let sig = attest::sign_memory_write(&kp, &mem, author).unwrap();

    // The signature verifies against the PERSISTED (redacted) bytes.
    let content_hash = attest::content_sha256(&mem.content);
    let sw = signable(&mem, author, &content_hash);
    verify::verify_write(&kp.public, &sw, &sig)
        .expect("sign-after-redact MUST verify against the persisted bytes");

    // Item 2: EMIT persists the signature for federation propagation.
    attest::persist_write_signature(&mut mem, &sig);
    let stored = mem.metadata[WRITE_SIGNATURE]
        .as_str()
        .expect("write_signature persisted");
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(stored)
            .unwrap(),
        sig,
        "the emitted signature must round-trip (standard base64)"
    );
}

/// #2340 (FBL-32) — the RECEIVE-side twin of the ordering discipline above:
/// an `off`-mode ORIGIN signs + emits over RAW secret-bearing bytes; a
/// `redact`-mode receiver must redact to the to-be-persisted form BEFORE
/// attestation, drop the now-uncoverable raw-bytes signature, and land the
/// row `claimed` — NEVER a false `agent_attested` over bytes that differ
/// from what is stored.
#[test]
fn receive_redacts_before_attestation_so_raw_signed_secret_lands_claimed_2340() {
    set_screen_mode(SecretScreenMode::Redact);
    let author = "ai:origin-off-mode";
    let kp = keypair::generate(author).unwrap();
    let mut mem = mem_with(&format!("deploy with {SECRET_TOKEN} then restart"));
    mem.metadata = serde_json::json!({ "agent_id": author });

    // Off-mode origin: `redact_before_sign` no-ops under `Off`, so the
    // signature commits to the RAW bytes; EMIT ships it.
    let sig = attest::sign_memory_write(&kp, &mem, author).unwrap();
    attest::persist_write_signature(&mut mem, &sig);

    // Receiver (#2340): redact to the persisted form BEFORE attestation.
    let mutated = ai_memory::federation::receive_auth::redact_inbound_before_attestation(&mut mem);
    assert!(mutated, "the raw secret must mutate the signed surface");
    assert!(
        !mem.content.contains(SECRET_TOKEN),
        "content must be redacted to the persisted form"
    );
    assert!(
        mem.metadata.get(WRITE_SIGNATURE).is_none(),
        "the stale raw-bytes signature must be dropped"
    );

    // The attestation step (now with no presented signature) lands the row
    // honestly `claimed` under the permissive posture.
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(kp.public.to_bytes());
    let level = attest::stamp_attestation(&mut mem, author, Some(&pk_b64), None, false)
        .expect("unsigned permissive attestation");
    assert_eq!(level.as_str(), "claimed");
    assert_eq!(mem.metadata["attest_level"], "claimed");

    // The storage funnel's own later redaction is an idempotent no-op — the
    // stamped/attested bytes ARE the persisted bytes.
    assert!(
        redact_for_storage(&mem.content).is_none(),
        "funnel redaction must be a no-op on the pre-redacted content"
    );
}

/// #2340 (FBL-32) — same-mode traffic is untouched: an origin following the
/// #1801 redact-before-sign discipline ships pre-redacted signed bytes; the
/// receiver's pre-attestation redact is a no-op, the signature survives, and
/// the row still verifies to `agent_attested` over the persisted bytes.
#[test]
fn receive_helper_is_noop_for_redact_before_sign_traffic_2340() {
    set_screen_mode(SecretScreenMode::Redact);
    let author = "ai:origin-same-mode";
    let kp = keypair::generate(author).unwrap();
    let mut mem = mem_with(&format!("deploy with {SECRET_TOKEN} then restart"));
    mem.metadata = serde_json::json!({ "agent_id": author });

    // Same-mode origin: redact FIRST, then sign + EMIT (#1801 discipline).
    attest::redact_before_sign(&mut mem);
    let sig = attest::sign_memory_write(&kp, &mem, author).unwrap();
    attest::persist_write_signature(&mut mem, &sig);

    let mutated = ai_memory::federation::receive_auth::redact_inbound_before_attestation(&mut mem);
    assert!(
        !mutated,
        "pre-redacted signed bytes must pass the receive screen unchanged"
    );
    let presented = mem
        .metadata
        .get(WRITE_SIGNATURE)
        .and_then(serde_json::Value::as_str)
        .map(|s| base64::engine::general_purpose::STANDARD.decode(s).unwrap())
        .expect("signature must be retained");
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(kp.public.to_bytes());
    let level = attest::stamp_attestation(&mut mem, author, Some(&pk_b64), Some(&presented), false)
        .expect("attested traffic must keep verifying");
    assert_eq!(level.as_str(), "agent_attested");
}
