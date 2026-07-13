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
