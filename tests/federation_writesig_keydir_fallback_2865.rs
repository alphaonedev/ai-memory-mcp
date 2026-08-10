// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2865 — the FINAL federation-convergence enrollment fix.
//!
//! A daemon authors a federated consolidation as its FEDERATION identity
//! (e.g. `ai:hive-memory-1`). A normally-enrolled mesh cross-enrolls a peer's
//! federation public key into the on-disk key store (the key-dir) — the SAME
//! source the PULL author lane, the signal-author lane, and the
//! transition-author lane already trust — but does NOT bind it into the per-node
//! DB `agent_pubkey` registry. Pre-#2865 the `/sync/push` receive lane resolved
//! the author's write-signature verification key from the DB registry ONLY, so
//! a daemon-authored consolidation's propagated `metadata.write_signature` could
//! not be verified and the row landed `attest_level=claimed` — quarantined at
//! peers under `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED` (asi-hard).
//!
//! The fix (5-agent vote `4d3ea1c5`, unanimous) makes the push lane's
//! author-key resolution consult the enrolled key-dir as a MISS-ONLY fallback
//! after the DB registry — `handlers::federation_receive::resolve_author_bound_key`
//! — bringing it to parity with the pull lane and closing the gap OUT-OF-BOX,
//! with NO manual DB-bind step.
//!
//! These tests pin the RESOLUTION SEAM directly (not merely `stamp_attestation`,
//! which would be a tautology since it already accepts the key as a param): a
//! DB-miss falls back to the key-dir, an unenrolled author yields `None`, and a
//! DB-registry key ALWAYS wins over the key-dir (miss-only precedence). The
//! end-to-end legs then reproduce the before/after — a key-dir-enrolled author
//! reaches `agent_attested` with NO DB bind, while an unenrolled author stays
//! `claimed`.

use base64::Engine as _;

use ai_memory::handlers::federation_receive::{
    resolve_author_bound_key, resolve_author_bound_key_in,
};
use ai_memory::identity::attest::{sign_memory_write, stamp_attestation};
use ai_memory::identity::keypair;
use ai_memory::identity::verify::AttestLevel;
use ai_memory::models::Memory;

const AUTHOR: &str = "ai:hive-memory-1";

fn url_safe(kp: &keypair::AgentKeypair) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(kp.public.to_bytes())
}

fn standard(kp: &keypair::AgentKeypair) -> String {
    base64::engine::general_purpose::STANDARD.encode(kp.public.to_bytes())
}

/// A memory shaped like a daemon-authored consolidation, authored as the
/// FEDERATION identity — the #2865 subject.
fn consolidation_mem() -> Memory {
    Memory {
        id: "m-2865".to_string(),
        namespace: "hive/ops".to_string(),
        title: "consolidated deployment guide".to_string(),
        content: "scale the deployment to three replicas across the mesh".to_string(),
        created_at: "2026-08-10T12:00:00+00:00".to_string(),
        metadata: serde_json::json!({ "agent_id": AUTHOR }),
        ..Memory::default()
    }
}

// ---- resolution seam (the load-bearing fix; NOT a stamp_attestation tautology)

#[test]
fn resolve_seam_db_miss_falls_back_to_keydir_2865() {
    // The peer's FEDERATION identity key is cross-enrolled into the key-dir
    // (mesh cross-enrollment) but NOT DB-bound → registry miss.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let kp = keypair::generate(AUTHOR).expect("generate");
    keypair::save(&kp, dir.path()).expect("save keypair");

    let resolved = resolve_author_bound_key_in(None, AUTHOR, dir.path());
    assert_eq!(
        resolved.as_deref(),
        Some(url_safe(&kp).as_str()),
        "a DB-registry miss must fall back to the enrolled key-dir key (URL-safe-no-pad)"
    );
}

#[test]
fn resolve_seam_unenrolled_author_yields_none_2865() {
    // No DB registry key AND no key-dir entry → None (the row will stay claimed,
    // and the honored-third-party WARN can still name missing-author-key).
    let dir = tempfile::TempDir::new().expect("tempdir");
    let resolved = resolve_author_bound_key_in(None, AUTHOR, dir.path());
    assert_eq!(
        resolved, None,
        "an author enrolled NEITHER in the DB registry NOR the key-dir must resolve to None"
    );
}

#[test]
fn resolve_seam_db_registry_wins_over_keydir_2865() {
    // MISS-ONLY precedence: a key bound into the DB registry (e.g. the cert-round
    // author via the admin PUT route / `agents bind-key`) ALWAYS wins, so a
    // stale/rotated key-dir entry can never shadow the authoritative registry key.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let keydir_kp = keypair::generate(AUTHOR).expect("generate keydir");
    keypair::save(&keydir_kp, dir.path()).expect("save keydir keypair");

    // A DIFFERENT key present in the DB registry.
    let registry_kp = keypair::generate("ai:registry-bound").expect("generate registry");
    let registry_b64 = standard(&registry_kp);

    let resolved = resolve_author_bound_key_in(Some(registry_b64.clone()), AUTHOR, dir.path());
    assert_eq!(
        resolved,
        Some(registry_b64),
        "the DB-registry key must win outright (key-dir is consulted ONLY on a registry miss)"
    );
    assert_ne!(
        resolved.as_deref(),
        Some(url_safe(&keydir_kp).as_str()),
        "the key-dir key must NOT be consulted when the registry already resolved a key"
    );
}

#[test]
fn resolve_default_helper_no_keydir_hit_is_none_2865() {
    // The production wrapper (default key-dir) resolves `None` for an author with
    // no DB key and no key-dir entry under the process default dir — a byte for
    // the pull-lane parity (pull passes `None` and expects the same helper).
    // Uses a randomised author so the process key-dir cannot coincidentally hold it.
    let unknown = format!("ai:unenrolled-{}", uuid::Uuid::new_v4());
    assert_eq!(resolve_author_bound_key(None, &unknown), None);
}

// ---- end-to-end before/after (no manual DB bind) --------------------------

#[test]
fn end_to_end_keydir_enrolled_author_reaches_agent_attested_2865() {
    // AFTER: the daemon authored + signed the consolidation as its FED identity;
    // the peer cross-enrolled that key into the key-dir (no DB bind). The push
    // lane resolves the key from the key-dir and the propagated write_signature
    // verifies → agent_attested, OUT-OF-BOX.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let kp = keypair::generate(AUTHOR).expect("generate");
    keypair::save(&kp, dir.path()).expect("save keypair");

    let mut mem = consolidation_mem();
    let sig = sign_memory_write(&kp, &mem, AUTHOR).expect("sign write");

    // The receive lane resolves the bound key with NO DB registry entry.
    let bound = resolve_author_bound_key_in(None, AUTHOR, dir.path());
    assert!(
        bound.is_some(),
        "key-dir fallback must resolve the enrolled key"
    );

    let level = stamp_attestation(&mut mem, AUTHOR, bound.as_deref(), Some(&sig), false)
        .expect("attestation must not error for a valid signature");
    assert_eq!(
        level,
        AttestLevel::AgentAttested,
        "a valid write_signature verified against the key-dir-resolved key must reach agent_attested"
    );
    assert_eq!(mem.metadata["attest_level"], "agent_attested");
}

#[test]
fn end_to_end_unenrolled_author_stays_claimed_2865() {
    // BEFORE (reproduced): with the author enrolled in NEITHER the DB registry
    // NOR the key-dir, the presented signature cannot be verified against any
    // key, so under the permissive default the row DEGRADES to claimed (never a
    // wrong result). This is the state the fix upgrades once the key is enrolled.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let kp = keypair::generate(AUTHOR).expect("generate");
    // Deliberately do NOT save the key anywhere.

    let mut mem = consolidation_mem();
    let sig = sign_memory_write(&kp, &mem, AUTHOR).expect("sign write");

    let bound = resolve_author_bound_key_in(None, AUTHOR, dir.path());
    assert_eq!(bound, None, "unenrolled author has no resolvable key");

    let level = stamp_attestation(&mut mem, AUTHOR, bound.as_deref(), Some(&sig), false)
        .expect("permissive unsigned-or-unresolvable path must not error");
    assert_eq!(
        level,
        AttestLevel::Claimed,
        "a presented signature with NO resolvable key must land claimed under the permissive default"
    );
}

#[test]
fn end_to_end_forged_signature_rejected_regardless_of_key_source_2865() {
    // The key-dir fallback NEVER weakens verification: a forged signature against
    // the key-dir-resolved key is rejected UNCONDITIONALLY (never downgraded to
    // claimed) — the fix widens the KEY SOURCE, never the accept criterion.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let kp = keypair::generate(AUTHOR).expect("generate");
    keypair::save(&kp, dir.path()).expect("save keypair");

    let mut mem = consolidation_mem();
    let mut sig = sign_memory_write(&kp, &mem, AUTHOR).expect("sign write");
    sig[0] ^= 0xFF; // flip a byte → forged

    let bound = resolve_author_bound_key_in(None, AUTHOR, dir.path());
    assert!(
        bound.is_some(),
        "key-dir fallback must resolve the enrolled key"
    );

    let err = stamp_attestation(&mut mem, AUTHOR, bound.as_deref(), Some(&sig), false);
    assert!(
        err.is_err(),
        "a forged signature must be rejected even when the key resolved via the key-dir fallback"
    );
}
