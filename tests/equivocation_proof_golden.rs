// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Golden-vector CI gate for the `EquivocationProof` CBOR-array envelope
//! encoder (#1947, epic #1940, spec §5.2).
//!
//! Per the frozen spec (§1 + Appendix A), a v2 signed-byte layout is pinned
//! by an **encoder-generated** `input → exact-hex` corpus — never
//! hand-authored hex. This test rebuilds a fixed-byte proof envelope (fixed
//! pubkey + fixed placeholder signature bytes so the vector pins the ENCODER
//! output, not Ed25519 signing determinism), re-encodes it through
//! [`ai_memory::identity::equivocation::EquivocationProof::to_bytes`], and
//! byte-compares against the committed `tests/golden/equivocation_proof/*.hex`
//! vectors. It also asserts the frozen envelope round-trips through
//! `from_bytes` (the offline-transport decode).
//!
//! To (re)generate the committed vectors after a DELIBERATE, spec-approved
//! format change, run:
//!
//! ```text
//! AI_MEMORY_REGEN_GOLDEN=1 cargo test --test equivocation_proof_golden
//! ```
//!
//! then review and commit the regenerated `.hex` files. A silent regen is
//! never allowed in CI (the env var is developer-only).

use std::path::PathBuf;

use ai_memory::identity::cbor_array::EQUIVOCATION_PROOF_V1_DOMAIN;
use ai_memory::identity::equivocation::{EquivocationProof, HeadAttestationEntry};

/// Environment toggle that rewrites the committed vectors instead of
/// asserting against them. Developer-only; never set in CI.
const REGEN_ENV: &str = "AI_MEMORY_REGEN_GOLDEN";

/// Directory (relative to the crate root) holding the committed vectors.
const GOLDEN_DIR: &str = "tests/golden/equivocation_proof";

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(GOLDEN_DIR)
        .join(format!("{name}.hex"))
}

/// Compare `encoded` against the committed vector `name`, or (re)write it
/// when the regen env var is set.
fn check_vector(name: &str, encoded: &[u8]) {
    let path = golden_path(name);
    let got = hex::encode(encoded);
    if std::env::var(REGEN_ENV).is_ok() {
        std::fs::create_dir_all(path.parent().expect("golden path has a parent"))
            .expect("create golden dir");
        std::fs::write(&path, format!("{got}\n")).expect("write golden vector");
        return;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing golden vector {}: {e}", path.display()))
        .trim()
        .to_string();
    assert_eq!(
        got, want,
        "golden vector `{name}` mismatch — re-encoded bytes differ from the committed corpus. \
         If this is a DELIBERATE, spec-approved format change, regenerate with \
         `{REGEN_ENV}=1 cargo test --test equivocation_proof_golden` and commit the .hex files.",
    );
}

/// A deterministic proof envelope: a fixed pubkey + two attestation entries
/// (same subject/epoch/seq, DIFFERENT `head_hash`) with fixed PLACEHOLDER
/// signature bytes, so the vector pins the encoder output rather than
/// depending on Ed25519 signing determinism.
fn worked_proof() -> EquivocationProof {
    EquivocationProof {
        subject_pubkey: [0x07; 32],
        attestation_a: HeadAttestationEntry {
            subject_agent_id: "ai:example-agent@host.example".to_string(),
            epoch: 3,
            head_sequence: 42,
            head_hash: vec![0xaa; 32],
            signed_at: "2026-07-11T00:00:00Z".to_string(),
            signature: vec![0xa1; 64],
        },
        attestation_b: HeadAttestationEntry {
            subject_agent_id: "ai:example-agent@host.example".to_string(),
            epoch: 3,
            head_sequence: 42,
            head_hash: vec![0xbb; 32],
            signed_at: "2026-07-11T00:00:01Z".to_string(),
            signature: vec![0xb2; 64],
        },
    }
}

#[test]
fn golden_worked_proof() {
    check_vector("worked_proof", &worked_proof().to_bytes());
}

/// The frozen envelope must round-trip through the offline decode path.
#[test]
fn worked_proof_round_trips_through_bytes() {
    let proof = worked_proof();
    let decoded = EquivocationProof::from_bytes(&proof.to_bytes()).expect("decode");
    assert_eq!(decoded, proof);
}

/// Structural sanity: independent of the committed bytes, the proof must open
/// with a 4-element array header and the frozen domain tag.
#[test]
fn proof_structure_is_pinned() {
    let enc = worked_proof().to_bytes();
    assert_eq!(enc[0], 0x84, "4-element array header (0x80 | 4)");
    // The 31-byte domain tag uses the 1-byte-length text form 0x78 0x1f.
    assert_eq!(&enc[1..3], &[0x78, 0x1f], "31-byte text length prefix");
    assert_eq!(
        &enc[3..3 + EQUIVOCATION_PROOF_V1_DOMAIN.len()],
        EQUIVOCATION_PROOF_V1_DOMAIN.as_bytes(),
        "element [0] is the frozen equivocation-proof/v1 domain tag",
    );
}
