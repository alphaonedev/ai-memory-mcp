// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Golden-vector CI gate for the `SignableHeadAttestation` CBOR-array
//! encoder (#1947, epic #1940, spec §5.2).
//!
//! Per the frozen spec (§1 + Appendix A), a v2 signed-byte layout is pinned
//! by an **encoder-generated** `input → exact-hex` corpus — never
//! hand-authored hex (a hand-written blob risks a subtle shortest-form /
//! length-prefix error baked permanently into a reference vector). This test
//! rebuilds each fixture's inputs, re-encodes them through
//! [`ai_memory::identity::equivocation::canonical_cbor_head_attestation`],
//! and byte-compares against the committed
//! `tests/golden/peer_head_attestation/*.hex` vectors. It is the R24
//! verifier's head-attestation re-encode path in miniature.
//!
//! To (re)generate the committed vectors after a DELIBERATE, spec-approved
//! format change, run:
//!
//! ```text
//! AI_MEMORY_REGEN_GOLDEN=1 cargo test --test head_attestation_golden
//! ```
//!
//! then review and commit the regenerated `.hex` files. A silent regen is
//! never allowed in CI (the env var is developer-only).

use std::path::PathBuf;

use ai_memory::identity::cbor_array::PEER_HEAD_ATTESTATION_V1_DOMAIN;
use ai_memory::identity::equivocation::{SignableHeadAttestation, canonical_cbor_head_attestation};

/// Environment toggle that rewrites the committed vectors instead of
/// asserting against them. Developer-only; never set in CI.
const REGEN_ENV: &str = "AI_MEMORY_REGEN_GOLDEN";

/// Directory (relative to the crate root) holding the committed vectors.
const GOLDEN_DIR: &str = "tests/golden/peer_head_attestation";

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
         `{REGEN_ENV}=1 cargo test --test head_attestation_golden` and commit the .hex files.",
    );
}

/// A canonical head-attestation with fixed, deterministic test bytes so the
/// vector is stable: `head_hash` is a fixed 32-byte placeholder.
fn worked_attestation() -> Vec<u8> {
    let head_hash = [0xab; 32];
    let att = SignableHeadAttestation {
        subject_agent_id: "ai:example-agent@host.example",
        epoch: 3,
        head_sequence: 42,
        head_hash: &head_hash,
        signed_at: "2026-07-11T00:00:00Z",
    };
    canonical_cbor_head_attestation(&att)
}

/// A variant exercising multi-byte integer heads (epoch/seq ≥ 256) and a
/// longer subject id, to pin the shortest-form integer encoding.
fn large_counters_variant() -> Vec<u8> {
    let head_hash = [0x5c; 32];
    let att = SignableHeadAttestation {
        subject_agent_id: "ai:a-longer-subject-id-crossing-the-boundary@node",
        epoch: 1000,
        head_sequence: 70000,
        head_hash: &head_hash,
        signed_at: "2026-07-11T12:34:56Z",
    };
    canonical_cbor_head_attestation(&att)
}

#[test]
fn golden_worked_attestation() {
    check_vector("worked_attestation", &worked_attestation());
}

#[test]
fn golden_large_counters_variant() {
    check_vector("large_counters_variant", &large_counters_variant());
}

/// Structural sanity: independent of the committed bytes, the attestation
/// must open with a 6-element array header and the frozen domain tag. Guards
/// against a regenerated corpus silently blessing a broken shape.
#[test]
fn attestation_structure_is_pinned() {
    let enc = worked_attestation();
    assert_eq!(enc[0], 0x86, "6-element array header (0x80 | 6)");
    // The 34-byte domain tag uses the 1-byte-length text form 0x78 0x22.
    assert_eq!(&enc[1..3], &[0x78, 0x22], "34-byte text length prefix");
    assert_eq!(
        &enc[3..3 + PEER_HEAD_ATTESTATION_V1_DOMAIN.len()],
        PEER_HEAD_ATTESTATION_V1_DOMAIN.as_bytes(),
        "element [0] is the frozen peer-head-attestation-v1 domain tag",
    );
}
