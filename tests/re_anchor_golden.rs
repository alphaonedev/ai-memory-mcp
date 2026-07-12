// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Golden-vector CI gate for the PQ re-anchor ceremony CBOR-array encoder
//! (#1942, epic #1940, spec §5.3).
//!
//! Per the frozen spec (§1 + Appendix A), a v2 signed-byte layout is pinned
//! by an **encoder-generated** `input → exact-hex` corpus — never
//! hand-authored hex. This test rebuilds each fixture's inputs, re-encodes
//! them through
//! [`ai_memory::identity::re_anchor::canonical_cbor_re_anchor_v1`], and
//! byte-compares against the committed `tests/golden/re_anchor/*.hex`
//! vectors. It also proves the structural decoder round-trips the pinned
//! bytes back to the same record (the R24 verifier's re-encode path in
//! miniature).
//!
//! To (re)generate the committed vectors after a DELIBERATE, spec-approved
//! format change, run:
//!
//! ```text
//! AI_MEMORY_REGEN_GOLDEN=1 cargo test --test re_anchor_golden
//! ```
//!
//! then review and commit the regenerated `.hex` files. A silent regen is
//! never allowed in CI (the env var is developer-only).

use std::path::PathBuf;

use ai_memory::identity::cbor_array::{RE_ANCHOR_V1_DOMAIN, SUITE_ED25519_SHA256};
use ai_memory::identity::re_anchor::{
    SignableReAnchorV1, canonical_cbor_re_anchor_v1, decode_re_anchor_v1,
};

/// Environment toggle that rewrites the committed vectors instead of
/// asserting against them. Developer-only; never set in CI.
const REGEN_ENV: &str = "AI_MEMORY_REGEN_GOLDEN";

/// Directory (relative to the crate root) holding the committed vectors.
const GOLDEN_DIR: &str = "tests/golden/re_anchor";

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
         `{REGEN_ENV}=1 cargo test --test re_anchor_golden` and commit the .hex files.",
    );
}

/// A canonical re-anchor record with fixed, deterministic test bytes so the
/// vector is stable.
fn worked_record_bytes() -> Vec<u8> {
    let head = [0xAB; 32];
    let r = SignableReAnchorV1 {
        prior_chain_head_hash: &head,
        prior_head_sequence: 4096,
        new_suite_tag: SUITE_ED25519_SHA256,
        anchored_at: "2026-07-12T00:00:00Z",
    };
    canonical_cbor_re_anchor_v1(&r)
}

#[test]
fn golden_worked_record() {
    check_vector("worked_record", &worked_record_bytes());
}

/// Structural sanity: independent of the committed bytes, the record must
/// open with a 5-element array header and the frozen domain tag. Guards
/// against a regenerated corpus silently blessing a broken shape.
#[test]
fn record_structure_is_pinned() {
    let enc = worked_record_bytes();
    assert_eq!(enc[0], 0x85, "5-element array header (0x80 | 5)");
    // The 22-byte domain tag uses the inline-length text head 0x76 (0x60 | 22).
    assert_eq!(enc[1], 0x76, "22-byte inline text length prefix");
    assert_eq!(
        &enc[2..2 + RE_ANCHOR_V1_DOMAIN.len()],
        RE_ANCHOR_V1_DOMAIN.as_bytes(),
        "element [0] is the frozen re-anchor/v1 domain tag",
    );
}

/// The structural decoder round-trips the pinned bytes back to the record
/// (the R24 re-encode path relies on decode∘encode == identity).
#[test]
fn decode_round_trips_the_golden_bytes() {
    let enc = worked_record_bytes();
    let decoded = decode_re_anchor_v1(&enc).expect("golden bytes decode structurally");
    assert_eq!(decoded.prior_head_sequence, 4096);
    assert_eq!(decoded.new_suite_tag, SUITE_ED25519_SHA256);
    assert_eq!(decoded.anchored_at, "2026-07-12T00:00:00Z");
    assert_eq!(
        canonical_cbor_re_anchor_v1(&decoded.as_signable()),
        enc,
        "re-encoding the decoded record reproduces the pinned bytes",
    );
}
