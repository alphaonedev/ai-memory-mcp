// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Golden-vector CI gate for the `SignableWrite` v2 CBOR-array encoder
//! (#1942, epic #1940).
//!
//! Per the frozen spec
//! (`docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md`
//! §1 + Appendix A), the v2 signed-byte layout is pinned by an
//! **encoder-generated** `input → exact-hex` corpus — never hand-authored
//! hex (a hand-written blob risks a subtle shortest-form / length-prefix
//! error baked permanently into a reference vector). This test rebuilds each
//! fixture's inputs, re-encodes them through
//! [`ai_memory::identity::cbor_array::canonical_cbor_write_v2`], and
//! byte-compares against the committed `tests/golden/signable_write_v2/*.hex`
//! vectors. It is the R24 verifier's re-encode path in miniature.
//!
//! To (re)generate the committed vectors after a DELIBERATE, spec-approved
//! format change, run:
//!
//! ```text
//! AI_MEMORY_REGEN_GOLDEN=1 cargo test --test signable_write_v2_golden
//! ```
//!
//! then review and commit the regenerated `.hex` files. A silent regen is
//! never allowed in CI (the env var is developer-only).

use std::path::PathBuf;

use ai_memory::identity::cbor_array::{
    HashCodec, Multihash, SUITE_ED25519_SHA256, SignableWriteV2, WRITE_V2_DOMAIN,
    canonical_cbor_write_v2,
};
use sha2::{Digest, Sha256};

/// Environment toggle that rewrites the committed vectors instead of
/// asserting against them. Developer-only; never set in CI.
const REGEN_ENV: &str = "AI_MEMORY_REGEN_GOLDEN";

/// Directory (relative to the crate root) holding the committed vectors.
const GOLDEN_DIR: &str = "tests/golden/signable_write_v2";

/// SHA2-256 over `content`'s bytes — the element-[6] digest input. In the
/// worked example the content is screen-clean, so this equals the digest the
/// production path commits.
fn content_digest(content: &str) -> [u8; 32] {
    Sha256::digest(content.as_bytes()).into()
}

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
         `{REGEN_ENV}=1 cargo test --test signable_write_v2_golden` and commit the .hex files.",
    );
}

/// The spec Appendix A.4 worked structural example: `agent="host:pop-os",
/// ns="global", title="x", kind="observation",
/// created="2026-07-09T00:00:00Z", content="hello"`, no session,
/// ed25519+sha256 suite. Fixed placeholder `instance_key_id` /
/// `model_version_ref` (deterministic test bytes) so the vector is stable.
fn a4_worked_example() -> Vec<u8> {
    let digest = Multihash::new(HashCodec::Sha2_256, content_digest("hello"));
    let w = SignableWriteV2 {
        agent_id: "host:pop-os",
        namespace: "global",
        title: "x",
        kind: "observation",
        created_at: "2026-07-09T00:00:00Z",
        content_digest: digest,
        instance_key_id: &[0x07; 32],
        model_version_ref: &[0xab; 32],
        session_id: None,
        suite_tag: SUITE_ED25519_SHA256,
    };
    canonical_cbor_write_v2(&w)
}

/// Same identity as the A.4 example but with `session_id` PRESENT, exercising
/// the `[1, value]` presence arm (spec Appendix A.3).
fn session_present() -> Vec<u8> {
    let digest = Multihash::new(HashCodec::Sha2_256, content_digest("hello"));
    let w = SignableWriteV2 {
        agent_id: "host:pop-os",
        namespace: "global",
        title: "x",
        kind: "observation",
        created_at: "2026-07-09T00:00:00Z",
        content_digest: digest,
        instance_key_id: &[0x07; 32],
        model_version_ref: &[0xab; 32],
        session_id: Some("sess-abc123"),
        suite_tag: SUITE_ED25519_SHA256,
    };
    canonical_cbor_write_v2(&w)
}

/// A BLAKE3-codec content digest with a non-zero suite tag and multi-byte
/// field lengths, exercising the `0x1e` codec and longer text prefixes.
fn blake3_digest_variant() -> Vec<u8> {
    let digest = Multihash::new(HashCodec::Blake3, [0x5c; 32]);
    let w = SignableWriteV2 {
        agent_id: "ai:claude-code@pop-os",
        namespace: "ai-memory-mcp",
        title: "a-longer-title-crossing-the-23-byte-boundary",
        kind: "instruction",
        created_at: "2026-07-11T12:34:56Z",
        content_digest: digest,
        instance_key_id: &[0x11; 32],
        model_version_ref: &[0x22; 32],
        session_id: Some("s"),
        suite_tag: 1,
    };
    canonical_cbor_write_v2(&w)
}

#[test]
fn golden_a4_worked_example() {
    check_vector("a4_worked_example", &a4_worked_example());
}

#[test]
fn golden_session_present() {
    check_vector("session_present", &session_present());
}

#[test]
fn golden_blake3_digest_variant() {
    check_vector("blake3_digest_variant", &blake3_digest_variant());
}

/// Structural sanity: independent of the committed bytes, the A.4 record must
/// open with an 11-element array header and the frozen domain tag. Guards
/// against a regenerated corpus silently blessing a broken shape.
#[test]
fn a4_structure_is_pinned() {
    let enc = a4_worked_example();
    assert_eq!(enc[0], 0x8b, "11-element array header (0x80 | 11)");
    assert_eq!(
        enc[1], 0x72,
        "18-byte text header for the domain tag (0x60 | 18)"
    );
    assert_eq!(
        &enc[2..2 + WRITE_V2_DOMAIN.len()],
        WRITE_V2_DOMAIN.as_bytes(),
        "element [0] is the frozen write/v2 domain tag",
    );
}
