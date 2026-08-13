// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Golden-vector CI gate for the `SubkeyCert` v1 CBOR-array encoder
//! (#1942, epic #1940, spec §2.3).
//!
//! Per the frozen spec (§1 + Appendix A), a v2 signed-byte layout is
//! pinned by an **encoder-generated** `input → exact-hex` corpus — never
//! hand-authored hex. This test rebuilds each fixture's inputs, re-encodes
//! them through
//! [`ai_memory::identity::subkey_cert::canonical_cbor_subkey_cert`], and
//! byte-compares against the committed `tests/golden/subkey_cert/*.hex`
//! vectors. It is the R24 verifier's cert re-encode path in miniature
//! (spec §7 step 3).
//!
//! To (re)generate the committed vectors after a DELIBERATE, spec-approved
//! format change, run:
//!
//! ```text
//! AI_MEMORY_REGEN_GOLDEN=1 cargo test --test subkey_cert_golden
//! ```
//!
//! then review and commit the regenerated `.hex` files. A silent regen is
//! never allowed in CI (the env var is developer-only).

use std::path::PathBuf;

use ai_memory::identity::cbor_array::SUBKEY_CERT_V1_DOMAIN;
use ai_memory::identity::subkey_cert::{SubkeyCert, canonical_cbor_subkey_cert};

/// Environment toggle that rewrites the committed vectors instead of
/// asserting against them. Developer-only; never set in CI.
const REGEN_ENV: &str = "AI_MEMORY_REGEN_GOLDEN";

/// Directory (relative to the crate root) holding the committed vectors.
const GOLDEN_DIR: &str = "tests/golden/subkey_cert";

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
         `{REGEN_ENV}=1 cargo test --test subkey_cert_golden` and commit the .hex files.",
    );
}

/// A canonical `SubkeyCert` with fixed, deterministic test bytes so the
/// vector is stable. `instance_key_id` is the sub-key's raw Ed25519
/// verifying-key bytes (spec §2.3); a fixed placeholder here.
fn worked_cert() -> Vec<u8> {
    let cert = SubkeyCert {
        principal: "ai:example-agent@host.example",
        instance_key_id: &[0x07; 32],
        model_version_ref: &[0xab; 32],
        not_before: "2026-07-11T00:00:00Z",
        not_after: "2027-07-11T00:00:00Z",
    };
    canonical_cbor_subkey_cert(&cert)
}

#[test]
fn golden_worked_cert() {
    check_vector("worked_cert", &worked_cert());
}

/// Structural sanity: independent of the committed bytes, the cert must
/// open with a 6-element array header and the frozen domain tag. Guards
/// against a regenerated corpus silently blessing a broken shape.
#[test]
fn cert_structure_is_pinned() {
    let enc = worked_cert();
    assert_eq!(enc[0], 0x86, "6-element array header (0x80 | 6)");
    // The 24-byte domain tag uses the 1-byte-length text form 0x78 0x18.
    assert_eq!(&enc[1..3], &[0x78, 0x18], "24-byte text length prefix");
    assert_eq!(
        &enc[3..3 + SUBKEY_CERT_V1_DOMAIN.len()],
        SUBKEY_CERT_V1_DOMAIN.as_bytes(),
        "element [0] is the frozen subkey-cert/v1 domain tag",
    );
}
