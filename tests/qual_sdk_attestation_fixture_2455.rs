// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2455 — PIN the cross-language write-attestation fixture the SDKs sign against.
//!
//! `sdk/fixtures/write_attestation_vector.json` is the ONLY thing binding the
//! Python + TypeScript `SignableWrite` encoders to this crate's encoder. A
//! fixture that nothing pins is the #2453 defect one layer up: change the
//! canonical encoding here — add a field, rename a key, alter the domain
//! separation tag, switch the content commitment — and the fixture goes stale,
//! both SDKs sign bytes the daemon never re-derives, and EVERY signed
//! `POST /api/v1/memories` starts returning `403 ATTESTATION_FAILED` at
//! RUNTIME while CI stays green on both sides, because neither side is
//! comparing against this code any more.
//!
//! That failure mode is especially nasty for attestation: a 403 from a stale
//! envelope is indistinguishable, from the caller's seat, from "the operator
//! never enrolled my public key" — so the real cause hides behind a plausible
//! wrong answer.
//!
//! The sibling pin `subscriptions::tests::webhook_hmac_fixture_matches_the_shipped_signer_2455`
//! covers the webhook HMAC fixture (its helpers are `pub(crate)`, so it must
//! live in the unit-test module). The attestation encoder is `pub`, so this
//! half lives out here in `tests/` and touches no `src/` file.
//!
//! **On failure: REGENERATE the fixture from this encoder and re-run BOTH SDK
//! suites. Never edit the expectation to match new output** — a mismatch means
//! the SDKs have drifted from the daemon, which is exactly what the fixture
//! exists to catch.

use std::path::PathBuf;

use ai_memory::identity::attest::content_sha256;
use ai_memory::identity::sign::{SignableWrite, canonical_cbor_write};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("sdk")
        .join("fixtures")
        .join("write_attestation_vector.json")
}

fn load_fixture() -> serde_json::Value {
    let path = fixture_path();
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read the SDK attestation fixture at {}: {e}. It is the SSOT \
             both SDK suites verify against and must not be deleted.",
            path.display()
        )
    });
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("fixture is not valid JSON: {e}"))
}

fn str_field<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("fixture is missing the `{key}` string field"))
}

/// The shipped encoder must still produce the exact bytes the SDKs sign.
///
/// Asserted against the fixture FILE rather than an inlined literal so the
/// thing under test is the artifact the SDKs actually read — an inlined copy
/// could itself drift from the JSON and pin nothing.
#[test]
fn attestation_fixture_matches_the_shipped_encoder_2455() {
    let fx = load_fixture();

    let content = str_field(&fx, "content");
    let content_hash = content_sha256(content);
    let content_hash_hex = hex_of(&content_hash);
    assert_eq!(
        content_hash_hex,
        str_field(&fx, "content_sha256_hex"),
        "fixture `content_sha256_hex` is stale — the content commitment changed. \
         Regenerate sdk/fixtures/write_attestation_vector.json from this encoder \
         and re-run both SDK suites; do NOT edit the expectation to match."
    );

    let write = SignableWrite {
        agent_id: str_field(&fx, "agent_id"),
        namespace: str_field(&fx, "namespace"),
        title: str_field(&fx, "title"),
        kind: str_field(&fx, "kind"),
        created_at: str_field(&fx, "created_at"),
        content_sha256: &content_hash,
    };
    let cbor = canonical_cbor_write(&write).expect("canonical CBOR encode");
    let cbor_hex = hex_of(&cbor);
    assert_eq!(
        cbor_hex,
        str_field(&fx, "canonical_cbor_hex"),
        "fixture `canonical_cbor_hex` is stale — the SignableWrite envelope changed. \
         Both SDKs now sign bytes this daemon will not re-derive, so every signed \
         HTTP store would 403 at runtime. Regenerate the fixture from this encoder \
         and re-run both SDK suites; do NOT edit the expectation to match."
    );
}

/// The domain-separation tag is a security boundary, not a cosmetic label
/// (#1931): it is what stops a signature minted for a link or a persona from
/// being replayed as a write. The SDKs hard-code the same string, so a change
/// here that the fixture does not carry would silently unbind that separation
/// for every SDK-signed write.
#[test]
fn attestation_fixture_pins_the_write_domain_tag_2455() {
    let fx = load_fixture();
    let tag = str_field(&fx, "domain_separation_tag");
    assert_eq!(
        tag, "ai-memory/write/v1",
        "the write domain-separation tag changed; update both SDK `attestation` \
         modules and regenerate the fixture in lockstep"
    );
    // The tag must actually be INSIDE the encoded envelope, not merely recorded
    // alongside it — a fixture field nothing consumes would pin nothing.
    assert!(
        str_field(&fx, "canonical_cbor_hex").contains(&hex_of(tag.as_bytes())),
        "the domain tag is absent from the pinned envelope bytes"
    );
}

/// Lower-hex encode.
///
/// Uses `fold` + `write!` rather than `map(format!).collect()`: the latter
/// allocates a `String` per byte and trips `clippy::format_collect`, which CI
/// lints on stable with `-D warnings`.
fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            // Writing to a String is infallible; the Result is discarded.
            let _ = write!(acc, "{b:02x}");
            acc
        })
}
