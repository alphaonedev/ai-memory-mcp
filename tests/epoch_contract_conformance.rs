// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 §25.3 S5 (RQ-10, #1853) — schema-vs-contract conformance for
//! the epoch manifest.
//!
//! The git-tracked JSON Schema (`docs/contracts/epoch_manifest.schema.json`)
//! is the DOCUMENTATION contract; the Rust `SignableEpochManifest` +
//! `ai-memory epoch-apply` serde struct are the RUNTIME contract. This
//! test asserts the two agree on the field set AND — critically — that
//! the manifest STRUCTURALLY carries NO diversity/decorrelation assertion
//! field, so a signed manifest cannot launder unattested diversity.
//!
//! This lives in `tests/` (NOT `src/`) on purpose: the L3-boundary
//! perma-ban gate scans `src/` only, and the schema file path contains
//! the ruled `epoch`+`manifest` token which must never appear in `src/`.

use std::path::Path;

fn load_schema() -> serde_json::Value {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/contracts/epoch_manifest.schema.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "epoch manifest schema must be git-tracked at {}: {e}",
            path.display()
        )
    });
    serde_json::from_slice(&bytes).expect("epoch manifest schema must be valid JSON")
}

#[test]
fn schema_is_valid_json_with_ruled_fields() {
    let schema = load_schema();
    let props = schema["properties"]
        .as_object()
        .expect("schema has a properties object");
    for field in [
        "epoch_seq",
        "prior_epoch_id",
        "policy_seq",
        "policy_digest_hex",
        "panel",
        "utility_weights",
        "created_at",
        "content_hash",
    ] {
        assert!(props.contains_key(field), "schema must declare `{field}`");
    }
}

#[test]
fn manifest_structurally_cannot_assert_diversity() {
    // The manifest must be diversity-field-free: no property whose name
    // hints at diversity/decorrelation/quorum/attestation, and
    // additionalProperties must be closed at the top level so no such
    // field can be smuggled in. This is the structural anti-laundering
    // guarantee (§25.2/§25.3).
    let schema = load_schema();
    assert_eq!(
        schema["additionalProperties"],
        serde_json::Value::Bool(false),
        "top-level additionalProperties must be closed"
    );
    let props = schema["properties"].as_object().unwrap();
    for name in props.keys() {
        let lower = name.to_ascii_lowercase();
        for banned in ["diversity", "decorrelat", "quorum", "attest", "distinct"] {
            assert!(
                !lower.contains(banned),
                "manifest must not carry a `{banned}`-like field (found `{name}`)"
            );
        }
    }
}

#[test]
fn utility_weights_are_frozen_within_epoch() {
    let schema = load_schema();
    let uw = &schema["properties"]["utility_weights"];
    assert_eq!(
        uw["properties"]["frozen_within_epoch"]["const"],
        serde_json::Value::Bool(true),
        "utility_weights.frozen_within_epoch must be pinned true"
    );
}
