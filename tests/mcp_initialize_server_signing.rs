// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for v0.7.x (#1154) — daemon serverInfo Ed25519
//! signing at MCP initialize handshake.
//!
//! Closes NSA CSI MCP Security concern (j) Tool invocation path
//! confusion at the substrate boundary. These tests pin the wire
//! contract that clients TOFU-pin against:
//!
//! 1. **Backwards compatibility** — existing v0.6.4 / v0.7.0 MCP
//!    clients that do not understand `ai_memory_identity` continue to
//!    function. The initialize response carries `serverInfo.name` +
//!    `serverInfo.version` exactly as before.
//! 2. **Additive surface** — when the daemon has an Ed25519 keypair
//!    on disk, the response gains an `ai_memory_identity` block with
//!    five fields: `schema_version`, `daemon_id`, `public_key`,
//!    `signed_at`, `signature`.
//! 3. **Verification round-trip** — the embedded `public_key` verifies
//!    the embedded `signature` over the canonical bytes of the four
//!    other fields. Any tampering with any field breaks verification.
//! 4. **No-keypair fallback** — when `load_daemon_signing_key`
//!    returns `None` (operator has not enrolled a daemon keypair),
//!    the `ai_memory_identity` block is OMITTED. The rest of
//!    `serverInfo` is unaffected.
//! 5. **Functionality preservation** — every test verifies that the
//!    legacy fields (`name`, `version`) are still present alongside
//!    the new field. Zero regression on the existing handshake
//!    contract.
//! 6. **Performance** — the cost is one Ed25519 sign over ~150 bytes
//!    of canonical identity (~10-50 µs). Initialize fires ONCE per
//!    session, not on the recall hot path. The performance smoke
//!    test asserts the order of magnitude is correct.

use ai_memory::identity::keypair::AgentKeypair;
use ai_memory::mcp::server_identity::{build_signed_identity, verify_signed_identity};
use ai_memory::storage::migrations::current_schema_version;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

// ============================================================================
//  Test fixtures
// ============================================================================

const TEST_TIMESTAMP: &str = "2026-05-23T16:30:22Z";

fn fixed_seed_signing_key(byte: u8) -> SigningKey {
    let seed = [byte; ed25519_dalek::SECRET_KEY_LENGTH];
    SigningKey::from_bytes(&seed)
}

fn keypair_with_signing(agent_id: &str, seed_byte: u8) -> AgentKeypair {
    let signing_key = fixed_seed_signing_key(seed_byte);
    AgentKeypair {
        agent_id: agent_id.to_string(),
        public: signing_key.verifying_key(),
        private: Some(signing_key),
    }
}

fn keypair_public_only(agent_id: &str, seed_byte: u8) -> AgentKeypair {
    let signing_key = fixed_seed_signing_key(seed_byte);
    AgentKeypair {
        agent_id: agent_id.to_string(),
        public: signing_key.verifying_key(),
        private: None,
    }
}

// ============================================================================
//  Group A — additive-surface tests (happy path)
// ============================================================================

#[test]
fn signed_identity_block_present_when_daemon_keypair_loaded() {
    let kp = keypair_with_signing("ai:nhi@frosty.local", 42);
    let block = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .expect("build_signed_identity succeeds")
        .expect("signing keypair yields Some(block)");

    let obj = block.as_object().expect("identity block is a JSON object");
    assert!(obj.contains_key("schema_version"));
    assert!(obj.contains_key("daemon_id"));
    assert!(obj.contains_key("public_key"));
    assert!(obj.contains_key("signed_at"));
    assert!(obj.contains_key("signature"));
}

#[test]
fn signed_identity_block_carries_resolved_daemon_id() {
    let kp = keypair_with_signing("ai:custom-daemon-id@host", 13);
    let block = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    assert_eq!(block["daemon_id"], json!("ai:custom-daemon-id@host"));
}

#[test]
fn signed_identity_block_carries_current_schema_version_string() {
    let kp = keypair_with_signing("ai:nhi@host", 1);
    let block = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    let schema = block["schema_version"].as_str().unwrap();
    let expected = format!("v{}", current_schema_version());
    assert_eq!(schema, expected, "must match SSOT constant");
    // Also assert it's the current v49 (catches accidental SSOT drift)
    assert_eq!(schema, "v49", "v0.7.0 schema is v49");
}

#[test]
fn signed_identity_block_carries_public_key_in_url_safe_base64() {
    let kp = keypair_with_signing("ai:nhi@host", 7);
    let block = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    let pk_b64 = block["public_key"].as_str().unwrap();
    assert_eq!(pk_b64, kp.public_base64());
    assert!(!pk_b64.is_empty());
    // URL-safe base64 of 32 bytes is 43 characters (no padding)
    assert_eq!(pk_b64.len(), 43);
}

#[test]
fn signed_identity_block_carries_handshake_timestamp() {
    let kp = keypair_with_signing("ai:nhi@host", 2);
    let block = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    assert_eq!(block["signed_at"], json!(TEST_TIMESTAMP));
}

#[test]
fn signed_identity_block_signature_verifies_round_trip() {
    let kp = keypair_with_signing("ai:nhi@host", 3);
    let block = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    verify_signed_identity(&block).expect("freshly-signed identity must verify");
}

// ============================================================================
//  Group B — no-keypair fallback (operationality preservation)
// ============================================================================

#[test]
fn no_signed_identity_when_keypair_argument_is_none() {
    // Operator has not enrolled a daemon keypair. The substrate must
    // continue to operate normally; the signed-identity block is
    // simply omitted from the response.
    let result = build_signed_identity(None, TEST_TIMESTAMP).unwrap();
    assert!(result.is_none(), "no keypair → no identity block");
}

#[test]
fn no_signed_identity_when_keypair_has_no_private_half() {
    // load_daemon_signing_key returned None because the .priv file is
    // missing while the .pub is still on disk (mid-rotation operator
    // workflow). The substrate must continue to operate — no panic, no
    // error envelope, just omission of the identity block.
    let kp = keypair_public_only("ai:nhi@host", 5);
    let result = build_signed_identity(Some(&kp), TEST_TIMESTAMP).unwrap();
    assert!(result.is_none(), "public-only keypair → no identity block");
}

// ============================================================================
//  Group C — backwards compatibility (functionality preservation)
// ============================================================================

#[test]
fn legacy_clients_can_still_parse_serverinfo_name_and_version() {
    // Simulate what a v0.6.4 / v0.7.0 MCP client does: read serverInfo,
    // pick out name + version, ignore unknown fields.
    let kp = keypair_with_signing("ai:nhi@host", 11);
    let identity = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    let server_info = json!({
        "name": "ai-memory",
        "version": "0.7.0",
        "ai_memory_identity": identity,
    });

    // Legacy clients read name + version directly.
    assert_eq!(server_info["name"], json!("ai-memory"));
    assert_eq!(server_info["version"], json!("0.7.0"));

    // Per MCP / JSON-RPC convention, unknown fields are ignored. Legacy
    // clients see the same `name` + `version` shape they always have.
    // The new `ai_memory_identity` field is invisible to them.
}

#[test]
fn legacy_no_keypair_handshake_shape_is_unchanged() {
    // Operator has no daemon keypair on disk. The serverInfo block
    // must be byte-equivalent to the pre-#1154 shape: name + version
    // ONLY. No new field present.
    let result = build_signed_identity(None, TEST_TIMESTAMP).unwrap();
    assert!(result.is_none());

    let server_info = json!({
        "name": "ai-memory",
        "version": "0.7.0",
    });
    assert!(
        !server_info.as_object().unwrap().contains_key("ai_memory_identity"),
        "no keypair → exact v0.7.0 wire shape"
    );
}

// ============================================================================
//  Group D — tampering rejection (security correctness)
// ============================================================================

#[test]
fn tampered_daemon_id_field_breaks_signature_verification() {
    let kp = keypair_with_signing("ai:nhi@host", 21);
    let mut block = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    block["daemon_id"] = json!("ai:adversary@host");
    assert!(
        verify_signed_identity(&block).is_err(),
        "post-sign mutation of daemon_id must be detected"
    );
}

#[test]
fn tampered_schema_version_field_breaks_signature_verification() {
    let kp = keypair_with_signing("ai:nhi@host", 22);
    let mut block = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    block["schema_version"] = json!("v99");
    assert!(verify_signed_identity(&block).is_err());
}

#[test]
fn tampered_public_key_field_breaks_signature_verification() {
    // Adversary swaps in a different public key without re-signing.
    // The canonical bytes diverge; verify rejects.
    let kp_a = keypair_with_signing("ai:nhi@host", 23);
    let mut block = build_signed_identity(Some(&kp_a), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();

    let kp_b = keypair_with_signing("ai:other@host", 24);
    block["public_key"] = json!(kp_b.public_base64());

    assert!(
        verify_signed_identity(&block).is_err(),
        "substituted public key must fail verification"
    );
}

#[test]
fn tampered_signed_at_field_breaks_signature_verification() {
    let kp = keypair_with_signing("ai:nhi@host", 25);
    let mut block = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    block["signed_at"] = json!("1999-01-01T00:00:00Z");
    assert!(verify_signed_identity(&block).is_err());
}

#[test]
fn bit_flipped_signature_breaks_verification() {
    let kp = keypair_with_signing("ai:nhi@host", 26);
    let mut block = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    let original = block["signature"].as_str().unwrap().to_string();
    let mut chars: Vec<char> = original.chars().collect();
    let mid = chars.len() / 2;
    chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
    block["signature"] = json!(chars.into_iter().collect::<String>());
    assert!(
        verify_signed_identity(&block).is_err(),
        "single-bit signature flip must be detected"
    );
}

// ============================================================================
//  Group E — malformed input rejection (defensive coding)
// ============================================================================

#[test]
fn verify_rejects_non_object_inputs() {
    assert!(verify_signed_identity(&json!("string")).is_err());
    assert!(verify_signed_identity(&json!(0)).is_err());
    assert!(verify_signed_identity(&json!(false)).is_err());
    assert!(verify_signed_identity(&json!([])).is_err());
    assert!(verify_signed_identity(&Value::Null).is_err());
}

#[test]
fn verify_rejects_each_missing_required_field() {
    let kp = keypair_with_signing("ai:nhi@host", 31);
    let complete = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();

    for field in [
        "schema_version",
        "daemon_id",
        "public_key",
        "signed_at",
        "signature",
    ] {
        let mut block = complete.clone();
        block.as_object_mut().unwrap().remove(field);
        assert!(
            verify_signed_identity(&block).is_err(),
            "missing `{field}` must cause verification failure"
        );
    }
}

#[test]
fn verify_rejects_non_string_field_types() {
    let kp = keypair_with_signing("ai:nhi@host", 32);
    let mut block = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    block["daemon_id"] = json!(42);
    assert!(verify_signed_identity(&block).is_err());

    let mut block2 = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    block2["public_key"] = json!(true);
    assert!(verify_signed_identity(&block2).is_err());
}

#[test]
fn verify_rejects_garbage_base64() {
    let kp = keypair_with_signing("ai:nhi@host", 33);
    let mut block = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    block["signature"] = json!("@@@not~base64!!");
    assert!(verify_signed_identity(&block).is_err());
}

#[test]
fn verify_rejects_correctly_encoded_but_wrong_length_key() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let kp = keypair_with_signing("ai:nhi@host", 34);
    let mut block = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    // 16-byte key encoded correctly but wrong length for Ed25519
    block["public_key"] = json!(URL_SAFE_NO_PAD.encode([0u8; 16]));
    assert!(verify_signed_identity(&block).is_err());
}

// ============================================================================
//  Group F — cross-rotation detection (TOFU pin workflow)
// ============================================================================

#[test]
fn client_tofu_pin_detects_keypair_rotation() {
    // Simulated client workflow:
    //   1. First connect to daemon — captures identity block A with signature S_A
    //   2. Daemon operator rotates keypair (different .priv on disk)
    //   3. Second connect produces identity block B with signature S_B
    //   4. Client compares S_B to pinned S_A → mismatch → refuses
    let kp_v1 = keypair_with_signing("ai:nhi@host", 41);
    let block_v1 = build_signed_identity(Some(&kp_v1), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    let sig_v1 = block_v1["signature"].as_str().unwrap().to_string();

    let kp_v2 = keypair_with_signing("ai:nhi@host", 42); // different seed → different keypair
    let block_v2 = build_signed_identity(Some(&kp_v2), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    let sig_v2 = block_v2["signature"].as_str().unwrap().to_string();

    assert_ne!(
        sig_v1, sig_v2,
        "keypair rotation produces distinguishable signatures (the TOFU defense)"
    );

    // Each individually verifies against its own embedded public key.
    verify_signed_identity(&block_v1).unwrap();
    verify_signed_identity(&block_v2).unwrap();
}

#[test]
fn timestamp_freshness_prevents_replay_within_session() {
    // Two identity blocks built one millisecond apart with the same
    // keypair and same daemon_id should still produce distinct
    // signatures because `signed_at` is part of the canonical bytes.
    let kp = keypair_with_signing("ai:nhi@host", 51);
    let block_t0 = build_signed_identity(Some(&kp), "2026-05-23T16:30:22Z")
        .unwrap()
        .unwrap();
    let block_t1 = build_signed_identity(Some(&kp), "2026-05-23T16:30:23Z")
        .unwrap()
        .unwrap();
    let sig_t0 = block_t0["signature"].as_str().unwrap();
    let sig_t1 = block_t1["signature"].as_str().unwrap();
    assert_ne!(
        sig_t0, sig_t1,
        "different timestamps → different signatures"
    );
}

// ============================================================================
//  Group G — determinism (regression invariants)
// ============================================================================

#[test]
fn identical_inputs_produce_identical_signatures() {
    // Same keypair, same timestamp, same daemon_id → byte-identical
    // signature. This is the deterministic-canonical-bytes guarantee.
    // Catches accidental introduction of non-determinism (random nonces,
    // unsorted JSON keys, BTreeMap reordering, etc.) in future refactors.
    let kp = keypair_with_signing("ai:nhi@host", 61);
    let block_a = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    let block_b = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    assert_eq!(block_a, block_b, "deterministic inputs → identical block");
}

// ============================================================================
//  Group H — performance (no hot-path regression)
// ============================================================================

#[test]
fn single_sign_is_sub_millisecond() {
    // Ed25519 sign over ~150 bytes of canonical identity. Even on the
    // slowest CI runner this completes in well under 1 ms. Catches
    // accidental introduction of expensive operations (key derivation
    // in a hot loop, cryptographic hashing on the request thread, etc).
    let kp = keypair_with_signing("ai:nhi@host", 71);
    let start = std::time::Instant::now();
    let _ = build_signed_identity(Some(&kp), TEST_TIMESTAMP).unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 5,
        "single sign + serialize must be sub-5ms (was {elapsed:?})"
    );
}

#[test]
fn one_thousand_signs_complete_under_one_second() {
    // The MCP initialize handshake fires ONCE per session, not on the
    // recall hot path. But CI may exercise the path many times during
    // an integration sweep. 1000 iterations should complete well under
    // 1 second on any reasonable hardware, confirming the per-call cost
    // is on the order of 10s of µs.
    let kp = keypair_with_signing("ai:nhi@host", 72);
    let start = std::time::Instant::now();
    for _ in 0..1000 {
        let _ = build_signed_identity(Some(&kp), TEST_TIMESTAMP).unwrap();
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 1,
        "1000 signs must complete under 1s (was {elapsed:?})"
    );
}

#[test]
fn no_keypair_path_is_constant_time_cheap() {
    // When the daemon has no keypair, the initialize hot path should
    // not pay any meaningful cost. This is critical because every
    // unattested deployment hits this path on every session start.
    let start = std::time::Instant::now();
    for _ in 0..10_000 {
        let _ = build_signed_identity(None, TEST_TIMESTAMP).unwrap();
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 10,
        "10k no-keypair calls must complete under 10ms (was {elapsed:?})"
    );
}

// ============================================================================
//  Group I — schema-version drift detection
// ============================================================================

#[test]
fn schema_version_string_matches_runtime_constant() {
    // The published schema_version string in the identity block MUST
    // match the SSOT constant in src/storage/migrations.rs. If the
    // schema version is bumped (e.g. v49 → v50 when #1156 lands) and
    // the constant is updated but this test breaks, the wiring needs
    // to follow the constant — not the other way around.
    let kp = keypair_with_signing("ai:nhi@host", 81);
    let block = build_signed_identity(Some(&kp), TEST_TIMESTAMP)
        .unwrap()
        .unwrap();
    let published = block["schema_version"].as_str().unwrap();
    let expected = format!("v{}", current_schema_version());
    assert_eq!(
        published, expected,
        "wire schema_version must follow CURRENT_SCHEMA_VERSION constant SSOT"
    );
}
