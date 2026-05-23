// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Daemon-side Ed25519-signed `serverInfo` block published in the MCP
//! initialize handshake response.
//!
//! Closes NSA CSI MCP Security concern (j) — Tool invocation path
//! confusion — at the substrate boundary. See [issue #1154][1] for the
//! full implementation specification and procurement context, and
//! [`docs/compliance/nsa-csi-mcp.html`][2] for the public-facing
//! coverage page.
//!
//! [1]: https://github.com/alphaonedev/ai-memory-mcp/issues/1154
//! [2]: https://alphaonedev.github.io/ai-memory-mcp/compliance/nsa-csi-mcp.html
//!
//! # Threat model — what this defends against
//!
//! An MCP client (Claude Code, Cursor, Cline, Codex, OpenClaw, ...) can
//! mount multiple MCP servers concurrently. The MCP protocol does not
//! mandate cryptographic server attestation at handshake time, so a
//! misconfigured or adversarial second server advertising the same tool
//! names (e.g. `memory_recall`) can shadow the legitimate ai-memory
//! daemon. ai-memory's defense at v0.7.0 captured `clientInfo.name`
//! during the handshake (proving WHICH client made a call for audit
//! purposes) but did not publish a cryptographic server identity the
//! client could pin.
//!
//! This module closes the second half. When the daemon has an Ed25519
//! keypair on disk (under `<key_dir>/<agent_id>.{pub,priv}` —
//! `load_daemon_signing_key` at [`crate::governance::audit`]), the
//! initialize response carries an `ai_memory_identity` block in
//! `serverInfo`:
//!
//! ```json
//! {
//!   "serverInfo": {
//!     "name": "ai-memory",
//!     "version": "<binary>",         // populated from `CARGO_PKG_VERSION` (SSOT)
//!     "ai_memory_identity": {
//!       "schema_version": "v<current>",   // populated from `current_schema_version()` (SSOT)
//!       "daemon_id": "ai:nhi@host",
//!       "public_key": "<URL-safe base64 of 32-byte Ed25519 verifying key>",
//!       "signed_at": "2026-05-23T16:30:22Z",
//!       "signature": "<URL-safe base64 of 64-byte Ed25519 signature>"
//!     }
//!   }
//! }
//! ```
//!
//! Clients implement Trust On First Use (TOFU): on the first
//! `initialize` response from a given daemon, the client captures the
//! `ai_memory_identity` blob and stores its `signature`. On subsequent
//! connects, the client re-verifies the daemon presents the same
//! signed identity. A daemon swap with a different keypair on disk
//! (operator key rotation OR adversary substitution) produces a
//! distinguishable `signature`, allowing the client to refuse the
//! mismatched server.
//!
//! # Backwards compatibility
//!
//! The `ai_memory_identity` block is OMITTED when the daemon has no
//! keypair on disk. This preserves the v0.7.0 "continuing unsigned"
//! posture documented at `src/main.rs:96-98`. Operators who do not
//! enrol a daemon keypair see the same handshake shape v0.6.4 clients
//! saw; the block appears once they generate a keypair via
//! `ai-memory identity generate`.
//!
//! Per MCP protocol convention (JSON-RPC 2.0), clients MUST ignore
//! unknown response fields. v0.6.4 / v0.7.0 clients that do not
//! understand `ai_memory_identity` continue to function identically —
//! the field is additive on the wire and zero-risk on the compat axis.
//!
//! # Canonical-bytes discipline
//!
//! The signed canonical bytes are the deterministic JSON serialisation
//! of the four-field [`DaemonIdentityToSign`] struct (without the
//! signature itself). This mirrors the existing canonical-bytes
//! discipline established by [`crate::governance::rules_store::canonical_bytes_for_signing`]
//! for governance rules: include exactly the load-bearing fields,
//! exclude the signature, produce identical bytes on every re-sign.
//!
//! The signature is computed over the canonical bytes via
//! [`ed25519_dalek::SigningKey::sign`].
//!
//! # Performance
//!
//! Initialize fires ONCE per MCP session — not on the recall hot
//! path. A single Ed25519 sign over ~150 bytes of canonical identity
//! takes ~10–50 µs on modern hardware. The cost is dwarfed by the
//! JSON serialisation of the initialize response itself. The 50 ms
//! recall p95 budget is untouched.

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde_json::{Value, json};

use crate::identity::keypair::AgentKeypair;
use crate::storage::migrations::current_schema_version;

/// Field set canonically serialised for the daemon-identity Ed25519
/// signature. Mirrors the discipline established by
/// [`crate::governance::rules_store::canonical_bytes_for_signing`]:
/// the signed property is *what identity the daemon is presenting* —
/// schema version, daemon id, public key, and the handshake timestamp.
/// The signature itself is excluded from the signed bytes.
#[derive(Debug, Clone)]
pub struct DaemonIdentityToSign<'a> {
    /// Substrate schema version the daemon is running. Stamped at
    /// runtime from
    /// [`crate::storage::migrations::current_schema_version()`] (the
    /// SSOT — see also `CURRENT_SCHEMA_VERSION` in
    /// `src/storage/migrations.rs`). Allows the TOFU-pinning client
    /// to detect a schema rollback / rollforward separately from a
    /// key rotation.
    pub schema_version: &'a str,
    /// Resolved daemon `agent_id` — the same identifier used for V-4
    /// signed-events row attribution and outbound link signing.
    pub daemon_id: &'a str,
    /// URL-safe, no-padding base64 of the 32-byte Ed25519 verifying
    /// key. Same format `AgentKeypair::public_base64` emits.
    pub public_key: &'a str,
    /// RFC3339 timestamp captured at handshake time. Pinned into the
    /// signed bytes so a client can detect signature replay across
    /// time-disjoint handshake windows.
    pub signed_at: &'a str,
}

/// Produce the canonical byte representation of the daemon identity
/// used as input to the Ed25519 sign + verify operations.
///
/// The canonical form is the deterministic JSON serialisation of the
/// four-field identity object. The order is fixed at the call site
/// (see [`canonical_bytes_for_identity`]); `serde_json::to_vec`
/// preserves key order on serde-derived `Serialize` impls. Since this
/// module owns both the signer and verifier code paths and both use
/// this same function, deterministic byte equality is guaranteed by
/// construction — no external canonicalisation library is required.
///
/// # Errors
///
/// Propagates `serde_json` encoding errors (unreachable in practice
/// for the field set above, but surfaced for completeness).
pub fn canonical_bytes_for_identity(identity: &DaemonIdentityToSign<'_>) -> Result<Vec<u8>> {
    let canonical = json!({
        "schema_version": identity.schema_version,
        "daemon_id": identity.daemon_id,
        "public_key": identity.public_key,
        "signed_at": identity.signed_at,
    });
    serde_json::to_vec(&canonical)
        .context("server_identity::canonical_bytes_for_identity: serialize")
}

/// Build the signed `ai_memory_identity` block for the MCP initialize
/// response. Returns `None` when `keypair` is `None` or its private
/// half is missing — caller omits the block from the response in that
/// case, preserving the v0.7.0 "continuing unsigned" posture.
///
/// On the happy path the returned [`Value`] is a JSON object with five
/// fields: `schema_version`, `daemon_id`, `public_key`, `signed_at`,
/// `signature`. The first four fields are the inputs to the canonical
/// bytes; the fifth is the Ed25519 signature over those bytes.
///
/// `now_rfc3339` is injected as a parameter (rather than read from
/// `chrono::Utc::now()` directly) so tests can pin the timestamp for
/// reproducible assertions. Production callers pass the current UTC
/// time formatted to RFC3339 with second precision.
///
/// # Errors
///
/// Propagates errors from [`canonical_bytes_for_identity`]. Returns
/// `Ok(None)` (not `Err`) when the keypair cannot sign — refusing to
/// sign is a normal posture, not an error condition.
pub fn build_signed_identity(
    keypair: Option<&AgentKeypair>,
    now_rfc3339: &str,
) -> Result<Option<Value>> {
    let Some(kp) = keypair else {
        return Ok(None);
    };
    let Some(signing_key) = kp.private.as_ref() else {
        return Ok(None);
    };

    let schema_version = format!("v{}", current_schema_version());
    let public_key = kp.public_base64();
    let identity = DaemonIdentityToSign {
        schema_version: &schema_version,
        daemon_id: &kp.agent_id,
        public_key: &public_key,
        signed_at: now_rfc3339,
    };
    let canonical = canonical_bytes_for_identity(&identity)?;
    let signature: Signature = signing_key.sign(&canonical);
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(Some(json!({
        "schema_version": schema_version,
        "daemon_id": kp.agent_id,
        "public_key": public_key,
        "signed_at": now_rfc3339,
        "signature": sig_b64,
    })))
}

/// Verify a previously-built `ai_memory_identity` block against the
/// embedded public key. Returns `Ok(())` when the signature is
/// well-formed, matches the canonical bytes of the four signed
/// fields, and verifies against the embedded public key.
///
/// Clients use this on TOFU pin acquisition (first connect) and on
/// every subsequent handshake. The verification is self-contained —
/// no operator-side public key is required because the daemon
/// publishes its own. A client wanting cross-deployment key custody
/// can pair this with an out-of-band allowlist.
///
/// # Errors
///
/// - Returns a `SignatureError` when any required field is missing or
///   not a string.
/// - Returns a `SignatureError` when `public_key` or `signature` is
///   not valid URL-safe base64.
/// - Returns a `SignatureError` when `public_key` does not decode to
///   32 bytes or `signature` does not decode to 64 bytes.
/// - Returns a `SignatureError` when the Ed25519 verify call fails
///   (tampered identity block, wrong key, or replay across a daemon
///   keypair rotation — exactly the bypass attempts this catches).
pub fn verify_signed_identity(block: &Value) -> Result<(), ed25519_dalek::SignatureError> {
    let make_err = ed25519_dalek::SignatureError::new;

    let obj = block.as_object().ok_or_else(make_err)?;
    let schema_version = obj
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or_else(make_err)?;
    let daemon_id = obj
        .get("daemon_id")
        .and_then(Value::as_str)
        .ok_or_else(make_err)?;
    let public_key_b64 = obj
        .get("public_key")
        .and_then(Value::as_str)
        .ok_or_else(make_err)?;
    let signed_at = obj
        .get("signed_at")
        .and_then(Value::as_str)
        .ok_or_else(make_err)?;
    let signature_b64 = obj
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(make_err)?;

    let public_key_bytes = URL_SAFE_NO_PAD
        .decode(public_key_b64)
        .map_err(|_| make_err())?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| make_err())?;

    if public_key_bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
        return Err(make_err());
    }
    if signature_bytes.len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Err(make_err());
    }
    let mut pk_arr = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
    pk_arr.copy_from_slice(&public_key_bytes);
    let mut sig_arr = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
    sig_arr.copy_from_slice(&signature_bytes);

    let verifying_key = VerifyingKey::from_bytes(&pk_arr).map_err(|_| make_err())?;
    let signature = Signature::from_bytes(&sig_arr);

    let identity = DaemonIdentityToSign {
        schema_version,
        daemon_id,
        public_key: public_key_b64,
        signed_at,
    };
    let canonical = canonical_bytes_for_identity(&identity).map_err(|_| make_err())?;
    verifying_key.verify(&canonical, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn make_test_keypair(agent_id: &str) -> AgentKeypair {
        // Deterministic seed so test signatures are byte-stable across runs.
        let seed = [42u8; ed25519_dalek::SECRET_KEY_LENGTH];
        let signing_key = SigningKey::from_bytes(&seed);
        AgentKeypair {
            agent_id: agent_id.to_string(),
            public: signing_key.verifying_key(),
            private: Some(signing_key),
        }
    }

    fn make_public_only_keypair(agent_id: &str) -> AgentKeypair {
        let kp = make_test_keypair(agent_id);
        AgentKeypair {
            agent_id: kp.agent_id,
            public: kp.public,
            private: None,
        }
    }

    fn fixed_timestamp() -> &'static str {
        "2026-05-23T16:30:22Z"
    }

    // --- canonical_bytes_for_identity tests -----------------------------------

    // NOTE: schema-version values in this test module are synthetic
    // fixtures (`vTEST_*`) — they exist only to exercise the canonical-
    // bytes determinism + divergence properties and DO NOT track the
    // real `CURRENT_SCHEMA_VERSION`. Hardcoded production schema
    // literals are banned in this codebase; the runtime path consumes
    // `crate::storage::migrations::current_schema_version()` as the
    // single source of truth.

    #[test]
    fn canonical_bytes_are_deterministic() {
        let id = DaemonIdentityToSign {
            schema_version: "vTEST_BASE",
            daemon_id: "ai:nhi@host",
            public_key: "abc123",
            signed_at: fixed_timestamp(),
        };
        let bytes_a = canonical_bytes_for_identity(&id).unwrap();
        let bytes_b = canonical_bytes_for_identity(&id).unwrap();
        assert_eq!(
            bytes_a, bytes_b,
            "canonical bytes must be deterministic across calls"
        );
    }

    #[test]
    fn canonical_bytes_diverge_on_any_field_change() {
        let base = DaemonIdentityToSign {
            schema_version: "vTEST_BASE",
            daemon_id: "ai:nhi@host",
            public_key: "abc123",
            signed_at: fixed_timestamp(),
        };
        let base_bytes = canonical_bytes_for_identity(&base).unwrap();

        let cases = [
            DaemonIdentityToSign {
                schema_version: "vTEST_CHANGED",
                ..base.clone()
            },
            DaemonIdentityToSign {
                daemon_id: "ai:other@host",
                ..base.clone()
            },
            DaemonIdentityToSign {
                public_key: "abc124",
                ..base.clone()
            },
            DaemonIdentityToSign {
                signed_at: "2026-05-24T00:00:00Z",
                ..base.clone()
            },
        ];

        for (i, mutated) in cases.iter().enumerate() {
            let mutated_bytes = canonical_bytes_for_identity(mutated).unwrap();
            assert_ne!(
                base_bytes, mutated_bytes,
                "canonical bytes must diverge when field {i} changes"
            );
        }
    }

    // --- build_signed_identity tests ------------------------------------------

    #[test]
    fn build_signed_identity_returns_none_when_keypair_absent() {
        let result = build_signed_identity(None, fixed_timestamp()).unwrap();
        assert!(result.is_none(), "absent keypair must yield None");
    }

    #[test]
    fn build_signed_identity_returns_none_when_private_key_missing() {
        let kp = make_public_only_keypair("ai:nhi@host");
        let result = build_signed_identity(Some(&kp), fixed_timestamp()).unwrap();
        assert!(result.is_none(), "public-only keypair must yield None");
    }

    #[test]
    fn build_signed_identity_returns_well_formed_block_when_signing_key_present() {
        let kp = make_test_keypair("ai:nhi@host");
        let block = build_signed_identity(Some(&kp), fixed_timestamp())
            .unwrap()
            .expect("signing keypair must yield Some");

        let obj = block.as_object().expect("block must be a JSON object");
        assert!(obj.get("schema_version").and_then(Value::as_str).is_some());
        assert!(obj.get("daemon_id").and_then(Value::as_str).is_some());
        assert!(obj.get("public_key").and_then(Value::as_str).is_some());
        assert!(obj.get("signed_at").and_then(Value::as_str).is_some());
        assert!(obj.get("signature").and_then(Value::as_str).is_some());

        assert_eq!(obj["daemon_id"], json!("ai:nhi@host"));
        assert_eq!(obj["signed_at"], json!(fixed_timestamp()));
    }

    #[test]
    fn build_signed_identity_carries_current_schema_version() {
        let kp = make_test_keypair("ai:nhi@host");
        let block = build_signed_identity(Some(&kp), fixed_timestamp())
            .unwrap()
            .expect("signing keypair must yield Some");
        let schema = block["schema_version"].as_str().unwrap();
        let expected = format!("v{}", current_schema_version());
        assert_eq!(
            schema, expected,
            "schema_version must match CURRENT_SCHEMA_VERSION constant"
        );
    }

    #[test]
    fn build_signed_identity_carries_public_key_base64() {
        let kp = make_test_keypair("ai:nhi@host");
        let block = build_signed_identity(Some(&kp), fixed_timestamp())
            .unwrap()
            .expect("signing keypair must yield Some");
        let pk_b64 = block["public_key"].as_str().unwrap();
        assert_eq!(
            pk_b64,
            kp.public_base64(),
            "public_key must round-trip kp.public_base64()"
        );
    }

    // --- verify_signed_identity happy-path tests ------------------------------

    #[test]
    fn signed_identity_verifies_against_embedded_public_key() {
        let kp = make_test_keypair("ai:nhi@host");
        let block = build_signed_identity(Some(&kp), fixed_timestamp())
            .unwrap()
            .expect("signing keypair must yield Some");
        verify_signed_identity(&block).expect("signature must verify");
    }

    #[test]
    fn signed_identity_round_trips_across_many_signers() {
        // 16 distinct seeds → 16 distinct keypairs → 16 distinct signatures
        // that each individually verify against their own embedded pubkey.
        for byte in 0u8..16 {
            let seed = [byte; ed25519_dalek::SECRET_KEY_LENGTH];
            let signing_key = SigningKey::from_bytes(&seed);
            let kp = AgentKeypair {
                agent_id: format!("ai:agent-{byte}@host"),
                public: signing_key.verifying_key(),
                private: Some(signing_key),
            };
            let block = build_signed_identity(Some(&kp), fixed_timestamp())
                .unwrap()
                .expect("signing keypair must yield Some");
            verify_signed_identity(&block)
                .unwrap_or_else(|_| panic!("signature {byte} must verify"));
        }
    }

    // --- verify_signed_identity tampering tests -------------------------------

    #[test]
    fn tampered_daemon_id_fails_verification() {
        let kp = make_test_keypair("ai:nhi@host");
        let mut block = build_signed_identity(Some(&kp), fixed_timestamp())
            .unwrap()
            .expect("signing keypair must yield Some");
        block["daemon_id"] = json!("ai:adversary@host");
        assert!(
            verify_signed_identity(&block).is_err(),
            "tampered daemon_id must fail verification"
        );
    }

    #[test]
    fn tampered_schema_version_fails_verification() {
        let kp = make_test_keypair("ai:nhi@host");
        let mut block = build_signed_identity(Some(&kp), fixed_timestamp())
            .unwrap()
            .expect("signing keypair must yield Some");
        block["schema_version"] = json!("v99");
        assert!(
            verify_signed_identity(&block).is_err(),
            "tampered schema_version must fail verification"
        );
    }

    #[test]
    fn tampered_signed_at_fails_verification() {
        let kp = make_test_keypair("ai:nhi@host");
        let mut block = build_signed_identity(Some(&kp), fixed_timestamp())
            .unwrap()
            .expect("signing keypair must yield Some");
        block["signed_at"] = json!("2099-12-31T23:59:59Z");
        assert!(
            verify_signed_identity(&block).is_err(),
            "tampered signed_at must fail verification"
        );
    }

    #[test]
    fn tampered_signature_byte_fails_verification() {
        let kp = make_test_keypair("ai:nhi@host");
        let mut block = build_signed_identity(Some(&kp), fixed_timestamp())
            .unwrap()
            .expect("signing keypair must yield Some");
        let original_sig = block["signature"].as_str().unwrap();
        // Flip a single character mid-signature
        let mut chars: Vec<char> = original_sig.chars().collect();
        let mid = chars.len() / 2;
        chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        block["signature"] = json!(tampered);
        assert!(
            verify_signed_identity(&block).is_err(),
            "tampered signature must fail verification"
        );
    }

    #[test]
    fn substituted_public_key_fails_verification() {
        let kp_a = make_test_keypair("ai:nhi@host");
        let mut block = build_signed_identity(Some(&kp_a), fixed_timestamp())
            .unwrap()
            .expect("signing keypair must yield Some");

        // Build a different keypair and substitute its public key into the block
        // without re-signing — exactly the substitution attack the canonical
        // bytes discipline catches.
        let seed_b = [99u8; ed25519_dalek::SECRET_KEY_LENGTH];
        let kp_b_signing = SigningKey::from_bytes(&seed_b);
        let kp_b_public_b64 = URL_SAFE_NO_PAD.encode(kp_b_signing.verifying_key().to_bytes());
        block["public_key"] = json!(kp_b_public_b64);

        assert!(
            verify_signed_identity(&block).is_err(),
            "substituted public key (without re-signing) must fail verification"
        );
    }

    // --- verify_signed_identity malformed-input tests -------------------------

    #[test]
    fn verify_rejects_non_object_input() {
        assert!(verify_signed_identity(&json!("not an object")).is_err());
        assert!(verify_signed_identity(&json!(42)).is_err());
        assert!(verify_signed_identity(&json!([1, 2, 3])).is_err());
        assert!(verify_signed_identity(&json!(null)).is_err());
    }

    #[test]
    fn verify_rejects_missing_required_field() {
        let kp = make_test_keypair("ai:nhi@host");
        let full_block = build_signed_identity(Some(&kp), fixed_timestamp())
            .unwrap()
            .expect("signing keypair must yield Some");

        for field in &[
            "schema_version",
            "daemon_id",
            "public_key",
            "signed_at",
            "signature",
        ] {
            let mut block = full_block.clone();
            block.as_object_mut().unwrap().remove(*field);
            assert!(
                verify_signed_identity(&block).is_err(),
                "missing field {field} must cause verification failure"
            );
        }
    }

    #[test]
    fn verify_rejects_invalid_base64() {
        let kp = make_test_keypair("ai:nhi@host");
        let mut block = build_signed_identity(Some(&kp), fixed_timestamp())
            .unwrap()
            .expect("signing keypair must yield Some");
        block["public_key"] = json!("@@@not-base64@@@");
        assert!(verify_signed_identity(&block).is_err());

        let mut block2 = build_signed_identity(Some(&kp), fixed_timestamp())
            .unwrap()
            .expect("signing keypair must yield Some");
        block2["signature"] = json!("@@@not-base64@@@");
        assert!(verify_signed_identity(&block2).is_err());
    }

    #[test]
    fn verify_rejects_wrong_length_public_key() {
        let kp = make_test_keypair("ai:nhi@host");
        let mut block = build_signed_identity(Some(&kp), fixed_timestamp())
            .unwrap()
            .expect("signing keypair must yield Some");
        // 16 bytes instead of 32
        block["public_key"] = json!(URL_SAFE_NO_PAD.encode([0u8; 16]));
        assert!(verify_signed_identity(&block).is_err());
    }

    #[test]
    fn verify_rejects_wrong_length_signature() {
        let kp = make_test_keypair("ai:nhi@host");
        let mut block = build_signed_identity(Some(&kp), fixed_timestamp())
            .unwrap()
            .expect("signing keypair must yield Some");
        // 32 bytes instead of 64
        block["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 32]));
        assert!(verify_signed_identity(&block).is_err());
    }

    // --- performance smoke test ----------------------------------------------

    #[test]
    fn build_signed_identity_completes_under_10ms_one_iteration() {
        let kp = make_test_keypair("ai:nhi@host");
        let start = std::time::Instant::now();
        let _ = build_signed_identity(Some(&kp), fixed_timestamp()).unwrap();
        let elapsed = start.elapsed();
        // Ed25519 sign over ~150 bytes is ~10-50µs on modern hardware;
        // 10ms is a 200-1000x margin to absorb CI noise. The test
        // smoke-checks the order of magnitude is correct.
        assert!(
            elapsed.as_millis() < 10,
            "single sign must be sub-10ms (was {elapsed:?})"
        );
    }
}
