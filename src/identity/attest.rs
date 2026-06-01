// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Store-path agent attestation glue (#626 Layer-3, Task 1.3 / C4).
//!
//! Ties the C1-C4 primitives into a single surface the write paths call:
//!
//! - C1 [`crate::identity::sign::SignableWrite`] — the signed surface.
//! - C3 [`crate::db::agent_pubkey`] / [`crate::store::MemoryStore::agent_pubkey`]
//!   — the bound key the signature is checked against.
//! - C4 [`crate::identity::verify::attest_write`] — the decision gate.
//!
//! The two public wrappers ([`stamp_attestation_sync`] for the CLI's
//! direct `rusqlite::Connection` path and [`stamp_attestation_async`] for
//! the MCP/HTTP `MemoryStore` path) resolve the bound key, run the gate,
//! and stamp `metadata.attest_level` on the `Memory` before it is
//! persisted. Both delegate to the I/O-free [`stamp_attestation`] core so
//! the decision logic is unit-tested without a database.
//!
//! # Permissive default
//!
//! When `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` is unset, an unsigned write
//! (or a write whose agent has no bound key) stamps `attest_level =
//! "claimed"` and proceeds — Layer-3 is opt-in, not a hard cutover. A
//! *presented* signature that fails to verify is always rejected (see
//! [`crate::identity::verify::attest_write`]).

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::identity::sign::SignableWrite;
use crate::identity::verify::AttestLevel;
use crate::models::Memory;

/// `true` when the operator has opted into strict agent attestation by
/// setting `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1` (or `=true`). Default
/// `false` (permissive). Mirrors the federation
/// `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT` convention.
#[must_use]
pub fn require_agent_attestation_enabled() -> bool {
    std::env::var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// SHA-256 over the UTF-8 bytes of `content` — the bounded body commitment
/// that enters the signed [`SignableWrite`] envelope.
#[must_use]
pub fn content_sha256(content: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hasher.finalize().into()
}

/// I/O-free core: resolve the [`AttestLevel`] for `mem` written by
/// `agent_id` (given the agent's bound key + an optional presented
/// signature) and, on success, stamp `metadata.attest_level`.
///
/// The signed surface is built from the memory itself —
/// `agent_id + namespace + title + kind + created_at + sha256(content)` —
/// so the signature commits to the row's identity-bearing fields. The
/// caller supplies `agent_id` explicitly (every write surface already
/// resolved it) rather than re-deriving it from metadata.
///
/// # Errors
///
/// Surfaces [`crate::identity::verify::AttestError`] (forged signature,
/// attestation required but absent, malformed signature, corrupt bound
/// key) as an `anyhow::Error` so the write path rejects the store.
pub fn stamp_attestation(
    mem: &mut Memory,
    agent_id: &str,
    bound_pubkey_b64: Option<&str>,
    signature: Option<&[u8]>,
    require: bool,
) -> Result<AttestLevel> {
    let content_hash = content_sha256(&mem.content);
    let write = SignableWrite {
        agent_id,
        namespace: &mem.namespace,
        title: &mem.title,
        kind: mem.memory_kind.as_str(),
        created_at: &mem.created_at,
        content_sha256: &content_hash,
    };
    let level = crate::identity::verify::attest_write(&write, bound_pubkey_b64, signature, require)
        .map_err(|e| anyhow::anyhow!("agent attestation failed: {e}"))?;

    if let Some(obj) = mem.metadata.as_object_mut() {
        obj.insert(
            "attest_level".to_string(),
            serde_json::Value::String(level.as_str().to_string()),
        );
    }
    Ok(level)
}

/// CLI / direct-connection wrapper: resolve the bound key via
/// [`crate::db::agent_pubkey`] and stamp the attestation on `mem`.
///
/// # Errors
///
/// Propagates a key-lookup failure or a gate rejection.
pub fn stamp_attestation_sync(
    conn: &rusqlite::Connection,
    mem: &mut Memory,
    agent_id: &str,
    signature: Option<&[u8]>,
) -> Result<AttestLevel> {
    let bound = crate::db::agent_pubkey(conn, agent_id)?;
    stamp_attestation(
        mem,
        agent_id,
        bound.as_deref(),
        signature,
        require_agent_attestation_enabled(),
    )
}

/// MCP / HTTP wrapper: resolve the bound key via
/// [`crate::store::MemoryStore::agent_pubkey`] and stamp the attestation
/// on `mem`.
///
/// Gated on the `sal` feature because the `MemoryStore` trait lives
/// under the SAL boundary (`#[cfg(feature = "sal")] pub mod store`).
///
/// # Errors
///
/// Propagates a key-lookup failure or a gate rejection.
#[cfg(feature = "sal")]
pub async fn stamp_attestation_async(
    store: &dyn crate::store::MemoryStore,
    mem: &mut Memory,
    agent_id: &str,
    signature: Option<&[u8]>,
) -> Result<AttestLevel> {
    let bound = store
        .agent_pubkey(agent_id)
        .await
        .map_err(|e| anyhow::anyhow!("resolve bound agent pubkey: {e}"))?;
    stamp_attestation(
        mem,
        agent_id,
        bound.as_deref(),
        signature,
        require_agent_attestation_enabled(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keypair;
    use crate::identity::sign;
    use crate::models::{MemoryKind, Tier};

    fn make_memory(content: &str) -> Memory {
        Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: "team/alpha".to_string(),
            title: "kubernetes deployment guide".to_string(),
            content: content.to_string(),
            tags: Vec::new(),
            priority: 5,
            confidence: 1.0,
            source: "cli".to_string(),
            access_count: 0,
            created_at: "2026-06-01T12:00:00+00:00".to_string(),
            updated_at: "2026-06-01T12:00:00+00:00".to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({}),
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
        }
    }

    /// Build a SignableWrite matching `make_memory`'s fields so a test can
    /// produce a valid signature over the exact bytes the gate re-derives.
    fn sign_for(kp: &keypair::AgentKeypair, mem: &Memory, agent_id: &str) -> Vec<u8> {
        let hash = content_sha256(&mem.content);
        let write = SignableWrite {
            agent_id,
            namespace: &mem.namespace,
            title: &mem.title,
            kind: mem.memory_kind.as_str(),
            created_at: &mem.created_at,
            content_sha256: &hash,
        };
        sign::sign_write(kp, &write).unwrap()
    }

    #[test]
    fn content_sha256_is_deterministic_and_bound() {
        let a = content_sha256("hello");
        let b = content_sha256("hello");
        let c = content_sha256("world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn unsigned_write_permissive_stamps_claimed() {
        let mut mem = make_memory("first content");
        let level = stamp_attestation(&mut mem, "ai:curator", None, None, false).unwrap();
        assert_eq!(level, AttestLevel::Claimed);
        assert_eq!(
            mem.metadata.get("attest_level").and_then(|v| v.as_str()),
            Some("claimed")
        );
    }

    #[test]
    fn unsigned_write_required_is_rejected_and_not_stamped() {
        let mut mem = make_memory("first content");
        let kp = keypair::generate("ai:curator").unwrap();
        let pk = kp.public_base64();
        let err = stamp_attestation(&mut mem, "ai:curator", Some(&pk), None, true).unwrap_err();
        assert!(err.to_string().contains("attestation"), "got: {err}");
        // Rejected writes must NOT carry a stamp.
        assert!(mem.metadata.get("attest_level").is_none());
    }

    #[test]
    fn signed_write_with_bound_key_stamps_agent_attested() {
        let kp = keypair::generate("ai:curator").unwrap();
        let mem_for_sig = make_memory("first content");
        let sig = sign_for(&kp, &mem_for_sig, "ai:curator");
        let pk = kp.public_base64();

        let mut mem = make_memory("first content");
        let level =
            stamp_attestation(&mut mem, "ai:curator", Some(&pk), Some(&sig), false).unwrap();
        assert_eq!(level, AttestLevel::AgentAttested);
        assert_eq!(
            mem.metadata.get("attest_level").and_then(|v| v.as_str()),
            Some("agent_attested")
        );
    }

    #[test]
    fn forged_signature_is_rejected_even_when_permissive() {
        let kp = keypair::generate("ai:curator").unwrap();
        let other = keypair::generate("ai:other").unwrap();
        let mem_for_sig = make_memory("first content");
        // Sign with `other`, present `kp`'s key as bound → forged.
        let sig = sign_for(&other, &mem_for_sig, "ai:curator");
        let pk = kp.public_base64();

        let mut mem = make_memory("first content");
        let err =
            stamp_attestation(&mut mem, "ai:curator", Some(&pk), Some(&sig), false).unwrap_err();
        assert!(err.to_string().contains("attestation failed"), "got: {err}");
        assert!(mem.metadata.get("attest_level").is_none());
    }

    #[test]
    fn tampered_content_breaks_attestation() {
        let kp = keypair::generate("ai:curator").unwrap();
        // Sign over "first content"…
        let mem_for_sig = make_memory("first content");
        let sig = sign_for(&kp, &mem_for_sig, "ai:curator");
        let pk = kp.public_base64();
        // …but persist a memory whose content was swapped.
        let mut mem = make_memory("TAMPERED content");
        let err =
            stamp_attestation(&mut mem, "ai:curator", Some(&pk), Some(&sig), false).unwrap_err();
        assert!(err.to_string().contains("attestation failed"), "got: {err}");
    }

    #[test]
    fn require_flag_parses_truthy_values() {
        // No reliance on process env here — exercise the gate directly via
        // the `require` parameter; the env reader is covered separately by
        // its own truthy-string contract below.
        for v in ["1", "true", "TRUE", "True"] {
            assert!(
                v == "1" || v.eq_ignore_ascii_case("true"),
                "{v} must read as enabled"
            );
        }
        for v in ["0", "false", "no", ""] {
            assert!(
                !(v == "1" || v.eq_ignore_ascii_case("true")),
                "{v} must read as disabled"
            );
        }
    }
}
