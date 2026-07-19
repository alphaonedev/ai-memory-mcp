// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G8 (#1825) — additive, content-addressed BLAKE3 content-id (CID)
//! for a memory's GENESIS identity.
//!
//! # What a CID is (and is not)
//!
//! Every stored memory keeps its UUID primary key untouched — the UUID
//! remains the PK, every FK, and the federation last-writer-wins
//! tiebreak. The CID is an ADDITIVE second name derived from the memory's
//! *genesis* identity (the fields fixed at creation time): the writing
//! `agent_id`, the `namespace`, the `title`, the `memory_kind`, the
//! `created_at` instant, and a one-way digest of the original `content`.
//! It is a `b3:<hex>` string computed once, at the genesis INSERT, and
//! never recomputed from mutable state.
//!
//! The pre-image is built in the [`crate::revisions::revision_leaf_signable_bytes`]
//! / [`crate::signed_events::compute_cause_hash`] house style: a versioned
//! domain-separation prefix, then delimiter-joined identity fields, then a
//! SHA-256 of the *screened* content as the sole content-derived term. The
//! OUTER address hash is BLAKE3 (`b3:` prefix); the INNER content digest
//! and the audit spine stay on SHA-256 (`sha2`) — BLAKE3 is introduced
//! ONLY as the outer content-address function.
//!
//! # Federation mode-independence (critical)
//!
//! Both the `title` and the `content` are folded through
//! [`crate::secret_screen::screen`] **mode-independently** before they
//! enter the pre-image. [`crate::secret_screen::screen`] runs its
//! detectors unconditionally — it does NOT consult
//! `AI_MEMORY_SECRET_SCREEN_MODE` — so two federated nodes configured with
//! DIFFERENT screen modes (`off` / `redact` / `refuse`) deterministically
//! fold the SAME credential span to the SAME `[REDACTED:secret]`
//! placeholder and therefore mint the SAME cid for the same genesis. If we
//! instead hashed the raw content, a node that stored the redacted form and
//! a node that stored the raw form would disagree on the cid for the same
//! logical memory, breaking receive-time equivalence. Screening the title +
//! content before the hash ALSO means the stored SHA-256 never carries a
//! recoverable credential.
//!
//! # Claim scope (§26.5 honesty)
//!
//! A CID delivers: (1) genesis-identity binding — a stable content-address
//! for "the same memory" independent of the UUID; (2) PARTIAL-corruption
//! detection — a stray bit-flip in `cid` or `cid_genesis` is caught by
//! [`verify_cid`]; (3) federation receive-time equivalence (above); and
//! (4) the G13 lineage-node id. A CID is **NOT** at-rest cryptographic
//! forgery-evidence: a consistent re-forge that rewrites BOTH `cid` and
//! `cid_genesis` from tampered fields verifies clean (the two are
//! self-consistent). The unforgeable anchor is the deferred keyed /
//! Ed25519 `SignableWrite` binding — CID is explicitly NOT
//! "tamper-evident by construction" beyond partial corruption.

use sha2::{Digest, Sha256};

use crate::secret_screen::{ScreenOutcome, screen};

/// Versioned domain-separation prefix for the cid pre-image. The trailing
/// NUL keeps a future shape change from colliding with a v1 pre-image
/// (mirrors [`crate::revisions`] `memory-revision-v1\0`).
pub const CID_DOMAIN: &[u8] = b"memory-cid-v1\x00";

/// Field separator for [`canonical_cid_preimage`]. ASCII 0x1F ("Unit
/// Separator") — present in neither RFC3339 timestamps, UUID-ish ids, nor
/// namespace strings, so it cannot collide with field content. Matches the
/// [`crate::revisions`] canonical-bytes separator.
const FIELD_SEP: u8 = 0x1F;

/// The `b3:` scheme prefix every cid carries (BLAKE3 outer address hash).
pub const CID_SCHEME_PREFIX: &str = "b3:";

/// Fold one field through [`crate::secret_screen::screen`]
/// mode-independently: return the redacted form when a credential span
/// fires, else the original. Deterministic + mode-independent, so two
/// federated nodes on different `AI_MEMORY_SECRET_SCREEN_MODE` settings
/// produce byte-identical output for the same input.
#[must_use]
fn screened(field: &str) -> String {
    match screen(field) {
        ScreenOutcome::Clean => field.to_string(),
        ScreenOutcome::Hit { redacted, .. } => redacted,
    }
}

/// Build the canonical cid PRE-IMAGE (the value stored in the
/// `cid_genesis` BLOB and hashed by [`compute_cid`]):
///
/// ```text
/// CID_DOMAIN || agent_id || 0x1F || namespace || 0x1F || screen(title)
///           || 0x1F || kind || 0x1F || created_at || 0x1F
///           || SHA256(screen(content))
/// ```
///
/// `title` and `content` are folded through
/// [`crate::secret_screen::screen`] mode-independently BEFORE hashing (see
/// module docs) so the pre-image never carries a recoverable credential and
/// federated nodes on different screen modes converge on the same cid. The
/// raw content NEVER appears — only its (screened) SHA-256 digest does.
#[must_use]
pub fn canonical_cid_preimage(
    agent_id: &str,
    namespace: &str,
    title: &str,
    kind: &str,
    created_at: &str,
    content: &str,
) -> Vec<u8> {
    let title_s = screened(title);
    let content_digest = Sha256::digest(screened(content).as_bytes());

    let mut bytes = Vec::with_capacity(
        CID_DOMAIN.len()
            + agent_id.len()
            + namespace.len()
            + title_s.len()
            + kind.len()
            + created_at.len()
            + content_digest.len()
            + 5,
    );
    bytes.extend_from_slice(CID_DOMAIN);
    bytes.extend_from_slice(agent_id.as_bytes());
    bytes.push(FIELD_SEP);
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.push(FIELD_SEP);
    bytes.extend_from_slice(title_s.as_bytes());
    bytes.push(FIELD_SEP);
    bytes.extend_from_slice(kind.as_bytes());
    bytes.push(FIELD_SEP);
    bytes.extend_from_slice(created_at.as_bytes());
    bytes.push(FIELD_SEP);
    bytes.extend_from_slice(&content_digest);
    bytes
}

/// The `b3:<hex>` content-address over a cid pre-image. BLAKE3 is the OUTER
/// address hash (the only place BLAKE3 is used); the pre-image's inner
/// content term stays SHA-256.
#[must_use]
pub fn compute_cid(preimage: &[u8]) -> String {
    format!("{CID_SCHEME_PREFIX}{}", blake3::hash(preimage).to_hex())
}

/// A minted `(cid, cid_genesis)` pair. `genesis` is the canonical
/// pre-image bytes ([`canonical_cid_preimage`]) — persisted in the
/// `cid_genesis` BLOB so [`verify_cid`] can recompute the address without
/// re-reading (and re-screening) the row's plaintext content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidStamp {
    /// The `b3:<hex>` content-address (the `cid` TEXT column).
    pub cid: String,
    /// The canonical pre-image bytes (the `cid_genesis` BLOB column).
    pub genesis: Vec<u8>,
}

/// Mint a [`CidStamp`] from explicit genesis fields. The single SSOT every
/// genesis INSERT site funnels through so the on-disk `cid` / `cid_genesis`
/// pair is derived one way on both backends.
#[must_use]
pub fn stamp_cid(
    agent_id: &str,
    namespace: &str,
    title: &str,
    kind: &str,
    created_at: &str,
    content: &str,
) -> CidStamp {
    let genesis = canonical_cid_preimage(agent_id, namespace, title, kind, created_at, content);
    let cid = compute_cid(&genesis);
    CidStamp { cid, genesis }
}

/// Mint a [`CidStamp`] for a [`crate::models::Memory`] at genesis. Reads
/// `agent_id` from `metadata.agent_id` (empty when absent — the same
/// fallback the encryption/store paths use), the `kind` from
/// [`crate::models::MemoryKind::as_str`], and hashes the PLAINTEXT
/// `content` (callers MUST invoke this BEFORE any seal / placeholder swap,
/// never on the ciphertext).
#[must_use]
pub fn stamp_memory_cid(mem: &crate::models::Memory) -> CidStamp {
    let agent_id = mem
        .metadata
        .get("agent_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    stamp_cid(
        agent_id,
        &mem.namespace,
        &mem.title,
        mem.memory_kind.as_str(),
        &mem.created_at,
        &mem.content,
    )
}

/// A stored `cid` that does not match the BLAKE3 re-hash of its stored
/// `cid_genesis` pre-image — surfaced by [`verify_cid`] and folded into the
/// verify report's `cid_ok` flag. Catches PARTIAL corruption of either
/// column (see the module claim-scope note).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidMismatch {
    /// The `cid` value read from the row.
    pub stored: String,
    /// The `b3:<hex>` recomputed from the row's `cid_genesis`.
    pub recomputed: String,
}

impl std::fmt::Display for CidMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cid mismatch: stored {} but cid_genesis re-hashes to {}",
            self.stored, self.recomputed
        )
    }
}

/// Verify a stored `cid` against its stored `cid_genesis` pre-image:
/// recompute the BLAKE3 address over `stored_genesis` and compare. `Ok`
/// when they agree; [`CidMismatch`] otherwise.
///
/// This is PARTIAL-corruption detection only: a consistent re-forge that
/// rewrote BOTH columns from tampered fields verifies clean (the pair is
/// self-consistent). See the module claim-scope note.
///
/// # Errors
///
/// [`CidMismatch`] when `stored_cid != compute_cid(stored_genesis)`.
pub fn verify_cid(stored_cid: &str, stored_genesis: &[u8]) -> Result<(), CidMismatch> {
    let recomputed = compute_cid(stored_genesis);
    if recomputed == stored_cid {
        Ok(())
    } else {
        Err(CidMismatch {
            stored: stored_cid.to_string(),
            recomputed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Memory, MemoryKind, Tier};
    use serde_json::json;

    const AGENT: &str = "ai:alice@host";
    const NS: &str = "global";
    const TITLE: &str = "genesis title";
    const KIND: &str = "observation";
    const CREATED: &str = "2026-06-30T00:00:00Z";
    const CONTENT: &str = "the original body of the memory";

    fn base_memory() -> Memory {
        Memory {
            id: "11111111-1111-1111-1111-111111111111".to_string(),
            tier: Tier::Long,
            namespace: NS.to_string(),
            title: TITLE.to_string(),
            content: CONTENT.to_string(),
            tags: vec!["a".to_string()],
            priority: 5,
            confidence: 1.0,
            source: "nhi".to_string(),
            access_count: 0,
            created_at: CREATED.to_string(),
            updated_at: CREATED.to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({ "agent_id": AGENT }),
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: vec![],
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::default(),
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::default(),
            cid: None,
            valid_from: None,
            valid_until: None,
        }
    }

    #[test]
    fn cid_is_domain_prefixed_and_b3() {
        let s = stamp_cid(AGENT, NS, TITLE, KIND, CREATED, CONTENT);
        assert!(
            s.genesis.starts_with(CID_DOMAIN),
            "pre-image domain-prefixed"
        );
        assert!(
            s.cid.starts_with("b3:"),
            "cid carries the b3: scheme prefix"
        );
        // b3: + 64 hex chars (BLAKE3-256).
        assert_eq!(s.cid.len(), 3 + 64);
    }

    #[test]
    fn cid_is_identity_only_no_raw_content() {
        let s = stamp_cid(AGENT, NS, TITLE, KIND, CREATED, CONTENT);
        let hay = String::from_utf8_lossy(&s.genesis);
        // Identity fields present.
        assert!(hay.contains(AGENT));
        assert!(hay.contains(NS));
        assert!(hay.contains(TITLE));
        assert!(hay.contains(KIND));
        assert!(hay.contains(CREATED));
        // The raw content NEVER appears — only its SHA-256 digest does.
        assert!(
            !hay.contains(CONTENT),
            "raw content must never appear in the cid pre-image"
        );
        // The trailing 32 bytes are exactly SHA256(screen(content)).
        let digest = Sha256::digest(CONTENT.as_bytes());
        assert!(s.genesis.ends_with(&digest[..]));
    }

    #[test]
    fn title_and_content_are_secret_screened_before_hash() {
        // A GitHub PAT-shaped token screen() redacts to the placeholder.
        let token = "ghp_0123456789abcdefABCDEF0123456789abcdef";
        let secret_content = format!("here is a token {token} embedded");
        let secret_title = format!("titled with {token}");

        let s = stamp_cid(AGENT, NS, &secret_title, KIND, CREATED, &secret_content);
        let hay = String::from_utf8_lossy(&s.genesis);
        // The raw token must be unrecoverable from the stored pre-image
        // (screened out of the title AND folded away inside the content
        // SHA-256).
        assert!(
            !hay.contains(token),
            "screened title must not leak the token"
        );

        // The cid equals the cid computed over the manually pre-redacted
        // fields — proving screen() ran on BOTH title and content before
        // the hash, mode-independently.
        let placeholder = crate::secret_screen::REDACTION_PLACEHOLDER;
        let manual_title = format!("titled with {placeholder}");
        let manual_content = format!("here is a token {placeholder} embedded");
        let manual = stamp_cid(AGENT, NS, &manual_title, KIND, CREATED, &manual_content);
        assert_eq!(s.cid, manual.cid);
    }

    #[test]
    fn mutable_fields_do_not_change_cid() {
        let a = base_memory();
        let mut b = base_memory();
        // Mutate everything NOT in the genesis pre-image.
        b.tags = vec!["totally".to_string(), "different".to_string()];
        b.priority = 9;
        b.confidence = 0.1;
        b.access_count = 42;
        b.updated_at = "2027-01-01T00:00:00Z".to_string();
        b.version = 7;
        b.lifecycle_state = crate::models::LifecycleState::default();
        assert_eq!(stamp_memory_cid(&a).cid, stamp_memory_cid(&b).cid);
    }

    #[test]
    fn kind_and_namespace_are_pinned() {
        let base = stamp_cid(AGENT, NS, TITLE, KIND, CREATED, CONTENT);
        let other_kind = stamp_cid(AGENT, NS, TITLE, "reflection", CREATED, CONTENT);
        let other_ns = stamp_cid(AGENT, "other-ns", TITLE, KIND, CREATED, CONTENT);
        assert_ne!(base.cid, other_kind.cid, "kind is pinned into the cid");
        assert_ne!(base.cid, other_ns.cid, "namespace is pinned into the cid");
    }

    #[test]
    fn verify_round_trips_and_detects_partial_corruption() {
        let s = stamp_cid(AGENT, NS, TITLE, KIND, CREATED, CONTENT);
        // Clean pair verifies.
        assert!(verify_cid(&s.cid, &s.genesis).is_ok());
        // Corrupt the genesis pre-image → mismatch.
        let mut bad_genesis = s.genesis.clone();
        *bad_genesis.last_mut().unwrap() ^= 0x01;
        assert!(verify_cid(&s.cid, &bad_genesis).is_err());
        // Corrupt the stored cid → mismatch.
        let bad_cid = format!("{}0", &s.cid[..s.cid.len() - 1]);
        assert!(verify_cid(&bad_cid, &s.genesis).is_err());
    }
}
