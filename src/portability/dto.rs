// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2006 — the per-class HEX envelope DTOs (spec §V2-2).
//!
//! Each signed record class crosses the v2 export envelope as a DEDICATED DTO
//! (never the domain struct's default serde — three of the domain structs have
//! no serde derive at all, and the ones that do emit `Vec<u8>` as a JSON number
//! array). Every byte field routes through the shared
//! [`crate::portability::hex_bytes`] codec so BOTH directions use the identical
//! encoding and the round-trip is byte-preserved (L2). Signatures cross
//! verbatim — an importer NEVER re-signs; it reconstructs the exact bytes so
//! the destination re-verify sees the original signature.
//!
//! Conversions are bidirectional: `From<&DomainRow>` for the emit path and
//! `try_into_domain` / `From<Dto>` for the import path. Reconstruction is
//! FAIL-CLOSED on a closed-vocabulary field (an unknown `reason` /
//! `custody_class` slug is an error, never a silent default).

use serde::{Deserialize, Serialize};

use crate::governance::rules_store::Rule;
use crate::identity::lineage::{CustodyClass, LineageReason, LineageRecord};
use crate::models::{Memory, Tier};
use crate::portability::hex_bytes::HexBytes;
use crate::portability::read::{
    ArchivedMemoryLinkRow, ArchivedMemoryRow, ForgetTombstone, LineageExport, NamespaceMetaRow,
    RevisionRow,
};
use crate::revisions::{RecordKind, RevisionLeaf};
use crate::signed_events::SignedEvent;
use crate::storage::model_attest::ModelAttestation;

/// Error reconstructing a domain row from its DTO on the import path — a
/// closed-vocabulary slug outside its enum. Fail-closed: never a silent
/// default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DtoError {
    /// A `memory_revisions.kind` slug outside [`RecordKind`].
    UnknownRevisionKind(String),
    /// An `agent_lineage.reason` slug outside [`LineageReason`].
    UnknownLineageReason(String),
    /// An `agent_lineage.custody_class` slug outside [`CustodyClass`].
    UnknownCustodyClass(String),
}

impl std::fmt::Display for DtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRevisionKind(s) => write!(f, "unknown revision kind {s:?}"),
            Self::UnknownLineageReason(s) => write!(f, "unknown lineage reason {s:?}"),
            Self::UnknownCustodyClass(s) => write!(f, "unknown custody class {s:?}"),
        }
    }
}

impl std::error::Error for DtoError {}

// ── signed_events (§V2-2.1) ────────────────────────────────────────────────

/// `signed_events[]` DTO — the V-4 audit chain row. Carries `prev_hash` +
/// `sequence` + `cause_hash` (the forensic-bundle envelope omits them) so the
/// destination `verify_audit_trail` can recompute the cross-row chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEventDto {
    pub id: String,
    pub agent_id: String,
    pub event_type: String,
    pub payload_hash: HexBytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<HexBytes>,
    pub attest_level: String,
    pub timestamp: String,
    pub prev_hash: HexBytes,
    pub sequence: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause_hash: Option<HexBytes>,
}

impl From<&SignedEvent> for SignedEventDto {
    fn from(e: &SignedEvent) -> Self {
        Self {
            id: e.id.clone(),
            agent_id: e.agent_id.clone(),
            event_type: e.event_type.clone(),
            payload_hash: HexBytes(e.payload_hash.clone()),
            signature: e.signature.clone().map(HexBytes),
            attest_level: e.attest_level.clone(),
            timestamp: e.timestamp.clone(),
            prev_hash: HexBytes(e.prev_hash.clone()),
            sequence: e.sequence,
            cause_hash: e.cause_hash.clone().map(HexBytes),
        }
    }
}

impl From<SignedEventDto> for SignedEvent {
    fn from(d: SignedEventDto) -> Self {
        Self {
            id: d.id,
            agent_id: d.agent_id,
            event_type: d.event_type,
            payload_hash: d.payload_hash.0,
            signature: d.signature.map(|h| h.0),
            attest_level: d.attest_level,
            timestamp: d.timestamp,
            prev_hash: d.prev_hash.0,
            sequence: d.sequence,
            cause_hash: d.cause_hash.map(|h| h.0),
        }
    }
}

// ── memory_revisions (§V2-2.2) ─────────────────────────────────────────────

/// `memory_revisions[]` DTO — an identity-only revision leaf + its chain
/// columns (`prev_hash`, `sequence`) so the destination recomputes the spine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionDto {
    pub id: String,
    pub memory_id: String,
    /// Closed [`RecordKind`] wire slug (e.g. `SUPERSEDE`).
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_version: Option<i64>,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<HexBytes>,
    pub prev_hash: HexBytes,
    pub sequence: i64,
}

impl From<&RevisionRow> for RevisionDto {
    fn from(r: &RevisionRow) -> Self {
        Self {
            id: r.leaf.id.clone(),
            memory_id: r.leaf.memory_id.clone(),
            kind: r.leaf.kind.as_str().to_string(),
            prior_version: r.leaf.prior_version,
            namespace: r.leaf.namespace.clone(),
            agent_id: r.leaf.agent_id.clone(),
            created_at: r.leaf.created_at.clone(),
            signature: r.leaf.signature.clone().map(HexBytes),
            prev_hash: HexBytes(r.prev_hash.clone()),
            sequence: r.sequence,
        }
    }
}

impl RevisionDto {
    /// Reconstruct the domain [`RevisionRow`]. Fail-closed on an unknown kind.
    ///
    /// # Errors
    /// The `kind` slug is outside [`RecordKind`].
    pub fn try_into_domain(self) -> Result<RevisionRow, DtoError> {
        let kind = RecordKind::from_str_opt(&self.kind)
            .ok_or_else(|| DtoError::UnknownRevisionKind(self.kind.clone()))?;
        Ok(RevisionRow {
            leaf: RevisionLeaf {
                id: self.id,
                memory_id: self.memory_id,
                kind,
                prior_version: self.prior_version,
                namespace: self.namespace,
                agent_id: self.agent_id,
                created_at: self.created_at,
                signature: self.signature.map(|h| h.0),
            },
            prev_hash: self.prev_hash.0,
            sequence: self.sequence,
        })
    }
}

// ── forget_tombstones (§V2-2.3) ────────────────────────────────────────────

/// `forget_tombstones[]` DTO — the signed erasure receipt (identity + time +
/// signature, NEVER a content fingerprint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgetTombstoneDto {
    pub memory_id: String,
    pub namespace: String,
    pub forgotten_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<HexBytes>,
}

impl From<&ForgetTombstone> for ForgetTombstoneDto {
    fn from(t: &ForgetTombstone) -> Self {
        Self {
            memory_id: t.memory_id.clone(),
            namespace: t.namespace.clone(),
            forgotten_at: t.forgotten_at.clone(),
            agent_id: t.agent_id.clone(),
            signature: t.signature.clone().map(HexBytes),
        }
    }
}

impl From<ForgetTombstoneDto> for ForgetTombstone {
    fn from(d: ForgetTombstoneDto) -> Self {
        Self {
            memory_id: d.memory_id,
            namespace: d.namespace,
            forgotten_at: d.forgotten_at,
            agent_id: d.agent_id,
            signature: d.signature.map(|h| h.0),
        }
    }
}

// ── agent_lineage (§V2-2.4) ────────────────────────────────────────────────

/// `agent_lineage[]` DTO — a signed key-succession record + its detached
/// signature. Closed-vocabulary `reason` / `custody_class` cross as their wire
/// slugs; the optional recovery-quorum bytes cross hex-encoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageDto {
    pub agent_id: String,
    pub epoch: u64,
    /// [`LineageReason`] wire slug (`genesis`/`rotation`/`recovery`/`revocation`).
    pub reason: String,
    pub predecessor_pubkey_b64: String,
    pub successor_pubkey_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_pubkey_b64: Option<String>,
    pub not_before: String,
    pub prev_record_hash: HexBytes,
    /// [`CustodyClass`] wire slug (`software-file` default).
    pub custody_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspected_compromise_from_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardian_set_id: Option<HexBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_threshold: Option<u64>,
    /// The detached Ed25519 signature over the record's canonical bytes
    /// (always present — stored ALONGSIDE the record, not signed-in).
    pub signature: HexBytes,
}

impl From<&LineageExport> for LineageDto {
    fn from(l: &LineageExport) -> Self {
        let r = &l.record;
        Self {
            agent_id: r.agent_id.clone(),
            epoch: r.epoch,
            reason: r.reason.as_str().to_string(),
            predecessor_pubkey_b64: r.predecessor_pubkey_b64.clone(),
            successor_pubkey_b64: r.successor_pubkey_b64.clone(),
            recovery_pubkey_b64: r.recovery_pubkey_b64.clone(),
            not_before: r.not_before.clone(),
            prev_record_hash: HexBytes(r.prev_record_hash.clone()),
            custody_class: r.custody_class.as_str().to_string(),
            suspected_compromise_from_seq: r.suspected_compromise_from_seq,
            guardian_set_id: r.guardian_set_id.clone().map(HexBytes),
            recovery_threshold: r.recovery_threshold,
            signature: HexBytes(l.signature.clone()),
        }
    }
}

impl LineageDto {
    /// Reconstruct the domain [`LineageExport`]. Fail-closed on an unknown
    /// `reason` or `custody_class` slug.
    ///
    /// # Errors
    /// A closed-vocabulary slug is outside its enum.
    pub fn try_into_domain(self) -> Result<LineageExport, DtoError> {
        let reason = LineageReason::from_str(&self.reason)
            .ok_or_else(|| DtoError::UnknownLineageReason(self.reason.clone()))?;
        let custody_class = CustodyClass::from_str(&self.custody_class)
            .ok_or_else(|| DtoError::UnknownCustodyClass(self.custody_class.clone()))?;
        Ok(LineageExport {
            agent_id: self.agent_id.clone(),
            record: LineageRecord {
                agent_id: self.agent_id,
                epoch: self.epoch,
                reason,
                predecessor_pubkey_b64: self.predecessor_pubkey_b64,
                successor_pubkey_b64: self.successor_pubkey_b64,
                recovery_pubkey_b64: self.recovery_pubkey_b64,
                not_before: self.not_before,
                prev_record_hash: self.prev_record_hash.0,
                custody_class,
                suspected_compromise_from_seq: self.suspected_compromise_from_seq,
                guardian_set_id: self.guardian_set_id.map(|h| h.0),
                recovery_threshold: self.recovery_threshold,
            },
            signature: self.signature.0,
        })
    }
}

// ── model_attestations (§V2-2.5) ───────────────────────────────────────────

/// `model_attestations[]` DTO — a write-once model-family provenance record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelAttestationDto {
    pub id: String,
    pub provider: String,
    pub model_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_digest: Option<String>,
    pub model_family: String,
    pub attest_level: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<HexBytes>,
    pub created_at: String,
}

impl From<&ModelAttestation> for ModelAttestationDto {
    fn from(m: &ModelAttestation) -> Self {
        Self {
            id: m.id.clone(),
            provider: m.provider.clone(),
            model_ref: m.model_ref.clone(),
            model_digest: m.model_digest.clone(),
            model_family: m.model_family.clone(),
            attest_level: m.attest_level.clone(),
            agent_id: m.agent_id.clone(),
            signature: m.signature.clone().map(HexBytes),
            created_at: m.created_at.clone(),
        }
    }
}

impl From<ModelAttestationDto> for ModelAttestation {
    fn from(d: ModelAttestationDto) -> Self {
        Self {
            id: d.id,
            provider: d.provider,
            model_ref: d.model_ref,
            model_digest: d.model_digest,
            model_family: d.model_family,
            attest_level: d.attest_level,
            agent_id: d.agent_id,
            signature: d.signature.map(|h| h.0),
            created_at: d.created_at,
        }
    }
}

// ── governance_rules (§V2-2.6, L3) ─────────────────────────────────────────

/// `governance_rules[]` DTO (L3) — an operator-signed policy row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceRuleDto {
    pub id: String,
    pub kind: String,
    pub matcher: String,
    pub severity: String,
    pub reason: String,
    pub namespace: String,
    pub created_by: String,
    pub created_at: i64,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<HexBytes>,
    pub attest_level: String,
}

impl From<&Rule> for GovernanceRuleDto {
    fn from(r: &Rule) -> Self {
        Self {
            id: r.id.clone(),
            kind: r.kind.clone(),
            matcher: r.matcher.clone(),
            severity: r.severity.clone(),
            reason: r.reason.clone(),
            namespace: r.namespace.clone(),
            created_by: r.created_by.clone(),
            created_at: r.created_at,
            enabled: r.enabled,
            signature: r.signature.clone().map(HexBytes),
            attest_level: r.attest_level.clone(),
        }
    }
}

impl From<GovernanceRuleDto> for Rule {
    fn from(d: GovernanceRuleDto) -> Self {
        Self {
            id: d.id,
            kind: d.kind,
            matcher: d.matcher,
            severity: d.severity,
            reason: d.reason,
            namespace: d.namespace,
            created_by: d.created_by,
            created_at: d.created_at,
            enabled: d.enabled,
            signature: d.signature.map(|h| h.0),
            attest_level: d.attest_level,
        }
    }
}

// ── trust_anchors (§V2-2.6, L3) ────────────────────────────────────────────

/// `trust_anchors[]` DTO (L3) — an enrolled role's PUBLIC verifying key.
///
/// PUBLIC keys ONLY; a private key NEVER crosses the envelope. Advisory at the
/// destination — the substrate's re-verify K1-pins its OWN out-of-band enrolled
/// keys (`AI_MEMORY_*_PUBKEY`), so an importer treats these as informational
/// and never adopts them as a trust root (spec §V2-2.6 + the #2006 vote).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAnchorDto {
    /// The enrolled role (`operator`/`witness`/`recorder`/`judge`/`stopper`).
    pub role: String,
    /// URL-safe-no-pad base64 of the 32-byte Ed25519 verifying key.
    pub pubkey_b64: String,
}

// ── archived_memories (#2571, spec §6.4) ────────────────────────────────────

/// `archived_memories[]` DTO — an archived row for export (issue #2571).
/// Flattens the live-`Memory`-shaped columns (spec §6.4: "same column set as
/// `memories[]`") alongside the archive-only columns, so the wire shape
/// mirrors a `memories[]` entry plus extras rather than nesting a `memory`
/// object. Content crosses DECRYPTED (never ciphertext) exactly like
/// `memories[]`; `embedding` routes through [`HexBytes`] like every other
/// byte field in this envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedMemoryDto {
    #[serde(flatten)]
    pub memory: Memory,
    pub archived_at: String,
    pub archive_reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_tier: Option<Tier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding: Option<HexBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_dim: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_space: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atomised_into: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atom_of: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mentioned_entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind_provenance: Option<String>,
}

impl From<&ArchivedMemoryRow> for ArchivedMemoryDto {
    fn from(r: &ArchivedMemoryRow) -> Self {
        Self {
            memory: r.memory.clone(),
            archived_at: r.archived_at.clone(),
            archive_reason: r.archive_reason.clone(),
            original_tier: r.original_tier.clone(),
            original_expires_at: r.original_expires_at.clone(),
            embedding: r.embedding.clone().map(HexBytes),
            embedding_dim: r.embedding_dim,
            embedding_space: r.embedding_space.clone(),
            atomised_into: r.atomised_into,
            atom_of: r.atom_of.clone(),
            mentioned_entity_id: r.mentioned_entity_id.clone(),
            kind_provenance: r.kind_provenance.clone(),
        }
    }
}

impl From<ArchivedMemoryDto> for ArchivedMemoryRow {
    fn from(d: ArchivedMemoryDto) -> Self {
        Self {
            memory: d.memory,
            archived_at: d.archived_at,
            archive_reason: d.archive_reason,
            original_tier: d.original_tier,
            original_expires_at: d.original_expires_at,
            embedding: d.embedding.map(|h| h.0),
            embedding_dim: d.embedding_dim,
            embedding_space: d.embedding_space,
            atomised_into: d.atomised_into,
            atom_of: d.atom_of,
            mentioned_entity_id: d.mentioned_entity_id,
            kind_provenance: d.kind_provenance,
        }
    }
}

// ── namespace_meta (#2571, spec §6.1) ──────────────────────────────────────

/// `namespace_meta[]` DTO — a namespace's governance binding (issue #2571,
/// spec §6.1): which memory carries its `CorePolicy` standard
/// (`standard_id`) and its explicit hierarchical parent (`parent_namespace`,
/// the chain `build_namespace_chain` walks).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceMetaDto {
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_namespace: Option<String>,
    pub updated_at: String,
}

impl From<&NamespaceMetaRow> for NamespaceMetaDto {
    fn from(r: &NamespaceMetaRow) -> Self {
        Self {
            namespace: r.namespace.clone(),
            standard_id: r.standard_id.clone(),
            parent_namespace: r.parent_namespace.clone(),
            updated_at: r.updated_at.clone(),
        }
    }
}

impl From<NamespaceMetaDto> for NamespaceMetaRow {
    fn from(d: NamespaceMetaDto) -> Self {
        Self {
            namespace: d.namespace,
            standard_id: d.standard_id,
            parent_namespace: d.parent_namespace,
            updated_at: d.updated_at,
        }
    }
}

// ── archived_memory_links (#2571, schema v70 / #1771) ───────────────────────

/// `archived_memory_links[]` DTO — the v70 archive-link snapshot (issue
/// #2571): a memory's links preserved at the moment it was archived, so
/// `restore_archived` can re-attach them. Deliberately carries no FK (mirrors
/// the table itself, `src/storage/migrations.rs` v70 arm).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivedMemoryLinkDto {
    pub source_id: String,
    pub target_id: String,
    pub relation: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<HexBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attest_level: Option<String>,
    pub archived_at: String,
    /// v91 (#3250) — lineage-DAG cid pins. Optional so a pre-v91 bundle
    /// still deserializes (NULL on import = legacy restore).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_cid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_cid: Option<String>,
}

impl From<&ArchivedMemoryLinkRow> for ArchivedMemoryLinkDto {
    fn from(r: &ArchivedMemoryLinkRow) -> Self {
        Self {
            source_id: r.source_id.clone(),
            target_id: r.target_id.clone(),
            relation: r.relation.clone(),
            created_at: r.created_at.clone(),
            valid_from: r.valid_from.clone(),
            valid_until: r.valid_until.clone(),
            observed_by: r.observed_by.clone(),
            signature: r.signature.clone().map(HexBytes),
            attest_level: r.attest_level.clone(),
            archived_at: r.archived_at.clone(),
            source_cid: r.source_cid.clone(),
            target_cid: r.target_cid.clone(),
        }
    }
}

impl From<ArchivedMemoryLinkDto> for ArchivedMemoryLinkRow {
    fn from(d: ArchivedMemoryLinkDto) -> Self {
        Self {
            source_id: d.source_id,
            target_id: d.target_id,
            relation: d.relation,
            created_at: d.created_at,
            valid_from: d.valid_from,
            valid_until: d.valid_until,
            observed_by: d.observed_by,
            signature: d.signature.map(|h| h.0),
            attest_level: d.attest_level,
            archived_at: d.archived_at,
            source_cid: d.source_cid,
            target_cid: d.target_cid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The load-bearing property for every DTO: domain → DTO → JSON → DTO →
    /// domain reproduces the exact bytes, and the JSON carries byte fields as
    /// hex STRINGS (never a number array).
    fn assert_no_number_array(json: &str) {
        assert!(
            !json.contains('['),
            "a byte field serialized as a number array (not hex): {json}"
        );
    }

    #[test]
    fn signed_event_dto_round_trips_byte_exact() {
        let ev = SignedEvent {
            id: "e1".into(),
            agent_id: "alice".into(),
            event_type: "memory_link.created".into(),
            payload_hash: vec![0xde, 0xad],
            signature: Some(vec![0x01; 64]),
            attest_level: "signed".into(),
            timestamp: "2026-07-14T00:00:00Z".into(),
            prev_hash: vec![0x00; 32],
            sequence: 7,
            cause_hash: None,
        };
        let dto = SignedEventDto::from(&ev);
        let json = serde_json::to_string(&dto).unwrap();
        assert_no_number_array(&json);
        let back: SignedEvent = serde_json::from_str::<SignedEventDto>(&json)
            .unwrap()
            .into();
        assert_eq!(back, ev);
    }

    #[test]
    fn revision_dto_round_trips_and_fails_closed_on_bad_kind() {
        let row = RevisionRow {
            leaf: RevisionLeaf {
                id: "r1".into(),
                memory_id: "m1".into(),
                kind: RecordKind::Supersede,
                prior_version: Some(3),
                namespace: "ns".into(),
                agent_id: None,
                created_at: "2026-07-14T00:00:00Z".into(),
                signature: Some(vec![0xab; 64]),
            },
            prev_hash: vec![0x11; 32],
            sequence: 4,
        };
        let dto = RevisionDto::from(&row);
        let json = serde_json::to_string(&dto).unwrap();
        assert_no_number_array(&json);
        let back = serde_json::from_str::<RevisionDto>(&json)
            .unwrap()
            .try_into_domain()
            .unwrap();
        assert_eq!(back, row);
        // Fail-closed on a forged kind.
        let mut bad = dto;
        bad.kind = "BOGUS".into();
        assert_eq!(
            bad.try_into_domain().unwrap_err(),
            DtoError::UnknownRevisionKind("BOGUS".into())
        );
    }

    #[test]
    fn forget_tombstone_dto_round_trips() {
        let t = ForgetTombstone {
            memory_id: "m1".into(),
            namespace: "ns".into(),
            forgotten_at: "2026-07-14T00:00:00Z".into(),
            agent_id: Some("alice".into()),
            signature: Some(vec![0x22; 64]),
        };
        let json = serde_json::to_string(&ForgetTombstoneDto::from(&t)).unwrap();
        assert_no_number_array(&json);
        let back: ForgetTombstone = serde_json::from_str::<ForgetTombstoneDto>(&json)
            .unwrap()
            .into();
        assert_eq!(back, t);
    }

    #[test]
    fn lineage_dto_round_trips_and_fails_closed() {
        let export = LineageExport {
            agent_id: "alice".into(),
            record: LineageRecord {
                agent_id: "alice".into(),
                epoch: 2,
                reason: LineageReason::Rotation,
                predecessor_pubkey_b64: "AAAA".into(),
                successor_pubkey_b64: "BBBB".into(),
                recovery_pubkey_b64: None,
                not_before: "2026-07-14T00:00:00Z".into(),
                prev_record_hash: vec![0x33; 32],
                custody_class: CustodyClass::SoftwareFile,
                suspected_compromise_from_seq: None,
                guardian_set_id: None,
                recovery_threshold: None,
            },
            signature: vec![0x44; 64],
        };
        let json = serde_json::to_string(&LineageDto::from(&export)).unwrap();
        assert_no_number_array(&json);
        let back = serde_json::from_str::<LineageDto>(&json)
            .unwrap()
            .try_into_domain()
            .unwrap();
        assert_eq!(back.record, export.record);
        assert_eq!(back.signature, export.signature);
    }

    #[test]
    fn model_attestation_dto_round_trips() {
        let m = ModelAttestation {
            id: "a1".into(),
            provider: "openrouter".into(),
            model_ref: "google/gemma-4-31b".into(),
            model_digest: None,
            model_family: "gemma".into(),
            attest_level: "operator_signed".into(),
            agent_id: "op".into(),
            signature: Some(vec![0x55; 64]),
            created_at: "2026-07-14T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&ModelAttestationDto::from(&m)).unwrap();
        assert_no_number_array(&json);
        let back: ModelAttestation = serde_json::from_str::<ModelAttestationDto>(&json)
            .unwrap()
            .into();
        assert_eq!(back, m);
    }

    #[test]
    fn governance_rule_dto_round_trips() {
        let r = Rule {
            id: "R1".into(),
            kind: "namespace_deny".into(),
            matcher: "secret/*".into(),
            severity: "refuse".into(),
            reason: "no secrets".into(),
            namespace: "*".into(),
            created_by: "op".into(),
            created_at: 1_700_000_000,
            enabled: true,
            signature: Some(vec![0x66; 64]),
            attest_level: "operator_signed".into(),
        };
        let json = serde_json::to_string(&GovernanceRuleDto::from(&r)).unwrap();
        assert_no_number_array(&json);
        let back: Rule = serde_json::from_str::<GovernanceRuleDto>(&json)
            .unwrap()
            .into();
        assert_eq!(back, r);
    }

    #[test]
    fn trust_anchor_dto_carries_only_public_key() {
        let a = TrustAnchorDto {
            role: "witness".into(),
            pubkey_b64: "abc123".into(),
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: TrustAnchorDto = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }

    /// #2571 — the archived-memory DTO flattens the live-Memory-shaped
    /// fields at the SAME JSON level as `archived_at`/`archive_reason`
    /// (spec §6.4: "same column set as `memories[]`, plus…"), never nested
    /// under a `memory` key, and `embedding` crosses as a hex STRING.
    #[test]
    fn archived_memory_dto_flattens_and_round_trips_byte_exact() {
        let row = ArchivedMemoryRow {
            memory: Memory {
                id: "m1".into(),
                title: "t".into(),
                content: "c".into(),
                namespace: "ns".into(),
                ..Memory::default()
            },
            archived_at: "2026-01-01T00:00:00Z".into(),
            archive_reason: "manual".into(),
            original_tier: Some(Tier::Long),
            original_expires_at: None,
            embedding: Some(vec![0x01, 0x02, 0x03]),
            embedding_dim: Some(3),
            embedding_space: Some("model#raw".into()),
            atomised_into: None,
            atom_of: None,
            mentioned_entity_id: None,
            kind_provenance: Some("declared".into()),
        };
        let dto = ArchivedMemoryDto::from(&row);
        let json = serde_json::to_string(&dto).unwrap();
        // `assert_no_number_array` is unsuitable here (Memory legitimately
        // carries array fields like `tags`/`citations`) — assert the
        // targeted byte-family invariant instead: `embedding` crosses as a
        // hex STRING, never a raw number array.
        assert!(
            json.contains("\"embedding\":\"010203\""),
            "embedding must cross as a hex string, not a number array: {json}"
        );
        assert!(
            json.contains("\"archived_at\":\"2026-01-01T00:00:00Z\""),
            "archive fields must be flattened alongside the memory fields: {json}"
        );
        assert!(
            !json.contains("\"memory\":{"),
            "the memory fields must NOT be nested under a `memory` key: {json}"
        );
        let back: ArchivedMemoryRow = serde_json::from_str::<ArchivedMemoryDto>(&json)
            .unwrap()
            .into();
        assert_eq!(back.memory.id, row.memory.id);
        assert_eq!(back.memory.title, row.memory.title);
        assert_eq!(back.memory.content, row.memory.content);
        assert_eq!(back.archived_at, row.archived_at);
        assert_eq!(back.archive_reason, row.archive_reason);
        assert_eq!(back.original_tier, row.original_tier);
        assert_eq!(back.embedding, row.embedding);
        assert_eq!(back.embedding_dim, row.embedding_dim);
        assert_eq!(back.kind_provenance, row.kind_provenance);
    }

    /// #2571, Fable review non-blocking fold-in (2026-08-11) — freezes the
    /// flatten-shadowing risk the data-integrity voter flagged on vote
    /// `17aa4567`: `ArchivedMemoryDto` merges its own archive-specific
    /// fields into the SAME JSON object as `#[serde(flatten)]`ed `Memory`
    /// fields (§ archived_memory_dto_flattens_and_round_trips_byte_exact
    /// above). `serde(flatten)` silently last-write-wins on a name
    /// collision — no compile error, no panic — so if `Memory` ever grows a
    /// field sharing one of these names, the archive-specific value would
    /// silently shadow (or be shadowed by) the memory field with zero
    /// signal at import time. This guard fails LOUD the day that happens.
    #[test]
    fn archived_memory_dto_archive_fields_never_collide_with_memory_fields() {
        const ARCHIVE_ONLY_FIELD_NAMES: &[&str] = &[
            "archived_at",
            "archive_reason",
            "original_tier",
            "original_expires_at",
            "embedding",
            "embedding_dim",
            "embedding_space",
            "atomised_into",
            "atom_of",
            "mentioned_entity_id",
            "kind_provenance",
        ];
        let memory_json = serde_json::to_value(Memory::default()).unwrap();
        let memory_keys = memory_json
            .as_object()
            .expect("Memory serializes as a JSON object");
        for name in ARCHIVE_ONLY_FIELD_NAMES {
            assert!(
                !memory_keys.contains_key(*name),
                "Memory gained a field named `{name}` — this now COLLIDES with \
                 ArchivedMemoryDto's flattened archive-specific field of the same \
                 name (src/portability/dto.rs::ArchivedMemoryDto). `#[serde(flatten)]` \
                 silently last-write-wins on this collision; rename one side before \
                 landing the new Memory field."
            );
        }
    }

    #[test]
    fn namespace_meta_dto_round_trips() {
        let row = NamespaceMetaRow {
            namespace: "team/eng".into(),
            standard_id: Some("std-1".into()),
            parent_namespace: Some("team".into()),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&NamespaceMetaDto::from(&row)).unwrap();
        let back: NamespaceMetaRow = serde_json::from_str::<NamespaceMetaDto>(&json)
            .unwrap()
            .into();
        assert_eq!(back, row);
    }

    #[test]
    fn archived_memory_link_dto_round_trips_byte_exact() {
        let row = ArchivedMemoryLinkRow {
            source_id: "a".into(),
            target_id: "b".into(),
            relation: "related_to".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            valid_from: None,
            valid_until: None,
            observed_by: None,
            signature: Some(vec![0xab; 64]),
            attest_level: Some("signed".into()),
            archived_at: "2026-01-02T00:00:00Z".into(),
            source_cid: None,
            target_cid: None,
        };
        let json = serde_json::to_string(&ArchivedMemoryLinkDto::from(&row)).unwrap();
        assert_no_number_array(&json);
        let back: ArchivedMemoryLinkRow = serde_json::from_str::<ArchivedMemoryLinkDto>(&json)
            .unwrap()
            .into();
        assert_eq!(back, row);
    }
}
