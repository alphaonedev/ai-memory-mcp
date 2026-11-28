//! #10108 (GA standard 3) — the one constructor of an agent-labelled
//! `signed_events` row.
//!
//! Invariant I1: a row carries an agent attest level (`self_signed`,
//! `signed_by_peer`, `peer_attested`) only when its `signature` column holds
//! the 64-byte Ed25519 signature that agent (or peer) made. A writer holding
//! no such signature writes `unsigned` with a NULL signature. The pair is
//! one value, [`AgentRowSignature`], so no writer can pass a label and an
//! `Option` signature separately: the agent arm cannot be built without the
//! 64 signature bytes (rust-1-98 ERRORS-09).
//!
//! The tree-wide source ratchet `tests/agent_attest_level_ratchet_10108.rs`
//! holds every other site that names an agent attest level.

use super::{AgentAttestation, SignedEvent};
use crate::models::AttestLevel;

/// Byte length of an Ed25519 signature, the only length an agent-labelled
/// row may carry.
pub const AGENT_SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// The signature evidence of an agent-written row: both columns at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentRowSignature {
    /// No agent signature: the row is `unsigned` with a NULL signature.
    Unsigned,
    /// A 64-byte signature made by the key `level` names.
    Signed {
        /// Which agent key made `sig`.
        level: AgentAttestation,
        /// The signature bytes.
        sig: [u8; AGENT_SIGNATURE_LEN],
    },
}

impl AgentAttestation {
    /// The stored `attest_level` this form names.
    #[must_use]
    pub const fn attest_level(self) -> AttestLevel {
        match self {
            Self::SelfSigned => AttestLevel::SelfSigned,
            Self::SignedByPeer => AttestLevel::SignedByPeer,
            Self::PeerAttested => AttestLevel::PeerAttested,
        }
    }
}

impl AgentRowSignature {
    /// `level` when `signature` is exactly [`AGENT_SIGNATURE_LEN`] bytes;
    /// `Unsigned` otherwise. A held signature of any other length is not an
    /// agent signature, so the row states the truth (`unsigned`, NULL) and
    /// the writer is told through a warning; the domain object (link row,
    /// persona metadata, ...) keeps its own copy untouched.
    #[must_use]
    pub fn from_signature(level: AgentAttestation, signature: Option<&[u8]>) -> Self {
        let Some(bytes) = signature else {
            return Self::Unsigned;
        };
        if let Ok(sig) = <[u8; AGENT_SIGNATURE_LEN]>::try_from(bytes) {
            Self::Signed { level, sig }
        } else {
            tracing::warn!(
                len = bytes.len(),
                "#10108: agent signature of the wrong length; the signed_events row is written unsigned"
            );
            Self::Unsigned
        }
    }

    /// `self_signed` over `signature`: the writing agent's own key.
    #[must_use]
    pub fn self_signed(signature: Option<&[u8]>) -> Self {
        Self::from_signature(AgentAttestation::SelfSigned, signature)
    }

    /// `signed_by_peer` over `signature`: a verified host or peer key.
    #[must_use]
    pub fn signed_by_peer(signature: Option<&[u8]>) -> Self {
        Self::from_signature(AgentAttestation::SignedByPeer, signature)
    }

    /// `peer_attested` over `signature`: a verified peer attestation key.
    #[must_use]
    pub fn peer_attested(signature: Option<&[u8]>) -> Self {
        Self::from_signature(AgentAttestation::PeerAttested, signature)
    }

    /// The row for a writer that holds a stored label and signature (an
    /// inbound federated link): an agent label keeps its level only with a
    /// 64-byte signature; every other label (`unsigned`, a daemon or
    /// unrecognised label) is `Unsigned`, since an agent writer never stamps
    /// a daemon label.
    #[must_use]
    pub fn from_label(attest_level: &str, signature: Option<&[u8]>) -> Self {
        match super::SignerIdentity::of(attest_level) {
            super::SignerIdentity::Agent(level) => Self::from_signature(level, signature),
            _ => Self::Unsigned,
        }
    }

    /// The `attest_level` this row stores.
    #[must_use]
    pub const fn attest_level(&self) -> AttestLevel {
        match self {
            Self::Unsigned => AttestLevel::Unsigned,
            Self::Signed { level, .. } => level.attest_level(),
        }
    }

    /// The `signature` column this row stores.
    #[must_use]
    pub fn signature(&self) -> Option<Vec<u8>> {
        self.signature_bytes().map(<[u8]>::to_vec)
    }

    /// The `signature` column this row stores, borrowed (the postgres
    /// append takes `Option<&[u8]>` beside `attest_level`; both come from
    /// this one value there too).
    #[must_use]
    pub fn signature_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Unsigned => None,
            Self::Signed { sig, .. } => Some(sig.as_slice()),
        }
    }
}

/// The caller-supplied fields of an agent-written row.
#[derive(Debug, Clone)]
pub struct AgentRow {
    /// The writing agent.
    pub agent_id: String,
    /// The event type (a constant of [`super::event_types`]).
    pub event_type: String,
    /// The row's payload hash.
    pub payload_hash: Vec<u8>,
    /// RFC 3339 write time.
    pub timestamp: String,
    /// Optional cause binding (v73, #1822).
    pub cause_hash: Option<Vec<u8>>,
}

impl SignedEvent {
    /// #10108 — build an agent-written row. The `signature` and
    /// `attest_level` columns both come from `sig`, so they cannot
    /// disagree; `prev_hash` and `sequence` are filled by the append.
    #[must_use]
    pub fn agent_row(row: AgentRow, sig: &AgentRowSignature) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: row.agent_id,
            event_type: row.event_type,
            payload_hash: row.payload_hash,
            signature: sig.signature(),
            attest_level: sig.attest_level().as_str().to_string(),
            timestamp: row.timestamp,
            prev_hash: Vec::new(),
            sequence: 0,
            cause_hash: row.cause_hash,
        }
    }
}
