// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10108 stage 2 (GA standard 3, signed writes) — the ONE canonical encoder
//! of an agent-attributed `signed_events.payload_hash` and the explicit era
//! that selects which `payload_hash` definition a row carries.
//!
//! `3-agent vote (71472661)` V1V2-AGENT-ROW-VERIFY, decision B, conditions:
//!
//! - B-1: the payload hash of the agent event types is a domain-separated,
//!   versioned, canonical encoding of the domain object's signed bytes plus
//!   the agent signature and its key. No untagged `serde_json` is hashed:
//!   every field is length-prefixed behind [`AGENT_PAYLOAD_DOMAIN`] and the
//!   event-kind tag, so two different inputs never share a pre-image.
//! - B-7: the era is explicit. [`PayloadEra::Legacy`] rows (below the v103
//!   cutover marker, or in a database with no marker) keep the definition
//!   their writer used; [`PayloadEra::Signed`] rows (above the marker) carry
//!   [`AgentPayloadHash`]. The walk matches [`RowEra`] exhaustively.
//!
//! The hash is a newtype ([`AgentPayloadHash`]) with a private field: the only
//! constructor is [`AgentPayloadHash::encode`], so no caller can store or
//! compare an untagged digest as a new-era payload hash (rust-1-98 ERRORS-09,
//! CBC-03).

use std::cmp::Ordering;

use sha2::{Digest, Sha256};

use super::AGENT_SIGNATURE_LEN;
use super::AgentCutover;
use super::event_types;

/// #10108 — the domain and version tag of the new-era agent-row
/// `payload_hash` pre-image. A new definition gets a new tag, never a reuse.
pub const AGENT_PAYLOAD_DOMAIN: &[u8] = b"ai-memory/signed-events/agent-row-v1\0";

/// #10108 — the domain and version tag of the canonical atomisation receipt
/// bytes (S-6: the receipt encoding carries a version tag).
pub const ATOMISATION_RECEIPT_DOMAIN: &[u8] = b"ai-memory/atomisation-receipt-v1\0";

/// Byte length of an Ed25519 public key, the only key length the encoder
/// accepts.
pub const AGENT_PUBKEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

/// Byte length of the SHA-256 digest an [`AgentPayloadHash`] holds.
pub const AGENT_PAYLOAD_HASH_LEN: usize = 32;

/// `event_type` of an offload write (`src/offload/mod.rs`).
pub const CONTEXT_OFFLOADED: &str = "context_offloaded";

/// `event_type` of an offload read-back (`src/offload/mod.rs`).
pub const CONTEXT_DEREFERENCED: &str = "context_dereferenced";

/// #10108 — the agent-attributed event kinds: the six event families of the
/// issue (offload writes two event types). Each kind has its own one-byte
/// tag in the pre-image, so the same signed bytes under two kinds never hash
/// alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentEventKind {
    /// `memory_link.created`: the link signature over the link CBOR.
    LinkCreated,
    /// `memory_capture_turn`: the L4 host signature over the captured turn.
    CaptureTurn,
    /// `persona_generated`: the persona signature over its CBOR.
    PersonaGenerated,
    /// `atomisation_complete`: the receipt signature over the receipt bytes.
    AtomisationComplete,
    /// `context_offloaded`: the offload signature over its CBOR bundle.
    ContextOffloaded,
    /// `context_dereferenced`: the offload read-back over its CBOR bundle.
    ContextDereferenced,
    /// `skill.registered`: the skill signature over its digest.
    SkillRegistered,
}

impl AgentEventKind {
    /// Every kind, in tag order.
    pub const ALL: [Self; 7] = [
        Self::LinkCreated,
        Self::CaptureTurn,
        Self::PersonaGenerated,
        Self::AtomisationComplete,
        Self::ContextOffloaded,
        Self::ContextDereferenced,
        Self::SkillRegistered,
    ];

    /// The stored `event_type` of this kind.
    #[must_use]
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::LinkCreated => event_types::MEMORY_LINK_CREATED,
            Self::CaptureTurn => event_types::MEMORY_CAPTURE_TURN,
            Self::PersonaGenerated => event_types::PERSONA_GENERATED,
            Self::AtomisationComplete => event_types::ATOMISATION_COMPLETE,
            Self::ContextOffloaded => CONTEXT_OFFLOADED,
            Self::ContextDereferenced => CONTEXT_DEREFERENCED,
            Self::SkillRegistered => event_types::SKILL_REGISTERED,
        }
    }

    /// The pre-image tag byte of this kind. Never renumbered.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::LinkCreated => 1,
            Self::CaptureTurn => 2,
            Self::PersonaGenerated => 3,
            Self::AtomisationComplete => 4,
            Self::ContextOffloaded => 5,
            Self::ContextDereferenced => 6,
            Self::SkillRegistered => 7,
        }
    }

    /// The kind a stored `event_type` names, `None` for every other type
    /// (those rows are not agent-attributed and keep their own definition).
    #[must_use]
    pub fn of_event_type(event_type: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.event_type() == event_type)
    }
}

/// #10108 — the inputs of one new-era agent-row payload hash: the domain
/// object's signed bytes, the agent signature over them and the 32-byte key
/// it verifies under. Fixed-width fields cannot carry a wrong length.
#[derive(Debug, Clone, Copy)]
pub struct AgentSignedPayload<'a> {
    /// The event kind.
    pub kind: AgentEventKind,
    /// The exact bytes the agent signed (the domain object's stored form).
    pub signed_bytes: &'a [u8],
    /// The agent's Ed25519 signature over `signed_bytes`.
    pub signature: &'a [u8; AGENT_SIGNATURE_LEN],
    /// The Ed25519 public key the signature verifies under.
    pub pubkey: &'a [u8; AGENT_PUBKEY_LEN],
}

/// #10108 — a new-era agent-row `payload_hash`. Built only by
/// [`AgentPayloadHash::encode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentPayloadHash([u8; AGENT_PAYLOAD_HASH_LEN]);

impl AgentPayloadHash {
    /// SHA-256 over: [`AGENT_PAYLOAD_DOMAIN`], the kind tag, the
    /// length-prefixed `event_type`, the length-prefixed signed bytes, the
    /// 64 signature bytes and the 32 key bytes. Lengths are big-endian
    /// `u64`.
    #[must_use]
    pub fn encode(payload: &AgentSignedPayload<'_>) -> Self {
        let mut h = Sha256::new();
        h.update(AGENT_PAYLOAD_DOMAIN);
        h.update([payload.kind.tag()]);
        update_len_prefixed(&mut h, payload.kind.event_type().as_bytes());
        update_len_prefixed(&mut h, payload.signed_bytes);
        h.update(payload.signature);
        h.update(payload.pubkey);
        Self(h.finalize().into())
    }

    /// The digest bytes, as the `payload_hash` column stores them.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AGENT_PAYLOAD_HASH_LEN] {
        &self.0
    }

    /// The digest as an owned column value.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// `true` iff the stored column equals this digest (exact length and
    /// bytes; a truncated or padded column never matches).
    #[must_use]
    pub fn matches(&self, stored: &[u8]) -> bool {
        stored == self.0.as_slice()
    }
}

/// `usize` lengths always fit a `u64` on every supported target; the
/// saturating fallback can only be reached on a 128-bit `usize`, where it
/// still keeps the pre-image injective for every length below `u64::MAX`.
fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn update_len_prefixed(h: &mut Sha256, bytes: &[u8]) {
    h.update(len_u64(bytes.len()).to_be_bytes());
    h.update(bytes);
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&len_u64(bytes.len()).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// #10108 (S-4, S-6) — the stored fields of one `atomisation_receipts` row
/// that the receipt signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomisationReceipt {
    /// The atomised source memory.
    pub source_id: String,
    /// RFC 3339 atomisation time (with `source_id`, the primary key).
    pub atomised_at: String,
    /// The atom ids, in decomposition order.
    pub atom_ids: Vec<String>,
    /// The atom count the curator reported.
    pub atom_count: u64,
    /// The agent that asked for the atomisation.
    pub calling_agent_id: String,
    /// The curator model, when known.
    pub curator_model: Option<String>,
}

impl AtomisationReceipt {
    /// The canonical receipt bytes: [`ATOMISATION_RECEIPT_DOMAIN`], then each
    /// field length-prefixed (big-endian `u64`), the atom ids as a count and
    /// one length-prefixed id each (order kept: it is the decomposition
    /// order), the atom count as big-endian `u64`, and the curator model as
    /// `0` (absent) or `1` plus its length-prefixed bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            ATOMISATION_RECEIPT_DOMAIN.len()
                + self.source_id.len()
                + self.atomised_at.len()
                + self.calling_agent_id.len()
                + self.atom_ids.iter().map(|a| a.len() + 8).sum::<usize>()
                + 64,
        );
        out.extend_from_slice(ATOMISATION_RECEIPT_DOMAIN);
        push_len_prefixed(&mut out, self.source_id.as_bytes());
        push_len_prefixed(&mut out, self.atomised_at.as_bytes());
        out.extend_from_slice(&len_u64(self.atom_ids.len()).to_be_bytes());
        for id in &self.atom_ids {
            push_len_prefixed(&mut out, id.as_bytes());
        }
        out.extend_from_slice(&self.atom_count.to_be_bytes());
        push_len_prefixed(&mut out, self.calling_agent_id.as_bytes());
        match &self.curator_model {
            None => out.push(0),
            Some(model) => {
                out.push(1);
                push_len_prefixed(&mut out, model.as_bytes());
            }
        }
        out
    }
}

/// #10108 (B-7) — which `payload_hash` definition a row carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadEra {
    /// Written before the cutover: the writer's own definition; the walk
    /// counts the row as legacy and never as verified or failed.
    Legacy,
    /// Written after the cutover: [`AgentPayloadHash`], recomputed by the
    /// walk from the stored domain row.
    Signed,
}

/// #10108 (B-7) — the era of one chain position, as the cutover resolves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowEra {
    /// The row has an era.
    Era(PayloadEra),
    /// The row IS the cutover marker position (judged by the marker
    /// recompute, never by an agent-row definition).
    Marker,
    /// The cutover marker is invalid, so no era can be trusted: every
    /// agent-attributed row fails closed.
    Unresolvable,
}

impl RowEra {
    /// The era of the chain row at `sequence` under the resolved cutover.
    /// No marker: every row is [`PayloadEra::Legacy`] (whether a missing
    /// marker at schema v103 is itself a failure is the walk's B-5 check,
    /// not the era's). A valid marker: rows below it are legacy, the marker
    /// position is [`RowEra::Marker`], rows above it are
    /// [`PayloadEra::Signed`]. An invalid marker: [`RowEra::Unresolvable`]
    /// for every position.
    #[must_use]
    pub fn resolve(cutover: &AgentCutover, sequence: i64) -> Self {
        match *cutover {
            AgentCutover::Absent => Self::Era(PayloadEra::Legacy),
            AgentCutover::Valid {
                sequence: marker, ..
            } => match sequence.cmp(&marker) {
                Ordering::Less => Self::Era(PayloadEra::Legacy),
                Ordering::Equal => Self::Marker,
                Ordering::Greater => Self::Era(PayloadEra::Signed),
            },
            AgentCutover::Invalid => Self::Unresolvable,
        }
    }
}
