// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10108 step 2 — the two-era agent-row walk (3-agent vote (71472661),
//! V1V2-AGENT-ROW-VERIFY B-4, B-5, B-6 and V1-AGENT-SIG-SCHEMA S-3, S-4, S-5;
//! #10135 for the erased receipt).
//!
//! One classifier, [`classify_agent_era_row`], used by the sqlite
//! [`super::verify_chain`] walk and the postgres verify twin, so both backends
//! give the same verdict for every row (K3 parity). It runs before
//! [`classify_row_signature`] and decides every row that claims agent
//! attribution:
//!
//! - a cutover marker row: [`AgentCutover::verdict_for`];
//! - an agent-labelled row (`self_signed`, `signed_by_peer`,
//!   `peer_attested`), by its [`RowEra`]:
//!   - legacy (below the marker, or no marker): a NULL or 64-byte signature
//!     is counted legacy, never failed (S-4, B-6); any other length is
//!     [`SignatureFailure::AgentSignatureMalformed`];
//!   - signed era (above the marker): [`SignatureFailure::PreCutoverWriter`],
//!     a binary that predates the cutover still wrote it (S-5, S-3 residual);
//!   - an invalid marker: [`SignatureFailure::AgentEraUnresolvable`];
//! - an `unsigned` row of an agent event kind above the marker: the same
//!   pre-cutover outcome;
//! - a `daemon_signed` row of an agent event kind above the marker: the
//!   daemon signature must verify AND the stored `payload_hash` must be
//!   recomputed from a stored domain row whose signature verifies (B-4).
//!   Every other state is its own outcome ([`AgentDomainEvidence::verdict`]).
//!   Below the marker (or with none) it keeps the daemon-row check, since
//!   legacy rows predate the encoding; an invalid marker fails it closed.
//!
//! Every other row keeps [`classify_row_signature`] unchanged.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use super::agent_cutover::is_agent_labelled;
use super::agent_payload::{
    AgentEventKind, AgentPayloadHash, AgentSignedPayload, AtomisationReceipt, PayloadEra, RowEra,
};
use super::{
    AGENT_SIGNATURE_LEN, AgentCutover, LegacyCutoff, RowSignatureVerdict, SignatureFailure,
    SignedEvent, SignerIdentity, SkipReason, classify_row_signature,
};

/// #10108 — the domain tag of [`SourceBinding`]. Never reused.
pub const ATOMISATION_SOURCE_DOMAIN: &[u8] = b"ai-memory/atomisation-source/v1\0";

/// #10108 — the `cause_hash` an `atomisation_complete` chain row carries:
/// SHA-256 over [`ATOMISATION_SOURCE_DOMAIN`] and the length-prefixed source
/// id. The daemon signature covers `cause_hash`, so the binding is signed.
/// It lets the walk tell a tampered receipt, a NULL-signature receipt and an
/// erased receipt apart when no receipt matches the stored `payload_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceBinding([u8; 32]);

impl SourceBinding {
    /// The binding of `source_id`.
    #[must_use]
    pub fn of_source(source_id: &str) -> Self {
        let mut h = Sha256::new();
        h.update(ATOMISATION_SOURCE_DOMAIN);
        h.update(
            u64::try_from(source_id.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        h.update(source_id.as_bytes());
        Self(h.finalize().into())
    }

    /// The binding a stored `cause_hash` names; `None` when the column is
    /// NULL or not 32 bytes.
    #[must_use]
    pub fn from_stored(cause_hash: Option<&[u8]>) -> Option<Self> {
        cause_hash
            .and_then(|c| <[u8; 32]>::try_from(c).ok())
            .map(Self)
    }

    /// The 32 bytes, as `cause_hash` stores them.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// #10108 — one stored `atomisation_receipts` row as read, before its
/// fields are checked. Both backends' loaders produce this shape so the
/// evidence index is built by one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReceiptRow {
    /// `source_id`.
    pub source_id: String,
    /// `atomised_at`.
    pub atomised_at: String,
    /// `atom_ids`, the stored JSON array text.
    pub atom_ids_json: String,
    /// `atom_count` as stored.
    pub atom_count: i64,
    /// `calling_agent_id`.
    pub calling_agent_id: String,
    /// `curator_model`.
    pub curator_model: Option<String>,
    /// `signature` (NULL, or the daemon signature over the canonical bytes).
    pub signature: Option<Vec<u8>>,
}

impl StoredReceiptRow {
    /// The receipt the stored fields describe; `None` when `atom_ids` is not
    /// a JSON array of strings or `atom_count` is negative.
    fn receipt(&self) -> Option<AtomisationReceipt> {
        Some(AtomisationReceipt {
            source_id: self.source_id.clone(),
            atomised_at: self.atomised_at.clone(),
            atom_ids: serde_json::from_str::<Vec<String>>(&self.atom_ids_json).ok()?,
            atom_count: u64::try_from(self.atom_count).ok()?,
            calling_agent_id: self.calling_agent_id.clone(),
            curator_model: self.curator_model.clone(),
        })
    }
}

/// #10108 — what a stored receipt whose recomputed hash names a chain row
/// proves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptCheck {
    /// The daemon signature over the canonical bytes verified.
    SignatureValid,
    /// The signature is 64 bytes but does not verify under the daemon key.
    SignatureInvalid,
}

/// #10108 — the stored domain rows one walk checks agent-kind chain rows
/// against. Built once per walk ([`AgentDomainEvidence::build`]) in time
/// linear in the receipts and tombstones read.
#[derive(Debug, Clone, Default)]
pub struct AgentDomainEvidence {
    /// Keyed by the digest bytes of an [`AgentPayloadHash`] the encoder made,
    /// so a stored column is looked up in O(1); the value carries the source
    /// the receipt names, which the row's signed `cause_hash` must equal.
    by_hash: HashMap<[u8; 32], (ReceiptCheck, SourceBinding)>,
    signed_sources: HashSet<SourceBinding>,
    unsigned_sources: HashSet<SourceBinding>,
    tombstoned_sources: HashSet<SourceBinding>,
}

impl AgentDomainEvidence {
    /// Index `receipts` and the forgotten memory ids under the daemon key.
    /// With no daemon key nothing is indexed: no daemon-signed row can verify
    /// then, so the index is never consulted.
    #[must_use]
    pub fn build(
        receipts: &[StoredReceiptRow],
        forgotten_ids: &[String],
        daemon_key: Option<&VerifyingKey>,
    ) -> Self {
        let mut ev = Self::default();
        let Some(key) = daemon_key else {
            return ev;
        };
        let pubkey = key.to_bytes();
        for row in receipts {
            let binding = SourceBinding::of_source(&row.source_id);
            let sig = row
                .signature
                .as_deref()
                .and_then(|s| <[u8; AGENT_SIGNATURE_LEN]>::try_from(s).ok());
            match (row.signature.as_deref(), sig, row.receipt()) {
                (None, _, _) => {
                    ev.unsigned_sources.insert(binding);
                }
                (Some(_), Some(sig), Some(receipt)) => {
                    ev.signed_sources.insert(binding);
                    let bytes = receipt.canonical_bytes();
                    let hash = AgentPayloadHash::encode(&AgentSignedPayload {
                        kind: AgentEventKind::AtomisationComplete,
                        signed_bytes: &bytes,
                        signature: &sig,
                        pubkey: &pubkey,
                    });
                    let check = if key.verify(&bytes, &Signature::from_bytes(&sig)).is_ok() {
                        ReceiptCheck::SignatureValid
                    } else {
                        ReceiptCheck::SignatureInvalid
                    };
                    ev.by_hash.insert(*hash.as_bytes(), (check, binding));
                }
                // A wrong-length signature or unreadable fields: the source
                // has a receipt that can match no chain row (fail closed).
                (Some(_), _, _) => {
                    ev.signed_sources.insert(binding);
                }
            }
        }
        for id in forgotten_ids {
            ev.tombstoned_sources.insert(SourceBinding::of_source(id));
        }
        ev
    }

    /// The verdict of a `daemon_signed` row of `kind` whose daemon signature
    /// verified.
    #[must_use]
    pub fn verdict(&self, event: &SignedEvent, kind: AgentEventKind) -> RowSignatureVerdict {
        match kind {
            AgentEventKind::AtomisationComplete => self.atomisation_verdict(event),
            // No writer emits these kinds daemon-signed yet (step 3 adds
            // their domain sources); until then no stored row can be
            // recomputed, so the row fails closed.
            AgentEventKind::LinkCreated
            | AgentEventKind::CaptureTurn
            | AgentEventKind::PersonaGenerated
            | AgentEventKind::ContextOffloaded
            | AgentEventKind::ContextDereferenced
            | AgentEventKind::SkillRegistered => {
                RowSignatureVerdict::Failed(SignatureFailure::DomainRowMissing)
            }
        }
    }

    fn atomisation_verdict(&self, event: &SignedEvent) -> RowSignatureVerdict {
        let cause = SourceBinding::from_stored(event.cause_hash.as_deref());
        let found = <[u8; 32]>::try_from(event.payload_hash.as_slice())
            .ok()
            .and_then(|stored| self.by_hash.get(&stored).copied());
        match found {
            // The receipt must name the source the signed cause names: a
            // row that borrows another source's receipt is a mismatch.
            Some((_, source)) if cause != Some(source) => {
                RowSignatureVerdict::Failed(SignatureFailure::DomainPayloadMismatch)
            }
            Some((ReceiptCheck::SignatureValid, _)) => RowSignatureVerdict::Verified,
            Some((ReceiptCheck::SignatureInvalid, _)) => {
                RowSignatureVerdict::Failed(SignatureFailure::DomainSignatureInvalid)
            }
            None => match cause {
                None => RowSignatureVerdict::Failed(SignatureFailure::DomainRowMissing),
                Some(b) if self.unsigned_sources.contains(&b) => {
                    RowSignatureVerdict::Failed(SignatureFailure::AgentSignatureMissing)
                }
                Some(b) if self.signed_sources.contains(&b) => {
                    RowSignatureVerdict::Failed(SignatureFailure::DomainPayloadMismatch)
                }
                Some(b) if self.tombstoned_sources.contains(&b) => {
                    RowSignatureVerdict::Skipped(SkipReason::ReceiptErasedUnderTombstone)
                }
                Some(_) => RowSignatureVerdict::Failed(SignatureFailure::DomainRowMissing),
            },
        }
    }
}

/// #10108 — the per-walk inputs of [`classify_agent_era_row`].
#[derive(Debug, Clone, Copy)]
pub struct AgentEraWalk<'a> {
    /// The resolved cutover marker.
    pub cutover: AgentCutover,
    /// The stored domain rows.
    pub evidence: &'a AgentDomainEvidence,
    /// The daemon (audit-pin or in-process) key.
    pub daemon_verifier: Option<&'a VerifyingKey>,
    /// The enrolled recorder key.
    pub recorder_verifier: Option<&'a VerifyingKey>,
    /// The #10074 legacy cutoff.
    pub cutoff: &'a LegacyCutoff,
}

/// #10108 — the verdict of one row on either backend. See the module docs.
#[must_use]
pub fn classify_agent_era_row(event: &SignedEvent, walk: &AgentEraWalk<'_>) -> RowSignatureVerdict {
    if let Some(v) = walk.cutover.verdict_for(event) {
        return v;
    }
    let base = || {
        classify_row_signature(
            event,
            walk.daemon_verifier,
            walk.recorder_verifier,
            walk.cutoff,
        )
    };
    let kind = AgentEventKind::of_event_type(&event.event_type);
    let era = RowEra::resolve(&walk.cutover, event.sequence);
    match SignerIdentity::of(&event.attest_level) {
        SignerIdentity::Agent(_) if is_agent_labelled(&event.attest_level) => match era {
            RowEra::Era(PayloadEra::Legacy) => legacy_agent_verdict(event),
            RowEra::Era(PayloadEra::Signed) => {
                RowSignatureVerdict::Failed(SignatureFailure::PreCutoverWriter)
            }
            // Only the marker holds the marker's sequence; any other row
            // there is a forged position.
            RowEra::Marker => RowSignatureVerdict::Failed(SignatureFailure::CutoverMarkerInvalid),
            RowEra::Unresolvable => {
                RowSignatureVerdict::Failed(SignatureFailure::AgentEraUnresolvable)
            }
        },
        SignerIdentity::Unsigned if kind.is_some() => match era {
            RowEra::Era(PayloadEra::Signed) => {
                RowSignatureVerdict::Failed(SignatureFailure::PreCutoverWriter)
            }
            RowEra::Unresolvable => {
                RowSignatureVerdict::Failed(SignatureFailure::AgentEraUnresolvable)
            }
            RowEra::Marker => RowSignatureVerdict::Failed(SignatureFailure::CutoverMarkerInvalid),
            RowEra::Era(PayloadEra::Legacy) => base(),
        },
        // A legacy-era daemon row predates the agent payload encoding, so it
        // keeps the daemon-row check alone; above the marker the encoding is
        // required (B-4); an invalid marker leaves no era to trust.
        SignerIdentity::Daemon => match (kind, era) {
            (None, _) | (Some(_), RowEra::Era(PayloadEra::Legacy)) => base(),
            (Some(kind), RowEra::Era(PayloadEra::Signed)) => match base() {
                RowSignatureVerdict::Verified => walk.evidence.verdict(event, kind),
                other => other,
            },
            (Some(_), RowEra::Marker) => {
                RowSignatureVerdict::Failed(SignatureFailure::CutoverMarkerInvalid)
            }
            (Some(_), RowEra::Unresolvable) => {
                RowSignatureVerdict::Failed(SignatureFailure::AgentEraUnresolvable)
            }
        },
        SignerIdentity::Agent(_)
        | SignerIdentity::Unsigned
        | SignerIdentity::Recorder
        | SignerIdentity::LineageWitness
        | SignerIdentity::Unrecognised => base(),
    }
}

/// S-4 — a legacy agent-labelled row: NULL and 64-byte signatures are
/// counted legacy; any other length is malformed.
fn legacy_agent_verdict(event: &SignedEvent) -> RowSignatureVerdict {
    match event.signature.as_deref() {
        None => RowSignatureVerdict::Skipped(SkipReason::AgentSignedDomainObject),
        Some(sig) if sig.len() == AGENT_SIGNATURE_LEN => {
            RowSignatureVerdict::Skipped(SkipReason::AgentSignedDomainObject)
        }
        Some(_) => RowSignatureVerdict::Failed(SignatureFailure::AgentSignatureMalformed),
    }
}

/// `true` iff `table` exists (a pre-v103 or bare connection has no receipts
/// table; that is no evidence, never an error).
fn sqlite_table_exists(conn: &Connection, table: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .optional()
        .context("agent evidence: table probe")?
        .is_some())
}

/// #10108 — the sqlite loader of [`AgentDomainEvidence`].
///
/// # Errors
/// A read of either table failed.
pub fn load_sqlite_agent_evidence(
    conn: &Connection,
    daemon_key: Option<&VerifyingKey>,
) -> Result<AgentDomainEvidence> {
    let mut receipts = Vec::new();
    if sqlite_table_exists(conn, "atomisation_receipts")? {
        let mut stmt = conn
            .prepare(
                "SELECT source_id, atomised_at, atom_ids, atom_count, calling_agent_id, \
                        curator_model, signature FROM atomisation_receipts",
            )
            .context("agent evidence: prepare receipts")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(StoredReceiptRow {
                    source_id: r.get(0)?,
                    atomised_at: r.get(1)?,
                    atom_ids_json: r.get(2)?,
                    atom_count: r.get(3)?,
                    calling_agent_id: r.get(4)?,
                    curator_model: r.get(5)?,
                    signature: r.get(6)?,
                })
            })
            .context("agent evidence: query receipts")?;
        for row in rows {
            receipts.push(row.context("agent evidence: read receipt")?);
        }
    }
    let mut forgotten = Vec::new();
    if sqlite_table_exists(conn, "forget_tombstones")? {
        let mut stmt = conn
            .prepare("SELECT memory_id FROM forget_tombstones")
            .context("agent evidence: prepare tombstones")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .context("agent evidence: query tombstones")?;
        for row in rows {
            forgotten.push(row.context("agent evidence: read tombstone")?);
        }
    }
    Ok(AgentDomainEvidence::build(
        &receipts, &forgotten, daemon_key,
    ))
}
