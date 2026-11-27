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
use ed25519_dalek::VerifyingKey;
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
use crate::governance::daemon_signer::{self, DaemonDomain};

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

/// #10135 — one stored `forget_tombstones` row as read. The tombstone is
/// evidence of an erasure only when its signature verifies under the daemon
/// key and [`DaemonDomain::Tombstone`] over
/// [`crate::storage::forget_tombstone_signing_body`] (the body the forget
/// paths of both backends sign).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTombstoneRow {
    /// `memory_id`.
    pub memory_id: String,
    /// `namespace`.
    pub namespace: String,
    /// `forgotten_at`, the stored text the signature covers.
    pub forgotten_at: String,
    /// `signature` (NULL when the forget ran keyless).
    pub signature: Option<Vec<u8>>,
}

impl StoredTombstoneRow {
    /// The evidence this tombstone gives under `key`.
    fn evidence(&self, key: &VerifyingKey) -> TombstoneEvidence {
        let Some(sig) = self.signature.as_deref() else {
            return TombstoneEvidence::Unsigned;
        };
        let body = crate::storage::forget_tombstone_signing_body(
            &self.memory_id,
            &self.namespace,
            &self.forgotten_at,
        );
        if daemon_signer::verify(key, DaemonDomain::Tombstone, &body, sig) {
            TombstoneEvidence::Signed
        } else {
            TombstoneEvidence::Invalid
        }
    }
}

/// #10135 — what one tombstone proves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TombstoneEvidence {
    /// A daemon signature under the tombstone domain verified: an erasure.
    Signed,
    /// No signature: no erasure evidence.
    Unsigned,
    /// A signature that does not verify: no erasure evidence.
    Invalid,
}

/// #10108 (W-14, S-4) — the `atomisation_complete` chain rows of the WHOLE
/// table (whatever window a walk covers) a stored receipt can be anchored
/// to: their stored `payload_hash` and `cause_hash`. Only `daemon_signed`
/// rows anchor; any other row is itself a failure above the marker.
#[derive(Debug, Clone, Default)]
pub struct ReceiptAnchors {
    payload_hashes: HashSet<[u8; 32]>,
    causes: HashSet<SourceBinding>,
}

impl ReceiptAnchors {
    /// Add one chain row's stored columns.
    pub fn insert(&mut self, payload_hash: &[u8], cause_hash: Option<&[u8]>) {
        if let Ok(h) = <[u8; 32]>::try_from(payload_hash) {
            self.payload_hashes.insert(h);
        }
        if let Some(b) = SourceBinding::from_stored(cause_hash) {
            self.causes.insert(b);
        }
    }
}

/// #10108 (W-14) — whether a stored receipt has a chain row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptAnchoring {
    /// A chain row names it.
    Anchored,
    /// No chain row names it: never verified, a chain-level failure.
    Orphan,
}

/// #10108 (W-12) — the query that lists the anchoring rows, shared by both
/// backends (the event type and the attest level are literals of the
/// chain's own vocabulary).
pub const RECEIPT_ANCHOR_SQL: &str = "SELECT payload_hash, cause_hash FROM signed_events \
     WHERE event_type = 'atomisation_complete' AND attest_level = 'daemon_signed'";

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
    /// W-14 — stored receipts no chain row of the whole table anchors.
    orphan_receipts: usize,
}

impl AgentDomainEvidence {
    /// Index `receipts` and the daemon-signed tombstones under the daemon
    /// key, and count the receipts no row of `anchors` names. With no daemon
    /// key nothing is indexed (no daemon-signed row can verify then, so the
    /// index is never consulted), but orphans are still counted by source.
    #[must_use]
    pub fn build(
        receipts: &[StoredReceiptRow],
        tombstones: &[StoredTombstoneRow],
        anchors: &ReceiptAnchors,
        daemon_key: Option<&VerifyingKey>,
    ) -> Self {
        let mut ev = Self::default();
        let Some(key) = daemon_key else {
            ev.orphan_receipts = receipts
                .iter()
                .filter(|r| {
                    !anchors
                        .causes
                        .contains(&SourceBinding::of_source(&r.source_id))
                })
                .count();
            return ev;
        };
        let pubkey = key.to_bytes();
        for row in receipts {
            let binding = SourceBinding::of_source(&row.source_id);
            let by_source = if anchors.causes.contains(&binding) {
                ReceiptAnchoring::Anchored
            } else {
                ReceiptAnchoring::Orphan
            };
            let sig = row
                .signature
                .as_deref()
                .and_then(|s| <[u8; AGENT_SIGNATURE_LEN]>::try_from(s).ok());
            let anchoring = match (row.signature.as_deref(), sig, row.receipt()) {
                (None, _, _) => {
                    ev.unsigned_sources.insert(binding);
                    by_source
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
                    // W-13 — the receipt's own domain; a raw-rule or
                    // other-domain signature never verifies here.
                    let check = if daemon_signer::verify(
                        key,
                        DaemonDomain::AtomisationReceipt,
                        &bytes,
                        &sig,
                    ) {
                        ReceiptCheck::SignatureValid
                    } else {
                        ReceiptCheck::SignatureInvalid
                    };
                    ev.by_hash.insert(*hash.as_bytes(), (check, binding));
                    if anchors.payload_hashes.contains(hash.as_bytes()) {
                        ReceiptAnchoring::Anchored
                    } else {
                        ReceiptAnchoring::Orphan
                    }
                }
                // A wrong-length signature or unreadable fields: the source
                // has a receipt that can match no chain row (fail closed).
                (Some(_), _, _) => {
                    ev.signed_sources.insert(binding);
                    by_source
                }
            };
            if anchoring == ReceiptAnchoring::Orphan {
                ev.orphan_receipts += 1;
            }
        }
        for t in tombstones {
            match t.evidence(key) {
                TombstoneEvidence::Signed => {
                    ev.tombstoned_sources
                        .insert(SourceBinding::of_source(&t.memory_id));
                }
                TombstoneEvidence::Unsigned | TombstoneEvidence::Invalid => {}
            }
        }
        ev
    }

    /// W-14 — the chain-level failure of this evidence: a stored receipt
    /// with no chain row. Reported at sequence 0 on every walk.
    #[must_use]
    pub fn chain_failure(&self) -> Option<SignatureFailure> {
        (self.orphan_receipts > 0).then_some(SignatureFailure::ReceiptChainRowMissing)
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

/// #10108 (W-12) — what a row says about the receipt it names, from the
/// row's position relative to the marker ONLY (never a receipt field or a
/// signature shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptEra {
    /// A `daemon_signed` `atomisation_complete` row below the marker (or with
    /// no marker): its receipt predates the receipt domain, so it is counted
    /// legacy and never verified; the row keeps the daemon-row check.
    Legacy,
    /// Any other row (a signed-era atomisation row is judged by
    /// [`AgentDomainEvidence::verdict`]).
    NotLegacyReceipt,
}

/// #10108 (W-12) — the [`ReceiptEra`] of `event`.
#[must_use]
pub fn receipt_era(event: &SignedEvent, walk: &AgentEraWalk<'_>) -> ReceiptEra {
    let is_atomisation = matches!(
        AgentEventKind::of_event_type(&event.event_type),
        Some(AgentEventKind::AtomisationComplete)
    );
    match (
        is_atomisation,
        SignerIdentity::of(&event.attest_level),
        RowEra::resolve(&walk.cutover, event.sequence),
    ) {
        (true, SignerIdentity::Daemon, RowEra::Era(PayloadEra::Legacy)) => ReceiptEra::Legacy,
        _ => ReceiptEra::NotLegacyReceipt,
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
    let mut tombstones = Vec::new();
    if sqlite_table_exists(conn, "forget_tombstones")? {
        let mut stmt = conn
            .prepare(TOMBSTONE_EVIDENCE_SQL)
            .context("agent evidence: prepare tombstones")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(StoredTombstoneRow {
                    memory_id: r.get(0)?,
                    namespace: r.get(1)?,
                    forgotten_at: r.get(2)?,
                    signature: r.get(3)?,
                })
            })
            .context("agent evidence: query tombstones")?;
        for row in rows {
            tombstones.push(row.context("agent evidence: read tombstone")?);
        }
    }
    let mut anchors = ReceiptAnchors::default();
    if sqlite_table_exists(conn, crate::storage::schema_integrity::TABLE_SIGNED_EVENTS)? {
        let mut stmt = conn
            .prepare(RECEIPT_ANCHOR_SQL)
            .context("agent evidence: prepare anchors")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<Vec<u8>>>(1)?))
            })
            .context("agent evidence: query anchors")?;
        for row in rows {
            let (payload_hash, cause_hash) = row.context("agent evidence: read anchor")?;
            anchors.insert(&payload_hash, cause_hash.as_deref());
        }
    }
    Ok(AgentDomainEvidence::build(
        &receipts,
        &tombstones,
        &anchors,
        daemon_key,
    ))
}

/// #10135 — the tombstone columns the signature covers, shared by both
/// backends' loaders.
pub const TOMBSTONE_EVIDENCE_SQL: &str =
    "SELECT memory_id, namespace, forgotten_at, signature FROM forget_tombstones";
