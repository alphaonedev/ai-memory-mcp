// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Equivocation-proof format spine — peer-head attestation + the
//! self-contained, offline-verifiable equivocation proof (#1947 R3/R22,
//! epic #1940, spec §5.2, decision `00d599ec`).
//!
//! Two frozen byte shapes, both built on the stage-1 pinned CBOR-**array**
//! encoder ([`crate::identity::cbor_array`]) so the RFC 8949 key-ordering
//! ambiguity cannot fire and the bytes are golden-vector-pinned:
//!
//! 1. [`SignableHeadAttestation`] (`"ai-memory/peer-head-attestation-v1"`)
//!    — a *single* subject-signed claim about "my head at
//!    `(epoch, head_sequence)` is `head_hash`, at `signed_at`". The domain
//!    tag is committed **inside** the signed pre-image (element [0]),
//!    mandatory here because [`crate::models::ConditionType`] resolutions do
//!    NOT commit `condition_type` — a bare head hash with no domain would be
//!    cross-protocol reinterpretable.
//! 2. [`EquivocationProof`] (`"ai-memory/equivocation-proof/v1"`) — a
//!    *pair* of subject-signed head-attestations for the SAME
//!    `(subject, epoch, head_sequence)` with DIFFERENT `head_hash`, carried
//!    together with the subject's 32-byte Ed25519 public key. It is
//!    **self-contained**: any third peer verifies it offline, from the
//!    bytes alone, with ZERO shared state — decode the envelope, re-encode
//!    each head-attestation through the pinned encoder, check both
//!    signatures under the embedded pubkey, and assert the divergence.
//!
//! # Divergence key + ordering authority (spec §5.2)
//!
//! The divergence key is `(subject_id, epoch, head_sequence) → head_hash`.
//! `epoch` is drawn from the SIGNED v76 lineage succession (never
//! self-declared — that is the epoch-lie escape hatch the ruling closes),
//! and the ordering authority for `head_sequence`/`head_hash` is the
//! subject's own `signed_events` V-4 `prev_hash` chain. This module freezes
//! the *format*; the epoch value is simply committed inside the
//! subject-signed attestation bytes, so the accuser cannot forge it.
//!
//! # Honest scope — LIVENESS, not SAFETY (spec §5.2)
//!
//! Detection is a **LIVENESS** property: a permanently-partitioned
//! Byzantine node is invisible until its two views heal into one verifier's
//! sight (the inherent equivocation lower bound). **SAFETY holds
//! unconditionally** — a well-formed proof is a genuine two-signature
//! contradiction and can never falsely accuse. A verifier whose lineage
//! view cannot confirm the proof's epoch withholds judgement
//! ([`EquivocationVerdict::Indeterminate`]) rather than accuse — INDETERMINATE
//! is *correct-failing*, never a false accusation.
//!
//! # Scope (format + offline verifier ONLY)
//!
//! Pure functions + the record types + the offline verifier + golden
//! vectors. This module does NOT wire into any live / federation / eviction
//! path (transport is #1936; the epoch-consulting eviction runtime is
//! FED-RQ-02/03) and adds NO schema migration. Automatic eviction consults
//! the v76 lineage chain (not the raw pubkey) so a stale proof after a
//! legit genesis re-key cannot self-evict — that gate lives in the deferred
//! runtime, not here.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::identity::cbor_array::{
    CborItem, EQUIVOCATION_PROOF_V1_DOMAIN, PEER_HEAD_ATTESTATION_V1_DOMAIN, encode,
};

/// Length of an Ed25519 signature in bytes.
const SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;
/// Length of an Ed25519 verifying (public) key in bytes.
const PUBKEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

/// The number of positional elements in a `SignableHeadAttestation` array
/// (spec §5.2): the domain tag (element [0]) plus the five committed fields
/// `{subject_agent_id, epoch, head_sequence, head_hash, signed_at}`. The
/// 64-byte signature is NOT part of the signed pre-image.
pub const HEAD_ATTESTATION_ELEMENTS: usize = 6;

/// The number of positional elements in an `EquivocationProof` envelope
/// array (spec §5.2): the domain tag (element [0]), the subject's 32-byte
/// pubkey (element [1]), and the two head-attestation entries (elements
/// [2], [3]).
pub const EQUIVOCATION_PROOF_ELEMENTS: usize = 4;

/// The number of positional elements in a single attestation ENTRY sub-array
/// carried inside an [`EquivocationProof`]: the five committed fields
/// `{subject_agent_id, epoch, head_sequence, head_hash, signed_at}` plus the
/// 64-byte signature. The domain tag is NOT stored in the entry — it is
/// re-derived by the pinned encoder at verify time (re-encode-and-compare).
pub const HEAD_ATTESTATION_ENTRY_ELEMENTS: usize = 6;

/// The reserved namespace for peer-head-entanglement checkpoint records
/// (spec §5.2). Write-reserved: a normal caller memory write to this exact
/// namespace is refused at the validate layer
/// ([`crate::validate::validate_create`]) so only the substrate's internal
/// equivocation lane authors rows under it. Underscore-prefixed by the
/// same `_`-reserved-namespace convention the curator already honours.
pub const PEER_HEAD_ENTANGLEMENT_NAMESPACE: &str = "_peer_head_entanglement";

// ---------------------------------------------------------------------------
// SignableHeadAttestation (spec §5.2) — one subject-signed head claim.
// ---------------------------------------------------------------------------

/// A subject-signed peer-head attestation (spec §5.2).
///
/// Borrowed, encoder-facing view of the five fields the subject's Ed25519
/// signature commits to. `epoch` is drawn from the subject's SIGNED v76
/// lineage succession; `head_sequence`/`head_hash` come from the subject's
/// own `signed_events` V-4 `prev_hash` chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignableHeadAttestation<'a> {
    /// The subject agent whose head this attests (element [1]).
    pub subject_agent_id: &'a str,
    /// The subject's signed lineage epoch this head belongs to (element [2]).
    pub epoch: u64,
    /// The subject's head sequence in its `signed_events` chain (element [3]).
    pub head_sequence: u64,
    /// The head hash at `head_sequence` — the subject's V-4 chain head
    /// (element [4]).
    pub head_hash: &'a [u8],
    /// RFC3339 instant the attestation was signed (element [5]).
    pub signed_at: &'a str,
}

/// Encode a [`SignableHeadAttestation`] to its canonical, profile-restricted
/// signed bytes: the frozen 6-element positional array of spec §5.2, via the
/// stage-1 pinned array encoder.
///
/// These are the exact bytes the subject's Ed25519 signature is computed
/// over; the golden-vector corpus (`tests/golden/peer_head_attestation/`)
/// pins the output of this function as a hard CI gate.
#[must_use]
pub fn canonical_cbor_head_attestation(att: &SignableHeadAttestation<'_>) -> Vec<u8> {
    let array = CborItem::Array(vec![
        CborItem::Text(PEER_HEAD_ATTESTATION_V1_DOMAIN), // [0] _dst
        CborItem::Text(att.subject_agent_id),            // [1]
        CborItem::Uint(att.epoch),                       // [2]
        CborItem::Uint(att.head_sequence),               // [3]
        CborItem::Bytes(att.head_hash),                  // [4]
        CborItem::Text(att.signed_at),                   // [5]
    ]);
    debug_assert!(
        matches!(&array, CborItem::Array(v) if v.len() == HEAD_ATTESTATION_ELEMENTS),
        "SignableHeadAttestation must encode exactly {HEAD_ATTESTATION_ELEMENTS} elements",
    );
    encode(&array)
}

/// Sign a [`SignableHeadAttestation`] with the **subject's** signing key,
/// returning the raw 64-byte Ed25519 signature over its canonical bytes.
#[must_use]
pub fn sign_head_attestation(
    subject: &SigningKey,
    att: &SignableHeadAttestation<'_>,
) -> [u8; SIGNATURE_LEN] {
    let bytes = canonical_cbor_head_attestation(att);
    let sig: Signature = subject.sign(&bytes);
    sig.to_bytes()
}

/// Verify a [`SignableHeadAttestation`] signature under the subject's
/// verifying key.
///
/// Re-encodes the attestation via the pinned §5.2 array profile and checks
/// the signature with `verify_strict` (rejecting malleable / non-canonical
/// signatures, matching the stage-2 [`crate::identity::subkey_cert`]
/// verifier).
///
/// # Errors
///
/// - [`EquivocationError::MalformedSignature`] — signature not 64 bytes.
/// - [`EquivocationError::SignatureInvalid`] — signature does not validate
///   under `subject_pubkey` over the canonical attestation bytes.
pub fn verify_head_attestation(
    subject_pubkey: &VerifyingKey,
    att: &SignableHeadAttestation<'_>,
    signature: &[u8],
) -> Result<(), EquivocationError> {
    let sig = parse_signature(signature)?;
    let bytes = canonical_cbor_head_attestation(att);
    subject_pubkey
        .verify_strict(&bytes, &sig)
        .map_err(|_| EquivocationError::SignatureInvalid)
}

// ---------------------------------------------------------------------------
// EquivocationProof (spec §5.2) — self-contained, offline-verifiable pair.
// ---------------------------------------------------------------------------

/// An owned head-attestation ENTRY as it lives inside an
/// [`EquivocationProof`]: the five committed fields plus the 64-byte
/// signature the subject minted over them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadAttestationEntry {
    /// Subject agent id (committed field).
    pub subject_agent_id: String,
    /// Lineage epoch (committed field).
    pub epoch: u64,
    /// Head sequence (committed field).
    pub head_sequence: u64,
    /// Head hash (committed field).
    pub head_hash: Vec<u8>,
    /// RFC3339 signing instant (committed field).
    pub signed_at: String,
    /// The subject's Ed25519 signature over the re-encoded committed fields.
    pub signature: Vec<u8>,
}

impl HeadAttestationEntry {
    /// Borrow this entry's committed fields as a [`SignableHeadAttestation`]
    /// so the verifier can RE-ENCODE (never decode-and-trust) and check the
    /// signature over the pinned bytes.
    #[must_use]
    pub fn as_signable(&self) -> SignableHeadAttestation<'_> {
        SignableHeadAttestation {
            subject_agent_id: &self.subject_agent_id,
            epoch: self.epoch,
            head_sequence: self.head_sequence,
            head_hash: &self.head_hash,
            signed_at: &self.signed_at,
        }
    }

    /// Build an owned entry from a borrowed attestation + its signature.
    #[must_use]
    pub fn from_signed(att: &SignableHeadAttestation<'_>, signature: &[u8]) -> Self {
        Self {
            subject_agent_id: att.subject_agent_id.to_string(),
            epoch: att.epoch,
            head_sequence: att.head_sequence,
            head_hash: att.head_hash.to_vec(),
            signed_at: att.signed_at.to_string(),
            signature: signature.to_vec(),
        }
    }
}

/// A self-contained, offline-verifiable equivocation proof (spec §5.2).
///
/// Carries the subject's 32-byte Ed25519 public key and the two conflicting
/// subject-signed head-attestations. Everything a third peer needs to render
/// a verdict is inside the struct (equivalently, inside [`Self::to_bytes`]):
/// no DB, no network, no shared state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivocationProof {
    /// The subject's raw 32-byte Ed25519 verifying key (element [1]).
    pub subject_pubkey: [u8; PUBKEY_LEN],
    /// The first conflicting head-attestation (element [2]).
    pub attestation_a: HeadAttestationEntry,
    /// The second conflicting head-attestation (element [3]).
    pub attestation_b: HeadAttestationEntry,
}

/// The verifier's lineage-epoch view for a `(subject, epoch)` pair — the
/// input the [`EquivocationProof::verify_with_lineage`] resolver returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochView {
    /// The verifier's lineage view confirms `epoch` is a real, current epoch
    /// for the subject — a cryptographically-sound proof is a genuine
    /// [`EquivocationVerdict::Equivocation`].
    Confirmed,
    /// The verifier cannot confirm the epoch (a stale / absent lineage view,
    /// e.g. after a legit genesis re-key the verifier hasn't observed) — the
    /// verdict withholds to [`EquivocationVerdict::Indeterminate`] rather than
    /// risk a false accusation.
    Unresolvable,
}

/// The verdict of a successful [`EquivocationProof`] verification (spec §5.2).
///
/// Both structural rejects and cryptographic failures surface as
/// [`EquivocationError`]; this enum is only the *accepted* dispositions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EquivocationVerdict {
    /// A genuine, cryptographically-sound equivocation: two valid
    /// subject-signed heads for the SAME `(subject, epoch, head_sequence)`
    /// with DIFFERENT `head_hash`, and the verifier's lineage view confirms
    /// the epoch. SAFETY holds — this is never a false accusation.
    Equivocation,
    /// The proof is cryptographically sound and structurally a divergence,
    /// but the verifier's lineage view cannot confirm the epoch (stale /
    /// re-keyed view). Judgement is WITHHELD — correct-failing, NOT an
    /// accusation and NOT an all-clear.
    Indeterminate,
}

/// Typed rejects / verdicts from the equivocation-proof verifier (spec §5.2).
///
/// The distinct variants are for logs / audit envelopes. A malformed,
/// same-hash, or cross-epoch pair is NOT an equivocation and is rejected as
/// such; a stale epoch view is reported as
/// [`EquivocationVerdict::Indeterminate`] (an `Ok`), never an error, so it
/// can never masquerade as a proof OR as a clean bill of health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EquivocationError {
    /// The proof bytes were structurally malformed (bad CBOR shape, wrong
    /// element count, wrong domain tag, wrong types).
    Malformed(String),
    /// The embedded subject pubkey was not a valid 32-byte Ed25519 key.
    BadPubkey,
    /// A signature was not exactly 64 bytes.
    MalformedSignature,
    /// One of the two attestation signatures did not verify under the
    /// embedded subject pubkey.
    SignatureInvalid,
    /// The two attestations name DIFFERENT subjects — not a divergence.
    SubjectMismatch,
    /// The two attestations are at DIFFERENT epochs — a cross-epoch pair is
    /// not equivocation (the divergence key includes `epoch`).
    EpochMismatch,
    /// The two attestations are at DIFFERENT head sequences — not a
    /// divergence at one point in the chain.
    SequenceMismatch,
    /// The two attestations carry the SAME `head_hash` — identical heads are
    /// agreement, NOT equivocation.
    SameHash,
}

impl EquivocationError {
    /// Stable machine-readable tag for logs + JSON error envelopes.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "equivocation_malformed",
            Self::BadPubkey => "equivocation_bad_pubkey",
            Self::MalformedSignature => "equivocation_malformed_signature",
            Self::SignatureInvalid => "equivocation_signature_invalid",
            Self::SubjectMismatch => "equivocation_subject_mismatch",
            Self::EpochMismatch => "equivocation_epoch_mismatch",
            Self::SequenceMismatch => "equivocation_sequence_mismatch",
            Self::SameHash => "equivocation_same_hash",
        }
    }
}

impl std::fmt::Display for EquivocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(d) => write!(f, "malformed equivocation proof: {d}"),
            other => f.write_str(other.tag()),
        }
    }
}

impl std::error::Error for EquivocationError {}

impl EquivocationProof {
    /// Assemble a proof from the subject pubkey and the two signed
    /// attestations. Does NOT verify — it is the constructor an accuser uses
    /// after observing two conflicting subject-signed heads.
    #[must_use]
    pub fn new(
        subject_pubkey: [u8; PUBKEY_LEN],
        att_a: &SignableHeadAttestation<'_>,
        sig_a: &[u8],
        att_b: &SignableHeadAttestation<'_>,
        sig_b: &[u8],
    ) -> Self {
        Self {
            subject_pubkey,
            attestation_a: HeadAttestationEntry::from_signed(att_a, sig_a),
            attestation_b: HeadAttestationEntry::from_signed(att_b, sig_b),
        }
    }

    /// Encode the proof to its self-contained, profile-restricted CBOR bytes:
    /// the frozen 4-element positional array of spec §5.2, via the stage-1
    /// pinned array encoder. These bytes are what a third peer transports and
    /// verifies offline; the golden-vector corpus
    /// (`tests/golden/equivocation_proof/`) pins the output as a CI gate.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let array = CborItem::Array(vec![
            CborItem::Text(EQUIVOCATION_PROOF_V1_DOMAIN), // [0] _dst
            CborItem::Bytes(&self.subject_pubkey),        // [1]
            entry_item(&self.attestation_a),              // [2]
            entry_item(&self.attestation_b),              // [3]
        ]);
        debug_assert!(
            matches!(&array, CborItem::Array(v) if v.len() == EQUIVOCATION_PROOF_ELEMENTS),
            "EquivocationProof must encode exactly {EQUIVOCATION_PROOF_ELEMENTS} elements",
        );
        encode(&array)
    }

    /// Decode a proof from its self-contained CBOR bytes (the offline
    /// transport form). This parses the ENVELOPE only; trust is established
    /// separately by [`Self::verify`], which RE-ENCODES each attestation
    /// through the pinned encoder and checks the subject signatures (never
    /// decode-and-trust).
    ///
    /// # Errors
    ///
    /// [`EquivocationError::Malformed`] on any CBOR shape / count / type /
    /// domain-tag violation; [`EquivocationError::BadPubkey`] when element
    /// [1] is not 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EquivocationError> {
        let value: ciborium::value::Value = ciborium::de::from_reader(bytes)
            .map_err(|e| EquivocationError::Malformed(format!("not decodable CBOR: {e}")))?;
        let top = as_array(&value, EQUIVOCATION_PROOF_ELEMENTS, "proof envelope")?;
        expect_domain(&top[0], EQUIVOCATION_PROOF_V1_DOMAIN)?;
        let pubkey_bytes = as_bytes(&top[1], "subject_pubkey")?;
        let subject_pubkey: [u8; PUBKEY_LEN] = pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| EquivocationError::BadPubkey)?;
        Ok(Self {
            subject_pubkey,
            attestation_a: decode_entry(&top[2], "attestation_a")?,
            attestation_b: decode_entry(&top[3], "attestation_b")?,
        })
    }

    /// Verify the proof offline, from the fields alone, WITHOUT a lineage
    /// view — the base third-peer path. Equivalent to
    /// [`Self::verify_with_lineage`] with a resolver that trusts the
    /// subject-signed epoch (which is inside the signed bytes, so the accuser
    /// cannot forge it). Returns [`EquivocationVerdict::Equivocation`] on a
    /// genuine proof.
    ///
    /// # Errors
    ///
    /// Any [`EquivocationError`] — a bad key, a bad signature, or a pair that
    /// is not a genuine divergence (`SubjectMismatch` / `EpochMismatch` /
    /// `SequenceMismatch` / `SameHash`).
    pub fn verify(&self) -> Result<EquivocationVerdict, EquivocationError> {
        self.verify_with_lineage(|_subject, _epoch| EpochView::Confirmed)
    }

    /// Verify the proof offline with an optional verifier-side lineage-epoch
    /// resolver (spec §5.2). The resolver answers "can my lineage view
    /// confirm this `(subject, epoch)`?"; when it returns
    /// [`EpochView::Unresolvable`] the verdict withholds to
    /// [`EquivocationVerdict::Indeterminate`] — never a false accusation on a
    /// stale / re-keyed epoch view.
    ///
    /// Cryptographic + structural checks (both signatures valid, same
    /// subject/epoch/sequence, different hash) run FIRST and yield typed
    /// rejects; only a sound-and-diverging pair reaches the lineage gate.
    ///
    /// # Errors
    ///
    /// Any [`EquivocationError`] — the same set as [`Self::verify`]. A stale
    /// epoch view is reported as an `Ok(Indeterminate)`, never an error.
    pub fn verify_with_lineage(
        &self,
        resolver: impl Fn(&str, u64) -> EpochView,
    ) -> Result<EquivocationVerdict, EquivocationError> {
        let subject = VerifyingKey::from_bytes(&self.subject_pubkey)
            .map_err(|_| EquivocationError::BadPubkey)?;

        // Both attestations must genuinely be the subject's — re-encode each
        // through the pinned encoder and check the signature. Never trust the
        // envelope's field values without a valid subject signature over them.
        verify_head_attestation(
            &subject,
            &self.attestation_a.as_signable(),
            &self.attestation_a.signature,
        )?;
        verify_head_attestation(
            &subject,
            &self.attestation_b.as_signable(),
            &self.attestation_b.signature,
        )?;

        // Divergence key = (subject_id, epoch, head_sequence). A pair that
        // does not share the whole key is NOT equivocation.
        if self.attestation_a.subject_agent_id != self.attestation_b.subject_agent_id {
            return Err(EquivocationError::SubjectMismatch);
        }
        if self.attestation_a.epoch != self.attestation_b.epoch {
            return Err(EquivocationError::EpochMismatch);
        }
        if self.attestation_a.head_sequence != self.attestation_b.head_sequence {
            return Err(EquivocationError::SequenceMismatch);
        }
        // Same key + SAME hash is agreement, not equivocation.
        if self.attestation_a.head_hash == self.attestation_b.head_hash {
            return Err(EquivocationError::SameHash);
        }

        // Cryptographically sound + structurally a divergence. The verdict now
        // rests on whether the verifier's lineage view can confirm the epoch.
        match resolver(
            &self.attestation_a.subject_agent_id,
            self.attestation_a.epoch,
        ) {
            EpochView::Confirmed => Ok(EquivocationVerdict::Equivocation),
            EpochView::Unresolvable => Ok(EquivocationVerdict::Indeterminate),
        }
    }
}

/// Build the 6-element attestation ENTRY sub-array (five committed fields +
/// the signature) carried inside an [`EquivocationProof`].
fn entry_item<'a>(entry: &'a HeadAttestationEntry) -> CborItem<'a> {
    let array = CborItem::Array(vec![
        CborItem::Text(&entry.subject_agent_id),
        CborItem::Uint(entry.epoch),
        CborItem::Uint(entry.head_sequence),
        CborItem::Bytes(&entry.head_hash),
        CborItem::Text(&entry.signed_at),
        CborItem::Bytes(&entry.signature),
    ]);
    debug_assert!(
        matches!(&array, CborItem::Array(v) if v.len() == HEAD_ATTESTATION_ENTRY_ELEMENTS),
        "attestation entry must encode exactly {HEAD_ATTESTATION_ENTRY_ELEMENTS} elements",
    );
    array
}

/// Decode a raw signature slice into a strict Ed25519 [`Signature`].
fn parse_signature(signature: &[u8]) -> Result<Signature, EquivocationError> {
    let arr: [u8; SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| EquivocationError::MalformedSignature)?;
    Ok(Signature::from_bytes(&arr))
}

// ---------------------------------------------------------------------------
// Envelope decode helpers (ciborium — parses the transport shape only; the
// signed head-attestation bytes are always re-encoded via the pinned encoder
// before the signature check, never decoded-and-trusted).
// ---------------------------------------------------------------------------

/// Borrow a `Value` as a definite-length array of exactly `n` items.
fn as_array<'a>(
    v: &'a ciborium::value::Value,
    n: usize,
    what: &str,
) -> Result<&'a [ciborium::value::Value], EquivocationError> {
    match v {
        ciborium::value::Value::Array(items) if items.len() == n => Ok(items),
        ciborium::value::Value::Array(items) => Err(EquivocationError::Malformed(format!(
            "{what}: expected {n} elements, got {}",
            items.len()
        ))),
        _ => Err(EquivocationError::Malformed(format!(
            "{what}: not an array"
        ))),
    }
}

/// Assert element [0] is the exact expected domain tag.
fn expect_domain(v: &ciborium::value::Value, expected: &str) -> Result<(), EquivocationError> {
    match v {
        ciborium::value::Value::Text(s) if s == expected => Ok(()),
        _ => Err(EquivocationError::Malformed(format!(
            "element [0] is not the `{expected}` domain tag"
        ))),
    }
}

/// Borrow a `Value` as a text string.
fn as_text(v: &ciborium::value::Value, what: &str) -> Result<String, EquivocationError> {
    match v {
        ciborium::value::Value::Text(s) => Ok(s.clone()),
        _ => Err(EquivocationError::Malformed(format!("{what}: not text"))),
    }
}

/// Borrow a `Value` as a byte string.
fn as_bytes(v: &ciborium::value::Value, what: &str) -> Result<Vec<u8>, EquivocationError> {
    match v {
        ciborium::value::Value::Bytes(b) => Ok(b.clone()),
        _ => Err(EquivocationError::Malformed(format!("{what}: not bytes"))),
    }
}

/// Borrow a `Value` as an unsigned integer that fits `u64`.
fn as_uint(v: &ciborium::value::Value, what: &str) -> Result<u64, EquivocationError> {
    match v {
        ciborium::value::Value::Integer(i) => u64::try_from(i128::from(*i))
            .map_err(|_| EquivocationError::Malformed(format!("{what}: not a u64"))),
        _ => Err(EquivocationError::Malformed(format!(
            "{what}: not an integer"
        ))),
    }
}

/// Decode one attestation ENTRY sub-array into an owned [`HeadAttestationEntry`].
fn decode_entry(
    v: &ciborium::value::Value,
    what: &str,
) -> Result<HeadAttestationEntry, EquivocationError> {
    let e = as_array(v, HEAD_ATTESTATION_ENTRY_ELEMENTS, what)?;
    Ok(HeadAttestationEntry {
        subject_agent_id: as_text(&e[0], "entry subject id")?,
        epoch: as_uint(&e[1], "entry epoch")?,
        head_sequence: as_uint(&e[2], "entry head seq")?,
        head_hash: as_bytes(&e[3], "entry head hash")?,
        signed_at: as_text(&e[4], "entry signed at")?,
        signature: as_bytes(&e[5], "entry signature")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    const SUBJECT: &str = "ai:claude-code@pop-os";
    const SIGNED_AT: &str = "2026-07-11T00:00:00Z";

    fn att<'a>(epoch: u64, seq: u64, head_hash: &'a [u8]) -> SignableHeadAttestation<'a> {
        SignableHeadAttestation {
            subject_agent_id: SUBJECT,
            epoch,
            head_sequence: seq,
            head_hash,
            signed_at: SIGNED_AT,
        }
    }

    // -- SignableHeadAttestation ----------------------------------------

    #[test]
    fn head_attestation_encodes_six_element_domain_tagged_array() {
        let enc = canonical_cbor_head_attestation(&att(3, 42, &[0xaa; 32]));
        // 6-element array header 0x86 (0x80 | 6).
        assert_eq!(enc[0], 0x86);
        // Element [0] is the 34-byte domain tag: text head 0x78 0x22.
        assert_eq!(&enc[1..3], &[0x78, 0x22]);
        assert_eq!(
            &enc[3..3 + PEER_HEAD_ATTESTATION_V1_DOMAIN.len()],
            PEER_HEAD_ATTESTATION_V1_DOMAIN.as_bytes()
        );
    }

    #[test]
    fn head_attestation_sign_then_verify_round_trips() {
        let sk = subject_key();
        let a = att(3, 42, &[0xaa; 32]);
        let sig = sign_head_attestation(&sk, &a);
        verify_head_attestation(&sk.verifying_key(), &a, &sig).expect("clean attestation verifies");
    }

    #[test]
    fn head_attestation_verify_rejects_forged_sig() {
        let sk = subject_key();
        let a = att(3, 42, &[0xaa; 32]);
        let mut sig = sign_head_attestation(&sk, &a);
        sig[0] ^= 0x01;
        assert_eq!(
            verify_head_attestation(&sk.verifying_key(), &a, &sig),
            Err(EquivocationError::SignatureInvalid)
        );
    }

    #[test]
    fn head_attestation_verify_rejects_mutated_field() {
        let sk = subject_key();
        let a = att(3, 42, &[0xaa; 32]);
        let sig = sign_head_attestation(&sk, &a);
        // Same signature, a mutated head_hash → re-encoded bytes differ → reject.
        let mutated = att(3, 42, &[0xbb; 32]);
        assert_eq!(
            verify_head_attestation(&sk.verifying_key(), &mutated, &sig),
            Err(EquivocationError::SignatureInvalid)
        );
    }

    #[test]
    fn head_attestation_verify_rejects_malformed_signature() {
        let sk = subject_key();
        assert_eq!(
            verify_head_attestation(&sk.verifying_key(), &att(1, 1, &[0; 32]), &[0u8; 10]),
            Err(EquivocationError::MalformedSignature)
        );
    }

    // -- EquivocationProof: happy path ----------------------------------

    /// Build a genuine equivocation proof: two heads at the SAME
    /// `(subject, epoch, seq)` with DIFFERENT `head_hash`, both signed.
    fn genuine_proof() -> EquivocationProof {
        let sk = subject_key();
        let hash_a = [0xaa; 32];
        let hash_b = [0xbb; 32];
        let a = att(3, 42, &hash_a);
        let b = att(3, 42, &hash_b);
        let sig_a = sign_head_attestation(&sk, &a);
        let sig_b = sign_head_attestation(&sk, &b);
        EquivocationProof::new(sk.verifying_key().to_bytes(), &a, &sig_a, &b, &sig_b)
    }

    #[test]
    fn genuine_proof_verifies_as_equivocation() {
        assert_eq!(
            genuine_proof().verify(),
            Ok(EquivocationVerdict::Equivocation)
        );
    }

    #[test]
    fn proof_round_trips_through_bytes() {
        let proof = genuine_proof();
        let bytes = proof.to_bytes();
        let decoded = EquivocationProof::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, proof);
    }

    /// Third-party offline verify: given ONLY the transport bytes (no keys,
    /// no DB, no shared state), a third peer decodes and renders the verdict.
    #[test]
    fn third_party_verifies_from_bytes_alone() {
        let bytes = genuine_proof().to_bytes();
        // A completely fresh reader with zero prior context.
        let verdict = EquivocationProof::from_bytes(&bytes)
            .expect("decode from bytes")
            .verify()
            .expect("verify from bytes");
        assert_eq!(verdict, EquivocationVerdict::Equivocation);
    }

    #[test]
    fn proof_envelope_is_four_element_domain_tagged_array() {
        let enc = genuine_proof().to_bytes();
        assert_eq!(enc[0], 0x84, "4-element array header (0x80 | 4)");
        // Element [0] is the 31-byte domain tag: text head 0x78 0x1f.
        assert_eq!(&enc[1..3], &[0x78, 0x1f]);
        assert_eq!(
            &enc[3..3 + EQUIVOCATION_PROOF_V1_DOMAIN.len()],
            EQUIVOCATION_PROOF_V1_DOMAIN.as_bytes()
        );
    }

    // -- EquivocationProof: typed rejects -------------------------------

    #[test]
    fn same_hash_is_not_equivocation() {
        // Two identical-hash heads = agreement. Even both-signed, it is a
        // typed reject, never an accusation.
        let sk = subject_key();
        let hash = [0xaa; 32];
        let a = att(3, 42, &hash);
        let b = att(3, 42, &hash);
        let sig_a = sign_head_attestation(&sk, &a);
        let sig_b = sign_head_attestation(&sk, &b);
        let proof = EquivocationProof::new(sk.verifying_key().to_bytes(), &a, &sig_a, &b, &sig_b);
        assert_eq!(proof.verify(), Err(EquivocationError::SameHash));
    }

    #[test]
    fn epoch_mismatch_is_not_equivocation() {
        // Different epochs = a cross-epoch pair (e.g. straddling a rotation),
        // NOT a divergence at one epoch.
        let sk = subject_key();
        let hash_a = [0xaa; 32];
        let hash_b = [0xbb; 32];
        let a = att(3, 42, &hash_a);
        let b = att(4, 42, &hash_b);
        let sig_a = sign_head_attestation(&sk, &a);
        let sig_b = sign_head_attestation(&sk, &b);
        let proof = EquivocationProof::new(sk.verifying_key().to_bytes(), &a, &sig_a, &b, &sig_b);
        assert_eq!(proof.verify(), Err(EquivocationError::EpochMismatch));
    }

    #[test]
    fn sequence_mismatch_is_not_equivocation() {
        let sk = subject_key();
        let hash_a = [0xaa; 32];
        let hash_b = [0xbb; 32];
        let a = att(3, 42, &hash_a);
        let b = att(3, 43, &hash_b);
        let sig_a = sign_head_attestation(&sk, &a);
        let sig_b = sign_head_attestation(&sk, &b);
        let proof = EquivocationProof::new(sk.verifying_key().to_bytes(), &a, &sig_a, &b, &sig_b);
        assert_eq!(proof.verify(), Err(EquivocationError::SequenceMismatch));
    }

    #[test]
    fn forged_signature_rejects_the_whole_proof() {
        let mut proof = genuine_proof();
        proof.attestation_b.signature[0] ^= 0x01;
        assert_eq!(proof.verify(), Err(EquivocationError::SignatureInvalid));
    }

    #[test]
    fn signature_over_a_different_key_is_rejected() {
        // An attacker fabricates two conflicting heads and signs with THEIR
        // key, then claims the victim's pubkey — the signatures do not verify
        // under the embedded (victim) key, so no false accusation lands.
        let attacker = SigningKey::from_bytes(&[0x99; 32]);
        let victim = subject_key();
        let hash_a = [0xaa; 32];
        let hash_b = [0xbb; 32];
        let a = att(3, 42, &hash_a);
        let b = att(3, 42, &hash_b);
        let sig_a = sign_head_attestation(&attacker, &a);
        let sig_b = sign_head_attestation(&attacker, &b);
        // Embed the VICTIM's pubkey but sign with the attacker key.
        let proof =
            EquivocationProof::new(victim.verifying_key().to_bytes(), &a, &sig_a, &b, &sig_b);
        assert_eq!(proof.verify(), Err(EquivocationError::SignatureInvalid));
    }

    #[test]
    fn bad_pubkey_is_rejected() {
        let mut proof = genuine_proof();
        // An all-zero point is not a valid Ed25519 verifying key.
        proof.subject_pubkey = [0u8; PUBKEY_LEN];
        // A zero key may decode but the signatures then fail; either way it is
        // an error, never an Equivocation verdict.
        assert!(proof.verify().is_err());
    }

    #[test]
    fn subject_mismatch_is_not_equivocation() {
        // Two heads with DIFFERENT subject ids, each self-signed by the same
        // key — the ids disagree so it is not one subject equivocating.
        let sk = subject_key();
        let hash_a = [0xaa; 32];
        let hash_b = [0xbb; 32];
        let a = SignableHeadAttestation {
            subject_agent_id: "ai:one@host",
            epoch: 3,
            head_sequence: 42,
            head_hash: &hash_a,
            signed_at: SIGNED_AT,
        };
        let b = SignableHeadAttestation {
            subject_agent_id: "ai:two@host",
            epoch: 3,
            head_sequence: 42,
            head_hash: &hash_b,
            signed_at: SIGNED_AT,
        };
        let sig_a = sign_head_attestation(&sk, &a);
        let sig_b = sign_head_attestation(&sk, &b);
        let proof = EquivocationProof::new(sk.verifying_key().to_bytes(), &a, &sig_a, &b, &sig_b);
        assert_eq!(proof.verify(), Err(EquivocationError::SubjectMismatch));
    }

    // -- EquivocationProof: INDETERMINATE on unresolvable epoch ----------

    #[test]
    fn unresolvable_epoch_view_is_indeterminate_not_accusation() {
        // A cryptographically-sound, structurally-diverging proof, but the
        // verifier's lineage view cannot confirm the epoch (e.g. a stale view
        // after a legit re-key). The verdict WITHHOLDS — never a false accusation.
        let proof = genuine_proof();
        let verdict = proof
            .verify_with_lineage(|_subject, _epoch| EpochView::Unresolvable)
            .expect("indeterminate is an Ok verdict, not an error");
        assert_eq!(verdict, EquivocationVerdict::Indeterminate);
    }

    #[test]
    fn confirmed_epoch_view_is_equivocation() {
        let proof = genuine_proof();
        assert_eq!(
            proof.verify_with_lineage(|subject, epoch| {
                // The resolver sees exactly what it needs to confirm.
                assert_eq!(subject, SUBJECT);
                assert_eq!(epoch, 3);
                EpochView::Confirmed
            }),
            Ok(EquivocationVerdict::Equivocation)
        );
    }

    #[test]
    fn indeterminate_gate_runs_after_crypto_checks() {
        // A same-hash pair is a typed reject BEFORE the lineage gate: an
        // unresolvable view must NOT launder a non-divergence into
        // Indeterminate.
        let sk = subject_key();
        let hash = [0xaa; 32];
        let a = att(3, 42, &hash);
        let b = att(3, 42, &hash);
        let sig_a = sign_head_attestation(&sk, &a);
        let sig_b = sign_head_attestation(&sk, &b);
        let proof = EquivocationProof::new(sk.verifying_key().to_bytes(), &a, &sig_a, &b, &sig_b);
        assert_eq!(
            proof.verify_with_lineage(|_, _| EpochView::Unresolvable),
            Err(EquivocationError::SameHash)
        );
    }

    // -- Malformed decode ------------------------------------------------

    #[test]
    fn from_bytes_rejects_garbage() {
        assert!(matches!(
            EquivocationProof::from_bytes(&[0xff, 0x00, 0x13]),
            Err(EquivocationError::Malformed(_))
        ));
    }

    #[test]
    fn from_bytes_rejects_wrong_domain_tag() {
        // A well-formed 4-element array whose element [0] is the wrong tag.
        let bogus = encode(&CborItem::Array(vec![
            CborItem::Text("ai-memory/write/v2"),
            CborItem::Bytes(&[0u8; 32]),
            CborItem::Uint(0),
            CborItem::Uint(0),
        ]));
        assert!(matches!(
            EquivocationProof::from_bytes(&bogus),
            Err(EquivocationError::Malformed(_))
        ));
    }

    #[test]
    fn from_bytes_rejects_bad_pubkey_length() {
        let bogus = encode(&CborItem::Array(vec![
            CborItem::Text(EQUIVOCATION_PROOF_V1_DOMAIN),
            CborItem::Bytes(&[0u8; 16]), // wrong length
            entry_item(&genuine_proof().attestation_a),
            entry_item(&genuine_proof().attestation_b),
        ]));
        assert_eq!(
            EquivocationProof::from_bytes(&bogus),
            Err(EquivocationError::BadPubkey)
        );
    }
}
