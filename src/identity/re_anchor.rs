// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! PQ re-anchor ceremony record for the v1.0.0 crypto-core
//! (#1942, epic #1940, spec §5.3, decision `129ca73f` R75).
//!
//! Per-record PQ signatures are forbidden (spec §2.4 — arithmetically
//! incompatible with endpoint budgets). Post-quantum strength therefore
//! binds at **checkpoint granularity** via a re-anchor ceremony: the
//! current-strength (new-suite) key **countersigns the prior chain head**
//! under a new suite, so enabling a stronger / PQ suite on a live corpus
//! causes zero write failures and zero record rewrites, and every
//! pre-break record stays attributable. This module is the FROZEN FORMAT
//! for that ceremony record — the [`SignableReAnchorV1`] type, its pinned
//! encoder (the countersignature-input definition), the countersign /
//! verify functions, and an unknown-suite-tolerant structural decoder.
//!
//! # Suite-tolerant decode, fail-closed verify (spec §2.4 / §5.3)
//!
//! The record commits a `new_suite_tag` (element [3]). Only
//! [`SUITE_ED25519_SHA256`](crate::identity::cbor_array::SUITE_ED25519_SHA256)
//! exists today, but a FUTURE PQ suite must be able to bind by tag alone:
//!
//! - [`decode_re_anchor_v1`] succeeds **structurally** for ANY
//!   `new_suite_tag` (a record minted under a not-yet-known PQ suite still
//!   parses), so an old binary can read a new record's shape.
//! - [`verify_re_anchor`] **fail-closes** on an unknown / mismatching
//!   suite BEFORE any signature check, via the §2.4 advisory-tag
//!   cross-check ([`verify_suite_binding`]). The enrolled suite is the
//!   sole authority; a wire tag it does not recognise is refused — never
//!   guessed, never dispatched (the JWS `alg`-confusion class is
//!   unrepresentable here for the same reason it is in
//!   [`crate::identity::suite`]).
//!
//! # Scope (crypto-core close-out)
//!
//! Pure types + sign/verify + a structural decoder + golden vectors ONLY.
//! There is **ZERO wiring** into any live path: checkpoint-granularity
//! EMISSION of a re-anchor record (the audit spine's
//! [`crate::governance::audit`] checkpoint/witness cadence is the natural
//! home) is post-v1.0-flip work. Only the bytes are frozen now, because
//! the first real ceremony record's layout becomes a permanent back-compat
//! + forensic obligation at the v1.0 tag.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::identity::cbor_array::{CborItem, RE_ANCHOR_V1_DOMAIN, encode};
use crate::identity::suite::{SuiteError, SuiteId, verify_suite_binding};

/// The number of positional elements in a `re-anchor/v1` array (spec §5.3).
///
/// `[domain, prior_chain_head_hash, prior_head_sequence, new_suite_tag,
/// anchored_at]` — the domain tag (element [0]) plus the four frozen bound
/// fields.
pub const RE_ANCHOR_V1_ELEMENTS: usize = 5;

/// Length of an Ed25519 signature in bytes.
const SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// The PQ re-anchor ceremony record (spec §5.3).
///
/// Borrowed, encoder-facing view: the fields are exactly the set the
/// new-suite key countersigns. Element order and the field set are FROZEN.
///
/// Frozen positions:
/// ```text
/// [0] "ai-memory/re-anchor/v1"  (domain tag)
/// [1] prior_chain_head_hash     (bytes; the head of the prior-suite chain)
/// [2] prior_head_sequence       (uint; that head's append sequence)
/// [3] new_suite_tag             (uint; the suite this ceremony enables —
///                                verification-ADVISORY per §2.4)
/// [4] anchored_at               (text; RFC3339 ceremony timestamp)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignableReAnchorV1<'a> {
    /// The prior-suite chain head being re-anchored (element [1]).
    pub prior_chain_head_hash: &'a [u8],
    /// The append sequence of that head (element [2]).
    pub prior_head_sequence: u64,
    /// The suite tag this ceremony enables (element [3]). Committed inside
    /// the signed bytes so the ceremony binds the suite it upgrades to;
    /// verification-ADVISORY per §2.4 (the enrolled suite is authoritative).
    pub new_suite_tag: u64,
    /// RFC3339 ceremony timestamp (element [4]).
    pub anchored_at: &'a str,
}

/// Encode a [`SignableReAnchorV1`] to its canonical, profile-restricted
/// signed bytes: the frozen 5-element positional array of spec §5.3, via
/// the stage-1 pinned array encoder.
///
/// **This is the countersignature-input definition** — the exact bytes the
/// new-suite key's signature is computed over in [`sign_re_anchor`] and
/// re-derived (never decode-and-trusted) in [`verify_re_anchor`]. The
/// golden-vector corpus (`tests/golden/re_anchor/`) pins the output of this
/// function as a hard CI gate.
#[must_use]
pub fn canonical_cbor_re_anchor_v1(r: &SignableReAnchorV1<'_>) -> Vec<u8> {
    let array = CborItem::Array(vec![
        CborItem::Text(RE_ANCHOR_V1_DOMAIN),      // [0] _dst
        CborItem::Bytes(r.prior_chain_head_hash), // [1]
        CborItem::Uint(r.prior_head_sequence),    // [2]
        CborItem::Uint(r.new_suite_tag),          // [3]
        CborItem::Text(r.anchored_at),            // [4]
    ]);
    debug_assert!(
        matches!(&array, CborItem::Array(v) if v.len() == RE_ANCHOR_V1_ELEMENTS),
        "re-anchor/v1 must encode exactly {RE_ANCHOR_V1_ELEMENTS} elements",
    );
    encode(&array)
}

/// Countersign a [`SignableReAnchorV1`] with the **new-suite** signing key,
/// returning the raw 64-byte Ed25519 signature over its canonical bytes
/// (the countersignature-input definition, [`canonical_cbor_re_anchor_v1`]).
///
/// Today only [`SUITE_ED25519_SHA256`](crate::identity::cbor_array::SUITE_ED25519_SHA256)
/// exists, so the countersignature is Ed25519; a future PQ suite supplies
/// its own signer over the SAME pinned pre-image. The caller is
/// responsible for setting `r.new_suite_tag` to the suite this key belongs
/// to — [`verify_re_anchor`] enforces the enrolled-suite cross-check.
#[must_use]
pub fn sign_re_anchor(
    new_suite_key: &SigningKey,
    r: &SignableReAnchorV1<'_>,
) -> [u8; SIGNATURE_LEN] {
    let bytes = canonical_cbor_re_anchor_v1(r);
    let sig: Signature = new_suite_key.sign(&bytes);
    sig.to_bytes()
}

/// Errors from the re-anchor countersignature check (spec §5.3 / §2.4).
///
/// The verifier's inbound posture is "reject"; the distinct variants are
/// for logs / audit envelopes (the [`crate::identity::verify::VerifyError`]
/// precedent), not for steering a verify path off the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReAnchorError {
    /// The committed `new_suite_tag` failed the §2.4 advisory-tag
    /// cross-check against the ENROLLED suite — the fail-closed refusal for
    /// an unknown suite ([`SuiteError::UnknownTag`]) or a downgrade attempt
    /// ([`SuiteError::TagMismatch`]). Checked FIRST, so an unknown-suite
    /// record is refused before any signature work.
    Suite(SuiteError),
    /// A signature was not exactly 64 bytes.
    MalformedSignature,
    /// The countersignature did not verify under the new-suite verifying
    /// key over the canonical re-anchor bytes (wrong key, flipped byte, or
    /// a mutated field).
    SignatureInvalid,
}

impl ReAnchorError {
    /// Stable machine-readable tag for logs + JSON error envelopes.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Suite(e) => e.tag(),
            Self::MalformedSignature => "re_anchor_malformed_signature",
            Self::SignatureInvalid => "re_anchor_signature_invalid",
        }
    }
}

impl From<SuiteError> for ReAnchorError {
    fn from(e: SuiteError) -> Self {
        Self::Suite(e)
    }
}

impl std::fmt::Display for ReAnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Suite(e) => write!(f, "{e}"),
            other => f.write_str(other.tag()),
        }
    }
}

impl std::error::Error for ReAnchorError {}

/// Verify a re-anchor ceremony countersignature (spec §5.3 / §2.4).
///
/// The `enrolled` [`SuiteId`] is the SOLE authority on the acceptable
/// suite (from key/epoch enrollment); `new_suite_verifying_key` is the
/// verifying key for that enrolled suite. The check order is deliberate
/// and **fail-closed**:
///
/// 1. cross-check the committed `r.new_suite_tag` against `enrolled` via
///    [`verify_suite_binding`] — an unknown tag is refused
///    ([`SuiteError::UnknownTag`]) and a known-but-different tag is refused
///    as a downgrade ([`SuiteError::TagMismatch`]). This runs BEFORE any
///    signature work, so a record minted under a not-yet-supported PQ
///    suite is rejected here (never dispatched onto a guessed verify path);
/// 2. re-encode the record via the pinned §5.3 array profile and check the
///    Ed25519 countersignature with `verify_strict` (rejecting malleable /
///    non-canonical signatures, matching the sibling v2 verifiers).
///
/// # Errors
///
/// - [`ReAnchorError::Suite`] — the suite cross-check failed (fail-closed
///   on an unknown / mismatching wire tag).
/// - [`ReAnchorError::MalformedSignature`] — signature not 64 bytes.
/// - [`ReAnchorError::SignatureInvalid`] — signature does not validate
///   under `new_suite_verifying_key` over the canonical bytes.
pub fn verify_re_anchor(
    new_suite_verifying_key: &VerifyingKey,
    enrolled: SuiteId,
    r: &SignableReAnchorV1<'_>,
    signature: &[u8],
) -> Result<(), ReAnchorError> {
    // (1) Suite cross-check FIRST — fail-closed on an unknown / mismatching
    // wire tag. The enrolled suite is authoritative; the wire tag is only
    // cross-checked, never used to select the verify path.
    verify_suite_binding(enrolled, r.new_suite_tag)?;

    // (2) Signature over the re-derived canonical pre-image.
    if signature.len() != SIGNATURE_LEN {
        return Err(ReAnchorError::MalformedSignature);
    }
    let mut arr = [0u8; SIGNATURE_LEN];
    arr.copy_from_slice(signature);
    let sig = Signature::from_bytes(&arr);
    let bytes = canonical_cbor_re_anchor_v1(r);
    new_suite_verifying_key
        .verify_strict(&bytes, &sig)
        .map_err(|_| ReAnchorError::SignatureInvalid)
}

// ---------------------------------------------------------------------------
// Unknown-suite-tolerant structural decode (spec §5.3).
//
// A purpose-built, profile-restricted decoder for the frozen 5-element
// re-anchor array. It is deliberately NOT a general CBOR decoder: it accepts
// exactly the pinned profile (definite-length array of {text | uint | bytes},
// shortest-form) and nothing else. It parses ANY `new_suite_tag` value so a
// future PQ suite binds by tag alone — the fail-closed suite refusal is a
// VERIFY-time concern (`verify_re_anchor`), never a decode-time one.
// ---------------------------------------------------------------------------

/// An owned, decoded re-anchor record (the structural-decode output).
///
/// Produced by [`decode_re_anchor_v1`]. Borrow it back as a
/// [`SignableReAnchorV1`] via [`ReAnchorRecord::as_signable`] to re-encode
/// or verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReAnchorRecord {
    /// The prior-suite chain head being re-anchored (element [1]).
    pub prior_chain_head_hash: Vec<u8>,
    /// The append sequence of that head (element [2]).
    pub prior_head_sequence: u64,
    /// The suite tag this ceremony enables (element [3]) — retained
    /// verbatim for ANY value, including a suite this binary does not yet
    /// understand.
    pub new_suite_tag: u64,
    /// RFC3339 ceremony timestamp (element [4]).
    pub anchored_at: String,
}

impl ReAnchorRecord {
    /// Borrow this owned record as a [`SignableReAnchorV1`] for re-encoding
    /// or [`verify_re_anchor`].
    #[must_use]
    pub fn as_signable(&self) -> SignableReAnchorV1<'_> {
        SignableReAnchorV1 {
            prior_chain_head_hash: &self.prior_chain_head_hash,
            prior_head_sequence: self.prior_head_sequence,
            new_suite_tag: self.new_suite_tag,
            anchored_at: &self.anchored_at,
        }
    }
}

/// Errors from the structural re-anchor decoder (spec §5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReAnchorDecodeError {
    /// The input ended before a full item could be read.
    Truncated,
    /// An additional-information code was reserved / indefinite-length
    /// (28..=31), which the pinned profile forbids.
    ReservedAdditionalInfo,
    /// An integer / length was not encoded shortest-form (a non-canonical
    /// wide encoding the profile forbids).
    NonMinimalInt,
    /// A major type did not match the profile at this position (e.g. a map
    /// or float where a text / uint / bytes was required).
    WrongMajorType,
    /// The outer array did not carry exactly [`RE_ANCHOR_V1_ELEMENTS`].
    WrongElementCount,
    /// Element [0] was not the frozen [`RE_ANCHOR_V1_DOMAIN`] tag.
    WrongDomainTag,
    /// A text element was not valid UTF-8.
    InvalidUtf8,
    /// Bytes remained after a well-formed record (a trailing-garbage
    /// splice attempt).
    TrailingBytes,
}

impl ReAnchorDecodeError {
    /// Stable machine-readable tag for logs + JSON error envelopes.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Truncated => "re_anchor_decode_truncated",
            Self::ReservedAdditionalInfo => "re_anchor_decode_reserved_ai",
            Self::NonMinimalInt => "re_anchor_decode_non_minimal_int",
            Self::WrongMajorType => "re_anchor_decode_wrong_major_type",
            Self::WrongElementCount => "re_anchor_decode_wrong_element_count",
            Self::WrongDomainTag => "re_anchor_decode_wrong_domain_tag",
            Self::InvalidUtf8 => "re_anchor_decode_invalid_utf8",
            Self::TrailingBytes => "re_anchor_decode_trailing_bytes",
        }
    }
}

impl std::fmt::Display for ReAnchorDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.tag())
    }
}

impl std::error::Error for ReAnchorDecodeError {}

/// CBOR major type 0 — unsigned integer.
const MT_UINT: u8 = 0;
/// CBOR major type 2 — byte string.
const MT_BYTES: u8 = 2;
/// CBOR major type 3 — UTF-8 text string.
const MT_TEXT: u8 = 3;
/// CBOR major type 4 — array.
const MT_ARRAY: u8 = 4;
/// Number of bits a CBOR major type occupies at the top of the head byte.
const MAJOR_SHIFT: u8 = 5;
/// Largest argument value that encodes inline in the low 5 bits (`0..=23`).
const ARG_INLINE_MAX: u64 = 23;

/// Read one CBOR head at `*pos`, returning `(major_type, argument)` and
/// advancing `*pos` past the head. Enforces the pinned profile:
/// definite-length only (rejects additional-info 28..=31) and shortest-form
/// (rejects a wide encoding of a value that fits a narrower one).
fn read_head(buf: &[u8], pos: &mut usize) -> Result<(u8, u64), ReAnchorDecodeError> {
    let head = *buf.get(*pos).ok_or(ReAnchorDecodeError::Truncated)?;
    *pos += 1;
    let major = head >> MAJOR_SHIFT;
    let info = head & 0x1f;
    let take = |pos: &mut usize, n: usize| -> Result<u64, ReAnchorDecodeError> {
        let end = pos.checked_add(n).ok_or(ReAnchorDecodeError::Truncated)?;
        let slice = buf.get(*pos..end).ok_or(ReAnchorDecodeError::Truncated)?;
        let mut val: u64 = 0;
        for &b in slice {
            val = (val << 8) | u64::from(b);
        }
        *pos = end;
        Ok(val)
    };
    let arg = match info {
        0..=23 => u64::from(info),
        24 => {
            let v = take(pos, 1)?;
            if v <= ARG_INLINE_MAX {
                return Err(ReAnchorDecodeError::NonMinimalInt);
            }
            v
        }
        25 => {
            let v = take(pos, 2)?;
            if v <= u64::from(u8::MAX) {
                return Err(ReAnchorDecodeError::NonMinimalInt);
            }
            v
        }
        26 => {
            let v = take(pos, 4)?;
            if v <= u64::from(u16::MAX) {
                return Err(ReAnchorDecodeError::NonMinimalInt);
            }
            v
        }
        27 => {
            let v = take(pos, 8)?;
            if v <= u64::from(u32::MAX) {
                return Err(ReAnchorDecodeError::NonMinimalInt);
            }
            v
        }
        _ => return Err(ReAnchorDecodeError::ReservedAdditionalInfo),
    };
    Ok((major, arg))
}

/// Read a definite-length payload of `len` bytes at `*pos`, advancing past it.
fn read_payload<'a>(
    buf: &'a [u8],
    pos: &mut usize,
    len: u64,
) -> Result<&'a [u8], ReAnchorDecodeError> {
    let len = usize::try_from(len).map_err(|_| ReAnchorDecodeError::Truncated)?;
    let end = pos.checked_add(len).ok_or(ReAnchorDecodeError::Truncated)?;
    let slice = buf.get(*pos..end).ok_or(ReAnchorDecodeError::Truncated)?;
    *pos = end;
    Ok(slice)
}

/// Read a uint element (major type 0) at `*pos`.
fn read_uint(buf: &[u8], pos: &mut usize) -> Result<u64, ReAnchorDecodeError> {
    let (major, arg) = read_head(buf, pos)?;
    if major != MT_UINT {
        return Err(ReAnchorDecodeError::WrongMajorType);
    }
    Ok(arg)
}

/// Structurally decode a `re-anchor/v1` record (spec §5.3).
///
/// Parses the pinned 5-element profile array back into an owned
/// [`ReAnchorRecord`]. It is intentionally **unknown-suite-tolerant**:
/// `new_suite_tag` (element [3]) is read as a bare `u64` and retained
/// verbatim for ANY value, so a record minted under a future PQ suite this
/// binary does not yet understand still decodes — a future suite binds by
/// tag alone. The fail-closed refusal of an unknown suite is a VERIFY-time
/// concern ([`verify_re_anchor`]), never a decode-time one.
///
/// Decode is strict about the WIRE PROFILE (definite-length, shortest-form,
/// exact element count + domain tag, no trailing bytes) so a malformed or
/// spliced encoding is rejected here rather than silently accepted.
///
/// # Errors
///
/// A [`ReAnchorDecodeError`] describing the first profile violation:
/// truncation, a non-minimal / reserved head, a wrong major type or element
/// count, a wrong domain tag, invalid UTF-8, or trailing bytes.
pub fn decode_re_anchor_v1(buf: &[u8]) -> Result<ReAnchorRecord, ReAnchorDecodeError> {
    let mut pos = 0usize;

    // Outer array header — must be exactly RE_ANCHOR_V1_ELEMENTS.
    let (major, count) = read_head(buf, &mut pos)?;
    if major != MT_ARRAY {
        return Err(ReAnchorDecodeError::WrongMajorType);
    }
    if count != RE_ANCHOR_V1_ELEMENTS as u64 {
        return Err(ReAnchorDecodeError::WrongElementCount);
    }

    // [0] domain tag (text) — must equal the frozen discriminator.
    let (m0, l0) = read_head(buf, &mut pos)?;
    if m0 != MT_TEXT {
        return Err(ReAnchorDecodeError::WrongMajorType);
    }
    let domain = read_payload(buf, &mut pos, l0)?;
    if domain != RE_ANCHOR_V1_DOMAIN.as_bytes() {
        return Err(ReAnchorDecodeError::WrongDomainTag);
    }

    // [1] prior_chain_head_hash (bytes).
    let (m1, l1) = read_head(buf, &mut pos)?;
    if m1 != MT_BYTES {
        return Err(ReAnchorDecodeError::WrongMajorType);
    }
    let prior_chain_head_hash = read_payload(buf, &mut pos, l1)?.to_vec();

    // [2] prior_head_sequence (uint).
    let prior_head_sequence = read_uint(buf, &mut pos)?;

    // [3] new_suite_tag (uint) — ANY value, retained verbatim.
    let new_suite_tag = read_uint(buf, &mut pos)?;

    // [4] anchored_at (text, RFC3339).
    let (m4, l4) = read_head(buf, &mut pos)?;
    if m4 != MT_TEXT {
        return Err(ReAnchorDecodeError::WrongMajorType);
    }
    let anchored_at = std::str::from_utf8(read_payload(buf, &mut pos, l4)?)
        .map_err(|_| ReAnchorDecodeError::InvalidUtf8)?
        .to_string();

    if pos != buf.len() {
        return Err(ReAnchorDecodeError::TrailingBytes);
    }

    Ok(ReAnchorRecord {
        prior_chain_head_hash,
        prior_head_sequence,
        new_suite_tag,
        anchored_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::cbor_array::SUITE_ED25519_SHA256;

    fn new_suite_key() -> SigningKey {
        SigningKey::from_bytes(&[0x33; 32])
    }

    fn sample<'a>(head: &'a [u8], ts: &'a str, suite_tag: u64) -> SignableReAnchorV1<'a> {
        SignableReAnchorV1 {
            prior_chain_head_hash: head,
            prior_head_sequence: 4096,
            new_suite_tag: suite_tag,
            anchored_at: ts,
        }
    }

    #[test]
    fn encodes_five_element_domain_tagged_array() {
        let head = [0xAB; 32];
        let enc = canonical_cbor_re_anchor_v1(&sample(
            &head,
            "2026-07-12T00:00:00Z",
            SUITE_ED25519_SHA256,
        ));
        // 5-element array header 0x85 (0x80 | 5).
        assert_eq!(enc[0], 0x85);
        // Element [0] is the 22-byte domain tag: inline-length text head 0x76.
        assert_eq!(enc[1], 0x76);
        assert_eq!(
            &enc[2..2 + RE_ANCHOR_V1_DOMAIN.len()],
            RE_ANCHOR_V1_DOMAIN.as_bytes()
        );
    }

    #[test]
    fn is_deterministic() {
        let head = [0x01; 32];
        let a = canonical_cbor_re_anchor_v1(&sample(
            &head,
            "2026-07-12T00:00:00Z",
            SUITE_ED25519_SHA256,
        ));
        let b = canonical_cbor_re_anchor_v1(&sample(
            &head,
            "2026-07-12T00:00:00Z",
            SUITE_ED25519_SHA256,
        ));
        assert_eq!(
            a, b,
            "re-encode is byte-stable (Ed25519 + R24 precondition)"
        );
    }

    // -- round-trip: sign then verify -----------------------------------

    #[test]
    fn sign_then_verify_round_trips() {
        let key = new_suite_key();
        let head = [0xCD; 32];
        let r = sample(&head, "2026-07-12T00:00:00Z", SUITE_ED25519_SHA256);
        let sig = sign_re_anchor(&key, &r);
        verify_re_anchor(&key.verifying_key(), SuiteId::Ed25519Sha256, &r, &sig)
            .expect("clean countersignature verifies");
    }

    // -- forged reject --------------------------------------------------

    #[test]
    fn verify_rejects_wrong_key() {
        let key = new_suite_key();
        let attacker = SigningKey::from_bytes(&[0x99; 32]);
        let head = [0xCD; 32];
        let r = sample(&head, "2026-07-12T00:00:00Z", SUITE_ED25519_SHA256);
        // Countersigned by the attacker, verified under the real key → reject.
        let sig = sign_re_anchor(&attacker, &r);
        assert_eq!(
            verify_re_anchor(&key.verifying_key(), SuiteId::Ed25519Sha256, &r, &sig),
            Err(ReAnchorError::SignatureInvalid)
        );
    }

    #[test]
    fn verify_rejects_mutated_field() {
        let key = new_suite_key();
        let head = [0xCD; 32];
        let r = sample(&head, "2026-07-12T00:00:00Z", SUITE_ED25519_SHA256);
        let sig = sign_re_anchor(&key, &r);
        // Same signature, a mutated prior_head_sequence → re-encoded bytes
        // differ → strict verify rejects.
        let mutated = SignableReAnchorV1 {
            prior_head_sequence: 4097,
            ..r
        };
        assert_eq!(
            verify_re_anchor(&key.verifying_key(), SuiteId::Ed25519Sha256, &mutated, &sig),
            Err(ReAnchorError::SignatureInvalid)
        );
    }

    #[test]
    fn verify_rejects_malformed_signature() {
        let key = new_suite_key();
        let head = [0xCD; 32];
        let r = sample(&head, "2026-07-12T00:00:00Z", SUITE_ED25519_SHA256);
        assert_eq!(
            verify_re_anchor(&key.verifying_key(), SuiteId::Ed25519Sha256, &r, &[0u8; 10]),
            Err(ReAnchorError::MalformedSignature)
        );
    }

    // -- unknown-suite verify-refusal (fail-closed) ---------------------

    #[test]
    fn verify_fail_closes_on_unknown_suite_before_signature_check() {
        // A record committing an unknown suite tag (999) — even with a
        // perfectly valid countersignature over its own bytes — is REFUSED
        // at the suite cross-check, BEFORE any signature work. The enrolled
        // suite is the sole authority; an unrecognised wire tag is never
        // dispatched onto a guessed verify path (§2.4 anti-`alg`-confusion).
        let key = new_suite_key();
        let head = [0xCD; 32];
        let unknown_tag = 999u64;
        let r = sample(&head, "2026-07-12T00:00:00Z", unknown_tag);
        let sig = sign_re_anchor(&key, &r); // internally valid signature
        assert_eq!(
            verify_re_anchor(&key.verifying_key(), SuiteId::Ed25519Sha256, &r, &sig),
            Err(ReAnchorError::Suite(SuiteError::UnknownTag {
                tag: unknown_tag
            })),
            "unknown suite fail-closes at verify time regardless of a valid signature",
        );
    }

    // -- structural decode of an unknown suite --------------------------

    #[test]
    fn decode_succeeds_structurally_for_unknown_suite() {
        // A record minted under a not-yet-known PQ suite must still DECODE
        // (a future suite binds by tag alone). Decode retains the tag
        // verbatim; only VERIFY fail-closes on it.
        let head = [0x5A; 32];
        let unknown_tag = 0xDEAD_BEEFu64;
        let enc = canonical_cbor_re_anchor_v1(&sample(&head, "2099-01-01T00:00:00Z", unknown_tag));
        let decoded = decode_re_anchor_v1(&enc).expect("unknown-suite record decodes structurally");
        assert_eq!(decoded.new_suite_tag, unknown_tag);
        assert_eq!(decoded.prior_chain_head_hash, head.to_vec());
        assert_eq!(decoded.prior_head_sequence, 4096);
        assert_eq!(decoded.anchored_at, "2099-01-01T00:00:00Z");
    }

    #[test]
    fn decode_round_trips_known_record() {
        let head = [0x77; 32];
        let r = sample(&head, "2026-07-12T00:00:00Z", SUITE_ED25519_SHA256);
        let enc = canonical_cbor_re_anchor_v1(&r);
        let decoded = decode_re_anchor_v1(&enc).expect("known record decodes");
        // Re-encoding the decoded record reproduces the exact bytes.
        assert_eq!(canonical_cbor_re_anchor_v1(&decoded.as_signable()), enc);
    }

    #[test]
    fn decoded_unknown_suite_still_fail_closes_on_verify() {
        // End-to-end of the two properties together: decode structurally,
        // then verify — verify fail-closes on the unknown suite.
        let key = new_suite_key();
        let unknown_tag = 42u64;
        let head = [0x5A; 32];
        let r = sample(&head, "2099-01-01T00:00:00Z", unknown_tag);
        let enc = canonical_cbor_re_anchor_v1(&r);
        let sig = sign_re_anchor(&key, &r);
        let decoded = decode_re_anchor_v1(&enc).expect("decodes");
        assert_eq!(
            verify_re_anchor(
                &key.verifying_key(),
                SuiteId::Ed25519Sha256,
                &decoded.as_signable(),
                &sig,
            ),
            Err(ReAnchorError::Suite(SuiteError::UnknownTag {
                tag: unknown_tag
            })),
        );
    }

    #[test]
    fn decode_rejects_wrong_domain_tag() {
        // Splice a different-but-well-formed 5-element array whose element
        // [0] is not the re-anchor domain → WrongDomainTag.
        let head = [0x01; 32];
        let write_v2_ish = CborItem::Array(vec![
            CborItem::Text("ai-memory/write/v2"),
            CborItem::Bytes(&head),
            CborItem::Uint(1),
            CborItem::Uint(0),
            CborItem::Text("2026-07-12T00:00:00Z"),
        ]);
        let enc = encode(&write_v2_ish);
        assert_eq!(
            decode_re_anchor_v1(&enc),
            Err(ReAnchorDecodeError::WrongDomainTag)
        );
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let head = [0x01; 32];
        let mut enc = canonical_cbor_re_anchor_v1(&sample(
            &head,
            "2026-07-12T00:00:00Z",
            SUITE_ED25519_SHA256,
        ));
        enc.push(0x00); // a trailing-garbage splice
        assert_eq!(
            decode_re_anchor_v1(&enc),
            Err(ReAnchorDecodeError::TrailingBytes)
        );
    }

    #[test]
    fn decode_rejects_wrong_element_count() {
        // A 4-element array (missing anchored_at) → WrongElementCount.
        let head = [0x01; 32];
        let short = CborItem::Array(vec![
            CborItem::Text(RE_ANCHOR_V1_DOMAIN),
            CborItem::Bytes(&head),
            CborItem::Uint(1),
            CborItem::Uint(0),
        ]);
        let enc = encode(&short);
        assert_eq!(
            decode_re_anchor_v1(&enc),
            Err(ReAnchorDecodeError::WrongElementCount)
        );
    }

    #[test]
    fn decode_rejects_truncated_input() {
        let head = [0x01; 32];
        let enc = canonical_cbor_re_anchor_v1(&sample(
            &head,
            "2026-07-12T00:00:00Z",
            SUITE_ED25519_SHA256,
        ));
        // Chop the last byte of the timestamp payload.
        assert_eq!(
            decode_re_anchor_v1(&enc[..enc.len() - 1]),
            Err(ReAnchorDecodeError::Truncated)
        );
    }

    #[test]
    fn error_tags_are_stable() {
        assert_eq!(
            ReAnchorError::Suite(SuiteError::UnknownTag { tag: 9 }).tag(),
            "suite_unknown_tag"
        );
        assert_eq!(
            ReAnchorError::MalformedSignature.tag(),
            "re_anchor_malformed_signature"
        );
        assert_eq!(
            ReAnchorError::SignatureInvalid.tag(),
            "re_anchor_signature_invalid"
        );
        assert_eq!(
            ReAnchorDecodeError::WrongDomainTag.tag(),
            "re_anchor_decode_wrong_domain_tag"
        );
    }
}
