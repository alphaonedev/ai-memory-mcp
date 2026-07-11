// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Instance sub-key certification for the v1.0.0 crypto-core
//! (#1942, epic #1940, spec §2.3).
//!
//! Every v2 write is signed by a **per-instance sub-key**, itself
//! certified by the principal identity root via a [`SubkeyCert`] — a
//! principal-root-signed, domain-tagged CBOR **array** record (own
//! domain `"ai-memory/subkey-cert/v1"`) binding `{principal,
//! instance_key_id, model_version_ref, not_before, not_after}`. This is
//! the "certified, not self-declared" instance-identity requirement (R2).
//!
//! # Verify order (mandatory, spec §2.3 / §7 step 3)
//!
//! Verification is a two-link chain, checked in a FIXED order:
//! 1. verify the [`SubkeyCert`] under the **principal root** key, THEN
//! 2. verify the write under the **sub-key**.
//!
//! A self-declared instance stamp with **no valid cert** is REJECTED:
//! [`verify_write_under_certified_subkey`] requires a cert that verifies
//! under the enrolled principal root, so a write that merely asserts an
//! `instance_key_id` with no root-signed cert (or a cert signed by any
//! key other than the enrolled root) cannot pass.
//!
//! # Reuse of the federation credential-chain machinery (spec §2.3 ask)
//!
//! The [`crate::federation::identity::credential::FederationCredential`]
//! subject→issuer→validity→sign/verify shape is the right *pattern*, and
//! this module reuses its `ed25519_dalek` type choices and its
//! `verify_strict` posture. It deliberately does **not** reuse its CBOR
//! **map** claim encoding: the v2 spec (§1) mandates the pinned,
//! domain-tagged CBOR **array** grammar (the stage-1
//! [`crate::identity::cbor_array`] encoder) so the RFC 8949 key-ordering
//! ambiguity cannot fire and the bytes are golden-vector-pinned. Hence
//! the cert is encoded through the stage-1 array encoder, not
//! `canonical_claims_bytes`.
//!
//! # Scope (crypto-core stage 2)
//!
//! Pure functions + the record type + golden vectors ONLY. This module
//! does NOT wire into the live store / ingest / receive paths — that is
//! stage 3. `instance_key_id` is interpreted as the sub-key's raw
//! Ed25519 verifying-key bytes so the cert→write chain is fully
//! offline-verifiable from the artifacts alone (resolves the spec's
//! `TBD-impl` on the id's concrete form — the frozen field SET stays as
//! §2.3 specifies).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::identity::cbor_array::{CborItem, SUBKEY_CERT_V1_DOMAIN, encode};

/// The number of positional elements in a `SubkeyCert` v1 array.
///
/// `[domain, principal, instance_key_id, model_version_ref, not_before,
/// not_after]` — the domain tag (element [0]) plus the five frozen bound
/// fields of spec §2.3.
pub const SUBKEY_CERT_ELEMENTS: usize = 6;

/// Length of an Ed25519 signature in bytes.
const SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// The principal-root-signed instance sub-key certificate (spec §2.3).
///
/// Borrowed, encoder-facing view: the fields are exactly the bound set
/// the principal root attests to. `instance_key_id` is the per-instance
/// sub-key's raw Ed25519 verifying-key bytes (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubkeyCert<'a> {
    /// The principal identity the sub-key acts on behalf of (element [1]).
    pub principal: &'a str,
    /// The certified per-instance sub-key: its raw Ed25519 verifying-key
    /// bytes (element [2]).
    pub instance_key_id: &'a [u8],
    /// Model-version reference bound at certification time: a `b3` cid of
    /// the model attestation, or a weights-hash / version-vector under
    /// continual learning (element [3]).
    pub model_version_ref: &'a [u8],
    /// RFC3339 instant the cert becomes valid (element [4]).
    pub not_before: &'a str,
    /// RFC3339 instant the cert expires (element [5]).
    pub not_after: &'a str,
}

/// Encode a [`SubkeyCert`] to its canonical, profile-restricted signed
/// bytes: the frozen 6-element positional array of spec §2.3, via the
/// stage-1 pinned array encoder.
///
/// These are the exact bytes the principal root's Ed25519 signature is
/// computed over; the golden-vector corpus
/// (`tests/golden/subkey_cert/`) pins the output of this function as a
/// hard CI gate.
#[must_use]
pub fn canonical_cbor_subkey_cert(cert: &SubkeyCert<'_>) -> Vec<u8> {
    let array = CborItem::Array(vec![
        CborItem::Text(SUBKEY_CERT_V1_DOMAIN),   // [0] _dst
        CborItem::Text(cert.principal),          // [1]
        CborItem::Bytes(cert.instance_key_id),   // [2]
        CborItem::Bytes(cert.model_version_ref), // [3]
        CborItem::Text(cert.not_before),         // [4]
        CborItem::Text(cert.not_after),          // [5]
    ]);
    debug_assert!(
        matches!(&array, CborItem::Array(v) if v.len() == SUBKEY_CERT_ELEMENTS),
        "SubkeyCert must encode exactly {SUBKEY_CERT_ELEMENTS} elements",
    );
    encode(&array)
}

/// Sign a [`SubkeyCert`] with the **principal root** signing key,
/// returning the raw 64-byte Ed25519 signature over its canonical bytes.
#[must_use]
pub fn sign_subkey_cert(principal_root: &SigningKey, cert: &SubkeyCert<'_>) -> [u8; SIGNATURE_LEN] {
    let bytes = canonical_cbor_subkey_cert(cert);
    let sig: Signature = principal_root.sign(&bytes);
    sig.to_bytes()
}

/// Errors from the sub-key certification chain (spec §2.3).
///
/// The verifier's inbound posture is "reject"; the distinct variants are
/// for logs / audit envelopes, not for leaking which check failed to a
/// misbehaving peer (the [`crate::identity::verify::VerifyError`]
/// precedent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubkeyCertError {
    /// A signature was not exactly 64 bytes.
    MalformedSignature,
    /// The `SubkeyCert` signature did not verify under the principal
    /// root key (link 1 of the chain) — includes the self-declared case
    /// (a cert signed by any key other than the enrolled root).
    CertInvalid,
    /// `instance_key_id` is not a valid Ed25519 verifying key (32 bytes,
    /// on-curve), so no sub-key is available to verify the write under.
    MalformedInstanceKey,
    /// The write's claimed `instance_key_id` does not match the one the
    /// cert certifies — the write is not covered by this cert.
    InstanceMismatch,
    /// The write signature did not verify under the certified sub-key
    /// (link 2 of the chain).
    WriteInvalid,
    /// `now` is outside `[not_before, not_after]`, or a validity bound is
    /// not parseable RFC3339 (fail-closed).
    OutsideValidity,
}

impl SubkeyCertError {
    /// Stable machine-readable tag for logs + JSON error envelopes.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::MalformedSignature => "subkey_cert_malformed_signature",
            Self::CertInvalid => "subkey_cert_cert_invalid",
            Self::MalformedInstanceKey => "subkey_cert_malformed_instance_key",
            Self::InstanceMismatch => "subkey_cert_instance_mismatch",
            Self::WriteInvalid => "subkey_cert_write_invalid",
            Self::OutsideValidity => "subkey_cert_outside_validity",
        }
    }
}

impl std::fmt::Display for SubkeyCertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.tag())
    }
}

impl std::error::Error for SubkeyCertError {}

/// Decode a raw signature slice into a strict Ed25519 [`Signature`].
fn parse_signature(signature: &[u8]) -> Result<Signature, SubkeyCertError> {
    if signature.len() != SIGNATURE_LEN {
        return Err(SubkeyCertError::MalformedSignature);
    }
    let mut arr = [0u8; SIGNATURE_LEN];
    arr.copy_from_slice(signature);
    Ok(Signature::from_bytes(&arr))
}

/// Verify a [`SubkeyCert`] under the **principal root** verifying key
/// (link 1 of the chain, spec §2.3).
///
/// Re-encodes the cert via the pinned §2.3 array profile and checks the
/// signature with `verify_strict` (rejecting malleable / non-canonical
/// signatures, matching the v0.8.0 Pillar-1 verifiers).
///
/// # Errors
///
/// - [`SubkeyCertError::MalformedSignature`] — signature not 64 bytes.
/// - [`SubkeyCertError::CertInvalid`] — signature does not validate under
///   `principal_root` over the canonical cert bytes (wrong/attacker key,
///   flipped byte, or a mutated field).
pub fn verify_subkey_cert(
    principal_root: &VerifyingKey,
    cert: &SubkeyCert<'_>,
    signature: &[u8],
) -> Result<(), SubkeyCertError> {
    let sig = parse_signature(signature)?;
    let bytes = canonical_cbor_subkey_cert(cert);
    principal_root
        .verify_strict(&bytes, &sig)
        .map_err(|_| SubkeyCertError::CertInvalid)
}

/// Check a [`SubkeyCert`]'s validity window against `now` (both RFC3339).
///
/// Fail-closed: an unparseable bound is treated as outside-validity.
/// Kept SEPARATE from the cryptographic chain in
/// [`verify_write_under_certified_subkey`] so the R24 core chain stays
/// clock-free and deterministic; stage-3 wiring supplies the clock.
///
/// # Errors
///
/// [`SubkeyCertError::OutsideValidity`] when `now < not_before`,
/// `now > not_after`, or any of the three timestamps is not RFC3339.
pub fn check_validity(cert: &SubkeyCert<'_>, now_rfc3339: &str) -> Result<(), SubkeyCertError> {
    let parse = |s: &str| chrono::DateTime::parse_from_rfc3339(s);
    match (
        parse(cert.not_before),
        parse(now_rfc3339),
        parse(cert.not_after),
    ) {
        (Ok(nb), Ok(now), Ok(na)) if now >= nb && now <= na => Ok(()),
        _ => Err(SubkeyCertError::OutsideValidity),
    }
}

/// Verify a write under a root-certified sub-key: the FULL two-link chain
/// of spec §2.3 / §7 step 3, in the mandatory order.
///
/// 1. verify the [`SubkeyCert`] under `principal_root` (cert-under-root),
/// 2. cross-check the write's claimed `write_instance_key_id` equals the
///    cert's certified `instance_key_id`,
/// 3. derive the sub-key verifying key from that id, and
/// 4. verify `write_signature` over `write_signed_bytes` under the
///    sub-key (write-under-subkey).
///
/// A self-declared instance (no root-signed cert) cannot pass: step 1
/// fails for any cert not signed by the enrolled root. The validity
/// window is checked separately via [`check_validity`] (this function is
/// intentionally clock-free — the R24 offline-verifier core).
///
/// `write_signed_bytes` is the canonical v2 write pre-image (e.g. the
/// output of [`crate::identity::cbor_array::canonical_cbor_write_v2`]),
/// NOT decoded-and-trusted — the caller re-encodes and this function
/// checks the signature over those exact bytes.
///
/// # Errors
///
/// The first failing [`SubkeyCertError`] in chain order — the walk is
/// fail-closed and never falls back to a partially-verified state.
pub fn verify_write_under_certified_subkey(
    principal_root: &VerifyingKey,
    cert: &SubkeyCert<'_>,
    cert_signature: &[u8],
    write_instance_key_id: &[u8],
    write_signed_bytes: &[u8],
    write_signature: &[u8],
) -> Result<(), SubkeyCertError> {
    // Link 1 (FIRST): the cert must verify under the principal root.
    verify_subkey_cert(principal_root, cert, cert_signature)?;

    // The write must claim the exact sub-key this cert certifies.
    if write_instance_key_id != cert.instance_key_id {
        return Err(SubkeyCertError::InstanceMismatch);
    }

    // Derive the sub-key verifying key from the certified id (raw
    // Ed25519 verifying-key bytes).
    let subkey = decode_verifying_key(cert.instance_key_id)?;

    // Link 2 (SECOND): the write must verify under the certified sub-key.
    let sig = parse_signature(write_signature)?;
    subkey
        .verify_strict(write_signed_bytes, &sig)
        .map_err(|_| SubkeyCertError::WriteInvalid)
}

/// Decode raw bytes into an Ed25519 [`VerifyingKey`], fail-closing on a
/// wrong length or an off-curve point.
fn decode_verifying_key(bytes: &[u8]) -> Result<VerifyingKey, SubkeyCertError> {
    let arr: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = bytes
        .try_into()
        .map_err(|_| SubkeyCertError::MalformedInstanceKey)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| SubkeyCertError::MalformedInstanceKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::cbor_array::{
        HashCodec, Multihash, SUITE_ED25519_SHA256, SignableWriteV2, canonical_cbor_write_v2,
    };

    fn root_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn subkey() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }

    fn sample_cert(instance_key_id: &[u8]) -> SubkeyCert<'_> {
        SubkeyCert {
            principal: "ai:claude-code@pop-os",
            instance_key_id,
            model_version_ref: &[0xab; 32],
            not_before: "2026-07-11T00:00:00Z",
            not_after: "2027-07-11T00:00:00Z",
        }
    }

    #[test]
    fn cert_encodes_six_element_domain_tagged_array() {
        let sk = subkey();
        let id = sk.verifying_key().to_bytes();
        let enc = canonical_cbor_subkey_cert(&sample_cert(&id));
        // 6-element array header 0x86 (0x80 | 6).
        assert_eq!(enc[0], 0x86);
        // Element [0] is the 24-byte domain tag: header 0x78 0x18.
        assert_eq!(&enc[1..3], &[0x78, 0x18]);
        assert_eq!(
            &enc[3..3 + SUBKEY_CERT_V1_DOMAIN.len()],
            SUBKEY_CERT_V1_DOMAIN.as_bytes()
        );
    }

    #[test]
    fn cert_sign_then_verify_round_trips() {
        let root = root_key();
        let sk = subkey();
        let id = sk.verifying_key().to_bytes();
        let cert = sample_cert(&id);
        let sig = sign_subkey_cert(&root, &cert);
        verify_subkey_cert(&root.verifying_key(), &cert, &sig).expect("clean cert verifies");
    }

    #[test]
    fn cert_verify_rejects_wrong_root() {
        let root = root_key();
        let attacker = SigningKey::from_bytes(&[0x99; 32]);
        let sk = subkey();
        let id = sk.verifying_key().to_bytes();
        let cert = sample_cert(&id);
        // Signed by the attacker, verified under the real root → reject.
        let sig = sign_subkey_cert(&attacker, &cert);
        assert_eq!(
            verify_subkey_cert(&root.verifying_key(), &cert, &sig),
            Err(SubkeyCertError::CertInvalid)
        );
    }

    #[test]
    fn cert_verify_rejects_mutated_field() {
        let root = root_key();
        let sk = subkey();
        let id = sk.verifying_key().to_bytes();
        let cert = sample_cert(&id);
        let sig = sign_subkey_cert(&root, &cert);
        // Same signature, a mutated principal → the re-encoded bytes
        // differ → strict verify rejects.
        let mut mutated = cert.clone();
        mutated.principal = "ai:evil@pop-os";
        assert_eq!(
            verify_subkey_cert(&root.verifying_key(), &mutated, &sig),
            Err(SubkeyCertError::CertInvalid)
        );
    }

    #[test]
    fn cert_verify_rejects_malformed_signature() {
        let root = root_key();
        let sk = subkey();
        let id = sk.verifying_key().to_bytes();
        assert_eq!(
            verify_subkey_cert(&root.verifying_key(), &sample_cert(&id), &[0u8; 10]),
            Err(SubkeyCertError::MalformedSignature)
        );
    }

    /// Build a canonical v2 write pre-image + its sub-key signature.
    fn signed_write(sk: &SigningKey, id: &[u8; 32]) -> (Vec<u8>, [u8; SIGNATURE_LEN]) {
        let digest = Multihash::new(HashCodec::Sha2_256, [0x33; 32]);
        let w = SignableWriteV2 {
            agent_id: "ai:claude-code@pop-os",
            namespace: "global",
            title: "t",
            kind: "instruction",
            created_at: "2026-07-11T00:00:00Z",
            content_digest: digest,
            instance_key_id: id,
            model_version_ref: &[0xab; 32],
            session_id: None,
            suite_tag: SUITE_ED25519_SHA256,
        };
        let bytes = canonical_cbor_write_v2(&w);
        let sig: Signature = sk.sign(&bytes);
        (bytes, sig.to_bytes())
    }

    #[test]
    fn full_chain_verifies_cert_then_write() {
        let root = root_key();
        let sk = subkey();
        let id = sk.verifying_key().to_bytes();
        let cert = sample_cert(&id);
        let cert_sig = sign_subkey_cert(&root, &cert);
        let (write_bytes, write_sig) = signed_write(&sk, &id);

        verify_write_under_certified_subkey(
            &root.verifying_key(),
            &cert,
            &cert_sig,
            &id,
            &write_bytes,
            &write_sig,
        )
        .expect("clean cert→write chain verifies");
    }

    #[test]
    fn full_chain_rejects_self_declared_instance_no_valid_cert() {
        // "Self-declared": an attacker forges a cert binding their OWN
        // sub-key, signed by a non-root key. Link 1 (cert-under-root)
        // fails, so the write is rejected even though its own signature is
        // internally consistent — exactly the R2 "certified, not
        // self-declared" property.
        let root = root_key();
        let attacker_root = SigningKey::from_bytes(&[0x77; 32]);
        let sk = subkey();
        let id = sk.verifying_key().to_bytes();
        let cert = sample_cert(&id);
        let forged_cert_sig = sign_subkey_cert(&attacker_root, &cert);
        let (write_bytes, write_sig) = signed_write(&sk, &id);

        assert_eq!(
            verify_write_under_certified_subkey(
                &root.verifying_key(),
                &cert,
                &forged_cert_sig,
                &id,
                &write_bytes,
                &write_sig,
            ),
            Err(SubkeyCertError::CertInvalid),
            "cert-under-root is checked FIRST and rejects the self-declared instance"
        );
    }

    #[test]
    fn full_chain_rejects_write_instance_mismatch() {
        let root = root_key();
        let sk = subkey();
        let id = sk.verifying_key().to_bytes();
        let cert = sample_cert(&id);
        let cert_sig = sign_subkey_cert(&root, &cert);
        let (write_bytes, write_sig) = signed_write(&sk, &id);

        // The write claims a DIFFERENT instance id than the cert certifies.
        let other_id = [0x44u8; 32];
        assert_eq!(
            verify_write_under_certified_subkey(
                &root.verifying_key(),
                &cert,
                &cert_sig,
                &other_id,
                &write_bytes,
                &write_sig,
            ),
            Err(SubkeyCertError::InstanceMismatch)
        );
    }

    #[test]
    fn full_chain_rejects_write_signed_by_uncertified_key() {
        let root = root_key();
        let sk = subkey();
        let id = sk.verifying_key().to_bytes();
        let cert = sample_cert(&id);
        let cert_sig = sign_subkey_cert(&root, &cert);
        // Write signed by a DIFFERENT key than the certified sub-key, but
        // still claiming the certified id → link 2 (write-under-subkey)
        // rejects.
        let impostor = SigningKey::from_bytes(&[0x55; 32]);
        let (write_bytes, write_sig) = signed_write(&impostor, &id);

        assert_eq!(
            verify_write_under_certified_subkey(
                &root.verifying_key(),
                &cert,
                &cert_sig,
                &id,
                &write_bytes,
                &write_sig,
            ),
            Err(SubkeyCertError::WriteInvalid)
        );
    }

    #[test]
    fn full_chain_rejects_malformed_instance_key() {
        let root = root_key();
        // instance_key_id is not 32 bytes → cannot be a verifying key.
        let bad_id: &[u8] = &[0x01, 0x02, 0x03];
        let cert = sample_cert(bad_id);
        let cert_sig = sign_subkey_cert(&root, &cert);
        assert_eq!(
            verify_write_under_certified_subkey(
                &root.verifying_key(),
                &cert,
                &cert_sig,
                bad_id,
                b"whatever",
                &[0u8; SIGNATURE_LEN],
            ),
            Err(SubkeyCertError::MalformedInstanceKey)
        );
    }

    #[test]
    fn validity_window_accepts_inside_rejects_outside() {
        let sk = subkey();
        let id = sk.verifying_key().to_bytes();
        let cert = sample_cert(&id);
        check_validity(&cert, "2026-12-01T00:00:00Z").expect("inside the window");
        assert_eq!(
            check_validity(&cert, "2020-01-01T00:00:00Z"),
            Err(SubkeyCertError::OutsideValidity),
            "before not_before"
        );
        assert_eq!(
            check_validity(&cert, "2030-01-01T00:00:00Z"),
            Err(SubkeyCertError::OutsideValidity),
            "after not_after"
        );
        assert_eq!(
            check_validity(&cert, "not-a-timestamp"),
            Err(SubkeyCertError::OutsideValidity),
            "unparseable now fails closed"
        );
    }
}
