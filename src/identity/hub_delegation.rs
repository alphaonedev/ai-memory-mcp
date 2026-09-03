// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Scoped `a2a-hub/join/v1` delegation (issue
//! [#3468](https://github.com/alphaonedev/ai-memory-mcp/issues/3468), EPIC
//! [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466)).
//!
//! A delegation is a short-lived certificate, minted by an agent's ENROLLED
//! key, that authorises exactly one thing: presenting a hello to one named
//! `ai-memory wake-hub` as that agent. It authorises nothing else — not a
//! write, not a link, not a lineage record.
//!
//! # Why this is not a `SubkeyCert`
//!
//! [`crate::identity::subkey_cert`] already has a certificate shape, and reusing
//! it would be the obvious move. The EPIC forbids it, and the reason is
//! structural rather than stylistic:
//!
//! 1. **A `SubkeyCert` has no scope element.** Its frozen six-element array is
//!    `{principal, instance_key_id, model_version_ref, not_before, not_after}`.
//!    Nothing in it says what the sub-key may DO; the authority is carried
//!    entirely by the domain tag.
//! 2. **That tag already means "may mint `agent_attested` writes."**
//!    [`crate::identity::subkey_cert::verify_write_under_certified_subkey`] is
//!    the ingest chain: any key holding a valid `ai-memory/subkey-cert/v1` cert
//!    under the enrolled root can sign v2 writes and have them stamped with the
//!    strongest provenance claim the substrate makes.
//! 3. **So a hub-join credential under that domain would be a write
//!    credential.** A hub session key lives in a long-running listener on a
//!    shared host. Certifying it under the write domain would turn a compromise
//!    of a wake LISTENER — a process that by design carries no message bodies —
//!    into forged `agent_attested` history. That is an escalation from "may be
//!    woken" to "may write this agent's past", and it is exactly the durable
//!    data-integrity breach the North Star puts above everything else.
//! 4. **Replay would run both ways.** One shared domain means a delegation
//!    harvested off the hub's socket verifies as a write cert, and a write cert
//!    admits a hub join.
//! 5. **The lifetimes are incompatible.** Write certs run for months; this
//!    delegation is deliberately short because the hub holds only a derived
//!    cache and performs no live revocation lookup — expiry IS the revocation
//!    mechanism, backed by an audit-spine event.
//! 6. **Revocation would be coupled.** `subkey_is_revoked` is keyed on
//!    `(principal, instance_key_id)`, so revoking a leaked hub key would also
//!    kill that key's write authority, and vice versa — two independent
//!    decisions welded into one.
//!
//! So this is a NEW domain with an explicit scope element and a bounded TTL.
//!
//! # Shape
//!
//! The same canon as `subkey_cert`: a domain-tagged, POSITIONAL CBOR array
//! (never a map, so RFC 8949 key-ordering ambiguity cannot fire), encoded
//! through the pinned stage-1 [`crate::identity::cbor_array`] encoder.
//!
//! ```text
//! [ "ai-memory/a2a-hub-join/v1",  // [0] domain
//!   principal,                    // [1] the enrolled agent id
//!   scope,                        // [2] "a2a-hub" — explicit, not implied
//!   delegate_key_id,              // [3] the hello key this authorises
//!   hub_id,                       // [4] ONE hub; not portable across hubs
//!   not_before,                   // [5] RFC3339
//!   not_after ]                   // [6] RFC3339, bounded by MAX_DELEGATION_TTL_SECS
//! ```
//!
//! Verification is CLOCK-FREE ([`verify_hub_delegation`]) and validity is a
//! separate step ([`check_validity`]), so the cryptographic core stays
//! deterministic and the caller supplies `now` — the same split
//! `subkey_cert` uses.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::cbor_array::{A2A_HUB_JOIN_V1_DOMAIN, CborItem, encode};

/// Element count of the signed array. Named so the vendor / literal gates have
/// one definition site, mirroring `SUBKEY_CERT_ELEMENTS`.
pub const HUB_DELEGATION_ELEMENTS: usize = 7;

/// The only scope this domain admits. A delegation carrying anything else is
/// refused: the scope element exists to be CHECKED, not merely recorded.
pub const A2A_HUB_SCOPE: &str = "a2a-hub";

/// Longest delegation lifetime, in seconds (12 hours).
///
/// The hub performs no live revocation lookup — it holds a derived cache and
/// only public material. Expiry therefore IS the revocation mechanism, so a
/// long-lived delegation would be an un-revocable credential. A minter that
/// asks for more is refused rather than silently clamped: an operator who
/// believes they minted a week-long credential must not be wrong about it.
pub const MAX_DELEGATION_TTL_SECS: i64 = 12 * 60 * 60;

/// Maximum byte length of the `principal` element (ai-memory ids go to 128).
pub const MAX_PRINCIPAL_BYTES: usize = 128;

/// Maximum byte length of the `hub_id` element.
pub const MAX_HUB_ID_BYTES: usize = 64;

/// Maximum byte length of the `scope` element.
pub const MAX_SCOPE_BYTES: usize = 32;

/// Maximum byte length of an RFC3339 timestamp element.
pub const MAX_TIMESTAMP_BYTES: usize = 32;

/// Length of an Ed25519 key id, in bytes.
pub const DELEGATE_KEY_ID_BYTES: usize = 32;

/// A scoped hub-join delegation, borrowed for signing and verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubDelegation<'a> {
    /// The enrolled agent this delegation speaks for.
    pub principal: &'a str,
    /// Must equal [`A2A_HUB_SCOPE`].
    pub scope: &'a str,
    /// Raw Ed25519 verifying-key bytes of the delegated hello key.
    pub delegate_key_id: &'a [u8],
    /// The one hub this delegation is valid at.
    pub hub_id: &'a str,
    /// RFC3339 start of the validity window, inclusive.
    pub not_before: &'a str,
    /// RFC3339 end of the validity window, exclusive.
    pub not_after: &'a str,
}

/// Every way a delegation can be refused.
///
/// Distinct variants exist for LOGS. The wire answer is a single
/// `401 unauthorized` (see `crate::wake_hub::identity::DenyReason`), so a peer
/// cannot learn which check failed by probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubDelegationError {
    /// The signature was not 64 bytes, or was not canonical.
    MalformedSignature,
    /// The signature did not verify under the enrolled key.
    DelegationInvalid,
    /// `delegate_key_id` was not a valid Ed25519 verifying key.
    MalformedDelegateKey,
    /// The scope element was not [`A2A_HUB_SCOPE`].
    ScopeMismatch,
    /// An element exceeded its byte bound, or `principal` was empty.
    MalformedElement,
    /// `now` is outside `[not_before, not_after)`, or a timestamp did not parse.
    OutsideValidity,
    /// The requested window is longer than [`MAX_DELEGATION_TTL_SECS`].
    TtlTooLong,
}

impl HubDelegationError {
    /// Stable label for logs and metrics.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::MalformedSignature => "hub_delegation_malformed_signature",
            Self::DelegationInvalid => "hub_delegation_invalid",
            Self::MalformedDelegateKey => "hub_delegation_malformed_delegate_key",
            Self::ScopeMismatch => "hub_delegation_scope_mismatch",
            Self::MalformedElement => "hub_delegation_malformed_element",
            Self::OutsideValidity => "hub_delegation_outside_validity",
            Self::TtlTooLong => "hub_delegation_ttl_too_long",
        }
    }
}

impl std::fmt::Display for HubDelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::MalformedSignature => "delegation signature is malformed",
            Self::DelegationInvalid => "delegation signature did not verify under the enrolled key",
            Self::MalformedDelegateKey => "delegated key is not a valid Ed25519 key",
            Self::ScopeMismatch => "delegation scope is not a2a-hub",
            Self::MalformedElement => "a delegation element was empty or over-long",
            Self::OutsideValidity => "delegation is outside its validity window",
            Self::TtlTooLong => "delegation window exceeds the maximum lifetime",
        };
        f.write_str(text)
    }
}

impl std::error::Error for HubDelegationError {}

/// Bound-check every element before it is signed or verified.
///
/// Runs on BOTH paths so the minter cannot produce a delegation the verifier
/// would refuse, and the verifier never hashes an unbounded peer-supplied
/// element.
///
/// # Errors
///
/// [`HubDelegationError::MalformedElement`] for an empty or over-long element,
/// [`HubDelegationError::ScopeMismatch`] for a foreign scope,
/// [`HubDelegationError::MalformedDelegateKey`] for a wrong-length key id.
pub fn check_elements(delegation: &HubDelegation<'_>) -> Result<(), HubDelegationError> {
    if delegation.scope != A2A_HUB_SCOPE || delegation.scope.len() > MAX_SCOPE_BYTES {
        return Err(HubDelegationError::ScopeMismatch);
    }
    if delegation.principal.is_empty()
        || delegation.principal.len() > MAX_PRINCIPAL_BYTES
        || delegation.hub_id.is_empty()
        || delegation.hub_id.len() > MAX_HUB_ID_BYTES
        || delegation.not_before.is_empty()
        || delegation.not_before.len() > MAX_TIMESTAMP_BYTES
        || delegation.not_after.is_empty()
        || delegation.not_after.len() > MAX_TIMESTAMP_BYTES
    {
        return Err(HubDelegationError::MalformedElement);
    }
    if delegation.delegate_key_id.len() != DELEGATE_KEY_ID_BYTES {
        return Err(HubDelegationError::MalformedDelegateKey);
    }
    Ok(())
}

/// The exact bytes a delegation signature covers.
///
/// # Panics
///
/// Never; the `debug_assert` documents the element-count invariant.
#[must_use]
pub fn canonical_cbor_hub_delegation(delegation: &HubDelegation<'_>) -> Vec<u8> {
    let array = CborItem::Array(vec![
        CborItem::Text(A2A_HUB_JOIN_V1_DOMAIN),      // [0] domain
        CborItem::Text(delegation.principal),        // [1]
        CborItem::Text(delegation.scope),            // [2]
        CborItem::Bytes(delegation.delegate_key_id), // [3]
        CborItem::Text(delegation.hub_id),           // [4]
        CborItem::Text(delegation.not_before),       // [5]
        CborItem::Text(delegation.not_after),        // [6]
    ]);
    debug_assert!(
        matches!(&array, CborItem::Array(v) if v.len() == HUB_DELEGATION_ELEMENTS),
        "HubDelegation must encode exactly {HUB_DELEGATION_ELEMENTS} elements",
    );
    encode(&array)
}

/// Mint a delegation with the agent's ENROLLED signing key.
///
/// # Errors
///
/// Propagates [`check_elements`]. The window bound is the caller's to enforce
/// via [`check_ttl`] — kept separate so this stays clock-free.
pub fn sign_hub_delegation(
    enrolled_root: &SigningKey,
    delegation: &HubDelegation<'_>,
) -> Result<[u8; 64], HubDelegationError> {
    check_elements(delegation)?;
    let bytes = canonical_cbor_hub_delegation(delegation);
    Ok(enrolled_root.sign(&bytes).to_bytes())
}

/// Verify a delegation against the enrolled key. CLOCK-FREE — pair it with
/// [`check_validity`].
///
/// Uses `verify_strict`, matching every certificate verifier in this tree: it
/// rejects small-order and non-canonical signatures that the permissive
/// `verify` would admit.
///
/// # Errors
///
/// Any [`HubDelegationError`] from the element bounds, the signature encoding,
/// or the signature check itself.
pub fn verify_hub_delegation(
    enrolled_root: &VerifyingKey,
    delegation: &HubDelegation<'_>,
    signature: &[u8],
) -> Result<(), HubDelegationError> {
    check_elements(delegation)?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| HubDelegationError::MalformedSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let bytes = canonical_cbor_hub_delegation(delegation);
    enrolled_root
        .verify_strict(&bytes, &signature)
        .map_err(|_| HubDelegationError::DelegationInvalid)
}

/// Refuse a window longer than [`MAX_DELEGATION_TTL_SECS`].
///
/// # Errors
///
/// [`HubDelegationError::OutsideValidity`] when either timestamp does not parse
/// or the window is inverted, [`HubDelegationError::TtlTooLong`] when it is
/// longer than the maximum.
pub fn check_ttl(delegation: &HubDelegation<'_>) -> Result<(), HubDelegationError> {
    let start = parse_rfc3339(delegation.not_before)?;
    let end = parse_rfc3339(delegation.not_after)?;
    if end <= start {
        return Err(HubDelegationError::OutsideValidity);
    }
    if (end - start).num_seconds() > MAX_DELEGATION_TTL_SECS {
        return Err(HubDelegationError::TtlTooLong);
    }
    Ok(())
}

/// Check `now` against the half-open window `[not_before, not_after)`.
///
/// End-exclusive, matching the claim-bitemporal convention used across the
/// substrate. An unparseable timestamp is [`HubDelegationError::OutsideValidity`]
/// — fail closed, never "assume valid".
///
/// # Errors
///
/// [`HubDelegationError::OutsideValidity`] outside the window or on a
/// timestamp that does not parse.
pub fn check_validity(
    delegation: &HubDelegation<'_>,
    now_rfc3339: &str,
) -> Result<(), HubDelegationError> {
    let now = parse_rfc3339(now_rfc3339)?;
    let start = parse_rfc3339(delegation.not_before)?;
    let end = parse_rfc3339(delegation.not_after)?;
    if now < start || now >= end {
        return Err(HubDelegationError::OutsideValidity);
    }
    Ok(())
}

fn parse_rfc3339(value: &str) -> Result<chrono::DateTime<chrono::Utc>, HubDelegationError> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|_| HubDelegationError::OutsideValidity)
}

// ---------------------------------------------------------------------------
// Wire form
// ---------------------------------------------------------------------------

/// Wire version of the delegation blob carried in a `hello`.
pub const DELEGATION_WIRE_VERSION: u8 = 1;

/// An owned, wire-decoded delegation plus its signature.
///
/// Kept separate from the borrowed [`HubDelegation`] so the signed pre-image
/// stays a pure view over borrowed fields: the bytes that get signed are built
/// from [`HubDelegation`] alone and cannot accidentally include the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationWire {
    /// The enrolled agent this delegation speaks for.
    pub principal: String,
    /// Must be [`A2A_HUB_SCOPE`].
    pub scope: String,
    /// The delegated hello key.
    pub delegate_key_id: [u8; DELEGATE_KEY_ID_BYTES],
    /// The one hub this delegation is valid at.
    pub hub_id: String,
    /// RFC3339 window start, inclusive.
    pub not_before: String,
    /// RFC3339 window end, exclusive.
    pub not_after: String,
    /// Signature by the ENROLLED root key over
    /// [`canonical_cbor_hub_delegation`].
    pub signature: [u8; 64],
}

impl DelegationWire {
    /// Borrow the signed view of this delegation.
    #[must_use]
    pub fn as_delegation(&self) -> HubDelegation<'_> {
        HubDelegation {
            principal: &self.principal,
            scope: &self.scope,
            delegate_key_id: &self.delegate_key_id,
            hub_id: &self.hub_id,
            not_before: &self.not_before,
            not_after: &self.not_after,
        }
    }

    /// Encode for the `hello` payload.
    ///
    /// # Errors
    ///
    /// [`HubDelegationError`] when any element is outside its bound.
    pub fn encode(&self) -> Result<Vec<u8>, HubDelegationError> {
        check_elements(&self.as_delegation())?;
        let mut out = Vec::with_capacity(128);
        out.push(DELEGATION_WIRE_VERSION);
        put_short(&mut out, self.principal.as_bytes())?;
        put_short(&mut out, self.scope.as_bytes())?;
        out.extend_from_slice(&self.delegate_key_id);
        put_short(&mut out, self.hub_id.as_bytes())?;
        put_short(&mut out, self.not_before.as_bytes())?;
        put_short(&mut out, self.not_after.as_bytes())?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Decode a delegation presented in a `hello`.
    ///
    /// Refuses trailing bytes: a delegation is a fixed record, so anything left
    /// over is either a different encoding or something smuggled alongside one.
    ///
    /// # Errors
    ///
    /// [`HubDelegationError::MalformedElement`] on a truncated, over-long,
    /// non-UTF-8 or trailing-byte encoding; [`HubDelegationError::ScopeMismatch`]
    /// for a foreign scope; [`HubDelegationError::MalformedSignature`] when the
    /// signature is short.
    pub fn decode(buf: &[u8]) -> Result<Self, HubDelegationError> {
        let (&version, rest) = buf
            .split_first()
            .ok_or(HubDelegationError::MalformedElement)?;
        if version != DELEGATION_WIRE_VERSION {
            return Err(HubDelegationError::MalformedElement);
        }
        let (principal, rest) = take_short(rest)?;
        let (scope, rest) = take_short(rest)?;
        if rest.len() < DELEGATE_KEY_ID_BYTES {
            return Err(HubDelegationError::MalformedElement);
        }
        let (key_bytes, rest) = rest.split_at(DELEGATE_KEY_ID_BYTES);
        let mut delegate_key_id = [0u8; DELEGATE_KEY_ID_BYTES];
        delegate_key_id.copy_from_slice(key_bytes);
        let (hub_id, rest) = take_short(rest)?;
        let (not_before, rest) = take_short(rest)?;
        let (not_after, rest) = take_short(rest)?;
        if rest.len() != 64 {
            return Err(HubDelegationError::MalformedSignature);
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(rest);

        let wire = Self {
            principal: utf8(principal)?,
            scope: utf8(scope)?,
            delegate_key_id,
            hub_id: utf8(hub_id)?,
            not_before: utf8(not_before)?,
            not_after: utf8(not_after)?,
            signature,
        };
        // Bound-check on the way IN, before any caller can hash or log a field.
        check_elements(&wire.as_delegation())?;
        Ok(wire)
    }
}

fn utf8(raw: &[u8]) -> Result<String, HubDelegationError> {
    std::str::from_utf8(raw)
        .map(ToOwned::to_owned)
        .map_err(|_| HubDelegationError::MalformedElement)
}

fn put_short(out: &mut Vec<u8>, raw: &[u8]) -> Result<(), HubDelegationError> {
    let len = u8::try_from(raw.len()).map_err(|_| HubDelegationError::MalformedElement)?;
    out.push(len);
    out.extend_from_slice(raw);
    Ok(())
}

fn take_short(buf: &[u8]) -> Result<(&[u8], &[u8]), HubDelegationError> {
    let (&len, rest) = buf
        .split_first()
        .ok_or(HubDelegationError::MalformedElement)?;
    let len = usize::from(len);
    if rest.len() < len {
        return Err(HubDelegationError::MalformedElement);
    }
    Ok(rest.split_at(len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const NOW: &str = "2026-09-03T12:00:00Z";
    const NB: &str = "2026-09-03T11:00:00Z";
    const NA: &str = "2026-09-03T13:00:00Z";

    fn root() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    fn delegate() -> SigningKey {
        SigningKey::from_bytes(&[4u8; 32])
    }

    fn wire() -> DelegationWire {
        let key = delegate().verifying_key().to_bytes();
        let mut wire = DelegationWire {
            principal: "agent-a".into(),
            scope: A2A_HUB_SCOPE.into(),
            delegate_key_id: key,
            hub_id: "ai-memory-wake-hub".into(),
            not_before: NB.into(),
            not_after: NA.into(),
            signature: [0u8; 64],
        };
        wire.signature = sign_hub_delegation(&root(), &wire.as_delegation()).expect("sign");
        wire
    }

    #[test]
    fn a_minted_delegation_verifies_under_the_enrolled_key() {
        let wire = wire();
        verify_hub_delegation(
            &root().verifying_key(),
            &wire.as_delegation(),
            &wire.signature,
        )
        .expect("verifies");
        check_ttl(&wire.as_delegation()).expect("ttl");
        check_validity(&wire.as_delegation(), NOW).expect("valid now");
    }

    #[test]
    fn a_delegation_does_not_verify_under_a_different_root() {
        let wire = wire();
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert_eq!(
            verify_hub_delegation(&other, &wire.as_delegation(), &wire.signature),
            Err(HubDelegationError::DelegationInvalid)
        );
    }

    #[test]
    fn every_signed_element_is_covered_by_the_signature() {
        // Flip each element in turn; each must break verification. This is the
        // test that would catch an element accidentally dropped from the
        // canonical array — the failure mode where a field looks authenticated
        // but is actually free for a caller to choose.
        let base = wire();
        let root_pub = root().verifying_key();
        let mut mutations: Vec<DelegationWire> = Vec::new();
        for mutate in [
            (|w: &mut DelegationWire| w.principal = "agent-b".into()) as fn(&mut DelegationWire),
            |w: &mut DelegationWire| w.hub_id = "other-hub".into(),
            |w: &mut DelegationWire| w.not_before = "2026-09-03T10:00:00Z".into(),
            |w: &mut DelegationWire| w.not_after = "2026-09-03T14:00:00Z".into(),
            |w: &mut DelegationWire| w.delegate_key_id = [7u8; DELEGATE_KEY_ID_BYTES],
        ] {
            let mut m = base.clone();
            mutate(&mut m);
            mutations.push(m);
        }
        for m in mutations {
            assert_eq!(
                verify_hub_delegation(&root_pub, &m.as_delegation(), &base.signature),
                Err(HubDelegationError::DelegationInvalid),
                "a mutated element must break the signature"
            );
        }
    }

    #[test]
    fn a_foreign_scope_is_refused_before_any_crypto() {
        let mut wire = wire();
        wire.scope = "write".into();
        assert_eq!(
            verify_hub_delegation(
                &root().verifying_key(),
                &wire.as_delegation(),
                &wire.signature
            ),
            Err(HubDelegationError::ScopeMismatch),
            "the scope element exists to be CHECKED, not merely recorded"
        );
    }

    #[test]
    fn an_over_long_window_is_refused_not_clamped() {
        let mut wire = wire();
        wire.not_after = "2026-09-10T11:00:00Z".into();
        assert_eq!(
            check_ttl(&wire.as_delegation()),
            Err(HubDelegationError::TtlTooLong),
            "expiry IS the revocation mechanism, so an un-revocable window must be refused"
        );
    }

    #[test]
    fn validity_is_half_open_and_fails_closed_on_a_bad_timestamp() {
        let wire = wire();
        assert!(
            check_validity(&wire.as_delegation(), NB).is_ok(),
            "start is inclusive"
        );
        assert_eq!(
            check_validity(&wire.as_delegation(), NA),
            Err(HubDelegationError::OutsideValidity),
            "end is exclusive"
        );
        assert_eq!(
            check_validity(&wire.as_delegation(), "not-a-timestamp"),
            Err(HubDelegationError::OutsideValidity)
        );
        let mut bad = wire;
        bad.not_after = "nonsense".into();
        assert_eq!(
            check_validity(&bad.as_delegation(), NOW),
            Err(HubDelegationError::OutsideValidity)
        );
    }

    #[test]
    fn the_wire_form_roundtrips_and_is_bounded() {
        let wire = wire();
        let bytes = wire.encode().expect("encode");
        assert!(
            bytes.len() <= crate::wake_hub::limits::MAX_DELEGATION_WIRE_BYTES,
            "encoded delegation must fit the wire bound"
        );
        assert_eq!(DelegationWire::decode(&bytes).expect("decode"), wire);
    }

    #[test]
    fn the_wire_form_refuses_truncation_trailing_bytes_and_a_wrong_version() {
        let bytes = wire().encode().expect("encode");
        assert_eq!(
            DelegationWire::decode(&bytes[..bytes.len() - 1]),
            Err(HubDelegationError::MalformedSignature)
        );
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(
            DelegationWire::decode(&extra),
            Err(HubDelegationError::MalformedSignature),
            "trailing bytes must be refused, not ignored"
        );
        let mut bad_version = bytes;
        bad_version[0] = 2;
        assert_eq!(
            DelegationWire::decode(&bad_version),
            Err(HubDelegationError::MalformedElement)
        );
        assert_eq!(
            DelegationWire::decode(&[]),
            Err(HubDelegationError::MalformedElement)
        );
    }

    #[test]
    fn the_domain_does_not_cross_verify_with_the_subkey_cert_domain() {
        // The whole reason this is a separate domain: a signature minted here
        // must never verify as a write-authority sub-key cert, and vice versa.
        use crate::identity::cbor_array::{A2A_HUB_JOIN_V1_DOMAIN, SUBKEY_CERT_V1_DOMAIN};
        assert_ne!(A2A_HUB_JOIN_V1_DOMAIN, SUBKEY_CERT_V1_DOMAIN);
        let bytes = canonical_cbor_hub_delegation(&wire().as_delegation());
        assert!(
            !bytes
                .windows(SUBKEY_CERT_V1_DOMAIN.len())
                .any(|w| w == SUBKEY_CERT_V1_DOMAIN.as_bytes()),
            "the sub-key cert tag must not appear anywhere in a delegation pre-image"
        );
        assert!(
            bytes
                .windows(A2A_HUB_JOIN_V1_DOMAIN.len())
                .any(|w| w == A2A_HUB_JOIN_V1_DOMAIN.as_bytes()),
            "the delegation pre-image must commit to its own domain tag"
        );
    }
}
