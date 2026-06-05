// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Federation credential — a CA-signed, short-lived binding of a node's
//! agent-id to its Ed25519 verifying key.
//!
//! This is the unit that replaces O(N²) per-peer `.pub` enrollment with
//! O(1) "trust the CA" (see ADR-001). A node presents a credential; the
//! receiver verifies it against a *trust bundle* of issuer keys
//! ([`super::trust_bundle`]) and, on success, uses the credential's
//! `subject_pubkey` as the verifying key for that peer's per-message
//! signatures — slotting into the exact place
//! `verify_signature_or_reject` previously called
//! `load_daemon_verifying_key(peer_id)`.
//!
//! ## Wire shape
//!
//! The credential travels as base64(CBOR) in the [`CREDENTIAL_HEADER`]
//! HTTP header, value-prefixed [`CREDENTIAL_PREFIX`] for version agility
//! (mirrors `ed25519=` on `X-Memory-Sig`). The CBOR is a 2-entry map:
//!
//! ```text
//! { "claims": bstr(<canonical-CBOR claims>), "sig": bstr(<64-byte Ed25519 sig>) }
//! ```
//!
//! The issuer signs the **exact** canonical claims bytes; the verifier
//! checks the signature over the bytes carried verbatim on the wire, so
//! there is no re-encode/canonicalisation drift between signer and
//! verifier — the load-bearing safety property.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Current credential format version. Bumped only on a breaking change
/// to the claim set or encoding; verifiers refuse versions they do not
/// understand so a mixed fleet degrades safely rather than misreading.
pub const CRED_VERSION: u16 = 1;

/// HTTP header carrying the base64(CBOR) credential. Lowercase per HTTP/2
/// wire convention; `HeaderMap` lookups are case-insensitive.
pub const CREDENTIAL_HEADER: &str = "x-memory-cred";

/// Version-agility prefix on the header value (`v1=<base64>`). A future
/// format can introduce `v2=` without breaking this parser.
pub const CREDENTIAL_PREFIX: &str = "v1=";

/// Length of the Ed25519 signature carried in the wire envelope.
pub const CREDENTIAL_SIG_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// Length of the subject Ed25519 verifying key.
pub const SUBJECT_PUBKEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

/// Filesystem path to this node's held outbound credential — the
/// `X-Memory-Cred` header value (`v1=<base64>`) written by the renewal
/// worker (ADR-001 Decision 5). Unset = this node holds no credential and
/// falls back to legacy per-peer enrollment on the wire.
pub const FED_CREDENTIAL_PATH_ENV: &str = "AI_MEMORY_FED_CRED_PATH";

// ---- canonical claim field keys (lexicographically ordered by BTreeMap) ----
const FIELD_CRED_VERSION: &str = "cred_version";
const FIELD_ISSUER_ID: &str = "issuer_id";
const FIELD_NOT_AFTER: &str = "not_after";
const FIELD_NOT_BEFORE: &str = "not_before";
const FIELD_SUBJECT_AGENT_ID: &str = "subject_agent_id";
const FIELD_SUBJECT_PUBKEY: &str = "subject_pubkey";
const FIELD_TRUST_DOMAIN: &str = "trust_domain";

// ---- wire envelope keys ----
const WIRE_CLAIMS_KEY: &str = "claims";
const WIRE_SIG_KEY: &str = "sig";

/// Reasons a credential fails to parse or verify. `tag()` yields a
/// stable machine string for structured logging + JSON error bodies
/// (mirrors `federation::signing::VerifyError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// Wire bytes (or base64) could not be parsed into the expected shape.
    Malformed,
    /// The issuer signature did not verify against the trust bundle.
    BadSignature,
    /// `now < not_before` — the credential is not yet valid.
    NotYetValid,
    /// `now > not_after` — the credential has expired.
    Expired,
    /// The credential's `cred_version` is newer than this binary understands.
    UnsupportedVersion(u16),
    /// `subject_pubkey` is not a valid Edwards-curve point.
    BadSubjectKey,
    /// The credential's `issuer_id` is not present in the trust bundle, so
    /// no key is available to verify its signature against.
    UnknownIssuer,
    /// The credential's `trust_domain` does not match the domain the
    /// receiving trust bundle is scoped to (multi-tenant isolation).
    WrongTrustDomain,
}

impl CredentialError {
    /// Stable machine-readable tag for logs + JSON error envelopes.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Malformed => "credential_malformed",
            Self::BadSignature => "credential_bad_signature",
            Self::NotYetValid => "credential_not_yet_valid",
            Self::Expired => "credential_expired",
            Self::UnsupportedVersion(_) => "credential_unsupported_version",
            Self::BadSubjectKey => "credential_bad_subject_key",
            Self::UnknownIssuer => "credential_unknown_issuer",
            Self::WrongTrustDomain => "credential_wrong_trust_domain",
        }
    }
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => {
                write!(
                    f,
                    "{} (got v{v}, this binary speaks v{CRED_VERSION})",
                    self.tag()
                )
            }
            _ => f.write_str(self.tag()),
        }
    }
}

impl std::error::Error for CredentialError {}

/// The signed claim set. These fields are what the CA attests to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationCredential {
    /// The node identity this credential vouches for (SPIFFE-style ids
    /// are legal — `validate::validate_agent_id` already permits the
    /// `/ : @ .` characters).
    pub subject_agent_id: String,
    /// The node's Ed25519 verifying key (raw 32 bytes).
    pub subject_pubkey: [u8; SUBJECT_PUBKEY_LEN],
    /// Identity of the CA / intermediate that issued this credential.
    pub issuer_id: String,
    /// Namespacing for multi-tenant fleets — the trust domain the
    /// subject and issuer both belong to.
    pub trust_domain: String,
    /// Unix seconds; credential invalid before this instant.
    pub not_before: i64,
    /// Unix seconds; credential invalid after this instant.
    pub not_after: i64,
    /// Format version. Equal to [`CRED_VERSION`] for credentials this
    /// binary mints.
    pub cred_version: u16,
}

impl FederationCredential {
    /// Canonical CBOR of the claim set. Deterministic: a `BTreeMap`
    /// enforces lexicographic key order and `ciborium` emits
    /// definite-length, smallest-int encodings. Same convention as
    /// [`crate::identity::sign::canonical_cbor`].
    ///
    /// # Errors
    /// Returns [`CredentialError::Malformed`] only on an internal
    /// serialisation fault (not reachable with well-formed fields).
    pub fn canonical_claims_bytes(&self) -> Result<Vec<u8>, CredentialError> {
        let mut map: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        map.insert(
            FIELD_SUBJECT_AGENT_ID,
            ciborium::Value::Text(self.subject_agent_id.clone()),
        );
        map.insert(
            FIELD_SUBJECT_PUBKEY,
            ciborium::Value::Bytes(self.subject_pubkey.to_vec()),
        );
        map.insert(
            FIELD_ISSUER_ID,
            ciborium::Value::Text(self.issuer_id.clone()),
        );
        map.insert(
            FIELD_TRUST_DOMAIN,
            ciborium::Value::Text(self.trust_domain.clone()),
        );
        map.insert(FIELD_NOT_BEFORE, int_value(self.not_before));
        map.insert(FIELD_NOT_AFTER, int_value(self.not_after));
        map.insert(FIELD_CRED_VERSION, int_value(i64::from(self.cred_version)));

        let entries: Vec<(ciborium::Value, ciborium::Value)> = map
            .into_iter()
            .map(|(k, v)| (ciborium::Value::Text(k.to_string()), v))
            .collect();
        let value = ciborium::Value::Map(entries);
        let mut out = Vec::with_capacity(128);
        ciborium::ser::into_writer(&value, &mut out).map_err(|_| CredentialError::Malformed)?;
        Ok(out)
    }

    /// Sign this credential with the issuer's CA signing key, producing a
    /// [`SignedCredential`] that carries the exact signed bytes.
    ///
    /// # Errors
    /// Propagates [`CredentialError::Malformed`] from claim encoding.
    pub fn sign(&self, ca_signing_key: &SigningKey) -> Result<SignedCredential, CredentialError> {
        let claims_bytes = self.canonical_claims_bytes()?;
        let sig: Signature = ca_signing_key.sign(&claims_bytes);
        Ok(SignedCredential {
            credential: self.clone(),
            claims_bytes,
            signature: sig.to_bytes(),
        })
    }

    /// Parse a credential from its canonical claim bytes.
    fn from_claims_bytes(bytes: &[u8]) -> Result<Self, CredentialError> {
        let value: ciborium::Value =
            ciborium::de::from_reader(bytes).map_err(|_| CredentialError::Malformed)?;
        let entries = match value {
            ciborium::Value::Map(e) => e,
            _ => return Err(CredentialError::Malformed),
        };
        let mut map: BTreeMap<String, ciborium::Value> = BTreeMap::new();
        for (k, v) in entries {
            if let ciborium::Value::Text(key) = k {
                map.insert(key, v);
            } else {
                return Err(CredentialError::Malformed);
            }
        }
        let subject_pubkey_vec = take_bytes(&mut map, FIELD_SUBJECT_PUBKEY)?;
        if subject_pubkey_vec.len() != SUBJECT_PUBKEY_LEN {
            return Err(CredentialError::Malformed);
        }
        let mut subject_pubkey = [0u8; SUBJECT_PUBKEY_LEN];
        subject_pubkey.copy_from_slice(&subject_pubkey_vec);

        let cred_version_i = take_int(&mut map, FIELD_CRED_VERSION)?;
        let cred_version = u16::try_from(cred_version_i).map_err(|_| CredentialError::Malformed)?;

        Ok(Self {
            subject_agent_id: take_text(&mut map, FIELD_SUBJECT_AGENT_ID)?,
            subject_pubkey,
            issuer_id: take_text(&mut map, FIELD_ISSUER_ID)?,
            trust_domain: take_text(&mut map, FIELD_TRUST_DOMAIN)?,
            not_before: take_int(&mut map, FIELD_NOT_BEFORE)?,
            not_after: take_int(&mut map, FIELD_NOT_AFTER)?,
            cred_version,
        })
    }

    /// The subject's verifying key, decoded from `subject_pubkey`.
    ///
    /// # Errors
    /// [`CredentialError::BadSubjectKey`] when the bytes are not a valid
    /// Edwards-curve point.
    pub fn subject_verifying_key(&self) -> Result<VerifyingKey, CredentialError> {
        VerifyingKey::from_bytes(&self.subject_pubkey).map_err(|_| CredentialError::BadSubjectKey)
    }
}

/// A [`FederationCredential`] plus the issuer signature over its exact
/// canonical claim bytes. This is the on-wire unit.
#[derive(Debug, Clone)]
pub struct SignedCredential {
    credential: FederationCredential,
    /// The exact bytes the issuer signed (carried verbatim so verify
    /// never re-encodes).
    claims_bytes: Vec<u8>,
    signature: [u8; CREDENTIAL_SIG_LEN],
}

impl SignedCredential {
    /// Borrow the inner credential (claims).
    #[must_use]
    pub fn credential(&self) -> &FederationCredential {
        &self.credential
    }

    /// Encode to the CBOR wire envelope (`{claims, sig}`).
    ///
    /// # Errors
    /// [`CredentialError::Malformed`] on an internal serialisation fault.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, CredentialError> {
        let entries: Vec<(ciborium::Value, ciborium::Value)> = vec![
            (
                ciborium::Value::Text(WIRE_CLAIMS_KEY.to_string()),
                ciborium::Value::Bytes(self.claims_bytes.clone()),
            ),
            (
                ciborium::Value::Text(WIRE_SIG_KEY.to_string()),
                ciborium::Value::Bytes(self.signature.to_vec()),
            ),
        ];
        let value = ciborium::Value::Map(entries);
        let mut out = Vec::with_capacity(self.claims_bytes.len() + CREDENTIAL_SIG_LEN + 16);
        ciborium::ser::into_writer(&value, &mut out).map_err(|_| CredentialError::Malformed)?;
        Ok(out)
    }

    /// Parse a wire envelope back into a [`SignedCredential`]. Does NOT
    /// verify the signature — call [`Self::verify_against`].
    ///
    /// # Errors
    /// [`CredentialError::Malformed`] on any structural problem.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, CredentialError> {
        let value: ciborium::Value =
            ciborium::de::from_reader(bytes).map_err(|_| CredentialError::Malformed)?;
        let entries = match value {
            ciborium::Value::Map(e) => e,
            _ => return Err(CredentialError::Malformed),
        };
        let mut claims_bytes: Option<Vec<u8>> = None;
        let mut signature_vec: Option<Vec<u8>> = None;
        for (k, v) in entries {
            let key = match k {
                ciborium::Value::Text(s) => s,
                _ => return Err(CredentialError::Malformed),
            };
            match (key.as_str(), v) {
                (WIRE_CLAIMS_KEY, ciborium::Value::Bytes(b)) => claims_bytes = Some(b),
                (WIRE_SIG_KEY, ciborium::Value::Bytes(b)) => signature_vec = Some(b),
                _ => return Err(CredentialError::Malformed),
            }
        }
        let claims_bytes = claims_bytes.ok_or(CredentialError::Malformed)?;
        let signature_vec = signature_vec.ok_or(CredentialError::Malformed)?;
        if signature_vec.len() != CREDENTIAL_SIG_LEN {
            return Err(CredentialError::Malformed);
        }
        let mut signature = [0u8; CREDENTIAL_SIG_LEN];
        signature.copy_from_slice(&signature_vec);
        let credential = FederationCredential::from_claims_bytes(&claims_bytes)?;
        Ok(Self {
            credential,
            claims_bytes,
            signature,
        })
    }

    /// Base64(standard) of the wire envelope, with the [`CREDENTIAL_PREFIX`]
    /// version marker — the full `X-Memory-Cred` header value.
    ///
    /// # Errors
    /// [`CredentialError::Malformed`] on encode fault.
    pub fn to_header_value(&self) -> Result<String, CredentialError> {
        let wire = self.to_wire_bytes()?;
        Ok(format!("{CREDENTIAL_PREFIX}{}", B64.encode(wire)))
    }

    /// Parse a `X-Memory-Cred` header value (`v1=<base64>`).
    ///
    /// # Errors
    /// [`CredentialError::Malformed`] on a missing prefix, bad base64, or
    /// bad envelope; [`CredentialError::UnsupportedVersion`] if a future
    /// `vN=` prefix is seen.
    pub fn from_header_value(value: &str) -> Result<Self, CredentialError> {
        let b64 = value
            .strip_prefix(CREDENTIAL_PREFIX)
            .ok_or_else(|| unsupported_or_malformed(value))?;
        let wire = B64.decode(b64).map_err(|_| CredentialError::Malformed)?;
        Self::from_wire_bytes(&wire)
    }

    /// Verify the issuer signature against a candidate issuer key AND the
    /// validity window against `now_unix`. On success the credential is
    /// cryptographically attributable to `issuer_pub` and currently valid.
    ///
    /// Identity binding (does the subject match the wire `peer_id`?) is
    /// the caller's responsibility — kept out of here so the crypto core
    /// stays single-purpose.
    ///
    /// # Errors
    /// - [`CredentialError::UnsupportedVersion`] if newer than this binary.
    /// - [`CredentialError::BadSignature`] if the signature does not verify.
    /// - [`CredentialError::NotYetValid`] / [`CredentialError::Expired`] on
    ///   the validity window.
    pub fn verify_against(
        &self,
        issuer_pub: &VerifyingKey,
        now_unix: i64,
    ) -> Result<(), CredentialError> {
        if self.credential.cred_version > CRED_VERSION {
            return Err(CredentialError::UnsupportedVersion(
                self.credential.cred_version,
            ));
        }
        let sig = Signature::from_bytes(&self.signature);
        issuer_pub
            .verify(&self.claims_bytes, &sig)
            .map_err(|_| CredentialError::BadSignature)?;
        self.check_validity(now_unix)
    }

    /// Validity-window check in isolation (no signature check).
    fn check_validity(&self, now_unix: i64) -> Result<(), CredentialError> {
        if now_unix < self.credential.not_before {
            return Err(CredentialError::NotYetValid);
        }
        if now_unix > self.credential.not_after {
            return Err(CredentialError::Expired);
        }
        Ok(())
    }

    /// Load a held outbound credential from a file whose contents are the
    /// `X-Memory-Cred` header value (`v1=<base64>`, as produced by
    /// [`Self::to_header_value`]). A missing file is `Ok(None)` — holding no
    /// credential is the normal pre-enrollment state, not an error.
    ///
    /// # Errors
    /// [`std::io::Error`] on a read fault other than not-found, or
    /// `InvalidData` if the file content is not a parseable header value.
    pub fn load_from_path(path: &std::path::Path) -> std::io::Result<Option<Self>> {
        let raw = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let cred = Self::from_header_value(raw.trim())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Some(cred))
    }

    /// Load the held outbound credential named by [`FED_CREDENTIAL_PATH_ENV`].
    /// An unset env var is `Ok(None)` — this node simply holds no credential.
    ///
    /// # Errors
    /// Propagates [`Self::load_from_path`] faults.
    pub fn load_from_env() -> std::io::Result<Option<Self>> {
        match std::env::var(FED_CREDENTIAL_PATH_ENV) {
            Ok(path) => Self::load_from_path(std::path::Path::new(&path)),
            Err(_) => Ok(None),
        }
    }
}

/// Map a missing-prefix header to the right error: a recognised future
/// `vN=` marker is an unsupported version; anything else is malformed.
fn unsupported_or_malformed(value: &str) -> CredentialError {
    if let Some(rest) = value.strip_prefix('v') {
        if let Some((digits, _)) = rest.split_once('=') {
            if let Ok(v) = digits.parse::<u16>() {
                return CredentialError::UnsupportedVersion(v);
            }
        }
    }
    CredentialError::Malformed
}

/// Wrap an `i64` as a CBOR integer value.
fn int_value(n: i64) -> ciborium::Value {
    ciborium::Value::Integer(n.into())
}

fn take_text(
    map: &mut BTreeMap<String, ciborium::Value>,
    key: &str,
) -> Result<String, CredentialError> {
    match map.remove(key) {
        Some(ciborium::Value::Text(s)) => Ok(s),
        _ => Err(CredentialError::Malformed),
    }
}

fn take_bytes(
    map: &mut BTreeMap<String, ciborium::Value>,
    key: &str,
) -> Result<Vec<u8>, CredentialError> {
    match map.remove(key) {
        Some(ciborium::Value::Bytes(b)) => Ok(b),
        _ => Err(CredentialError::Malformed),
    }
}

fn take_int(
    map: &mut BTreeMap<String, ciborium::Value>,
    key: &str,
) -> Result<i64, CredentialError> {
    match map.remove(key) {
        Some(ciborium::Value::Integer(i)) => {
            i64::try_from(i128::from(i)).map_err(|_| CredentialError::Malformed)
        }
        _ => Err(CredentialError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn ca_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn subject_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sample(now: i64) -> FederationCredential {
        let subj = subject_key(7);
        FederationCredential {
            subject_agent_id: "region/nyc/node-7".to_string(),
            subject_pubkey: subj.verifying_key().to_bytes(),
            issuer_id: "trust-domain-root".to_string(),
            trust_domain: "fleet.example".to_string(),
            not_before: now - 10,
            not_after: now + 3600,
            cred_version: CRED_VERSION,
        }
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let ca = ca_key(1);
        let now = 1_900_000_000;
        let signed = sample(now).sign(&ca).expect("sign");
        signed
            .verify_against(&ca.verifying_key(), now)
            .expect("valid credential verifies");
    }

    #[test]
    fn wire_round_trip_preserves_claims_and_verifies() {
        let ca = ca_key(2);
        let now = 1_900_000_000;
        let signed = sample(now).sign(&ca).expect("sign");
        let wire = signed.to_wire_bytes().expect("wire encode");
        let parsed = SignedCredential::from_wire_bytes(&wire).expect("wire decode");
        assert_eq!(parsed.credential(), signed.credential());
        parsed
            .verify_against(&ca.verifying_key(), now)
            .expect("re-parsed credential still verifies");
    }

    #[test]
    fn header_value_round_trip() {
        let ca = ca_key(3);
        let now = 1_900_000_000;
        let signed = sample(now).sign(&ca).expect("sign");
        let header = signed.to_header_value().expect("header encode");
        assert!(header.starts_with(CREDENTIAL_PREFIX));
        let parsed = SignedCredential::from_header_value(&header).expect("header decode");
        parsed
            .verify_against(&ca.verifying_key(), now)
            .expect("verifies");
    }

    #[test]
    fn wrong_issuer_key_is_rejected() {
        let ca = ca_key(4);
        let attacker = ca_key(5);
        let now = 1_900_000_000;
        let signed = sample(now).sign(&ca).expect("sign");
        assert_eq!(
            signed.verify_against(&attacker.verifying_key(), now),
            Err(CredentialError::BadSignature)
        );
    }

    #[test]
    fn tampered_claims_break_signature() {
        let ca = ca_key(6);
        let now = 1_900_000_000;
        let signed = sample(now).sign(&ca).expect("sign");
        let mut wire = signed.to_wire_bytes().expect("wire");
        // Flip a byte somewhere in the claims region (early in the buffer).
        wire[10] ^= 0xFF;
        // Either the structure no longer parses, or the signature fails.
        match SignedCredential::from_wire_bytes(&wire) {
            Ok(parsed) => assert_eq!(
                parsed.verify_against(&ca.verifying_key(), now),
                Err(CredentialError::BadSignature)
            ),
            Err(e) => assert_eq!(e, CredentialError::Malformed),
        }
    }

    #[test]
    fn not_yet_valid_and_expired_windows() {
        let ca = ca_key(7);
        let now = 1_900_000_000;
        let signed = sample(now).sign(&ca).expect("sign");
        assert_eq!(
            signed.verify_against(&ca.verifying_key(), now - 100),
            Err(CredentialError::NotYetValid)
        );
        assert_eq!(
            signed.verify_against(&ca.verifying_key(), now + 100_000),
            Err(CredentialError::Expired)
        );
    }

    #[test]
    fn unsupported_future_version_is_refused() {
        let ca = ca_key(8);
        let now = 1_900_000_000;
        let mut cred = sample(now);
        cred.cred_version = CRED_VERSION + 1;
        let signed = cred.sign(&ca).expect("sign");
        assert_eq!(
            signed.verify_against(&ca.verifying_key(), now),
            Err(CredentialError::UnsupportedVersion(CRED_VERSION + 1))
        );
    }

    #[test]
    fn subject_verifying_key_matches_issued_subject() {
        let now = 1_900_000_000;
        let subj = subject_key(7);
        let cred = sample(now);
        assert_eq!(
            cred.subject_verifying_key().expect("valid point"),
            subj.verifying_key()
        );
    }

    #[test]
    fn malformed_header_prefix_is_malformed() {
        assert_eq!(
            SignedCredential::from_header_value("garbage").unwrap_err(),
            CredentialError::Malformed
        );
    }

    #[test]
    fn future_header_version_marker_is_unsupported_version() {
        assert_eq!(
            SignedCredential::from_header_value("v9=AAAA").unwrap_err(),
            CredentialError::UnsupportedVersion(9)
        );
    }

    #[test]
    fn truncated_wire_is_malformed() {
        assert_eq!(
            SignedCredential::from_wire_bytes(&[0x01, 0x02, 0x03]).unwrap_err(),
            CredentialError::Malformed
        );
    }

    // ---- FED-P3a: held outbound credential loader ----

    fn loader_scratch_dir() -> std::path::PathBuf {
        let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.push(".local-runs");
        dir.push("test-tmp");
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    fn unique_cred_path(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        loader_scratch_dir().join(format!("cred-{label}-{nanos}.cred"))
    }

    #[test]
    fn load_from_path_round_trips_a_written_credential() {
        let ca = ca_key(11);
        let now = 1_900_000_000;
        let signed = sample(now).sign(&ca).expect("sign");
        let header = signed.to_header_value().expect("encode");
        let path = unique_cred_path("roundtrip");
        std::fs::write(&path, format!("{header}\n")).expect("write cred file");

        let loaded = SignedCredential::load_from_path(&path)
            .expect("io ok")
            .expect("present");
        assert_eq!(loaded.credential(), signed.credential());
        loaded
            .verify_against(&ca.verifying_key(), now)
            .expect("loaded credential still verifies");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_from_path_missing_file_is_none() {
        let path = unique_cred_path("missing");
        assert!(
            SignedCredential::load_from_path(&path)
                .expect("missing file is not an error")
                .is_none()
        );
    }

    #[test]
    fn load_from_path_malformed_content_is_invalid_data() {
        let path = unique_cred_path("garbage");
        std::fs::write(&path, "not-a-credential").expect("write");
        let err = SignedCredential::load_from_path(&path).expect_err("malformed must error");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_from_env_unset_is_none() {
        // SAFETY: single-threaded within this test; we only remove the var.
        unsafe {
            std::env::remove_var(FED_CREDENTIAL_PATH_ENV);
        }
        assert!(
            SignedCredential::load_from_env()
                .expect("unset env is not an error")
                .is_none()
        );
    }
}
