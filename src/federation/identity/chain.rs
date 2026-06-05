// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Hierarchical trust — chain-of-N credential verification (FED-P4).
//!
//! P2/P3 verify a node credential directly against a trusted issuer key
//! (one level: the root signs every node). At fleet scale a single root that
//! must sign every node credential is both an operational bottleneck and a
//! blast-radius concentration — every issuance touches the one key whose
//! compromise re-keys the whole fleet. Hierarchical trust introduces
//! *intermediate* CAs (typically one per region per the inventory's
//! `region.intermediate_ca`): the root signs a small number of intermediate
//! certs; each intermediate signs the node credentials in its region.
//! Receivers still enroll only the *root* key — the chain carries the
//! intermediate cert inline and [`CertChain::verify`] walks
//! root → … → leaf.
//!
//! ## An intermediate cert is just a credential
//!
//! No new wire type: an intermediate CA cert is a [`SignedCredential`] whose
//! `subject_agent_id` is the intermediate's own `issuer_id` and whose
//! `subject_pubkey` is the intermediate's verifying key, signed by the
//! parent (root). Verifying it yields the key that verifies the next level
//! down. This reuses the entire [`super::credential`] encoding + window +
//! version machinery unchanged — no `CRED_VERSION` bump.
//!
//! ## What this core checks (and what it leaves to the caller)
//!
//! [`CertChain::verify`] enforces, at every link: the issuer signature, the
//! validity window, **name binding** (a cert's `issuer_id` equals its
//! parent's `subject_agent_id`, so the key chain and the *name* chain agree
//! — a stolen intermediate key cannot impersonate a differently-named CA),
//! cross-level `trust_domain` consistency, and a **depth cap** (an unbounded
//! chain is a verify-cost DoS). It deliberately does NOT decide whether an
//! intermediate has *authority* over the leaf's namespace — that delegation
//! policy is the caller's, exactly as identity-binding is the caller's in
//! [`SignedCredential::verify_against`]. [`subject_in_delegated_namespace`]
//! is a pure helper callers may apply on the returned leaf.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::VerifyingKey;

use super::credential::{
    CREDENTIAL_PREFIX, CredentialError, FederationCredential, SignedCredential,
};
use super::trust_bundle::TrustBundle;

/// HTTP header carrying the base64(CBOR) array of *intermediate* CA certs
/// (anchor-first) for a hierarchical credential. The leaf still travels in
/// [`super::credential::CREDENTIAL_HEADER`]; this header is emitted only when
/// the leaf is signed by an intermediate rather than a root, so single-level
/// P2/P3 peers never send it and receivers that see it absent verify exactly
/// as they did pre-P4.
pub const CHAIN_HEADER: &str = "x-memory-cred-chain";

/// Default maximum chain depth (levels, leaf inclusive). `2` is the P4
/// target: root → intermediate → leaf is depth 2 (one intermediate + the
/// leaf). A direct root-signed leaf is depth 1. Receivers raise this only
/// for deliberately deeper hierarchies.
pub const DEFAULT_MAX_CHAIN_DEPTH: usize = 2;

/// Reasons a certificate chain fails to verify. `tag()` yields a stable
/// machine string for structured logging + JSON error envelopes, mirroring
/// [`CredentialError::tag`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The chain carried no leaf at all (structurally impossible to present
    /// a [`CertChain`], retained for completeness of the error surface).
    EmptyChain,
    /// The chain is deeper than the receiver's configured maximum.
    ChainTooDeep {
        /// The presented depth (intermediates + leaf).
        depth: usize,
        /// The configured cap.
        max: usize,
    },
    /// A cert's `issuer_id` does not equal its parent's `subject_agent_id`:
    /// the key chain links but the *name* chain does not, so the parent
    /// never vouched for this issuer name.
    NameMismatch,
    /// Two adjacent links disagree on `trust_domain` — a credential from one
    /// tenant must not ride a chain anchored in another.
    DomainMismatch,
    /// A credential-layer failure at some link (bad signature, expired,
    /// not-yet-valid, unknown/anchor issuer, bad subject key, unsupported
    /// version).
    Link(CredentialError),
}

impl ChainError {
    /// Stable machine-readable tag for logs + JSON error envelopes.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::EmptyChain => "chain_empty",
            Self::ChainTooDeep { .. } => "chain_too_deep",
            Self::NameMismatch => "chain_name_mismatch",
            Self::DomainMismatch => "chain_domain_mismatch",
            Self::Link(e) => e.tag(),
        }
    }
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainTooDeep { depth, max } => {
                write!(f, "{} (depth {depth} > max {max})", self.tag())
            }
            Self::Link(e) => write!(f, "{e}"),
            _ => f.write_str(self.tag()),
        }
    }
}

impl std::error::Error for ChainError {}

impl From<CredentialError> for ChainError {
    fn from(e: CredentialError) -> Self {
        Self::Link(e)
    }
}

/// A presented certificate chain: zero or more intermediate CA certs plus
/// the leaf (node) credential.
#[derive(Debug, Clone)]
pub struct CertChain {
    /// Intermediate CA certs, ordered **anchor-first**: `intermediates[0]`
    /// is signed by a trusted root in the receiver's bundle; each subsequent
    /// cert is signed by the previous one; the last signed the leaf. Empty
    /// ⇒ the leaf is signed directly by a trusted root (the P2/P3 one-level
    /// case, preserved for back-compat).
    pub intermediates: Vec<SignedCredential>,
    /// The leaf (node) credential whose `subject_pubkey` the caller will use
    /// as the peer's verifying key once the chain verifies.
    pub leaf: SignedCredential,
}

impl CertChain {
    /// A chain with an explicit leaf and intermediates (anchor-first).
    #[must_use]
    pub fn new(leaf: SignedCredential, intermediates: Vec<SignedCredential>) -> Self {
        Self {
            intermediates,
            leaf,
        }
    }

    /// A one-level chain: the leaf is signed directly by a trusted root.
    #[must_use]
    pub fn direct(leaf: SignedCredential) -> Self {
        Self {
            intermediates: Vec::new(),
            leaf,
        }
    }

    /// Chain depth in levels (intermediates + the leaf).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.intermediates.len() + 1
    }

    /// Encode the anchor-first intermediates as the [`CHAIN_HEADER`] value
    /// (`v1=<base64(CBOR array of credential wire envelopes)>`), or `None`
    /// when the chain is one-level (no intermediates ⇒ no chain header, so a
    /// hierarchical sender degrades to the exact P2/P3 wire when it happens to
    /// hold a root-signed leaf). The leaf is encoded separately via
    /// [`SignedCredential::to_header_value`] into the credential header.
    ///
    /// # Errors
    /// [`CredentialError::Malformed`] on an internal serialisation fault.
    pub fn intermediates_header_value(&self) -> Result<Option<String>, CredentialError> {
        if self.intermediates.is_empty() {
            return Ok(None);
        }
        let mut items = Vec::with_capacity(self.intermediates.len());
        for ic in &self.intermediates {
            items.push(ciborium::Value::Bytes(ic.to_wire_bytes()?));
        }
        let value = ciborium::Value::Array(items);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&value, &mut out).map_err(|_| CredentialError::Malformed)?;
        Ok(Some(format!("{CREDENTIAL_PREFIX}{}", B64.encode(out))))
    }

    /// Parse a [`CHAIN_HEADER`] value (`v1=<base64(CBOR array)>`) into the
    /// anchor-first intermediates list. Pair with a leaf parsed from the
    /// credential header to reconstruct a [`CertChain`] via [`Self::new`].
    ///
    /// # Errors
    /// [`CredentialError::Malformed`] on a missing prefix, bad base64, or a
    /// structurally invalid CBOR array / envelope.
    pub fn intermediates_from_header_value(
        value: &str,
    ) -> Result<Vec<SignedCredential>, CredentialError> {
        let b64 = value
            .strip_prefix(CREDENTIAL_PREFIX)
            .ok_or(CredentialError::Malformed)?;
        let wire = B64.decode(b64).map_err(|_| CredentialError::Malformed)?;
        let parsed: ciborium::Value =
            ciborium::de::from_reader(&wire[..]).map_err(|_| CredentialError::Malformed)?;
        let items = match parsed {
            ciborium::Value::Array(a) => a,
            _ => return Err(CredentialError::Malformed),
        };
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let bytes = match item {
                ciborium::Value::Bytes(b) => b,
                _ => return Err(CredentialError::Malformed),
            };
            out.push(SignedCredential::from_wire_bytes(&bytes)?);
        }
        Ok(out)
    }

    /// Verify the whole chain against `bundle` at `now_unix`, rejecting
    /// chains deeper than `max_depth`. On success returns the verified leaf
    /// [`FederationCredential`] whose `subject_pubkey` is the peer's key.
    ///
    /// Identity-binding (does the leaf's `subject_agent_id` match the wire
    /// `peer_id`?) and delegation-authority (may this intermediate vouch for
    /// this leaf's namespace?) stay the caller's responsibility — the same
    /// crypto/policy split as [`SignedCredential::verify_against`].
    ///
    /// # Errors
    /// - [`ChainError::ChainTooDeep`] when `depth() > max_depth`.
    /// - [`ChainError::NameMismatch`] / [`ChainError::DomainMismatch`] on a
    ///   broken name or domain link.
    /// - [`ChainError::Link`] wrapping any credential-layer failure (anchor
    ///   not in bundle, bad signature, expired, etc.).
    pub fn verify(
        &self,
        bundle: &TrustBundle,
        now_unix: i64,
        max_depth: usize,
    ) -> Result<FederationCredential, ChainError> {
        let depth = self.depth();
        if depth > max_depth {
            return Err(ChainError::ChainTooDeep {
                depth,
                max: max_depth,
            });
        }

        // One-level: the leaf is signed directly by a trusted root. Defer
        // wholesale to the bundle (issuer-in-bundle + domain scope + sig +
        // window) — preserves the exact P2/P3 verify semantics.
        let Some((anchor, rest)) = self.intermediates.split_first() else {
            return Ok(bundle.verify(&self.leaf, now_unix)?);
        };

        // Anchor the chain: the topmost intermediate must be signed by a
        // root the bundle trusts. `bundle.verify` returns the intermediate's
        // own claims (its subject name + key become the next verifier).
        let mut parent = bundle.verify(anchor, now_unix)?;

        // Walk the remaining intermediates, then the leaf, each verified
        // against the previous link's subject key + name + domain.
        for cert in rest.iter().chain(std::iter::once(&self.leaf)) {
            verify_link(cert, &parent, now_unix)?;
            parent = cert.credential().clone();
        }

        Ok(self.leaf.credential().clone())
    }
}

/// Verify one child→parent link: name binding, domain consistency, then the
/// child's issuer signature + validity window against the parent's subject
/// key.
fn verify_link(
    child: &SignedCredential,
    parent: &FederationCredential,
    now_unix: i64,
) -> Result<(), ChainError> {
    let c = child.credential();
    if c.issuer_id != parent.subject_agent_id {
        return Err(ChainError::NameMismatch);
    }
    if c.trust_domain != parent.trust_domain {
        return Err(ChainError::DomainMismatch);
    }
    let parent_key: VerifyingKey = parent.subject_verifying_key()?;
    child.verify_against(&parent_key, now_unix)?;
    Ok(())
}

/// Whether `subject_agent_id` falls within the namespace an intermediate CA
/// is delegated to sign. A region intermediate whose authority is
/// `region/nyc` may vouch for `region/nyc/node-1` (and for the bare
/// `region/nyc` itself) but NOT for `region/sfo/node-9` nor the
/// sibling-prefix `region/nyceast/node-2`. An empty `ca_namespace` delegates
/// everything (the root).
///
/// This is pure delegation *policy* a caller applies AFTER
/// [`CertChain::verify`] proves the chain crypto; it is intentionally not
/// baked into `verify` (same crypto/policy split as identity-binding).
#[must_use]
pub fn subject_in_delegated_namespace(subject_agent_id: &str, ca_namespace: &str) -> bool {
    if ca_namespace.is_empty() {
        return true;
    }
    if subject_agent_id == ca_namespace {
        return true;
    }
    // Trailing-slash prefix so `region/nyc` does NOT match `region/nyceast`.
    let boundary = if ca_namespace.ends_with('/') {
        ca_namespace.to_string()
    } else {
        format!("{ca_namespace}/")
    };
    subject_agent_id.starts_with(&boundary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const NOW: i64 = 1_900_000_000;
    const DOMAIN: &str = "fleet.example";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Mint a credential: `signer` vouches for `subject_id` bound to
    /// `subject_key`, naming itself `issuer_id`, in `domain`.
    fn mint(
        signer: &SigningKey,
        issuer_id: &str,
        subject_id: &str,
        subject_key: &VerifyingKey,
        domain: &str,
        not_after: i64,
    ) -> SignedCredential {
        FederationCredential {
            subject_agent_id: subject_id.to_string(),
            subject_pubkey: subject_key.to_bytes(),
            issuer_id: issuer_id.to_string(),
            trust_domain: domain.to_string(),
            not_before: NOW - 10,
            not_after,
            cred_version: super::super::credential::CRED_VERSION,
        }
        .sign(signer)
        .expect("sign")
    }

    /// Build a standard root → intermediate → leaf trio and a bundle that
    /// trusts only the root. Returns (bundle, intermediate_cert, leaf).
    fn two_level_setup() -> (TrustBundle, SignedCredential, SignedCredential) {
        let root = signing_key(1);
        let intermediate = signing_key(2);
        let node = signing_key(3);

        // root signs the intermediate cert (subject = intermediate issuer).
        let inter_cert = mint(
            &root,
            "root",
            "region/nyc/ca",
            &intermediate.verifying_key(),
            DOMAIN,
            NOW + 7200,
        );
        // intermediate signs the node leaf.
        let leaf = mint(
            &intermediate,
            "region/nyc/ca",
            "region/nyc/node-1",
            &node.verifying_key(),
            DOMAIN,
            NOW + 3600,
        );
        let bundle = TrustBundle::new().with_issuer("root", root.verifying_key());
        (bundle, inter_cert, leaf)
    }

    #[test]
    fn two_level_chain_verifies() {
        let (bundle, inter, leaf) = two_level_setup();
        let chain = CertChain::new(leaf, vec![inter]);
        let verified = chain
            .verify(&bundle, NOW, DEFAULT_MAX_CHAIN_DEPTH)
            .expect("chain verifies");
        assert_eq!(verified.subject_agent_id, "region/nyc/node-1");
    }

    #[test]
    fn intermediates_header_round_trips_and_reverifies() {
        let (bundle, inter, leaf) = two_level_setup();
        let chain = CertChain::new(leaf, vec![inter]);

        // Encode the intermediates to the chain header, parse them back,
        // reassemble with a freshly-decoded leaf, and prove the rebuilt
        // chain still verifies against the root-only bundle.
        let header = chain
            .intermediates_header_value()
            .expect("encode chain header")
            .expect("two-level chain emits a header");
        let parsed_inters =
            CertChain::intermediates_from_header_value(&header).expect("parse chain header");
        let leaf_header = chain.leaf.to_header_value().expect("encode leaf");
        let parsed_leaf = SignedCredential::from_header_value(&leaf_header).expect("parse leaf");

        let rebuilt = CertChain::new(parsed_leaf, parsed_inters);
        let verified = rebuilt
            .verify(&bundle, NOW, DEFAULT_MAX_CHAIN_DEPTH)
            .expect("rebuilt chain verifies");
        assert_eq!(verified.subject_agent_id, "region/nyc/node-1");
    }

    #[test]
    fn direct_chain_emits_no_intermediates_header() {
        let root = signing_key(60);
        let node = signing_key(61);
        let leaf = mint(
            &root,
            "root",
            "region/nyc/node-1",
            &node.verifying_key(),
            DOMAIN,
            NOW + 3600,
        );
        let chain = CertChain::direct(leaf);
        assert!(
            chain
                .intermediates_header_value()
                .expect("encode")
                .is_none(),
            "a one-level chain must emit no chain header"
        );
    }

    #[test]
    fn malformed_chain_header_is_rejected() {
        assert_eq!(
            CertChain::intermediates_from_header_value("not-a-prefix").unwrap_err(),
            CredentialError::Malformed
        );
        assert_eq!(
            CertChain::intermediates_from_header_value("v1=@@notbase64@@").unwrap_err(),
            CredentialError::Malformed
        );
    }

    #[test]
    fn one_level_direct_chain_still_verifies() {
        // Back-compat: a leaf signed directly by the trusted root.
        let root = signing_key(10);
        let node = signing_key(11);
        let leaf = mint(
            &root,
            "root",
            "region/nyc/node-1",
            &node.verifying_key(),
            DOMAIN,
            NOW + 3600,
        );
        let bundle = TrustBundle::new().with_issuer("root", root.verifying_key());
        let verified = CertChain::direct(leaf)
            .verify(&bundle, NOW, DEFAULT_MAX_CHAIN_DEPTH)
            .expect("direct chain verifies");
        assert_eq!(verified.subject_agent_id, "region/nyc/node-1");
    }

    #[test]
    fn chain_deeper_than_max_is_rejected() {
        let (bundle, inter, leaf) = two_level_setup();
        // Two intermediates + leaf = depth 3 > max 2 (content irrelevant —
        // the cap is checked before any crypto).
        let chain = CertChain::new(leaf, vec![inter.clone(), inter]);
        let err = chain
            .verify(&bundle, NOW, DEFAULT_MAX_CHAIN_DEPTH)
            .unwrap_err();
        assert_eq!(err, ChainError::ChainTooDeep { depth: 3, max: 2 });
        assert_eq!(err.tag(), "chain_too_deep");
    }

    #[test]
    fn name_mismatch_between_levels_is_rejected() {
        let root = signing_key(20);
        let intermediate = signing_key(21);
        let node = signing_key(22);
        let inter_cert = mint(
            &root,
            "root",
            "region/nyc/ca",
            &intermediate.verifying_key(),
            DOMAIN,
            NOW + 7200,
        );
        // Leaf claims a DIFFERENT issuer name than the intermediate's subject.
        let leaf = mint(
            &intermediate,
            "region/sfo/ca",
            "region/nyc/node-1",
            &node.verifying_key(),
            DOMAIN,
            NOW + 3600,
        );
        let bundle = TrustBundle::new().with_issuer("root", root.verifying_key());
        let err = CertChain::new(leaf, vec![inter_cert])
            .verify(&bundle, NOW, DEFAULT_MAX_CHAIN_DEPTH)
            .unwrap_err();
        assert_eq!(err, ChainError::NameMismatch);
    }

    #[test]
    fn domain_mismatch_between_levels_is_rejected() {
        let root = signing_key(30);
        let intermediate = signing_key(31);
        let node = signing_key(32);
        let inter_cert = mint(
            &root,
            "root",
            "region/nyc/ca",
            &intermediate.verifying_key(),
            DOMAIN,
            NOW + 7200,
        );
        // Leaf rides a different trust domain than the intermediate.
        let leaf = mint(
            &intermediate,
            "region/nyc/ca",
            "region/nyc/node-1",
            &node.verifying_key(),
            "other.tenant",
            NOW + 3600,
        );
        let bundle = TrustBundle::new().with_issuer("root", root.verifying_key());
        let err = CertChain::new(leaf, vec![inter_cert])
            .verify(&bundle, NOW, DEFAULT_MAX_CHAIN_DEPTH)
            .unwrap_err();
        assert_eq!(err, ChainError::DomainMismatch);
    }

    #[test]
    fn rogue_intermediate_not_signed_by_root_is_rejected() {
        // Attacker self-signs an intermediate cert the root never vouched for.
        let root = signing_key(40);
        let attacker = signing_key(41);
        let node = signing_key(42);
        let rogue_inter = mint(
            &attacker,
            "root",
            "region/nyc/ca",
            &attacker.verifying_key(),
            DOMAIN,
            NOW + 7200,
        );
        let leaf = mint(
            &attacker,
            "region/nyc/ca",
            "region/nyc/node-1",
            &node.verifying_key(),
            DOMAIN,
            NOW + 3600,
        );
        let bundle = TrustBundle::new().with_issuer("root", root.verifying_key());
        let err = CertChain::new(leaf, vec![rogue_inter])
            .verify(&bundle, NOW, DEFAULT_MAX_CHAIN_DEPTH)
            .unwrap_err();
        // Anchor signature fails against the real root key.
        assert_eq!(err, ChainError::Link(CredentialError::BadSignature));
    }

    #[test]
    fn leaf_signed_by_wrong_key_is_bad_signature() {
        let (bundle, inter, _leaf) = two_level_setup();
        // Forge a leaf signed by a key that is NOT the intermediate.
        let imposter = signing_key(99);
        let node = signing_key(98);
        let forged_leaf = mint(
            &imposter,
            "region/nyc/ca",
            "region/nyc/node-1",
            &node.verifying_key(),
            DOMAIN,
            NOW + 3600,
        );
        let err = CertChain::new(forged_leaf, vec![inter])
            .verify(&bundle, NOW, DEFAULT_MAX_CHAIN_DEPTH)
            .unwrap_err();
        assert_eq!(err, ChainError::Link(CredentialError::BadSignature));
    }

    #[test]
    fn expired_intermediate_propagates_window_error() {
        let root = signing_key(50);
        let intermediate = signing_key(51);
        let node = signing_key(52);
        // Intermediate already expired at NOW.
        let inter_cert = mint(
            &root,
            "root",
            "region/nyc/ca",
            &intermediate.verifying_key(),
            DOMAIN,
            NOW - 1,
        );
        let leaf = mint(
            &intermediate,
            "region/nyc/ca",
            "region/nyc/node-1",
            &node.verifying_key(),
            DOMAIN,
            NOW + 3600,
        );
        let bundle = TrustBundle::new().with_issuer("root", root.verifying_key());
        let err = CertChain::new(leaf, vec![inter_cert])
            .verify(&bundle, NOW, DEFAULT_MAX_CHAIN_DEPTH)
            .unwrap_err();
        assert_eq!(err, ChainError::Link(CredentialError::Expired));
    }

    #[test]
    fn anchor_issuer_not_in_bundle_is_unknown_issuer() {
        let (_bundle, inter, leaf) = two_level_setup();
        // Bundle trusts a DIFFERENT root id than the intermediate names.
        let other_root = signing_key(60);
        let empty_for_root =
            TrustBundle::new().with_issuer("other-root", other_root.verifying_key());
        let err = CertChain::new(leaf, vec![inter])
            .verify(&empty_for_root, NOW, DEFAULT_MAX_CHAIN_DEPTH)
            .unwrap_err();
        assert_eq!(err, ChainError::Link(CredentialError::UnknownIssuer));
    }

    #[test]
    fn delegated_namespace_accepts_child_and_self_rejects_sibling() {
        // In-region child + the bare CA namespace pass.
        assert!(subject_in_delegated_namespace(
            "region/nyc/node-1",
            "region/nyc"
        ));
        assert!(subject_in_delegated_namespace("region/nyc", "region/nyc"));
        // Out-of-region + sibling-prefix are rejected.
        assert!(!subject_in_delegated_namespace(
            "region/sfo/node-9",
            "region/nyc"
        ));
        assert!(!subject_in_delegated_namespace(
            "region/nyceast/node-2",
            "region/nyc"
        ));
        // Root (empty namespace) delegates everything.
        assert!(subject_in_delegated_namespace("anything/at/all", ""));
    }
}
