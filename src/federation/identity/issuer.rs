// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! First-party federation credential issuer — the CA half of the trust
//! model.
//!
//! A [`FederationIssuer`] holds an Ed25519 signing key and mints
//! short-lived [`SignedCredential`]s that bind a node's `agent_id` to its
//! verifying key. Receivers trust the issuer's *verifying* key (published
//! into a [`super::trust_bundle::TrustBundle`]) and thereby trust every
//! credential it signs — the O(1) replacement for O(N²) per-peer `.pub`
//! enrollment.
//!
//! ## Attestation
//!
//! Who is allowed to receive a credential for `agent_id` X? That gate is
//! [`AttestationMap`]: it maps an *attested identity* — the mTLS-verified
//! peer identity the TLS layer already extracts (cert CN / SAN) — to the
//! `agent_id` the issuer is willing to vouch for. An empty map is
//! *passthrough* (zero-config: the attested mTLS identity IS the subject);
//! a populated map is a strict allowlist (an unmapped identity is denied).
//! This keeps the heavy X.509 parsing at the TLS boundary and leaves the
//! issuer reasoning over a clean identity string.
//!
//! The issuer takes `now_unix` as an explicit parameter (the same testable
//! convention as [`SignedCredential::verify_against`]); the renewal timer
//! in P3 supplies the real wall clock.

use std::collections::BTreeMap;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};

use super::chain::CertChain;
use super::credential::{CredentialError, FederationCredential, SignedCredential};

/// Default credential lifetime. Short by design so a leaked credential
/// self-expires quickly; the P3 renewal timer re-mints well before expiry.
pub const DEFAULT_CREDENTIAL_TTL_SECS: i64 = crate::SECS_PER_HOUR;

/// Default clock-skew allowance applied to `not_before` so a freshly
/// minted credential is not rejected as `NotYetValid` by a verifier whose
/// clock trails the issuer's by a few seconds.
pub const DEFAULT_CLOCK_SKEW_SECS: i64 = 30;

/// Default lifetime for an *intermediate CA* credential. Longer than a
/// leaf TTL — an intermediate is itself re-minted by its parent on a
/// slower cadence than the leaves it signs — but still bounded so a
/// compromised region key self-expires without a manual revocation list.
pub const DEFAULT_INTERMEDIATE_TTL_SECS: i64 = crate::SECS_PER_DAY;

/// Reasons issuance fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerError {
    /// The attested identity is not permitted to receive a credential (the
    /// attestation map is a non-empty allowlist and the identity is absent).
    AttestationDenied,
    /// The issuer was loaded from disk but no private signing key was found.
    MissingPrivateKey,
    /// The requested TTL is not strictly positive.
    InvalidTtl,
    /// A credential-layer error surfaced while signing.
    Credential(CredentialError),
    /// An I/O error surfaced while loading the issuer key from disk.
    Io(String),
}

impl IssuerError {
    /// Stable machine-readable tag for logs + JSON error envelopes.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::AttestationDenied => "issuer_attestation_denied",
            Self::MissingPrivateKey => "issuer_missing_private_key",
            Self::InvalidTtl => "issuer_invalid_ttl",
            Self::Credential(e) => e.tag(),
            Self::Io(_) => "issuer_io_error",
        }
    }
}

impl std::fmt::Display for IssuerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Credential(e) => write!(f, "{e}"),
            Self::Io(msg) => write!(f, "{} ({msg})", self.tag()),
            _ => f.write_str(self.tag()),
        }
    }
}

impl std::error::Error for IssuerError {}

impl From<CredentialError> for IssuerError {
    fn from(e: CredentialError) -> Self {
        Self::Credential(e)
    }
}

/// Issuer configuration: identity, trust domain, and lifetime knobs.
#[derive(Debug, Clone)]
pub struct IssuerConfig {
    /// The `issuer_id` stamped into every minted credential. Receivers key
    /// their trust bundle on this string.
    pub issuer_id: String,
    /// The `trust_domain` stamped into every minted credential.
    pub trust_domain: String,
    /// Default credential lifetime in seconds.
    pub ttl_secs: i64,
    /// Clock-skew allowance applied to `not_before`.
    pub clock_skew_secs: i64,
}

impl IssuerConfig {
    /// Build a config with the default TTL + skew.
    #[must_use]
    pub fn new(issuer_id: impl Into<String>, trust_domain: impl Into<String>) -> Self {
        Self {
            issuer_id: issuer_id.into(),
            trust_domain: trust_domain.into(),
            ttl_secs: DEFAULT_CREDENTIAL_TTL_SECS,
            clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
        }
    }

    /// Override the default credential lifetime (builder form).
    #[must_use]
    pub fn with_ttl_secs(mut self, ttl_secs: i64) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }
}

/// The first-party CA: an Ed25519 signing key plus issuance policy.
#[derive(Debug, Clone)]
pub struct FederationIssuer {
    signing_key: SigningKey,
    config: IssuerConfig,
}

impl FederationIssuer {
    /// Construct an issuer from an in-memory signing key + config.
    #[must_use]
    pub fn new(signing_key: SigningKey, config: IssuerConfig) -> Self {
        Self {
            signing_key,
            config,
        }
    }

    /// Load the issuer signing key from `<key_dir>/<issuer_id>.priv`
    /// (the substrate's raw-32-byte keypair format) and construct an issuer.
    ///
    /// # Errors
    /// - [`IssuerError::Io`] if the key file cannot be read / parsed.
    /// - [`IssuerError::MissingPrivateKey`] if only a public key is present.
    pub fn load(config: IssuerConfig, key_dir: &Path) -> Result<Self, IssuerError> {
        let keypair = crate::identity::keypair::load(&config.issuer_id, key_dir)
            .map_err(|e| IssuerError::Io(e.to_string()))?;
        let signing_key = keypair.private.ok_or(IssuerError::MissingPrivateKey)?;
        Ok(Self::new(signing_key, config))
    }

    /// The issuer identity stamped into minted credentials.
    #[must_use]
    pub fn issuer_id(&self) -> &str {
        &self.config.issuer_id
    }

    /// The issuer's verifying key — publish this into receivers' trust
    /// bundles so they accept credentials this issuer signs.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Mint a credential for `subject_agent_id` bound to `subject_pubkey`,
    /// using the issuer's default TTL.
    ///
    /// # Errors
    /// See [`Self::issue_with_ttl`].
    pub fn issue(
        &self,
        subject_agent_id: impl Into<String>,
        subject_pubkey: &VerifyingKey,
        now_unix: i64,
    ) -> Result<SignedCredential, IssuerError> {
        self.issue_with_ttl(
            subject_agent_id,
            subject_pubkey,
            self.config.ttl_secs,
            now_unix,
        )
    }

    /// Mint a credential with an explicit TTL.
    ///
    /// # Errors
    /// - [`IssuerError::InvalidTtl`] when `ttl_secs <= 0`.
    /// - [`IssuerError::Credential`] when signing fails.
    pub fn issue_with_ttl(
        &self,
        subject_agent_id: impl Into<String>,
        subject_pubkey: &VerifyingKey,
        ttl_secs: i64,
        now_unix: i64,
    ) -> Result<SignedCredential, IssuerError> {
        if ttl_secs <= 0 {
            return Err(IssuerError::InvalidTtl);
        }
        let cred = FederationCredential {
            subject_agent_id: subject_agent_id.into(),
            subject_pubkey: subject_pubkey.to_bytes(),
            issuer_id: self.config.issuer_id.clone(),
            trust_domain: self.config.trust_domain.clone(),
            not_before: now_unix - self.config.clock_skew_secs,
            not_after: now_unix + ttl_secs,
            cred_version: super::credential::CRED_VERSION,
        };
        Ok(cred.sign(&self.signing_key)?)
    }

    /// Mint an *intermediate CA* credential: a [`SignedCredential`] whose
    /// subject is another issuer's identity (`intermediate_id`) bound to
    /// that issuer's verifying key, signed by this (parent/root) issuer.
    ///
    /// Structurally this is an ordinary credential — there is no separate
    /// "CA cert" wire type. It becomes the anchor link of a
    /// [`super::chain::CertChain`]: a receiver that trusts *this* issuer's
    /// key thereby trusts every leaf the intermediate signs, without ever
    /// enrolling the intermediate's key directly. `intermediate_id` MUST
    /// equal the intermediate issuer's own `issuer_id` — that name binding
    /// (`child.issuer_id == parent.subject_agent_id`) is what
    /// [`super::chain::CertChain::verify`] enforces between links.
    ///
    /// Uses [`DEFAULT_INTERMEDIATE_TTL_SECS`]; call
    /// [`Self::issue_with_ttl`] directly for a custom intermediate lifetime.
    ///
    /// # Errors
    /// See [`Self::issue_with_ttl`].
    pub fn issue_intermediate(
        &self,
        intermediate_id: impl Into<String>,
        intermediate_pubkey: &VerifyingKey,
        now_unix: i64,
    ) -> Result<SignedCredential, IssuerError> {
        self.issue_with_ttl(
            intermediate_id,
            intermediate_pubkey,
            DEFAULT_INTERMEDIATE_TTL_SECS,
            now_unix,
        )
    }

    /// Mint a leaf credential for `subject_agent_id` and assemble it into a
    /// [`CertChain`] anchored by `intermediates`.
    ///
    /// `intermediates` is anchor-first: the root-signed credential for
    /// *this* (intermediate) issuer comes first, then any deeper links, so
    /// the chain reads root → … → this-issuer → leaf. A receiver verifies
    /// the whole chain against a trust bundle holding only the *root* key —
    /// this is the outbound-path assembly that lets a region node present
    /// one self-contained chain instead of requiring the receiver to
    /// pre-enroll every intermediate.
    ///
    /// Pass an empty `intermediates` to produce a single-level chain
    /// equivalent to a bare [`Self::issue`] (back-compat with P2/P3).
    ///
    /// # Errors
    /// See [`Self::issue_with_ttl`].
    pub fn issue_chained(
        &self,
        subject_agent_id: impl Into<String>,
        subject_pubkey: &VerifyingKey,
        intermediates: Vec<SignedCredential>,
        now_unix: i64,
    ) -> Result<CertChain, IssuerError> {
        let leaf = self.issue(subject_agent_id, subject_pubkey, now_unix)?;
        Ok(CertChain::new(leaf, intermediates))
    }

    /// Mint a credential for a peer whose mTLS identity has been attested.
    /// The `attestation` map resolves `attested_identity` to the
    /// `subject_agent_id` the issuer will vouch for; passthrough maps use
    /// the attested identity verbatim.
    ///
    /// # Errors
    /// - [`IssuerError::AttestationDenied`] when the identity is not
    ///   permitted by a non-empty allowlist.
    /// - Otherwise as [`Self::issue`].
    pub fn issue_for_attested(
        &self,
        attested_identity: &str,
        attestation: &AttestationMap,
        subject_pubkey: &VerifyingKey,
        now_unix: i64,
    ) -> Result<SignedCredential, IssuerError> {
        let subject_agent_id = attestation
            .resolve(attested_identity)
            .ok_or(IssuerError::AttestationDenied)?;
        self.issue(subject_agent_id, subject_pubkey, now_unix)
    }
}

/// Maps an attested mTLS identity to the `agent_id` the issuer will vouch
/// for. Empty = passthrough (the attested identity is the subject);
/// non-empty = strict allowlist (an unmapped identity is denied).
#[derive(Debug, Clone, Default)]
pub struct AttestationMap {
    entries: BTreeMap<String, String>,
}

impl AttestationMap {
    /// An empty (passthrough) map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an `attested_identity -> agent_id` mapping (builder form).
    #[must_use]
    pub fn with_mapping(
        mut self,
        attested_identity: impl Into<String>,
        agent_id: impl Into<String>,
    ) -> Self {
        self.entries
            .insert(attested_identity.into(), agent_id.into());
        self
    }

    /// Add an `attested_identity -> agent_id` mapping (mutating form).
    pub fn insert(&mut self, attested_identity: impl Into<String>, agent_id: impl Into<String>) {
        self.entries
            .insert(attested_identity.into(), agent_id.into());
    }

    /// Whether this map is passthrough (no explicit mappings).
    #[must_use]
    pub fn is_passthrough(&self) -> bool {
        self.entries.is_empty()
    }

    /// Resolve an attested identity to the `agent_id` to issue for. A
    /// passthrough map returns the identity verbatim; a populated map
    /// returns the mapped value or `None` (deny) for an unmapped identity.
    #[must_use]
    pub fn resolve(&self, attested_identity: &str) -> Option<String> {
        if self.entries.is_empty() {
            return Some(attested_identity.to_string());
        }
        self.entries.get(attested_identity).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer(seed: u8) -> FederationIssuer {
        let key = SigningKey::from_bytes(&[seed; 32]);
        FederationIssuer::new(key, IssuerConfig::new("root-ca", "fleet.example"))
    }

    fn subject_key(seed: u8) -> VerifyingKey {
        SigningKey::from_bytes(&[seed; 32]).verifying_key()
    }

    #[test]
    fn issued_credential_verifies_against_issuer_key() {
        let iss = issuer(1);
        let now = 1_900_000_000;
        let subj = subject_key(50);
        let signed = iss.issue("region/nyc/node-1", &subj, now).expect("issue");
        signed
            .verify_against(&iss.verifying_key(), now)
            .expect("issued credential verifies");
        assert_eq!(signed.credential().issuer_id, "root-ca");
        assert_eq!(signed.credential().trust_domain, "fleet.example");
        assert_eq!(signed.credential().subject_agent_id, "region/nyc/node-1");
        assert_eq!(signed.credential().subject_pubkey, subj.to_bytes());
    }

    #[test]
    fn default_ttl_window_brackets_now() {
        let iss = issuer(2);
        let now = 1_900_000_000;
        let signed = iss.issue("node", &subject_key(51), now).expect("issue");
        let cred = signed.credential();
        assert_eq!(cred.not_before, now - DEFAULT_CLOCK_SKEW_SECS);
        assert_eq!(cred.not_after, now + DEFAULT_CREDENTIAL_TTL_SECS);
    }

    #[test]
    fn zero_or_negative_ttl_is_rejected() {
        let iss = issuer(3);
        let now = 1_900_000_000;
        assert_eq!(
            iss.issue_with_ttl("node", &subject_key(52), 0, now)
                .unwrap_err(),
            IssuerError::InvalidTtl
        );
        assert_eq!(
            iss.issue_with_ttl("node", &subject_key(52), -10, now)
                .unwrap_err(),
            IssuerError::InvalidTtl
        );
    }

    #[test]
    fn custom_ttl_is_honoured() {
        let iss = issuer(4);
        let now = 1_900_000_000;
        let signed = iss
            .issue_with_ttl("node", &subject_key(53), 300, now)
            .expect("issue");
        assert_eq!(signed.credential().not_after, now + 300);
    }

    #[test]
    fn passthrough_attestation_uses_identity_verbatim() {
        let iss = issuer(5);
        let now = 1_900_000_000;
        let map = AttestationMap::new();
        assert!(map.is_passthrough());
        let signed = iss
            .issue_for_attested("region/sfo/node-9", &map, &subject_key(54), now)
            .expect("issue");
        assert_eq!(signed.credential().subject_agent_id, "region/sfo/node-9");
    }

    #[test]
    fn allowlist_attestation_maps_identity() {
        let iss = issuer(6);
        let now = 1_900_000_000;
        let map = AttestationMap::new().with_mapping("CN=node9.fleet", "region/sfo/node-9");
        let signed = iss
            .issue_for_attested("CN=node9.fleet", &map, &subject_key(55), now)
            .expect("issue");
        assert_eq!(signed.credential().subject_agent_id, "region/sfo/node-9");
    }

    #[test]
    fn allowlist_denies_unmapped_identity() {
        let iss = issuer(7);
        let now = 1_900_000_000;
        let map = AttestationMap::new().with_mapping("CN=node9.fleet", "region/sfo/node-9");
        assert_eq!(
            iss.issue_for_attested("CN=intruder", &map, &subject_key(56), now)
                .unwrap_err(),
            IssuerError::AttestationDenied
        );
    }

    #[test]
    fn issuer_round_trips_through_trust_bundle() {
        use super::super::trust_bundle::TrustBundle;
        let iss = issuer(8);
        let now = 1_900_000_000;
        let bundle = TrustBundle::new().with_issuer(iss.issuer_id(), iss.verifying_key());
        let signed = iss.issue("node", &subject_key(57), now).expect("issue");
        let cred = bundle
            .verify(&signed, now)
            .expect("bundle verifies issued cred");
        assert_eq!(cred.subject_agent_id, "node");
    }

    #[test]
    fn load_missing_private_key_is_error() {
        // A public-only keypair on disk must surface MissingPrivateKey.
        let tmp = tempfile::tempdir().expect("tempdir");
        let kp = crate::identity::keypair::generate("some-ca").expect("gen");
        crate::identity::keypair::save_public_only(&kp, tmp.path()).expect("save pub");
        let err = FederationIssuer::load(IssuerConfig::new("some-ca", "fleet.example"), tmp.path())
            .unwrap_err();
        assert_eq!(err, IssuerError::MissingPrivateKey);
    }

    #[test]
    fn intermediate_credential_uses_intermediate_ttl() {
        let root = issuer(20);
        let now = 1_900_000_000;
        let region_key = subject_key(60);
        let anchor = root
            .issue_intermediate("region/nyc/ca", &region_key, now)
            .expect("issue intermediate");
        let cred = anchor.credential();
        assert_eq!(cred.subject_agent_id, "region/nyc/ca");
        assert_eq!(cred.subject_pubkey, region_key.to_bytes());
        assert_eq!(cred.not_after, now + DEFAULT_INTERMEDIATE_TTL_SECS);
        anchor
            .verify_against(&root.verifying_key(), now)
            .expect("intermediate verifies under root key");
    }

    #[test]
    fn issue_chained_assembles_root_verifiable_two_level_chain() {
        use super::super::chain::{CertChain, DEFAULT_MAX_CHAIN_DEPTH};
        use super::super::trust_bundle::TrustBundle;
        let now = 1_900_000_000;

        // Root mints an intermediate CA for region/nyc.
        let root = issuer(21);
        let region_signing = SigningKey::from_bytes(&[70; 32]);
        let region = FederationIssuer::new(
            region_signing.clone(),
            IssuerConfig::new("region/nyc/ca", "fleet.example"),
        );
        let anchor = root
            .issue_intermediate(region.issuer_id(), &region.verifying_key(), now)
            .expect("issue intermediate");

        // Region issuer mints a leaf for a node + wraps the chain.
        let node_key = subject_key(71);
        let chain: CertChain = region
            .issue_chained("region/nyc/node-1", &node_key, vec![anchor], now)
            .expect("issue chained");
        assert_eq!(chain.depth(), 2);

        // A receiver trusting ONLY the root key verifies the whole chain.
        let bundle = TrustBundle::new().with_issuer(root.issuer_id(), root.verifying_key());
        let verified = chain
            .verify(&bundle, now, DEFAULT_MAX_CHAIN_DEPTH)
            .expect("chain verifies against root-only bundle");
        assert_eq!(verified.subject_agent_id, "region/nyc/node-1");
        assert_eq!(verified.subject_pubkey, node_key.to_bytes());
    }

    #[test]
    fn issue_chained_with_no_intermediates_is_single_level() {
        use super::super::chain::{CertChain, DEFAULT_MAX_CHAIN_DEPTH};
        use super::super::trust_bundle::TrustBundle;
        let iss = issuer(22);
        let now = 1_900_000_000;
        let node_key = subject_key(72);
        let chain: CertChain = iss
            .issue_chained("node", &node_key, vec![], now)
            .expect("issue chained");
        assert_eq!(chain.depth(), 1);
        let bundle = TrustBundle::new().with_issuer(iss.issuer_id(), iss.verifying_key());
        let verified = chain
            .verify(&bundle, now, DEFAULT_MAX_CHAIN_DEPTH)
            .expect("single-level chain verifies");
        assert_eq!(verified.subject_agent_id, "node");
    }

    #[test]
    fn load_reads_signing_key_and_issues() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let kp = crate::identity::keypair::generate("disk-ca").expect("gen");
        crate::identity::keypair::save(&kp, tmp.path()).expect("save");
        let iss = FederationIssuer::load(IssuerConfig::new("disk-ca", "fleet.example"), tmp.path())
            .expect("load");
        let now = 1_900_000_000;
        let signed = iss.issue("node", &subject_key(58), now).expect("issue");
        signed
            .verify_against(&kp.public, now)
            .expect("issued cred verifies under the on-disk key");
    }
}
