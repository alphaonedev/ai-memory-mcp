// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Federation trust bundle — the set of issuer verifying keys a receiver
//! trusts to mint [`FederationCredential`]s.
//!
//! This is the O(1) replacement for the O(N²) per-peer `.pub` allowlist:
//! instead of enrolling every peer's key, a receiver enrols a handful of
//! *issuer* keys (typically one CA, plus region intermediates in P4) and
//! trusts any credential they sign. When a peer presents a credential,
//! [`TrustBundle::verify`] looks the credential's `issuer_id` up in the
//! bundle, verifies the issuer signature + validity window, and — if the
//! bundle is domain-scoped — enforces `trust_domain` isolation.
//!
//! ## On-disk format
//!
//! [`TrustBundle::from_dir`] reads `<dir>/<issuer_id>.pub` files, each the
//! raw 32-byte `VerifyingKey::to_bytes()` encoding used everywhere else in
//! the substrate ([`crate::identity::keypair`]). The directory is named by
//! the [`TRUST_BUNDLE_DIR_ENV`] environment variable; when unset the
//! bundle is empty and the receiver transparently falls back to the legacy
//! per-peer `.pub` verify path (no live-hive partition during rollout).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use ed25519_dalek::VerifyingKey;

use super::credential::{CredentialError, FederationCredential, SignedCredential};

/// Environment variable naming the directory of trusted issuer public
/// keys (`<issuer_id>.pub`, raw 32 bytes each). Unset ⇒ empty bundle ⇒
/// the receiver keeps using the legacy per-peer `.pub` verify path.
pub const TRUST_BUNDLE_DIR_ENV: &str = "AI_MEMORY_FED_TRUST_BUNDLE_DIR";

/// Environment variable scoping a bundle to a single `trust_domain`. When
/// set, [`TrustBundle::verify`] refuses any credential whose `trust_domain`
/// differs, even if the issuer signature is valid — multi-tenant isolation
/// so a credential minted for one fleet can't be replayed into another.
pub const TRUST_DOMAIN_ENV: &str = "AI_MEMORY_FED_TRUST_DOMAIN";

/// On-disk suffix for an issuer public-key file. Mirrors
/// [`crate::identity::keypair`]'s `.pub` convention.
const ISSUER_PUB_SUFFIX: &str = ".pub";

/// Length of a raw Ed25519 verifying key on disk.
const VERIFYING_KEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

/// A set of trusted issuer keys, optionally scoped to a single trust
/// domain. Cheap to clone the handle is not needed — it lives behind an
/// `Arc` in the federation config, built once at boot.
#[derive(Debug, Clone, Default)]
pub struct TrustBundle {
    issuers: BTreeMap<String, VerifyingKey>,
    trust_domain: Option<String>,
}

impl TrustBundle {
    /// An empty bundle. A receiver holding an empty bundle verifies no
    /// credentials and falls back to the legacy per-peer path.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scope this bundle to a single `trust_domain`. Credentials carrying a
    /// different domain are refused with [`CredentialError::WrongTrustDomain`].
    #[must_use]
    pub fn with_trust_domain(mut self, trust_domain: impl Into<String>) -> Self {
        let domain = trust_domain.into();
        self.trust_domain = if domain.is_empty() {
            None
        } else {
            Some(domain)
        };
        self
    }

    /// Add a trusted issuer key (builder form).
    #[must_use]
    pub fn with_issuer(mut self, issuer_id: impl Into<String>, key: VerifyingKey) -> Self {
        self.issuers.insert(issuer_id.into(), key);
        self
    }

    /// Add a trusted issuer key (mutating form).
    pub fn insert(&mut self, issuer_id: impl Into<String>, key: VerifyingKey) {
        self.issuers.insert(issuer_id.into(), key);
    }

    /// Number of trusted issuers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.issuers.len()
    }

    /// Whether the bundle trusts no issuers — the signal a receiver uses to
    /// decide it must fall back to the legacy per-peer verify path.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.issuers.is_empty()
    }

    /// The trust domain this bundle is scoped to, if any.
    #[must_use]
    pub fn trust_domain(&self) -> Option<&str> {
        self.trust_domain.as_deref()
    }

    /// Verify a presented credential against this bundle: the issuer must be
    /// trusted, the issuer signature must verify over the exact carried
    /// claim bytes, the validity window must contain `now_unix`, and — when
    /// the bundle is domain-scoped — the `trust_domain` must match.
    ///
    /// On success returns the verified [`FederationCredential`] whose
    /// `subject_pubkey` the caller then uses as the peer's verifying key.
    /// Identity binding (does `subject_agent_id` match the wire `peer_id`?)
    /// stays the caller's responsibility — the same split as
    /// [`SignedCredential::verify_against`].
    ///
    /// # Errors
    /// - [`CredentialError::UnknownIssuer`] when no key is enrolled for the
    ///   credential's `issuer_id`.
    /// - [`CredentialError::WrongTrustDomain`] when the bundle is scoped and
    ///   the domains differ.
    /// - Any error surfaced by [`SignedCredential::verify_against`]
    ///   (`BadSignature`, `NotYetValid`, `Expired`, `UnsupportedVersion`).
    pub fn verify(
        &self,
        signed: &SignedCredential,
        now_unix: i64,
    ) -> Result<FederationCredential, CredentialError> {
        let cred = signed.credential();
        if let Some(domain) = &self.trust_domain
            && &cred.trust_domain != domain
        {
            return Err(CredentialError::WrongTrustDomain);
        }
        let issuer_key = self
            .issuers
            .get(&cred.issuer_id)
            .ok_or(CredentialError::UnknownIssuer)?;
        signed.verify_against(issuer_key, now_unix)?;
        Ok(cred.clone())
    }

    /// Load a bundle from a directory of `<issuer_id>.pub` files (raw
    /// 32-byte verifying keys). A missing directory yields an empty bundle
    /// (not an error) so an un-provisioned node degrades to the legacy path.
    /// Files that are not exactly [`VERIFYING_KEY_LEN`] bytes, or not valid
    /// Edwards points, are skipped with a WARN rather than failing the whole
    /// load — one corrupt key must not deny trust in every other issuer.
    ///
    /// # Errors
    /// Returns an error only when the directory exists but cannot be read
    /// (permissions, I/O fault).
    pub fn from_dir(dir: &Path) -> std::io::Result<Self> {
        let mut bundle = Self::new();
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(bundle),
            Err(err) => return Err(err),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let Some(issuer_id) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(ISSUER_PUB_SUFFIX))
            else {
                continue;
            };
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(err) => {
                    tracing::warn!(issuer = issuer_id, error = %err, "skipping unreadable issuer key");
                    continue;
                }
            };
            match verifying_key_from_bytes(&bytes) {
                Some(key) => {
                    bundle.insert(issuer_id.to_string(), key);
                }
                None => {
                    tracing::warn!(
                        issuer = issuer_id,
                        len = bytes.len(),
                        "skipping malformed issuer key (not a 32-byte Ed25519 point)"
                    );
                }
            }
        }
        Ok(bundle)
    }

    /// Build the bundle a daemon trusts at boot from the environment: the
    /// directory named by [`TRUST_BUNDLE_DIR_ENV`], scoped to the domain
    /// named by [`TRUST_DOMAIN_ENV`]. Both unset ⇒ an empty, unscoped
    /// bundle ⇒ legacy per-peer verify path.
    ///
    /// # Errors
    /// Propagates an I/O error from [`Self::from_dir`] when the configured
    /// directory exists but cannot be read.
    pub fn load_from_env() -> std::io::Result<Self> {
        let mut bundle = match std::env::var(TRUST_BUNDLE_DIR_ENV) {
            Ok(dir) if !dir.is_empty() => Self::from_dir(Path::new(&dir))?,
            _ => Self::new(),
        };
        if let Ok(domain) = std::env::var(TRUST_DOMAIN_ENV)
            && !domain.is_empty()
        {
            bundle.trust_domain = Some(domain);
        }
        Ok(bundle)
    }
}

/// Decode a raw 32-byte Ed25519 verifying key, returning `None` on a wrong
/// length or a non-canonical point.
fn verifying_key_from_bytes(bytes: &[u8]) -> Option<VerifyingKey> {
    let arr: [u8; VERIFYING_KEY_LEN] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sample_signed(
        ca: &SigningKey,
        issuer_id: &str,
        trust_domain: &str,
        now: i64,
    ) -> SignedCredential {
        let subject = signing_key(200);
        FederationCredential {
            subject_agent_id: "region/nyc/node-1".to_string(),
            subject_pubkey: subject.verifying_key().to_bytes(),
            issuer_id: issuer_id.to_string(),
            trust_domain: trust_domain.to_string(),
            not_before: now - 10,
            not_after: now + 3600,
            cred_version: super::super::credential::CRED_VERSION,
        }
        .sign(ca)
        .expect("sign")
    }

    #[test]
    fn trusted_issuer_verifies() {
        let ca = signing_key(1);
        let now = 1_900_000_000;
        let bundle = TrustBundle::new().with_issuer("root", ca.verifying_key());
        let signed = sample_signed(&ca, "root", "fleet.example", now);
        let cred = bundle.verify(&signed, now).expect("verifies");
        assert_eq!(cred.issuer_id, "root");
    }

    #[test]
    fn unknown_issuer_is_rejected() {
        let ca = signing_key(2);
        let now = 1_900_000_000;
        let bundle = TrustBundle::new().with_issuer("root", ca.verifying_key());
        let signed = sample_signed(&ca, "other-ca", "fleet.example", now);
        assert_eq!(
            bundle.verify(&signed, now).unwrap_err(),
            CredentialError::UnknownIssuer
        );
    }

    #[test]
    fn wrong_issuer_key_for_known_id_is_bad_signature() {
        let real = signing_key(3);
        let attacker = signing_key(4);
        let now = 1_900_000_000;
        // Bundle trusts "root" but with the attacker's key; the credential
        // was signed by the real key, so the signature must fail.
        let bundle = TrustBundle::new().with_issuer("root", attacker.verifying_key());
        let signed = sample_signed(&real, "root", "fleet.example", now);
        assert_eq!(
            bundle.verify(&signed, now).unwrap_err(),
            CredentialError::BadSignature
        );
    }

    #[test]
    fn domain_scoped_bundle_rejects_other_domain() {
        let ca = signing_key(5);
        let now = 1_900_000_000;
        let bundle = TrustBundle::new()
            .with_issuer("root", ca.verifying_key())
            .with_trust_domain("fleet.example");
        let signed = sample_signed(&ca, "root", "other.tenant", now);
        assert_eq!(
            bundle.verify(&signed, now).unwrap_err(),
            CredentialError::WrongTrustDomain
        );
    }

    #[test]
    fn domain_scoped_bundle_accepts_matching_domain() {
        let ca = signing_key(6);
        let now = 1_900_000_000;
        let bundle = TrustBundle::new()
            .with_issuer("root", ca.verifying_key())
            .with_trust_domain("fleet.example");
        let signed = sample_signed(&ca, "root", "fleet.example", now);
        bundle
            .verify(&signed, now)
            .expect("matching domain verifies");
    }

    #[test]
    fn expired_credential_propagates_window_error() {
        let ca = signing_key(7);
        let now = 1_900_000_000;
        let bundle = TrustBundle::new().with_issuer("root", ca.verifying_key());
        let signed = sample_signed(&ca, "root", "fleet.example", now);
        assert_eq!(
            bundle.verify(&signed, now + 100_000).unwrap_err(),
            CredentialError::Expired
        );
    }

    #[test]
    fn empty_bundle_is_empty() {
        let bundle = TrustBundle::new();
        assert!(bundle.is_empty());
        assert_eq!(bundle.len(), 0);
        assert!(bundle.trust_domain().is_none());
    }

    #[test]
    fn from_dir_missing_is_empty_not_error() {
        let dir = std::path::Path::new("/nonexistent/ai-memory-trust-bundle-xyz");
        let bundle = TrustBundle::from_dir(dir).expect("missing dir is not an error");
        assert!(bundle.is_empty());
    }

    #[test]
    fn from_dir_loads_pub_files_and_skips_malformed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ca = signing_key(9);
        // Valid issuer key.
        fs::write(tmp.path().join("root.pub"), ca.verifying_key().to_bytes()).expect("write valid");
        // Malformed key (wrong length) — must be skipped, not fatal.
        fs::write(tmp.path().join("broken.pub"), [0u8; 8]).expect("write broken");
        // Non-.pub file — ignored.
        fs::write(tmp.path().join("notes.txt"), b"ignore me").expect("write txt");

        let bundle = TrustBundle::from_dir(tmp.path()).expect("read dir");
        assert_eq!(bundle.len(), 1);

        let now = 1_900_000_000;
        let signed = sample_signed(&ca, "root", "fleet.example", now);
        bundle.verify(&signed, now).expect("loaded key verifies");
    }
}
