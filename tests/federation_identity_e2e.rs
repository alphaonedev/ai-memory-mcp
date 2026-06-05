// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Federation-identity-at-scale — end-to-end capstone.
//!
//! The per-module unit tests (under `src/federation/identity/*`) each
//! prove their own seam against `super::`-private helpers. This file is
//! the cross-module proof: it drives the CA-rooted credential path
//! exclusively through the *public crate API*
//! (`ai_memory::federation::identity::{issuer, trust_bundle, chain,
//! credential}`), the same surface a downstream embedder of the crate
//! sees. It ties the four FED phases together:
//!
//! - P2 issuer + credential — a root [`FederationIssuer`] mints a leaf,
//!   a receiver verifies it against a [`TrustBundle`] holding only the
//!   issuer key (the O(1)-enrollment property that replaces O(N²)
//!   per-peer `.pub` files).
//! - P4 hierarchical trust — a root mints an intermediate CA, the
//!   intermediate mints a leaf, and a receiver trusting ONLY the root
//!   key verifies the whole [`CertChain`] in one shot.
//! - Negative paths — broken name-binding, wrong trust domain, expiry,
//!   and over-deep chains are all rejected, proving the binding +
//!   window + domain checks are load-bearing end-to-end.
//!
//! Mirrors the H6 philosophy of `tests/identity_e2e.rs` for the OSS
//! attestation chain, but for the federation-credential CA path.

use ai_memory::federation::identity::chain::{CertChain, ChainError, DEFAULT_MAX_CHAIN_DEPTH};
use ai_memory::federation::identity::credential::CredentialError;
use ai_memory::federation::identity::issuer::{FederationIssuer, IssuerConfig};
use ai_memory::federation::identity::trust_bundle::TrustBundle;
use ed25519_dalek::{SigningKey, VerifyingKey};

const NOW: i64 = 1_900_000_000;
const TRUST_DOMAIN: &str = "fleet.example";

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn subject_key(seed: u8) -> VerifyingKey {
    signing_key(seed).verifying_key()
}

fn root_issuer(seed: u8, issuer_id: &str) -> FederationIssuer {
    FederationIssuer::new(
        signing_key(seed),
        IssuerConfig::new(issuer_id.to_string(), TRUST_DOMAIN),
    )
}

/// P2 single-level: a receiver enrolls only the issuer key and verifies
/// a leaf credential — the O(1)-trust property at the heart of the epic.
#[test]
fn single_level_credential_verifies_against_issuer_only_bundle() {
    let root = root_issuer(1, "root/ca");
    let node_key = subject_key(2);
    let signed = root
        .issue("region/nyc/node-1", &node_key, NOW)
        .expect("issue leaf");

    let bundle = TrustBundle::new()
        .with_trust_domain(TRUST_DOMAIN)
        .with_issuer(root.issuer_id(), root.verifying_key());

    let verified = bundle.verify(&signed, NOW).expect("leaf verifies");
    assert_eq!(verified.subject_agent_id, "region/nyc/node-1");
    assert_eq!(verified.subject_pubkey, node_key.to_bytes());
    assert_eq!(verified.trust_domain, TRUST_DOMAIN);
}

/// P4 hierarchical: root → intermediate → leaf, verified against a
/// root-ONLY bundle. The receiver never enrolls the intermediate key.
#[test]
fn two_level_chain_verifies_against_root_only_bundle() {
    let root = root_issuer(10, "root/ca");

    // Root mints an intermediate CA cert for the region issuer.
    let region = root_issuer(11, "region/nyc/ca");
    let anchor = root
        .issue_intermediate(region.issuer_id(), &region.verifying_key(), NOW)
        .expect("issue intermediate");

    // Region issuer mints a leaf and assembles the anchor-first chain.
    let node_key = subject_key(12);
    let chain: CertChain = region
        .issue_chained("region/nyc/node-1", &node_key, vec![anchor], NOW)
        .expect("issue chained");
    assert_eq!(chain.depth(), 2);

    let bundle = TrustBundle::new()
        .with_trust_domain(TRUST_DOMAIN)
        .with_issuer(root.issuer_id(), root.verifying_key());

    let verified = chain
        .verify(&bundle, NOW, DEFAULT_MAX_CHAIN_DEPTH)
        .expect("chain verifies against root-only bundle");
    assert_eq!(verified.subject_agent_id, "region/nyc/node-1");
    assert_eq!(verified.subject_pubkey, node_key.to_bytes());
}

/// A leaf whose `issuer_id` does not equal the intermediate's
/// `subject_agent_id` breaks the name binding the chain enforces.
#[test]
fn chain_rejects_broken_name_binding() {
    let root = root_issuer(20, "root/ca");

    // Root mints an intermediate for region/nyc/ca.
    let region = root_issuer(21, "region/nyc/ca");
    let anchor = root
        .issue_intermediate(region.issuer_id(), &region.verifying_key(), NOW)
        .expect("issue intermediate");

    // But a DIFFERENT (rogue) issuer mints the leaf and tries to ride
    // the region anchor — its leaf.issuer_id ("rogue/ca") != the
    // anchor's subject ("region/nyc/ca").
    let rogue = root_issuer(22, "rogue/ca");
    let node_key = subject_key(23);
    let leaf = rogue
        .issue("region/nyc/node-1", &node_key, NOW)
        .expect("rogue issues leaf");
    let chain = CertChain::new(leaf, vec![anchor]);

    let bundle = TrustBundle::new()
        .with_trust_domain(TRUST_DOMAIN)
        .with_issuer(root.issuer_id(), root.verifying_key());

    let err = chain
        .verify(&bundle, NOW, DEFAULT_MAX_CHAIN_DEPTH)
        .expect_err("broken name binding must reject");
    assert!(matches!(err, ChainError::NameMismatch), "got {err:?}");
}

/// A bundle scoped to one trust domain rejects a credential minted in a
/// different domain (multi-tenant isolation).
#[test]
fn verify_rejects_wrong_trust_domain() {
    let root = FederationIssuer::new(
        signing_key(30),
        IssuerConfig::new("root/ca".to_string(), "other.tenant"),
    );
    let signed = root
        .issue("node-1", &subject_key(31), NOW)
        .expect("issue leaf");

    let bundle = TrustBundle::new()
        .with_trust_domain(TRUST_DOMAIN)
        .with_issuer(root.issuer_id(), root.verifying_key());

    let err = bundle
        .verify(&signed, NOW)
        .expect_err("cross-domain credential must reject");
    assert!(
        matches!(err, CredentialError::WrongTrustDomain),
        "got {err:?}"
    );
}

/// A credential verified past its `not_after` window is rejected.
#[test]
fn verify_rejects_expired_credential() {
    let root = root_issuer(40, "root/ca");
    let signed = root
        .issue("node-1", &subject_key(41), NOW)
        .expect("issue leaf");

    let bundle = TrustBundle::new()
        .with_trust_domain(TRUST_DOMAIN)
        .with_issuer(root.issuer_id(), root.verifying_key());

    // Default leaf TTL is one hour; verify a day later.
    let later = NOW + ai_memory::SECS_PER_DAY;
    let err = bundle
        .verify(&signed, later)
        .expect_err("expired credential must reject");
    assert!(matches!(err, CredentialError::Expired), "got {err:?}");
}

/// A structurally valid two-level chain is still refused when the
/// caller caps `max_depth` below its depth.
#[test]
fn chain_rejects_when_deeper_than_max_depth() {
    let root = root_issuer(50, "root/ca");
    let region = root_issuer(51, "region/nyc/ca");
    let anchor = root
        .issue_intermediate(region.issuer_id(), &region.verifying_key(), NOW)
        .expect("issue intermediate");
    let chain = region
        .issue_chained("region/nyc/node-1", &subject_key(52), vec![anchor], NOW)
        .expect("issue chained");

    let bundle = TrustBundle::new()
        .with_trust_domain(TRUST_DOMAIN)
        .with_issuer(root.issuer_id(), root.verifying_key());

    let err = chain
        .verify(&bundle, NOW, 1)
        .expect_err("chain deeper than max_depth must reject");
    assert!(
        matches!(err, ChainError::ChainTooDeep { depth: 2, max: 1 }),
        "got {err:?}"
    );
}
