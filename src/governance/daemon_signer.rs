// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10074 — the ONE daemon signer: every daemon Ed25519 signature is made over
//! `DaemonDomain::tag() || body`, so a signature made for one meaning (a
//! `signed_events` row, a revision leaf, a forget tombstone, a governance
//! payload, the legacy cutoff) can never verify as another.
//!
//! The process-wide key is private to this module. There is no bytes-only
//! signer: [`sign`] takes a [`DaemonDomain`], and the source ratchet
//! `tests/daemon_signer_ratchet_10074.rs` holds that no other file reaches the
//! key or signs with it.

use std::sync::OnceLock;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// The meaning a daemon signature is made for. One variant per meaning; the
/// tag is the first bytes of the signed preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DaemonDomain {
    /// The identity-bound signature of one `signed_events` row
    /// (`signed_events::daemon_row_signing_input`).
    EventRow,
    /// The pre-append placeholder signature over a row's payload/cause input
    /// (`SignedEvent::with_daemon_signature`); the append path replaces it with
    /// an [`DaemonDomain::EventRow`] signature.
    EventPayload,
    /// A governance payload signature (`agent_action`, `deferred_audit`); the
    /// append path replaces it with an [`DaemonDomain::EventRow`] signature.
    Governance,
    /// A forget / evict tombstone (`storage::forget_tombstone_signable_bytes`).
    Tombstone,
    /// A memory revision leaf (`revisions::revision_leaf_signable_bytes`).
    RevisionLeaf,
    /// The one legacy cutoff row of a `signed_events` chain.
    LegacyCutoff,
}

/// decision: the tombstone and revision-leaf tags are the domain prefixes those
/// preimages already carried (`forget-tombstone-v1\0`, `memory-revision-v1\0`)
/// over minting new ones, because then every stored tombstone and leaf
/// signature stays byte-identical and verifiable (no stored bytes change).
const TAG_EVENT_ROW: &[u8] = b"ai-memory/daemon-sig/v2/event-row\0";
const TAG_EVENT_PAYLOAD: &[u8] = b"ai-memory/daemon-sig/v2/event-payload\0";
const TAG_GOVERNANCE: &[u8] = b"ai-memory/daemon-sig/v2/governance\0";
const TAG_TOMBSTONE: &[u8] = b"forget-tombstone-v1\x00";
const TAG_REVISION_LEAF: &[u8] = b"memory-revision-v1\x00";
const TAG_LEGACY_CUTOFF: &[u8] = b"ai-memory/daemon-sig/v2/legacy-cutoff\0";

impl DaemonDomain {
    /// Every domain, for the cross-domain tests.
    pub const ALL: [DaemonDomain; 6] = [
        DaemonDomain::EventRow,
        DaemonDomain::EventPayload,
        DaemonDomain::Governance,
        DaemonDomain::Tombstone,
        DaemonDomain::RevisionLeaf,
        DaemonDomain::LegacyCutoff,
    ];

    /// The domain tag prefixed to every preimage of this domain. No tag is a
    /// prefix of another, so two domains never share a preimage.
    #[must_use]
    pub const fn tag(self) -> &'static [u8] {
        match self {
            DaemonDomain::EventRow => TAG_EVENT_ROW,
            DaemonDomain::EventPayload => TAG_EVENT_PAYLOAD,
            DaemonDomain::Governance => TAG_GOVERNANCE,
            DaemonDomain::Tombstone => TAG_TOMBSTONE,
            DaemonDomain::RevisionLeaf => TAG_REVISION_LEAF,
            DaemonDomain::LegacyCutoff => TAG_LEGACY_CUTOFF,
        }
    }
}

static DAEMON_AUDIT_KEY: OnceLock<SigningKey> = OnceLock::new();

/// Install the process-wide daemon key. First install wins (one daemon, one
/// signing identity per process lifetime); returns `true` when this call
/// installed it.
pub(crate) fn install(key: &SigningKey) -> bool {
    DAEMON_AUDIT_KEY.set(key.clone()).is_ok()
}

/// `true` when a daemon key is installed.
#[must_use]
pub fn is_installed() -> bool {
    DAEMON_AUDIT_KEY.get().is_some()
}

/// The public half of the installed daemon key.
#[must_use]
pub fn verifying_key() -> Option<VerifyingKey> {
    DAEMON_AUDIT_KEY.get().map(SigningKey::verifying_key)
}

/// The exact bytes a daemon signature of `domain` over `body` is made over.
#[must_use]
pub fn preimage(domain: DaemonDomain, body: &[u8]) -> Vec<u8> {
    let tag = domain.tag();
    let mut out = Vec::with_capacity(tag.len() + body.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(body);
    out
}

/// Sign `body` under `domain` with the installed daemon key. Returns
/// `Some((signature, "daemon_signed"))`, or `None` when no key is installed.
#[must_use]
pub fn sign(domain: DaemonDomain, body: &[u8]) -> Option<(Vec<u8>, &'static str)> {
    let key = DAEMON_AUDIT_KEY.get()?;
    let sig: Signature = key.sign(&preimage(domain, body));
    Some((
        sig.to_bytes().to_vec(),
        crate::models::AttestLevel::DaemonSigned.as_str(),
    ))
}

/// `true` iff `signature` is a strict Ed25519 signature by `vk` over
/// `domain.tag() || body`.
#[must_use]
pub fn verify(vk: &VerifyingKey, domain: DaemonDomain, body: &[u8], signature: &[u8]) -> bool {
    let Ok(arr) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    vk.verify_strict(&preimage(domain, body), &Signature::from_bytes(&arr))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::{DaemonDomain, preimage};

    #[test]
    fn no_domain_tag_is_a_prefix_of_another_10074() {
        for a in DaemonDomain::ALL {
            for b in DaemonDomain::ALL {
                if a != b {
                    assert!(
                        !b.tag().starts_with(a.tag()),
                        "{a:?} tag is a prefix of {b:?} tag"
                    );
                }
            }
        }
    }

    #[test]
    fn preimage_is_tag_then_body_10074() {
        let p = preimage(DaemonDomain::EventRow, b"xyz");
        assert_eq!(p, b"ai-memory/daemon-sig/v2/event-row\0xyz");
    }

    mod chain_signer_10145 {
        use super::super::{DaemonChainSigner, DaemonKeyCause, DaemonKeyMissing};
        use crate::identity::keypair::AgentKeypair;
        use crate::signed_events::SignedEvent;
        use ed25519_dalek::SigningKey;

        const SEED: [u8; 32] = [7u8; 32];
        const OTHER_SEED: [u8; 32] = [9u8; 32];

        fn pair(seed: [u8; 32]) -> AgentKeypair {
            let key = SigningKey::from_bytes(&seed);
            AgentKeypair {
                agent_id: crate::identity::keypair::DAEMON_KEYPAIR_LABEL.to_string(),
                public: key.verifying_key(),
                private: Some(key),
            }
        }

        fn row() -> SignedEvent {
            SignedEvent {
                id: "row-10145".to_string(),
                agent_id: "ai-memory:migration-v103".to_string(),
                event_type: "signed_events.agent_cutover".to_string(),
                payload_hash: vec![3u8; 33],
                signature: None,
                attest_level: crate::models::AttestLevel::Unsigned.as_str().to_string(),
                timestamp: "2026-11-26T00:00:00+00:00".to_string(),
                prev_hash: vec![0u8; 32],
                sequence: 1,
                cause_hash: None,
            }
        }

        #[test]
        fn a_public_only_keypair_builds_no_chain_signer_10145() {
            let mut kp = pair(SEED);
            kp.private = None;
            let err = DaemonChainSigner::try_from(kp).expect_err("public-only must refuse");
            assert_eq!(err.cause(), DaemonKeyCause::PublicOnly);
        }

        #[test]
        fn a_mismatched_keypair_builds_no_chain_signer_10145() {
            let mut kp = pair(SEED);
            kp.public = SigningKey::from_bytes(&OTHER_SEED).verifying_key();
            let err = DaemonChainSigner::try_from(kp).expect_err("mismatch must refuse");
            assert_eq!(err.cause(), DaemonKeyCause::KeyMismatch);
        }

        #[test]
        fn a_signed_row_verifies_and_every_flipped_byte_fails_10145() {
            let signer = DaemonChainSigner::try_from(pair(SEED)).expect("full keypair");
            let vk = signer.verifying_key();
            let mut signed = row();
            signer.sign_row(&mut signed);
            assert_eq!(
                signed.attest_level,
                crate::models::AttestLevel::DaemonSigned.as_str()
            );
            assert_eq!(signed.signature.as_ref().map(Vec::len), Some(64));
            assert!(DaemonChainSigner::verify_row(&vk, &signed));
            let other = SigningKey::from_bytes(&OTHER_SEED).verifying_key();
            assert!(!DaemonChainSigner::verify_row(&other, &signed));
            for i in 0..signed.payload_hash.len() {
                let mut m = signed.clone();
                m.payload_hash[i] ^= 1;
                assert!(!DaemonChainSigner::verify_row(&vk, &m), "payload byte {i}");
            }
            for i in 0..64 {
                let mut m = signed.clone();
                if let Some(s) = m.signature.as_mut() {
                    s[i] ^= 1;
                }
                assert!(
                    !DaemonChainSigner::verify_row(&vk, &m),
                    "signature byte {i}"
                );
            }
            let mut m = signed.clone();
            m.sequence = 2;
            assert!(!DaemonChainSigner::verify_row(&vk, &m), "sequence");
            let mut m = signed.clone();
            m.attest_level = crate::models::AttestLevel::Unsigned.as_str().to_string();
            assert!(!DaemonChainSigner::verify_row(&vk, &m), "attest level");
            let mut m = signed;
            m.signature = None;
            assert!(!DaemonChainSigner::verify_row(&vk, &m), "no signature");
        }

        #[test]
        fn the_refusal_is_counted_and_names_the_provisioning_command_10145() {
            let before = super::super::daemon_key_missing_total();
            let err = DaemonKeyMissing::new(DaemonKeyCause::GenerationDisabled, None);
            assert!(super::super::daemon_key_missing_total() > before);
            let text = err.to_string();
            assert!(
                text.contains("ai-memory identity generate --agent-id daemon"),
                "{text}"
            );
            assert!(text.contains("AI_MEMORY_KEY_DIR"), "{text}");
            assert!(text.contains("ai-memory backup"), "{text}");
            assert!(text.contains("key generation is disabled"), "{text}");
        }
    }
}
