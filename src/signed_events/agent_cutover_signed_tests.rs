// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10145 (3-agent vote (71472661) V2-10108-KEYLESS-MARKER, K-1 / K-2, I-2,
//! I-9) — the signed genesis marker: built only with a
//! [`DaemonChainSigner`], it verifies under the daemon key and fails on any
//! altered byte, including its signed origin.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use super::{
    AgentCutover, MarkerOrigin, MarkerSignature, MarkerVerifier, build_signed_marker,
    resolve_signed, signed_marker_structure, verify_signed_marker,
};
use crate::governance::daemon_signer::DaemonChainSigner;
use crate::identity::keypair::{AgentKeypair, DAEMON_KEYPAIR_LABEL};
use crate::signed_events::{SignedEvent, ZERO_HASH, canonical_chain_bytes};

const SEED: [u8; 32] = [11u8; 32];
const OTHER_SEED: [u8; 32] = [12u8; 32];
const TS: &str = "2026-11-26T00:00:00+00:00";

fn signer(seed: [u8; 32]) -> DaemonChainSigner {
    let key = SigningKey::from_bytes(&seed);
    DaemonChainSigner::try_from(AgentKeypair {
        agent_id: DAEMON_KEYPAIR_LABEL.to_string(),
        public: key.verifying_key(),
        private: Some(key),
    })
    .expect("full keypair")
}

fn genesis(origin: MarkerOrigin) -> SignedEvent {
    build_signed_marker(&signer(SEED), None, 0, origin, "m-1".into(), TS.into())
        .expect("genesis marker")
        .into_event()
}

#[test]
fn a_signed_genesis_marker_verifies_under_the_daemon_key_10145() {
    let s = signer(SEED);
    let m = genesis(MarkerOrigin::Create);
    assert_eq!(m.sequence, 1);
    assert_eq!(m.prev_hash, ZERO_HASH.to_vec());
    assert_eq!(
        m.attest_level,
        crate::models::AttestLevel::DaemonSigned.as_str()
    );
    assert_eq!(m.signature.as_ref().map(Vec::len), Some(64));
    assert_eq!(
        verify_signed_marker(&s.verifying_key(), &m, None, 0),
        Some(MarkerOrigin::Create)
    );
    let other = signer(OTHER_SEED).verifying_key();
    assert_eq!(verify_signed_marker(&other, &m, None, 0), None);
}

#[test]
fn every_flipped_marker_byte_fails_10145() {
    let vk = signer(SEED).verifying_key();
    let m = genesis(MarkerOrigin::Migrate);
    for i in 0..m.payload_hash.len() {
        let mut x = m.clone();
        x.payload_hash[i] ^= 1;
        assert_eq!(verify_signed_marker(&vk, &x, None, 0), None, "payload {i}");
    }
    for i in 0..64 {
        let mut x = m.clone();
        if let Some(sig) = x.signature.as_mut() {
            sig[i] ^= 1;
        }
        assert_eq!(verify_signed_marker(&vk, &x, None, 0), None, "sig {i}");
    }
    for i in 0..m.prev_hash.len() {
        let mut x = m.clone();
        x.prev_hash[i] ^= 1;
        assert_eq!(verify_signed_marker(&vk, &x, None, 0), None, "prev {i}");
    }
    let mut x = m.clone();
    x.signature = None;
    assert_eq!(verify_signed_marker(&vk, &x, None, 0), None, "unsigned");
    let mut x = m.clone();
    x.attest_level = crate::models::AttestLevel::Unsigned.as_str().to_string();
    assert_eq!(verify_signed_marker(&vk, &x, None, 0), None, "attest");
    assert_eq!(verify_signed_marker(&vk, &m, None, 1), None, "legacy count");
}

#[test]
fn an_altered_origin_fails_even_when_re_signed_with_another_key_10145() {
    let vk = signer(SEED).verifying_key();
    for origin in MarkerOrigin::ALL {
        let m = genesis(origin);
        assert_eq!(verify_signed_marker(&vk, &m, None, 0), Some(origin));
        for other in MarkerOrigin::ALL {
            if other == origin {
                continue;
            }
            let mut x = m.clone();
            x.payload_hash[0] = other.byte();
            assert_eq!(verify_signed_marker(&vk, &x, None, 0), None, "{other:?}");
        }
    }
}

#[test]
fn exactly_three_origin_bytes_decode_10145() {
    for o in MarkerOrigin::ALL {
        assert_eq!(MarkerOrigin::from_byte(o.byte()), Some(o));
    }
    let decoded = (0..=u8::MAX)
        .filter(|b| MarkerOrigin::from_byte(*b).is_some())
        .count();
    assert_eq!(decoded, MarkerOrigin::ALL.len());
    assert_eq!(MarkerOrigin::ALL.len(), 3);
}

#[test]
fn a_marker_above_a_head_links_to_it_10145() {
    let s = signer(SEED);
    let head = SignedEvent {
        id: "h".into(),
        sequence: 4,
        payload_hash: vec![1u8; 32],
        prev_hash: vec![2u8; 32],
        ..SignedEvent::default()
    };
    let m = build_signed_marker(
        &s,
        Some(&head),
        2,
        MarkerOrigin::Migrate,
        "m".into(),
        TS.into(),
    )
    .expect("marker above head")
    .into_event();
    assert_eq!(m.sequence, 5);
    assert_eq!(
        m.prev_hash,
        Sha256::digest(canonical_chain_bytes(&head)).to_vec()
    );
    assert_eq!(
        verify_signed_marker(&s.verifying_key(), &m, Some(&head), 2),
        Some(MarkerOrigin::Migrate)
    );
    assert_eq!(verify_signed_marker(&s.verifying_key(), &m, None, 2), None);
    let max = SignedEvent {
        sequence: i64::MAX,
        ..head
    };
    assert!(
        build_signed_marker(
            &s,
            Some(&max),
            0,
            MarkerOrigin::Import,
            "m".into(),
            TS.into()
        )
        .is_none()
    );
}

/// #10195 — the marker shapes the resolver table covers.
#[derive(Debug, Clone, Copy)]
enum Shape {
    Valid,
    EditedPayload,
    FlippedSignature,
    StrippedSignature,
    ShortSignature,
    NotDaemonAttested,
    Duplicate,
    CorruptCount,
    NoMarker,
}

impl Shape {
    const ALL: [Self; 9] = [
        Self::Valid,
        Self::EditedPayload,
        Self::FlippedSignature,
        Self::StrippedSignature,
        Self::ShortSignature,
        Self::NotDaemonAttested,
        Self::Duplicate,
        Self::CorruptCount,
        Self::NoMarker,
    ];
}

/// #10195 — the verifier states: none, the signing key, another key.
#[derive(Debug, Clone, Copy)]
enum Key {
    Absent,
    Signer,
    Other,
}

const KEYS: [Key; 3] = [Key::Absent, Key::Signer, Key::Other];

/// The hand-written expected verdict of the resolver (never derived from it).
fn expected(shape: Shape, key: Key) -> AgentCutover {
    let valid = |signature| AgentCutover::Valid {
        sequence: 1,
        legacy_agent_rows: 0,
        signature,
    };
    match (shape, key) {
        (Shape::Valid | Shape::FlippedSignature, Key::Absent) => valid(MarkerSignature::Unchecked),
        (Shape::Valid, Key::Signer) => valid(MarkerSignature::Verified),
        (Shape::NoMarker, Key::Absent | Key::Signer | Key::Other) => AgentCutover::Absent,
        (Shape::Valid | Shape::FlippedSignature, Key::Other)
        | (Shape::FlippedSignature, Key::Signer)
        | (
            Shape::EditedPayload
            | Shape::StrippedSignature
            | Shape::ShortSignature
            | Shape::NotDaemonAttested
            | Shape::Duplicate
            | Shape::CorruptCount,
            Key::Absent | Key::Signer | Key::Other,
        ) => AgentCutover::Invalid,
    }
}

fn judge(shape: Shape, key: Key) -> AgentCutover {
    let m = genesis(MarkerOrigin::Create);
    let mut x = m.clone();
    let mut count = Some(0);
    let markers: Vec<SignedEvent> = match shape {
        Shape::Valid => vec![m],
        Shape::EditedPayload => {
            x.payload_hash[1] ^= 1;
            vec![x]
        }
        Shape::FlippedSignature => {
            if let Some(sig) = x.signature.as_mut() {
                sig[0] ^= 1;
            }
            vec![x]
        }
        Shape::StrippedSignature => {
            x.signature = None;
            vec![x]
        }
        Shape::ShortSignature => {
            if let Some(sig) = x.signature.as_mut() {
                sig.pop();
            }
            vec![x]
        }
        Shape::NotDaemonAttested => {
            x.attest_level = crate::models::AttestLevel::Unsigned.as_str().to_string();
            vec![x]
        }
        Shape::Duplicate => vec![m, x],
        Shape::CorruptCount => {
            count = None;
            vec![m]
        }
        Shape::NoMarker => Vec::new(),
    };
    let signer_vk = signer(SEED).verifying_key();
    let other_vk = signer(OTHER_SEED).verifying_key();
    let verifier = match key {
        Key::Absent => MarkerVerifier::Absent,
        Key::Signer => MarkerVerifier::Present(&signer_vk),
        Key::Other => MarkerVerifier::Present(&other_vk),
    };
    resolve_signed(verifier, &markers, None, count)
}

/// #10195 — the resolver over every marker shape and verifier state: no key
/// leaves a well-formed marker unchecked (never invalid, never verified); a
/// present key that does not verify it is invalid; a structural defect is
/// invalid with or without a key.
#[test]
fn resolve_signed_table_over_shape_and_verifier_10195() {
    for shape in Shape::ALL {
        for key in KEYS {
            assert_eq!(
                judge(shape, key),
                expected(shape, key),
                "{shape:?} x {key:?}"
            );
        }
    }
}

/// #10195 — the verdict of the marker row per cutover state: verified only
/// when the signature verified, withheld with no key, failed otherwise.
#[test]
fn verdict_for_maps_unchecked_to_no_verifier_skip_10195() {
    use crate::signed_events::{RowSignatureVerdict, SignatureFailure, SkipReason};
    let m = genesis(MarkerOrigin::Create);
    let at = |signature, sequence| AgentCutover::Valid {
        sequence,
        legacy_agent_rows: 0,
        signature,
    };
    let failed = Some(RowSignatureVerdict::Failed(
        SignatureFailure::CutoverMarkerInvalid,
    ));
    let rows: [(AgentCutover, Option<RowSignatureVerdict>); 7] = [
        (
            at(MarkerSignature::Verified, 1),
            Some(RowSignatureVerdict::Verified),
        ),
        (
            at(MarkerSignature::Unchecked, 1),
            Some(RowSignatureVerdict::Skipped(SkipReason::NoVerifier)),
        ),
        (at(MarkerSignature::Verified, 2), failed),
        (at(MarkerSignature::Unchecked, 2), failed),
        (AgentCutover::Absent, failed),
        (AgentCutover::Invalid, failed),
        (AgentCutover::Missing, failed),
    ];
    for (cutover, want) in rows {
        assert_eq!(cutover.verdict_for(&m), want, "{cutover:?}");
    }
    let ordinary = SignedEvent {
        event_type: "memory.store".into(),
        ..m
    };
    assert_eq!(
        at(MarkerSignature::Unchecked, 1).verdict_for(&ordinary),
        None
    );
}

/// #10195 — the structural check is what the keyed check adds a signature
/// verification to: a structurally bad marker fails both.
#[test]
fn structure_is_necessary_for_verification_10195() {
    let vk = signer(SEED).verifying_key();
    let m = genesis(MarkerOrigin::Create);
    assert_eq!(
        signed_marker_structure(&m, None, 0),
        Some(MarkerOrigin::Create)
    );
    let mut flipped = m.clone();
    if let Some(sig) = flipped.signature.as_mut() {
        sig[0] ^= 1;
    }
    assert_eq!(
        signed_marker_structure(&flipped, None, 0),
        Some(MarkerOrigin::Create),
        "the structure does not judge the signature bytes"
    );
    assert_eq!(verify_signed_marker(&vk, &flipped, None, 0), None);
    assert_eq!(signed_marker_structure(&m, None, 1), None, "legacy count");
}
