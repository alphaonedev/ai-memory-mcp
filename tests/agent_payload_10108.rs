// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10108 stage 2 step 1 (GA standard 3): the canonical agent-row
//! `payload_hash` encoder (B-1) and the explicit era (B-7).
//! `3-agent vote (71472661)` V1V2-AGENT-ROW-VERIFY decision B.
//!
//! The golden digests were computed outside the crate (Python `hashlib`
//! over the documented pre-image), so a change to the encoder that the
//! docs do not describe turns these tests red.

use ai_memory::signed_events::AgentCutover;
use ai_memory::signed_events::agent_payload::{
    AGENT_PAYLOAD_DOMAIN, ATOMISATION_RECEIPT_DOMAIN, AgentEventKind, AgentPayloadHash,
    AgentSignedPayload, AtomisationReceipt, PayloadEra, RowEra,
};
use sha2::{Digest, Sha256};

const SIG: [u8; 64] = [7; 64];
const KEY: [u8; 32] = [9; 32];
const SIGNED: &[u8] = b"link-cbor";

/// Python: `sha256(domain | 0x01 | lp("memory_link.created") | lp("link-cbor")
/// | 0x07*64 | 0x09*32)`, where `lp` is a u64 big-endian length prefix.
const GOLDEN_LINK_PAYLOAD: &str =
    "50d7eaf8c23c24d958901f3fc47bf76f4b2ba8f285b235971dd8d792a3011368";

/// Python: sha256 of the receipt pre-image for `receipt()` below (135 bytes).
const GOLDEN_RECEIPT_SHA256: &str =
    "ee95c1e422a3bf1b90d0b62eb3b27b5f05a98ed4dfc6c10f561ad9b2ebab58cc";
const GOLDEN_RECEIPT_LEN: usize = 135;

/// Python: the same receipt with `curator_model: None`, which encodes as
/// a single 0x00 flag byte (126 bytes).
const GOLDEN_RECEIPT_NO_MODEL_SHA256: &str =
    "a632c3e25e219c0cff800a803feedc741a266656cb8e8690bbd6ec67a4cecb1b";
const GOLDEN_RECEIPT_NO_MODEL_LEN: usize = 126;

/// Hand-written: every agent kind, its stored event type and its tag.
const KIND_TABLE: [(AgentEventKind, &str, u8); 7] = [
    (AgentEventKind::LinkCreated, "memory_link.created", 1),
    (AgentEventKind::CaptureTurn, "memory_capture_turn", 2),
    (AgentEventKind::PersonaGenerated, "persona_generated", 3),
    (
        AgentEventKind::AtomisationComplete,
        "atomisation_complete",
        4,
    ),
    (AgentEventKind::ContextOffloaded, "context_offloaded", 5),
    (
        AgentEventKind::ContextDereferenced,
        "context_dereferenced",
        6,
    ),
    (AgentEventKind::SkillRegistered, "skill.registered", 7),
];

fn payload(kind: AgentEventKind) -> AgentSignedPayload<'static> {
    AgentSignedPayload {
        kind,
        signed_bytes: SIGNED,
        signature: &SIG,
        pubkey: &KEY,
    }
}

fn receipt() -> AtomisationReceipt {
    AtomisationReceipt {
        source_id: "src-1".to_string(),
        atomised_at: "2026-11-26T00:00:00Z".to_string(),
        atom_ids: vec!["a1".to_string(), "a2".to_string()],
        atom_count: 2,
        calling_agent_id: "ai:test".to_string(),
        curator_model: Some("m".to_string()),
    }
}

#[test]
fn encoder_matches_the_documented_preimage_10108() {
    let h = AgentPayloadHash::encode(&payload(AgentEventKind::LinkCreated));
    assert_eq!(hex::encode(h.as_bytes()), GOLDEN_LINK_PAYLOAD);
    assert_eq!(h.to_vec(), h.as_bytes().to_vec());
    assert!(AGENT_PAYLOAD_DOMAIN.ends_with(b"-v1\0"));
}

#[test]
fn encoder_never_equals_the_untagged_legacy_digest_10108() {
    for kind in AgentEventKind::ALL {
        let h = AgentPayloadHash::encode(&payload(kind));
        let legacy: [u8; 32] = Sha256::digest(SIGNED).into();
        assert_ne!(h.as_bytes(), &legacy, "{kind:?}");
        assert!(!h.matches(&legacy), "{kind:?}");
    }
}

#[test]
fn each_input_field_changes_the_digest_10108() {
    let base = AgentPayloadHash::encode(&payload(AgentEventKind::LinkCreated));
    let mut sig = SIG;
    sig[63] ^= 1;
    let mut key = KEY;
    key[0] ^= 1;
    let variants = [
        AgentSignedPayload {
            signed_bytes: b"link-cboR",
            ..payload(AgentEventKind::LinkCreated)
        },
        AgentSignedPayload {
            signed_bytes: b"",
            ..payload(AgentEventKind::LinkCreated)
        },
        AgentSignedPayload {
            signature: &sig,
            ..payload(AgentEventKind::LinkCreated)
        },
        AgentSignedPayload {
            pubkey: &key,
            ..payload(AgentEventKind::LinkCreated)
        },
    ];
    for (i, v) in variants.iter().enumerate() {
        assert_ne!(AgentPayloadHash::encode(v), base, "variant {i}");
    }
}

#[test]
fn every_kind_hashes_apart_10108() {
    let digests: Vec<AgentPayloadHash> = AgentEventKind::ALL
        .into_iter()
        .map(|k| AgentPayloadHash::encode(&payload(k)))
        .collect();
    for (i, a) in digests.iter().enumerate() {
        for b in &digests[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn kind_table_is_exact_and_round_trips_10108() {
    assert_eq!(AgentEventKind::ALL.len(), KIND_TABLE.len());
    for (kind, event_type, tag) in KIND_TABLE {
        assert_eq!(kind.event_type(), event_type, "{kind:?}");
        assert_eq!(kind.tag(), tag, "{kind:?}");
        assert_eq!(AgentEventKind::of_event_type(event_type), Some(kind));
    }
    for other in [
        "",
        "memory.stored",
        "memory_link.invalidated",
        "signed_events.agent_cutover",
        "MEMORY_LINK.CREATED",
        "memory_link.created ",
        "skill.registered\0",
    ] {
        assert_eq!(AgentEventKind::of_event_type(other), None, "{other:?}");
    }
}

#[test]
fn matches_refuses_truncated_and_padded_columns_10108() {
    let h = AgentPayloadHash::encode(&payload(AgentEventKind::CaptureTurn));
    let exact = h.to_vec();
    assert!(h.matches(&exact));
    assert!(!h.matches(&exact[..31]));
    let mut padded = exact.clone();
    padded.push(0);
    assert!(!h.matches(&padded));
    assert!(!h.matches(&[]));
}

#[test]
fn receipt_bytes_match_the_documented_encoding_10108() {
    let bytes = receipt().canonical_bytes();
    assert!(bytes.starts_with(ATOMISATION_RECEIPT_DOMAIN));
    assert_eq!(bytes.len(), GOLDEN_RECEIPT_LEN);
    assert_eq!(hex::encode(Sha256::digest(&bytes)), GOLDEN_RECEIPT_SHA256);
}

#[test]
fn receipt_without_model_matches_the_documented_encoding_10108() {
    let bytes = AtomisationReceipt {
        curator_model: None,
        ..receipt()
    }
    .canonical_bytes();
    assert_eq!(bytes.len(), GOLDEN_RECEIPT_NO_MODEL_LEN);
    assert_eq!(bytes.last(), Some(&0_u8));
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        GOLDEN_RECEIPT_NO_MODEL_SHA256
    );
}

#[test]
fn receipt_fields_cannot_be_shifted_into_each_other_10108() {
    let base = receipt().canonical_bytes();
    let shifted_ids = AtomisationReceipt {
        atom_ids: vec!["a".to_string(), "1a2".to_string()],
        ..receipt()
    };
    let reordered = AtomisationReceipt {
        atom_ids: vec!["a2".to_string(), "a1".to_string()],
        ..receipt()
    };
    let no_model = AtomisationReceipt {
        curator_model: None,
        ..receipt()
    };
    let empty_model = AtomisationReceipt {
        curator_model: Some(String::new()),
        ..receipt()
    };
    let shifted_source = AtomisationReceipt {
        source_id: "src-12026".to_string(),
        atomised_at: "-11-26T00:00:00Z".to_string(),
        ..receipt()
    };
    let count = AtomisationReceipt {
        atom_count: 3,
        ..receipt()
    };
    let all = [
        shifted_ids.canonical_bytes(),
        reordered.canonical_bytes(),
        no_model.canonical_bytes(),
        empty_model.canonical_bytes(),
        shifted_source.canonical_bytes(),
        count.canonical_bytes(),
    ];
    for (i, b) in all.iter().enumerate() {
        assert_ne!(b, &base, "variant {i}");
        for c in &all[i + 1..] {
            assert_ne!(b, c, "variant {i}");
        }
    }
}

#[test]
fn era_table_is_exhaustive_10108() {
    let valid = AgentCutover::Valid {
        sequence: 10,
        legacy_agent_rows: 3,
    };
    let rows: [(AgentCutover, i64, RowEra); 9] = [
        (AgentCutover::Absent, 1, RowEra::Era(PayloadEra::Legacy)),
        (
            AgentCutover::Absent,
            i64::MAX,
            RowEra::Era(PayloadEra::Legacy),
        ),
        (valid, i64::MIN, RowEra::Era(PayloadEra::Legacy)),
        (valid, 9, RowEra::Era(PayloadEra::Legacy)),
        (valid, 10, RowEra::Marker),
        (valid, 11, RowEra::Era(PayloadEra::Signed)),
        (valid, i64::MAX, RowEra::Era(PayloadEra::Signed)),
        (AgentCutover::Invalid, 1, RowEra::Unresolvable),
        (AgentCutover::Invalid, 11, RowEra::Unresolvable),
    ];
    for (cutover, seq, expected) in rows {
        assert_eq!(
            RowEra::resolve(&cutover, seq),
            expected,
            "{cutover:?} {seq}"
        );
    }
}

#[test]
fn encoder_is_linear_in_the_signed_bytes_10108() {
    let big = vec![0xA5_u8; 4 * 1024 * 1024];
    let start = std::time::Instant::now();
    let h = AgentPayloadHash::encode(&AgentSignedPayload {
        signed_bytes: &big,
        ..payload(AgentEventKind::ContextOffloaded)
    });
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    assert_ne!(
        h,
        AgentPayloadHash::encode(&payload(AgentEventKind::ContextOffloaded))
    );
}
