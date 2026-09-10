// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3578: shared Rust/Python/TypeScript binary hint acceptance vectors.
//! The 256-byte ceiling belongs to `WakeMeta`, not handshake/control frames or
//! the CLI reporting envelope. This test does not claim JSON-input validation.

use ai_memory::wake_hub::frame::{Frame, FrameError, Kind, WakeMeta};
use serde_json::{Value, json};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../sdk/fixtures/wake_meta_3578.json"))
        .expect("shared codec vectors")
}

fn bytes(case: &Value) -> Vec<u8> {
    hex::decode(case["hex"].as_str().expect("hex string")).expect("fixture hex")
}

fn expected_fields(meta: WakeMeta) -> Value {
    // No `..`: adding any sixth field breaks this compiled field inventory.
    let WakeMeta {
        inbox_row_id,
        namespace,
        sender,
        digest,
        seq_high_watermark,
    } = meta;
    json!({
        "inbox_row_id": inbox_row_id,
        "namespace": namespace,
        "sender": sender,
        "digest": hex::encode(digest),
        "seq_high_watermark": seq_high_watermark,
    })
}

#[test]
fn allowed_vectors_roundtrip_exactly_five_fields_3578() {
    let vectors = vectors();
    let allowed = vectors["allowed"].as_array().expect("allowed cases");
    assert_eq!(allowed.len(), 4, "shared allowed census");
    for case in allowed {
        let raw = bytes(case);
        let decoded = WakeMeta::decode(&raw).expect("allowed hint");
        assert_eq!(decoded.encode().expect("re-encode"), raw, "{case}");
        assert_eq!(expected_fields(decoded), case["expected"], "{case}");
    }
}

#[test]
fn exact_256_byte_boundary_is_allowed_but_257_is_refused_3578() {
    let vectors = vectors();
    let raw = bytes(&vectors["allowed"][2]);
    assert_eq!(raw.len(), 256, "the fixture must hit the actual boundary");
    let mut meta = WakeMeta::decode(&raw).expect("256 bytes allowed");
    meta.sender.push('s');
    assert_eq!(meta.encode(), Err(FrameError::MetaTooLarge { len: 257 }));
    let mut oversized = raw;
    oversized.push(0);
    assert_eq!(
        WakeMeta::decode(&oversized),
        Err(FrameError::MetaTooLarge { len: 257 })
    );
}

#[test]
fn appended_content_title_and_other_denied_vectors_are_refused_3578() {
    let vectors = vectors();
    let denied = vectors["denied"].as_array().expect("denied cases");
    assert_eq!(denied.len(), 5, "shared denied census");
    for case in denied {
        assert!(WakeMeta::decode(&bytes(case)).is_err(), "{case}");
    }
}

#[test]
fn every_truncation_of_each_allowed_hint_is_refused_3578() {
    let vectors = vectors();
    for case in vectors["allowed"].as_array().expect("allowed cases") {
        let raw = bytes(case);
        for end in 0..raw.len() {
            assert!(
                WakeMeta::decode(&raw[..end]).is_err(),
                "{} truncated at {end}",
                case["name"]
            );
        }
    }
}

#[test]
fn reserved_body_kinds_are_refused_with_a_valid_wake_control_3578() {
    let vectors = vectors();
    let raw = bytes(&vectors["allowed"][1]);
    let frame = Frame::new(Kind::Wake, "producer", "ai:alice", raw.into());
    let encoded = frame.encode().expect("allowed frame");
    assert_eq!(Frame::decode(&encoded).expect("allowed decode"), frame);
    assert_eq!(vectors["reserved_kinds"], json!([11, 12, 13]));
    for kind in [11, 12, 13] {
        let mut denied = encoded.to_vec();
        denied[5] = kind;
        assert!(Frame::decode(&denied).is_err(), "reserved kind {kind}");
    }
}
