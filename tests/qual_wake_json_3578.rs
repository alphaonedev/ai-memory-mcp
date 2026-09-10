// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3578: the JSON OUTPUT envelope is closed; it is not an input codec.

use ai_memory::cli::wake_listen::{Resolved, wake_line};
use ai_memory::wake_client::{WakeClientConfig, WakeReason, WakeSignal};
use ai_memory::wake_hub::frame::WakeMeta;
use serde_json::{Value, json};

fn resolved() -> Resolved {
    Resolved {
        agent_id: "ai:listener-3578".into(),
        socket: None,
        hub_id: "hub-3578".into(),
        key_dir: "unused-3578".into(),
        bundle: "unused-3578".into(),
        client: WakeClientConfig::default(),
    }
}

fn assert_closed(line: &Value) {
    let mut keys: Vec<_> = line
        .as_object()
        .expect("output object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "agent_id",
            "digest",
            "hub_driven",
            "hub_id",
            "inbox_count",
            "inbox_row_id",
            "missed",
            "namespace",
            "pending_count",
            "reason",
            "sender",
            "seq_high_watermark",
        ]
    );
    for forbidden in ["content", "title", "body", "payload"] {
        assert!(
            line.get(forbidden).is_none(),
            "forbidden output key {forbidden}"
        );
    }
}

#[test]
fn json_output_preserves_exact_hint_and_reporting_fields_3578() {
    let vectors: Value = serde_json::from_str(include_str!("../sdk/fixtures/wake_meta_3578.json"))
        .expect("shared vectors");
    let resolved = resolved();
    for case in vectors["allowed"].as_array().expect("allowed vectors") {
        let raw = hex::decode(case["hex"].as_str().expect("hex")).expect("bytes");
        let meta = WakeMeta::decode(&raw).expect("allowed binary hint");
        let signal = WakeSignal {
            reason: WakeReason::Gap,
            meta: Some(meta),
            pending_count: 7,
            missed: 3,
        };
        let line = wake_line(&resolved, &signal, 2);
        assert_closed(&line);
        let hint = &case["expected"];
        assert_eq!(
            line,
            json!({
                "agent_id": "ai:listener-3578", "hub_id": "hub-3578",
                "reason": "gap", "hub_driven": true, "pending_count": 7,
                "missed": 3, "inbox_count": 2,
                "inbox_row_id": hint["inbox_row_id"], "namespace": hint["namespace"],
                "sender": hint["sender"], "digest": hint["digest"],
                "seq_high_watermark": hint["seq_high_watermark"],
            })
        );
        let encoded = serde_json::to_string(&line).expect("output JSON");
        assert_eq!(
            serde_json::from_str::<Value>(&encoded).expect("roundtrip"),
            line
        );
        if raw.len() == 256 {
            assert!(
                encoded.len() > 256,
                "the binary cap is not a JSON output cap"
            );
        }
    }
}

#[test]
fn every_bare_reason_has_the_same_closed_output_envelope_3578() {
    let resolved = resolved();
    for (reason, label, hub_driven) in [
        (WakeReason::Welcome, "welcome", true),
        (WakeReason::Lagged, "lagged", true),
        (WakeReason::Wake, "wake", true),
        (WakeReason::Gap, "gap", true),
        (WakeReason::Backstop, "backstop", false),
    ] {
        let line = wake_line(&resolved, &WakeSignal::bare(reason), 0);
        assert_closed(&line);
        assert_eq!(
            line,
            json!({
                "agent_id": "ai:listener-3578", "hub_id": "hub-3578",
                "reason": label, "hub_driven": hub_driven,
                "pending_count": 0, "missed": 0, "inbox_count": 0,
                "inbox_row_id": "", "namespace": "", "sender": "", "digest": "",
                "seq_high_watermark": 0,
            })
        );
    }
}

#[test]
fn metadata_strings_cannot_inject_output_keys_3578() {
    // TEST-02: hostile text remains a value; checking serialized substrings
    // would incorrectly reject legitimate metadata containing a key's name.
    let meta = WakeMeta {
        inbox_row_id: "row\",\"content\":\"injected".into(),
        namespace: "title".into(),
        sender: "body\npayload".into(),
        digest: vec![0xab; 32],
        seq_high_watermark: 42,
    };
    let meta = WakeMeta::decode(&meta.encode().expect("bounded hint")).expect("decode");
    let signal = WakeSignal {
        reason: WakeReason::Wake,
        meta: Some(meta),
        pending_count: 0,
        missed: 0,
    };
    let line = wake_line(&resolved(), &signal, 0);
    let rendered = serde_json::to_string(&line).expect("render");
    let parsed: Value = serde_json::from_str(&rendered).expect("parse rendered output");
    assert_closed(&parsed);
    assert_eq!(parsed["inbox_row_id"], "row\",\"content\":\"injected");
    assert_eq!(parsed["namespace"], "title");
    assert_eq!(parsed["sender"], "body\npayload");
}
