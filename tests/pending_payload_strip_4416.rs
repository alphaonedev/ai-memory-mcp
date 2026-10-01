// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4416 — the execution marker is SERVER-ONLY: every inbound pending payload
//! is stripped of every reserved key before it is stored, and the one presence
//! predicate classifies a marker as a JSON object key holding a string.

use ai_memory::storage::{
    EFFECT_MARKER_KEY, RESERVED_PAYLOAD_KEYS, payload_has_effect_marker,
    strip_reserved_payload_keys,
};
use serde_json::json;

#[test]
fn strip_removes_every_reserved_key_and_keeps_the_rest_4416() {
    let mut p = json!({"title": "t", EFFECT_MARKER_KEY: "2026-01-01T00:00:00Z", "n": 1});
    assert!(strip_reserved_payload_keys(&mut p));
    assert_eq!(p, json!({"title": "t", "n": 1}));
    for k in RESERVED_PAYLOAD_KEYS {
        assert!(p.get(*k).is_none());
    }
    assert!(!strip_reserved_payload_keys(&mut p), "idempotent");
    let mut arr = json!(["x"]);
    assert!(
        !strip_reserved_payload_keys(&mut arr),
        "non-object untouched"
    );
    assert_eq!(arr, json!(["x"]));
}

#[test]
fn presence_predicate_is_object_key_with_string_value_4416() {
    assert!(payload_has_effect_marker(&json!({EFFECT_MARKER_KEY: "x"})));
    assert!(!payload_has_effect_marker(
        &json!({EFFECT_MARKER_KEY: null})
    ));
    assert!(!payload_has_effect_marker(&json!({EFFECT_MARKER_KEY: 5})));
    assert!(!payload_has_effect_marker(
        &json!({EFFECT_MARKER_KEY: {"a": 1}})
    ));
    assert!(!payload_has_effect_marker(&json!([EFFECT_MARKER_KEY])));
    assert!(!payload_has_effect_marker(&json!({})));
    assert!(!payload_has_effect_marker(&json!("x")));
}

#[test]
fn sqlite_inbound_funnels_strip_the_marker_4416() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(tmp.path()).expect("open");
    let now = chrono::Utc::now().to_rfc3339();
    let pa = ai_memory::models::PendingAction {
        id: uuid::Uuid::new_v4().to_string(),
        action_type: "store".into(),
        memory_id: None,
        namespace: "ns".into(),
        payload: json!({"title": "t", EFFECT_MARKER_KEY: "forged"}),
        requested_by: "ai:peer".into(),
        requested_at: now,
        status: "pending".into(),
        decided_by: None,
        decided_at: None,
        approvals: Vec::new(),
    };
    ai_memory::storage::upsert_pending_action(&conn, &pa).expect("upsert");
    let stored = ai_memory::storage::get_pending_action(&conn, &pa.id)
        .expect("get")
        .expect("row");
    assert!(
        !payload_has_effect_marker(&stored.payload),
        "an inbound upsert must not persist a wire-supplied marker"
    );

    let id = ai_memory::storage::queue_pending_action(
        &conn,
        ai_memory::models::GovernedAction::Store,
        "ns",
        None,
        "ai:local",
        &json!({EFFECT_MARKER_KEY: "forged"}),
    )
    .expect("queue");
    let queued = ai_memory::storage::get_pending_action(&conn, &id)
        .expect("get")
        .expect("row");
    assert!(!payload_has_effect_marker(&queued.payload));
}
