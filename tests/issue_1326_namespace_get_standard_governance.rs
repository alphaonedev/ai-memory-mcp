// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! v0.7.0 issue #1326 — `memory_namespace_get_standard` governance
//! pass-through.
//!
//! Pre-#1326 regression: `memory_namespace_set_standard` correctly
//! merged caller-supplied off-struct fields (`require_approval_above_depth`,
//! `skill_promotion_min_depth`, etc.) into the standard memory's
//! `metadata.governance` blob (fix #707 / G-PHASE-E-2). The L1-8
//! approval gate at `storage::resolve_require_approval_above_depth`
//! continued to read the field correctly from the merged blob, so the
//! enforcement layer worked.
//!
//! BUT — `memory_namespace_get_standard` round-tripped the response
//! through the typed `GovernancePolicy` struct, which only carries
//! the whitelist (write / promote / delete / approver / inherit /
//! `max_reflection_depth`). Any off-struct field was dropped on the
//! get side. Operators inspecting the get-standard surface saw an
//! incomplete policy blob and could not confirm their approval gate
//! was stored.
//!
//! Fix: `handle_namespace_get_standard` now layers the raw
//! `metadata.governance` JSON keys back onto the typed-struct
//! serialisation so off-struct fields survive the round-trip. This
//! file pins:
//!
//! 1. `require_approval_above_depth` survives a set → get round-trip
//!    on the leaf-namespace surface.
//! 2. Off-struct fields survive the `--inherit` chain surface
//!    (multiple namespaces under one global root).
//! 3. The typed-struct defaults (`write`, `promote`, `delete`,
//!    `approver`, `inherit`) still populate alongside the off-struct
//!    fields — no regression on the well-known-fields surface.

use ai_memory::mcp::{handle_namespace_get_standard, handle_namespace_set_standard};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::storage as db;
use chrono::Utc;
use rusqlite::Connection;
use serde_json::json;

mod common;
use common::fresh_conn;

fn insert_one(conn: &Connection, namespace: &str, title: &str) -> String {
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("body for {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("insert memory")
}

/// Case 1 — leaf namespace round-trip. Caller sets
/// `require_approval_above_depth = 2` via `memory_namespace_set_standard`,
/// then reads back via `memory_namespace_get_standard`. The get
/// response MUST carry the field in `governance`.
#[test]
fn issue_1326_require_approval_above_depth_round_trips() {
    let conn = fresh_conn();
    let standard_id = insert_one(&conn, "ns-1326-leaf", "standard");

    let set_resp = handle_namespace_set_standard(
        &conn,
        &json!({
            "namespace": "ns-1326-leaf",
            "id": standard_id,
            "governance": {
                "write": "any",
                "require_approval_above_depth": 2,
            },
        }),
    )
    .expect("set_standard must succeed");
    assert_eq!(
        set_resp["governance"]["require_approval_above_depth"], 2,
        "set-side echo must include the field; got: {set_resp}"
    );

    let get_resp =
        handle_namespace_get_standard(&conn, &json!({"namespace": "ns-1326-leaf"})).expect("get");
    let gov = &get_resp["governance"];
    assert!(
        gov.is_object(),
        "get response must surface a governance object; got: {get_resp}"
    );
    assert_eq!(
        gov["require_approval_above_depth"], 2,
        "require_approval_above_depth MUST survive set → get; got governance={gov}"
    );

    // Sanity: the substrate's resolver also sees the value.
    let resolved = db::resolve_require_approval_above_depth(&conn, "ns-1326-leaf")
        .expect("resolver returns Some");
    assert_eq!(resolved, 2, "substrate resolver must agree with get-side");
}

/// Case 2 — `--inherit` chain surface. A global standard carries an
/// off-struct field. The leaf get-standard with inherit=true returns
/// a chain whose entries all carry the off-struct field on every
/// link that has it set.
#[test]
fn issue_1326_off_struct_fields_survive_inherit_chain() {
    let conn = fresh_conn();
    let global_id = insert_one(&conn, "*", "global-std");
    let leaf_id = insert_one(&conn, "ns-1326-leaf-2", "leaf-std");

    handle_namespace_set_standard(
        &conn,
        &json!({
            "namespace": "*",
            "id": global_id,
            "governance": {
                "write": "any",
                "require_approval_above_depth": 4,
            },
        }),
    )
    .expect("set global standard");

    handle_namespace_set_standard(
        &conn,
        &json!({
            "namespace": "ns-1326-leaf-2",
            "id": leaf_id,
            "governance": {
                "write": "any",
                "require_approval_above_depth": 1,
            },
        }),
    )
    .expect("set leaf standard");

    let get_resp = handle_namespace_get_standard(
        &conn,
        &json!({"namespace": "ns-1326-leaf-2", "inherit": true}),
    )
    .expect("inherit-chain get must succeed");
    let standards = get_resp["standards"]
        .as_array()
        .expect("inherit response must carry a standards array")
        .clone();
    assert!(
        !standards.is_empty(),
        "inherit chain must surface at least one standard"
    );
    // Every entry in the chain that originated from a set with the
    // field MUST carry it through the inherit surface.
    let global_entry = standards
        .iter()
        .find(|s| s["namespace"] == "*")
        .expect("global entry present in chain");
    assert_eq!(
        global_entry["governance"]["require_approval_above_depth"], 4,
        "global standard's off-struct field must surface on inherit-chain; got: {global_entry}"
    );
    let leaf_entry = standards
        .iter()
        .find(|s| s["namespace"] == "ns-1326-leaf-2")
        .expect("leaf entry present in chain");
    assert_eq!(
        leaf_entry["governance"]["require_approval_above_depth"], 1,
        "leaf standard's off-struct field must surface on inherit-chain; got: {leaf_entry}"
    );
}

/// Case 3 — well-known-fields surface preserved. The fix adds
/// off-struct fields without dropping the typed `GovernancePolicy`
/// defaults (`write`, `promote`, `delete`, `approver`, `inherit`).
#[test]
fn issue_1326_typed_defaults_still_populate_alongside_off_struct() {
    let conn = fresh_conn();
    let standard_id = insert_one(&conn, "ns-1326-defaults", "standard");

    handle_namespace_set_standard(
        &conn,
        &json!({
            "namespace": "ns-1326-defaults",
            "id": standard_id,
            "governance": {
                "write": "any",
                "require_approval_above_depth": 3,
            },
        }),
    )
    .expect("set");

    let get_resp = handle_namespace_get_standard(&conn, &json!({"namespace": "ns-1326-defaults"}))
        .expect("get");
    let gov = &get_resp["governance"];
    // Off-struct field survived.
    assert_eq!(gov["require_approval_above_depth"], 3, "off-struct field");
    // Typed fields populated (defaults or set value).
    assert!(gov.get("write").is_some(), "typed `write` must populate");
    assert!(
        gov.get("promote").is_some(),
        "typed `promote` must populate"
    );
    assert!(gov.get("delete").is_some(), "typed `delete` must populate");
    assert!(
        gov.get("approver").is_some(),
        "typed `approver` must populate"
    );
    assert!(
        gov.get("inherit").is_some(),
        "typed `inherit` must populate"
    );
}
