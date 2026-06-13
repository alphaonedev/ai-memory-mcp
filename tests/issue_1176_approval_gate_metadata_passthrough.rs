// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

//! Regression suite for issue #1176 — MCP approval-gate `pending_action`
//! payload drops caller-supplied `metadata`.
//!
//! ## Defect
//!
//! When an L1-8 governance approval-gate fires on a `memory_reflect`
//! call (namespace policy carries a non-None `require_approval_above_depth`
//! threshold AND the proposed reflection depth exceeds it), the handler
//! at `src/mcp/tools/reflect.rs:152-163` serialises the input into a
//! `pending_action` row. Pre-#1176 the serialised payload omitted
//! `metadata` entirely.
//!
//! When an approver later resolved the pending row via
//! `execute_pending_action`, the rebuild path at
//! `execute_reflect_from_payload` (`src/storage/mod.rs:8685`) read
//! `payload["metadata"]` and got `None` → fell back to `json!({})` →
//! caller-supplied keys (notably `entity_id` for persona binding) were
//! silently dropped on the pending → execute round-trip.
//!
//! Sibling defect to #1172 via the L1-8 governance code path; #1172
//! is the storage-layer half (closed via PR #1177), #1176 is the
//! pending-action half.
//!
//! ## Invariants pinned
//!
//! 1. **Producer side**: MCP `handle_reflect` writes `payload["metadata"]`
//!    to the `pending_actions` row when the approval-gate fires.
//! 2. **End-to-end**: a gated reflection with `metadata.entity_id`
//!    queues a pending row carrying the entity_id, and the executed
//!    reflection (post-approval) lands with both
//!    `json_extract(metadata, '$.entity_id')` AND
//!    `mentioned_entity_id` carrying the caller-supplied value.
//! 3. **Back-compat**: a gated reflection with empty caller metadata
//!    still queues a pending row whose `payload["metadata"]` is the
//!    empty object — the execute-side fallback continues to work.
//! 4. **Field completeness**: every documented payload key (per the
//!    docstring at `src/storage/mod.rs:8591-8604`) is present so the
//!    execute-side parser can rebuild `ReflectInput` losslessly.

use ai_memory::db;
use ai_memory::mcp;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use chrono::Utc;
use rusqlite::Connection;
use serde_json::{Value, json};

mod common;
use common::fresh_db_tempfile_path;

// ---------------------------------------------------------------------------
// Test invariants — module-level constants per pm-v3.1 discipline.
// ---------------------------------------------------------------------------

const FIXTURE_AGENT_ID: &str = "test-agent-1176";
const FIXTURE_SOURCE: &str = "api";
const FIXTURE_ENTITY_ID: &str = "entity-uuid-1176";
const FIXTURE_CUSTOM_KEY: &str = "custom_key";
const FIXTURE_CUSTOM_VALUE: &str = "custom_value";
const NS_GATED: &str = "issue-1176-gated";

/// Documented payload key set from `src/storage/mod.rs:8591-8604` —
/// every key the execute-side `execute_reflect_from_payload` parser
/// reads back when reconstructing the `ReflectInput`. Pinning the
/// list at module scope (instead of inside the test body) keeps
/// `clippy::items_after_statements` happy and makes the contract
/// queryable from a single grep.
const REQUIRED_PAYLOAD_KEYS: &[&str] = &[
    "source_ids",
    "title",
    "content",
    "namespace",
    "tier",
    "tags",
    "priority",
    "confidence",
    "agent_id",
    "metadata",
    "proposed_depth",
];

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn seed_observation(conn: &Connection, namespace: &str, title: &str) -> String {
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("issue_1176 fixture observation: {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: FIXTURE_SOURCE.to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": FIXTURE_AGENT_ID}),
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
    };
    db::insert(conn, &mem).expect("insert observation")
}

/// Seed a namespace standard whose `metadata.governance.require_approval_above_depth = 0`
/// so any reflection (even depth=1) triggers the L1-8 approval gate.
/// Mirrors the fixture pattern from `src/mcp/tools/reflect.rs::tests::approval_gate_above_depth_queues_pending`.
fn seed_approval_gate_namespace(conn: &Connection, namespace: &str) {
    let std_id = seed_observation(conn, namespace, "namespace-standard");
    let gov_metadata = json!({
        "governance": {
            "write": "any",
            "require_approval_above_depth": 0,
        },
    });
    conn.execute(
        "UPDATE memories SET metadata = json(?1) WHERE id = ?2",
        rusqlite::params![gov_metadata.to_string(), &std_id],
    )
    .expect("patch governance metadata");
    db::set_namespace_standard(conn, namespace, &std_id, None).expect("set standard");
}

fn read_pending_payload(conn: &Connection, pending_id: &str) -> Value {
    let payload_str: String = conn
        .query_row(
            "SELECT payload FROM pending_actions WHERE id = ?1",
            rusqlite::params![pending_id],
            |row| row.get(0),
        )
        .expect("read pending payload");
    serde_json::from_str(&payload_str).expect("parse pending payload as JSON")
}

// ---------------------------------------------------------------------------
// (1) Producer-side pin — handle_reflect queues metadata in the payload
// ---------------------------------------------------------------------------

#[test]
fn approval_gate_payload_carries_caller_supplied_metadata() {
    let (tmp, db_path) = fresh_db_tempfile_path();
    let _ = &tmp;
    let conn = db::open(&db_path).expect("re-open db");

    let src_id = seed_observation(&conn, NS_GATED, "src-observation");
    seed_approval_gate_namespace(&conn, NS_GATED);

    let params = json!({
        "source_ids": [src_id],
        "title": "gated-reflection-1176",
        "content": "synthesised reflection content",
        "namespace": NS_GATED,
        "agent_id": FIXTURE_AGENT_ID,
        "metadata": {
            "entity_id": FIXTURE_ENTITY_ID,
            FIXTURE_CUSTOM_KEY: FIXTURE_CUSTOM_VALUE,
        },
    });

    let resp = mcp::handle_reflect(&conn, &db_path, &params, None, None, None, None)
        .expect("handle_reflect ok");

    // Gate should fire and queue a pending row.
    assert_eq!(
        resp["status"].as_str(),
        Some("pending"),
        "L1-8 approval gate must fire on depth=1 with require_approval_above_depth=0; \
         got response = {resp}"
    );
    let pending_id = resp["pending_id"]
        .as_str()
        .expect("pending_id in response")
        .to_string();

    let payload = read_pending_payload(&conn, &pending_id);

    // Invariant 1: caller-supplied metadata.entity_id round-trips into
    // the pending_actions payload.
    let payload_meta = payload
        .get("metadata")
        .expect("payload.metadata must be present in pending row");
    assert_eq!(
        payload_meta.get("entity_id").and_then(Value::as_str),
        Some(FIXTURE_ENTITY_ID),
        "pending_action payload must carry caller-supplied metadata.entity_id; \
         full payload.metadata = {payload_meta}"
    );
    assert_eq!(
        payload_meta.get(FIXTURE_CUSTOM_KEY).and_then(Value::as_str),
        Some(FIXTURE_CUSTOM_VALUE),
        "every caller-supplied key must round-trip, not just entity_id"
    );

    // The substrate's canonical fields land too.
    assert!(payload.get("source_ids").is_some());
    assert!(payload.get("title").is_some());
    assert_eq!(
        payload.get("agent_id").and_then(Value::as_str),
        Some(FIXTURE_AGENT_ID)
    );
}

// ---------------------------------------------------------------------------
// (2) End-to-end pin — approve → execute → reflection carries metadata
//     and mentioned_entity_id
// ---------------------------------------------------------------------------

#[test]
fn approved_pending_reflection_lands_with_caller_metadata_and_mentioned_entity_id() {
    let (tmp, db_path) = fresh_db_tempfile_path();
    let _ = &tmp;
    let conn = db::open(&db_path).expect("re-open db");

    let src_id = seed_observation(&conn, NS_GATED, "src-observation");
    seed_approval_gate_namespace(&conn, NS_GATED);

    let params = json!({
        "source_ids": [src_id],
        "title": "e2e-gated-reflection-1176",
        "content": "synthesised reflection content",
        "namespace": NS_GATED,
        "agent_id": FIXTURE_AGENT_ID,
        "metadata": {"entity_id": FIXTURE_ENTITY_ID},
    });

    let resp = mcp::handle_reflect(&conn, &db_path, &params, None, None, None, None)
        .expect("handle_reflect ok");
    let pending_id = resp["pending_id"].as_str().unwrap().to_string();

    // Approve the pending row.
    let approved = db::decide_pending_action(&conn, &pending_id, true, FIXTURE_AGENT_ID)
        .expect("decide approve");
    assert!(
        approved,
        "decide_pending_action must report the row was updated"
    );

    let executed_id = db::execute_pending_action(&conn, &pending_id)
        .expect("execute approved reflect action")
        .expect("execute returns the new reflection id");

    // Invariant 2a: the executed reflection's metadata carries the
    // caller-supplied entity_id.
    let (meta, mention) = conn
        .query_row(
            "SELECT metadata, mentioned_entity_id FROM memories WHERE id = ?1",
            rusqlite::params![executed_id],
            |row| {
                let meta_str: String = row.get(0)?;
                let mention: Option<String> = row.get(1)?;
                Ok((
                    serde_json::from_str::<Value>(&meta_str).unwrap_or(Value::Null),
                    mention,
                ))
            },
        )
        .expect("read executed reflection row");

    assert_eq!(
        meta.get("entity_id").and_then(Value::as_str),
        Some(FIXTURE_ENTITY_ID),
        "executed reflection's metadata.entity_id must come from the queued payload; \
         full metadata = {meta}"
    );

    // Invariant 2b: PERF-8 indexed column populated end-to-end.
    assert_eq!(
        mention.as_deref(),
        Some(FIXTURE_ENTITY_ID),
        "mentioned_entity_id column must be populated from the pending-action payload"
    );
}

// ---------------------------------------------------------------------------
// (3) Back-compat — empty caller metadata still queues a usable payload
// ---------------------------------------------------------------------------

#[test]
fn approval_gate_payload_handles_empty_caller_metadata() {
    let (tmp, db_path) = fresh_db_tempfile_path();
    let _ = &tmp;
    let conn = db::open(&db_path).expect("re-open db");

    let src_id = seed_observation(&conn, NS_GATED, "src-observation");
    seed_approval_gate_namespace(&conn, NS_GATED);

    let params = json!({
        "source_ids": [src_id],
        "title": "empty-meta-gated-1176",
        "content": "synthesised reflection content",
        "namespace": NS_GATED,
        "agent_id": FIXTURE_AGENT_ID,
        // No metadata field at all.
    });

    let resp = mcp::handle_reflect(&conn, &db_path, &params, None, None, None, None)
        .expect("handle_reflect ok");
    let pending_id = resp["pending_id"].as_str().unwrap().to_string();

    let payload = read_pending_payload(&conn, &pending_id);
    let payload_meta = payload
        .get("metadata")
        .expect("payload.metadata must be present even when caller omitted it");

    // Substrate normalises absent metadata to {} at the handler boundary
    // (src/mcp/tools/reflect.rs:79-83), so the queued payload carries an
    // empty object — never null, never absent.
    assert!(
        payload_meta.is_object(),
        "payload.metadata must be a JSON object when caller omitted metadata; got: {payload_meta}"
    );
    assert!(
        payload_meta.as_object().unwrap().is_empty(),
        "payload.metadata must be the empty object {{}} for a caller who omitted metadata; \
         got: {payload_meta}"
    );

    // Approve + execute path must still work (no panic, no missing-key
    // failures from the execute-side rebuild).
    db::decide_pending_action(&conn, &pending_id, true, FIXTURE_AGENT_ID).expect("decide approve");
    let executed_id = db::execute_pending_action(&conn, &pending_id)
        .expect("execute approved reflect action with empty metadata")
        .expect("execute returns the new reflection id");

    assert!(!executed_id.is_empty(), "executed_id must be a real uuid");
}

// ---------------------------------------------------------------------------
// (4) Field-completeness pin — every documented payload key is present
//     so the execute-side parser (src/storage/mod.rs:8609 docstring) can
//     rebuild the ReflectInput losslessly.
// ---------------------------------------------------------------------------

#[test]
fn approval_gate_payload_carries_all_documented_keys() {
    let (tmp, db_path) = fresh_db_tempfile_path();
    let _ = &tmp;
    let conn = db::open(&db_path).expect("re-open db");

    let src_id = seed_observation(&conn, NS_GATED, "src-observation");
    seed_approval_gate_namespace(&conn, NS_GATED);

    let params = json!({
        "source_ids": [src_id],
        "title": "field-complete-1176",
        "content": "synthesised reflection content",
        "namespace": NS_GATED,
        "tier": "long",
        "tags": ["reflection", "test"],
        "priority": 7,
        "confidence": 0.85,
        "agent_id": FIXTURE_AGENT_ID,
        "metadata": {"entity_id": FIXTURE_ENTITY_ID},
    });

    let resp = mcp::handle_reflect(&conn, &db_path, &params, None, None, None, None)
        .expect("handle_reflect ok");
    let pending_id = resp["pending_id"].as_str().unwrap().to_string();

    let payload = read_pending_payload(&conn, &pending_id);

    // Every key from the documented payload shape at
    // src/storage/mod.rs:8591-8604 must be present so the execute-side
    // parser can rebuild ReflectInput losslessly. List lives at
    // module scope as REQUIRED_PAYLOAD_KEYS.
    for key in REQUIRED_PAYLOAD_KEYS {
        assert!(
            payload.get(*key).is_some(),
            "payload must carry key {key:?} (documented at src/storage/mod.rs:8591); \
             actual keys = {:?}",
            payload.as_object().map(|o| o.keys().collect::<Vec<_>>())
        );
    }
}
