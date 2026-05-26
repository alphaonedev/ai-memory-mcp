// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 issue #1325 — `memory_reflect` caller-asserted `depth` cap.
//!
//! Pre-#1325 regression: the docstring example in the capabilities
//! surface advertised `{"source_ids": [...], "depth": 1}` as a valid
//! `memory_reflect` payload, but the handler silently dropped the
//! `depth` field. Callers who set `depth = 0` (intending to disable
//! a deep reflection) saw the substrate write a depth-1 reflection
//! anyway with no error, no warning, no audit trail.
//!
//! Fix: `handle_reflect` now reads `params["depth"]`. When present
//! it MUST equal `max(source_depths) + 1` or the call returns a
//! stable `CALLER_DEPTH_MISMATCH` error slug. Omission preserves the
//! pre-#1325 substrate-computed behaviour (backward-compatible).
//!
//! Three cases pinned here:
//!
//! 1. Omitted — substrate computes depth, write succeeds (control).
//! 2. Match — caller asserts the substrate-computed value, write succeeds.
//! 3. Mismatch — caller asserts a value the substrate would refute,
//!    returns `CALLER_DEPTH_MISMATCH` BEFORE the write lands.

use ai_memory::mcp::handle_reflect;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::storage as db;
use chrono::Utc;
use rusqlite::Connection;
use serde_json::json;
use tempfile::NamedTempFile;

mod common;
use common::fresh_conn;

fn insert_depth0_observation(conn: &Connection, namespace: &str, title: &str) -> String {
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
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
        metadata: json!({"agent_id": "ai:test"}),
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

/// Case 1 — caller omits `depth`. Substrate computes
/// `reflection_depth = max(src) + 1 = 1`. Write succeeds. Pinned to
/// document that the new field is OPTIONAL (no breaking change).
#[test]
fn issue_1325_depth_omitted_preserves_substrate_default() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let conn = db::open(tmp.path()).expect("db::open");
    let src_a = insert_depth0_observation(&conn, "ns-1325-omit", "src-a");
    let src_b = insert_depth0_observation(&conn, "ns-1325-omit", "src-b");

    let resp = handle_reflect(
        &conn,
        tmp.path(),
        &json!({
            "source_ids": [src_a, src_b],
            "title": "reflection omits depth",
            "content": "substrate computes depth from sources",
        }),
        None,
        None,
        None,
        None,
    )
    .expect("omit-depth path must succeed");
    assert_eq!(
        resp["reflection_depth"], 1,
        "substrate-computed depth should be max(src)+1 = 1; got resp={resp}"
    );
}

/// Case 2 — caller asserts the matching depth. Write succeeds.
/// Honors the docstring example payload (`{"depth": 1}` over
/// depth-0 sources).
#[test]
fn issue_1325_depth_matching_substrate_value_accepted() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let conn = db::open(tmp.path()).expect("db::open");
    let src_a = insert_depth0_observation(&conn, "ns-1325-match", "src-a");
    let src_b = insert_depth0_observation(&conn, "ns-1325-match", "src-b");

    let resp = handle_reflect(
        &conn,
        tmp.path(),
        &json!({
            "source_ids": [src_a, src_b],
            "title": "reflection asserts matching depth",
            "content": "depth=1 matches substrate computation over depth-0 sources",
            "depth": 1,
        }),
        None,
        None,
        None,
        None,
    )
    .expect("matching depth must succeed");
    assert_eq!(resp["reflection_depth"], 1);
}

/// Case 3 — caller asserts a mismatched depth. The handler refuses
/// BEFORE the substrate write with a stable `CALLER_DEPTH_MISMATCH`
/// slug. This is the load-bearing regression: pre-#1325 this
/// returned a successful response with `reflection_depth=1` and the
/// caller's `depth=5` silently dropped.
#[test]
fn issue_1325_depth_mismatch_refused_with_stable_slug() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let conn = db::open(tmp.path()).expect("db::open");
    let src_a = insert_depth0_observation(&conn, "ns-1325-bad", "src-a");

    let err = handle_reflect(
        &conn,
        tmp.path(),
        &json!({
            "source_ids": [src_a],
            "title": "reflection asserts wrong depth",
            "content": "depth=5 over depth-0 source must be refused",
            "depth": 5,
        }),
        None,
        None,
        None,
        None,
    )
    .expect_err("mismatched depth must refuse");
    assert!(
        err.starts_with("CALLER_DEPTH_MISMATCH"),
        "refusal must use stable slug; got: {err}"
    );
    assert!(
        err.contains("caller asserted depth=5"),
        "refusal must echo the caller's asserted value; got: {err}"
    );
    assert!(
        err.contains("substrate computed reflection_depth=1"),
        "refusal must echo the substrate-computed value; got: {err}"
    );
}

/// Negative-domain — a negative depth integer is rejected at parse
/// time (`CALLER_DEPTH_MISMATCH` slug) without consulting the substrate.
#[test]
fn issue_1325_negative_depth_rejected_at_parse() {
    let conn = fresh_conn();
    let src_a = insert_depth0_observation(&conn, "ns-1325-neg", "src-a");
    let tmp = NamedTempFile::new().expect("tempfile");

    let err = handle_reflect(
        &conn,
        tmp.path(),
        &json!({
            "source_ids": [src_a],
            "title": "negative depth",
            "content": "should be rejected",
            "depth": -1,
        }),
        None,
        None,
        None,
        None,
    )
    .expect_err("negative depth must refuse");
    assert!(
        err.starts_with("CALLER_DEPTH_MISMATCH"),
        "negative-depth refusal must use the stable slug; got: {err}"
    );
}
