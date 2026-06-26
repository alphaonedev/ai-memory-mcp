// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! #1800 — MCP KG visibility gate parity with the #944 HTTP gate.
//!
//! The MCP read tools `memory_find_paths` and `memory_kg_timeline`
//! historically returned KG data (path id-chains; outbound link-event
//! timelines carrying `target_id` / `relation` / `valid_from` / `title` /
//! `target_namespace`) with NO visibility/owner gate, while their HTTP
//! twins enforce the #944 caller-vs-source-owner gate (`handlers/kg.rs`).
//!
//! #1800 mirrors that gate onto the two MCP handlers via the new
//! `caller: Option<&str>` parameter: when a visibility caller is resolved
//! (operator opted in via `AI_MEMORY_AGENT_ID`), both handlers fetch the
//! SOURCE memory and refuse (`Err`) when it exists and is not visible to
//! the caller per `crate::visibility::is_visible_to_caller`. A `None`
//! caller (single-tenant trust-all) or a missing source row proceeds
//! unchanged.
//!
//! Cases pinned here (sqlite — MCP is sqlite-only):
//!   (a) caller==None (trust-all) → both return data (no regression).
//!   (b) caller=="owner", source owned by "owner" (scope=private) → data.
//!   (c) caller=="intruder", source owned by "owner" scope=private →
//!       both return Err (permission denied), NOT the data.
//!   (d) source scope=collective (non-private) → visible to any caller.

use ai_memory::db;
use ai_memory::mcp;
use ai_memory::models;
use ai_memory::models::ConfidenceSource;
use chrono::Utc;
use serde_json::{Value, json};
use tempfile::TempDir;

fn open_db() -> (rusqlite::Connection, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("ai-memory-kg-vis-1800.db");
    let conn = db::open(&path).expect("db::open");
    (conn, tmp)
}

/// Seed a memory with explicit `agent_id` (owner) + `scope` metadata so
/// the visibility predicate has something to gate on.
fn seed(conn: &rusqlite::Connection, title: &str, owner: &str, scope: &str) -> String {
    let now = Utc::now().to_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();
    let mut metadata = models::default_metadata();
    metadata[ai_memory::META_KEY_AGENT_ID] = json!(owner);
    metadata[ai_memory::META_KEY_SCOPE] = json!(scope);
    let mem = models::Memory {
        id: id.clone(),
        tier: models::Tier::Long,
        namespace: "kg-vis-1800".to_string(),
        title: title.to_string(),
        content: "x".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..ai_memory::models::Memory::default()
    };
    db::insert(conn, &mem).expect("db::insert")
}

/// Build a 2-hop chain (A→B→C) under one owner+scope. Returns the ids.
fn chain(conn: &rusqlite::Connection, owner: &str, scope: &str) -> (String, String, String) {
    let a = seed(conn, "a", owner, scope);
    let b = seed(conn, "b", owner, scope);
    let c = seed(conn, "c", owner, scope);
    db::create_link(conn, &a, &b, "related_to").unwrap();
    db::create_link(conn, &b, &c, "related_to").unwrap();
    (a, b, c)
}

fn find_paths(
    conn: &rusqlite::Connection,
    src: &str,
    dst: &str,
    caller: Option<&str>,
) -> Result<Value, String> {
    mcp::handle_find_paths(conn, &json!({"source_id": src, "target_id": dst}), caller)
}

fn kg_timeline(
    conn: &rusqlite::Connection,
    src: &str,
    caller: Option<&str>,
) -> Result<Value, String> {
    mcp::handle_kg_timeline(conn, &json!({"source_id": src}), caller)
}

// ---------------------------------------------------------------------------
// (a) caller==None (trust-all) → data as before (no regression)
// ---------------------------------------------------------------------------

#[test]
fn case_a_trust_all_none_caller_returns_data() {
    let (conn, _tmp) = open_db();
    let (a, _b, c) = chain(&conn, "owner", "private");

    let fp = find_paths(&conn, &a, &c, None).expect("find_paths Ok with None caller");
    assert_eq!(
        fp["count"], 1,
        "trust-all find_paths returns the path: {fp}"
    );

    let tl = kg_timeline(&conn, &a, None).expect("kg_timeline Ok with None caller");
    assert_eq!(tl["count"], 1, "trust-all kg_timeline returns events: {tl}");
}

// ---------------------------------------------------------------------------
// (b) caller==owner, source private → data
// ---------------------------------------------------------------------------

#[test]
fn case_b_owner_caller_private_source_returns_data() {
    let (conn, _tmp) = open_db();
    let (a, _b, c) = chain(&conn, "owner", "private");

    let fp = find_paths(&conn, &a, &c, Some("owner")).expect("find_paths Ok for owner");
    assert_eq!(fp["count"], 1, "owner find_paths returns the path: {fp}");

    let tl = kg_timeline(&conn, &a, Some("owner")).expect("kg_timeline Ok for owner");
    assert_eq!(tl["count"], 1, "owner kg_timeline returns events: {tl}");
}

// ---------------------------------------------------------------------------
// (c) caller==intruder, source private → Err (permission denied), NOT data
// ---------------------------------------------------------------------------

#[test]
fn case_c_intruder_caller_private_source_is_refused() {
    let (conn, _tmp) = open_db();
    let (a, _b, c) = chain(&conn, "owner", "private");

    let fp_err = find_paths(&conn, &a, &c, Some("intruder"))
        .expect_err("find_paths must refuse a non-owner of a private source");
    assert_eq!(
        fp_err,
        ai_memory::errors::msg::CALLER_NOT_SOURCE_MEMORY_OWNER
    );

    let tl_err = kg_timeline(&conn, &a, Some("intruder"))
        .expect_err("kg_timeline must refuse a non-owner of a private source");
    assert_eq!(
        tl_err,
        ai_memory::errors::msg::CALLER_NOT_SOURCE_MEMORY_OWNER
    );
}

// ---------------------------------------------------------------------------
// (d) source scope=collective (non-private) → visible to any caller
// ---------------------------------------------------------------------------

#[test]
fn case_d_collective_source_is_visible_to_any_caller() {
    let (conn, _tmp) = open_db();
    let (a, _b, c) = chain(&conn, "owner", "collective");

    // A caller who is NOT the owner can still read a non-private source.
    let fp = find_paths(&conn, &a, &c, Some("stranger")).expect("find_paths Ok for collective");
    assert_eq!(
        fp["count"], 1,
        "collective find_paths visible to stranger: {fp}"
    );

    let tl = kg_timeline(&conn, &a, Some("stranger")).expect("kg_timeline Ok for collective");
    assert_eq!(
        tl["count"], 1,
        "collective kg_timeline visible to stranger: {tl}"
    );
}
