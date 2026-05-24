// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

//! Regression suite for issue #1172 — `memory_reflect` metadata-passthrough drop.
//!
//! ## Defect
//!
//! `memory_reflect` accepted a `metadata` object parameter but the
//! observed behavior (per the issue's sqlite probe) showed the stored
//! row's metadata column carrying only the canonical
//! `{agent_id, reflection_metadata}` keys — caller-supplied keys such
//! as `entity_id` were absent. This broke the documented PERF-8
//! step-1 path of [`ai_memory::storage::extract_mentioned_entity_id`]
//! which keys the auto-persona / `load_reflections_for_entity` lookup
//! off `metadata.entity_id`.
//!
//! ## Invariants pinned
//!
//! 1. Substrate-level [`ai_memory::db::reflect`]: when called with
//!    `metadata.entity_id = "X"`, the stored row's metadata carries
//!    `entity_id = "X"` alongside the system-generated
//!    `agent_id` + `reflection_metadata` keys.
//! 2. Same call populates the indexed `mentioned_entity_id` column
//!    with `"X"` (the PERF-8 step-1 path in
//!    [`ai_memory::storage::extract_mentioned_entity_id`]).
//! 3. MCP wire layer ([`ai_memory::mcp::handle_reflect`]): the same
//!    `metadata.entity_id = "X"` round-trips end-to-end through the
//!    JSON-RPC boundary into the same row state.
//! 4. End-to-end: a reflection bound via `metadata.entity_id` is
//!    discoverable by an indexed `mentioned_entity_id` lookup (the
//!    same shape `persona::load_reflections_for_entity` uses) without
//!    needing the `[entity:X]` title-marker fallback.
//! 5. Back-compat: empty caller metadata still produces the canonical
//!    shape (the pre-#1172 behavior must not regress for callers who
//!    didn't supply custom keys).
//! 6. Caller-supplied `reflection_metadata` is honored over the
//!    system-generated splice (documented additive contract — caller
//!    wins on collision).
//!
//! ## On the choice of `source`
//!
//! The fixtures use the vendor-neutral role-categorical source value
//! [`FIXTURE_SOURCE`] (`"api"`) rather than any LLM-vendor identifier.
//! The substrate is heterogeneous-NHI by design (Anthropic, OpenAI,
//! xAI, etc. all write reflections through the same primitive); pinning
//! a regression to one vendor's name in test data would itself be a
//! monoculture defect.

use ai_memory::db::{self, ReflectInput};
use ai_memory::mcp;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use chrono::Utc;
use rusqlite::Connection;
use serde_json::{Value, json};

mod common;
use common::fresh_conn;

// ---------------------------------------------------------------------------
// Test invariants — constants, not magic literals.
//
// One source of truth per concept so changing the test scenario (e.g.
// renaming the fixture entity, swapping the source kind) is a single
// edit, and the assertions read against the same names the fixtures
// produced. Each test still uses its own namespace to keep state
// isolated within the shared :memory: DB.
// ---------------------------------------------------------------------------

const FIXTURE_AGENT_ID: &str = "test-agent-1172";
/// Vendor-neutral role-categorical source value. The substrate accepts
/// `user | claude | hook | api | cli | import | consolidation | system
/// | chaos | notify`; `"api"` is the LLM-agnostic role that any
/// frontier-model AI NHI writing through the substrate would naturally
/// occupy.
const FIXTURE_SOURCE: &str = "api";
const FIXTURE_ENTITY_ID: &str = "entity-uuid-aaaa-bbbb";
const FIXTURE_ENTITY_ID_MCP: &str = "entity-uuid-mcp-1172";
const FIXTURE_ENTITY_ID_E2E: &str = "entity-uuid-e2e";
const FIXTURE_ENTITY_ID_COLLISION: &str = "entity-uuid-collision";

const NS_SUBSTRATE: &str = "issue-1172-ns";
const NS_MCP: &str = "issue-1172-mcp";
const NS_E2E: &str = "issue-1172-e2e";
const NS_EMPTY: &str = "issue-1172-empty";
const NS_COLLISION: &str = "issue-1172-coll";

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
        content: format!("issue_1172 fixture observation: {title}"),
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

fn reflect_input(
    source_ids: Vec<String>,
    namespace: &str,
    title: &str,
    metadata: Value,
) -> ReflectInput {
    ReflectInput {
        source_ids,
        title: title.to_string(),
        content: format!("synthesised reflection content for {title}"),
        namespace: Some(namespace.to_string()),
        tier: Tier::Mid,
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: FIXTURE_SOURCE.to_string(),
        agent_id: FIXTURE_AGENT_ID.to_string(),
        metadata,
    }
}

fn read_metadata_and_mention(conn: &Connection, id: &str) -> (Value, Option<String>) {
    conn.query_row(
        "SELECT metadata, mentioned_entity_id FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |row| {
            let meta_str: String = row.get(0)?;
            let mention: Option<String> = row.get(1)?;
            Ok((
                serde_json::from_str(&meta_str).unwrap_or(Value::Null),
                mention,
            ))
        },
    )
    .expect("read row by id")
}

// ---------------------------------------------------------------------------
// (1) Substrate-level pin — db::reflect preserves caller metadata.entity_id
// ---------------------------------------------------------------------------

#[test]
fn db_reflect_preserves_caller_supplied_entity_id() {
    let conn = fresh_conn();
    let src_id = seed_observation(&conn, NS_SUBSTRATE, "src-observation");

    let input = reflect_input(
        vec![src_id],
        NS_SUBSTRATE,
        "reflection-binding-via-metadata",
        json!({"entity_id": FIXTURE_ENTITY_ID}),
    );
    let outcome = db::reflect(&conn, &input).expect("reflect must succeed");

    let (meta, mention) = read_metadata_and_mention(&conn, &outcome.id);

    // Invariant 1: caller-supplied entity_id round-trips into stored metadata.
    assert_eq!(
        meta.get("entity_id").and_then(Value::as_str),
        Some(FIXTURE_ENTITY_ID),
        "metadata.entity_id must survive the reflect persist path; full metadata = {meta}"
    );

    // System-generated keys land alongside it (additive contract).
    assert!(
        meta.get("agent_id").is_some(),
        "system-generated agent_id must still be spliced in"
    );
    assert!(
        meta.get("reflection_metadata").is_some(),
        "system-generated reflection_metadata must still be spliced in"
    );

    // Invariant 2: the PERF-8 indexed column is populated from the caller's entity_id.
    assert_eq!(
        mention.as_deref(),
        Some(FIXTURE_ENTITY_ID),
        "mentioned_entity_id column must be populated by extract_mentioned_entity_id step-1"
    );
}

// ---------------------------------------------------------------------------
// (2) MCP wire-layer pin — handle_reflect preserves metadata.entity_id
// ---------------------------------------------------------------------------

#[test]
fn mcp_handle_reflect_preserves_caller_supplied_entity_id() {
    let (tmp, db_path) = common::fresh_db_tempfile_path();
    let _ = &tmp; // keep tempfile alive for the test body
    let conn = db::open(&db_path).expect("re-open db");

    let src_id = seed_observation(&conn, NS_MCP, "src-observation");

    let params = json!({
        "source_ids": [src_id],
        "title": "reflection-via-mcp-handler",
        "content": "synthesised reflection content",
        "namespace": NS_MCP,
        "agent_id": FIXTURE_AGENT_ID,
        "metadata": {"entity_id": FIXTURE_ENTITY_ID_MCP},
    });

    let resp = mcp::handle_reflect(&conn, &db_path, &params, None, None, None, None)
        .expect("handle_reflect ok");
    let new_id = resp["id"].as_str().expect("id in response").to_string();

    let (meta, mention) = read_metadata_and_mention(&conn, &new_id);

    assert_eq!(
        meta.get("entity_id").and_then(Value::as_str),
        Some(FIXTURE_ENTITY_ID_MCP),
        "MCP wire layer must preserve caller-supplied metadata.entity_id; full metadata = {meta}"
    );
    assert_eq!(
        mention.as_deref(),
        Some(FIXTURE_ENTITY_ID_MCP),
        "mentioned_entity_id column must reflect caller-supplied entity_id"
    );
}

// ---------------------------------------------------------------------------
// (3) End-to-end persona-binding — reflection is discoverable by entity_id
//     without the [entity:X] title-marker workaround documented at
//     `src/storage/mod.rs:557`.
// ---------------------------------------------------------------------------

#[test]
fn entity_bound_reflection_is_discoverable_without_title_marker() {
    let conn = fresh_conn();
    let src_id = seed_observation(&conn, NS_E2E, "src-observation");

    // Title deliberately omits the [entity:X] marker — exercising the
    // metadata-driven path, not the title-scan fallback.
    let input = reflect_input(
        vec![src_id],
        NS_E2E,
        "naked-reflection-no-title-marker",
        json!({"entity_id": FIXTURE_ENTITY_ID_E2E}),
    );
    let outcome = db::reflect(&conn, &input).expect("reflect must succeed");

    // The persona path keys off the PERF-8 indexed column via SQL
    // `WHERE mentioned_entity_id = ?` (see persona::load_reflections_for_entity).
    // Probe the same SELECT shape so this test pins the column the
    // persona path consumes.
    let found: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories
             WHERE namespace = ?1
               AND memory_kind = 'reflection'
               AND mentioned_entity_id = ?2",
            rusqlite::params![NS_E2E, FIXTURE_ENTITY_ID_E2E],
            |r| r.get(0),
        )
        .expect("count reflections");
    assert_eq!(
        found, 1,
        "load_reflections_for_entity-shaped SELECT must find the reflection \
         bound only via metadata.entity_id (no title marker present); outcome.id = {}",
        outcome.id
    );
}

// ---------------------------------------------------------------------------
// (4) Back-compat — empty caller metadata produces the canonical shape.
// ---------------------------------------------------------------------------

#[test]
fn empty_caller_metadata_preserves_pre_1172_canonical_shape() {
    let conn = fresh_conn();
    let src_id = seed_observation(&conn, NS_EMPTY, "src-observation");

    let input = reflect_input(
        vec![src_id],
        NS_EMPTY,
        "empty-metadata-reflection",
        json!({}),
    );
    let outcome = db::reflect(&conn, &input).expect("reflect must succeed");

    let (meta, mention) = read_metadata_and_mention(&conn, &outcome.id);

    // Canonical shape: agent_id + reflection_metadata, nothing else.
    assert!(
        meta.get("agent_id").is_some(),
        "agent_id must be spliced in"
    );
    assert!(
        meta.get("reflection_metadata").is_some(),
        "reflection_metadata block must be spliced in"
    );
    assert!(
        meta.get("entity_id").is_none(),
        "no entity_id should appear when caller didn't supply one"
    );
    assert!(
        mention.is_none(),
        "mentioned_entity_id stays NULL when no entity binding was supplied"
    );
}

// ---------------------------------------------------------------------------
// (5) Caller-supplied reflection_metadata wins on collision — the
//     documented additive-contract invariant from src/storage/reflect.rs:213.
// ---------------------------------------------------------------------------

#[test]
fn caller_supplied_reflection_metadata_wins_on_collision() {
    let conn = fresh_conn();
    let src_id = seed_observation(&conn, NS_COLLISION, "src-observation");

    let caller_block = json!({"caller_owned": true, "reflection_depth": 99});
    let input = reflect_input(
        vec![src_id],
        NS_COLLISION,
        "collision-reflection",
        json!({
            "reflection_metadata": caller_block,
            "entity_id": FIXTURE_ENTITY_ID_COLLISION,
        }),
    );
    let outcome = db::reflect(&conn, &input).expect("reflect must succeed");

    let (meta, _) = read_metadata_and_mention(&conn, &outcome.id);

    // Caller's reflection_metadata is preserved verbatim — system
    // splice does NOT overwrite it.
    let stored_block = meta
        .get("reflection_metadata")
        .expect("reflection_metadata key present");
    assert_eq!(
        stored_block, &caller_block,
        "caller-supplied reflection_metadata wins on collision"
    );

    // entity_id passthrough still works alongside the collision win.
    assert_eq!(
        meta.get("entity_id").and_then(Value::as_str),
        Some(FIXTURE_ENTITY_ID_COLLISION)
    );
}
