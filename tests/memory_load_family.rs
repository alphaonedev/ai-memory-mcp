// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! v0.7 Track B1 — `memory_load_family` MCP tool integration tests.
//!
//! B1 ships an always-on alternative to `memory_recall` for the case
//! where the agent already knows the `Family` taxonomy bucket it cares
//! about. The handler filters memories by `metadata.family` (one of the
//! eight enum names) and returns the top-k recent + high-priority
//! matches inside the requested namespace.
//!
//! Scenarios pinned here:
//! 1. Family filter is exact — three memories with different families
//!    seeded; loading one family returns only its match.
//! 2. Namespace filter narrows the result set (cross-namespace
//!    bleed-through is a regression).
//! 3. `k` defaults to 20 and caps at 100 (silent clamp, not error).
//! 4. Unknown family returns the canonical `UnknownFamily` diagnostic.

use ai_memory::db;
use ai_memory::mcp::handle_load_family;
use ai_memory::models::ConfidenceSource;
use ai_memory::models::{self, Memory, Tier};
use chrono::Utc;
use serde_json::{Value, json};

fn open_db() -> rusqlite::Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

/// Seed a memory tagged with `metadata.family = <family>` and the given
/// namespace. The B1 handler walks `json_extract(metadata, '$.family')`,
/// so the family-string must land inside the metadata JSON.
fn seed_family_memory(
    conn: &rusqlite::Connection,
    title: &str,
    namespace: &str,
    family: &str,
    priority: i32,
) -> String {
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("seeded for {family}"),
        tags: vec![],
        priority,
        confidence: 1.0,
        source: "import".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"family": family}),
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
        ..Memory::default()
    };
    let _ = models::default_metadata(); // keep the import live for parity with sibling tests
    db::insert(conn, &mem).expect("db::insert")
}

// ---------------------------------------------------------------------------
// 1. Family filter is exact — only the matching family is returned.
// ---------------------------------------------------------------------------
#[test]
fn load_family_returns_only_matching_family() {
    let conn = open_db();

    // Three memories under the same namespace but with three different
    // family tags. memory_load_family(family=core) must return only the
    // first one.
    let core_id = seed_family_memory(&conn, "core-mem", "ns-a", "core", 5);
    let _graph_id = seed_family_memory(&conn, "graph-mem", "ns-a", "graph", 5);
    let _power_id = seed_family_memory(&conn, "power-mem", "ns-a", "power", 5);

    let resp: Value =
        handle_load_family(&conn, &json!({"family": "core", "namespace": "ns-a"}), None)
            .expect("memory_load_family must succeed");

    assert_eq!(resp["family"], "core");
    assert_eq!(resp["namespace"], "ns-a");
    assert_eq!(
        resp["count"], 1,
        "only the core memory must come back; got: {resp}"
    );
    let memories = resp["memories"].as_array().expect("memories array");
    assert_eq!(memories.len(), 1);
    assert_eq!(memories[0]["id"], core_id);
    assert_eq!(memories[0]["title"], "core-mem");
}

// ---------------------------------------------------------------------------
// 2. Namespace filter narrows the result set — cross-namespace
//    bleed-through is a regression.
// ---------------------------------------------------------------------------
#[test]
fn load_family_namespace_filter_narrows_result_set() {
    let conn = open_db();

    // Two `core` memories in two different namespaces.
    let here_id = seed_family_memory(&conn, "here-core", "ns-a", "core", 5);
    let _there_id = seed_family_memory(&conn, "there-core", "ns-b", "core", 5);

    let resp: Value =
        handle_load_family(&conn, &json!({"family": "core", "namespace": "ns-a"}), None)
            .expect("memory_load_family must succeed");

    assert_eq!(
        resp["count"], 1,
        "namespace must filter cross-ns rows out; got: {resp}"
    );
    let memories = resp["memories"].as_array().expect("memories array");
    assert_eq!(memories[0]["id"], here_id);

    // Without the namespace filter, both rows must come back.
    let resp_all: Value = handle_load_family(&conn, &json!({"family": "core"}), None)
        .expect("must succeed without ns");
    assert_eq!(
        resp_all["count"], 2,
        "no-namespace must span all; got: {resp_all}"
    );
}

// ---------------------------------------------------------------------------
// 3. Priority + recency ordering — higher-priority rows come first;
//    `k` caps the response.
// ---------------------------------------------------------------------------
#[test]
fn load_family_orders_by_priority_then_recency_and_caps_k() {
    let conn = open_db();

    // Seed three core memories with descending priorities.
    let _low = seed_family_memory(&conn, "low", "ns", "core", 1);
    let _mid = seed_family_memory(&conn, "mid", "ns", "core", 5);
    let _hi = seed_family_memory(&conn, "hi", "ns", "core", 9);

    let resp: Value = handle_load_family(&conn, &json!({"family": "core", "k": 2}), None).unwrap();
    assert_eq!(resp["count"], 2, "k=2 must cap to two rows");
    let memories = resp["memories"].as_array().unwrap();
    assert_eq!(memories[0]["title"], "hi");
    assert_eq!(memories[1]["title"], "mid");
    assert_eq!(resp["k"], 2);

    // k clamps silently at 100 — passing 9999 is treated as 100, not an
    // error. We only have 3 rows so the count is 3 either way; the
    // payload's reported `k` is the clamped value.
    let resp_big: Value =
        handle_load_family(&conn, &json!({"family": "core", "k": 9999}), None).unwrap();
    assert_eq!(resp_big["k"], 100, "k must clamp to 100");
    assert_eq!(resp_big["count"], 3);
}

// ---------------------------------------------------------------------------
// 4. Unknown family → canonical UnknownFamily diagnostic (lists valid
//    family names so the caller can self-correct).
// ---------------------------------------------------------------------------
#[test]
fn load_family_unknown_family_yields_diagnostic_error() {
    let conn = open_db();
    let err = handle_load_family(&conn, &json!({"family": "xyz"}), None).unwrap_err();
    assert!(
        err.contains("xyz"),
        "diagnostic must echo the bad value; got: {err}"
    );
    assert!(
        err.contains("core"),
        "diagnostic must list valid families; got: {err}"
    );
    assert!(
        err.contains("graph"),
        "diagnostic must list valid families; got: {err}"
    );
}

// ---------------------------------------------------------------------------
// 5. Missing required `family` arg → handler returns Err.
// ---------------------------------------------------------------------------
#[test]
fn load_family_missing_family_arg_errors() {
    let conn = open_db();
    let err = handle_load_family(&conn, &json!({}), None).unwrap_err();
    assert!(
        err.contains("family"),
        "error must mention missing arg; got: {err}"
    );
}

// ---------------------------------------------------------------------------
// #2600 (CB-15) — lifecycle allow-list on the sqlite path.
//
// Pre-fix the sqlite `handle_load_family` query had NO
// `lifecycle_visible_clause`, so quarantined + tombstoned rows were
// readable through this always-on core-profile tool, bypassing the #1948
// fail-closed lifecycle allow-list — while postgres filtered them (a
// cross-backend divergence). A quarantined AND a tombstoned family-tagged
// row must NOT come back; the open row must.
// ---------------------------------------------------------------------------
fn seed_family_memory_lifecycle(
    conn: &rusqlite::Connection,
    title: &str,
    namespace: &str,
    family: &str,
    lifecycle_state: &str,
) -> String {
    let id = seed_family_memory(conn, title, namespace, family, 5);
    conn.execute(
        "UPDATE memories SET lifecycle_state = ?1 WHERE id = ?2",
        rusqlite::params![lifecycle_state, id],
    )
    .expect("set lifecycle_state");
    id
}

#[test]
fn load_family_excludes_quarantined_and_tombstoned_rows_2600() {
    let conn = open_db();

    let open_id = seed_family_memory_lifecycle(&conn, "open-mem", "ns", "core", "open");
    let _quar = seed_family_memory_lifecycle(&conn, "quar-mem", "ns", "core", "quarantined");
    let _tomb = seed_family_memory_lifecycle(&conn, "tomb-mem", "ns", "core", "tombstoned");

    let resp: Value =
        handle_load_family(&conn, &json!({"family": "core", "namespace": "ns"}), None).unwrap();

    assert_eq!(
        resp["count"], 1,
        "only the lifecycle-visible row must return; got: {resp}"
    );
    let memories = resp["memories"].as_array().unwrap();
    assert_eq!(memories.len(), 1);
    assert_eq!(memories[0]["id"], open_id);
}

// ---------------------------------------------------------------------------
// #2601 (CB-15) — the scope=private visibility filter runs BEFORE the LIMIT
// (via the postgres-style escalation), so hidden rows sitting above the
// `k` boundary no longer under-return the visible set.
//
// Seed (all family=core, one namespace):
//   - two HIGH-priority rows owned by "other" + scope=private (hidden from
//     caller "me") — these sort FIRST and would fill a bare `LIMIT 2`;
//   - two lower-priority rows owned by "me" (visible).
// Pre-fix: SQL `LIMIT 2` returns the two hidden rows, the Rust filter drops
// both → count 0 (silent under-return). Post-fix: escalate + re-filter →
// the two visible rows come back.
// ---------------------------------------------------------------------------
fn seed_family_memory_owned(
    conn: &rusqlite::Connection,
    title: &str,
    namespace: &str,
    family: &str,
    priority: i32,
    owner: &str,
) -> String {
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("seeded for {family}"),
        tags: vec![],
        priority,
        confidence: 1.0,
        source: "import".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"family": family, "scope": "private", "agent_id": owner}),
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
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("db::insert")
}

#[test]
fn load_family_visibility_applies_before_limit_no_under_return_2601() {
    let conn = open_db();

    // Two hidden (other-owned, private) high-priority rows sort first.
    seed_family_memory_owned(&conn, "hidden-1", "ns", "core", 9, "other");
    seed_family_memory_owned(&conn, "hidden-2", "ns", "core", 8, "other");
    // Two visible (me-owned) lower-priority rows sit past the k=2 boundary.
    let mine_hi = seed_family_memory_owned(&conn, "mine-hi", "ns", "core", 5, "me");
    let mine_lo = seed_family_memory_owned(&conn, "mine-lo", "ns", "core", 4, "me");

    let resp: Value = handle_load_family(
        &conn,
        &json!({"family": "core", "namespace": "ns", "k": 2}),
        Some("me"),
    )
    .unwrap();

    assert_eq!(
        resp["count"], 2,
        "visibility must be applied before the LIMIT so both visible rows \
         come back even though hidden rows sort above them; got: {resp}"
    );
    let rows = resp["memories"].as_array().unwrap();
    let ids: Vec<&str> = rows.iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&mine_hi.as_str()), "mine-hi must be returned");
    assert!(ids.contains(&mine_lo.as_str()), "mine-lo must be returned");
    // No other-owned private row leaked through.
    for m in rows {
        let title = m["title"].as_str().unwrap();
        assert!(
            !title.starts_with("hidden"),
            "other-owned private row leaked: {title}"
        );
    }
}
