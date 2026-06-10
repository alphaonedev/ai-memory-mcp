// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]

//! #1579 (v0.7.0 perf final gate) — storage-side regression pins.
//!
//! ## A2 — sargable `list` + composite ordering indexes (schema v56)
//!
//! The P1 perf audit measured the 100k-row `storage::list` page at
//! ~141 ms local / ~156 ms HTTP: every optional filter was written as
//! a non-sargable `(?N IS NULL OR col = ?N)` arm, so the planner fell
//! back to `idx_memories_expires` + `USE TEMP B-TREE FOR ORDER BY`
//! over the whole table. The fix is two-sided and both sides are
//! pinned here:
//!
//! * `db::build_list_query` appends each filter only when present
//!   (distinct prepared shapes), and
//! * migration v56 adds `idx_memories_list_order (priority DESC,
//!   updated_at DESC)` + `idx_memories_ns_list_order (namespace,
//!   priority DESC, updated_at DESC)` so the ORDER BY is the index
//!   walk (plus `idx_archived_ns_archived_at` for `list_archived`).
//!
//! The EXPLAIN tests plan the EXACT production SQL (via the public
//! `build_list_query` SSOT accessor — not a restated copy that could
//! drift) and assert the composite index is chosen AND no temp B-tree
//! sort appears.
//!
//! ## B6 — scale bundle
//!
//! * F5.6 `get_unembedded_ids_batch` LIMIT bound.
//! * F5.7 chunked GC: >1 chunk of expired rows is fully reaped across
//!   bounded transactions with archive semantics intact.

use ai_memory::db;
use ai_memory::models::{Memory, Tier};
use rusqlite::Connection;
use std::path::Path;

fn open_test_db() -> Connection {
    db::open(Path::new(":memory:")).expect("open in-memory DB")
}

/// Run `EXPLAIN QUERY PLAN` over `sql` and return the concatenated
/// plan-detail column. The plan is computed at prepare time; rusqlite
/// still demands a full bind, so every parameter is bound NULL — the
/// same typed-variable posture the production `prepare_cached` call
/// presents to the planner.
fn explain(conn: &Connection, sql: &str) -> String {
    let explain_sql = format!("EXPLAIN QUERY PLAN {sql}");
    let mut stmt = conn.prepare(&explain_sql).expect("prepare EXPLAIN");
    let nulls = vec![rusqlite::types::Value::Null; stmt.parameter_count()];
    let rows = stmt
        .query_map(rusqlite::params_from_iter(nulls), |r| r.get::<_, String>(3))
        .expect("query EXPLAIN");
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect EXPLAIN rows")
        .join(" | ")
}

fn make_memory(title: &str, namespace: &str, priority: i32) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: title.to_string(),
        content: format!("content for {title}"),
        namespace: namespace.to_string(),
        tier: Tier::Long,
        priority,
        created_at: now.clone(),
        updated_at: now,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// A2 — EXPLAIN pins
// ---------------------------------------------------------------------------

#[test]
fn a2_migration_v56_creates_composite_indexes() {
    let conn = open_test_db();
    for idx in [
        "idx_memories_list_order",
        "idx_memories_ns_list_order",
        "idx_archived_ns_archived_at",
    ] {
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                rusqlite::params![idx],
                |r| r.get(0),
            )
            .expect("index probe");
        assert_eq!(n, 1, "migration v56 must create index {idx}");
    }
}

#[test]
fn a2_bare_list_walks_composite_index_without_sort() {
    let conn = open_test_db();
    let now = chrono::Utc::now().to_rfc3339();
    let (sql, _params) =
        db::build_list_query(None, None, None, &now, None, None, None, None, 10, 0);
    let plan = explain(&conn, &sql);
    assert!(
        plan.contains("USING INDEX idx_memories_list_order"),
        "bare list must walk idx_memories_list_order — got: {plan}"
    );
    assert!(
        !plan.contains("TEMP B-TREE FOR ORDER BY"),
        "bare list must not sort (the index IS the ORDER BY) — got: {plan}"
    );
}

#[test]
fn a2_namespace_list_uses_ns_composite_index_without_sort() {
    let conn = open_test_db();
    let now = chrono::Utc::now().to_rfc3339();
    let (sql, _params) = db::build_list_query(
        Some("alpha/ns"),
        None,
        None,
        &now,
        None,
        None,
        None,
        None,
        10,
        0,
    );
    let plan = explain(&conn, &sql);
    assert!(
        plan.contains("USING INDEX idx_memories_ns_list_order"),
        "namespace list must walk idx_memories_ns_list_order — got: {plan}"
    );
    assert!(
        !plan.contains("TEMP B-TREE FOR ORDER BY"),
        "namespace list must not sort — got: {plan}"
    );
}

#[test]
fn a2_namespace_tier_minpriority_list_stays_sort_free() {
    let conn = open_test_db();
    let now = chrono::Utc::now().to_rfc3339();
    let tier = Tier::Long;
    let (sql, _params) = db::build_list_query(
        Some("alpha/ns"),
        Some(&tier),
        Some(5),
        &now,
        None,
        None,
        None,
        None,
        10,
        0,
    );
    let plan = explain(&conn, &sql);
    assert!(
        plan.contains("USING INDEX idx_memories_ns_list_order"),
        "filtered namespace list must still walk the ns composite index — got: {plan}"
    );
    assert!(
        !plan.contains("TEMP B-TREE FOR ORDER BY"),
        "filtered namespace list must not sort — got: {plan}"
    );
}

#[test]
fn a2_min_priority_only_list_range_scans_composite_index() {
    let conn = open_test_db();
    let now = chrono::Utc::now().to_rfc3339();
    let (sql, _params) =
        db::build_list_query(None, None, Some(5), &now, None, None, None, None, 10, 0);
    let plan = explain(&conn, &sql);
    assert!(
        plan.contains("USING INDEX idx_memories_list_order"),
        "min_priority list must range-scan idx_memories_list_order — got: {plan}"
    );
    assert!(
        !plan.contains("TEMP B-TREE FOR ORDER BY"),
        "min_priority list must not sort — got: {plan}"
    );
}

/// B6d — the namespace-filtered `list_archived` shape (restated from
/// `storage::list_archived`; the bare shape keeps using
/// `idx_archived_at`).
#[test]
fn b6d_namespace_list_archived_uses_composite_archive_index() {
    let conn = open_test_db();
    let plan = explain(
        &conn,
        "SELECT id FROM archived_memories WHERE namespace = ?1 \
         ORDER BY archived_at DESC LIMIT ?2 OFFSET ?3",
    );
    assert!(
        plan.contains("USING INDEX idx_archived_ns_archived_at"),
        "namespace-filtered archive list must walk idx_archived_ns_archived_at — got: {plan}"
    );
    assert!(
        !plan.contains("TEMP B-TREE FOR ORDER BY"),
        "namespace-filtered archive list must not sort — got: {plan}"
    );
}

// ---------------------------------------------------------------------------
// A2 — behavioural pin: the sargable builder returns the same rows in
// the same order as the legacy single-shape query would have.
// ---------------------------------------------------------------------------

#[test]
fn a2_list_filters_and_ordering_behave_unchanged() {
    let conn = open_test_db();

    // Two namespaces, mixed priorities, one tagged + agent-attributed row.
    for (title, ns, prio) in [
        ("a-low", "ns/one", 2),
        ("a-high", "ns/one", 9),
        ("a-mid", "ns/one", 5),
        ("b-high", "ns/two", 9),
    ] {
        db::insert(&conn, &make_memory(title, ns, prio)).expect("insert");
    }
    let mut tagged = make_memory("a-tagged", "ns/one", 7);
    tagged.tags = vec!["pinned".to_string()];
    tagged.metadata = serde_json::json!({"agent_id": "ai:test-agent"});
    db::insert(&conn, &tagged).expect("insert tagged");

    // Namespace filter + ordering: priority DESC.
    let listed = db::list(
        &conn,
        Some("ns/one"),
        None,
        10,
        0,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("list ns/one");
    let titles: Vec<&str> = listed.iter().map(|m| m.title.as_str()).collect();
    assert_eq!(
        titles,
        vec!["a-high", "a-tagged", "a-mid", "a-low"],
        "namespace filter + priority DESC ordering must be preserved"
    );

    // min_priority floor.
    let floored = db::list(
        &conn,
        Some("ns/one"),
        None,
        10,
        0,
        Some(6),
        None,
        None,
        None,
        None,
    )
    .expect("list min_priority");
    assert_eq!(floored.len(), 2, "priority >= 6 must keep exactly 2 rows");

    // Tags filter.
    let by_tag = db::list(
        &conn,
        None,
        None,
        10,
        0,
        None,
        None,
        None,
        Some("pinned"),
        None,
    )
    .expect("list by tag");
    assert_eq!(by_tag.len(), 1);
    assert_eq!(by_tag[0].title, "a-tagged");

    // Agent filter (agent_id_idx generated column).
    let by_agent = db::list(
        &conn,
        None,
        None,
        10,
        0,
        None,
        None,
        None,
        None,
        Some("ai:test-agent"),
    )
    .expect("list by agent");
    assert_eq!(by_agent.len(), 1);
    assert_eq!(by_agent[0].title, "a-tagged");

    // LIMIT/OFFSET paging.
    let page2 = db::list(
        &conn,
        Some("ns/one"),
        None,
        2,
        2,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("list page 2");
    let page2_titles: Vec<&str> = page2.iter().map(|m| m.title.as_str()).collect();
    assert_eq!(page2_titles, vec!["a-mid", "a-low"]);

    // since/until window excludes everything in the future.
    let future = "2999-01-01T00:00:00+00:00";
    let none = db::list(
        &conn,
        None,
        None,
        10,
        0,
        None,
        Some(future),
        None,
        None,
        None,
    )
    .expect("list since future");
    assert!(none.is_empty(), "since=2999 must match nothing");
}

// ---------------------------------------------------------------------------
// B6a (F5.6) — bounded unembedded-id fetch
// ---------------------------------------------------------------------------

#[test]
fn b6a_get_unembedded_ids_batch_is_bounded_and_drains() {
    let conn = open_test_db();
    for i in 0..7 {
        db::insert(&conn, &make_memory(&format!("unembedded-{i}"), "ns/emb", 5)).expect("insert");
    }

    let batch = db::get_unembedded_ids_batch(&conn, 3).expect("batch fetch");
    assert_eq!(batch.len(), 3, "LIMIT must bound the materialisation");

    // Embedding the fetched rows removes them from the predicate, so
    // the drain loop converges without an OFFSET.
    for (id, _, _) in &batch {
        db::set_embedding(&conn, id, &[0.1_f32, 0.2, 0.3]).expect("set embedding");
    }
    let rest = db::get_unembedded_ids_batch(&conn, 100).expect("rest fetch");
    assert_eq!(rest.len(), 4, "embedded rows must drop out of the scan");

    // The unbounded snapshot variant agrees.
    let all = db::get_unembedded_ids(&conn).expect("full fetch");
    assert_eq!(all.len(), 4);
}

// ---------------------------------------------------------------------------
// B6c (F5.7) — chunked GC
// ---------------------------------------------------------------------------

/// Seed MORE than one 500-row GC chunk of expired rows, then prove a
/// single `gc` call drains the whole backlog across multiple bounded
/// transactions with archive semantics intact (every reaped row lands
/// in `archived_memories` with reason `ttl_expired`).
#[test]
fn b6c_chunked_gc_reaps_multi_chunk_backlog_with_archive() {
    const EXPIRED: usize = 1_203; // 3 chunks: 500 + 500 + 203
    let conn = open_test_db();
    let past = "2001-01-01T00:00:00+00:00";
    let now = chrono::Utc::now().to_rfc3339();
    {
        let mut stmt = conn
            .prepare(
                "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
                 confidence, source, access_count, created_at, updated_at, metadata, \
                 reflection_depth, expires_at) \
                 VALUES (?1, 'mid', 'gc/test', ?2, 'c', '[]', 5, 1.0, 'test', 0, ?3, ?3, '{}', 0, ?4)",
            )
            .expect("prepare seed");
        for i in 0..EXPIRED {
            stmt.execute(rusqlite::params![
                format!("gc-row-{i:04}"),
                format!("gc-title-{i:04}"),
                now,
                past
            ])
            .expect("seed expired row");
        }
    }
    // One live row that must survive.
    db::insert(&conn, &make_memory("survivor", "gc/test", 5)).expect("insert survivor");

    let reaped = db::gc(&conn, true).expect("gc");
    assert_eq!(
        reaped, EXPIRED,
        "gc must reap every expired row across chunks"
    );

    let live: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
        .expect("live count");
    assert_eq!(live, 1, "only the survivor remains");

    let archived: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE archive_reason = 'ttl_expired'",
            [],
            |r| r.get(0),
        )
        .expect("archive count");
    assert_eq!(
        archived,
        i64::try_from(EXPIRED).expect("fits"),
        "every reaped row must be archived before deletion"
    );

    // Steady state: nothing left to reap; gc_if_needed takes the cheap
    // EXISTS fast path and reports zero.
    let again = db::gc_if_needed(&conn, true).expect("gc_if_needed");
    assert_eq!(again, 0, "second sweep must be a no-op");
}

/// `gc(archive=false)` must delete without archiving — the chunked
/// rewrite must not have coupled the DELETE to the archive INSERT.
#[test]
fn b6c_chunked_gc_without_archive_skips_archive_table() {
    let conn = open_test_db();
    let past = "2001-01-01T00:00:00+00:00";
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
         confidence, source, access_count, created_at, updated_at, metadata, \
         reflection_depth, expires_at) \
         VALUES ('gc-na-1', 'mid', 'gc/na', 't', 'c', '[]', 5, 1.0, 'test', 0, ?1, ?1, '{}', 0, ?2)",
        rusqlite::params![now, past],
    )
    .expect("seed");

    let reaped = db::gc(&conn, false).expect("gc no-archive");
    assert_eq!(reaped, 1);
    let archived: i64 = conn
        .query_row("SELECT COUNT(*) FROM archived_memories", [], |r| r.get(0))
        .expect("archive count");
    assert_eq!(archived, 0, "archive=false must not write archive rows");
}
