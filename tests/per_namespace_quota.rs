// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]
//! v0.7.0 #1156 — per-namespace K8 quota dimension regression tests.
//!
//! The substrate-level inline-unit coverage lives in
//! `src/quotas.rs::tests`. This integration suite pins the
//! end-to-end contracts a downstream caller will rely on:
//!
//! 1. **Per-namespace isolation.** An agent that hits their
//!    memories/day cap in namespace A still has full headroom in
//!    namespace B. Same for storage_bytes + links/day.
//! 2. **Aggregate rollup.** `get_aggregate_status(agent)` sums
//!    counters across every namespace the agent has written into.
//! 3. **Backwards-compat.** Pre-#1156 callers (who didn't pass a
//!    namespace) continue to land on the `_global` sentinel
//!    namespace, preserving the historically-shaped accounting row.
//! 4. **Schema v50 idempotency.** Re-applying the migration is a
//!    no-op on an already-migrated DB.
//! 5. **Listing.** `list_status(None)` returns every per-namespace
//!    row sorted by `(agent_id ASC, namespace ASC)`;
//!    `list_status(Some(ns))` filters to one namespace.
//!
//! NSA CSI MCP mapping: recommendation (c) — defense-in-depth
//! blast-radius controls on a compromised or misbehaving agent.
//! Per-namespace allotments bound a compromised agent's reach
//! without affecting their write capacity in unrelated namespaces.

use ai_memory::quotas::{
    self, DEFAULT_MAX_MEMORIES_PER_DAY, DEFAULT_MAX_STORAGE_BYTES, GLOBAL_NAMESPACE,
    QuotaCheckError, QuotaLimit, QuotaOp,
};
use rusqlite::{Connection, params};

mod common;
use common::fresh_db_tempfile_path as fresh_db;

// ─────────────────────────────────────────────────────────────────────
// Per-namespace isolation
// ─────────────────────────────────────────────────────────────────────

/// An agent that fills their memories/day cap in namespace A must
/// still have full headroom in namespace B.
#[test]
fn per_namespace_memories_isolation() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    // Seed both per-(agent, namespace) rows with a single op.
    quotas::check_and_record(
        &conn,
        "ai:alice",
        "alice/scratch",
        QuotaOp::Memory { bytes: 1 },
    )
    .unwrap();
    quotas::check_and_record(
        &conn,
        "ai:alice",
        "team/policies",
        QuotaOp::Memory { bytes: 1 },
    )
    .unwrap();

    // Tighten only the alice/scratch cap to 1.
    conn.execute(
        "UPDATE agent_quotas SET max_memories_per_day = 1
         WHERE agent_id = ?1 AND namespace = ?2",
        params!["ai:alice", "alice/scratch"],
    )
    .unwrap();

    // Second write to alice/scratch trips the cap.
    let err = quotas::check_and_record(
        &conn,
        "ai:alice",
        "alice/scratch",
        QuotaOp::Memory { bytes: 1 },
    )
    .expect_err("alice/scratch must trip cap");
    match err {
        QuotaCheckError::Quota(q) => {
            assert_eq!(q.namespace, "alice/scratch");
            assert_eq!(q.limit, QuotaLimit::MemoriesPerDay);
            // Display impl must include the namespace.
            assert!(q.to_string().contains("alice/scratch"));
        }
        QuotaCheckError::Sql(e) => panic!("expected Quota, got SQL: {e}"),
    }

    // team/policies still has full headroom.
    quotas::check_and_record(
        &conn,
        "ai:alice",
        "team/policies",
        QuotaOp::Memory { bytes: 1 },
    )
    .expect("team/policies must still have headroom");
    let team_status = quotas::get_status(&conn, "ai:alice", "team/policies").unwrap();
    assert_eq!(team_status.current_memories_today, 2);
    // alice/scratch only has the original 1 row (refused write rolled back).
    let scratch_status = quotas::get_status(&conn, "ai:alice", "alice/scratch").unwrap();
    assert_eq!(scratch_status.current_memories_today, 1);
}

/// Per-namespace storage_bytes isolation — bytes recorded in
/// namespace A do not consume the cap of namespace B.
#[test]
fn per_namespace_storage_bytes_isolation() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    quotas::check_and_record(
        &conn,
        "ai:bob",
        "alice/scratch",
        QuotaOp::Memory { bytes: 50 },
    )
    .unwrap();
    conn.execute(
        "UPDATE agent_quotas SET max_storage_bytes = 100
         WHERE agent_id = ?1 AND namespace = ?2",
        params!["ai:bob", "alice/scratch"],
    )
    .unwrap();

    // 60-byte write in alice/scratch trips the cap (50 + 60 > 100).
    let err = quotas::check_and_record(
        &conn,
        "ai:bob",
        "alice/scratch",
        QuotaOp::Memory { bytes: 60 },
    )
    .expect_err("alice/scratch storage cap should fire");
    assert!(matches!(err, QuotaCheckError::Quota(q) if q.limit == QuotaLimit::StorageBytes));

    // Same write in shared/team-a goes through (default 100 MiB cap).
    quotas::check_and_record(
        &conn,
        "ai:bob",
        "shared/team-a",
        QuotaOp::Memory { bytes: 60 },
    )
    .unwrap();
}

/// Per-namespace links/day isolation.
#[test]
fn per_namespace_links_isolation() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    quotas::check_and_record(&conn, "ai:carol", "alice/scratch", QuotaOp::Link).unwrap();
    conn.execute(
        "UPDATE agent_quotas SET max_links_per_day = 1
         WHERE agent_id = ?1 AND namespace = ?2",
        params!["ai:carol", "alice/scratch"],
    )
    .unwrap();

    let err = quotas::check_and_record(&conn, "ai:carol", "alice/scratch", QuotaOp::Link)
        .expect_err("alice/scratch links cap should fire");
    assert!(matches!(err, QuotaCheckError::Quota(q) if q.limit == QuotaLimit::LinksPerDay));

    // Different namespace still has headroom.
    quotas::check_and_record(&conn, "ai:carol", "team/policies", QuotaOp::Link).unwrap();
}

// ─────────────────────────────────────────────────────────────────────
// Aggregate rollup
// ─────────────────────────────────────────────────────────────────────

/// `get_aggregate_status(agent)` sums counters across every namespace
/// the agent has written into. Returns one synthesised row with
/// `namespace = "_global"`.
#[test]
fn aggregate_rollup_sums_counters() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    quotas::record_op(
        &conn,
        "ai:dan",
        "alice/scratch",
        QuotaOp::Memory { bytes: 100 },
    )
    .unwrap();
    quotas::record_op(
        &conn,
        "ai:dan",
        "team/policies",
        QuotaOp::Memory { bytes: 200 },
    )
    .unwrap();
    quotas::record_op(&conn, "ai:dan", "alice/scratch", QuotaOp::Link).unwrap();
    quotas::record_op(&conn, "ai:dan", "team/policies", QuotaOp::Link).unwrap();
    quotas::record_op(&conn, "ai:dan", "team/policies", QuotaOp::Link).unwrap();

    let agg = quotas::get_aggregate_status(&conn, "ai:dan").unwrap();
    assert_eq!(agg.agent_id, "ai:dan");
    assert_eq!(agg.namespace, GLOBAL_NAMESPACE);
    assert_eq!(agg.current_memories_today, 2);
    assert_eq!(agg.current_storage_bytes, 300);
    assert_eq!(agg.current_links_today, 3);
}

/// `get_aggregate_status` on an agent with no rows falls back to
/// auto-inserting the `_global` row (same shape pre-#1156 callers saw).
#[test]
fn aggregate_rollup_unknown_agent_auto_inserts_global_sentinel() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    let agg = quotas::get_aggregate_status(&conn, "ai:never-seen").unwrap();
    assert_eq!(agg.agent_id, "ai:never-seen");
    assert_eq!(agg.namespace, GLOBAL_NAMESPACE);
    assert_eq!(agg.current_memories_today, 0);
    assert_eq!(agg.max_memories_per_day, DEFAULT_MAX_MEMORIES_PER_DAY);
    assert_eq!(agg.max_storage_bytes, DEFAULT_MAX_STORAGE_BYTES);
}

// ─────────────────────────────────────────────────────────────────────
// Listing — full + per-namespace filter
// ─────────────────────────────────────────────────────────────────────

/// `list_status(None)` returns every (agent, namespace) row sorted
/// by `(agent_id ASC, namespace ASC)`.
#[test]
fn list_status_returns_per_namespace_rows_sorted() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    quotas::record_op(&conn, "ai:eve", "z-ns", QuotaOp::Memory { bytes: 1 }).unwrap();
    quotas::record_op(&conn, "ai:eve", "a-ns", QuotaOp::Memory { bytes: 1 }).unwrap();
    quotas::record_op(&conn, "ai:alice", "z-ns", QuotaOp::Memory { bytes: 1 }).unwrap();

    let rows = quotas::list_status(&conn, None).unwrap();
    // Must include (ai:alice, z-ns), (ai:eve, a-ns), (ai:eve, z-ns) at minimum.
    let triple: Vec<(String, String)> = rows
        .iter()
        .map(|r| (r.agent_id.clone(), r.namespace.clone()))
        .collect();
    let pos_alice_z = triple
        .iter()
        .position(|t| t == &("ai:alice".to_string(), "z-ns".to_string()));
    let pos_eve_a = triple
        .iter()
        .position(|t| t == &("ai:eve".to_string(), "a-ns".to_string()));
    let pos_eve_z = triple
        .iter()
        .position(|t| t == &("ai:eve".to_string(), "z-ns".to_string()));
    assert!(pos_alice_z.is_some() && pos_eve_a.is_some() && pos_eve_z.is_some());
    // Sort order: ai:alice before ai:eve; within ai:eve, a-ns before z-ns.
    assert!(pos_alice_z.unwrap() < pos_eve_a.unwrap());
    assert!(pos_eve_a.unwrap() < pos_eve_z.unwrap());
}

/// `list_status(Some(ns))` filters down to one namespace.
#[test]
fn list_status_namespace_filter() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    quotas::record_op(
        &conn,
        "ai:f1",
        "team/policies",
        QuotaOp::Memory { bytes: 1 },
    )
    .unwrap();
    quotas::record_op(
        &conn,
        "ai:f1",
        "alice/scratch",
        QuotaOp::Memory { bytes: 1 },
    )
    .unwrap();
    quotas::record_op(
        &conn,
        "ai:f2",
        "team/policies",
        QuotaOp::Memory { bytes: 1 },
    )
    .unwrap();

    let rows = quotas::list_status(&conn, Some("team/policies")).unwrap();
    for r in &rows {
        assert_eq!(r.namespace, "team/policies");
    }
    let agent_ids: std::collections::HashSet<String> =
        rows.iter().map(|r| r.agent_id.clone()).collect();
    assert!(agent_ids.contains("ai:f1"));
    assert!(agent_ids.contains("ai:f2"));
}

// ─────────────────────────────────────────────────────────────────────
// Backwards-compat — `_global` sentinel
// ─────────────────────────────────────────────────────────────────────

/// Pre-#1156 callers passing `_global` see the historically-shaped
/// accounting row with default caps.
#[test]
fn global_sentinel_is_backwards_compat_landing_zone() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    quotas::record_op(
        &conn,
        "ai:legacy",
        GLOBAL_NAMESPACE,
        QuotaOp::Memory { bytes: 42 },
    )
    .unwrap();
    let s = quotas::get_status(&conn, "ai:legacy", GLOBAL_NAMESPACE).unwrap();
    assert_eq!(s.namespace, GLOBAL_NAMESPACE);
    assert_eq!(s.current_memories_today, 1);
    assert_eq!(s.current_storage_bytes, 42);
    assert_eq!(s.max_memories_per_day, DEFAULT_MAX_MEMORIES_PER_DAY);
}

/// The `_global` sentinel name starts with an underscore. While
/// `validate_namespace` does not strictly reject underscore-prefixed
/// strings, the convention across the substrate is that operators
/// don't use `_`-prefixed namespaces for user data; this discipline
/// keeps the sentinel out of the user namespace by convention. The
/// test pins the structural shape so a future rename can't
/// accidentally land on a regular-looking identifier.
#[test]
fn global_sentinel_has_underscore_prefix_for_collision_safety() {
    assert!(
        GLOBAL_NAMESPACE.starts_with('_'),
        "GLOBAL_NAMESPACE must keep its leading underscore so it is \
         visibly distinct from user-supplied namespaces; got {GLOBAL_NAMESPACE}"
    );
    assert_eq!(GLOBAL_NAMESPACE, "_global");
}

// ─────────────────────────────────────────────────────────────────────
// Schema v50 idempotency
// ─────────────────────────────────────────────────────────────────────

/// Re-applying the v50 migration ladder against an already-migrated
/// DB is a no-op. Driving `ai_memory::storage::open` against a fresh
/// DB lands at v50; calling it again on the same file MUST NOT
/// re-fire the v50 arm (the arm probes for the `namespace` column
/// and skips the swap when it's already present).
#[test]
fn schema_v50_migration_is_idempotent() {
    let (_keep, db_path) = fresh_db();
    {
        let conn = Connection::open(&db_path).unwrap();
        // Fresh DB is already at v50 via the migration ladder.
        let version: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, 50);

        // Insert a row in a non-_global namespace.
        quotas::record_op(
            &conn,
            "ai:idem",
            "team/policies",
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
    }

    // Re-driving open() runs the migration ladder again. The v50 arm
    // sees `version >= CURRENT_SCHEMA_VERSION` and short-circuits.
    let conn = ai_memory::storage::open(&db_path).unwrap();

    // The row survives intact — no shadow-swap happened.
    let s = quotas::get_status(&conn, "ai:idem", "team/policies").unwrap();
    assert_eq!(s.current_memories_today, 1);
    assert_eq!(s.namespace, "team/policies");
}

/// The v50 migration must preserve pre-existing rows by mapping them
/// into the `_global` namespace sentinel. We can't trivially exercise
/// the upgrade path from a fresh-database start (the ladder runs
/// straight through v50), but we CAN simulate the upgrade by hand-
/// dropping the namespace column and re-driving the arm against a
/// stamped-back-down schema_version. The re-drive goes through the
/// public `ai_memory::storage::open` entry point which runs the
/// migration ladder.
#[test]
fn schema_v50_migration_backfills_global_sentinel() {
    let (_keep, db_path) = fresh_db();
    {
        let conn = Connection::open(&db_path).unwrap();
        // Seed a row at the v50 shape.
        quotas::record_op(
            &conn,
            "ai:bf",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 7 },
        )
        .unwrap();

        // Simulate a downgrade: rebuild the table at the pre-v50 shape
        // so the arm has a non-trivial swap to perform. (This is
        // structural sleight-of-hand; the production migration ladder
        // never reverses.)
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE agent_quotas_pre_v50 (
                 agent_id                TEXT PRIMARY KEY,
                 max_memories_per_day    INTEGER NOT NULL DEFAULT 1000,
                 max_storage_bytes       INTEGER NOT NULL DEFAULT 104857600,
                 max_links_per_day       INTEGER NOT NULL DEFAULT 5000,
                 current_memories_today  INTEGER NOT NULL DEFAULT 0,
                 current_storage_bytes   INTEGER NOT NULL DEFAULT 0,
                 current_links_today     INTEGER NOT NULL DEFAULT 0,
                 day_started_at          TEXT NOT NULL,
                 created_at              TEXT NOT NULL,
                 updated_at              TEXT NOT NULL
             );
             INSERT INTO agent_quotas_pre_v50
                (agent_id, current_memories_today, current_storage_bytes,
                 day_started_at, created_at, updated_at)
             SELECT agent_id, current_memories_today, current_storage_bytes,
                    day_started_at, created_at, updated_at
             FROM agent_quotas WHERE namespace = '_global';
             DROP TABLE agent_quotas;
             ALTER TABLE agent_quotas_pre_v50 RENAME TO agent_quotas;
             DELETE FROM schema_version;
             INSERT INTO schema_version (version) VALUES (49);
             COMMIT;",
        )
        .unwrap();

        // Confirm we're at v49 with the pre-v50 shape.
        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(agent_quotas)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!cols.contains(&"namespace".to_string()));
    }

    // Re-drive open(). The v50 arm fires; the row backfills to _global.
    let conn = ai_memory::storage::open(&db_path).unwrap();
    let s = quotas::get_status(&conn, "ai:bf", GLOBAL_NAMESPACE).unwrap();
    assert_eq!(s.namespace, GLOBAL_NAMESPACE);
    assert_eq!(s.current_memories_today, 1);
    assert_eq!(s.current_storage_bytes, 7);

    // Schema version advanced.
    let version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(version, 50);
}

// ─────────────────────────────────────────────────────────────────────
// Refund symmetry
// ─────────────────────────────────────────────────────────────────────

/// A refund lands on the same `(agent_id, namespace)` row the
/// matching `check_and_record` incremented — refunds in namespace A
/// do not touch namespace B's counter.
#[test]
fn refund_op_is_namespace_scoped() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    quotas::check_and_record(
        &conn,
        "ai:refund",
        "alice/scratch",
        QuotaOp::Memory { bytes: 50 },
    )
    .unwrap();
    quotas::check_and_record(
        &conn,
        "ai:refund",
        "team/policies",
        QuotaOp::Memory { bytes: 25 },
    )
    .unwrap();

    // Refund only the alice/scratch op.
    quotas::refund_op(
        &conn,
        "ai:refund",
        "alice/scratch",
        QuotaOp::Memory { bytes: 50 },
    )
    .unwrap();

    let scratch = quotas::get_status(&conn, "ai:refund", "alice/scratch").unwrap();
    assert_eq!(scratch.current_memories_today, 0);
    assert_eq!(scratch.current_storage_bytes, 0);

    let team = quotas::get_status(&conn, "ai:refund", "team/policies").unwrap();
    // team/policies unaffected by the alice/scratch refund.
    assert_eq!(team.current_memories_today, 1);
    assert_eq!(team.current_storage_bytes, 25);
}
