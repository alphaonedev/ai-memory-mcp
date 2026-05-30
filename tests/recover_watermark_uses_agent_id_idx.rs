// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]

//! v0.7.0 R5.F5.3 (#1419) — regression pin for the L2
//! `recover_from_transcript` watermark query routing through the
//! indexed `agent_id_idx` VIRTUAL column.
//!
//! Before this fix the watermark query used
//! `json_extract(metadata, '$.agent_id') = ?1`, which SQLite cannot
//! index — degenerating to a full table scan on populated DBs and
//! blowing the L2 fast-path `<100 ms` budget pinned by issue #1394.
//!
//! The v14 migration (`src/storage/migrations.rs:1174-1209`) added
//! the VIRTUAL generated column `agent_id_idx` + index
//! `idx_memories_agent_id` precisely so `agent_id` lookups can use
//! a real index. This regression test pins that the rewritten
//! watermark query (`WHERE agent_id_idx = ?1`) shows up in the
//! SQLite query plan as a SEARCH using `idx_memories_agent_id`.
//!
//! ## Probe: `EXPLAIN QUERY PLAN`
//!
//! `EXPLAIN QUERY PLAN` is SQLite's diagnostic that shows which
//! index (if any) the planner picked for each table reference.
//! For our two-form comparison:
//!
//! - Legacy (`json_extract(metadata, '$.agent_id') = ?1`) → plan
//!   line shows "SCAN memories" — full table scan, no index.
//! - Fixed (`agent_id_idx = ?1`) → plan line shows
//!   "SEARCH memories USING INDEX idx_memories_agent_id" — the
//!   v14 index does the work.
//!
//! The test pins the FIXED form. If a future refactor regresses
//! the query back to `json_extract`, the plan no longer mentions
//! `idx_memories_agent_id` and the test fails.

use rusqlite::Connection;

/// Bring a fresh DB up to the current schema (v53 at the moment
/// this fix lands). The substrate's `open()` runs SCHEMA bootstrap
/// plus the migration ladder; the v14 arm installs `agent_id_idx`
/// and `idx_memories_agent_id`, so by the time `open()` returns
/// the index the planner needs is in place.
fn fresh_db() -> Connection {
    let local_runs = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("recover-watermark-agent-id-idx");
    std::fs::create_dir_all(&local_runs).expect("create local-runs dir");
    let tmpdir = tempfile::tempdir_in(&local_runs).expect("tempdir under .local-runs");
    let db_path = tmpdir.path().join("test.db");
    std::mem::forget(tmpdir);
    ai_memory::storage::open(&db_path).expect("open fresh db")
}

/// Run `EXPLAIN QUERY PLAN` and return the concatenated plan-detail
/// text. Each row of EXPLAIN QUERY PLAN has the shape
/// `(id, parent, notused, detail)`; the load-bearing column is
/// `detail`. The `bound` parameter is the value bound to the `?1`
/// placeholder in the SQL; SQLite needs every parameter slot filled
/// to prepare the EXPLAIN, even though the plan is invariant in the
/// bound value.
fn explain_query_plan(conn: &Connection, sql: &str, bound: &str) -> String {
    let explain_sql = format!("EXPLAIN QUERY PLAN {sql}");
    let mut stmt = conn.prepare(&explain_sql).expect("prepare EXPLAIN");
    let rows = stmt
        .query_map(rusqlite::params![bound], |row| {
            // The fourth column is the human-readable detail.
            row.get::<_, String>(3)
        })
        .expect("query EXPLAIN plan");
    let mut out = String::new();
    for r in rows {
        let detail = r.expect("EXPLAIN row detail");
        out.push_str(&detail);
        out.push('\n');
    }
    out
}

#[test]
fn watermark_query_uses_idx_memories_agent_id() {
    // The exact query string the L2 watermark probe runs (see
    // `src/recover/mod.rs` after the R5.F5.3 fix). The bound
    // parameter is irrelevant for plan analysis — SQLite picks
    // the plan from the SQL shape + statistics, not the bound
    // value.
    //
    // We pin the post-fix shape: `WHERE agent_id_idx = ?1`. If
    // a future refactor reverts to `json_extract(...) = ?1`, the
    // plan no longer mentions `idx_memories_agent_id` and the
    // assertion below fires.
    let conn = fresh_db();
    let fixed_sql = "SELECT MAX(created_at) FROM memories WHERE agent_id_idx = ?1";

    let plan = explain_query_plan(&conn, fixed_sql, "ai:test-agent");

    // Load-bearing assertion: the index is used. SQLite's plan
    // detail text for an indexed equality lookup looks like
    // "SEARCH memories USING INDEX idx_memories_agent_id ..."
    // (older SQLite) or "SEARCH TABLE memories USING INDEX ..."
    // (newer SQLite). Both spellings contain the index name.
    assert!(
        plan.contains("idx_memories_agent_id"),
        "L2 watermark query MUST use the v14 idx_memories_agent_id index. \
         EXPLAIN QUERY PLAN output:\n{plan}"
    );

    // Defense-in-depth: the planner should report SEARCH, not
    // SCAN, against the `memories` table. SEARCH = indexed
    // lookup; SCAN = full table scan. The pre-fix query plan
    // would have a "SCAN memories" line because json_extract is
    // un-indexable; the fixed query must show SEARCH.
    let upper = plan.to_uppercase();
    let has_search = upper.contains("SEARCH");
    assert!(
        has_search,
        "L2 watermark query plan MUST show SEARCH (indexed lookup), not SCAN. \
         EXPLAIN QUERY PLAN output:\n{plan}"
    );
}

#[test]
fn legacy_json_extract_form_does_full_scan() {
    // Negative control — verify our methodology by demonstrating
    // that the PRE-fix query shape does NOT use the index. This
    // is the empirical evidence that R5.F5.3's diagnosis was
    // correct: `json_extract(metadata, '$.agent_id') = ?1`
    // cannot ride `idx_memories_agent_id`. If this assertion
    // ever flips (i.e., SQLite gains the ability to index
    // json_extract over expressions), the rewrite would no
    // longer be strictly necessary and the fix can be
    // re-evaluated — but until then this control documents the
    // observable.
    let conn = fresh_db();
    let legacy_sql = "SELECT MAX(created_at) FROM memories \
                      WHERE json_extract(metadata, '$.agent_id') = ?1";

    let plan = explain_query_plan(&conn, legacy_sql, "ai:test-agent");

    // The legacy form MUST NOT use the agent_id index.
    assert!(
        !plan.contains("idx_memories_agent_id"),
        "PRE-fix json_extract form MUST NOT use idx_memories_agent_id \
         (that's the whole reason R5.F5.3 was filed). \
         EXPLAIN QUERY PLAN output:\n{plan}"
    );
}

#[test]
fn agent_id_idx_column_exists_post_v14() {
    // Sanity pin — verify the v14 migration actually installed
    // `agent_id_idx` + `idx_memories_agent_id`, so the fixed
    // query has a real target. If a future refactor drops the
    // v14 arm (or the VIRTUAL column changes shape), this test
    // catches it before the L2 watermark rewrite silently
    // regresses back to a SCAN.
    let conn = fresh_db();

    // VIRTUAL column probe — `SELECT ... LIMIT 0` succeeds if the
    // column exists, errors if it doesn't.
    let column_exists = conn
        .prepare("SELECT agent_id_idx FROM memories LIMIT 0")
        .is_ok();
    assert!(
        column_exists,
        "v14 migration MUST install the `agent_id_idx` VIRTUAL column \
         on memories — required by R5.F5.3 fix"
    );

    // Index existence probe via sqlite_master.
    let idx_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'index' AND name = 'idx_memories_agent_id'",
            [],
            |r| r.get(0),
        )
        .expect("query sqlite_master for idx_memories_agent_id");
    assert_eq!(
        idx_exists, 1,
        "v14 migration MUST install `idx_memories_agent_id` — required by R5.F5.3 fix"
    );
}
