// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3766 — crate-storage driver text never reaches MCP callers at
//! `memory_share` (companion to the `memory_checkpoint_create` lib cells in
//! `src/mcp/tools/checkpoint.rs`).
//!
//! The derived gate-7 model sees direct driver calls (`conn.`, `lock.0`)
//! but not a CRATE storage fn whose DECLARED return type carries the driver
//! error (`db::insert` propagates rusqlite through bare `?` into anyhow),
//! so `db::insert(conn, &m).map_err(|e| e.to_string())` rendered
//! `no such table: memories…` verbatim to the caller.
//!
//! The fault cell drops the FTS companion table (`memories_fts`): the
//! `memories_ai` AFTER INSERT trigger faults the INSERT arm while reads
//! (resolve / visibility) keep working, so the fault lands exactly on the
//! `db::insert` site. Presence + absence on the same sink; the control
//! proves the own-vocabulary ownership refusal still passes through
//! byte-identical, so a funnel that flattened everything could not pass.

#![allow(clippy::missing_panics_doc)]

use ai_memory::mcp::error_text::DB_ERROR_TEXT;
use serde_json::json;

#[cfg(feature = "sal")]
mod common;

fn open_mem() -> rusqlite::Connection {
    ai_memory::db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn seed_owned(conn: &rusqlite::Connection, owner: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "ns3766".to_string(),
        title: "share source 3766".to_string(),
        content: "closed vocabulary regression".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({
            "agent_id": owner,
            "scope": "collective",
            "why_trace": "3766 probe rationale",
        }),
        ..ai_memory::models::Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("seed memory")
}

#[test]
fn share_insert_driver_fault_renders_closed_3766() {
    let conn = open_mem();
    let id = seed_owned(&conn, "ai:owner-3766");
    conn.execute_batch("DROP TABLE memories_fts")
        .expect("drop fts");
    let err = ai_memory::mcp::share::handle_share(
        &conn,
        &json!({"source_memory_id": id, "target_agent_id": "ai:target-3766"}),
        None,
    )
    .expect_err("a faulted insert must fail the share");
    assert_eq!(err, DB_ERROR_TEXT, "the caller gets the class, got: {err}");
    assert!(
        !err.contains("no such table") && !err.contains("memories"),
        "#3766: driver text must not cross to the caller: {err}"
    );
}

#[test]
fn share_ownership_refusal_passes_through_3766() {
    let conn = open_mem();
    let id = seed_owned(&conn, "ai:owner-3766");
    let err = ai_memory::mcp::share::handle_share(
        &conn,
        &json!({"source_memory_id": id, "target_agent_id": "ai:target-3766"}),
        Some("ai:intruder-3766"),
    )
    .expect_err("an intruder share must be refused");
    assert_eq!(
        err,
        ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY,
        "the ownership refusal passes through byte-identical: {err}"
    );
}

/// PG LEG (measured on the build host; self-skips on f1): the funnel each
/// #3766 site routes through renders a live `sqlx` driver fault as the same
/// closed class. The handlers hold a bare `rusqlite::Connection`, so the
/// postgres driver reaches the shared predicate as an anyhow chain — this
/// cell drives that exact seam per site.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn pg_driver_faults_render_closed_per_site_3766() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("pg connect");
    for site in ["checkpoint_create", "share", "namespace_get_standard"] {
        let raw = sqlx::query("SELECT * FROM missing_tbl_3766")
            .execute(&pool)
            .await
            .expect_err("unknown table must fail");
        assert!(
            raw.to_string().contains("missing_tbl_3766"),
            "the injection must carry the marker: {raw}"
        );
        let text = ai_memory::mcp::error_text::mcp_foreign_err(site, anyhow::Error::new(raw));
        assert_eq!(text, DB_ERROR_TEXT, "site {site}: caller gets the class");
        assert!(
            !text.contains("missing_tbl_3766"),
            "#3766: pg driver text must not cross to the caller at {site}: {text}"
        );
    }
}
