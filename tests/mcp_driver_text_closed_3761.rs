// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3761 — driver error text never reaches MCP callers.
//!
//! The DERIVED gate-7 re-cut found two shapes the enumerated gate could not
//! see: a `?`-propagated `Result<_, String>` helper outside `src/mcp/`
//! (`actions::create_guarded*`, reached verbatim from `memory_action_create`)
//! and `match`-arm values carrying `.map_err(|e| e.to_string())`
//! (forget / archive / lineage / namespace). Each rendered a
//! `rusqlite::Error` / anyhow-chain `Display` — table names, SQL fragments,
//! constraint text — to the MCP caller.
//!
//! Every cell below injects a driver fault (a dropped table, so the
//! `Display` carries a table name) and asserts the MCP result text does NOT
//! contain the table name AND does contain the closed-vocabulary phrase
//! (presence + absence on the same sink). The controls prove our OWN
//! closed-vocabulary refusals still pass through unflattened, so a funnel
//! that flattened everything to a constant could not pass.

#![allow(clippy::missing_panics_doc)]

use ai_memory::mcp::error_text::DB_ERROR_TEXT;
use serde_json::json;

#[cfg(feature = "sal")]
mod common;

fn open_mem() -> rusqlite::Connection {
    unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
    ai_memory::db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn action_params(namespace: &str) -> serde_json::Value {
    json!({
        "namespace": namespace,
        "kind": "test.kind",
        "title": "t3761",
        "payload": {"a": 1},
        "agent_id": "agent-x",
    })
}

#[test]
fn action_create_driver_fault_renders_closed_3761() {
    let conn = open_mem();
    conn.execute_batch("DROP TABLE actions")
        .expect("drop actions");
    let err = ai_memory::mcp::handle_action_create(&conn, &action_params("_act"))
        .expect_err("a dropped actions table must fail the create");
    assert_eq!(err, DB_ERROR_TEXT, "the caller gets the class, got: {err}");
    assert!(
        !err.contains("no such table") && !err.contains("actions"),
        "#3761: driver text must not cross to the caller: {err}"
    );
}

#[test]
fn action_create_validation_refusal_passes_through_3761() {
    let conn = open_mem();
    let err = ai_memory::mcp::handle_action_create(&conn, &action_params(""))
        .expect_err("an empty namespace must be refused");
    assert_ne!(
        err, DB_ERROR_TEXT,
        "an own-vocabulary refusal must not be flattened to the class: {err}"
    );
    assert!(
        err.contains("namespace"),
        "the refusal must still name the bad field: {err}"
    );
}

fn seed_memory(conn: &rusqlite::Connection, title: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "ns3761".to_string(),
        title: title.to_string(),
        content: "closed vocabulary regression".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": "ai:me", "scope": "collective"}),
        ..ai_memory::models::Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("seed memory")
}

#[test]
fn lineage_driver_fault_renders_closed_3761() {
    let conn = open_mem();
    let a = seed_memory(&conn, "src 3761");
    let b = seed_memory(&conn, "dst 3761");
    ai_memory::db::create_link(&conn, &a, &b, "related_to").expect("seed edge");
    conn.execute_batch("DROP TABLE memory_links").expect("drop");
    let err = ai_memory::mcp::handle_lineage(&conn, &json!({"id": a}), None)
        .expect_err("a dropped link table must fail the walk");
    assert_eq!(err, DB_ERROR_TEXT, "the caller gets the class, got: {err}");
    assert!(
        !err.contains("no such table") && !err.contains("memory_links"),
        "#3761: driver text must not cross to the caller: {err}"
    );
}

#[test]
fn lineage_depth_refusal_passes_through_3761() {
    let conn = open_mem();
    let a = seed_memory(&conn, "src 3761");
    let err = ai_memory::mcp::handle_lineage(&conn, &json!({"id": a, "max_depth": 0}), None)
        .expect_err("max_depth=0 must be refused");
    assert_ne!(
        err, DB_ERROR_TEXT,
        "an own-vocabulary refusal must not be flattened to the class: {err}"
    );
    assert!(
        err.contains("max_depth"),
        "the refusal must still name the bad field: {err}"
    );
}

#[test]
fn namespace_bind_read_fault_refuses_closed_3761() {
    let conn = open_mem();
    conn.execute_batch("DROP TABLE namespace_meta")
        .expect("drop");
    let err = ai_memory::mcp::handle_namespace_set_standard(
        &conn,
        &json!({"namespace": "ns3761", "id": "00000000-0000-0000-0000-000000000000"}),
    )
    .expect_err("an unverifiable current owner must refuse the bind");
    assert!(
        !err.contains("no such table") && !err.contains("namespace_meta"),
        "#3761: driver text must not cross to the caller: {err}"
    );
    assert!(
        err.contains("refusing the bind"),
        "the fail-closed refusal must survive: {err}"
    );
}

#[test]
fn namespace_ownership_refusal_passes_through_3761() {
    unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") };
    unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
    let dir = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(dir.path()).expect("open");
    let ttl = ai_memory::config::ResolvedTtl::default();
    let owner = "ai:owner-3761";
    let intruder = "ai:intruder-3761";
    let id = ai_memory::mcp::tools::handle_store_for_tests(
        &conn,
        dir.path(),
        &json!({
            "tier": "long",
            "namespace": "ns3761",
            "title": "standard anchor",
            "content": "3761 anchor",
            "priority": 5,
            "agent_id": owner,
        }),
        None,
        None,
        None,
        &ttl,
        false,
        None,
        None,
    )
    .expect("seed memory store")["id"]
        .as_str()
        .expect("seed id")
        .to_string();
    ai_memory::mcp::handle_namespace_set_standard(
        &conn,
        &json!({"namespace": "ns3761", "id": id, "agent_id": owner}),
    )
    .expect("owner binds its own standard");
    let err = ai_memory::mcp::handle_namespace_set_standard(
        &conn,
        &json!({"namespace": "ns3761", "id": id, "agent_id": intruder}),
    )
    .expect_err("an intruder bind must be refused");
    assert_eq!(
        err,
        ai_memory::errors::msg::CALLER_DOES_NOT_OWN_NAMESPACE_STANDARD,
        "the ownership refusal passes through byte-identical: {err}"
    );
}

/// PG LEG (measured on the build host; self-skips on f1): every funnel's
/// MCP error text renders a live `sqlx` driver fault as the same closed
/// class. The handlers themselves hold a bare `rusqlite::Connection`, so
/// the postgres driver reaches the shared predicate as an anyhow chain —
/// this cell drives that exact seam per funnel site.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn pg_driver_faults_render_closed_per_funnel_3761() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("pg connect");
    for site in [
        "action_create",
        "forget",
        "archive_restore",
        "lineage",
        "namespace_set_standard",
    ] {
        let raw = sqlx::query("SELECT * FROM missing_tbl_3761")
            .execute(&pool)
            .await
            .expect_err("unknown table must fail");
        assert!(
            raw.to_string().contains("missing_tbl_3761"),
            "the injection must carry the marker: {raw}"
        );
        let text = ai_memory::mcp::error_text::mcp_foreign_err(site, anyhow::Error::new(raw));
        assert_eq!(text, DB_ERROR_TEXT, "site {site}: caller gets the class");
        assert!(
            !text.contains("missing_tbl_3761"),
            "#3761: pg driver text must not cross to the caller at {site}: {text}"
        );
    }
}
