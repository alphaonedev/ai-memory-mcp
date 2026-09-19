// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3713 — the MCP tool error string is rendered from a CLOSED VOCABULARY.
//!
//! Before the `crate::mcp::error_text` funnel, a tool handler built its error
//! string from a driver's `Display` and the dispatcher shipped it verbatim to
//! the MCP client as `isError: true` content. These cells drive ONE tool
//! (`memory_find_paths`) through the same handler the dispatcher calls:
//!
//! * a driver fault (a dropped table) reaches the caller as the storage CLASS
//!   constant and never as the SQL text — RED on the untouched tree, where the
//!   error was `no such table: memory_links` verbatim;
//! * a typed refusal riding the same `anyhow` chain (`max_depth` past the
//!   ceiling, `StorageError::InvalidArgument`) keeps its own message — the
//!   PRESENCE half, so a funnel that flattened everything to a constant
//!   could not pass;
//! * the constant itself is the one the funnel exports, so the two cells pin
//!   the contract and not a coincidental string.

#![allow(clippy::missing_panics_doc)]

use ai_memory::mcp::error_text::DB_ERROR_TEXT;
use ai_memory::mcp::handle_find_paths;
use ai_memory::models::Memory;
use serde_json::json;

fn seed(conn: &rusqlite::Connection, title: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "ns3713".to_string(),
        title: title.to_string(),
        content: "closed vocabulary regression".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": "ai:me", "scope": "collective"}),
        ..Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("seed memory")
}

fn seeded_conn() -> (rusqlite::Connection, String, String) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("open");
    let a = seed(&conn, "src 3713");
    let b = seed(&conn, "dst 3713");
    ai_memory::db::create_link(&conn, &a, &b, "related_to").expect("seed edge");
    (conn, a, b)
}

#[test]
fn a_driver_fault_reaches_the_caller_as_the_class_never_the_sql_text_3713() {
    let (conn, a, b) = seeded_conn();
    // The fault: the link table the traversal walks is gone. rusqlite's
    // Display for this is `no such table: memory_links` — schema detail a
    // co-tenant is not entitled to.
    conn.execute_batch("DROP TABLE memory_links").expect("drop");

    let err = handle_find_paths(&conn, &json!({"source_id": a, "target_id": b}), None)
        .expect_err("a dropped link table must fail the traversal");

    assert_eq!(
        err, DB_ERROR_TEXT,
        "the caller gets the storage class, got: {err}"
    );
    assert!(
        !err.contains("no such table") && !err.contains("memory_links"),
        "#3713: driver text must not cross to the caller: {err}"
    );
}

#[test]
fn a_typed_refusal_through_the_same_funnel_keeps_its_message_3713() {
    let (conn, a, b) = seeded_conn();

    // `max_depth` past the ceiling is OUR `StorageError::InvalidArgument`,
    // carried on the same anyhow chain a driver fault rides; property 3 says
    // it must reach the caller as itself.
    let err = handle_find_paths(
        &conn,
        &json!({"source_id": a, "target_id": b, "max_depth": 99}),
        None,
    )
    .expect_err("max_depth=99 must be refused");

    assert_ne!(
        err, DB_ERROR_TEXT,
        "a typed refusal must not be flattened to the class"
    );
    assert!(
        err.contains("max_depth") && err.contains("99"),
        "the refusal must still name what the caller asked for: {err}"
    );
}
