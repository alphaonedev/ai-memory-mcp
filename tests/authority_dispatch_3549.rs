// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3549 — the dispatch-level authority chokepoint, driven through the
//! REAL `tools/call` arm (`ai_memory::mcp::dispatch_test_hook`) with the caller
//! principal steered by the #3523 thread-local seam, so no process env is
//! mutated. The #3356 boot gate refuses to SERVE on an unusable configured
//! identity; these cells pin the dispatch-level twin that makes the boundary
//! structural for a server that is already up: a READ tool and a WRITE tool
//! are refused alike (`-32603`) and the write never lands.

use ai_memory::identity::test_agent_id::AgentIdOverride;
use ai_memory::mcp::dispatch_test_hook::handle_request_for_test;
use serde_json::{Value, json};

const INTERNAL_ERROR: i64 = -32603;

fn call(tool: &str, args: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    })
}

fn open_db() -> (tempfile::NamedTempFile, rusqlite::Connection) {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(tmp.path()).expect("open db");
    (tmp, conn)
}

fn row_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
        .expect("count")
}

/// DENIED — an unusable configured identity refuses a READ tool at dispatch
/// with the protocol-level `-32603`, before the table lookup.
#[test]
fn unusable_configured_identity_refuses_a_read_tool_at_dispatch_3549() {
    let _seam = AgentIdOverride::set("bad id with spaces");
    let (tmp, conn) = open_db();
    let resp = handle_request_for_test(&conn, tmp.path(), &call("memory_list", &json!({})));
    assert_eq!(resp["error"]["code"], INTERNAL_ERROR, "{resp}");
    assert!(
        resp["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("caller authority unresolvable")),
        "{resp}"
    );
    assert!(resp.get("result").is_none(), "{resp}");
}

/// DENIED — the same refusal for a WRITE tool: the boot gate never covered
/// writes at dispatch; this does, and the row is never written.
#[test]
fn unusable_configured_identity_refuses_a_write_tool_at_dispatch_3549() {
    let _seam = AgentIdOverride::set("");
    let (tmp, conn) = open_db();
    let resp = handle_request_for_test(
        &conn,
        tmp.path(),
        &call(
            "memory_store",
            &json!({"title": "t", "content": "c", "namespace": "ns-3549"}),
        ),
    );
    assert_eq!(resp["error"]["code"], INTERNAL_ERROR, "{resp}");
    assert_eq!(row_count(&conn), 0, "the refusal precedes the write");
}

/// ALLOWED — a valid configured identity dispatches, and the resolved
/// principal is the one the write is attributed to.
#[test]
fn valid_configured_identity_dispatches_and_attributes_the_write_3549() {
    let _seam = AgentIdOverride::set("ai:alice");
    let (tmp, conn) = open_db();
    let resp = handle_request_for_test(
        &conn,
        tmp.path(),
        &call(
            "memory_store",
            &json!({"title": "t", "content": "c", "namespace": "ns-3549"}),
        ),
    );
    assert!(resp.get("error").is_none(), "{resp}");
    let owner: String = conn
        .query_row(
            "SELECT json_extract(metadata, '$.agent_id') FROM memories LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("owner");
    assert_eq!(owner, "ai:alice");
}

/// ALLOWED — the unset identity is the local-operator trust domain (F13):
/// dispatch proceeds with trust-all reads.
#[test]
fn unset_identity_dispatches_as_the_local_operator_3549() {
    let _seam = AgentIdOverride::unset();
    let (tmp, conn) = open_db();
    let resp = handle_request_for_test(&conn, tmp.path(), &call("memory_list", &json!({})));
    assert!(resp.get("error").is_none(), "{resp}");
}
