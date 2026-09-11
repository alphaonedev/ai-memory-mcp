// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3152 — MCP `memory_update` applies the content patch and the
//! lifecycle transition in ONE transaction. Before #3152 the patch committed
//! first, so an illegal edge returned an error while the patch — and the
//! storage-growth charge for it — stayed persisted.

#![cfg(test)]

use std::sync::{Arc, Mutex, PoisonError};

use serde_json::json;

use super::handle_update;
use crate::models::{LifecycleState, Memory};
use crate::recover::durability::in_tx_fault;
use crate::storage as db;

const OWNER: &str = "ai:mcp-atomicity-3152";
const NAMESPACE: &str = "mcp-atomicity-3152";
const ORIGINAL_CONTENT: &str = "mcp atomicity 3152 original body";

fn fixture() -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: NAMESPACE.to_string(),
        title: "mcp atomicity 3152".to_string(),
        content: ORIGINAL_CONTENT.to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": OWNER }),
        ..Memory::default()
    }
}

fn storage_bytes(conn: &rusqlite::Connection) -> i64 {
    crate::quotas::get_status(conn, OWNER, NAMESPACE)
        .expect("quota status")
        .current_storage_bytes
}

/// An illegal edge refuses the whole update: the patch rolls back, and the
/// FBL-12 growth charge is refunded because the bytes never landed.
#[test]
fn mcp_illegal_edge_rolls_the_patch_back_and_refunds_the_growth_3152() {
    let _agent_env = crate::identity::agent_id_env_unset_guard();
    let conn = db::open(std::path::Path::new(":memory:")).expect("open");
    let id = db::insert(&conn, &fixture()).expect("insert");
    let before = storage_bytes(&conn);

    let err = handle_update(
        &conn,
        &json!({ "id": id, "content": "x".repeat(20_000), "lifecycle_state": "done" }),
        None,
        None,
        None,
    )
    .expect_err("open -> done must refuse the whole update");
    assert!(err.contains("illegal lifecycle transition"), "got: {err}");

    let row = db::get(&conn, &id).expect("read").expect("row");
    assert_eq!(row.content, ORIGINAL_CONTENT, "the patch must roll back");
    assert_eq!(row.lifecycle_state, LifecycleState::Open);
    assert_eq!(row.version, 1, "no version bump may survive the refusal");
    let snapshots: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
            [&id],
            |r| r.get(0),
        )
        .expect("count snapshots");
    assert_eq!(snapshots, 0, "the in_place_edit snapshot rolls back too");
    assert_eq!(
        storage_bytes(&conn),
        before,
        "the growth charge must be refunded for bytes that never landed"
    );
}

/// At the fault point the patch has executed but a second connection still
/// reads the original row.
#[test]
fn mcp_patch_is_uncommitted_at_the_fault_point_3152() {
    let _agent_env = crate::identity::agent_id_env_unset_guard();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mcp-atomicity-3152.db");
    let conn = db::open(&path).expect("open");
    let id = db::insert(&conn, &fixture()).expect("insert");

    let seen: Arc<Mutex<Option<Memory>>> = Arc::new(Mutex::new(None));
    let (seen_in, path_in, id_in) = (Arc::clone(&seen), path.clone(), id.clone());
    in_tx_fault::arm(
        &id,
        in_tx_fault::Action::Observe(Box::new(move || {
            let reader = db::open_read_only(&path_in).expect("open read-only");
            let row = db::get(&reader, &id_in).expect("read").expect("row");
            *seen_in.lock().unwrap_or_else(PoisonError::into_inner) = Some(row);
        })),
    );
    let res = handle_update(
        &conn,
        &json!({ "id": id, "content": "patched body", "lifecycle_state": "active" }),
        None,
        None,
        None,
    );
    in_tx_fault::disarm(&id);
    res.expect("open -> active is legal");

    let observed = seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .expect("the fault point must be reached between patch and transition");
    assert_eq!(observed.content, ORIGINAL_CONTENT, "nothing is committed yet");
    assert_eq!(observed.lifecycle_state, LifecycleState::Open);
    let row = db::get(&conn, &id).expect("read").expect("row");
    assert_eq!(row.content, "patched body");
    assert_eq!(row.lifecycle_state, LifecycleState::Active);
}
