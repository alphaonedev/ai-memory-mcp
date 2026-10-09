// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4147 — the sqlite `PUT /api/v1/memories/{id}` and
//! `DELETE /api/v1/memories/{id}` funnels must run the ownership gate and the
//! write it authorises in ONE `BEGIN IMMEDIATE`, so a SECOND OS PROCESS on
//! the same database file cannot commit an ownership change between the
//! gate's read and the write (the #3957 property, on the two HTTP funnels
//! that bypass the SAL trait).
//!
//! The in-process mutex is exactly what a second process routes around, so
//! the interloper is a SEPARATE `rusqlite::Connection` on the same file,
//! fired from the `in_tx_fault::owner_gate_passed` point between the gate
//! and the write. Pre-fix the interloper COMMITS (RED: the write authorised
//! against the previous owner lands on the new owner's row — on delete, an
//! irreversible erase); with gate and write under one write transaction the
//! interloper cannot take the write lock and the row keeps its owner
//! (GREEN). Controls: the owner's own write succeeds; a non-owner is refused.

use super::memories::{delete_memory, update_memory};
use super::tests::test_app_state;
use crate::handlers::Db;
use crate::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use crate::recover::in_tx_fault;
use crate::storage as db;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt as _;

const OWNER: &str = "ai:alice-4147";
const INTERLOPER: &str = "ai:mallory-4147";
const OWNER_EDIT: &str = "content written by the owner after the gate passed";
/// Short, so a blocked interloper fails fast instead of stalling the cell.
const INTERLOPER_BUSY_TIMEOUT: Duration = Duration::from_millis(100);

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("owner-gate-txn-4147-http-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("tempdir under .local-runs")
}

fn owned_memory(owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: "owner-gate-4147".to_string(),
        title: format!("owner-gate-4147 {}", uuid::Uuid::new_v4()),
        content: "original content".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({ "agent_id": owner }),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

/// A file-backed `Db` (the interloper needs a second connection on the file).
fn file_db(path: &std::path::Path) -> Db {
    let conn = db::open(path).expect("open sqlite");
    Arc::new(tokio::sync::Mutex::new((
        conn,
        path.to_path_buf(),
        crate::config::ResolvedTtl::default(),
        true,
    )))
}

fn router(db: Db) -> Router {
    Router::new()
        .route(
            "/api/v1/memories/{id}",
            axum::routing::put(update_memory).delete(delete_memory),
        )
        .with_state(test_app_state(db))
}

/// Arm the point for `id`: when the gate has passed, a second connection on
/// the same file tries to hand the row to the interloper. Returns whether
/// that ownership change COMMITTED.
fn arm_interloper(path: std::path::PathBuf, id: &str) -> Arc<Mutex<Option<bool>>> {
    let committed = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&committed);
    let target = id.to_string();
    in_tx_fault::arm_owner_gate(
        id,
        Box::new(move || {
            let other = rusqlite::Connection::open(&path).expect("interloper connection");
            other
                .busy_timeout(INTERLOPER_BUSY_TIMEOUT)
                .expect("set the interloper busy timeout");
            let outcome = other.execute(
                "UPDATE memories SET metadata = json_set(metadata, '$.agent_id', ?1) WHERE id = ?2",
                rusqlite::params![INTERLOPER, target],
            );
            *slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(outcome.is_ok());
        }),
    );
    committed
}

fn owner_of(conn: &rusqlite::Connection, id: &str) -> Option<String> {
    use rusqlite::OptionalExtension as _;
    conn.query_row(
        "SELECT json_extract(metadata, '$.agent_id') FROM memories WHERE id = ?1",
        [id],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .expect("owner read")
}

fn content_of(conn: &rusqlite::Connection, id: &str) -> Option<String> {
    use rusqlite::OptionalExtension as _;
    conn.query_row("SELECT content FROM memories WHERE id = ?1", [id], |r| {
        r.get::<_, String>(0)
    })
    .optional()
    .expect("content read")
}

async fn put(router: &Router, id: &str, caller: &str, content: &str) -> StatusCode {
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/memories/{id}"))
        .header("x-agent-id", caller)
        .header(crate::HEADER_CONTENT_TYPE, crate::MIME_JSON)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({ "content": content })).unwrap(),
        ))
        .unwrap();
    router.clone().oneshot(req).await.unwrap().status()
}

async fn delete(router: &Router, id: &str, caller: &str) -> StatusCode {
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/memories/{id}"))
        .header("x-agent-id", caller)
        .body(Body::empty())
        .unwrap();
    router.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn http_put_gate_and_write_share_one_write_transaction_4147() {
    let dir = scratch();
    let path = dir.path().join("put.db");
    let db = file_db(&path);
    let id = {
        let guard = db.lock().await;
        db::insert(&guard.0, &owned_memory(OWNER)).expect("insert")
    };
    let committed = arm_interloper(path.clone(), &id);
    let router = router(db);

    let status = put(&router, &id, OWNER, OWNER_EDIT).await;
    in_tx_fault::disarm_owner_gate(&id);

    let fired = *committed.lock().unwrap();
    assert!(
        fired.is_some(),
        "the interloper must have run at the gate point"
    );
    let conn = rusqlite::Connection::open(&path).expect("reader");
    let owner = owner_of(&conn, &id);
    let content = content_of(&conn, &id);
    assert_eq!(
        fired,
        Some(false),
        "#4147: the gate and the write share one BEGIN IMMEDIATE, so a second \
         process cannot commit a re-own in between (status={status}, owner={owner:?})"
    );
    assert_eq!(owner.as_deref(), Some(OWNER), "the row keeps its owner");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        content.as_deref(),
        Some(OWNER_EDIT),
        "the owner's write lands"
    );
}

#[tokio::test]
async fn http_delete_gate_and_write_share_one_write_transaction_4147() {
    let dir = scratch();
    let path = dir.path().join("delete.db");
    let db = file_db(&path);
    let id = {
        let guard = db.lock().await;
        db::insert(&guard.0, &owned_memory(OWNER)).expect("insert")
    };
    let committed = arm_interloper(path.clone(), &id);
    let router = router(db);

    let status = delete(&router, &id, OWNER).await;
    in_tx_fault::disarm_owner_gate(&id);

    let fired = *committed.lock().unwrap();
    assert!(
        fired.is_some(),
        "the interloper must have run at the gate point"
    );
    assert_eq!(
        fired,
        Some(false),
        "#4147: a re-own cannot commit between the delete gate and the erase \
         (status={status})"
    );
    assert_eq!(status, StatusCode::OK);
    let conn = rusqlite::Connection::open(&path).expect("reader");
    assert!(content_of(&conn, &id).is_none(), "the owner's delete lands");
}

/// Control — a non-owner is refused on both funnels and nothing changes.
#[tokio::test]
async fn http_non_owner_is_refused_4147_control() {
    let dir = scratch();
    let path = dir.path().join("control.db");
    let db = file_db(&path);
    let id = {
        let guard = db.lock().await;
        db::insert(&guard.0, &owned_memory(OWNER)).expect("insert")
    };
    let router = router(db);
    // A private row is refused as 403 or, where the funnel hides it from a
    // stranger, 404; either way the row is untouched.
    let status = put(&router, &id, INTERLOPER, OWNER_EDIT).await;
    assert!(
        matches!(status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND),
        "non-owner PUT: {status}"
    );
    let status = delete(&router, &id, INTERLOPER).await;
    assert!(
        matches!(status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND),
        "non-owner DELETE: {status}"
    );
    let conn = rusqlite::Connection::open(&path).expect("reader");
    assert_eq!(content_of(&conn, &id).as_deref(), Some("original content"));
    assert_eq!(owner_of(&conn, &id).as_deref(), Some(OWNER));
}
