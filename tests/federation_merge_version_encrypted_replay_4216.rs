// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::doc_markdown)]

//! #4216 (f2r checklist item 2, c4216 F3a) — an ENCRYPTED row replayed by a
//! peer must not look changed. Every federation merge re-seals the plaintext
//! under a fresh per-record DEK, so the stored envelope bytes differ on every
//! replay; the change predicate compares PLAINTEXT content, so a replay of the
//! same row leaves `version` alone (and the first, content-changing merge still
//! bumps).

use ai_memory::models::Memory;
use ai_memory::storage as db;
use std::sync::Mutex;

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

/// Serializes the tests that toggle the process-global at-rest gate.
static ENV_GATE_LOCK: Mutex<()> = Mutex::new(());
const ENV_ENCRYPT_AT_REST: &str = "AI_MEMORY_ENCRYPT_AT_REST";

struct EncryptGate {
    prev: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EncryptGate {
    fn on() -> Self {
        let lock = ENV_GATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var(ENV_ENCRYPT_AT_REST).ok();
        // SAFETY: serialized via ENV_GATE_LOCK; restored on Drop.
        unsafe { std::env::set_var(ENV_ENCRYPT_AT_REST, "1") };
        Self { prev, _lock: lock }
    }
}

impl Drop for EncryptGate {
    fn drop(&mut self) {
        // SAFETY: still holding ENV_GATE_LOCK.
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var(ENV_ENCRYPT_AT_REST, v),
                None => std::env::remove_var(ENV_ENCRYPT_AT_REST),
            }
        }
    }
}

fn memory(id: &str, content: &str, updated_at: &str) -> Memory {
    serde_json::from_value(serde_json::json!({
        "id": id, "tier": "long", "namespace": "fit-4216-enc",
        "title": format!("encrypted replay probe {id}"), "content": content,
        "tags": [], "priority": 5, "confidence": 1.0, "source": "nhi",
        "access_count": 0, "created_at": "2026-09-20T00:00:00Z",
        "updated_at": updated_at, "version": 1,
        "metadata": {"agent_id": "ai:alice-4216-enc"}
    }))
    .expect("memory")
}

fn version_of(conn: &rusqlite::Connection, id: &str) -> i64 {
    db::get_any(conn, id).expect("read").expect("row").version
}

fn soon() -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(2)).to_rfc3339()
}

fn open() -> rusqlite::Connection {
    let _ = key_dir_sandbox::pin();
    db::open(std::path::Path::new(":memory:")).expect("open")
}

#[test]
fn encrypted_replay_through_merge_inbound_does_not_bump_4216() {
    let _gate = EncryptGate::on();
    let conn = open();
    let id = uuid::Uuid::new_v4().to_string();
    db::insert(
        &conn,
        &memory(&id, "A's text", &chrono::Utc::now().to_rfc3339()),
    )
    .expect("insert");
    let before = version_of(&conn, &id);
    let remote = memory(&id, "B's text", &soon());
    db::merge_inbound(&conn, &remote, false).expect("merge");
    let once = version_of(&conn, &id);
    assert_eq!(once, before + 1, "the content change bumps");
    db::merge_inbound(&conn, &remote, false).expect("replay");
    assert_eq!(
        version_of(&conn, &id),
        once,
        "a replay re-sealed under a fresh key must not look changed"
    );
    assert_eq!(
        db::get_any(&conn, &id).expect("read").expect("row").content,
        "B's text"
    );
}

#[test]
fn encrypted_replay_through_insert_if_newer_does_not_bump_4216() {
    let _gate = EncryptGate::on();
    let conn = open();
    let id = uuid::Uuid::new_v4().to_string();
    db::insert(
        &conn,
        &memory(&id, "A's text", &chrono::Utc::now().to_rfc3339()),
    )
    .expect("insert");
    let before = version_of(&conn, &id);
    let remote = memory(&id, "B's text", &soon());
    db::insert_if_newer(&conn, &remote).expect("merge");
    let once = version_of(&conn, &id);
    assert_eq!(once, before + 1, "the content change bumps");
    db::insert_if_newer(&conn, &remote).expect("replay");
    assert_eq!(
        version_of(&conn, &id),
        once,
        "a replay re-sealed under a fresh key must not look changed"
    );
}
