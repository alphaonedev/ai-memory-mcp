// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #5035: the #2445 schema-ahead guard must hold for the LIFETIME of a
//! connection, not only at open. SQLite arm; the postgres twin is
//! `tests/pg_schema_guard_lifetime_5035.rs`.
//!
//! # The defect
//!
//! `storage::schema_guard::evaluate` was reached only from the open path
//! (`resolve_schema_posture` inside `db::open`). A long-lived daemon that
//! opened the database at schema N kept writing after a NEWER binary migrated
//! the same file to N+k. The caller then saw a raw SQLite error (`ON CONFLICT
//! clause does not match any PRIMARY KEY or UNIQUE constraint`) instead of the
//! typed refusal, and any write that happened to succeed landed on a schema
//! this binary does not understand.
//!
//! # What is asserted
//!
//! * the bare-`Connection` `db::` write funnel (the MCP stdio path) refuses
//!   with the typed `StorageError::SchemaAheadOfBinary` once the stamp moves
//!   ahead under an already-open connection, and the row is NOT written;
//! * the refusal text is path-free (the DB path goes to the log only);
//! * reads on the same connection keep working (refuse writes, preserve egress);
//! * the MCP `tools/call` fence returns the typed refusal text for a mutating
//!   tool and still serves a read-only tool;
//! * the SAL sqlite adapter returns the typed `StoreError::SchemaAheadOfBinary`;
//! * the operator hatch (`AI_MEMORY_ALLOW_SCHEMA_AHEAD=<exact version>`) still
//!   admits the write, and the steady state (stamp == tip) is untouched.

use std::path::{Path, PathBuf};

use ai_memory::errors::error_codes::SCHEMA_AHEAD_OF_BINARY;
use ai_memory::models::{Memory, Tier};
use ai_memory::storage::StorageError;
use ai_memory::storage::schema_guard::ENV_ALLOW_SCHEMA_AHEAD;
use serde_json::json;

const NS: &str = "schema-guard-lifetime-5035";

/// Serialises the process-wide `ENV_ALLOW_SCHEMA_AHEAD` mutations. Every test
/// in this file takes it, because the hatch changes every verdict.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn clear_hatch() {
    // SAFETY: process-wide env mutation, serialised by `env_lock`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
}

fn tip() -> i64 {
    ai_memory::storage::migrations::current_schema_version()
}

fn mk_memory(title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("durable text for {title}"),
        tags: vec!["t5035".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": "ai:operator"}),
        version: 1,
        ..Memory::default()
    }
}

/// A fresh, fully-migrated database file inside `dir`.
fn fresh_db(dir: &Path) -> PathBuf {
    let path = dir.join("ai-memory.db");
    drop(ai_memory::db::open(&path).expect("fresh open must succeed"));
    path
}

/// Move the recorded schema version of the file at `path` to `version` through
/// a SECOND connection, exactly what a newer binary's migration does to a file
/// another process already holds open.
fn stamp_from_another_connection(path: &Path, version: i64) {
    let other = rusqlite::Connection::open(path).expect("second connection");
    other
        .execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            rusqlite::params![version],
        )
        .expect("stamp schema_version ahead");
}

fn count_rows(conn: &rusqlite::Connection, title: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE title = ?1",
        rusqlite::params![title],
        |r| r.get(0),
    )
    .expect("count rows")
}

#[test]
fn db_funnel_write_refuses_typed_after_schema_moves_ahead_5035() {
    let _g = env_lock();
    clear_hatch();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = fresh_db(dir.path());

    // The long-lived daemon's connection, opened while the schema was at tip.
    let conn = ai_memory::db::open(&path).expect("daemon open at tip");
    let before = mk_memory("before-move");
    ai_memory::db::insert(&conn, &before).expect("write at tip must succeed");

    // A newer binary migrates the file underneath it.
    stamp_from_another_connection(&path, tip() + 1);

    let after = mk_memory("after-move");
    let err = ai_memory::db::insert(&conn, &after)
        .expect_err("a write after the schema moved ahead must be REFUSED");
    let se = err
        .downcast_ref::<StorageError>()
        .unwrap_or_else(|| panic!("typed StorageError in the chain, got: {err:#}"));
    assert_eq!(
        se.code(),
        SCHEMA_AHEAD_OF_BINARY,
        "must refuse with the typed schema-ahead refusal, got {se:?}"
    );
    let text = se.to_string();
    assert!(
        text.contains("AHEAD of this binary") && text.contains(&(tip() + 1).to_string()),
        "refusal must name the condition and the observed version: {text}"
    );
    assert!(
        !text.contains(&path.display().to_string()),
        "refusal text must not carry the database path: {text}"
    );
    assert_eq!(
        count_rows(&conn, "after-move"),
        0,
        "the refused row must not land"
    );

    // Egress survives on the SAME connection.
    let got = ai_memory::db::get(&conn, &before.id).expect("read must keep working");
    assert!(got.is_some(), "the pre-move row must still be readable");
}

#[test]
fn mcp_tools_call_refuses_write_with_typed_text_and_serves_reads_5035() {
    let _g = env_lock();
    clear_hatch();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = fresh_db(dir.path());
    let conn = ai_memory::db::open(&path).expect("daemon open at tip");

    stamp_from_another_connection(&path, tip() + 1);

    let store_req = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "memory_store", "arguments": {
            "title": "mcp-after-move", "content": "must not land", "namespace": NS
        }}
    });
    let resp =
        ai_memory::mcp::dispatch_test_hook::handle_request_for_test(&conn, &path, &store_req);
    let msg = resp
        .pointer("/error/message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("memory_store must be refused with a JSON-RPC error: {resp}"));
    assert!(
        msg.contains("AHEAD of this binary"),
        "the MCP caller must see the typed schema-ahead refusal, not a raw SQLite string: {msg}"
    );
    assert!(
        !msg.contains(&path.display().to_string()),
        "MCP refusal text must not carry the database path: {msg}"
    );
    assert_eq!(count_rows(&conn, "mcp-after-move"), 0);

    let list_req = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "memory_list", "arguments": {"namespace": NS}}
    });
    let resp = ai_memory::mcp::dispatch_test_hook::handle_request_for_test(&conn, &path, &list_req);
    assert!(
        resp.get("error").is_none(),
        "a read-only tool must keep working while writes are refused: {resp}"
    );
}

/// The SAL adapter lives behind the `sal` feature (`ai_memory::store`), so this
/// arm runs under `cargo test --features sal` (CI's sal matrix leg).
#[cfg(feature = "sal")]
mod sal {
    use super::{clear_hatch, env_lock, fresh_db, mk_memory, stamp_from_another_connection, tip};
    use ai_memory::store::sqlite::SqliteStore;
    use ai_memory::store::{CallerContext, MemoryStore, StoreError};

    /// Sync test with its own runtime: the env lock is a std mutex and must
    /// not be held across an `.await` (CONCURRENCY-20), but it must cover the
    /// whole async body because the hatch env is process-wide.
    #[test]
    fn sal_sqlite_write_refuses_typed_and_reads_survive_5035() {
        let _g = env_lock();
        clear_hatch();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(sal_body());
    }

    async fn sal_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = fresh_db(dir.path());
        let store = SqliteStore::open(&path).expect("open SqliteStore at tip");
        let ctx = CallerContext::for_agent("ai:operator");

        let before = mk_memory("sal-before-move");
        let id = store.store(&ctx, &before).await.expect("write at tip");

        stamp_from_another_connection(&path, tip() + 1);

        let err = store
            .store(&ctx, &mk_memory("sal-after-move"))
            .await
            .expect_err("SAL write after the schema moved ahead must be REFUSED");
        assert!(
            matches!(err, StoreError::SchemaAheadOfBinary { .. }),
            "SAL must surface the typed SchemaAheadOfBinary (HTTP 503), got {err:?}"
        );
        store
            .get(&ctx, &id)
            .await
            .expect("SAL read must keep working");
    }
}

#[test]
fn exact_version_hatch_still_admits_and_steady_state_is_untouched_5035() {
    let _g = env_lock();
    clear_hatch();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = fresh_db(dir.path());
    let conn = ai_memory::db::open(&path).expect("daemon open at tip");

    // Steady state: re-stamping the SAME version is not a move.
    stamp_from_another_connection(&path, tip());
    ai_memory::db::insert(&conn, &mk_memory("steady")).expect("stamp == tip must write");

    let ahead = tip() + 1;
    stamp_from_another_connection(&path, ahead);

    // A hatch naming a DIFFERENT version must not widen.
    // SAFETY: process-wide env mutation, serialised by `_g`.
    unsafe { std::env::set_var(ENV_ALLOW_SCHEMA_AHEAD, (ahead + 1).to_string()) };
    let wrong = ai_memory::db::insert(&conn, &mk_memory("wrong-hatch"));
    // SAFETY: as above.
    unsafe { std::env::set_var(ENV_ALLOW_SCHEMA_AHEAD, ahead.to_string()) };
    let admitted = ai_memory::db::insert(&conn, &mk_memory("exact-hatch"));
    clear_hatch();

    let wrong = wrong.expect_err("a hatch for a different version must refuse");
    assert_eq!(
        wrong.downcast_ref::<StorageError>().map(StorageError::code),
        Some(SCHEMA_AHEAD_OF_BINARY),
        "wrong-version hatch must refuse typed, got {wrong:#}"
    );
    admitted.expect("the exact-version hatch must admit the write");
}
