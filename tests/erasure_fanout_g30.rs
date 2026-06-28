// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.1 W2 / gap G30 — erasure fanout: `forget` purges the non-cascaded
//! derived-store leaks (`federation_push_dlq` cleartext payload,
//! `transcript_line_dedup` content-hash oracle) in the same transaction.
//!
//! These channels survive a plain cascade DELETE because the DLQ keys its
//! row by a deliberately NON-FK `memory_id` and the dedup table has no FK /
//! cascade at all — so pre-W2 a forgotten secret lingered in both. (The
//! HNSW-eviction + federated-tombstone halves of W2 are covered separately.)

use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind, Tier};

fn seed_memory(conn: &rusqlite::Connection, namespace: &str, title: &str, content: &str) -> String {
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        memory_kind: MemoryKind::Observation,
        metadata: serde_json::json!({ "agent_id": "ai:test:g30" }),
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("insert memory")
}

fn seed_dlq_row(conn: &rusqlite::Connection, memory_id: &str, payload: &str) {
    conn.execute(
        "INSERT INTO federation_push_dlq \
         (memory_id, peer_id, payload_json, attempt_count, last_error, failed_at) \
         VALUES (?1, ?2, ?3, 1, 'simulated', '2026-06-28T00:00:00Z')",
        rusqlite::params![memory_id, "peer-1", payload],
    )
    .expect("insert dlq row");
}

fn seed_dedup_row(conn: &rusqlite::Connection, memory_id: &str, sha: &[u8]) {
    conn.execute(
        "INSERT INTO transcript_line_dedup (sha256, memory_id, host_kind, recovered_at) \
         VALUES (?1, ?2, 'claude-code', 0)",
        rusqlite::params![sha, memory_id],
    )
    .expect("insert dedup row");
}

fn dlq_count(conn: &rusqlite::Connection, memory_id: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM federation_push_dlq WHERE memory_id = ?1",
        rusqlite::params![memory_id],
        |r| r.get(0),
    )
    .unwrap()
}

fn dedup_count(conn: &rusqlite::Connection, memory_id: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM transcript_line_dedup WHERE memory_id = ?1",
        rusqlite::params![memory_id],
        |r| r.get(0),
    )
    .unwrap()
}

fn mem_count(conn: &rusqlite::Connection, id: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get(0),
    )
    .unwrap()
}

fn fresh_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("g30.db");
    (dir, path)
}

/// Bulk `db::forget` purges the DLQ + dedup leaks for the forgotten rows.
#[test]
fn forget_purges_dlq_and_transcript_dedup_g30() {
    let (_dir, path) = fresh_db();
    let conn = db::open(&path).expect("open");

    let id = seed_memory(
        &conn,
        "g30-erase",
        "secret-note",
        "AKIAIOSFODNN7EXAMPLE leaked",
    );
    seed_dlq_row(&conn, &id, "{\"content\":\"AKIAIOSFODNN7EXAMPLE leaked\"}");
    seed_dedup_row(&conn, &id, &[1u8, 2, 3, 4]);

    assert_eq!(dlq_count(&conn, &id), 1, "precondition: DLQ row present");
    assert_eq!(
        dedup_count(&conn, &id),
        1,
        "precondition: dedup row present"
    );

    let deleted = db::forget(&conn, Some("g30-erase"), None, None, false).expect("forget");
    assert_eq!(deleted, 1, "the memory must be forgotten");

    assert_eq!(mem_count(&conn, &id), 0, "G30: the row must be gone");
    assert_eq!(
        dlq_count(&conn, &id),
        0,
        "G30.1: the federation_push_dlq cleartext payload must be purged on forget"
    );
    assert_eq!(
        dedup_count(&conn, &id),
        0,
        "G30: the transcript_line_dedup content-hash oracle must be purged on forget"
    );
}

/// The purge is SCOPED to the forgotten set — a DLQ / dedup row for an
/// UNRELATED memory (different namespace) survives.
#[test]
fn forget_does_not_over_purge_other_namespaces_g30() {
    let (_dir, path) = fresh_db();
    let conn = db::open(&path).expect("open");

    let keep_id = seed_memory(&conn, "g30-keep", "keep-note", "benign content here");
    seed_dlq_row(&conn, &keep_id, "{\"content\":\"benign\"}");
    seed_dedup_row(&conn, &keep_id, &[9u8, 9, 9, 9]);

    let gone_id = seed_memory(&conn, "g30-drop", "drop-note", "drop me");
    seed_dlq_row(&conn, &gone_id, "{\"content\":\"drop\"}");

    // Forget ONLY the g30-drop namespace.
    db::forget(&conn, Some("g30-drop"), None, None, false).expect("forget");

    assert_eq!(dlq_count(&conn, &gone_id), 0, "forgotten row's DLQ purged");
    assert_eq!(
        dlq_count(&conn, &keep_id),
        1,
        "G30: another namespace's pending DLQ row must NOT be over-purged"
    );
    assert_eq!(
        dedup_count(&conn, &keep_id),
        1,
        "G30: another namespace's dedup row must NOT be over-purged"
    );
    assert_eq!(mem_count(&conn, &keep_id), 1, "the kept memory survives");
}
