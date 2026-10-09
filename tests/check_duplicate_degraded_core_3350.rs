// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3350 (WP-FAULT #6051) — storage-core half of the fail-closed duplicate
//! check: `db::check_duplicate_with_text` carries the degraded signal on
//! [`DuplicateCheck::degraded`] so every surface (MCP / HTTP / CLI, both
//! backends through the SAL trait) renders the ONE verdict.
//!
//! Kept in its own test binary: on the untouched tip the `degraded` field
//! does not exist, so this file is RED by failing to compile (E0609),
//! while the surface tests in `check_duplicate_degraded_3350.rs` stay
//! compilable and fail at runtime.

use ai_memory::db;
use ai_memory::models::{DuplicateDegraded, Memory, Tier};
use serde_json::json;
use std::path::Path;

const NS: &str = "ns3350core";
const TITLE: &str = "Exact Title 3350 core";
const CONTENT: &str = "full content that is stored but never embedded";

fn open() -> rusqlite::Connection {
    db::open(Path::new(":memory:")).expect("open")
}

fn seed(conn: &rusqlite::Connection, title: &str, content: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: title.to_string(),
        content: content.to_string(),
        namespace: NS.to_string(),
        tier: Tier::Long,
        metadata: json!({"agent_id": "ai:owner-3350"}),
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("seed")
}

const QUERY: [f32; 3] = [1.0, 0.0, 0.0];

/// Pool of one unembedded row, no hash hit ⇒ degraded, verdict withheld.
#[test]
fn core_degraded_when_pool_non_empty_and_nothing_compared_3350() {
    let conn = open();
    seed(&conn, TITLE, CONTENT);
    let r =
        db::check_duplicate_with_text(&conn, &QUERY, "Exact Title 3350 core short", Some(NS), 0.85)
            .expect("check");
    assert_eq!(r.candidates_scanned, 0);
    assert!(!r.is_duplicate, "a degraded check never claims a duplicate");
    assert!(r.nearest.is_none());
    assert_eq!(
        r.degraded,
        Some(DuplicateDegraded::NoComparableCandidates { pool: 1 }),
        "the pool had 1 live row and none could be compared"
    );
    let reason = r
        .degraded
        .as_ref()
        .map(DuplicateDegraded::reason)
        .unwrap_or_default();
    assert!(
        reason.contains("none of the 1 live candidate"),
        "reason names the pool: {reason}"
    );
}

/// Empty pool ⇒ NOT degraded (confident false).
#[test]
fn core_empty_pool_is_not_degraded_3350() {
    let conn = open();
    let r =
        db::check_duplicate_with_text(&conn, &QUERY, "anything", Some(NS), 0.85).expect("check");
    assert!(!r.is_duplicate);
    assert_eq!(r.degraded, None);
}

/// Hash hit on an unembedded row ⇒ duplicate, NOT degraded.
#[test]
fn core_hash_hit_is_not_degraded_3350() {
    let conn = open();
    let id = seed(&conn, TITLE, CONTENT);
    let text = ai_memory::embeddings::embedding_document(TITLE, CONTENT);
    let r = db::check_duplicate_with_text(&conn, &QUERY, &text, Some(NS), 0.85).expect("check");
    assert!(r.is_duplicate);
    assert_eq!(r.nearest.map(|n| n.id), Some(id));
    assert_eq!(r.degraded, None);
}

/// A compared (embedded, active-space) row ⇒ boolean verdict, NOT degraded.
#[test]
fn core_compared_candidate_is_not_degraded_3350() {
    let conn = open();
    let id = seed(&conn, TITLE, CONTENT);
    db::set_embedding(
        &conn,
        &id,
        &[0.0, 1.0, 0.0],
        &ai_memory::embeddings::embedding_space_fingerprint("test-space-3350"),
    )
    .expect("embed");
    let r = db::check_duplicate_with_text(&conn, &QUERY, "different text", Some(NS), 0.85)
        .expect("check");
    assert_eq!(r.candidates_scanned, 1);
    assert!(!r.is_duplicate);
    assert_eq!(r.degraded, None);
}

/// Phase 2 alone (`check_duplicate`) cannot see the pool and never claims
/// degraded on its own; the signal is derived in `check_duplicate_with_text`.
#[test]
fn core_phase_two_alone_does_not_fabricate_degraded_3350() {
    let conn = open();
    seed(&conn, TITLE, CONTENT);
    let r = db::check_duplicate(&conn, &QUERY, Some(NS), 0.85).expect("check");
    assert_eq!(r.candidates_scanned, 0);
    assert_eq!(r.degraded, None);
}
