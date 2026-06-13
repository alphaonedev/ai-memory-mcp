// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Issue #1601 — destructive forget matching must be AND, not fuzzy OR.
//!
//! Pre-fix, `forget` / `forget_count` routed the caller's pattern
//! through the recall-side fuzzy-OR FTS builder: pattern "D6 scratch"
//! reported `would_delete=3` in a namespace where only ONE row
//! contained both tokens, and "D6 nonexistentzzzword" still matched 1.
//! Post-fix all three forget sites (`forget_count`, the `forget`
//! delete arm, and the archive-before-delete arm) route through the
//! shared `forget_fts_query` builder: every whitespace-separated token
//! must match (FTS5 implicit AND).

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier, default_metadata};
use chrono::Utc;

const NS: &str = "forget-and-1601";

fn insert_row(conn: &rusqlite::Connection, title: &str, content: &str) -> String {
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: default_metadata(),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("insert")
}

/// Corpus shape mirroring the lived #1601 evidence: one row carries
/// BOTH tokens, two rows carry only one of them.
fn seed_corpus(conn: &rusqlite::Connection) -> String {
    let both = insert_row(conn, "delta scratch note", "delta scratch contents");
    let _only_a = insert_row(conn, "delta plan", "delta only here");
    let _only_b = insert_row(conn, "scratch pad", "scratch only here");
    both
}

fn open_db() -> rusqlite::Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

/// #1601 — `forget_count` with a multi-token pattern counts ONLY rows
/// containing every token (pre-fix OR counted all 3).
#[test]
fn issue_1601_forget_count_multi_token_is_and() {
    let conn = open_db();
    let _both = seed_corpus(&conn);
    let count = db::forget_count(&conn, Some(NS), Some("delta scratch"), None).expect("count");
    assert_eq!(
        count, 1,
        "multi-token forget pattern must AND its tokens (#1601)"
    );
}

/// #1601 — a nonsense token AND-joined with a real one matches ZERO rows
/// (pre-fix OR still matched the real-token rows).
#[test]
fn issue_1601_forget_count_nonsense_token_matches_zero() {
    let conn = open_db();
    let _both = seed_corpus(&conn);
    let count =
        db::forget_count(&conn, Some(NS), Some("delta nonexistentzzzword"), None).expect("count");
    assert_eq!(
        count, 0,
        "nonsense+real token must match zero rows under AND (#1601)"
    );
}

/// #1601 — a single token still matches every row containing it.
#[test]
fn issue_1601_forget_count_single_token_still_matches() {
    let conn = open_db();
    let _both = seed_corpus(&conn);
    let count = db::forget_count(&conn, Some(NS), Some("delta"), None).expect("count");
    assert_eq!(count, 2, "single-token pattern keeps matching (#1601)");
}

/// #1601 — the destructive `forget` arm deletes ONLY the AND-matched
/// row; the single-token rows survive.
#[test]
fn issue_1601_forget_deletes_only_and_matched_rows() {
    let conn = open_db();
    let both = seed_corpus(&conn);
    let deleted = db::forget(&conn, Some(NS), Some("delta scratch"), None, false).expect("forget");
    assert_eq!(deleted, 1, "forget must delete only the AND match (#1601)");
    assert!(db::get(&conn, &both).unwrap().is_none(), "AND match gone");
    let remaining = db::forget_count(&conn, Some(NS), None, None).expect("count");
    assert_eq!(remaining, 2, "single-token rows must survive (#1601)");
}

/// #1601 — the archive-before-delete arm uses the SAME query builder:
/// only the AND-matched row lands in `archived_memories`.
#[test]
fn issue_1601_forget_archive_arm_uses_and_query() {
    let conn = open_db();
    let both = seed_corpus(&conn);
    let deleted =
        db::forget(&conn, Some(NS), Some("delta scratch"), None, true).expect("forget+archive");
    assert_eq!(deleted, 1);
    let archived: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE namespace = ?1",
            rusqlite::params![NS],
            |r| r.get(0),
        )
        .expect("count archived");
    assert_eq!(
        archived, 1,
        "archive arm must archive only the AND match (#1601)"
    );
    let archived_id: String = conn
        .query_row(
            "SELECT id FROM archived_memories WHERE namespace = ?1",
            rusqlite::params![NS],
            |r| r.get(0),
        )
        .expect("archived id");
    assert_eq!(archived_id, both);
}
