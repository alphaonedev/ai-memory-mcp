// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Issue #1602 — `db::forget_matches`, the storage helper behind the
//! sighted forget preview.
//!
//! `memory_forget {dry_run:true}` previously returned only a blind
//! `{would_delete: N}`; the live run returned only a count even though
//! rows are archived and recoverable. The MCP layer now returns the
//! matched rows (dry-run) / deleted ids (live run) capped at
//! `DRY_RUN_PREVIEW_CAP` with a `truncated` flag — those handler-level
//! pins live in `src/mcp/tools/forget.rs::tests`. This file pins the
//! storage helper itself: filter parity with `forget` / `forget_count`
//! (including #1601 AND pattern semantics), the cap, and the
//! no-filter refusal.

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier, default_metadata};
use chrono::Utc;

const NS: &str = "forget-listing-1602";

fn insert_row(conn: &rusqlite::Connection, title: &str, tier: Tier) -> String {
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("content for {title}"),
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

fn open_db() -> rusqlite::Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

/// #1602 — the listing carries id/title/namespace/tier for every
/// matched row and respects the namespace filter.
#[test]
fn issue_1602_forget_matches_lists_rows_with_fields() {
    let conn = open_db();
    let id_a = insert_row(&conn, "alpha", Tier::Short);
    let id_b = insert_row(&conn, "beta", Tier::Mid);
    let rows = db::forget_matches(&conn, Some(NS), None, None, 10).expect("matches");
    assert_eq!(rows.len(), 2);
    let ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&id_a.as_str()) && ids.contains(&id_b.as_str()));
    assert!(rows.iter().all(|r| r.namespace == NS));
    let by_id = |id: &str| rows.iter().find(|r| r.id == id).expect("row");
    assert_eq!(by_id(&id_a).title, "alpha");
    assert_eq!(by_id(&id_a).tier, Tier::Short.as_str());
    assert_eq!(by_id(&id_b).tier, Tier::Mid.as_str());
}

/// #1602 — pattern + tier filters match `forget`'s semantics
/// (including #1601 AND): the preview is exactly the deletion set.
#[test]
fn issue_1602_forget_matches_filter_parity_with_forget() {
    let conn = open_db();
    let both = insert_row(&conn, "delta scratch note", Tier::Mid);
    let _only = insert_row(&conn, "delta plan", Tier::Mid);
    let rows =
        db::forget_matches(&conn, Some(NS), Some("delta scratch"), None, 10).expect("matches");
    assert_eq!(rows.len(), 1, "AND pattern semantics (#1601) apply");
    assert_eq!(rows[0].id, both);

    let deleted = db::forget(&conn, Some(NS), Some("delta scratch"), None, false).expect("forget");
    assert_eq!(
        deleted,
        rows.len(),
        "preview set must equal the deletion set (#1602)"
    );
}

/// #1602 — `limit` caps the listing (callers over-fetch by one to
/// detect truncation).
#[test]
fn issue_1602_forget_matches_respects_limit() {
    let conn = open_db();
    for i in 0..5 {
        let _ = insert_row(&conn, &format!("row {i}"), Tier::Short);
    }
    let rows = db::forget_matches(&conn, Some(NS), None, None, 3).expect("matches");
    assert_eq!(rows.len(), 3, "limit caps the listing (#1602)");
}

/// #1602 — same no-filter refusal as `forget` / `forget_count`.
#[test]
fn issue_1602_forget_matches_requires_a_filter() {
    let conn = open_db();
    let err = db::forget_matches(&conn, None, None, None, 10).unwrap_err();
    assert!(!err.to_string().is_empty());
}
