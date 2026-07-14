// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

//! v1.0.0 #1834 — claim-bitemporal recall acceptance suite.
//!
//! Pins the VALID-time (`valid_at`) recall filter across the sqlite
//! keyword (`db::recall`) and hybrid (`db::recall_hybrid`) paths. The
//! contract (spec + 5-agent vote `4d3ea1c5`, design `591608d4`):
//!
//! * The validity interval is HALF-OPEN `[valid_from, valid_until)` —
//!   start-INCLUSIVE, end-EXCLUSIVE per SQL:2011 (`valid_until > valid_at`).
//! * NULL bounds are unbounded (a NULL/NULL legacy row is valid at every
//!   instant), so pre-#1834 rows stay visible.
//! * Omitting `valid_at` (None) is byte-identical to legacy recall — no
//!   row is filtered on the validity axis.

use ai_memory::config::ResolvedScoring;
use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::storage;
use std::sync::{Mutex, OnceLock};

mod common;
use common::fresh_db_tempfile_conn as fresh_db;

fn test_serial() -> &'static Mutex<()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
}

const NS: &str = "bitemporal-1834";
const TERM: &str = "bitemporal";

// Interval endpoints used across the scenarios.
const T_JAN: &str = "2026-01-01T00:00:00+00:00";
const T_JUN: &str = "2026-06-01T00:00:00+00:00";

fn mem(title: &str, valid_from: Option<&str>, valid_until: Option<&str>) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("{TERM} claim body for {title}"),
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        created_at: now.clone(),
        updated_at: now,
        memory_kind: MemoryKind::Claim,
        valid_from: valid_from.map(str::to_string),
        valid_until: valid_until.map(str::to_string),
        version: 1,
        ..Memory::default()
    }
}

/// Insert A (legacy NULL/NULL), B ([JAN, JUN)), C ([JUN, ∞)). All share
/// the FTS term so the keyword pool returns every row before the
/// validity predicate runs.
fn seed(conn: &rusqlite::Connection) {
    storage::insert(conn, &mem("alpha", None, None)).expect("insert A");
    storage::insert(conn, &mem("bravo", Some(T_JAN), Some(T_JUN))).expect("insert B");
    storage::insert(conn, &mem("charlie", Some(T_JUN), None)).expect("insert C");
}

fn titles_keyword(conn: &rusqlite::Connection, valid_at: Option<&str>) -> Vec<String> {
    let (rows, _) = db::recall(
        conn,
        TERM,
        Some(NS),
        50,
        None,
        None,
        None,
        ai_memory::SECS_PER_HOUR,
        ai_memory::SECS_PER_DAY,
        None,
        None,
        false,
        None,
        None,
        valid_at,
    )
    .expect("keyword recall");
    let mut t: Vec<String> = rows.into_iter().map(|(m, _)| m.title).collect();
    t.sort();
    t
}

fn titles_hybrid(conn: &rusqlite::Connection, valid_at: Option<&str>) -> Vec<String> {
    // No vector index + no stored embeddings → the FTS pool drives the
    // result set, exercising the FTS-branch valid_at predicate. A dummy
    // query embedding is required by the signature but scores nothing.
    let scoring = ResolvedScoring::default();
    let (rows, _) = db::recall_hybrid(
        conn,
        TERM,
        &[0.0_f32; 8],
        Some(NS),
        50,
        None,
        None,
        None,
        None,
        ai_memory::SECS_PER_HOUR,
        ai_memory::SECS_PER_DAY,
        None,
        None,
        &scoring,
        false,
        None,
        None,
        valid_at,
    )
    .expect("hybrid recall");
    let mut t: Vec<String> = rows.into_iter().map(|(m, _)| m.title).collect();
    t.sort();
    t
}

fn titles_list(conn: &rusqlite::Connection, valid_at: Option<&str>) -> Vec<String> {
    let rows = db::list(
        conn,
        Some(NS),
        None, // tier
        50,   // limit
        0,    // offset
        None, // min_priority
        None, // since
        None, // until
        None, // tags
        None, // agent_id
        valid_at,
    )
    .expect("list");
    let mut t: Vec<String> = rows.into_iter().map(|m| m.title).collect();
    t.sort();
    t
}

#[test]
fn list_surface_applies_valid_at_with_the_same_half_open_contract() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_tmp, conn) = fresh_db();
    seed(&conn);

    // Omitted → all; legacy NULL/NULL always visible; inside-window selects
    // the bounded claim; boundary is start-inclusive / end-exclusive at T_JUN.
    assert_eq!(titles_list(&conn, None), vec!["alpha", "bravo", "charlie"]);
    assert!(titles_list(&conn, Some("2099-01-01T00:00:00+00:00")).contains(&"alpha".to_string()));
    assert_eq!(
        titles_list(&conn, Some("2026-03-01T00:00:00+00:00")),
        vec!["alpha", "bravo"]
    );
    assert_eq!(titles_list(&conn, Some(T_JUN)), vec!["alpha", "charlie"]);
    assert_eq!(
        titles_list(&conn, Some("2025-12-01T00:00:00+00:00")),
        vec!["alpha"]
    );
}

#[test]
fn validate_valid_at_rejects_non_rfc3339() {
    // The entry surfaces (HTTP recall/list, MCP list, CLI) reject a malformed
    // as-of so it never reaches the lexicographic SQL comparison.
    assert!(ai_memory::validate::validate_valid_at("2026-01-01T00:00:00Z").is_ok());
    assert!(ai_memory::validate::validate_valid_at("2026-01-01T00:00:00+00:00").is_ok());
    for bad in [
        "not-a-date",
        "2026-13-01T00:00:00Z",
        "2026-01-01",
        "",
        "yesterday",
    ] {
        assert!(
            ai_memory::validate::validate_valid_at(bad).is_err(),
            "expected reject: {bad:?}"
        );
    }
}

#[test]
fn omitted_valid_at_returns_every_row_on_both_paths() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_tmp, conn) = fresh_db();
    seed(&conn);

    assert_eq!(
        titles_keyword(&conn, None),
        vec!["alpha", "bravo", "charlie"],
        "keyword: no as-of must not filter on validity"
    );
    assert_eq!(
        titles_hybrid(&conn, None),
        vec!["alpha", "bravo", "charlie"],
        "hybrid: no as-of must not filter on validity"
    );
}

#[test]
fn legacy_null_bounded_row_is_valid_at_every_instant() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_tmp, conn) = fresh_db();
    seed(&conn);

    // Alpha (NULL/NULL) must appear at instants far before AND after the
    // other rows' windows — pre-#1834 rows never get filtered out.
    for as_of in ["2000-01-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00"] {
        assert!(
            titles_keyword(&conn, Some(as_of)).contains(&"alpha".to_string()),
            "keyword: legacy NULL/NULL row must be visible at {as_of}"
        );
        assert!(
            titles_hybrid(&conn, Some(as_of)).contains(&"alpha".to_string()),
            "hybrid: legacy NULL/NULL row must be visible at {as_of}"
        );
    }
}

#[test]
fn as_of_inside_bounded_window_selects_that_claim() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_tmp, conn) = fresh_db();
    seed(&conn);

    // 2026-03 is inside [JAN, JUN) → bravo; before [JUN,∞) → not charlie.
    let as_of = "2026-03-01T00:00:00+00:00";
    assert_eq!(titles_keyword(&conn, Some(as_of)), vec!["alpha", "bravo"]);
    assert_eq!(titles_hybrid(&conn, Some(as_of)), vec!["alpha", "bravo"]);
}

#[test]
fn window_boundary_is_start_inclusive_end_exclusive() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_tmp, conn) = fresh_db();
    seed(&conn);

    // At exactly T_JUN: bravo's valid_until == JUN is END-EXCLUSIVE, so
    // bravo drops; charlie's valid_from == JUN is START-INCLUSIVE, so
    // charlie appears. This is the SQL:2011 half-open contract.
    let both = titles_keyword(&conn, Some(T_JUN));
    assert_eq!(both, vec!["alpha", "charlie"], "keyword boundary");
    assert_eq!(
        titles_hybrid(&conn, Some(T_JUN)),
        vec!["alpha", "charlie"],
        "hybrid boundary"
    );

    // Just before the whole timeline: only the legacy row is visible.
    let before = "2025-12-01T00:00:00+00:00";
    assert_eq!(titles_keyword(&conn, Some(before)), vec!["alpha"]);
    assert_eq!(titles_hybrid(&conn, Some(before)), vec!["alpha"]);
}
