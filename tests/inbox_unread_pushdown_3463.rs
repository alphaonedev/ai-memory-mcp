// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3463 → #3730 — what happened to the unread pushdown.
//!
//! #3463 pushed the inbox's `unread_only` narrowing (`AND access_count = 0`)
//! INTO the query, before the SQL `LIMIT`, because an agent whose newest
//! `limit` messages were all "read" was answered `unread_count: 0` while older
//! unread messages sat behind the page — a real false negative and a correct
//! fix for the marker as it was then defined.
//!
//! #3730 retired the marker itself: `access_count` counts TOUCHES (a recall
//! landed by the fold), which no inbox operation advances and which never
//! meant HANDLED. The inbox is now the PENDING set — a message leaves it when
//! its recipient deletes it — so there are no "read" rows for a page to be
//! spent on, and the #3463 problem is DISSOLVED rather than reverted: nothing
//! is narrowed, and nothing can hide behind the limit. The pins below say
//! exactly that, on the same corpus shape #3463 used, so a later reader who
//! finds the pushdown gone knows it was made unnecessary.
//!
//! * **SQL shape** — `build_list_query` never emits an `access_count`
//!   predicate (there is no axis to set).
//! * **Page shape** — the same corpus (three newer TOUCHED rows in front of one
//!   older untouched one, `limit = 3`) lists the three newest rows under
//!   `unread_only` too: touched is not handled, and the page is the page.
//! * **Full window** — all four rows list, with no `read` field on the wire and
//!   `unread_count == count`.
//! * **SAL parity** — `SqliteStore::list` has no unread axis; the same
//!   fixture returns the same page.

#![allow(clippy::missing_panics_doc, clippy::field_reassign_with_default)]

use ai_memory::models::Memory;
use serde_json::json;

/// The fragment #3463 used to push into SQL. Restated so its ABSENCE is what
/// this file pins.
const RETIRED_FRAGMENT: &str = "access_count = 0";

const OWNER: &str = "ai:bob-3463";

fn inbox_ns() -> String {
    format!("_messages/{OWNER}")
}

/// Seed `touched` TOUCHED messages at HIGH priority plus one older untouched
/// message at LOW priority — the exact corpus shape that produced the #3463
/// false negative, kept so the dissolution is shown on the same input.
fn seed_inbox(conn: &rusqlite::Connection, touched: usize) {
    let ns = inbox_ns();
    let mut older = Memory::default();
    older.id = "m3463-untouched".to_string();
    older.namespace.clone_from(&ns);
    older.title = "older untouched".to_string();
    older.content = "the message the agent must still be told about".to_string();
    older.priority = 1;
    older.metadata = json!({"agent_id": "ai:alice-3463"});
    ai_memory::db::insert(conn, &older).expect("insert untouched");

    for n in 0..touched {
        let mut m = Memory::default();
        m.id = format!("m3463-touched-{n}");
        m.namespace.clone_from(&ns);
        m.title = format!("newer touched {n}");
        m.content = "recalled once and folded".to_string();
        m.priority = 9;
        m.metadata = json!({"agent_id": "ai:alice-3463"});
        ai_memory::db::insert(conn, &m).expect("insert touched");
        // Touch it the way the fold does: bump `access_count`. #3730 — this
        // is a TOUCH, not a handling; it must not hide the row.
        let n_rows = conn
            .execute(
                "UPDATE memories SET access_count = 1 WHERE id = ?1",
                rusqlite::params![m.id],
            )
            .expect("bump access_count");
        assert_eq!(n_rows, 1, "fixture must touch exactly one row");
    }
}

fn scratch_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir_in(".local-runs").expect("scratch dir under the repo");
    let path = dir.path().join("inbox-3463.db");
    (dir, path)
}

// ---------------------------------------------------------------------
// SQL shape — no unread axis exists any more.
// ---------------------------------------------------------------------

#[test]
fn sql_shape_never_emits_an_access_count_predicate_3730() {
    let now = chrono::Utc::now().to_rfc3339();
    let (sql, _params) = ai_memory::db::build_list_query(
        Some("ns"),
        None,
        None,
        &now,
        None,
        None,
        None,
        None,
        None,
        None,
        10,
        0,
    );
    assert!(
        !sql.contains(RETIRED_FRAGMENT),
        "#3730: the #3463 unread pushdown is retired — `access_count` counts touches, not \
         handling, and the inbox is the pending set; got:\n{sql}"
    );
}

// ---------------------------------------------------------------------
// Page shape — touched is not handled; the page is the page.
// ---------------------------------------------------------------------

#[test]
fn mcp_inbox_unread_only_lists_touched_rows_on_the_same_page_3730() {
    let (_dir, path) = scratch_db();
    let conn = ai_memory::db::open(&path).expect("db::open");
    seed_inbox(&conn, 3);

    let out = ai_memory::mcp::handle_inbox(
        &conn,
        &json!({"agent_id": OWNER, "unread_only": true, "limit": 3}),
        None,
        Some(OWNER),
    )
    .expect("inbox must succeed");

    let messages = out["messages"].as_array().expect("messages array");
    assert_eq!(
        messages.len(),
        3,
        "#3730: `unread_only` narrows nothing — the three newest (touched) rows are the \
         page, because a touch is not a handling. got={out}"
    );
    assert!(
        messages
            .iter()
            .all(|m| m["access_count"].as_u64() == Some(1)),
        "the high-priority page is the three TOUCHED rows; got={messages:?}"
    );
    assert!(
        messages.iter().all(|m| m.get("read").is_none()),
        "#3730: no `read` field on the inbox wire shape; got={messages:?}"
    );
    assert_eq!(out["count"].as_u64(), Some(3));
    assert_eq!(
        out["unread_count"].as_u64(),
        Some(3),
        "every listed message is unhandled, so unread_count == count; got={out}"
    );
    assert_eq!(out["unread_only"].as_bool(), Some(true), "echoed as sent");
}

// ---------------------------------------------------------------------
// Full window — nothing hides behind the limit because nothing is narrowed.
// ---------------------------------------------------------------------

#[test]
fn mcp_inbox_full_window_lists_every_row_with_or_without_the_flag_3730() {
    let (_dir, path) = scratch_db();
    let conn = ai_memory::db::open(&path).expect("db::open");
    seed_inbox(&conn, 3);

    for unread_only in [false, true] {
        let all = ai_memory::mcp::handle_inbox(
            &conn,
            &json!({"agent_id": OWNER, "unread_only": unread_only, "limit": 50}),
            None,
            Some(OWNER),
        )
        .expect("inbox must succeed");
        assert_eq!(
            all["count"].as_u64(),
            Some(4),
            "unread_only={unread_only}: {all}"
        );
        assert_eq!(all["unread_count"].as_u64(), Some(4));
        assert_eq!(all["unread_only"].as_bool(), Some(unread_only));
        let ids: Vec<&str> = all["messages"]
            .as_array()
            .expect("messages")
            .iter()
            .filter_map(|m| m["id"].as_str())
            .collect();
        assert!(
            ids.contains(&"m3463-untouched"),
            "the older row is in the window: {ids:?}"
        );
    }
}

// ---------------------------------------------------------------------
// SAL parity — no unread axis on the adapter the postgres twin mirrors.
// ---------------------------------------------------------------------

#[cfg(feature = "sal")]
mod sal {
    use super::{inbox_ns, scratch_db, seed_inbox};
    use ai_memory::store::sqlite::SqliteStore;
    use ai_memory::store::{CallerContext, Filter, MemoryStore};

    #[tokio::test]
    async fn sal_list_has_no_unread_axis_and_pages_touched_rows_3730() {
        let (_dir, path) = scratch_db();
        {
            let conn = ai_memory::db::open(&path).expect("db::open");
            seed_inbox(&conn, 3);
        }
        let store = SqliteStore::open(&path).expect("open SqliteStore");
        let ctx = CallerContext::for_admin("test-3463");

        let filter = {
            let mut f = Filter::new();
            f.namespace = Some(inbox_ns());
            f.limit = 3;
            f
        };
        let rows = store.list(&ctx, &filter).await.expect("list");
        assert_eq!(rows.len(), 3, "the 3-row window is the three touched rows");
        assert!(rows.iter().all(|r| r.access_count == 1));

        let filter = {
            let mut f = Filter::new();
            f.namespace = Some(inbox_ns());
            f.limit = 50;
            f
        };
        let rows = store.list(&ctx, &filter).await.expect("list");
        assert_eq!(rows.len(), 4, "the full window lists every row");
    }
}
