// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3463 — the inbox `unread_only` narrowing must run INSIDE the query,
//! before the SQL `LIMIT`, on every backend.
//!
//! Pre-fix, `handle_inbox` (`src/mcp/tools/notify.rs`, which the HTTP-sqlite
//! `get_inbox` delegates to) fetched the newest `limit` rows via `db::list` and
//! only then dropped the read ones in Rust; the postgres arm of `get_inbox` did
//! the same over `store.list`. So an agent whose newest `limit` messages were
//! all read was answered `count: 0` / `unread_count: 0` while OLDER unread
//! messages sat untouched in its namespace — a silent false negative. Any
//! "wake, then read the inbox once" push design built on that is unsound, and
//! the wrong answer is a data-integrity defect on its own: the substrate may
//! return FEWER results, never WRONG ones.
//!
//! What is pinned here:
//!
//! * **Fail-at-parent SQL shape** — `build_list_query` must EMIT the
//!   `access_count = 0` predicate when the axis is set, must NOT emit it
//!   otherwise, must place it BEFORE the `ORDER BY ... LIMIT` tail (the whole
//!   point of the fix), and must add no bind parameter.
//! * **DENIED path** — the pre-fix false negative: a full page of newer READ
//!   messages must not hide an older unread one. This test fails against the
//!   pre-#3463 tree.
//! * **ALLOWED path** — `unread_only` absent/false still returns the exact
//!   legacy page, so the fix narrows nothing it should not.
//! * **SAL parity** — the same fixture through `SqliteStore::list` with
//!   `Filter::unread_only`, the adapter the postgres twin mirrors.

#![allow(clippy::missing_panics_doc, clippy::field_reassign_with_default)]

use ai_memory::models::Memory;
use serde_json::json;

/// The exact fragment the sqlite builder must push into SQL. Restated here on
/// purpose: this test is the SSOT contract, so a silent rewrite of the
/// production fragment fails loudly instead of drifting.
const EXPECTED_FRAGMENT: &str = "access_count = 0";

const OWNER: &str = "ai:bob-3463";

fn inbox_ns() -> String {
    format!("_messages/{OWNER}")
}

/// Seed `read_count` READ messages at HIGH priority plus one older UNREAD
/// message at LOW priority, so the read rows deterministically occupy the whole
/// first `read_count`-row window of `ORDER BY priority DESC, updated_at DESC,
/// id ASC`. This is the exact corpus shape that produced the false negative.
fn seed_inbox(conn: &rusqlite::Connection, read_count: usize) {
    let ns = inbox_ns();
    let mut unread = Memory::default();
    unread.id = "m3463-unread".to_string();
    unread.namespace.clone_from(&ns);
    unread.title = "older unread".to_string();
    unread.content = "the message the agent must still be told about".to_string();
    unread.priority = 1;
    unread.metadata = json!({"agent_id": "ai:alice-3463"});
    ai_memory::db::insert(conn, &unread).expect("insert unread");

    for n in 0..read_count {
        let mut m = Memory::default();
        m.id = format!("m3463-read-{n}");
        m.namespace.clone_from(&ns);
        m.title = format!("newer read {n}");
        m.content = "already read".to_string();
        m.priority = 9;
        m.metadata = json!({"agent_id": "ai:alice-3463"});
        ai_memory::db::insert(conn, &m).expect("insert read");
        // Mark it read the way a real read does: bump `access_count`, the
        // #3027 unread marker, a real NOT NULL column on both backends.
        let touched = conn
            .execute(
                "UPDATE memories SET access_count = 1 WHERE id = ?1",
                rusqlite::params![m.id],
            )
            .expect("bump access_count");
        assert_eq!(touched, 1, "fixture must touch exactly one row");
    }
}

// ---------------------------------------------------------------------
// Fail-at-parent — SQL shape.
// ---------------------------------------------------------------------

#[test]
fn sql_shape_emits_unread_predicate_only_when_axis_is_set_3463() {
    let now = chrono::Utc::now().to_rfc3339();
    let (without, params_without) = ai_memory::db::build_list_query(
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
        false, // #3463 unread_only unset
        10,
        0,
    );
    assert!(
        !without.contains(EXPECTED_FRAGMENT),
        "an unset unread axis must leave the legacy list SQL byte-identical (no \
         `{EXPECTED_FRAGMENT}` fragment), so every pre-#3463 list shape keeps its \
         cached plan; got:\n{without}"
    );

    let (with, params_with) = ai_memory::db::build_list_query(
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
        true, // #3463 unread_only set
        10,
        0,
    );
    let frag_at = with.find(EXPECTED_FRAGMENT).unwrap_or_else(|| {
        panic!(
            "#3463 REGRESSED: `unread_only` must be pushed INTO the SQL, not applied \
             in Rust after the LIMIT has already been spent. Expected the \
             `{EXPECTED_FRAGMENT}` fragment in:\n{with}"
        )
    });
    let order_at = with
        .find(" ORDER BY")
        .expect("the list SQL always carries an ORDER BY ... LIMIT tail");
    assert!(
        frag_at < order_at,
        "#3463: the unread predicate must precede the `ORDER BY ... LIMIT` tail — a \
         narrowing applied AFTER the LIMIT is exactly the defect. got:\n{with}"
    );
    assert_eq!(
        params_with.len(),
        params_without.len(),
        "the unread predicate is a parameter-free constant, so it must add no bind \
         (and therefore cannot shift any other placeholder's position)"
    );
}

// ---------------------------------------------------------------------
// DENIED path — the pre-fix false negative.
// ---------------------------------------------------------------------

#[test]
fn mcp_inbox_unread_only_sees_past_a_full_page_of_read_messages_3463() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    // A full page (limit == 3) of NEWER, higher-priority, already-read rows in
    // front of one older unread row.
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
        1,
        "#3463 REGRESSED: `unread_only` was applied AFTER the SQL LIMIT, so a full \
         page of newer READ messages hid the older unread one and the agent was told \
         it had nothing unread. got={out}"
    );
    assert_eq!(messages[0]["id"].as_str(), Some("m3463-unread"));
    assert_eq!(messages[0]["read"].as_bool(), Some(false));
    assert_eq!(out["count"].as_u64(), Some(1));
    assert_eq!(
        out["unread_count"].as_u64(),
        Some(1),
        "`unread_count` must be derived from the SAME `access_count` marker the \
         filter and the `read` wire field use; got={out}"
    );
    assert_eq!(out["unread_only"].as_bool(), Some(true));
}

/// The narrowing must be exact, not merely non-empty: every returned row is
/// unread, and no read row leaks in even when the page has room for it.
#[test]
fn mcp_inbox_unread_only_returns_exactly_the_unread_rows_3463() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    seed_inbox(&conn, 3);

    let out = ai_memory::mcp::handle_inbox(
        &conn,
        &json!({"agent_id": OWNER, "unread_only": true, "limit": 50}),
        None,
        Some(OWNER),
    )
    .expect("inbox must succeed");
    let messages = out["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 1, "exactly one row is unread; got={out}");
    for m in messages {
        assert_eq!(
            m["access_count"].as_u64(),
            Some(0),
            "a read row leaked through the unread narrowing (fail-OPEN): {m}"
        );
    }
}

// ---------------------------------------------------------------------
// ALLOWED path — the unfiltered inbox is unchanged.
// ---------------------------------------------------------------------

#[test]
fn mcp_inbox_without_unread_only_still_returns_the_legacy_page_3463() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    seed_inbox(&conn, 3);

    let out = ai_memory::mcp::handle_inbox(
        &conn,
        &json!({"agent_id": OWNER, "limit": 3}),
        None,
        Some(OWNER),
    )
    .expect("inbox must succeed");
    let messages = out["messages"].as_array().expect("messages array");
    assert_eq!(
        messages.len(),
        3,
        "with `unread_only` absent the inbox must return the SAME first page it \
         always did — the fix must narrow nothing it was not asked to; got={out}"
    );
    for m in messages {
        assert_eq!(
            m["read"].as_bool(),
            Some(true),
            "the high-priority page is the three READ rows; got={m}"
        );
    }
    assert_eq!(out["count"].as_u64(), Some(3));
    assert_eq!(out["unread_count"].as_u64(), Some(0));
    assert_eq!(out["unread_only"].as_bool(), Some(false));

    // And the full window still exposes all four rows.
    let all = ai_memory::mcp::handle_inbox(
        &conn,
        &json!({"agent_id": OWNER, "limit": 50}),
        None,
        Some(OWNER),
    )
    .expect("inbox must succeed");
    assert_eq!(all["count"].as_u64(), Some(4));
    assert_eq!(all["unread_count"].as_u64(), Some(1));
}

// ---------------------------------------------------------------------
// SAL parity — the adapter the postgres twin mirrors.
// ---------------------------------------------------------------------

#[cfg(feature = "sal")]
mod sal {
    use super::{OWNER, inbox_ns, seed_inbox};
    use ai_memory::store::sqlite::SqliteStore;
    use ai_memory::store::{CallerContext, Filter, MemoryStore};

    #[tokio::test]
    async fn sal_list_unread_only_narrows_before_the_limit_3463() {
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        {
            let conn = ai_memory::db::open(f.path()).expect("db::open");
            seed_inbox(&conn, 3);
        }
        let store = SqliteStore::open(f.path()).expect("open SqliteStore");
        let ctx = CallerContext::for_admin("test-3463");

        // DENIED path: a 3-row window entirely occupied by newer READ rows must
        // still surface the older unread one.
        let filter = {
            let mut f = Filter::new();
            f.namespace = Some(inbox_ns());
            f.limit = 3;
            f.unread_only = true;
            f
        };
        let rows = store.list(&ctx, &filter).await.expect("list");
        assert_eq!(
            rows.len(),
            1,
            "#3463: `Filter::unread_only` must narrow in SQL, before the LIMIT — a \
             post-LIMIT filter returns nothing here. owner={OWNER}"
        );
        assert_eq!(rows[0].id, "m3463-unread");
        for r in &rows {
            assert_eq!(
                r.access_count, 0,
                "the adapter's fail-closed re-check must reject any read row: {}",
                r.id
            );
        }

        // ALLOWED path: the same window without the axis is the legacy page.
        let filter = {
            let mut f = Filter::new();
            f.namespace = Some(inbox_ns());
            f.limit = 3;
            f
        };
        let rows = store.list(&ctx, &filter).await.expect("list");
        assert_eq!(rows.len(), 3, "unfiltered listing must be unchanged");
        assert!(rows.iter().all(|r| r.access_count == 1));
    }
}
