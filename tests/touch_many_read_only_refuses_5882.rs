// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #5882 — `touch_many` REFUSES a `PRAGMA query_only = ON` connection.
//!
//! Pre-fix the explicit touch verb read `PRAGMA query_only` with
//! `.unwrap_or(0)` (a pragma read fault assumed a writable connection) and
//! answered a read-only connection with `Ok(0)`: the access signal was lost
//! without an error or a log line, while every other writer on such a
//! connection is refused with `SQLITE_READONLY`. The doc comment said the
//! return value is "always equal to `ids.len()` on success", which the
//! `Ok(0)` branch contradicted for a non-empty batch.
//!
//! These cells pin the refusal: a read-only connection yields `Err`, the
//! row is untouched, and the same connection touches once `query_only` is
//! off again.

use rusqlite::params;

const SHORT_EXTEND: i64 = 3_600;
const MID_EXTEND: i64 = 86_400;

fn seed(conn: &rusqlite::Connection, id: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO memories \
            (id, tier, namespace, title, content, tags, priority, confidence, \
             source, access_count, created_at, updated_at, metadata, reflection_depth) \
         VALUES (?1, 'mid', 'ns', 'findme', 'findme quick brown fox', '[]', 5, 0.9, \
                 'api', 4, ?2, ?2, '{}', 0)",
        params![id, now],
    )
    .expect("seed");
}

fn access_count(conn: &rusqlite::Connection, id: &str) -> i64 {
    conn.query_row(
        "SELECT access_count FROM memories WHERE id = ?1",
        params![id],
        |r| r.get(0),
    )
    .expect("read access_count")
}

/// The read-pool posture (`open_read_only` sets `query_only = ON`): the
/// touch is REFUSED with an error that names the posture, and nothing is
/// written.
#[test]
fn touch_many_refuses_a_read_only_pool_connection_5882() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let writer = ai_memory::storage::open(tmp.path()).expect("open writer");
    seed(&writer, "m1");

    let ro = ai_memory::storage::open_read_only(tmp.path()).expect("open read-only");
    let err = ai_memory::storage::touch_many(&ro, &["m1"], SHORT_EXTEND, MID_EXTEND)
        .expect_err("a read-only connection must be REFUSED, never reported as Ok(0)");
    assert!(
        format!("{err:#}").contains("query_only"),
        "the refusal must name the read-only posture: {err:#}"
    );
    assert_eq!(
        access_count(&writer, "m1"),
        4,
        "access_count must be UNCHANGED after a refused touch"
    );
}

/// A writer connection that a scope made read-only (`PRAGMA query_only = ON`
/// on the SAME connection) is refused too, and touches again once the
/// pragma is cleared — the refusal is about the posture, not the handle.
#[test]
fn touch_many_refuses_query_only_then_touches_when_cleared_5882() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::storage::open(tmp.path()).expect("open writer");
    seed(&conn, "m1");

    conn.pragma_update(None, "query_only", "ON")
        .expect("query_only ON");
    ai_memory::storage::touch_many(&conn, &["m1"], SHORT_EXTEND, MID_EXTEND)
        .expect_err("query_only = ON must be REFUSED, never reported as Ok(0)");
    assert_eq!(access_count(&conn, "m1"), 4, "no write under query_only");

    conn.pragma_update(None, "query_only", "OFF")
        .expect("query_only OFF");
    let touched = ai_memory::storage::touch_many(&conn, &["m1"], SHORT_EXTEND, MID_EXTEND)
        .expect("writable again");
    assert_eq!(touched, 1, "the return value is ids.len() on success");
    assert_eq!(
        access_count(&conn, "m1"),
        5,
        "the touch landed once writable"
    );
}
