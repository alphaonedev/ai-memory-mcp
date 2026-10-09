// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2462 — the schema-v54 tier-default-expiry backfill must write the
//! canonical `YYYY-MM-DDTHH:MM:SS.ffffffZ` rendering ON ITS OWN.
//!
//! `memories.expires_at` is TEXT compared lexicographically (GC reap,
//! list/recall visibility, the #1596 extension floors), so the rendering IS
//! the ordering contract. Before this fix the v54 arm wrote
//! `strftime('…%S+00:00')` (no fraction, `+00:00` offset) and was correct
//! only because the later v87 `normalize_expiry_rows` heal happened to run
//! after it. These cells drive the v54 arm in isolation — no v87 — and
//! assert the stored bytes are already a fixpoint of
//! `validate::canonicalize_valid_time`.

use ai_memory::storage::migrations::backfill_v54_tier_default_expiry;
use ai_memory::validate::canonicalize_valid_time;
use rusqlite::{Connection, params};

/// Only the columns the v54 arm reads and writes.
fn legacy_db() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory sqlite");
    conn.execute_batch(
        "CREATE TABLE memories (id TEXT PRIMARY KEY, tier TEXT NOT NULL, \
         created_at TEXT NOT NULL, expires_at TEXT)",
    )
    .expect("legacy memories table");
    conn
}

fn insert(conn: &Connection, id: &str, tier: &str, created_at: &str) {
    conn.execute(
        "INSERT INTO memories (id, tier, created_at, expires_at) VALUES (?1, ?2, ?3, NULL)",
        params![id, tier, created_at],
    )
    .expect("insert legacy row");
}

fn expiry(conn: &Connection, id: &str) -> Option<String> {
    conn.query_row(
        "SELECT expires_at FROM memories WHERE id = ?1",
        params![id],
        |r| r.get(0),
    )
    .expect("select expires_at")
}

#[test]
fn v54_backfill_writes_canonical_rendering_without_v87_2462() {
    let conn = legacy_db();
    insert(&conn, "mid1", "mid", "2026-01-01T00:00:00+00:00");
    insert(&conn, "short1", "short", "2026-01-01T09:00:00+09:00");
    backfill_v54_tier_default_expiry(&conn).expect("v54 backfill");

    assert_eq!(
        expiry(&conn, "mid1").as_deref(),
        Some("2026-01-08T00:00:00.000000Z"),
        "mid = created_at + 1w, canonical fixed-width micros + Z"
    );
    assert_eq!(
        expiry(&conn, "short1").as_deref(),
        Some("2026-01-01T06:00:00.000000Z"),
        "short = created_at (+09:00 normalised to UTC) + 6h, canonical"
    );
    for id in ["mid1", "short1"] {
        let got = expiry(&conn, id).expect("backfilled");
        assert_eq!(
            canonicalize_valid_time(&got).as_deref(),
            Some(got.as_str()),
            "{id}: stored expiry must already be canonical (no v87 heal needed)"
        );
    }
}

#[test]
fn v54_backfill_keeps_long_null_and_is_idempotent_2462() {
    let conn = legacy_db();
    insert(&conn, "long1", "long", "2026-01-01T00:00:00.000000Z");
    insert(&conn, "mid1", "mid", "2026-01-01T00:00:00.000000Z");
    backfill_v54_tier_default_expiry(&conn).expect("first pass");
    let first = expiry(&conn, "mid1");
    backfill_v54_tier_default_expiry(&conn).expect("second pass");
    assert_eq!(expiry(&conn, "mid1"), first, "stamped rows are not moved");
    assert_eq!(expiry(&conn, "long1"), None, "long has no TTL — stays NULL");
}
