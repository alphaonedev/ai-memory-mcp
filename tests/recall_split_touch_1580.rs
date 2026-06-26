// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1580 — pin the HTTP recall read/write split at the storage layer.
//!
//! The WAL read-pool change splits HTTP recall into two phases: the
//! FTS5/HNSW SELECT runs on a read-only pool connection (PHASE 1) and the
//! authoritative `touch_many` (access-count bump + mid→long promotion +
//! TTL floor-extension) runs on the writer connection (PHASE 2). The
//! enabler is that `touch_many` no-ops on a connection with
//! `PRAGMA query_only = ON` (the read-pool posture) so the read phase
//! performs no writes.
//!
//! This test pins both halves deterministically against a shared file DB
//! (the read-pool is per-connection-correct only on a file DB; `:memory:`
//! is per-connection):
//!
//!  1. `touch_many` on a read-only connection is a NO-OP — `access_count`
//!     is unchanged (the PHASE 1 skip).
//!  2. `touch_many` on the writer connection applies the FULL ladder —
//!     `access_count` 4→5, `tier` mid→long at `PROMOTION_THRESHOLD`,
//!     `expires_at` cleared on promotion (the PHASE 2 authoritative touch).
//!  3. A full `recall` dispatched on the read-only connection still
//!     RETURNS the row (the SELECT works) but does NOT touch it — proving
//!     the read phase is write-free end-to-end.

use rusqlite::params;

const SHORT_EXTEND: i64 = 3_600;
const MID_EXTEND: i64 = 86_400;

fn seed_mid_at_4(conn: &rusqlite::Connection, id: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    // A near-future expiry so a (hypothetical) floor-extend would be visible.
    let soon = (chrono::Utc::now() + chrono::Duration::seconds(30)).to_rfc3339();
    conn.execute(
        "INSERT INTO memories \
            (id, tier, namespace, title, content, tags, priority, confidence, \
             source, access_count, created_at, updated_at, expires_at, metadata, \
             reflection_depth) \
         VALUES (?1, 'mid', 'ns', 'findme', 'findme quick brown fox', '[]', 5, 0.9, \
                 'api', 4, ?2, ?2, ?3, '{}', 0)",
        params![id, now, soon],
    )
    .expect("seed");
}

fn read_access_count(conn: &rusqlite::Connection, id: &str) -> i64 {
    conn.query_row(
        "SELECT access_count FROM memories WHERE id = ?1",
        params![id],
        |r| r.get(0),
    )
    .expect("read access_count")
}

fn read_tier(conn: &rusqlite::Connection, id: &str) -> String {
    conn.query_row(
        "SELECT tier FROM memories WHERE id = ?1",
        params![id],
        |r| r.get(0),
    )
    .expect("read tier")
}

#[test]
fn touch_many_noop_on_readonly_then_full_ladder_on_writer() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let writer = ai_memory::storage::open(tmp.path()).expect("open writer");
    seed_mid_at_4(&writer, "m1");

    // PHASE 1 — read-only (read-pool) connection: touch_many must no-op.
    let ro = ai_memory::storage::open_read_only(tmp.path()).expect("open read-only");
    let n = ai_memory::storage::touch_many(&ro, &["m1"], SHORT_EXTEND, MID_EXTEND)
        .expect("touch_many on read-only conn must succeed (as a no-op)");
    assert_eq!(
        n, 0,
        "touch_many must report zero touched rows on a read-only connection"
    );
    assert_eq!(
        read_access_count(&writer, "m1"),
        4,
        "access_count must be UNCHANGED after a touch on the read-only pool connection"
    );
    assert_eq!(
        read_tier(&writer, "m1"),
        "mid",
        "tier must be unchanged on the read phase"
    );

    // PHASE 2 — writer connection: the authoritative touch applies the
    // full ladder (bump 4→5, then mid→long promotion at the threshold).
    let touched = ai_memory::storage::touch_many(&writer, &["m1"], SHORT_EXTEND, MID_EXTEND)
        .expect("touch_many on writer");
    assert_eq!(touched, 1, "writer touch_many reports one row");
    assert_eq!(
        read_access_count(&writer, "m1"),
        5,
        "writer touch must bump access_count 4→5"
    );
    assert_eq!(
        read_tier(&writer, "m1"),
        "long",
        "writer touch must promote mid→long at PROMOTION_THRESHOLD (access_count >= 5)"
    );
    let expires_at: Option<String> = writer
        .query_row("SELECT expires_at FROM memories WHERE id = 'm1'", [], |r| {
            r.get(0)
        })
        .expect("read expires_at");
    assert!(
        expires_at.is_none(),
        "promotion to long clears expires_at (got {expires_at:?})"
    );
}

#[test]
fn recall_on_readonly_connection_returns_rows_without_touching() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let writer = ai_memory::storage::open(tmp.path()).expect("open writer");
    seed_mid_at_4(&writer, "m1");

    let ro = ai_memory::storage::open_read_only(tmp.path()).expect("open read-only");
    let (results, _budget) = ai_memory::storage::recall(
        &ro,
        "findme",
        Some("ns"),
        10,
        None,
        None,
        None,
        SHORT_EXTEND,
        MID_EXTEND,
        None,
        None,
        false,
        None,
        None,
    )
    .expect("recall on read-only connection must succeed");

    assert!(
        results.iter().any(|(m, _)| m.id == "m1"),
        "recall on the read-only pool connection must still find the seeded row"
    );
    // The internal touch_many no-ops on the read-only connection, so the
    // row is NOT touched by the read phase (the writer phase does that).
    assert_eq!(
        read_access_count(&writer, "m1"),
        4,
        "recall on the read-only pool connection must NOT touch (access_count unchanged)"
    );
}
