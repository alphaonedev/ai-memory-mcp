// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2399 — LANE PARITY: a `long`-tier row is permanent on EVERY write
//! lane, including a FRESH insert that carried a caller-supplied `expires_at`.
//!
//! Pre-#2399 the fresh-insert lane was TIER-BLIND. `POST /api/v1/memories`
//! (and the bulk lane) with `tier=long` + an explicit `expires_at` / `ttl_secs`
//! stored a "permanent" row carrying a live expiry, while EVERY other lane
//! forces NULL for long:
//!
//! * the insert `ON CONFLICT` arms —
//!   `expires_at = CASE WHEN excluded.tier = 'long' OR memories.tier = 'long'
//!    THEN NULL ... END`;
//! * both update funnels (#2331 FBL-01) and the supersede funnel.
//!
//! Because the GC reap predicate is TIER-BLIND
//! (`expires_at IS NOT NULL AND expires_at < now`), the documented-permanent
//! row was archived — or hard-deleted **and crypto-erased** under
//! `archive_on_gc=false` — at the caller's deadline, while the identical
//! logical write through the upsert lane survived forever. Silent destruction
//! of a documented-permanent row: a direct North-Star data-integrity
//! violation, and the reason the gate now runs FIRST.
//!
//! These tests assert on the DURABLE ROW, not on the helper's return value —
//! the helper unit tests in `handlers::parity` and `models::memory` cover the
//! projection; this file covers what actually lands in the database, which is
//! the thing GC reads.

use ai_memory::db;
use ai_memory::models::{Memory, Tier, default_metadata};
use rusqlite::{Connection, params};

const NS: &str = "long-permanence-2399";

fn open_db() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

/// An expiry one hour in the PAST, so a row that kept it is not merely
/// reapable in principle — it is reapable by the very next `gc()` call.
fn already_past() -> String {
    (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339()
}

fn row(tier: Tier, title: &str, expires_at: Option<String>) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: "durable permanent text".to_string(),
        created_at: now.clone(),
        updated_at: now,
        expires_at,
        metadata: default_metadata(),
        ..Memory::default()
    }
}

fn stored_expiry(conn: &Connection, id: &str) -> Option<String> {
    conn.query_row(
        "SELECT expires_at FROM memories WHERE id = ?1",
        params![id],
        |r| r.get::<_, Option<String>>(0),
    )
    .expect("row must exist")
}

/// The core regression: a FRESH long-tier insert carrying a caller expiry
/// lands with `expires_at` NULL, so the tier-blind GC predicate can never see
/// it.
#[test]
fn fresh_long_insert_with_caller_expiry_lands_immortal_2399() {
    let conn = open_db();
    let id = ai_memory::storage::insert(
        &conn,
        &row(Tier::Long, "fresh-long-with-expiry", Some(already_past())),
    )
    .expect("insert");
    assert_eq!(
        stored_expiry(&conn, &id),
        None,
        "#2399: a long-tier row must never carry an expiry on the fresh-insert \
         lane — the GC reap predicate is tier-blind"
    );
}

/// The consequence the issue is actually about: with the expiry gone, `gc()`
/// does not reap the row. Pre-#2399 this row was archived (or hard-deleted +
/// crypto-erased) at the caller's deadline.
#[test]
fn gc_does_not_reap_a_fresh_long_row_that_carried_an_expiry_2399() {
    let conn = open_db();
    let id = ai_memory::storage::insert(
        &conn,
        &row(Tier::Long, "long-survives-gc", Some(already_past())),
    )
    .expect("insert");

    let reaped = ai_memory::storage::gc(&conn, true).expect("gc");
    assert_eq!(reaped, 0, "#2399: gc must not reap a long-tier row");

    let survives: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        survives, 1,
        "#2399: the documented-permanent row must still be in the live tier"
    );
}

/// LANE PARITY, stated as the issue states it: the fresh-insert lane and the
/// upsert lane must produce the SAME durable expiry for the same logical
/// write. Pre-#2399 the upsert lane pinned NULL and the fresh lane did not.
#[test]
fn fresh_insert_and_upsert_lanes_agree_on_long_permanence_2399() {
    let conn = open_db();

    let fresh = ai_memory::storage::insert(
        &conn,
        &row(Tier::Long, "lane-parity-fresh", Some(already_past())),
    )
    .expect("fresh insert");

    // The upsert lane, reached by re-storing the SAME (namespace, title) with
    // a caller expiry — the arm that already forced NULL before #2399.
    let seed = row(Tier::Long, "lane-parity-upsert", None);
    let upserted = ai_memory::storage::insert(&conn, &seed).expect("seed for upsert");
    let mut second = row(Tier::Long, "lane-parity-upsert", Some(already_past()));
    second.id.clone_from(&seed.id);
    ai_memory::storage::insert(&conn, &second).expect("upsert");

    assert_eq!(
        stored_expiry(&conn, &fresh),
        stored_expiry(&conn, &upserted),
        "#2399: the fresh-insert and upsert lanes must resolve a long-tier \
         expiry identically"
    );
    assert_eq!(
        stored_expiry(&conn, &fresh),
        None,
        "#2399: and the value they agree on is NULL (permanent)"
    );
}

/// The gate is NARROW: it must not touch `short` / `mid`, whose caller expiry
/// is the documented contract. A fix that made every tier immortal would trade
/// one data-integrity defect for a retention-policy one.
#[test]
fn non_long_tiers_keep_their_caller_expiry_verbatim_2399() {
    let conn = open_db();
    // v87 canonicalizes expiry TEXT to the v86 fixed-UTC form
    // (`YYYY-MM-DDTHH:MM:SS.ffffffZ`) at the write funnel. The instant
    // is what short/mid must keep; feeding the canonical rendering lets
    // this assertion stay byte-equal without fighting that pre-existing
    // heal. `#2399` must not NULL these.
    let expiry = "2030-01-01T00:00:00.000000Z".to_string();
    for (tier, title) in [(Tier::Short, "short-keeps"), (Tier::Mid, "mid-keeps")] {
        let id = ai_memory::storage::insert(&conn, &row(tier, title, Some(expiry.clone())))
            .expect("insert");
        assert_eq!(
            stored_expiry(&conn, &id).as_deref(),
            Some(expiry.as_str()),
            "#2399: the long gate must not widen to {title}"
        );
    }
}

/// And a non-long row that HAS passed its expiry is still reaped — proof the
/// gate did not disable GC wholesale.
#[test]
fn a_non_long_expired_row_is_still_reaped_2399() {
    let conn = open_db();
    let id = ai_memory::storage::insert(
        &conn,
        &row(Tier::Short, "short-still-reaped", Some(already_past())),
    )
    .expect("insert");

    let reaped = ai_memory::storage::gc(&conn, true).expect("gc");
    assert_eq!(reaped, 1, "#2399: gc must still reap an expired short row");

    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(live, 0, "the expired short row leaves the live tier");
}
