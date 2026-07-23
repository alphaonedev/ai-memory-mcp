// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 STORAGE-CHAIN lane regression pins (fable-3x7 findings).
//!
//! One test group per finding/issue, all against the canonical
//! `db::open(":memory:")` fixture so the migration ladder fires:
//!
//! * #2331 (FBL-01) — `memory_update` tier→long must clear the stale
//!   short/mid `expires_at` (the #1626 coupling, sqlite parity), and the
//!   tier-blind GC must therefore never reap the promoted row.

use ai_memory::db;
use ai_memory::models::{Memory, Tier};
use rusqlite::Connection;
use serde_json::json;

fn fresh_sqlite() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory sqlite")
}

/// Seed a memory row through the canonical `db::insert` funnel.
fn seed(conn: &Connection, id: &str, tier: Tier, expires_at: Option<&str>) -> String {
    let mem = Memory {
        id: id.to_string(),
        tier,
        namespace: "storage-chain".to_string(),
        title: format!("title-{id}"),
        content: format!("content for {id}"),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        expires_at: expires_at.map(str::to_string),
        metadata: json!({}),
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("seed memory")
}

fn row_tier_and_expiry(conn: &Connection, id: &str) -> (String, Option<String>) {
    conn.query_row(
        "SELECT tier, expires_at FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .expect("row present")
}

// ─────────────────────────────────────────────────────────────────────
// #2331 (FBL-01)
// ─────────────────────────────────────────────────────────────────────

/// `memory_update {tier:"long"}` on a mid-tier row (which always carries a
/// live TTL) must clear `expires_at` — the pg #1626 contract, previously
/// missing on sqlite.
#[test]
fn fbl01_update_tier_long_clears_stale_expiry() {
    let conn = fresh_sqlite();
    // Expiry already in the past: the worst case — without the coupling
    // the very next gc() reaps the freshly-promoted "permanent" row.
    let stale = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let id = seed(&conn, "fbl01-a", Tier::Mid, Some(&stale));

    let (found, _) = db::update_with_expected_version(
        &conn,
        &id,
        None,
        None,
        Some(&Tier::Long),
        None,
        None,
        None,
        None,
        None, // no expires_at in the patch — the natural "make permanent" call
        None,
        None,
        None,
        None,
    )
    .expect("tier promotion update succeeds");
    assert!(found, "row must be found");

    let (tier, expiry) = row_tier_and_expiry(&conn, &id);
    assert_eq!(tier, "long");
    assert_eq!(
        expiry, None,
        "tier→long must clear the stale short/mid expires_at (#1626 sqlite parity)"
    );

    // The tier-blind GC must not reap the promoted row.
    db::gc(&conn, true).expect("gc runs");
    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(live, 1, "gc must not reap an explicitly-promoted long row");
}

/// An explicitly-supplied `expires_at` patch value LOSES to the long⇒NULL
/// clear (mirrors the pg CASE, which nulls unconditionally when the new
/// tier is long).
#[test]
fn fbl01_update_tier_long_overrides_explicit_expiry_patch() {
    let conn = fresh_sqlite();
    let id = seed(&conn, "fbl01-b", Tier::Short, None);
    let future = (chrono::Utc::now() + chrono::Duration::days(3)).to_rfc3339();

    db::update_with_expected_version(
        &conn,
        &id,
        None,
        None,
        Some(&Tier::Long),
        None,
        None,
        None,
        None,
        Some(&future),
        None,
        None,
        None,
        None,
    )
    .expect("update succeeds");

    let (tier, expiry) = row_tier_and_expiry(&conn, &id);
    assert_eq!(tier, "long");
    assert_eq!(
        expiry, None,
        "an explicit expires_at patch loses to the long⇒NULL clear"
    );
}

/// A non-promoting update keeps the existing expiry untouched (the fix
/// must not widen into clearing short/mid TTLs).
#[test]
fn fbl01_update_without_tier_change_preserves_expiry() {
    let conn = fresh_sqlite();
    let future = (chrono::Utc::now() + chrono::Duration::days(2)).to_rfc3339();
    let id = seed(&conn, "fbl01-c", Tier::Mid, Some(&future));

    db::update_with_expected_version(
        &conn,
        &id,
        Some("retitled"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("update succeeds");

    let (tier, expiry) = row_tier_and_expiry(&conn, &id);
    assert_eq!(tier, "mid");
    // Instant-preserving comparison: the #2332 funnel canonicalizes the
    // carried-forward rendering (micros + `Z`), so compare instants, not
    // bytes.
    let stored = chrono::DateTime::parse_from_rfc3339(expiry.as_deref().expect("expiry kept"))
        .expect("parseable");
    let expected = chrono::DateTime::parse_from_rfc3339(&future).expect("parseable");
    assert_eq!(
        stored.timestamp_micros(),
        expected.timestamp_micros(),
        "a non-promoting update must not move expires_at"
    );
}

/// The append-and-archive supersede path shares the coupling: a mid→long
/// supersede mints a FRESH row (the insert ON CONFLICT long⇒NULL arm never
/// fires for it), so the guard must clear the inherited TTL.
#[test]
fn fbl01_supersede_tier_long_clears_inherited_expiry() {
    let conn = fresh_sqlite();
    let stale = (chrono::Utc::now() - chrono::Duration::minutes(30)).to_rfc3339();
    let id = seed(&conn, "fbl01-d", Tier::Mid, Some(&stale));

    let result = db::update_with_archive_on_supersede(
        &conn,
        &id,
        None,
        Some("superseding content"),
        Some(&Tier::Long),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        ai_memory::models::EditSource::Llm,
    )
    .expect("supersede succeeds");

    let (tier, expiry) = row_tier_and_expiry(&conn, &result.new_id);
    assert_eq!(tier, "long");
    assert_eq!(
        expiry, None,
        "supersede to long must not inherit the OLD row's live TTL"
    );
}

// ─────────────────────────────────────────────────────────────────────
// #2332 (FBL-02)
// ─────────────────────────────────────────────────────────────────────

fn stored_expiry(conn: &Connection, id: &str) -> Option<String> {
    conn.query_row(
        "SELECT expires_at FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get(0),
    )
    .expect("row present")
}

/// A FUTURE expiry supplied in a negative-offset RFC3339 rendering sorts
/// lexicographically BELOW a UTC-rendered `now` (the pre-fix premature-GC
/// shape). The insert funnel must canonicalize it to the fixed-UTC form so
/// the same instant survives gc() and the byte order is chronological.
#[test]
fn fbl02_insert_canonicalizes_offset_expiry_and_gc_does_not_reap() {
    let conn = fresh_sqlite();
    let future = chrono::Utc::now() + chrono::Duration::hours(4);
    let offset = chrono::FixedOffset::west_opt(5 * 3600).expect("offset");
    let rendered = future.with_timezone(&offset).to_rfc3339();
    let id = seed(&conn, "fbl02-a", Tier::Mid, Some(&rendered));

    let stored = stored_expiry(&conn, &id).expect("expiry stored");
    assert!(
        stored.ends_with('Z'),
        "stored expiry must be the canonical fixed-UTC rendering, got {stored}"
    );
    let stored_dt = chrono::DateTime::parse_from_rfc3339(&stored).expect("parseable");
    assert_eq!(
        stored_dt.timestamp_micros(),
        future.timestamp_micros(),
        "canonicalization must preserve the instant"
    );

    db::gc(&conn, true).expect("gc runs");
    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        live, 1,
        "a 4h-in-the-future expiry must not be reaped just because its \
         offset rendering byte-sorts below now"
    );
}

/// The inverse hazard: an EXPIRED instant in a positive-offset rendering
/// byte-sorts ABOVE `now` (pre-fix over-retention). Canonicalized, gc()
/// reaps it on schedule.
#[test]
fn fbl02_insert_canonicalizes_positive_offset_expired_row_so_gc_reaps() {
    let conn = fresh_sqlite();
    let past = chrono::Utc::now() - chrono::Duration::hours(4);
    let offset = chrono::FixedOffset::east_opt(9 * 3600).expect("offset");
    let rendered = past.with_timezone(&offset).to_rfc3339();
    let id = seed(&conn, "fbl02-b", Tier::Short, Some(&rendered));

    db::gc(&conn, true).expect("gc runs");
    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        live, 0,
        "an expired row must be reaped even when its +09:00 rendering \
         byte-sorts above now"
    );
}

/// The optimistic-update funnel canonicalizes a caller-patched offset
/// rendering too.
#[test]
fn fbl02_update_patch_canonicalizes_offset_expiry() {
    let conn = fresh_sqlite();
    let id = seed(&conn, "fbl02-c", Tier::Mid, None);
    let future = chrono::Utc::now() + chrono::Duration::days(2);
    let offset = chrono::FixedOffset::west_opt(3 * 3600).expect("offset");
    let rendered = future.with_timezone(&offset).to_rfc3339();

    db::update_with_expected_version(
        &conn,
        &id,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&rendered),
        None,
        None,
        None,
        None,
    )
    .expect("update succeeds");

    let stored = stored_expiry(&conn, &id).expect("expiry stored");
    assert!(stored.ends_with('Z'), "canonical rendering, got {stored}");
    let stored_dt = chrono::DateTime::parse_from_rfc3339(&stored).expect("parseable");
    assert_eq!(stored_dt.timestamp_micros(), future.timestamp_micros());
}

/// The federation-receive funnel (`insert_if_newer`) canonicalizes a
/// peer-supplied offset rendering.
#[test]
fn fbl02_insert_if_newer_canonicalizes_offset_expiry() {
    let conn = fresh_sqlite();
    let future = chrono::Utc::now() + chrono::Duration::hours(6);
    let offset = chrono::FixedOffset::west_opt(7 * 3600).expect("offset");
    let mem = Memory {
        id: "fbl02-d".to_string(),
        tier: Tier::Mid,
        namespace: "storage-chain".to_string(),
        title: "fed offset expiry".to_string(),
        content: "peer row".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        expires_at: Some(future.with_timezone(&offset).to_rfc3339()),
        metadata: json!({}),
        ..Memory::default()
    };
    let id = db::insert_if_newer(&conn, &mem).expect("federation insert");

    let stored = stored_expiry(&conn, &id).expect("expiry stored");
    assert!(stored.ends_with('Z'), "canonical rendering, got {stored}");
    let stored_dt = chrono::DateTime::parse_from_rfc3339(&stored).expect("parseable");
    assert_eq!(stored_dt.timestamp_micros(), future.timestamp_micros());
}
