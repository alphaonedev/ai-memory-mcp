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
    assert_eq!(
        expiry.as_deref(),
        Some(future.as_str()),
        "a non-promoting update must not touch expires_at"
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
