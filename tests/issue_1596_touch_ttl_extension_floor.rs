// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Issue #1596 — recall touch must never SHORTEN a row's life.
//!
//! Pre-fix, the per-access TTL window REPLACED `expires_at`: a fresh
//! mid-tier row carrying its create-time +7d backstop, recalled once,
//! got `expires_at = now + 1d` — six days EARLIER (lived evidence:
//! row 4c7e7cc1 went 2026-06-18 → 2026-06-12 on first recall). The
//! fix makes the window a pure extension floor inside the touch SQL:
//! `expires_at = MAX(existing, now + per-tier window)`, single batched
//! UPDATE preserved. Long-tier (NULL expiry) stays NULL.
//!
//! The short-tier pins (and the history of the superseded #830
//! REPLACE contract) live in `tests/lifecycle_short_tier_ttl_replace.rs`.

use ai_memory::db;
use ai_memory::models::{
    ConfidenceSource, MID_TTL_EXTEND_SECS, Memory, MemoryKind, SHORT_TTL_EXTEND_SECS, Tier,
    default_metadata,
};
use chrono::{Duration, Utc};

fn make_memory(tier: Tier, expires_at: Option<String>) -> Memory {
    let now = Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier,
        namespace: "ttl-floor-1596".to_string(),
        title: format!("ttl-floor-row-{}", uuid::Uuid::new_v4()),
        content: "issue 1596 regression content".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at,
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
    }
}

fn open_db() -> rusqlite::Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

/// #1596 scenario A — a fresh mid-tier row with the create-time +7d
/// backstop, touched once: `expires_at` must be unchanged (>= the
/// original), NOT pulled in to now+1d.
#[test]
fn issue_1596_mid_tier_touch_keeps_7d_backstop() {
    let conn = open_db();
    let backstop = (Utc::now() + Duration::days(7)).to_rfc3339();
    let id = db::insert(&conn, &make_memory(Tier::Mid, Some(backstop.clone()))).expect("insert");

    db::touch(&conn, &id, SHORT_TTL_EXTEND_SECS, MID_TTL_EXTEND_SECS).expect("touch");

    let post = db::get(&conn, &id).unwrap().unwrap();
    assert_eq!(
        post.expires_at.as_deref(),
        Some(backstop.as_str()),
        "first recall must not shorten a mid row's +7d backstop to +1d (#1596)"
    );
}

/// #1596 scenario B — a mid-tier row about to expire (now+1h) is
/// EXTENDED to ~now+1d by a touch (the window still works as a floor).
#[test]
fn issue_1596_mid_tier_touch_extends_imminent_expiry_to_1d() {
    let conn = open_db();
    let imminent = (Utc::now() + Duration::hours(1)).to_rfc3339();
    let id = db::insert(&conn, &make_memory(Tier::Mid, Some(imminent))).expect("insert");

    let touch_at = Utc::now();
    db::touch(&conn, &id, SHORT_TTL_EXTEND_SECS, MID_TTL_EXTEND_SECS).expect("touch");

    let post = db::get(&conn, &id).unwrap().unwrap();
    let new_expires =
        chrono::DateTime::parse_from_rfc3339(post.expires_at.as_deref().expect("expiry set"))
            .expect("rfc3339");
    let expected = touch_at + Duration::seconds(MID_TTL_EXTEND_SECS);
    let drift = (new_expires.with_timezone(&Utc) - expected)
        .num_milliseconds()
        .abs();
    assert!(
        drift < 5_000,
        "an imminent mid expiry must be extended to ~now+1d; drift_ms={drift}"
    );
}

/// #1596 — the batched `touch_many` (the actual recall path post-#1079)
/// applies the same extension-floor semantics: backstops survive,
/// imminent expiries extend, in one call.
#[test]
fn issue_1596_touch_many_is_extension_floor() {
    let conn = open_db();
    let backstop = (Utc::now() + Duration::days(7)).to_rfc3339();
    let id_backstop =
        db::insert(&conn, &make_memory(Tier::Mid, Some(backstop.clone()))).expect("insert");
    let imminent = (Utc::now() + Duration::hours(1)).to_rfc3339();
    let id_imminent = db::insert(&conn, &make_memory(Tier::Mid, Some(imminent))).expect("insert");

    let touch_at = Utc::now();
    let touched = db::touch_many(
        &conn,
        &[id_backstop.as_str(), id_imminent.as_str()],
        SHORT_TTL_EXTEND_SECS,
        MID_TTL_EXTEND_SECS,
    )
    .expect("touch_many");
    assert_eq!(touched, 2);

    let post_backstop = db::get(&conn, &id_backstop).unwrap().unwrap();
    assert_eq!(
        post_backstop.expires_at.as_deref(),
        Some(backstop.as_str()),
        "touch_many must not shorten the +7d backstop (#1596)"
    );

    let post_imminent = db::get(&conn, &id_imminent).unwrap().unwrap();
    let new_expires = chrono::DateTime::parse_from_rfc3339(
        post_imminent.expires_at.as_deref().expect("expiry set"),
    )
    .expect("rfc3339");
    let expected = touch_at + Duration::seconds(MID_TTL_EXTEND_SECS);
    let drift = (new_expires.with_timezone(&Utc) - expected)
        .num_milliseconds()
        .abs();
    assert!(
        drift < 5_000,
        "touch_many must extend an imminent mid expiry to ~now+1d; drift_ms={drift}"
    );
}

/// #1596 — long-tier rows (NULL expiry) stay NULL through both touch
/// paths; the MAX rewrite must not synthesize an expiry for them.
#[test]
fn issue_1596_long_tier_null_expiry_stays_null() {
    let conn = open_db();
    let id = db::insert(&conn, &make_memory(Tier::Long, None)).expect("insert");

    db::touch(&conn, &id, SHORT_TTL_EXTEND_SECS, MID_TTL_EXTEND_SECS).expect("touch");
    let post = db::get(&conn, &id).unwrap().unwrap();
    assert!(
        post.expires_at.is_none(),
        "long-tier expiry must remain NULL after touch (#1596)"
    );

    db::touch_many(
        &conn,
        &[id.as_str()],
        SHORT_TTL_EXTEND_SECS,
        MID_TTL_EXTEND_SECS,
    )
    .expect("touch_many");
    let post = db::get(&conn, &id).unwrap().unwrap();
    assert!(
        post.expires_at.is_none(),
        "long-tier expiry must remain NULL after touch_many (#1596)"
    );
}
