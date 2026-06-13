// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Issue #830 → superseded by issue #1596 — short-tier TTL touch
//! semantics.
//!
//! HISTORY: #830 originally pinned the sliding-window **REPLACEMENT**
//! contract (`expires_at = now + SHORT_TTL_EXTEND_SECS` on every
//! access). #1596 found that contract harmful in lived use: a fresh
//! row carrying its create-time backstop (+6h short / +7d mid) had its
//! expiry pulled IN on the very first recall — recalling a memory made
//! it die SOONER (lived evidence: mid row 4c7e7cc1 went 2026-06-18 →
//! 2026-06-12 on first recall). The contract is now an extension
//! FLOOR: `expires_at = MAX(existing, now + per-tier window)` — the
//! per-access window only ever extends, never shortens. This file is
//! updated (per #1596) to pin the NEW contract on the short tier; the
//! mid-tier + batched `touch_many` pins live in
//! `tests/issue_1596_touch_ttl_extension_floor.rs`.

use ai_memory::db;
use ai_memory::models::{
    ConfidenceSource, MID_TTL_EXTEND_SECS, Memory, MemoryKind, SHORT_TTL_EXTEND_SECS, Tier,
    default_metadata,
};
use chrono::{Duration, Utc};

fn make_short_memory(expires_at: Option<String>) -> Memory {
    let now = Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Short,
        namespace: "lifecycle-test".to_string(),
        title: format!("lifecycle-row-{}", uuid::Uuid::new_v4()),
        content: "lifecycle test content".to_string(),
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

/// **Issue #1596** (supersedes the #830 REPLACE pin) — the short-tier
/// touch TTL is an extension floor.
///
/// Scenario A: a short-tier row created with `expires_at = create + 6h`
/// (the documented backstop) is touched once. Pre-#1596 the expiry was
/// REPLACED with `now + 1h` — recalling the row shortened its life by
/// ~5h. Post-#1596 `MAX(existing, now + window)` keeps the later
/// backstop: the expiry must be unchanged (>= the original).
#[test]
fn lifecycle_short_tier_touch_never_shortens_backstop_1596() {
    let conn = db::open(std::path::Path::new(":memory:")).expect("open in-memory db");

    let create_time = Utc::now();
    let backstop_expires_at = (create_time + Duration::hours(6)).to_rfc3339();
    let mem = make_short_memory(Some(backstop_expires_at.clone()));
    let id = db::insert(&conn, &mem).expect("insert short-tier memory");

    db::touch(&conn, &id, SHORT_TTL_EXTEND_SECS, MID_TTL_EXTEND_SECS).expect("touch");

    let post_touch = db::get(&conn, &id).unwrap().unwrap();
    let new_expires_str = post_touch
        .expires_at
        .as_deref()
        .expect("expires_at must still be set on short-tier post-touch");
    // #1596 extension-floor contract: the 6h backstop is LATER than
    // now + 1h, so MAX keeps it byte-identical. Strictly-earlier (the
    // old #830 REPLACE assertion) is the regression this test pins out.
    assert_eq!(
        new_expires_str, backstop_expires_at,
        "touch must not pull a later backstop expiry IN (#1596); \
         the per-access window is a floor, not a replacement"
    );
}

/// **Issue #1596** — the per-access window still EXTENDS a
/// nearly-expired short-tier row (the half of the old sliding-window
/// behaviour worth keeping).
#[test]
fn lifecycle_short_tier_touch_extends_imminent_expiry_1596() {
    let conn = db::open(std::path::Path::new(":memory:")).expect("open in-memory db");

    // Row with only 5 minutes left — well inside the 1h touch window.
    let imminent_expires_at = (Utc::now() + Duration::minutes(5)).to_rfc3339();
    let mem = make_short_memory(Some(imminent_expires_at.clone()));
    let id = db::insert(&conn, &mem).expect("insert short-tier memory");

    let touch_at = Utc::now();
    db::touch(&conn, &id, SHORT_TTL_EXTEND_SECS, MID_TTL_EXTEND_SECS).expect("touch");

    let post_touch = db::get(&conn, &id).unwrap().unwrap();
    let new_expires = chrono::DateTime::parse_from_rfc3339(
        post_touch
            .expires_at
            .as_deref()
            .expect("expires_at must still be set"),
    )
    .expect("expires_at must parse as RFC3339");

    // Expected: ~touch_at + 1h (generous ±5s window for jitter between
    // our `touch_at` sample and the `Utc::now()` inside `touch`).
    let expected = touch_at + Duration::seconds(SHORT_TTL_EXTEND_SECS);
    let drift = (new_expires.with_timezone(&Utc) - expected)
        .num_milliseconds()
        .abs();
    assert!(
        drift < 5_000,
        "post-touch expires_at should be within 5s of touch_at + 1h; drift_ms={drift}"
    );
}
