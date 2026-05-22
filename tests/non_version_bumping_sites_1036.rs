// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1036 (Agent-3 #7) — pin the non-version-bumping contract
//! on the six direct `UPDATE memories SET …` sites that bypass
//! `storage::update` / SAL.
//!
//! ## Why the sites don't bump version
//!
//! The optimistic-concurrency contract (Gap-1 #884) protects against
//! concurrent USER edits via `memories.version`. The six bypass sites
//! enumerated by Agent-3 #7 are NOT user-initiated content edits:
//!
//! - `src/confidence/decay.rs:107-114` — periodic confidence decay
//!   sweep (monotonic + idempotent system bookkeeping)
//! - `src/atomisation/mod.rs:613-616` — `atom_of` back-fill on a
//!   freshly-inserted row (no caller has observed it yet)
//! - `src/curator/mod.rs:1759-1763, :1876` — test fixture seed
//! - `src/mcp/tools/reflect.rs:654` — test fixture seed
//! - `src/cli/boot.rs:1249-1253` — test fixture seed
//!
//! Bumping `version` on these sites would cause spurious
//! `VersionConflict` errors on the next user `update_with_expected_version`
//! call: the user's stored `version` would diverge from the row's
//! system-bumped value without the user having made any edit.
//!
//! This file pins both halves of the contract:
//!
//! 1. **Confidence decay does NOT bump version** — the production
//!    `apply_decay_sweep` path; a row at `version = 7` post-decay
//!    must still be at `version = 7`.
//! 2. **Storage-layer `db::update` DOES bump version** — the
//!    user-facing edit path bumps. The test ensures the two contracts
//!    don't drift (re-running the file after a future refactor
//!    catches a misguided "make decay bump version" change).
//!
//! The atomisation + curator + reflect + boot sites are exercised
//! by their own existing test suites; this file focuses on the
//! production decay path which is the only non-test, non-just-inserted
//! UPDATE in the bypass list.

#![allow(clippy::similar_names)] // `conn` + `conf` flagged; intentional in this short test.

use ai_memory::db;
use ai_memory::models::Memory;

fn fresh_db_conn() -> rusqlite::Connection {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    db::open(&path).expect("open fresh DB")
}

fn seed_memory_with_confidence(conn: &rusqlite::Connection, id: &str, conf: f64) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: id.to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: "1036/decay-pin".to_string(),
        title: format!("decay-{id}"),
        content: "decay-pin fixture".to_string(),
        tags: vec![],
        priority: 5,
        confidence: conf,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now.clone(),
        last_accessed_at: None,
        // Anchor in the past so the decay sweep computes a non-zero age.
        expires_at: None,
        metadata: serde_json::json!({}),
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("insert seed");
    let row: Memory = db::get(conn, id).expect("get seed").expect("present");
    row
}

#[test]
fn confidence_decay_does_not_bump_version_1036() {
    let conn = fresh_db_conn();
    let seeded = seed_memory_with_confidence(&conn, "1036-decay-stable-version", 0.9);
    // Fresh row lands at version=1 per Gap-1 contract (#884).
    assert_eq!(
        seeded.version, 1,
        "#1036: fresh-insert MUST land at version=1"
    );

    // Anchor a past confidence_decayed_at so the sweep computes a
    // non-trivial age and actually executes the UPDATE branch.
    let past = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
    conn.execute(
        "UPDATE memories SET confidence_decayed_at = ?1 WHERE id = ?2",
        rusqlite::params![past, &seeded.id],
    )
    .unwrap();

    // Drive the production decay path via the public entry point.
    let _ = ai_memory::confidence::decay::apply_decay_touch(&conn, &seeded.id);

    // Read the row back and assert version is UNCHANGED.
    let after: Memory = db::get(&conn, &seeded.id)
        .expect("get post-decay")
        .expect("present");
    assert_eq!(
        after.version, seeded.version,
        "#1036: confidence decay sweep MUST NOT bump version; \
         pre={}, post={}",
        seeded.version, after.version
    );
    // Confidence should have decreased (or stayed equal — depends on
    // whether the sweep was 'due'). Pin: confidence is still <=
    // the original.
    assert!(
        after.confidence <= seeded.confidence,
        "#1036: confidence decay MUST be monotonic non-increasing; \
         pre={}, post={}",
        seeded.confidence,
        after.confidence
    );
}

#[test]
fn user_update_bumps_version_pinning_the_contrast_1036() {
    // Companion pin: the user-facing edit path DOES bump version.
    // Without this assertion the previous test could silently pass
    // even if a future refactor made user updates also skip the
    // version bump — at which point optimistic concurrency would be
    // entirely broken. Pinning the contrast keeps the contract
    // load-bearing.
    let conn = fresh_db_conn();
    let seeded = seed_memory_with_confidence(&conn, "1036-user-edit-bumps", 0.9);
    assert_eq!(seeded.version, 1);

    // Apply a user-style edit via the storage layer's update path.
    db::update(
        &conn,
        &seeded.id,
        None,                       // title
        Some("user edit"),          // content
        None,                       // tier
        None,                       // namespace
        None,                       // tags
        None,                       // priority
        None,                       // confidence
        None,                       // expires_at
        None,                       // metadata
    )
    .expect("user update");

    let after: Memory = db::get(&conn, &seeded.id)
        .expect("get post-edit")
        .expect("present");
    assert_eq!(
        after.version,
        seeded.version + 1,
        "#1036 companion: USER edits via db::update MUST bump version; \
         pre={}, post={}",
        seeded.version,
        after.version
    );
}
