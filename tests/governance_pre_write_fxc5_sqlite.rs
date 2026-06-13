// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! FX-C5 — SQLite-side governance pre-write hook coverage for the
//! supersede / consolidate / archive-restore / reflect paths.
//!
//! The FX-2 fix (ARCH-1 closeout, 2026-05-25) wired
//! `consult_governance_pre_write_pg` into the 3 primary postgres
//! insert sites (`store`, `store_with_embedding`,
//! `apply_remote_memory`). The FX-C5 follow-up extended hook coverage
//! to the four substrate write paths that bypass those primary entry
//! points by issuing raw `INSERT INTO memories` statements directly:
//!
//! * `update_with_archive_on_supersede` — append-and-archive write
//!   used by MCP `memory_update` when `edit_source` is `llm` or
//!   `hook`. Pre-FX-C5 the SQLite path called `db::insert(..)` at the
//!   tail (which DID consult the hook), but only AFTER the archive
//!   step had already destroyed the OLD live row. A refusal at the
//!   tail therefore left the substrate in a half-applied state. The
//!   fix hoists the hook consult to BEFORE the archive step.
//!
//! * `consolidate` — mints a fresh consolidated memory via a raw
//!   INSERT that bypasses `db::insert(..)`. Pre-FX-C5 the hook never
//!   fired, so an operator's signed governance rule could be
//!   bypassed by routing through the consolidate surface.
//!
//! * `restore_archived` / `restore_archived_for_caller` — mint a
//!   fresh live row from an archived row via INSERT...SELECT, again
//!   bypassing `db::insert(..)`. Pre-FX-C5 a refused namespace could
//!   accept restored rows that a direct write would have refused.
//!
//! * `reflect_with_hooks` (SQLite path) — already covered via the
//!   `insert_with_conflict(.., ConflictMode::Error)` tail (which
//!   consults the hook). Test included here for completeness +
//!   regression-pin parity with the postgres side.
//!
//! All tests in this file share a single process-wide hook closure
//! (OnceLock constraint) and use a per-test serialization mutex to
//! coordinate the shared verdict slot.

#![allow(
    clippy::needless_update,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc
)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, EditSource, Memory, MemoryKind, Tier};
use ai_memory::storage::{self, GovernanceRefusal};

mod common;
use common::fresh_conn;

// ---------------------------------------------------------------------------
// Process-wide dispatcher (mirror governance_storage_insert_hook.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum HookMode {
    Allow,
    Refuse(String),
}

static HOOK_MODE: OnceLock<Mutex<HookMode>> = OnceLock::new();
static HOOK_FIRE_COUNT: OnceLock<AtomicU64> = OnceLock::new();

fn hook_mode_slot() -> &'static Mutex<HookMode> {
    HOOK_MODE.get_or_init(|| Mutex::new(HookMode::Allow))
}

fn hook_fire_count() -> &'static AtomicU64 {
    HOOK_FIRE_COUNT.get_or_init(|| AtomicU64::new(0))
}

fn test_serial() -> &'static Mutex<()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
}

fn ensure_hook_installed() {
    let _ = storage::GOVERNANCE_PRE_WRITE.set(Box::new(|_mem: &Memory| {
        hook_fire_count().fetch_add(1, Ordering::SeqCst);
        let guard = hook_mode_slot().lock().expect("hook mode mutex poisoned");
        match &*guard {
            HookMode::Allow => Ok(()),
            HookMode::Refuse(reason) => Err(reason.clone()),
        }
    }));
}

fn set_mode(mode: HookMode) {
    *hook_mode_slot().lock().expect("hook mode mutex poisoned") = mode;
}

fn reset_fire_count() -> u64 {
    hook_fire_count().swap(0, Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Sample-memory factory
// ---------------------------------------------------------------------------

fn fresh_memory(title: &str, ns: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: "fxc5 body".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "system".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": "ai:fxc5"}),
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

// ---------------------------------------------------------------------------
// 1. update_with_archive_on_supersede
// ---------------------------------------------------------------------------

#[test]
fn supersede_fires_hook_on_allow() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ensure_hook_installed();
    set_mode(HookMode::Allow);
    let _ = reset_fire_count();

    let conn = fresh_conn();
    let seed = fresh_memory("supersede-allow", "fxc5/supersede");
    let seed_id = db::insert(&conn, &seed).expect("seed insert");
    let _ = reset_fire_count();

    let result = db::update_with_archive_on_supersede(
        &conn,
        &seed_id,
        Some("supersede-allow-new"),
        Some("patched body"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        EditSource::Llm,
    )
    .expect("Allow verdict must let supersede succeed");

    assert_ne!(result.new_id, seed_id, "supersede produces a new id");
    let fires = hook_fire_count().load(Ordering::SeqCst);
    assert!(
        fires >= 1,
        "GOVERNANCE_PRE_WRITE hook MUST fire on update_with_archive_on_supersede; observed {fires}"
    );

    // OLD row archived, NEW row present.
    let new_row = db::get(&conn, &result.new_id)
        .expect("get new row")
        .expect("new row exists");
    assert_eq!(new_row.title, "supersede-allow-new");
    assert!(
        db::get(&conn, &seed_id).expect("get old").is_none(),
        "OLD row should be archived (not in live table)"
    );
}

#[test]
fn supersede_refusal_short_circuits_before_archive() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ensure_hook_installed();
    set_mode(HookMode::Allow);
    let _ = reset_fire_count();

    let conn = fresh_conn();
    let seed = fresh_memory("supersede-refuse", "fxc5/supersede-refuse");
    let seed_id = db::insert(&conn, &seed).expect("seed insert");

    set_mode(HookMode::Refuse("fxc5 supersede deny".to_string()));
    let _ = reset_fire_count();

    let err = db::update_with_archive_on_supersede(
        &conn,
        &seed_id,
        Some("would-not-land"),
        Some("blocked body"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        EditSource::Llm,
    )
    .expect_err("Refuse verdict MUST short-circuit supersede");
    assert!(
        err.downcast_ref::<GovernanceRefusal>().is_some(),
        "refusal must surface as GovernanceRefusal; got: {err}"
    );

    let fires = hook_fire_count().load(Ordering::SeqCst);
    assert!(fires >= 1, "hook MUST fire on supersede; observed {fires}");

    // FX-C5 atomicity guarantee: the OLD row MUST still be live (not
    // archived), since the hook fires BEFORE the archive step. Pre-fix
    // the SQLite path archived the OLD row first then called
    // db::insert(..) which only THEN consulted the hook — leaving the
    // substrate without the OLD row on refusal.
    let still_live = db::get(&conn, &seed_id)
        .expect("get")
        .expect("OLD must still live");
    assert_eq!(still_live.title, "supersede-refuse");

    set_mode(HookMode::Allow);
}

// ---------------------------------------------------------------------------
// 2. consolidate
// ---------------------------------------------------------------------------

#[test]
fn consolidate_fires_hook_on_allow() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ensure_hook_installed();
    set_mode(HookMode::Allow);
    let _ = reset_fire_count();

    let conn = fresh_conn();
    let a = fresh_memory("cons-src-a", "fxc5/cons-allow");
    let b = fresh_memory("cons-src-b", "fxc5/cons-allow");
    let id_a = db::insert(&conn, &a).expect("seed a");
    let id_b = db::insert(&conn, &b).expect("seed b");
    let _ = reset_fire_count();

    let new_id = db::consolidate(
        &conn,
        &[id_a.clone(), id_b.clone()],
        "consolidated-allow",
        "merged summary",
        "fxc5/cons-allow",
        &Tier::Long,
        "test",
        "ai:fxc5-consolidator",
    )
    .expect("Allow verdict must let consolidate succeed");

    assert!(!new_id.is_empty());
    let fires = hook_fire_count().load(Ordering::SeqCst);
    assert!(
        fires >= 1,
        "GOVERNANCE_PRE_WRITE hook MUST fire on consolidate; observed {fires}"
    );

    // Sources deleted, new row present.
    assert!(db::get(&conn, &id_a).unwrap().is_none());
    assert!(db::get(&conn, &id_b).unwrap().is_none());
    assert!(db::get(&conn, &new_id).unwrap().is_some());
}

#[test]
fn consolidate_refusal_blocks_insert_and_preserves_sources() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ensure_hook_installed();
    set_mode(HookMode::Allow);
    let _ = reset_fire_count();

    let conn = fresh_conn();
    let a = fresh_memory("cons-src-a", "fxc5/cons-refuse");
    let b = fresh_memory("cons-src-b", "fxc5/cons-refuse");
    let id_a = db::insert(&conn, &a).expect("seed a");
    let id_b = db::insert(&conn, &b).expect("seed b");

    set_mode(HookMode::Refuse("fxc5 consolidate deny".to_string()));
    let _ = reset_fire_count();

    let err = db::consolidate(
        &conn,
        &[id_a.clone(), id_b.clone()],
        "would-not-land",
        "blocked summary",
        "fxc5/cons-refuse",
        &Tier::Long,
        "test",
        "ai:fxc5-refuse",
    )
    .expect_err("Refuse verdict MUST short-circuit consolidate");
    assert!(
        err.downcast_ref::<GovernanceRefusal>().is_some(),
        "refusal must surface as GovernanceRefusal; got: {err}"
    );

    let fires = hook_fire_count().load(Ordering::SeqCst);
    assert!(
        fires >= 1,
        "hook MUST fire on consolidate; observed {fires}"
    );

    // FX-C5 atomicity: source rows MUST remain. Pre-fix the hook
    // never fired so this test couldn't probe the gap; the regression
    // catch is that the source rows are NOT deleted on refusal.
    assert!(db::get(&conn, &id_a).unwrap().is_some(), "src a preserved");
    assert!(db::get(&conn, &id_b).unwrap().is_some(), "src b preserved");

    set_mode(HookMode::Allow);
}

// ---------------------------------------------------------------------------
// 3. restore_archived
// ---------------------------------------------------------------------------

#[test]
fn restore_archived_fires_hook_on_allow() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ensure_hook_installed();
    set_mode(HookMode::Allow);
    let _ = reset_fire_count();

    let conn = fresh_conn();
    let mem = fresh_memory("restore-allow", "fxc5/restore-allow");
    let id = db::insert(&conn, &mem).expect("seed insert");
    let moved = db::archive_memory(&conn, &id, Some("test")).expect("archive");
    assert!(moved);
    let _ = reset_fire_count();

    let restored = db::restore_archived(&conn, &id).expect("Allow lets restore proceed");
    assert!(restored);

    let fires = hook_fire_count().load(Ordering::SeqCst);
    assert!(
        fires >= 1,
        "GOVERNANCE_PRE_WRITE hook MUST fire on restore_archived; observed {fires}"
    );

    assert!(db::get(&conn, &id).unwrap().is_some(), "row restored");
}

#[test]
fn restore_archived_refusal_blocks_insert_and_preserves_archive() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ensure_hook_installed();
    set_mode(HookMode::Allow);
    let _ = reset_fire_count();

    let conn = fresh_conn();
    let mem = fresh_memory("restore-refuse", "fxc5/restore-refuse");
    let id = db::insert(&conn, &mem).expect("seed insert");
    let moved = db::archive_memory(&conn, &id, Some("test")).expect("archive");
    assert!(moved);

    set_mode(HookMode::Refuse("fxc5 restore deny".to_string()));
    let _ = reset_fire_count();

    let err = db::restore_archived(&conn, &id).expect_err("Refuse verdict MUST block restore");
    assert!(
        err.downcast_ref::<GovernanceRefusal>().is_some(),
        "refusal must surface as GovernanceRefusal; got: {err}"
    );

    let fires = hook_fire_count().load(Ordering::SeqCst);
    assert!(
        fires >= 1,
        "hook MUST fire on restore_archived; observed {fires}"
    );

    // FX-C5 atomicity: archived row remains, live row does NOT exist.
    let archived_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(archived_count, 1, "archived row preserved on refusal");
    assert!(db::get(&conn, &id).unwrap().is_none(), "no live row");

    set_mode(HookMode::Allow);
}

// ---------------------------------------------------------------------------
// 4. reflect_with_hooks (SQLite path) — coverage parity
//
// The SQLite reflect path already consults the hook via
// `insert_with_conflict(.., ConflictMode::Error)` (which calls
// `consult_governance_pre_write` at its head). Pin the contract.
// ---------------------------------------------------------------------------

#[test]
fn reflect_fires_hook_and_refuses() {
    use ai_memory::db::{ReflectError, ReflectHooks, ReflectInput, reflect_with_hooks};
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ensure_hook_installed();
    set_mode(HookMode::Allow);
    let _ = reset_fire_count();

    let conn = fresh_conn();
    let src = fresh_memory("reflect-src", "fxc5/reflect-refuse");
    let src_id = db::insert(&conn, &src).expect("seed insert");

    set_mode(HookMode::Refuse("fxc5 reflect deny".to_string()));
    let _ = reset_fire_count();

    let input = ReflectInput {
        source_ids: vec![src_id.clone()],
        title: "reflect-refuse".to_string(),
        content: "reflection body".to_string(),
        tier: Tier::Long,
        namespace: Some("fxc5/reflect-refuse".to_string()),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "system".to_string(),
        agent_id: "ai:fxc5-reflect".to_string(),
        metadata: serde_json::json!({}),
    };

    let err = reflect_with_hooks(&conn, &input, &ReflectHooks::empty())
        .expect_err("Refuse verdict MUST short-circuit reflect");
    // SQLite reflect routes the substrate hook refusal through
    // insert_with_conflict, which surfaces it as ReflectError::Validation
    // (the ConflictMode::Error branch wraps the error; the substrate
    // hook refusal is a non-conflict error so it lands on the
    // Database arm). Either Database or Validation is acceptable —
    // the substrate-side guarantee is that no row landed.
    match &err {
        ReflectError::Validation(m) | ReflectError::Database(m) => {
            assert!(
                m.contains("fxc5 reflect deny") || m.to_lowercase().contains("governance"),
                "refusal text must propagate; got: {m}"
            );
        }
        ReflectError::HookVeto { reason, .. } => {
            assert!(
                reason.contains("fxc5 reflect deny"),
                "refusal text must propagate; got: {reason}"
            );
        }
        other => panic!("expected Validation/Database/HookVeto; got {other:?}"),
    }

    let fires = hook_fire_count().load(Ordering::SeqCst);
    assert!(fires >= 1, "hook MUST fire on reflect; observed {fires}");

    // No row landed under the reflection title.
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = 'reflect-refuse'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0, "refused reflect must not write");

    set_mode(HookMode::Allow);
}
