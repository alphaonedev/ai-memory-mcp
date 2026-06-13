// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
#![allow(clippy::too_many_lines)]

//! Regression coverage for #1451 (SEC, HIGH) — the optimistic-update
//! path (`storage::update` / `update_with_expected_version`) MUST
//! consult the `GOVERNANCE_PRE_WRITE` hook on the POST-MERGE row, just
//! like the insert / supersede / consolidate / restore paths.
//!
//! Before the fix, `memory_update` skipped the hook entirely, so a
//! refuse rule was trivially evaded: store benign content (gated), then
//! update it into the refused namespace / tier / content (un-gated).
//!
//! These tests install a process-wide dispatcher (the hook is a
//! set-once `OnceLock`; this integration binary gets its own fresh
//! one) that refuses when the merged row's namespace OR content carries
//! a sentinel. That proves the hook sees the *new* (merged) values, not
//! the pre-update row.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::storage::{self, GovernanceRefusal};

mod common;
use common::fresh_conn;

static HOOK_FIRE_COUNT: OnceLock<AtomicU64> = OnceLock::new();

fn hook_fire_count() -> &'static AtomicU64 {
    HOOK_FIRE_COUNT.get_or_init(|| AtomicU64::new(0))
}

fn test_serial() -> &'static Mutex<()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
}

/// Refuse when the merged row's namespace or content carries the
/// sentinel `FORBIDDEN`. Installed once per process.
fn ensure_hook_installed() {
    let _ = storage::GOVERNANCE_PRE_WRITE.set(Box::new(|mem: &Memory| {
        hook_fire_count().fetch_add(1, Ordering::SeqCst);
        if mem.namespace.contains("FORBIDDEN") {
            return Err(format!("namespace refused: {}", mem.namespace));
        }
        if mem.content.contains("FORBIDDEN") {
            return Err("content refused".to_string());
        }
        Ok(())
    }));
}

fn fresh_memory(title: &str, ns: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({}),
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

/// Update that mutates content into the refused shape must be refused,
/// with the row left byte-for-byte unchanged (the hook fires BEFORE the
/// SQL UPDATE, so no mutation lands).
#[test]
fn update_into_refused_content_is_gated_and_row_unchanged() {
    let _g = test_serial().lock().unwrap();
    ensure_hook_installed();

    let conn = fresh_conn();
    let mem = fresh_memory("benign", "test/ok", "all good");
    let id = db::insert(&conn, &mem).expect("benign insert must pass the gate");

    let before = hook_fire_count().load(Ordering::SeqCst);
    let err = db::update(
        &conn,
        &id,
        None,
        Some("now FORBIDDEN content"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect_err("update into refused content MUST be refused");
    let after = hook_fire_count().load(Ordering::SeqCst);
    assert!(after > before, "the hook MUST fire on the update path");

    let refusal = err
        .downcast_ref::<GovernanceRefusal>()
        .expect("update refusal must wrap GovernanceRefusal");
    assert_eq!(refusal.reason, "content refused");

    // Row unchanged: content still the original, version not bumped.
    let row = db::get(&conn, &id).unwrap().expect("row must still exist");
    assert_eq!(row.content, "all good", "refused update must not mutate");
    assert_eq!(row.version, 1, "refused update must not bump version");
}

/// Update that retargets the namespace into the refused subtree is
/// gated on the MERGED namespace (proves the hook sees the new value).
#[test]
fn update_into_refused_namespace_is_gated() {
    let _g = test_serial().lock().unwrap();
    ensure_hook_installed();

    let conn = fresh_conn();
    let mem = fresh_memory("benign-ns", "test/ok2", "fine");
    let id = db::insert(&conn, &mem).expect("benign insert must pass");

    let err = db::update(
        &conn,
        &id,
        None,
        None,
        None,
        Some("FORBIDDEN/zone"),
        None,
        None,
        None,
        None,
        None,
    )
    .expect_err("update retargeting into a refused namespace MUST be refused");
    let refusal = err
        .downcast_ref::<GovernanceRefusal>()
        .expect("must wrap GovernanceRefusal");
    assert!(refusal.reason.contains("namespace refused"));

    let row = db::get(&conn, &id).unwrap().expect("row exists");
    assert_eq!(row.namespace, "test/ok2", "namespace must be unchanged");
}

/// An allowed update still succeeds and the mutation lands — the gate
/// is not a blanket denial.
#[test]
fn allowed_update_passes_through_and_mutates() {
    let _g = test_serial().lock().unwrap();
    ensure_hook_installed();

    let conn = fresh_conn();
    let mem = fresh_memory("benign-allow", "test/ok3", "v1");
    let id = db::insert(&conn, &mem).expect("insert must pass");

    let (updated, _) = db::update(
        &conn,
        &id,
        Some("benign-allow-2"),
        Some("v2 still clean"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("clean update must pass the gate");
    assert!(updated, "update must report a row changed");

    let row = db::get(&conn, &id).unwrap().expect("row exists");
    assert_eq!(row.content, "v2 still clean");
    assert_eq!(row.title, "benign-allow-2");
    assert_eq!(row.version, 2, "allowed update bumps version");
}
