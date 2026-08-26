// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]
#![cfg(feature = "sal")]

//! #3182 — four sqlite reads turned a substrate fault into a benign answer.
//!
//! `is_registered_agent` ended in `.is_ok()`, `agent_max_created_at` in
//! `.unwrap_or(None)`, `schema_version` in `.unwrap_or(0)` and
//! `storage::get_embedding` in `.ok()`. Each collapsed EVERY rusqlite failure
//! — dropped table, missing migration, lock failure, corruption — into a
//! plausible value that is indistinguishable from a legitimate negative
//! result, while the postgres twins all propagate.
//!
//! `schema_version` is the most dangerous of the four: `0` is a
//! migration-ladder INPUT, so a populated-but-damaged database presented
//! itself as FRESH.
//!
//! The scout fold-in on the issue adds `db::find_by_title_namespace`, whose
//! `.ok()` made a fault read as "no such (title, namespace)" on the
//! DEDUPLICATION probe every `on_conflict` caller trusts — while its own
//! doc claimed it "returns the underlying SQLite error".
//!
//! The fifth site in this class, `agent_pubkey`, is #3145 and is deliberately
//! not touched here. `auto_detect_parent` (the other scout fold-in) is NOT
//! touched here either: propagating it requires changing
//! `db::get_namespace_standard`, which fans into five governance-policy
//! resolution sites that share the same fail-open shape, and #3188 owns that
//! decision (it must also settle the pg parent-detection contract).
//!
//! **R-203.** Parent behaviour per cell:
//!
//! | cell | parent behaviour |
//! |---|---|
//! | `sqlite_schema_version_propagates_substrate_fault_3182` | `Ok(0)` — a broken DB reports FRESH |
//! | `sqlite_registration_and_watermark_propagate_faults_3182` | `Ok(false)` / `Ok(None)` / `Ok(None)` |
//! | `sqlite_watermark_is_microsecond_normalised_3182` | a nanosecond string postgres can never produce |

use std::path::PathBuf;

use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};
use serde_json::json;

fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before the caller issues any gated write.
    ONCE.call_once(|| unsafe {
        std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
    });
}

/// Hermetic DB path under `.local-runs/` (never `/tmp`, per project rule).
fn fresh_db_path() -> (tempfile::TempDir, PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("sal-parity-3181-3182");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let path = dir.path().join("memories.db");
    (dir, path)
}

fn memory(ns: &str, title: &str, content: &str, owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        priority: 5,
        confidence: 1.0,
        source: "parity-3181".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": owner }),
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    }
}

#[tokio::test]
async fn sqlite_schema_version_propagates_substrate_fault_3182() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");

    // CONTROL — a healthy DB reports its real applied ladder height.
    let healthy = store.schema_version().await.expect("healthy read");
    assert!(healthy > 0, "a migrated DB must report a non-zero ladder");

    {
        let conn = ai_memory::db::open(&path).expect("reopen");
        conn.execute_batch("DROP TABLE schema_version")
            .expect("drop schema_version");
    }

    // PRE-FIX: `Ok(0)` — a DAMAGED, POPULATED database was indistinguishable
    // from a fresh one, and `0` is a migration-ladder input.
    let err = store
        .schema_version()
        .await
        .expect_err("a missing schema_version table must not read as 'fresh'");
    assert!(
        format!("{err}").contains("schema_version"),
        "the error must name the missing table, got {err}"
    );
}

#[tokio::test]
async fn sqlite_registration_and_watermark_propagate_faults_3182() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    // Hold this connection open ACROSS the fault: `db::open` runs migrations,
    // so re-opening after the drop would silently repair the table.
    let raw = ai_memory::db::open(&path).expect("raw conn");
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");

    let id = store
        .store(&ctx, &memory("parity/3182", "seed", "body", "alice"))
        .await
        .expect("store");

    // CONTROL — healthy answers first, so the assertions below cannot pass for
    // the trivial reason that these methods always error.
    assert!(!store.is_registered_agent("nobody").await.expect("healthy"));
    assert!(
        store
            .agent_max_created_at("alice")
            .await
            .expect("healthy")
            .is_some()
    );
    assert!(
        ai_memory::db::get_embedding(&raw, &id)
            .expect("healthy")
            .is_none()
    );

    // `foreign_keys=OFF` for the drop only: with the pragma ON, SQLite runs an
    // implicit delete of the parent rows first, so an unrelated child row
    // would turn this fault injection into a constraint error instead of the
    // missing-table fault the cells below are about.
    raw.execute_batch("PRAGMA foreign_keys=OFF; DROP TABLE memories;")
        .expect("drop memories");

    // PRE-FIX: `Ok(false)` — a dropped table read as "this agent is not
    // registered", which feeds the governance `Registered` level and all three
    // pending-action approver gates.
    store
        .is_registered_agent("alice")
        .await
        .expect_err("a substrate fault must not read as 'not registered'");

    // PRE-FIX: `Ok(None)` — a fault read as "this agent has no watermark",
    // which is what a brand-new agent legitimately returns.
    store
        .agent_max_created_at("alice")
        .await
        .expect_err("a substrate fault must not read as 'no watermark'");

    // PRE-FIX: `Ok(None)` — a fault read as "this memory has no embedding".
    ai_memory::db::get_embedding(&raw, &id)
        .expect_err("a substrate fault must not read as 'no embedding'");
}

#[tokio::test]
async fn sqlite_watermark_is_microsecond_normalised_3182() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");

    // A NANOSECOND-precision stamp: sqlite stores RFC3339 TEXT losslessly,
    // postgres `TIMESTAMPTZ` quantises to microseconds, so the raw column
    // could never be byte-equal across backends.
    let mut mem = memory("parity/3182/wm", "nanos", "body", "alice");
    mem.created_at = "2026-05-06T07:08:09.123456789+00:00".to_string();
    store.store(&ctx, &mem).await.expect("store");

    let wm = store
        .agent_max_created_at("alice")
        .await
        .expect("watermark")
        .expect("some watermark");
    // PRE-FIX: the raw nanosecond string, which the postgres twin can never
    // produce for the same instant.
    assert_eq!(wm, "2026-05-06T07:08:09.123456+00:00");
}

#[tokio::test]
async fn sqlite_find_by_title_namespace_propagates_substrate_fault_3182() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    // Hold the connection open across the fault so `db::open`'s migrations
    // cannot silently repair the dropped table.
    let raw = ai_memory::db::open(&path).expect("raw conn");
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");

    store
        .store(&ctx, &memory("parity/3182/dedup", "seed", "body", "alice"))
        .await
        .expect("store");

    // CONTROL — a healthy DB distinguishes hit from miss.
    assert!(
        ai_memory::db::find_by_title_namespace(&raw, "seed", "parity/3182/dedup")
            .expect("healthy hit")
            .is_some()
    );
    assert!(
        ai_memory::db::find_by_title_namespace(&raw, "absent", "parity/3182/dedup")
            .expect("healthy miss")
            .is_none(),
        "a genuine miss must stay Ok(None)"
    );

    raw.execute_batch("PRAGMA foreign_keys=OFF; DROP TABLE memories;")
        .expect("drop memories");

    // PRE-FIX: `Ok(None)` — indistinguishable from the healthy miss above, so
    // every `on_conflict` caller read it as "safe to insert a new row" and
    // forked a duplicate lineage instead of updating the existing memory.
    ai_memory::db::find_by_title_namespace(&raw, "seed", "parity/3182/dedup")
        .expect_err("a substrate fault must not read as 'no such (title, namespace)'");
}
