// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::missing_panics_doc, clippy::too_many_lines)]
#![cfg(feature = "sal")]

//! #3181 — the sqlite SAL adapter silently inherited trait defaults that do
//! not meet the contracts their docblocks state.
//!
//! `MemoryStore::store_batch`'s docblock says the batch "is atomic (all rows
//! commit or none do)" and that "SQLite inherits it unchanged". SQLite had NO
//! override, so it inherited the DEFAULT — a per-row `self.store()` loop in
//! autocommit — and a mid-batch failure left a COMMITTED PREFIX durable while
//! returning only `Err`, with no way for the caller to learn how far the batch
//! got. postgres wrapped the whole batch in one transaction.
//!
//! Same family: `set_embeddings_batch` looped `update_embedding` and
//! incremented `written` unconditionally, so an id that vanished between the
//! scan and the write was counted as a GHOST write; and `check_memory_quota`'s
//! no-op default meant a trait-routed sqlite caller got NO quota gate at all
//! while the postgres twin enforced one.
//!
//! **R-203.** Parent behaviour per cell:
//!
//! | cell | parent behaviour |
//! |---|---|
//! | `sqlite_store_batch_is_all_or_nothing_3181` | rows 1-2 COMMITTED after the row-3 failure |
//! | `sqlite_store_batch_recovers_after_a_failed_batch_3181` | (control) |
//! | `sqlite_store_batch_intrabatch_duplicate_is_last_wins_3181` | (control — the #2551 contract must survive the override) |
//! | `sqlite_set_embeddings_batch_does_not_count_ghost_ids_3181` | `written == 2` for 1 real row |
//! | `sqlite_check_memory_quota_enforces_the_cap_3181` | `Ok(())` — no gate at all |

use std::path::PathBuf;

use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};
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

fn live_count(path: &std::path::Path, ns: &str) -> i64 {
    let conn = ai_memory::db::open(path).expect("reopen");
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
        rusqlite::params![ns],
        |r| r.get(0),
    )
    .expect("count")
}

// ─────────────────────────────────────────────────────────────────────
// #3181 — store_batch atomicity.
// ─────────────────────────────────────────────────────────────────────

const NS_BATCH: &str = "parity/3181/batch";
const POISON_TITLE: &str = "row-3-poison";

/// Install a fault on exactly one row of the batch: a `BEFORE INSERT` trigger
/// that aborts on one title. This is the substrate-level equivalent of the
/// mid-batch failure a real deployment hits (constraint violation, disk error,
/// a governance trigger) and it is what makes "committed prefix" observable.
fn arm_row_3_fault(path: &std::path::Path) {
    let conn = ai_memory::db::open(path).expect("reopen to arm fault");
    conn.execute_batch(&format!(
        "CREATE TRIGGER parity_3181_poison BEFORE INSERT ON memories \
         WHEN NEW.title = '{POISON_TITLE}' \
         BEGIN SELECT RAISE(ABORT, 'parity-3181 injected mid-batch failure'); END;"
    ))
    .expect("arm trigger");
}

#[tokio::test]
async fn sqlite_store_batch_is_all_or_nothing_3181() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");
    arm_row_3_fault(&path);

    let rows: Vec<Memory> = (1..=5)
        .map(|i| {
            let title = if i == 3 {
                POISON_TITLE.to_string()
            } else {
                format!("row-{i}")
            };
            memory(NS_BATCH, &title, &format!("content {i}"), "alice")
        })
        .collect();

    let err = store
        .store_batch(&ctx, &rows)
        .await
        .expect_err("row 3 must fail the batch");
    assert!(
        format!("{err}").contains("parity-3181"),
        "the injected failure must surface, got {err}"
    );

    // PRE-FIX: 2 — rows 1 and 2 were durably committed before the failure and
    // the caller had no way to learn how far the batch got.
    assert_eq!(
        live_count(&path, NS_BATCH),
        0,
        "a mid-batch failure must roll the ENTIRE batch back"
    );
}

#[tokio::test]
async fn sqlite_store_batch_recovers_after_a_failed_batch_3181() {
    // CONTROL — the rollback must actually END the transaction. If the failed
    // batch left the connection inside an open tx, this second batch would
    // fail with "cannot start a transaction within a transaction" (or land in
    // a never-committed tx), which is exactly the failure mode a naive
    // BEGIN-without-rollback introduces.
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");
    arm_row_3_fault(&path);

    let bad = vec![memory(NS_BATCH, POISON_TITLE, "boom", "alice")];
    store.store_batch(&ctx, &bad).await.expect_err("poisoned");

    let good: Vec<Memory> = (1..=3)
        .map(|i| memory(NS_BATCH, &format!("ok-{i}"), &format!("body {i}"), "alice"))
        .collect();
    let ids = store
        .store_batch(&ctx, &good)
        .await
        .expect("a later batch must still work");
    assert_eq!(ids.len(), 3);
    assert_eq!(live_count(&path, NS_BATCH), 3);
}

#[tokio::test]
async fn sqlite_store_batch_intrabatch_duplicate_is_last_wins_3181() {
    // CONTROL — the #2551 returned-id contract must survive the override:
    // in-batch `(title, namespace)` duplicates collapse to ONE row, the
    // returned vector stays 1:1 with the input, and the LAST input row's
    // content is what is durable. `handlers::bulk`'s created/updated/deduped
    // ledger is derived from exactly these two properties.
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");

    let ns = "parity/3181/dupe";
    let rows = vec![
        memory(ns, "same-title", "first content", "alice"),
        memory(ns, "same-title", "LAST content", "alice"),
    ];
    let ids = store.store_batch(&ctx, &rows).await.expect("store_batch");
    assert_eq!(ids.len(), 2, "the id vector is 1:1 with the input");
    assert_eq!(ids[0], ids[1], "both inputs map to ONE row");
    assert_eq!(live_count(&path, ns), 1);

    let got = store.get(&ctx, &ids[0]).await.expect("get");
    assert_eq!(
        got.content, "LAST content",
        "the LAST input row's content must be the durable one"
    );
}

// ─────────────────────────────────────────────────────────────────────
// #3181 — set_embeddings_batch honest counts.
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sqlite_set_embeddings_batch_does_not_count_ghost_ids_3181() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");

    let real = store
        .store(&ctx, &memory("parity/3181/emb", "embed-me", "body", "alice"))
        .await
        .expect("store");
    let ghost = uuid::Uuid::new_v4().to_string();
    let space = ai_memory::embeddings::embedding_space_fingerprint("parity-3181-space");

    let entries = vec![
        (real, vec![0.1_f32, 0.2, 0.3, 0.4]),
        (ghost, vec![0.5_f32, 0.6, 0.7, 0.8]),
    ];
    let written = store
        .set_embeddings_batch(&ctx, &entries, &space)
        .await
        .expect("set_embeddings_batch");

    // PRE-FIX: 2 — the default loop counted one write per ENTRY, so a row that
    // vanished between the scan and the write was reported as embedded.
    assert_eq!(
        written, 1,
        "only the row that actually exists may be counted"
    );
}

// ─────────────────────────────────────────────────────────────────────
// #3181 — check_memory_quota is a real gate on sqlite.
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sqlite_check_memory_quota_enforces_the_cap_3181() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");
    let ns = "parity/3181/quota";

    // CONTROL — a single row is under every default cap.
    store
        .check_memory_quota(&ctx, ns, 1, 1)
        .await
        .expect("one row is under the cap");

    // PRE-FIX: `Ok(())` — the trait default was a silent no-op, so a
    // trait-routed sqlite caller had NO quota gate at all.
    let over = i64::from(u32::MAX);
    match store.check_memory_quota(&ctx, ns, over, 0).await {
        Err(StoreError::QuotaExceeded { limit, .. }) => {
            assert_eq!(limit, "memories_per_day");
        }
        other => panic!("an over-cap batch must be refused, got {other:?}"),
    }
    match store.check_memory_quota(&ctx, ns, 0, i64::MAX / 2).await {
        Err(StoreError::QuotaExceeded { limit, .. }) => {
            assert_eq!(limit, "storage_bytes");
        }
        other => panic!("an over-cap byte charge must be refused, got {other:?}"),
    }

    // CONTROL — an empty/anonymous principal stays UNCHARGED, mirroring both
    // the postgres twin and the sqlite handler's skip-on-empty.
    let anon = CallerContext::for_agent("");
    store
        .check_memory_quota(&anon, ns, over, 0)
        .await
        .expect("an unidentified caller is uncharged");
}
