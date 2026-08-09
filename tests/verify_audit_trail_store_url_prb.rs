// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 pg-parity PR-B (5-agent vote `4d3ea1c5`) — end-to-end tests
//! for `ai-memory verify-audit-trail --store-url postgres://…`.
//!
//! Before PR-B the `verify-audit-trail` verb could only walk the LOCAL
//! sqlite `signed_events` chain, so a postgres fleet had no first-party
//! way to run audit-chain verification. PR-B threads the existing
//! `serve` / `curator` `--store-url` precedent (the #1927 non-argv
//! credential channel plus the argv flag) into the verb and dispatches
//! to the postgres twin
//! [`ai_memory::store::postgres::PostgresStore::verify_audit_trail`],
//! rendering BYTE-FOR-BYTE identically to the sqlite path (GATE K3).
//!
//! ## Coverage
//!
//! 1. **`store_url_flag_absent_uses_sqlite_smoke`** (always runs under
//!    the `sal-postgres` build; needs NO live DB) — proves the PR-B
//!    dispatch refactor still routes the flag-absent case to the local
//!    sqlite `--db`: a fresh sqlite db verifies clean (exit 0, "OK").
//!    This is the regression pin for "the sqlite path is unchanged".
//!
//! 2. **`store_url_pg_clean_chain_verifies_exit_0`** (`#[ignore]`; live
//!    postgres via `AI_MEMORY_TEST_POSTGRES_URL`) — seeds a couple of
//!    chained `signed_events` on a pg store via the public
//!    `capture_turn_idempotent` write path, then runs
//!    `verify-audit-trail --store-url <pg> --since <t0>` and asserts
//!    exit 0 with the "chain intact" verdict. The `--since <t0>` window
//!    (captured BEFORE seeding) scopes verification to the freshly-
//!    seeded, correctly-chained rows PLUS the boundary link, so the
//!    assertion is robust against whatever the shared, persistent
//!    `ai_memory_test` chain already contains (no per-test isolation —
//!    see CLAUDE.md).
//!
//! 3. **`store_url_pg_gap_detected_exit_1`** (`#[ignore]`; live pg) —
//!    seeds three chained rows, then raw-DELETEs the MIDDLE one to punch
//!    a sequence gap, and asserts the same CLI reports the break and
//!    exits 1 ("FAIL"). Proves the dirty→exit-1 contract reaches the
//!    postgres path. The DELETE mirrors the `verify_audit_trail_pe8.rs`
//!    sqlite gap case; raw `signed_events` mutation is test-only (the
//!    `append_only_invariant_no_mutators_in_src` H5 guard forbids it in
//!    `src/`).
//!
//! Run the ignored legs with a live PG16 + pgvector + AGE at
//! `AI_MEMORY_TEST_POSTGRES_URL`:
//!
//! ```text
//! cargo test --test verify_audit_trail_store_url_prb \
//!     --features sal-postgres --include-ignored -- --test-threads=1
//! ```

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;
use tempfile::TempDir;

use ai_memory::models::{CaptureTurnWrite, Memory};
use ai_memory::signed_events::SignedEvent;
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

// ───────────────────────────────────────────────────────────────────
// Fixtures
// ───────────────────────────────────────────────────────────────────

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

/// Standard `ai-memory --db <tmp>` command shape with
/// `AI_MEMORY_NO_CONFIG=1`. `--db` is a global clap flag required even
/// for the `--store-url` verbs; point it at a throwaway tempfile so the
/// operator's main DB is never touched. The store-url env channels are
/// scrubbed so the argv `--store-url` is authoritative in the test.
///
/// `AI_MEMORY_AUDIT_DIR` is isolated to the tempfile's parent so the
/// GLOBAL off-table forensic watermark (`last_audit_watermark`, which
/// the truncation verdict compares against on BOTH backends and which
/// is NOT scoped by the verified DB) reads no stray anchor from the
/// host's real audit dir — otherwise a real watermark higher than the
/// (empty / freshly-seeded) chain head would falsely dirty the verify.
fn ai_memory(db: &Path) -> Command {
    let audit_dir = db.parent().expect("db has a parent dir");
    let mut cmd = Command::cargo_bin("ai-memory").unwrap();
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_AUDIT_DIR", audit_dir)
        .env_remove("AI_MEMORY_STORE_URL")
        .env_remove("AI_MEMORY_STORE_URL_FILE")
        .args(["--db", db.to_str().unwrap()]);
    cmd
}

/// Build a `CaptureTurnWrite` whose append lands one chained
/// `signed_events` row attributed to `agent`. `turn` keys the
/// idempotency dedup so distinct turns are distinct writes.
fn capture_write(agent: &str, ns: &str, session: &str, turn: i64) -> CaptureTurnWrite {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(format!("{session}|{turn}|prb").as_bytes());
    let sha = hasher.finalize().to_vec();

    let now = chrono::Utc::now().to_rfc3339();
    let memory = Memory {
        id: uid("prb-ct"),
        namespace: ns.to_string(),
        title: uid("prb-turn"),
        content: format!("prb turn {turn} content"),
        source: "verify-audit-trail-prb".to_string(),
        metadata: serde_json::json!({ "agent_id": agent }),
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    };
    let signed_event = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: agent.to_string(),
        event_type: "memory.capture_turn".to_string(),
        payload_hash: sha.clone(),
        signature: None,
        attest_level: "unsigned".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    CaptureTurnWrite {
        memory,
        sha256: sha,
        host_kind: "prb-test".to_string(),
        host_session_id: session.to_string(),
        host_turn_index: turn,
        recovered_at_ms: chrono::Utc::now().timestamp_millis(),
        signed_event,
    }
}

/// Append `count` chained audit rows attributed to `agent` on the pg
/// store via the public L4 capture path.
async fn seed_chain(store: &PostgresStore, agent: &str, count: i64) {
    let ctx = CallerContext::for_agent(agent);
    let ns = uid("prb-ns");
    let session = uid("prb-sess");
    for turn in 0..count {
        store
            .capture_turn_idempotent(&ctx, &capture_write(agent, &ns, &session, turn))
            .await
            .unwrap_or_else(|e| panic!("seed capture turn {turn}: {e}"));
    }
}

// ───────────────────────────────────────────────────────────────────
// 1. sqlite regression pin — flag-absent path unchanged
// ───────────────────────────────────────────────────────────────────

#[test]
fn store_url_flag_absent_uses_sqlite_smoke() {
    // No `--store-url`: the PR-B dispatch must fall through to the local
    // sqlite `--db`. A fresh (empty) chain is trivially clean → exit 0.
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("prb-sqlite.db");

    ai_memory(&db)
        .args(["verify-audit-trail"])
        .assert()
        .success()
        .stdout(predicate::str::contains("verify-audit-trail OK"))
        .stdout(predicate::str::contains("chain intact"));
}

// ───────────────────────────────────────────────────────────────────
// 2. postgres clean-chain verify (exit 0)
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires a live postgres at AI_MEMORY_TEST_POSTGRES_URL"]
async fn store_url_pg_clean_chain_verifies_exit_0() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect pg");

    // Window floor: captured BEFORE seeding so verification scopes to the
    // rows this test appends (robust vs the shared persistent chain).
    let t0 = chrono::Utc::now().to_rfc3339();
    let agent = uid("ai:prb-clean");
    seed_chain(&store, &agent, 2).await;

    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("prb-main.db");
    ai_memory(&db)
        .args(["verify-audit-trail", "--store-url", &url, "--since", &t0])
        .assert()
        .success()
        .stdout(predicate::str::contains("verify-audit-trail OK"))
        .stdout(predicate::str::contains("chain intact"));
}

// ───────────────────────────────────────────────────────────────────
// 3. postgres dirty-chain verify (gap → exit 1)
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires a live postgres at AI_MEMORY_TEST_POSTGRES_URL"]
async fn store_url_pg_gap_detected_exit_1() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect pg");

    let t0 = chrono::Utc::now().to_rfc3339();
    let agent = uid("ai:prb-gap");
    seed_chain(&store, &agent, 3).await;

    // Punch a sequence gap: raw-DELETE the MIDDLE of this test's three
    // rows. Test-only mutation of the append-only chain (H5 guard forbids
    // it in src/); scoped by the unique per-test agent_id.
    let pool = sqlx::PgPool::connect(&url).await.expect("raw pool");
    let middle: i64 = sqlx::query_scalar(
        "SELECT sequence FROM signed_events WHERE agent_id = $1 \
         ORDER BY sequence ASC LIMIT 1 OFFSET 1",
    )
    .bind(&agent)
    .fetch_one(&pool)
    .await
    .expect("resolve middle sequence");
    let deleted = sqlx::query("DELETE FROM signed_events WHERE sequence = $1")
        .bind(middle)
        .execute(&pool)
        .await
        .expect("delete middle row")
        .rows_affected();
    assert_eq!(deleted, 1, "exactly the middle row is deleted");

    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("prb-main.db");
    ai_memory(&db)
        .args(["verify-audit-trail", "--store-url", &url, "--since", &t0])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("verify-audit-trail FAIL"));
}
