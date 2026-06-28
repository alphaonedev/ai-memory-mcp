// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.1 W5 / #1693 — L2 transcript rehydration MUST be backend-blind:
//! a postgres-backed daemon rehydrates from host transcripts identically
//! to the sqlite path.
//!
//! Pre-#1693 the L2 `recover-previous-session` path was sqlite-only —
//! there was no SAL `recover_turn_idempotent`, so postgres-backed
//! daemons silently skipped cross-session rehydration. The fix put
//! `recover_turn_idempotent` (+ `capture_turn_idempotent`,
//! `agent_max_created_at`) on the `MemoryStore` trait and implemented it
//! on `PostgresStore`; `dispatch_recover_previous_session` routes
//! `--store-url postgres://…` through `recover_from_transcript_store`.
//!
//! This test replays the SAME transcript through BOTH a `SqliteStore`
//! and a `PostgresStore` via the SAL `recover_from_transcript_store`
//! entry and asserts:
//!   * identical first-run memory count (one per turn),
//!   * idempotent re-run on BOTH (every line dedup-skipped, no new rows),
//!   * the recovered content SET is identical across the two backends.
//!
//! The sqlite SAL-path twin lives in
//! `src/recover/mod.rs::tests::store_path_recovers_and_dedups_sqlite`.
//!
//! ## Skip / run semantics
//!
//! Postgres backend tests require `AI_MEMORY_TEST_POSTGRES_URL` to point
//! at a live instance and are `#[ignore]`-gated — run them explicitly
//! with `--include-ignored`:
//!
//! ```text
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://aimem:aimem@127.0.0.1:5432/aimem_test \
//!   cargo test --features sal-postgres --test postgres_l2_rehydration_1693 \
//!   -- --include-ignored --nocapture
//! ```
//!
//! When the env var is unset the test self-skips with a stderr WARN.

#![cfg(feature = "sal-postgres")]

use ai_memory::recover::{HostKind, RecoverOpts, recover_from_transcript_store};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};

/// Two distinct user turns in the Claude-Code transcript shape.
const TURN_A: &str = r#"{"timestamp":"2026-05-28T12:00:00Z","type":"user","message":{"content":[{"type":"text","text":"l2 parity directive alpha"}]}}"#;
const TURN_B: &str = r#"{"timestamp":"2026-05-28T12:05:00Z","type":"user","message":{"content":[{"type":"text","text":"l2 parity directive beta"}]}}"#;

fn write_transcript(dir: &std::path::Path, lines: &[&str]) -> std::path::PathBuf {
    use std::io::Write;
    let p = dir.join("session.jsonl");
    let mut f = std::fs::File::create(&p).unwrap();
    for l in lines {
        writeln!(f, "{l}").unwrap();
    }
    f.flush().unwrap();
    p
}

fn opts_for(transcript: std::path::PathBuf, namespace: &str, agent_id: &str) -> RecoverOpts {
    RecoverOpts {
        host: HostKind::ClaudeCode,
        transcript_override: Some(transcript),
        since_iso: None,
        namespace: Some(namespace.to_string()),
        limit: 100,
        dry_run: false,
        quiet: false,
        agent_id: agent_id.to_string(),
    }
}

async fn maybe_open_pg() -> Option<PostgresStore> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!(
            "test skipped: AI_MEMORY_TEST_POSTGRES_URL not set — \
             #1693 postgres L2-rehydration parity requires a live instance"
        );
        return None;
    };
    match PostgresStore::connect(&url).await {
        Ok(store) => Some(store),
        Err(e) => {
            eprintln!("test skipped: PostgresStore::connect failed: {e}");
            None
        }
    }
}

/// Collect the recovered memories' content for a namespace, sorted, so
/// the two backends can be compared as a set (ids differ; content must
/// match).
async fn recovered_contents(
    store: &dyn MemoryStore,
    ctx: &CallerContext,
    ids: &[String],
) -> Vec<String> {
    let mut out = Vec::new();
    for id in ids {
        let mem = store.get(ctx, id).await.expect("get recovered memory");
        out.push(mem.content);
    }
    out.sort();
    out
}

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn l2_rehydration_identical_on_sqlite_and_postgres_1693() {
    let Some(pg) = maybe_open_pg().await else {
        return;
    };

    // Unique namespace + agent per run so re-runs against the shared
    // postgres instance never collide with a prior run's rows.
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let namespace = format!("l2-1693-{tag}");
    let agent_id = format!("ai:test:l2-{tag}");

    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = write_transcript(dir.path(), &[TURN_A, TURN_B]);

    // sqlite backend.
    let sqlite_db = dir.path().join("mem.db");
    let sqlite = SqliteStore::open(&sqlite_db).expect("open sqlite store");

    let admin = CallerContext::for_admin("operator:test-1693");

    // ── First run on BOTH backends: one memory per turn ──────────────
    let sq1 = recover_from_transcript_store(&sqlite, &opts_for(transcript.clone(), &namespace, &agent_id))
        .await
        .expect("sqlite recover");
    let pg1 = recover_from_transcript_store(&pg, &opts_for(transcript.clone(), &namespace, &agent_id))
        .await
        .expect("postgres recover");

    assert_eq!(
        sq1.memories_created.len(),
        2,
        "sqlite: one memory per turn; errors={:?}",
        sq1.errors
    );
    assert_eq!(
        pg1.memories_created.len(),
        2,
        "postgres: one memory per turn (backend-blind L2); errors={:?}",
        pg1.errors
    );
    assert_eq!(
        sq1.lines_atomised, pg1.lines_atomised,
        "lines_atomised must be identical across backends"
    );

    // ── Content parity: the recovered SET is identical ───────────────
    let sq_contents = recovered_contents(&sqlite, &admin, &sq1.memories_created).await;
    let pg_contents = recovered_contents(&pg, &admin, &pg1.memories_created).await;
    assert_eq!(
        sq_contents, pg_contents,
        "recovered content set must be identical on sqlite and postgres"
    );

    // ── Idempotent re-run on BOTH: every line dedup-skipped ──────────
    let sq2 = recover_from_transcript_store(&sqlite, &opts_for(transcript.clone(), &namespace, &agent_id))
        .await
        .expect("sqlite recover re-run");
    let pg2 = recover_from_transcript_store(&pg, &opts_for(transcript, &namespace, &agent_id))
        .await
        .expect("postgres recover re-run");

    assert_eq!(sq2.lines_atomised, 0, "sqlite re-run must atomise nothing");
    assert_eq!(
        pg2.lines_atomised, 0,
        "postgres re-run must atomise nothing (recover_turn_idempotent dedup)"
    );
    assert!(
        sq2.memories_created.is_empty() && pg2.memories_created.is_empty(),
        "idempotent re-run must create no new rows on either backend"
    );
    assert_eq!(
        sq2.lines_skipped_dedup, pg2.lines_skipped_dedup,
        "dedup-skip count must be identical across backends"
    );
    assert_eq!(
        pg2.lines_skipped_dedup, 2,
        "both turns must dedup-skip on the postgres re-run"
    );
}
