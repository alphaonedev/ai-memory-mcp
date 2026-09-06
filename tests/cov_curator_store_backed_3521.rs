// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3521 — `ai-memory curator --store-url …` SAL arms.
//!
//! The store-backed curator twins (`--prune-reports` and
//! `--rollback[-last]`) are the ones an operator running a federated
//! (Postgres) deployment actually reaches; the direct-rusqlite twins are
//! what the historical tests drove. These pins run the SAL arms over a
//! `sqlite://` store URL — the same trait dispatch a `postgres://` URL
//! takes, minus the server — so a regression in the store-backed branch
//! cannot hide behind the SQLite path's coverage.
//!
//! Data-integrity contracts pinned here:
//! * a rollback of an id the store does not hold REFUSES (no silent
//!   "applied"), so an operator cannot believe a reversal landed;
//! * a reversed entry is TAGGED `_reversed` and skipped on a re-run, so
//!   `--rollback-last N` is idempotent and cannot double-apply;
//! * an entry whose content is not a `RollbackEntry` is SKIPPED, never
//!   guessed at;
//! * `--prune-reports` without `--apply` is a DRY RUN that changes
//!   nothing and says so.

#![cfg(feature = "sal")]

use std::path::Path;

use ai_memory::cli::CliOutput;
use ai_memory::cli::curator::{CuratorArgs, run};
use ai_memory::config::AppConfig;
use ai_memory::models::{
    ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier, default_metadata,
};
use ai_memory::store::{CallerContext, MemoryStore, sqlite::SqliteStore};

const ROLLBACK_NS: &str = "_curator/rollback";

fn args_for(store_url: &Path) -> CuratorArgs {
    CuratorArgs {
        once: false,
        daemon: false,
        interval_secs: 3_600,
        max_ops: 1,
        dry_run: false,
        include_namespaces: Vec::new(),
        exclude_namespaces: Vec::new(),
        json: false,
        prune_reports: false,
        apply: false,
        rollback: None,
        rollback_last: None,
        reflect: false,
        namespace: None,
        max_depth: None,
        all_namespaces: false,
        store_url: Some(format!("sqlite://{}", store_url.display())),
    }
}

fn memory(namespace: &str, title: &str, content: &str, priority: i32) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert(
            "agent_id".to_string(),
            serde_json::Value::String("ai:curator".to_string()),
        );
    }
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: Vec::new(),
        priority,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
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
        lifecycle_state: LifecycleState::Open,
        cid: None,
        valid_from: None,
        valid_until: None,
    }
}

/// Seed rows through the SAL adapter, then DROP the handle so the CLI's
/// own store build opens the file cleanly.
async fn seed(db: &Path, rows: &[Memory]) {
    let store = SqliteStore::open(db).expect("open sal sqlite store");
    let ctx = CallerContext::for_admin("ai:curator");
    for m in rows {
        store.store(&ctx, m).await.expect("seed row");
    }
}

async fn read_back(db: &Path, id: &str) -> Memory {
    let store = SqliteStore::open(db).expect("open sal sqlite store");
    let ctx = CallerContext::for_admin("ai:curator");
    store.get(&ctx, id).await.expect("read back")
}

fn tmp_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("curator-3521.db");
    (dir, path)
}

/// `--prune-reports` over a SAL store: the DRY RUN says nothing is
/// deleted, `--apply` reports the collapse, and `--json` emits the
/// serialised report rather than prose.
#[tokio::test]
async fn store_backed_prune_reports_dry_run_then_apply_then_json() {
    let (_dir, db) = tmp_db();
    seed(&db, &[memory("cov-3521", "seed", "body", 5)]).await;
    let cfg = AppConfig::default();

    // 1. Dry run — the default. Never deletes; names the daily namespace.
    {
        let mut args = args_for(&db);
        args.prune_reports = true;
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            run(&db, &args, &cfg, &mut out)
                .await
                .expect("store-backed --prune-reports dry run");
        }
        let text = String::from_utf8(stdout).expect("utf8");
        assert!(
            text.contains("DRY RUN") && text.contains("Nothing is deleted"),
            "dry run must say it deletes nothing; got: {text}"
        );
    }

    // 2. --apply — reports the collapse in the reaping-is-the-GC's words.
    {
        let mut args = args_for(&db);
        args.prune_reports = true;
        args.apply = true;
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            run(&db, &args, &cfg, &mut out)
                .await
                .expect("store-backed --prune-reports --apply");
        }
        let text = String::from_utf8(stdout).expect("utf8");
        assert!(
            text.contains("curator report backlog collapsed"),
            "apply must report the collapse; got: {text}"
        );
    }

    // 3. --json — machine shape, no prose.
    {
        let mut args = args_for(&db);
        args.prune_reports = true;
        args.json = true;
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            run(&db, &args, &cfg, &mut out)
                .await
                .expect("store-backed --prune-reports --json");
        }
        let text = String::from_utf8(stdout).expect("utf8");
        let parsed: serde_json::Value = serde_json::from_str(text.trim()).expect("json report");
        assert!(
            parsed.get("backlog").is_some(),
            "the JSON report must carry the backlog count; got: {text}"
        );
    }
}

/// A `--rollback <id>` the store does not hold REFUSES. Reporting
/// "applied" for a reversal that never ran would tell an operator their
/// corpus was restored when it was not.
#[tokio::test]
async fn store_backed_rollback_of_an_unknown_id_refuses() {
    let (_dir, db) = tmp_db();
    seed(&db, &[memory("cov-3521", "seed", "body", 5)]).await;
    let cfg = AppConfig::default();

    let mut args = args_for(&db);
    args.rollback = Some("no-such-rollback-id".to_string());
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
    let err = run(&db, &args, &cfg, &mut out)
        .await
        .expect_err("an unknown rollback id must be refused")
        .to_string();
    assert!(
        err.contains("not found"),
        "the refusal must name the miss; got: {err}"
    );
}

/// The single-id store-backed rollback reverses the recorded adjustment,
/// tags the log row `_reversed`, and re-running it does not move the row
/// again.
///
/// The adjustment reversed here RAISES the priority back (4 -> 9). The
/// substrate's `(title, namespace)` upsert-merge resolves `priority` with
/// `MAX(existing, incoming)`, so a store-backed reversal that would LOWER a
/// priority is currently a silent no-op that still prints `applied` — see
/// the residual-risk note on #3521; this test deliberately does not pin
/// that behaviour as correct.
#[tokio::test]
async fn store_backed_rollback_by_id_applies_then_is_idempotent() {
    let (_dir, db) = tmp_db();
    let target = memory("cov-3521", "target", "body", 4);
    let entry = serde_json::to_string(&ai_memory::autonomy::RollbackEntry::PriorityAdjust {
        memory_id: target.id.clone(),
        before: 9,
        after: 4,
    })
    .expect("serialise rollback entry");
    let log = memory(ROLLBACK_NS, "rollback-by-id", &entry, 5);
    seed(&db, &[target.clone(), log.clone()]).await;
    let cfg = AppConfig::default();

    // First run: the adjustment is reversed 4 -> 9.
    {
        let mut args = args_for(&db);
        args.rollback = Some(log.id.clone());
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        // The `CliOutput` borrow of the capture buffers is scoped so the
        // buffers can be read back afterwards.
        {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            run(&db, &args, &cfg, &mut out)
                .await
                .expect("store-backed --rollback");
        }
        let text = String::from_utf8(stdout).expect("utf8");
        assert!(
            text.contains("applied"),
            "the first reversal must report applied; got: {text}"
        );
    }
    assert_eq!(
        read_back(&db, &target.id).await.priority,
        9,
        "the reversal must restore the pre-adjust priority"
    );
    assert!(
        read_back(&db, &log.id)
            .await
            .tags
            .iter()
            .any(|t| t == "_reversed"),
        "the log row must be tagged so a re-run cannot double-apply"
    );

    // Second run: the row is already tagged; the priority must not move.
    {
        let mut args = args_for(&db);
        args.rollback = Some(log.id.clone());
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        run(&db, &args, &cfg, &mut out)
            .await
            .expect("second store-backed --rollback");
    }
    assert_eq!(
        read_back(&db, &target.id).await.priority,
        9,
        "a repeated reversal must not move the row again"
    );
}

/// `--rollback-last N` reverses the untagged entries, SKIPS an entry whose
/// content is not a `RollbackEntry` (never guesses), and reports the count
/// it actually applied.
#[tokio::test]
async fn store_backed_rollback_last_skips_malformed_and_already_reversed() {
    let (_dir, db) = tmp_db();
    let target = memory("cov-3521", "target-last", "body", 3);
    let entry = serde_json::to_string(&ai_memory::autonomy::RollbackEntry::PriorityAdjust {
        memory_id: target.id.clone(),
        before: 8,
        after: 3,
    })
    .expect("serialise rollback entry");
    let good = memory(ROLLBACK_NS, "rollback-good", &entry, 5);
    let malformed = memory(ROLLBACK_NS, "rollback-malformed", "not a rollback entry", 5);
    let mut already = memory(ROLLBACK_NS, "rollback-already", &entry, 5);
    already.tags.push("_reversed".to_string());
    seed(
        &db,
        &[target.clone(), good.clone(), malformed.clone(), already],
    )
    .await;
    let cfg = AppConfig::default();

    let mut args = args_for(&db);
    args.rollback_last = Some(10);
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    {
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        run(&db, &args, &cfg, &mut out)
            .await
            .expect("store-backed --rollback-last");
    }
    let text = String::from_utf8(stdout).expect("utf8");
    assert!(
        text.contains("reversed 1 rollback entries"),
        "only the one well-formed, untagged entry may be reversed; got: {text}"
    );
    assert_eq!(
        read_back(&db, &target.id).await.priority,
        8,
        "the well-formed entry must have restored the pre-adjust priority"
    );
    assert!(
        !read_back(&db, &malformed.id)
            .await
            .tags
            .iter()
            .any(|t| t == "_reversed"),
        "a malformed entry must be left untouched, not marked reversed"
    );
}

/// `--rollback-last N` over a store with no log rows reports zero rather
/// than failing — an empty rollback log is not an error condition.
#[tokio::test]
async fn store_backed_rollback_last_on_an_empty_log_reports_zero() {
    let (_dir, db) = tmp_db();
    seed(&db, &[memory("cov-3521", "seed-empty", "body", 5)]).await;
    let cfg = AppConfig::default();

    let mut args = args_for(&db);
    args.rollback_last = Some(5);
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    {
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        run(&db, &args, &cfg, &mut out)
            .await
            .expect("store-backed --rollback-last on an empty log");
    }
    let text = String::from_utf8(stdout).expect("utf8");
    assert!(
        text.contains("reversed 0 rollback entries"),
        "an empty log must report zero; got: {text}"
    );
}
