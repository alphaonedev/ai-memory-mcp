// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3435 — `ai-memory migrate` through the REAL binary:
//!
//! * (c) `--dry-run` against a non-existent `--to` path reports the counts
//!   and leaves NO file behind (it used to `Connection::open` + migrate the
//!   destination while sizing);
//! * (d) a non-existent `--from` is a non-zero exit naming the refusal —
//!   never a freshly-created empty source and a `memories_read: 0`
//!   "success" — and creates neither path;
//! * (a, end-to-end) a clock-skewed valid lineage DAG round-trips through
//!   the binary, whose boot seeds the lineage guard ON (the production
//!   default a library-linked test does not inherit).
//!
//! The child runs with `AI_MEMORY_NO_CONFIG=1` and a scratch `HOME` so it
//! never reads the developer's config or touches their key directory.

#![cfg(feature = "sal")]
#![allow(clippy::doc_markdown)]

// #3733 — key dirs created 0700 (not the ambient umask; the #3198 guard
// refuses a group-writable key dir at umask 0002).
#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Output;

use ai_memory::models::{
    AttestLevel, ConfidenceSource, LifecycleState, Memory, MemoryKind, MemoryLink,
    MemoryLinkRelation, Tier,
};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn run(dir: &Path, args: &[&str]) -> Output {
    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".config")).expect("scratch home");
    let keys = dir.join("keys");
    key_dir_sandbox::mkdir_0700(&keys);
    std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .current_dir(dir)
        .args(args)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .expect("spawn ai-memory")
}

fn sqlite_url(path: &Path) -> String {
    format!("sqlite://{}", path.display())
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

const NS: &str = "cli-3435";

fn memory_at(id: &str, created_at: chrono::DateTime<chrono::Utc>) -> Memory {
    let ts = created_at.to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: format!("title {id}"),
        content: format!("content for {id}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: ts.clone(),
        updated_at: ts,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": "ai:cli-3435", "scope": "collective"}),
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
    }
}

fn edge(source: &str, target: &str) -> MemoryLink {
    MemoryLink {
        source_id: source.to_string(),
        target_id: target.to_string(),
        relation: MemoryLinkRelation::DerivedFrom,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: Some("ai:cli-3435".to_string()),
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

type Triple = (String, String, String);

async fn edge_set(store: &dyn MemoryStore) -> BTreeSet<Triple> {
    store
        .list_links(Some(NS))
        .await
        .expect("list_links")
        .iter()
        .map(|l| {
            (
                l.source_id.clone(),
                l.target_id.clone(),
                l.relation.as_str().to_string(),
            )
        })
        .collect()
}

/// Seed `rows` memories with INCREASING `created_at` and a `derived_from`
/// chain pointing OLDER -> NEWER: a valid DAG the per-write wall-clock guard
/// refuses edge by edge. Landed through the inbound funnel, as a peer would.
async fn seed_skewed_chain(path: &Path, rows: usize) -> usize {
    let store = SqliteStore::open(path).expect("open source");
    let ctx = CallerContext::for_admin(ai_memory::identity::sentinels::AI_MIGRATE);
    let base = chrono::Utc::now() - chrono::Duration::days(3);
    for i in 0..rows {
        let at = base + chrono::Duration::seconds(i64::try_from(i).expect("index"));
        store
            .store(&ctx, &memory_at(&format!("c{i:04}"), at))
            .await
            .expect("seed memory");
    }
    for i in 0..rows - 1 {
        store
            .apply_remote_link(
                &ctx,
                &edge(&format!("c{i:04}"), &format!("c{:04}", i + 1)),
                AttestLevel::Unsigned.as_str(),
            )
            .await
            .expect("seed edge");
    }
    rows - 1
}

/// (c) `--dry-run` never creates its destination and still reports counts.
#[tokio::test]
async fn migrate_dry_run_does_not_create_destination_3435() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.db");
    let destination = dir.path().join("missing-destination.db");
    let edges = seed_skewed_chain(&source, 7).await;

    let out = run(
        dir.path(),
        &[
            "migrate",
            "--from",
            &sqlite_url(&source),
            "--to",
            &sqlite_url(&destination),
            "--dry-run",
            "--json",
        ],
    );
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(
        !destination.exists(),
        "migrate --dry-run must not create its destination"
    );
    let report: serde_json::Value = serde_json::from_str(text(&out.stdout).trim())
        .unwrap_or_else(|e| panic!("json report: {e}\n{}", text(&out.stdout)));
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["memories_read"], 7);
    assert_eq!(report["memories_written"], 0);
    assert_eq!(report["errors"].as_array().map(Vec::len), Some(0));
    // Sanity on the fixture: the dry run saw the edges too.
    assert!(edges > 0);
    // The source is opened READ-ONLY: it is byte-identical after the plan.
    // (A write would have surfaced as a `query_only` error above.)
    assert!(source.exists());
}

/// (d) A missing SOURCE is an error, never an empty store; nothing created.
#[tokio::test]
async fn migrate_missing_source_errors_and_creates_nothing_3435() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("no-such-source.db");
    let destination = dir.path().join("never-created.db");
    let from_url = sqlite_url(&source);
    let to_url = sqlite_url(&destination);
    for extra in [&[][..], &["--dry-run"][..]] {
        let mut args = vec!["migrate", "--from", &from_url, "--to", &to_url];
        args.extend_from_slice(extra);
        let out = run(dir.path(), &args);
        assert!(
            !out.status.success(),
            "a missing source must be a non-zero exit (extra={extra:?}); stdout: {}",
            text(&out.stdout)
        );
        let stderr = text(&out.stderr);
        assert!(
            stderr.contains(ai_memory::storage::MISSING_DATABASE_REFUSAL),
            "refusal must be named (extra={extra:?}): {stderr}"
        );
        assert!(
            !source.exists(),
            "the source probe must not create the file"
        );
        assert!(
            !destination.exists(),
            "a refused migrate must not create its destination"
        );
    }
}

/// (a) End-to-end through the binary, whose boot seeds the lineage guard ON:
/// a clock-skewed `derived_from` chain round-trips node-for-node and
/// edge-for-edge, and a second run is idempotent.
#[tokio::test]
async fn migrate_cli_round_trips_clock_skewed_chain_3435() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.db");
    let destination = dir.path().join("destination.db");
    let edges = seed_skewed_chain(&source, 40).await;
    let expected = edge_set(&SqliteStore::open(&source).unwrap()).await;
    assert_eq!(expected.len(), edges);

    for pass in 1..=2 {
        let out = run(
            dir.path(),
            &[
                "migrate",
                "--from",
                &sqlite_url(&source),
                "--to",
                &sqlite_url(&destination),
                "--json",
            ],
        );
        assert!(
            out.status.success(),
            "pass {pass}: stdout: {}\nstderr: {}",
            text(&out.stdout),
            text(&out.stderr)
        );
        let report: serde_json::Value = serde_json::from_str(text(&out.stdout).trim())
            .unwrap_or_else(|e| panic!("json report: {e}\n{}", text(&out.stdout)));
        assert_eq!(report["memories_read"], 40, "pass {pass}");
        assert_eq!(report["memories_written"], 40, "pass {pass}");
        assert_eq!(
            report["errors"].as_array().map(Vec::len),
            Some(0),
            "pass {pass}"
        );
    }
    let dst = SqliteStore::open(&destination).unwrap();
    assert_eq!(edge_set(&dst).await, expected, "every edge arrived");
    let ctx = CallerContext::for_admin(ai_memory::identity::sentinels::AI_MIGRATE);
    let mut filter = ai_memory::store::Filter::new();
    filter.namespace = Some(NS.to_string());
    filter.limit = 100;
    let landed = dst.list(&ctx, &filter).await.unwrap();
    assert_eq!(landed.len(), 40, "every node arrived");
}
