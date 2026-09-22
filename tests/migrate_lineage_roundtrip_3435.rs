// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3435 — `ai-memory migrate` must round-trip a VALID provenance
//! DAG independent of the order its edges are enumerated in, and must
//! refuse a GENUINE cycle for the whole store rather than dropping edges.
//!
//! The defect: the per-write Pass-0 lineage guard (#1859) refuses a
//! `derived_from` / `reflects_on` / `derives_from` edge whose SOURCE row is
//! wall-clock OLDER than its TARGET (a lineage edge must point newer ->
//! older on a single clock). A real store assembled elsewhere — cross-node
//! clock skew, operator-supplied stamps, a historical import — carries
//! exactly that shape while still being a DAG; the CLI sweep measured 12 of
//! 289 provenance edges refused as a "reflection cycle" on `migrate`.
//!
//! Each cell here pins the lineage flag ON (the production boot default,
//! which a library-linked test does not inherit) so the wall-clock guard is
//! LIVE for the duration, and FIRST reproduces the refusal through the
//! pre-fix funnel (`MemoryStore::link`) before proving the migration lands
//! every node AND every edge through the fixed one.
//!
//! Corpus size: the issue's 10k-store sweep has no fixture in the tree, so
//! the round-trip cell generates ~1k rows in-test (a chain + diamonds, every
//! edge clock-skewed the "wrong" way) — the shape, not the volume, is what
//! trips the guard.

#![cfg(feature = "sal")]
#![allow(clippy::doc_markdown, clippy::too_many_lines)]
// The lineage flag is a process-wide atomic; the guard serialises the
// cells in this file. Each #[tokio::test] runs on its own runtime thread,
// so holding the std guard across awaits cannot deadlock.
#![allow(clippy::await_holding_lock)]

use std::collections::BTreeSet;
use std::sync::Mutex;

use ai_memory::migrate::{migrate, open_source_store, plan};
use ai_memory::models::{
    AttestLevel, ConfidenceSource, LifecycleState, Memory, MemoryKind, MemoryLink,
    MemoryLinkRelation, Tier,
};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore};

static FLAG_LOCK: Mutex<()> = Mutex::new(());

/// Pin the lineage-DAG guard ON for the caller's scope, restoring the
/// previous value on drop.
struct LineageOn {
    _guard: std::sync::MutexGuard<'static, ()>,
    prev: bool,
}

impl LineageOn {
    fn pin() -> Self {
        let guard = FLAG_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = ai_memory::config::lineage_dag_enabled();
        ai_memory::config::set_lineage_dag(true);
        Self {
            _guard: guard,
            prev,
        }
    }
}

impl Drop for LineageOn {
    fn drop(&mut self) {
        ai_memory::config::set_lineage_dag(self.prev);
    }
}

const NS: &str = "lineage-3435";

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
        tags: vec!["lineage-3435".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: ts.clone(),
        updated_at: ts,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": "ai:lineage-3435", "scope": "collective"}),
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

fn edge(source: &str, target: &str, relation: MemoryLinkRelation) -> MemoryLink {
    MemoryLink {
        source_id: source.to_string(),
        target_id: target.to_string(),
        relation,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: Some("ai:lineage-3435".to_string()),
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

type Triple = (String, String, String);

fn triple(l: &MemoryLink) -> Triple {
    (
        l.source_id.clone(),
        l.target_id.clone(),
        l.relation.as_str().to_string(),
    )
}

async fn edge_set(store: &dyn MemoryStore) -> BTreeSet<Triple> {
    store
        .list_links(None)
        .await
        .expect("list_links")
        .iter()
        .map(triple)
        .collect()
}

async fn id_set(store: &dyn MemoryStore) -> BTreeSet<String> {
    let ctx = CallerContext::for_admin(ai_memory::identity::sentinels::AI_MIGRATE);
    let mut ids = BTreeSet::new();
    let mut offset = 0;
    loop {
        let mut filter = Filter::new();
        filter.namespace = Some(NS.to_string());
        filter.limit = ai_memory::storage::LIST_MAX_LIMIT;
        filter.offset = offset;
        let page = store.list(&ctx, &filter).await.expect("list");
        let n = page.len();
        ids.extend(page.into_iter().map(|m| m.id));
        if n < ai_memory::storage::LIST_MAX_LIMIT {
            return ids;
        }
        offset += n;
    }
}

/// Seed `rows` memories whose `created_at` INCREASES with the index, then a
/// provenance graph whose every edge points OLDER -> NEWER — a structurally
/// valid DAG (a chain plus a diamond every 10 nodes, mixed relations) that
/// the single-clock wall-clock guard nevertheless rejects edge by edge.
/// Edges land through the inbound funnel, the way a federation receiver or
/// a historical import lands them.
async fn seed_skewed_dag(store: &dyn MemoryStore, rows: usize) -> Vec<MemoryLink> {
    let ctx = CallerContext::for_admin(ai_memory::identity::sentinels::AI_MIGRATE);
    let base = chrono::Utc::now() - chrono::Duration::days(3);
    for i in 0..rows {
        let at = base + chrono::Duration::seconds(i64::try_from(i).expect("row index"));
        store
            .store(&ctx, &memory_at(&format!("n{i:05}"), at))
            .await
            .expect("seed memory");
    }
    let mut edges = Vec::new();
    for i in 0..rows.saturating_sub(1) {
        let rel = match i % 3 {
            0 => MemoryLinkRelation::DerivedFrom,
            1 => MemoryLinkRelation::ReflectsOn,
            _ => MemoryLinkRelation::DerivesFrom,
        };
        edges.push(edge(&format!("n{i:05}"), &format!("n{:05}", i + 1), rel));
        if i % 10 == 0 && i + 2 < rows {
            // Diamond: i -> i+2 alongside i -> i+1 -> i+2.
            edges.push(edge(
                &format!("n{i:05}"),
                &format!("n{:05}", i + 2),
                MemoryLinkRelation::DerivedFrom,
            ));
        }
    }
    for e in &edges {
        store
            .apply_remote_link(&ctx, e, AttestLevel::Unsigned.as_str())
            .await
            .expect("seed edge through the inbound funnel");
    }
    edges
}

/// (a) Round trip: every node AND every edge of a clock-skewed valid DAG
/// arrives, in the order `list_links` returns them — the pre-fix funnel
/// provably refuses the very first edge.
#[tokio::test]
async fn migrate_round_trips_clock_skewed_lineage_dag_3435() {
    const ROWS: usize = 1_000;
    let _flag = LineageOn::pin();
    let dir = tempfile::tempdir().unwrap();
    let src_path = dir.path().join("source.db");
    let dst_path = dir.path().join("destination.db");
    let src = SqliteStore::open(&src_path).unwrap();
    let dst = SqliteStore::open(&dst_path).unwrap();
    let seeded = seed_skewed_dag(&src, ROWS).await;
    let expected: BTreeSet<Triple> = seeded.iter().map(triple).collect();
    assert_eq!(
        edge_set(&src).await,
        expected,
        "fixture: source holds the DAG"
    );

    // R-203 — reproduce the defect through the PRE-FIX funnel first: with
    // the nodes present on the destination, `MemoryStore::link` (the
    // per-write wall-clock guard) refuses the skewed edge as a cycle.
    let ctx = CallerContext::for_admin(ai_memory::identity::sentinels::AI_MIGRATE);
    let probe = SqliteStore::open(dir.path().join("probe.db")).unwrap();
    let base = chrono::Utc::now() - chrono::Duration::days(3);
    probe.store(&ctx, &memory_at("p0", base)).await.unwrap();
    probe
        .store(&ctx, &memory_at("p1", base + chrono::Duration::seconds(1)))
        .await
        .unwrap();
    let refused = probe
        .link(&ctx, &edge("p0", "p1", MemoryLinkRelation::DerivedFrom))
        .await
        .expect_err("the wall-clock guard must refuse an older -> newer lineage edge");
    assert!(
        refused
            .to_string()
            .contains(ai_memory::storage::LINK_CYCLE_ERR_PREFIX),
        "defect reproduction: {refused}"
    );

    let report = migrate(&src, &dst, 250, None, false).await;
    assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
    assert_eq!(report.memories_read, ROWS);
    assert_eq!(report.memories_written, ROWS);
    assert_eq!(report.links_read, seeded.len());
    assert_eq!(report.links_written, seeded.len());
    assert_eq!(report.links_skipped, 0);
    assert_eq!(id_set(&dst).await, id_set(&src).await, "every node arrived");
    assert_eq!(edge_set(&dst).await, expected, "every edge arrived");

    // Idempotent re-run: the same edge set, now counted as skipped.
    let again = migrate(&src, &dst, 250, None, false).await;
    assert!(again.errors.is_empty(), "errors: {:?}", again.errors);
    assert_eq!(again.links_skipped, seeded.len());
    assert_eq!(again.links_written, 0);
    assert_eq!(edge_set(&dst).await, expected);
}

/// (b) A genuine cycle in the source is refused as a WHOLE with the named
/// error; nothing — no node, no edge — is written to the destination.
#[tokio::test]
async fn migrate_refuses_genuine_cycle_and_writes_nothing_3435() {
    let _flag = LineageOn::pin();
    let dir = tempfile::tempdir().unwrap();
    let src = SqliteStore::open(dir.path().join("source.db")).unwrap();
    let dst = SqliteStore::open(dir.path().join("destination.db")).unwrap();
    let mut seeded = seed_skewed_dag(&src, 12).await;
    // Close a cycle deep in the chain: n00009 -> n00003 alongside the
    // chain n00003 -> ... -> n00009. Through the inbound funnel, the way a
    // corrupt peer would land it.
    let ctx = CallerContext::for_admin(ai_memory::identity::sentinels::AI_MIGRATE);
    let closing = edge("n00009", "n00003", MemoryLinkRelation::DerivedFrom);
    src.apply_remote_link(&ctx, &closing, AttestLevel::Unsigned.as_str())
        .await
        .expect("inbound funnel lands the closing edge");
    seeded.push(closing);

    let report = migrate(&src, &dst, 250, None, false).await;
    assert_eq!(report.errors.len(), 1, "errors: {:?}", report.errors);
    let err = &report.errors[0];
    assert!(
        err.contains("final lineage graph invalid")
            && err.contains(ai_memory::storage::LINK_CYCLE_ERR_PREFIX)
            && err.contains("n00003"),
        "named error must identify the cycle: {err}"
    );
    assert_eq!(report.memories_written, 0);
    assert_eq!(report.links_written, 0);
    assert!(id_set(&dst).await.is_empty(), "no node may be written");
    assert!(edge_set(&dst).await.is_empty(), "no edge may be written");

    // The dry-run plan carries the same verdict, so an operator learns of
    // the cycle before committing.
    let planned = plan(&src, 250, None).await;
    assert!(
        planned
            .errors
            .iter()
            .any(|e| e.contains("final lineage graph invalid")),
        "{:?}",
        planned.errors
    );
}

/// (d) A missing SOURCE is an error — never an empty-store "success" — and
/// the probe leaves no file behind.
#[tokio::test]
async fn migrate_missing_source_is_an_error_not_an_empty_store_3435() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no-such-source.db");
    let url = format!("sqlite://{}", missing.display());
    let err = open_source_store(&url)
        .await
        .err()
        .expect("a missing source must be refused");
    assert!(
        format!("{err:#}").contains(ai_memory::storage::MISSING_DATABASE_REFUSAL),
        "{err:#}"
    );
    assert!(
        !missing.exists(),
        "the source probe must not create the file"
    );
    // `--dry-run` shape: a plan over a real source needs no destination and
    // must not mint one.
    let src = SqliteStore::open(dir.path().join("real-source.db")).unwrap();
    let seeded = seed_skewed_dag(&src, 5).await;
    let report = plan(&src, 250, None).await;
    assert!(report.dry_run);
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(report.memories_read, 5);
    assert_eq!(report.links_read, seeded.len());
    assert_eq!(report.memories_written + report.links_written, 0);
}

/// Postgres twin of (a): the same clock-skewed DAG migrates sqlite -> pg
/// through `PostgresStore::apply_remote_link` (which never consults the pg
/// Pass-0 twin). Self-skips when `AI_MEMORY_TEST_POSTGRES_URL` is unset.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn migrate_round_trips_clock_skewed_lineage_dag_to_postgres_3435() {
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _flag = LineageOn::pin();
    let dir = tempfile::tempdir().unwrap();
    let src = SqliteStore::open(dir.path().join("source.db")).unwrap();
    let seeded = seed_skewed_dag(&src, 60).await;
    let expected: BTreeSet<Triple> = seeded.iter().map(triple).collect();
    let dst = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect postgres adapter");
    // The shared test database may hold rows from other cells; scope the
    // assertions to this namespace's ids.
    let report = migrate(&src, &dst, 250, Some(NS.to_string()), false).await;
    assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
    assert_eq!(report.memories_written, 60);
    assert_eq!(report.links_written + report.links_skipped, seeded.len());
    let landed: BTreeSet<Triple> = dst
        .list_links(Some(NS))
        .await
        .expect("pg list_links")
        .iter()
        .map(triple)
        .filter(|t| expected.contains(t))
        .collect();
    assert_eq!(landed, expected, "every edge arrived on postgres");
}
