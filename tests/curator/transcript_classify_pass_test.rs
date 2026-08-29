// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

//! #1393 sub-unit 2 — transcript-classify pass acceptance suite.
//!
//! Exercises the PUBLIC entry point
//! [`ai_memory::curator::transcript_classify_pass::run_transcript_classify_pass`]
//! against a real `SqliteStore`, with a deterministic stub LLM, and pins the
//! behaviours from the 5-agent decision (memory `4d3ea1c5`):
//!
//! 1. A recovered-from-transcript `Observation` the LLM refines is re-tagged
//!    to the new kind AND a `memory.reclassified` signed audit row is emitted.
//! 2. LLM abstention (`None`) leaves the kind untouched (no audit).
//! 3. A non-recovered `Observation` (no tag) is never a candidate.
//! 4. `dry_run` computes the classification but writes nothing.
//! 5. The store guard protects `reflection` kinds from being clobbered, even
//!    via a direct `reclassify_memory_kind` call.

use ai_memory::autonomy::AutonomyLlm;
use ai_memory::curator::transcript_classify_pass::run_transcript_classify_pass;
use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::recover::RECOVERED_FROM_TRANSCRIPT_TAG;
use ai_memory::signed_events::list_signed_events;
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore};
use anyhow::Result;
use chrono::Utc;
use std::path::Path;
use tempfile::NamedTempFile;

const NS: &str = "ns-1393";

/// Deterministic stub LLM: `classify_kind` returns the configured value;
/// the other trait methods are inert (the pass only calls `classify_kind`).
struct StubLlm {
    kind: Option<MemoryKind>,
}

impl AutonomyLlm for StubLlm {
    fn auto_tag(&self, _t: &str, _c: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }
    fn detect_contradiction(&self, _a: &str, _b: &str) -> Result<bool> {
        Ok(false)
    }
    fn summarize_memories(&self, _m: &[(String, String)]) -> Result<String> {
        Ok(String::new())
    }
    fn classify_kind(&self, _t: &str, _c: &str) -> Result<Option<MemoryKind>> {
        Ok(self.kind)
    }
}

fn make_mem(title: &str, recovered: bool, kind: MemoryKind) -> Memory {
    let now = Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("body of {title}"),
        tags: if recovered {
            vec![RECOVERED_FROM_TRANSCRIPT_TAG.to_string()]
        } else {
            vec![]
        },
        memory_kind: kind,
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        metadata: serde_json::json!({ "agent_id": "test-agent" }),
        created_at: now.clone(),
        updated_at: now,
        version: 1,
        ..Memory::default()
    }
}

fn seed(path: &Path, mems: &[Memory]) {
    let conn = db::open(path).expect("db::open");
    for m in mems {
        db::insert(&conn, m).expect("db::insert");
    }
}

/// Read a memory's current kind through the SAL trait (admin ctx bypasses
/// the per-row visibility filter so the test sees the seeded rows).
async fn kind_of(store: &SqliteStore, id: &str) -> MemoryKind {
    let ctx = CallerContext::for_admin("test-admin");
    let f = {
        let mut __f = Filter::new();
        __f.namespace = Some(NS.to_string());
        __f.limit = 500;
        __f
    };
    store
        .list(&ctx, &f)
        .await
        .expect("list")
        .into_iter()
        .find(|m| m.id == id)
        .expect("seeded memory present")
        .memory_kind
}

/// Count `memory.reclassified` audit rows in the chain.
fn reclassified_audit_count(path: &Path) -> usize {
    let conn = db::open(path).expect("db::open");
    list_signed_events(&conn, None, 10_000, 0)
        .expect("list_signed_events")
        .into_iter()
        .filter(|e| e.event_type == "memory.reclassified")
        .count()
}

#[tokio::test]
async fn recovered_observation_reclassified_with_audit() {
    let tmp = NamedTempFile::new().unwrap();
    let m = make_mem("recovered decision turn", true, MemoryKind::Observation);
    let id = m.id.clone();
    seed(tmp.path(), &[m]);
    let store = SqliteStore::open(tmp.path()).unwrap();
    let llm = StubLlm {
        kind: Some(MemoryKind::Decision),
    };

    let report = run_transcript_classify_pass(&store, &llm, "ai:curator-test", Some(NS), false, 0)
        .await
        .unwrap();

    assert_eq!(report.observations_scanned, 1);
    assert_eq!(report.classified, 1);
    assert_eq!(report.reclassified, 1);
    assert_eq!(kind_of(&store, &id).await, MemoryKind::Decision);
    assert_eq!(
        reclassified_audit_count(tmp.path()),
        1,
        "exactly one memory.reclassified audit row was emitted"
    );
}

#[tokio::test]
async fn abstain_is_noop() {
    let tmp = NamedTempFile::new().unwrap();
    let m = make_mem("recovered ambiguous turn", true, MemoryKind::Observation);
    let id = m.id.clone();
    seed(tmp.path(), &[m]);
    let store = SqliteStore::open(tmp.path()).unwrap();
    let llm = StubLlm { kind: None };

    let report = run_transcript_classify_pass(&store, &llm, "t", Some(NS), false, 0)
        .await
        .unwrap();

    assert_eq!(report.observations_scanned, 1);
    assert_eq!(report.classified, 0);
    assert_eq!(report.reclassified, 0);
    assert_eq!(report.abstained, 1);
    assert_eq!(kind_of(&store, &id).await, MemoryKind::Observation);
    assert_eq!(reclassified_audit_count(tmp.path()), 0);
}

#[tokio::test]
async fn non_recovered_observation_skipped() {
    let tmp = NamedTempFile::new().unwrap();
    // No recovered-from-transcript tag → not a candidate.
    let m = make_mem("ordinary observation", false, MemoryKind::Observation);
    let id = m.id.clone();
    seed(tmp.path(), &[m]);
    let store = SqliteStore::open(tmp.path()).unwrap();
    let llm = StubLlm {
        kind: Some(MemoryKind::Decision),
    };

    let report = run_transcript_classify_pass(&store, &llm, "t", Some(NS), false, 0)
        .await
        .unwrap();

    assert_eq!(
        report.observations_scanned, 0,
        "a non-recovered memory is never scanned"
    );
    assert_eq!(report.reclassified, 0);
    assert_eq!(kind_of(&store, &id).await, MemoryKind::Observation);
}

#[tokio::test]
async fn dry_run_does_not_write() {
    let tmp = NamedTempFile::new().unwrap();
    let m = make_mem("recovered dry-run turn", true, MemoryKind::Observation);
    let id = m.id.clone();
    seed(tmp.path(), &[m]);
    let store = SqliteStore::open(tmp.path()).unwrap();
    let llm = StubLlm {
        kind: Some(MemoryKind::Decision),
    };

    let report = run_transcript_classify_pass(&store, &llm, "t", Some(NS), true, 0)
        .await
        .unwrap();

    assert_eq!(
        report.classified, 1,
        "the would-be classification is computed"
    );
    assert_eq!(report.reclassified, 0, "dry_run suppresses the write");
    assert!(report.dry_run);
    assert_eq!(kind_of(&store, &id).await, MemoryKind::Observation);
    assert_eq!(reclassified_audit_count(tmp.path()), 0);
}

#[tokio::test]
async fn reclassify_protects_reflection_kind() {
    // The store-layer guard: a reflection-kind memory is never clobbered,
    // even by a direct `reclassify_memory_kind` call (mirrors the upsert CASE).
    let tmp = NamedTempFile::new().unwrap();
    let m = make_mem("a synthesised reflection", true, MemoryKind::Reflection);
    let id = m.id.clone();
    seed(tmp.path(), &[m]);
    let store = SqliteStore::open(tmp.path()).unwrap();
    let ctx = CallerContext::for_admin("t");

    let changed = store
        .reclassify_memory_kind(&ctx, &id, MemoryKind::Decision)
        .await
        .unwrap();

    assert!(
        !changed,
        "reflection kind is protected from reclassification"
    );
    assert_eq!(kind_of(&store, &id).await, MemoryKind::Reflection);
    assert_eq!(reclassified_audit_count(tmp.path()), 0);
}
