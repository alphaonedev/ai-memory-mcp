// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3280 — `SqliteStore::store_with_embedding_no_overwrite` must not commit
//! the memory row before validating `embedding_space`. Pre-fix the insert ran
//! in autocommit; a None/blank space then returned `InvalidInput`, leaving an
//! orphan that poisoned the retry with `Conflict`. rust-1.98 ERRORS-09 /
//! PERF-15: validate the invariant at the boundary before persist.

#![allow(clippy::missing_panics_doc, clippy::uninlined_format_args)]
#![cfg(feature = "sal")]

use ai_memory::models::{
    ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier,
};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};

fn mem(id: &str, ns: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["orphan-3280".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test-3280".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": "ai:tester" }),
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

fn row_count(path: &std::path::Path, title: &str, ns: &str) -> i64 {
    let conn = rusqlite::Connection::open(path).expect("open raw");
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE title = ?1 AND namespace = ?2",
        rusqlite::params![title, ns],
        |r| r.get(0),
    )
    .expect("count")
}

#[tokio::test]
async fn sqlite_no_overwrite_missing_space_leaves_no_orphan_3280() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("m.db");
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("ai:tester");
    let ns = "ns/3280";
    let title = "shared-title-3280";
    let embedding = [0.1_f32, 0.2, 0.3];

    let first = mem("id-3280-a", ns, title, "first attempt");
    let err = store
        .store_with_embedding_no_overwrite(&ctx, &first, Some(&embedding), None)
        .await
        .expect_err("missing space must refuse");
    assert!(
        matches!(err, StoreError::InvalidInput { .. }),
        "missing space must be InvalidInput, got {err:?}"
    );
    assert_eq!(
        row_count(&path, title, ns),
        0,
        "refused create must leave no orphan row"
    );

    let retry = mem("id-3280-a", ns, title, "retry with space");
    let id = store
        .store_with_embedding_no_overwrite(&ctx, &retry, Some(&embedding), Some("space-3280"))
        .await
        .expect("retry after space refusal must succeed (no Conflict from an orphan)");
    assert_eq!(id, "id-3280-a");
    assert_eq!(row_count(&path, title, ns), 1);
}

#[tokio::test]
async fn sqlite_no_overwrite_blank_space_leaves_no_orphan_3280() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("m.db");
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("ai:tester");
    let ns = "ns/3280-blank";
    let title = "blank-space-3280";
    let embedding = [0.1_f32, 0.2];

    let first = mem("id-3280-blank", ns, title, "blank stamp");
    let err = store
        .store_with_embedding_no_overwrite(&ctx, &first, Some(&embedding), Some("   "))
        .await
        .expect_err("whitespace-only space must refuse");
    assert!(
        matches!(err, StoreError::InvalidInput { .. }),
        "blank space must be InvalidInput, got {err:?}"
    );
    assert_eq!(row_count(&path, title, ns), 0);
}

#[tokio::test]
async fn sqlite_no_overwrite_dim_mismatch_rolls_back_orphan_3280() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("m.db");
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("ai:tester");
    let ns = "ns/3280-dim";

    let established = mem("id-3280-dim-a", ns, "established", "dim-2 row");
    store
        .store_with_embedding_no_overwrite(
            &ctx,
            &established,
            Some(&[0.1_f32, 0.2]),
            Some("space-3280"),
        )
        .await
        .expect("establish namespace dim=2");
    assert_eq!(row_count(&path, "mismatch-title", ns), 0);

    let mismatch = mem("id-3280-dim-b", ns, "mismatch-title", "dim-3 attempt");
    let err = store
        .store_with_embedding_no_overwrite(
            &ctx,
            &mismatch,
            Some(&[0.1_f32, 0.2, 0.3]),
            Some("space-3280"),
        )
        .await
        .expect_err("dim mismatch must refuse");
    assert!(
        !matches!(err, StoreError::Conflict { .. }),
        "dim-mismatch must not surface as Conflict, got {err:?}"
    );
    assert_eq!(
        row_count(&path, "mismatch-title", ns),
        0,
        "dim-mismatch after insert must roll the orphan back"
    );
}
