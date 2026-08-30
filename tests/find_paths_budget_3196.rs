// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3196 — `find_paths` traversal-budget + write-plane de-stall, on
//! the SQLite SAL adapter (`SqliteStore`).
//!
//! Two properties the fix must guarantee, both exercised here:
//!
//! 1. **Bounded traversal (fail-closed).** A crafted dense graph explodes the
//!    path-prefix count past the materialised-prefix budget inside the depth
//!    ceiling; `find_paths` must REFUSE with the typed
//!    `StoreError::TraversalBudgetExceeded` rather than run an unbounded walk.
//!    Never a truncated result reported as complete.
//!
//! 2. **Write-plane de-stall.** `find_paths` now runs on a dedicated
//!    read-only connection, so a bounded-but-nontrivial traversal shares no
//!    mutex with the write plane: concurrent `memory_store` calls complete
//!    alongside it under WAL, with no deadlock, `SQLITE_BUSY`, or corruption.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::uninlined_format_args)]

use std::sync::Arc;

use ai_memory::models::{
    ConfidenceSource, LifecycleState, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier,
};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};
use tempfile::NamedTempFile;

fn mem(id: &str, ns: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: "body".to_string(),
        tags: vec!["fp3196".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "fp3196".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": "ai:fp3196" }),
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

fn link(src: &str, tgt: &str) -> MemoryLink {
    MemoryLink {
        source_id: src.to_string(),
        target_id: tgt.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: None,
        valid_from: Some(chrono::Utc::now().to_rfc3339()),
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

/// Seed an `n`-node complete graph (clique) and return the node ids. A clique
/// is the worst case for path enumeration: from any source the simple-path
/// count grows like `(n-1)(n-2)…`, blowing past the prefix budget within the
/// depth ceiling.
async fn seed_clique(store: &SqliteStore, ctx: &CallerContext, ns: &str, n: usize) -> Vec<String> {
    let ids: Vec<String> = (0..n).map(|i| format!("{ns}-node-{i}")).collect();
    for (i, id) in ids.iter().enumerate() {
        store
            .store(ctx, &mem(id, ns, &format!("clique {i}")))
            .await
            .expect("seed store");
    }
    for i in 0..n {
        for j in (i + 1)..n {
            store
                .link(ctx, &link(&ids[i], &ids[j]))
                .await
                .expect("seed link");
        }
    }
    ids
}

#[tokio::test]
async fn find_paths_dense_clique_refuses_with_budget_3196() {
    let f = NamedTempFile::new().expect("tempfile");
    let store = SqliteStore::open(f.path()).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("ai:fp3196");
    let ids = seed_clique(&store, &ctx, "budget", 14).await;

    // A depth-7 traversal on the clique explodes past the prefix budget →
    // typed refusal, byte-parity with the postgres twin.
    let err = MemoryStore::find_paths(&store, &ctx, &ids[0], &ids[13], Some(7), Some(50))
        .await
        .expect_err("dense clique at depth 7 must trip the prefix budget");
    assert!(
        matches!(err, StoreError::TraversalBudgetExceeded { .. }),
        "expected TraversalBudgetExceeded, got: {err:?}"
    );
    assert!(
        err.to_string().contains("FIND_PATHS_MAX_PREFIXES"),
        "refusal must name the budget knob: {err}"
    );

    // Within budget on the SAME dense fixture: a depth-1 lookup still resolves
    // the direct edge (the budget refuses only the explosive traversal).
    let shallow = MemoryStore::find_paths(&store, &ctx, &ids[0], &ids[1], Some(1), Some(5))
        .await
        .expect("depth-1 lookup stays within budget");
    assert!(
        shallow
            .iter()
            .any(|p| p == &vec![ids[0].clone(), ids[1].clone()]),
        "direct edge must be enumerated within budget"
    );
}

/// The write-plane de-stall property: a budget-tripping `find_paths` runs on
/// the dedicated read-only connection concurrently with a burst of
/// `memory_store` writes on the writer connection. All writes must succeed and
/// the traversal must return its typed refusal — proving the read traversal
/// and the write plane operate on independent connections under WAL, with no
/// deadlock, `SQLITE_BUSY`, or corruption.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn find_paths_does_not_stall_concurrent_writes_3196() {
    let f = NamedTempFile::new().expect("tempfile");
    let store = Arc::new(SqliteStore::open(f.path()).expect("open SqliteStore"));
    let ctx = CallerContext::for_agent("ai:fp3196");
    let ids = seed_clique(&store, &ctx, "destall", 14).await;

    // Spawn the explosive traversal on its own task.
    let traversal_store = Arc::clone(&store);
    let traversal_ctx = ctx.clone();
    let src = ids[0].clone();
    let dst = ids[13].clone();
    let traversal = tokio::spawn(async move {
        MemoryStore::find_paths(
            &*traversal_store,
            &traversal_ctx,
            &src,
            &dst,
            Some(7),
            Some(50),
        )
        .await
    });

    // Concurrently drive a burst of writes on the writer connection.
    let mut writes = Vec::new();
    for i in 0..25 {
        let write_store = Arc::clone(&store);
        let write_ctx = ctx.clone();
        writes.push(tokio::spawn(async move {
            write_store
                .store(
                    &write_ctx,
                    &mem(&format!("concurrent-{i}"), "destall-w", "w"),
                )
                .await
        }));
    }

    for (i, w) in writes.into_iter().enumerate() {
        let id = w
            .await
            .expect("write task join")
            .expect("concurrent write must succeed");
        assert!(!id.is_empty(), "write {i} returned an id");
    }

    let outcome = traversal.await.expect("traversal task join");
    assert!(
        matches!(outcome, Err(StoreError::TraversalBudgetExceeded { .. })),
        "the bounded traversal must still refuse, got: {outcome:?}"
    );
}
