// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Coverage agent cov4 — live-Postgres integration coverage for the
//! `PostgresStore` SAL adapter CRUD / batch / embedding / federation /
//! recall surfaces (`src/store/postgres.rs`).
//!
//! Per the operator-standard 90% per-module floor (2026-06-11), this
//! suite drives the trait + inherent methods against a real
//! Postgres+AGE instance so every live-pg code path is exercised. The
//! suite is gated on `AI_MEMORY_TEST_POSTGRES_URL`; when unset it skips
//! cleanly (the skip-if-unset pattern shared by
//! `tests/store_parity_gaps.rs` / `tests/serve_postgres_continuation2.rs`).
//!
//! Per-run ids are uuid-randomized so the suite is rerunnable against a
//! persistent DB without pkey / `(title, namespace)` upsert collisions.

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::uninlined_format_args,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]

use ai_memory::models::{
    ConfidenceSource, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier,
};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, Filter, StoreError, UpdatePatch, VerifyFilter};

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

async fn connect() -> Option<PostgresStore> {
    let url = postgres_url()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

fn mem(id: &str, ns: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["covtest".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "cov4-integration".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id":"ai:cov4"}),
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
    }
}

// ───────────────────────────────────────────────────────────────────
// store / store_with_embedding / store_batch
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn store_with_embedding_then_update_embedding_roundtrip() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-emb");
    let id = uid("emb");
    let m = mem(&id, &ns, "embedded memory", "vector body covtest");
    // store_with_embedding persists the inline vector (#1608 path).
    // The connected DB's embedding column dim is resolved at runtime so
    // the test rides whatever pgvector dim the fixture was built with.
    let dim_i32 = store
        .current_embedding_dim()
        .await
        .expect("current_embedding_dim")
        .unwrap_or(384);
    let dim = usize::try_from(dim_i32).unwrap_or(384);
    let vec: Vec<f32> = (0..dim).map(|i| (i as f32) * 0.001).collect();
    let returned = store
        .store_with_embedding(&ctx, &m, Some(&vec))
        .await
        .expect("store_with_embedding");
    assert_eq!(returned, id);
    // update_embedding clears + resets the vector.
    store
        .update_embedding(&ctx, &id, None)
        .await
        .expect("clear embedding");
    let vec2: Vec<f32> = (0..dim).map(|i| (i as f32) * 0.002).collect();
    store
        .update_embedding(&ctx, &id, Some(&vec2))
        .await
        .expect("reset embedding");
    let got = store.get(&ctx, &id).await.expect("get");
    assert_eq!(got.title, "embedded memory");
}

#[tokio::test]
async fn store_batch_upserts_all_rows_in_order() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-batch");
    let rows: Vec<Memory> = (0..5)
        .map(|i| {
            mem(
                &uid("batch"),
                &ns,
                &format!("batch title {i}"),
                "batch body",
            )
        })
        .collect();
    let ids = store.store_batch(&ctx, &rows).await.expect("store_batch");
    assert_eq!(ids.len(), 5);
    let filter = Filter {
        namespace: Some(ns.clone()),
        limit: 50,
        ..Filter::default()
    };
    let listed = store.list(&ctx, &filter).await.expect("list");
    assert_eq!(listed.len(), 5);
}

#[tokio::test]
async fn store_batch_empty_is_noop() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ids = store.store_batch(&ctx, &[]).await.expect("empty batch");
    assert!(ids.is_empty());
}

#[tokio::test]
async fn store_batch_collapses_duplicate_title_namespace() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-batch-dup");
    let rows = vec![
        mem(&uid("d1"), &ns, "same title", "first body"),
        mem(&uid("d2"), &ns, "same title", "second body"),
    ];
    let ids = store.store_batch(&ctx, &rows).await.expect("batch dup");
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], ids[1], "duplicate (title, ns) collapse to one id");
}

// ───────────────────────────────────────────────────────────────────
// get / update / update_with_expected_version / delete
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn update_all_patch_fields() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-upd");
    let id = uid("upd");
    store
        .store(&ctx, &mem(&id, &ns, "before", "before body"))
        .await
        .unwrap();
    let patch = UpdatePatch {
        title: Some("after".to_string()),
        content: Some("after body".to_string()),
        tier: Some(Tier::Long),
        tags: Some(vec!["a".to_string(), "b".to_string()]),
        priority: Some(8),
        confidence: Some(0.5),
        metadata: Some(serde_json::json!({"agent_id":"ai:cov4","note":"x"})),
        source_uri: Some("doc:cov4".to_string()),
        expires_at: None,
        namespace: None,
    };
    store.update(&ctx, &id, patch).await.expect("update");
    let got = store.get(&ctx, &id).await.unwrap();
    assert_eq!(got.title, "after");
    assert_eq!(got.priority, 8);
    assert!(matches!(got.tier, Tier::Long));
}

#[tokio::test]
async fn update_nonexistent_returns_not_found() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let res = store
        .update(&ctx, &uid("ghost"), UpdatePatch::default())
        .await;
    assert!(matches!(res, Err(StoreError::NotFound { .. })));
}

#[tokio::test]
async fn update_with_expected_version_conflict_and_success() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-ver");
    let id = uid("ver");
    {
        use ai_memory::store::MemoryStore;
        store
            .store(&ctx, &mem(&id, &ns, "versioned", "v1 body"))
            .await
            .unwrap();
    }
    // Correct expected version (1) succeeds.
    let patch = UpdatePatch {
        content: Some("v2 body".to_string()),
        ..UpdatePatch::default()
    };
    store
        .update_with_expected_version(&ctx, &id, patch, Some(1))
        .await
        .expect("version match update");
    // Stale expected version now conflicts.
    let patch2 = UpdatePatch {
        content: Some("v3 body".to_string()),
        ..UpdatePatch::default()
    };
    let res = store
        .update_with_expected_version(&ctx, &id, patch2, Some(1))
        .await;
    assert!(res.is_err(), "stale version must conflict");
}

#[tokio::test]
async fn delete_nonexistent_returns_not_found() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let res = store.delete(&ctx, &uid("ghost")).await;
    assert!(matches!(res, Err(StoreError::NotFound { .. })));
}

// ───────────────────────────────────────────────────────────────────
// list / list_by_namespace_prefix / search / recall_hybrid /
// touch_after_recall
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_by_namespace_prefix_groups_children() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let root = uid("cov-prefix");
    let child_a = format!("{root}/alpha");
    let child_b = format!("{root}/beta");
    let id_a = uid("p1");
    let id_b = uid("p2");
    store
        .store(&ctx, &mem(&id_a, &child_a, "alpha mem", "body"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&id_b, &child_b, "beta mem", "body"))
        .await
        .unwrap();
    // Bounded read-retry: under `--test-threads=2` against a shared
    // persistent DB the sqlx pool can momentarily lag a just-committed
    // write; the uuid-unique root means only these two children can ever
    // match, so retry until both appear (or give up after a few tries
    // and let the assertion fail loudly).
    let mut listed = Vec::new();
    for _ in 0..5 {
        listed = store
            .list_by_namespace_prefix(&ctx, &root, 50)
            .await
            .expect("prefix list");
        if listed.iter().any(|m| m.id == id_a) && listed.iter().any(|m| m.id == id_b) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        listed.iter().any(|m| m.id == id_a),
        "prefix must surface child alpha"
    );
    assert!(
        listed.iter().any(|m| m.id == id_b),
        "prefix must surface child beta"
    );
}

#[tokio::test]
async fn recall_hybrid_returns_scored_results() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-recall");
    let token = format!("ztok{}", uuid::Uuid::new_v4().simple());
    let id = uid("rec");
    store
        .store(
            &ctx,
            &mem(&id, &ns, &token, &format!("body with {token} marker")),
        )
        .await
        .unwrap();
    let filter = Filter {
        namespace: Some(ns.clone()),
        limit: 5,
        ..Filter::default()
    };
    let scored = store
        .recall_hybrid(&ctx, &token, None, &filter)
        .await
        .expect("recall_hybrid");
    assert!(scored.iter().any(|(m, _)| m.id == id));
    // touch_after_recall mutates access_count + TTL.
    store
        .touch_after_recall(std::slice::from_ref(&id))
        .await
        .expect("touch");
    let got = store.get(&ctx, &id).await.unwrap();
    assert!(got.access_count >= 1, "touch increments access_count");
}

#[tokio::test]
async fn search_empty_namespace_returns_no_hits() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-empty");
    let filter = Filter {
        namespace: Some(ns),
        limit: 5,
        ..Filter::default()
    };
    let hits = store
        .search(&ctx, "nothingmatcheshere", &filter)
        .await
        .expect("search empty");
    assert!(hits.is_empty());
}

// ───────────────────────────────────────────────────────────────────
// link / link_signed / list_links / get_links_for_anchor /
// invalidate_link / verify_link
// ───────────────────────────────────────────────────────────────────

fn link(src: &str, tgt: &str) -> MemoryLink {
    MemoryLink {
        source_id: src.to_string(),
        target_id: tgt.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: None,
        valid_from: None,
        valid_until: None,
        attest_level: None,
    }
}

#[tokio::test]
async fn link_list_links_get_links_for_anchor_and_invalidate() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-link");
    let a = uid("la");
    let b = uid("lb");
    store
        .store(&ctx, &mem(&a, &ns, "node a", "abody"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&b, &ns, "node b", "bbody"))
        .await
        .unwrap();
    store.link(&ctx, &link(&a, &b)).await.expect("link");

    let links = store.list_links(Some(&ns)).await.expect("list_links");
    assert!(links.iter().any(|l| l.source_id == a && l.target_id == b));

    let anchored = store
        .get_links_for_anchor(&a)
        .await
        .expect("get_links_for_anchor");
    assert!(anchored.iter().any(|l| l.target_id == b));

    // verify_link surfaces the unsigned link.
    let report = store
        .verify_link(VerifyFilter {
            source_id: Some(a.clone()),
            target_id: Some(b.clone()),
            link_id: None,
        })
        .await
        .expect("verify_link");
    assert_eq!(report.source_id, a);
    assert_eq!(report.attest_level, "unsigned");

    // invalidate_link marks the row found.
    let inv = store
        .invalidate_link(&a, &b, "related_to", None)
        .await
        .expect("invalidate_link");
    assert!(inv.found, "existing link must be found on invalidate");

    // invalidate of an unknown triple returns found=false.
    let miss = store
        .invalidate_link(&uid("x"), &uid("y"), "related_to", None)
        .await
        .expect("invalidate miss");
    assert!(!miss.found);
}

#[tokio::test]
async fn link_signed_lands_attest_level() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-linksig");
    let a = uid("sa");
    let b = uid("sb");
    store
        .store(&ctx, &mem(&a, &ns, "sig a", "body"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&b, &ns, "sig b", "body"))
        .await
        .unwrap();
    let level = store
        .link_signed(&ctx, &link(&a, &b), None)
        .await
        .expect("link_signed");
    assert!(!level.is_empty());
}

// ───────────────────────────────────────────────────────────────────
// federation: apply_remote_memory / apply_remote_link /
// apply_remote_deletion / list_memories_updated_since
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn apply_remote_memory_link_deletion_and_list_since() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-fed");
    let a = uid("fa");
    let b = uid("fb");
    // Capture a watermark BEFORE the writes so the catch-up scan window
    // is small + deterministic against a persistent DB (exercises the
    // sargable `Some(since)` predicate arm, #1476).
    let watermark = (chrono::Utc::now() - chrono::Duration::seconds(5)).to_rfc3339();
    let remote_a = store
        .apply_remote_memory(&ctx, &mem(&a, &ns, "remote a", "rbody"))
        .await
        .expect("apply_remote_memory a");
    let remote_b = store
        .apply_remote_memory(&ctx, &mem(&b, &ns, "remote b", "rbody"))
        .await
        .expect("apply_remote_memory b");

    // Re-apply same memory (older-or-equal updated_at) is an idempotent noop.
    let again = store
        .apply_remote_memory(&ctx, &mem(&a, &ns, "remote a", "rbody"))
        .await
        .expect("re-apply idempotent");
    assert_eq!(again, remote_a);

    store
        .apply_remote_link(&ctx, &link(&remote_a, &remote_b), "unsigned")
        .await
        .expect("apply_remote_link");

    let since = store
        .list_memories_updated_since(Some(&watermark), 1000)
        .await
        .expect("list_memories_updated_since");
    assert!(since.iter().any(|m| m.id == remote_a));
    // Also exercise the `None` (no-predicate) arm of the #1476 split.
    let _ = store
        .list_memories_updated_since(None, 50)
        .await
        .expect("list_memories_updated_since none arm");

    // apply_remote_deletion returns true on hit, false on miss.
    let removed = store
        .apply_remote_deletion(&ctx, &remote_a)
        .await
        .expect("apply_remote_deletion hit");
    assert!(removed);
    let removed_again = store
        .apply_remote_deletion(&ctx, &remote_a)
        .await
        .expect("apply_remote_deletion miss");
    assert!(!removed_again);
}

// ───────────────────────────────────────────────────────────────────
// export / verify
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn export_memories_and_links_and_verify() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-export");
    let a = uid("ea");
    let b = uid("eb");
    store
        .store(&ctx, &mem(&a, &ns, "exp a", "body"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&b, &ns, "exp b", "body"))
        .await
        .unwrap();
    store.link(&ctx, &link(&a, &b)).await.unwrap();

    let mems = store.export_memories().await.expect("export_memories");
    assert!(mems.iter().any(|m| m.id == a));
    let links = store.export_links().await.expect("export_links");
    assert!(links.iter().any(|l| l.source_id == a && l.target_id == b));

    let report = store.verify(&ctx, &a).await.expect("verify");
    assert_eq!(report.memory_id, a);
}
