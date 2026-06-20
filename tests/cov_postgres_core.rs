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
        lifecycle_state: ai_memory::models::LifecycleState::Open,
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
        lifecycle_state: None,
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
async fn update_enforces_lifecycle_transition_1726() {
    // #1726 — postgres twin of the sqlite `trait_update_threads_lifecycle_state_1726`
    // test: the SAL `update` path must enforce the lifecycle transition
    // machine via `patch.lifecycle_state`. Legal open→active persists; illegal
    // open→done (skips active) is rejected with the typed
    // `StoreError::InvalidTransition` (→ HTTP 409). Skips without a live pg.
    use ai_memory::models::LifecycleState;
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-lc");

    // Legal: open -> active.
    let legal_id = uid("lc-legal");
    store
        .store(&ctx, &mem(&legal_id, &ns, "lc-legal", "lifecycle pg body"))
        .await
        .unwrap();
    let legal = UpdatePatch {
        lifecycle_state: Some(LifecycleState::Active),
        ..UpdatePatch::default()
    };
    store
        .update(&ctx, &legal_id, legal)
        .await
        .expect("open->active");
    assert_eq!(
        store.get(&ctx, &legal_id).await.unwrap().lifecycle_state,
        LifecycleState::Active,
        "a legal transition through the pg trait update path must persist"
    );

    // Illegal: open -> done on a fresh row.
    let illegal_id = uid("lc-illegal");
    store
        .store(
            &ctx,
            &mem(&illegal_id, &ns, "lc-illegal", "lifecycle pg body two"),
        )
        .await
        .unwrap();
    let illegal = UpdatePatch {
        lifecycle_state: Some(LifecycleState::Done),
        ..UpdatePatch::default()
    };
    let res = store.update(&ctx, &illegal_id, illegal).await;
    assert!(
        matches!(res, Err(StoreError::InvalidTransition { .. })),
        "open->done must be rejected with InvalidTransition, got: {res:?}"
    );
    assert_eq!(
        store.get(&ctx, &illegal_id).await.unwrap().lifecycle_state,
        LifecycleState::Open,
        "a rejected transition must leave the pg row untouched"
    );
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
    // `store()` commits synchronously (tx.commit().await before returning),
    // so a single read sees both committed rows — no retry needed. (An
    // earlier version retried on a read-after-write theory; the real cause of
    // the historical flake was a collation bug in `list_by_namespace_prefix`
    // — see `list_by_namespace_prefix_collation_boundary_pins_byte_range`
    // below — now fixed at the query layer with `~>=~`/`~<~`.)
    let listed = store
        .list_by_namespace_prefix(&ctx, &root, 50)
        .await
        .expect("prefix list");
    assert!(
        listed.iter().any(|m| m.id == id_a),
        "prefix must surface child alpha"
    );
    assert!(
        listed.iter().any(|m| m.id == id_b),
        "prefix must surface child beta"
    );
}

/// v0.8.0 #1709 SHIP-HARDEN — DETERMINISTIC regression pin for the
/// `list_by_namespace_prefix` collation bug. The root namespace's last byte
/// is forced to `'9'`, whose byte-incremented upper bound is `':'`. Under a
/// non-C (glibc `en_US.utf8`) database collation — the CI image + most stock
/// postgres deployments — `<root>/alpha` collates AFTER `':'`, so the pre-fix
/// `WHERE namespace >= $1 AND namespace < $2` predicate SILENTLY EXCLUDED the
/// child (the production data-loss bug; intermittent in the random-uuid test
/// above at ~1/16). The fix uses byte-ordered `~>=~`/`~<~`. This test fails on
/// the pre-fix query on any non-C DB and passes on the fix regardless of
/// collation, so it deterministically pins the byte-range semantics.
#[tokio::test]
async fn list_by_namespace_prefix_collation_boundary_pins_byte_range() {
    use ai_memory::store::MemoryStore;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    // Unique, but last byte forced to '9' (upper bound ':' — the glibc
    // punctuation-reweight boundary that drops `/alpha` under linguistic
    // collation).
    let root = format!("cov-coll-{}9", uuid::Uuid::new_v4().simple());
    let child_a = format!("{root}/alpha");
    let child_b = format!("{root}/beta");
    let id_a = uid("c1");
    let id_b = uid("c2");
    store
        .store(&ctx, &mem(&id_a, &child_a, "coll alpha", "body"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&id_b, &child_b, "coll beta", "body"))
        .await
        .unwrap();
    let listed = store
        .list_by_namespace_prefix(&ctx, &root, 50)
        .await
        .expect("prefix list");
    assert!(
        listed.iter().any(|m| m.id == id_a),
        "byte-range must surface `/alpha` even when the prefix ends in '9' \
         under a non-C collation (collation-bug regression pin)"
    );
    assert!(
        listed.iter().any(|m| m.id == id_b),
        "byte-range must surface `/beta` for a '9'-terminated prefix"
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

// ───────────────────────────────────────────────────────────────────
// consolidate (#1747 slice-3c1) — the pg consolidate path the store-backed
// curator ConsolidationPass depends on. Closes the cov_postgres_core
// consolidate coverage hole flagged by the 5-agent vote (4d3ea1c5).
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn consolidate_merges_and_hard_deletes_sources() {
    use ai_memory::store::{CallerContext, MemoryStore};
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ctx = CallerContext::for_admin("ai:cov-consolidate");
    let ns = uid("cons-ns");
    let a = uid("a");
    let b = uid("b");
    let dup = "kubernetes rolling canary deploy strategy notes pg consolidate";
    store
        .store(&ctx, &mem(&a, &ns, "t1", dup))
        .await
        .expect("store a");
    store
        .store(&ctx, &mem(&b, &ns, "t2", dup))
        .await
        .expect("store b");

    let new_id = store
        .consolidate(
            &ctx,
            &[a.clone(), b.clone()],
            "[consolidated] pg",
            "merged summary",
            &ns,
            &Tier::Mid,
            "ai-memory curator (autonomy)",
            "ai:cov-consolidate",
        )
        .await
        .expect("consolidate");

    // The consolidated row exists; both sources were hard-deleted (get →
    // NotFound). `MemoryStore::get` returns the row or errors, not an Option.
    store
        .get(&ctx, &new_id)
        .await
        .expect("consolidated row must exist");
    assert!(
        store.get(&ctx, &a).await.is_err(),
        "source a hard-deleted (get → NotFound)"
    );
    assert!(
        store.get(&ctx, &b).await.is_err(),
        "source b hard-deleted (get → NotFound)"
    );
}

// ───────────────────────────────────────────────────────────────────
// reverse_rollback_entry_store (#1748 slice-3c2) — postgres-backed
// reversal of a consolidation: the store-backed `curator --rollback`
// path. Postgres twin of the SQLite `reverse_consolidation_restores_
// originals` / the autonomy `reverse_rollback_entry_store_*_sqlite`
// unit tests. Decision provenance: 5-agent vote 4d3ea1c5 → Option B
// (free async fn over &dyn MemoryStore; memory ed85b972).
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn reverse_rollback_restores_consolidated_sources_pg() {
    use ai_memory::autonomy::{RollbackEntry, reverse_rollback_entry_store};
    use ai_memory::store::{CallerContext, MemoryStore};
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ctx = CallerContext::for_admin("ai:cov-rollback");
    let ns = uid("rb-ns");
    let a = uid("a");
    let b = uid("b");
    let dup = "kubernetes rolling canary deploy strategy notes pg rollback";
    let mem_a = mem(&a, &ns, "rb-t1", dup);
    let mem_b = mem(&b, &ns, "rb-t2", dup);
    store.store(&ctx, &mem_a).await.expect("store a");
    store.store(&ctx, &mem_b).await.expect("store b");

    let new_id = store
        .consolidate(
            &ctx,
            &[a.clone(), b.clone()],
            "[consolidated] pg rollback",
            "merged summary",
            &ns,
            &Tier::Mid,
            "ai-memory curator (autonomy)",
            "ai:cov-rollback",
        )
        .await
        .expect("consolidate");

    // Post-consolidation: summary present, both sources hard-deleted.
    store.get(&ctx, &new_id).await.expect("summary present");
    assert!(store.get(&ctx, &a).await.is_err(), "a gone pre-reverse");
    assert!(store.get(&ctx, &b).await.is_err(), "b gone pre-reverse");

    // Reverse through the SAL trait — what `--rollback --store-url
    // postgres://…` now dispatches to (#1748).
    let entry = RollbackEntry::Consolidate {
        originals: vec![mem_a, mem_b],
        result_id: new_id.clone(),
    };
    let applied = reverse_rollback_entry_store(&store, &ctx, &entry)
        .await
        .expect("reverse");
    assert!(applied, "summary existed → reverse applied");

    // Originals restored; summary removed.
    store.get(&ctx, &a).await.expect("a restored");
    store.get(&ctx, &b).await.expect("b restored");
    assert!(
        store.get(&ctx, &new_id).await.is_err(),
        "consolidated summary removed after reverse"
    );

    // Idempotent: a second reverse is a no-op (summary already gone).
    let again = reverse_rollback_entry_store(&store, &ctx, &entry)
        .await
        .expect("reverse again");
    assert!(!again, "summary already removed → no-op");

    // Cleanup.
    let _ = store.delete(&ctx, &a).await;
    let _ = store.delete(&ctx, &b).await;
}

// ───────────────────────────────────────────────────────────────────
// recover_turn_idempotent (#1693) — postgres L2 transcript-recovery
// parity. Proves a postgres-backed daemon can rehydrate from host
// transcripts (the gap #1693 closes): a turn writes a memory + dedup row
// on first recovery, and a re-recovery is an idempotent no-op (dedup_hit,
// no duplicate memory). The postgres twin of the sqlite recover path.
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn recover_turn_idempotent_writes_then_dedups_pg() {
    use ai_memory::models::RecoverTurnWrite;
    use ai_memory::store::{CallerContext, MemoryStore};
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov-recover");
    let ns = uid("rec-ns");
    let mid = uid("rec-mem");
    let norm_sha = format!("recnorm-{}", uuid::Uuid::new_v4()).into_bytes();
    let raw_sha = format!("recraw-{}", uuid::Uuid::new_v4()).into_bytes();
    let sid = uid("sess");

    let write = RecoverTurnWrite {
        memory: mem(
            &mid,
            &ns,
            "L2 recovered user turn pg",
            "operator directive recovered on pg",
        ),
        normalized_sha256: norm_sha.clone(),
        raw_sha256: raw_sha.clone(),
        host_kind: "claude-code".to_string(),
        transcript_path: "/host/transcript.jsonl".to_string(),
        host_session_id: Some(sid.clone()),
        host_turn_index: Some(7),
        recovered_at_ms: 1_700_000_000_000,
    };

    // First recovery → writes the memory + dedup row.
    let r1 = store
        .recover_turn_idempotent(&ctx, &write)
        .await
        .expect("first recover_turn");
    assert!(!r1.dedup_hit, "first recovery is a fresh write");
    store
        .get(&ctx, &r1.memory_id)
        .await
        .expect("recovered memory exists");

    // Re-recovery (same (sid,tix)) → idempotent no-op.
    let r2 = store
        .recover_turn_idempotent(&ctx, &write)
        .await
        .expect("second recover_turn");
    assert!(
        r2.dedup_hit,
        "re-recovery dedups on (host_session_id, host_turn_index)"
    );
    assert_eq!(
        r2.memory_id, r1.memory_id,
        "same memory id returned, no duplicate"
    );

    // Sha-only dedup path: a write with no (sid,tix) but the same normalized
    // sha must also dedup to the existing row.
    let sha_only = RecoverTurnWrite {
        memory: mem(
            &uid("rec-mem2"),
            &ns,
            "L2 recovered user turn pg 2",
            "different title same sha",
        ),
        normalized_sha256: norm_sha.clone(),
        raw_sha256: raw_sha.clone(),
        host_kind: "claude-code".to_string(),
        transcript_path: "/host/transcript.jsonl".to_string(),
        host_session_id: None,
        host_turn_index: None,
        recovered_at_ms: 1_700_000_000_001,
    };
    let r3 = store
        .recover_turn_idempotent(&ctx, &sha_only)
        .await
        .expect("sha-only recover_turn");
    assert!(
        r3.dedup_hit,
        "re-recovery dedups on content sha when (sid,tix) absent"
    );
    assert_eq!(r3.memory_id, r1.memory_id);

    // Cleanup.
    let _ = store.delete(&ctx, &r1.memory_id).await;
}
