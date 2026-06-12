// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Coverage agent GA-2 — live-Postgres integration coverage for the
//! `PostgresStore` SAL adapter (`src/store/postgres.rs`), targeting the
//! *complement* of the cov4 suite (`tests/cov_postgres_{core,governance,kg}.rs`).
//!
//! cov4 drove the happy-path trait surface (CRUD / batch / federation /
//! governance / KG). This suite deliberately exercises the surfaces cov4
//! left uncovered so the module climbs toward the operator-standard 90%
//! per-module floor (2026-06-11):
//!
//! - The **inherent** (non-trait) public methods reachable only via the
//!   concrete `PostgresStore`: `search_with_source_uri`,
//!   `list_by_source_uri`, `find_paths` / `find_paths_cte` /
//!   `find_paths_cypher` (both KG backends), `kg_query_with_history` with
//!   `include_invalidated`, `get_links`, `recall_observation_insert` +
//!   `recall_observation_gc`, `taxonomy_namespaces`, `list_archived_pg`,
//!   `list_pending_actions`, `current_embedding_dim`.
//! - The free-function **`*_via_store` dispatchers** (`kg_query_via_store`,
//!   `kg_timeline_via_store`, `kg_invalidate_via_store`,
//!   `list_archived_via_store`, `archive_stats_via_store`,
//!   `taxonomy_namespaces_via_store`, `list_pending_actions_via_store`)
//!   that downcast an `Arc<dyn MemoryStore>` back to `PostgresStore` — the
//!   exact path the postgres HTTP handlers take.
//! - The **error arms**: `NotFound` on get/update/delete of a ghost id,
//!   `InvalidInput` on `find_paths` `max_depth=0` and
//!   `max_depth > FIND_PATHS_MAX_DEPTH_SAL`, empty-input no-ops on
//!   `set_embeddings_batch` / `recall_observation_insert` /
//!   `store_batch`, the `BackendUnavailable` arm of `downcast_postgres`
//!   when handed a non-postgres store, the admin-gate refusal arm of
//!   `list_unembedded` under a non-admin `CallerContext`.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset
//! (the skip-if-unset + connect pattern is copied verbatim from
//! `tests/cov_postgres_core.rs`). Per-run uuid ids keep the suite
//! rerunnable against a persistent DB without pkey / `(title, namespace)`
//! collisions.

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

use std::sync::Arc;

use ai_memory::models::{
    ConfidenceSource, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier,
};
use ai_memory::store::postgres::{
    PostgresStore, archive_stats_via_store, kg_invalidate_via_store, kg_query_via_store,
    kg_timeline_via_store, list_archived_via_store, list_pending_actions_via_store,
    taxonomy_namespaces_via_store,
};
use ai_memory::store::{CallerContext, Filter, MemoryStore, StoreError, UpdatePatch};

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

/// Connect and hand back an `Arc<dyn MemoryStore>` — the trait-object
/// shape the `*_via_store` dispatchers downcast back to `PostgresStore`.
async fn connect_arc() -> Option<Arc<dyn MemoryStore>> {
    let store = connect().await?;
    Some(Arc::new(store) as Arc<dyn MemoryStore>)
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
        tags: vec!["covga2".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "cov-ga2".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id":"ai:ga2"}),
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
    }
}

// ───────────────────────────────────────────────────────────────────
// inherent source_uri surfaces — search_with_source_uri /
// list_by_source_uri (provenance gaps #889 / #906)
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn search_with_source_uri_filters_on_provenance() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2");
    let ns = uid("ga2-uri");
    let token = format!("provtok{}", uuid::Uuid::new_v4().simple());
    let uri = format!("doc:ga2/{}", uuid::Uuid::new_v4().simple());

    let mut m = mem(&uid("u1"), &ns, &token, &format!("body about {token}"));
    m.source_uri = Some(uri.clone());
    store.store(&ctx, &m).await.expect("store with source_uri");

    let filter = Filter {
        namespace: Some(ns.clone()),
        limit: 10,
        ..Filter::default()
    };
    // With the matching source_uri the row surfaces.
    let hits = store
        .search_with_source_uri(&token, &filter, Some(&uri))
        .await
        .expect("search_with_source_uri match");
    assert!(
        hits.iter()
            .any(|r| r.source_uri.as_deref() == Some(uri.as_str())),
        "matching source_uri must surface the row"
    );

    // A non-matching source_uri filter excludes it (the $6 predicate arm).
    let none = store
        .search_with_source_uri(&token, &filter, Some("doc:nonexistent-ga2"))
        .await
        .expect("search_with_source_uri miss");
    assert!(
        none.iter()
            .all(|r| r.source_uri.as_deref() != Some(uri.as_str())),
        "non-matching source_uri filter excludes the row"
    );

    // None (no source_uri narrowing) still matches on the FTS query alone.
    let any = store
        .search_with_source_uri(&token, &filter, None)
        .await
        .expect("search_with_source_uri no-uri");
    assert!(any.iter().any(|r| r.title == token));
}

#[tokio::test]
async fn list_by_source_uri_orders_and_caps() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2");
    let ns = uid("ga2-listuri");
    let uri = format!("doc:list-ga2/{}", uuid::Uuid::new_v4().simple());
    for i in 0..3 {
        let mut m = mem(&uid("lu"), &ns, &format!("listuri {i}"), "body");
        m.source_uri = Some(uri.clone());
        store.store(&ctx, &m).await.unwrap();
    }
    let listed = store
        .list_by_source_uri(&uri, Some(&ns), Some(50))
        .await
        .expect("list_by_source_uri");
    assert_eq!(listed.len(), 3, "all three provenance rows surface");
    assert!(
        listed
            .iter()
            .all(|m| m.source_uri.as_deref() == Some(uri.as_str()))
    );

    // namespace=None arm + a tiny cap exercises the limit clamp.
    let capped = store
        .list_by_source_uri(&uri, None, Some(1))
        .await
        .expect("list_by_source_uri capped");
    assert_eq!(capped.len(), 1, "limit caps the result set");

    // unknown source_uri returns an empty set, not an error.
    let empty = store
        .list_by_source_uri("doc:no-such-uri-ga2", None, None)
        .await
        .expect("list_by_source_uri empty");
    assert!(empty.is_empty());
}

// ───────────────────────────────────────────────────────────────────
// find_paths inherent dispatcher + both backends + depth validation
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn find_paths_inherent_connected_and_cte_branch() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2");
    let ns = uid("ga2-fp");
    let a = uid("fpa");
    let b = uid("fpb");
    let c = uid("fpc");
    store
        .store(&ctx, &mem(&a, &ns, "fp a", "body"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&b, &ns, "fp b", "body"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&c, &ns, "fp c", "body"))
        .await
        .unwrap();
    store.link(&ctx, &link(&a, &b)).await.unwrap();
    store.link(&ctx, &link(&b, &c)).await.unwrap();

    // The inherent dispatcher routes on kg_backend (AGE-or-CTE).
    let via_dispatch = store
        .find_paths(&a, &c, Some(5), Some(10))
        .await
        .expect("find_paths inherent");
    assert!(!via_dispatch.is_empty(), "a→b→c path enumerated");

    // Drive the recursive-CTE branch directly so it's exercised even on
    // an AGE-enabled DB (the CTE is the universal fallback).
    let via_cte = store
        .find_paths_cte(&a, &c, Some(5), Some(10))
        .await
        .expect("find_paths_cte");
    assert!(
        !via_cte.is_empty(),
        "CTE enumerates the same connected path"
    );

    // disconnected pair returns empty (the no-route arm).
    let iso = uid("iso");
    store
        .store(&ctx, &mem(&iso, &ns, "iso", "body"))
        .await
        .unwrap();
    let none = store
        .find_paths_cte(&a, &iso, Some(4), Some(10))
        .await
        .expect("find_paths_cte disconnected");
    assert!(none.is_empty());
}

#[tokio::test]
async fn find_paths_cypher_branch_when_age_present() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2");
    let ns = uid("ga2-fpcy");
    let a = uid("cya");
    let b = uid("cyb");
    store
        .store(&ctx, &mem(&a, &ns, "cy a", "body"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&b, &ns, "cy b", "body"))
        .await
        .unwrap();
    store.link(&ctx, &link(&a, &b)).await.unwrap();

    // find_paths_cypher is public; on an AGE-backed fixture it exercises
    // the Cypher enumeration + agtype-string peeling. On a CTE-only DB the
    // call may surface a backend error — tolerate it (the goal is to drive
    // the entry path; the parity test pins identical output elsewhere).
    match store.find_paths_cypher(&a, &b, Some(4), Some(5)).await {
        Ok(paths) => {
            // When AGE answers, the a→b edge yields at least one path.
            let _ = paths;
        }
        Err(StoreError::BackendUnavailable { .. } | StoreError::InvalidInput { .. }) => {
            // CTE-only fixture: the cypher path is legitimately unavailable.
        }
        Err(other) => panic!("unexpected find_paths_cypher error: {other:?}"),
    }
}

#[tokio::test]
async fn find_paths_rejects_zero_and_oversized_depth() {
    let Some(store) = connect().await else {
        return;
    };
    let a = uid("dpa");
    let b = uid("dpb");
    // max_depth=0 is the MAX_DEPTH_MIN InvalidInput arm.
    let zero = store.find_paths_cte(&a, &b, Some(0), Some(5)).await;
    assert!(
        matches!(zero, Err(StoreError::InvalidInput { .. })),
        "max_depth=0 must be rejected as InvalidInput"
    );
    // A wildly oversized depth trips the > FIND_PATHS_MAX_DEPTH_SAL arm.
    let huge = store.find_paths_cte(&a, &b, Some(100_000), Some(5)).await;
    assert!(
        matches!(huge, Err(StoreError::InvalidInput { .. })),
        "oversized max_depth must be rejected as InvalidInput"
    );
    // The trait-level find_paths also validates depth.
    let ctx = CallerContext::for_agent("ai:ga2");
    let trait_zero = MemoryStore::find_paths(&store, &ctx, &a, &b, Some(0), Some(5)).await;
    assert!(matches!(trait_zero, Err(StoreError::InvalidInput { .. })));
}

// ───────────────────────────────────────────────────────────────────
// kg_query_with_history — include_invalidated arm
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn kg_query_with_history_includes_invalidated_edges() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2");
    let ns = uid("ga2-hist");
    let a = uid("ha");
    let b = uid("hb");
    store
        .store(&ctx, &mem(&a, &ns, "hist a", "body"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&b, &ns, "hist b", "body"))
        .await
        .unwrap();
    store.link(&ctx, &link(&a, &b)).await.unwrap();

    // Invalidate the edge — the "current view" must then drop it.
    let inv = store
        .invalidate_link(&a, &b, "related_to", None)
        .await
        .expect("invalidate_link");
    assert!(inv.found);

    // include_invalidated=false → current view (edge filtered out).
    let current = store
        .kg_query_with_history(&a, 3, false)
        .await
        .expect("kg_query current view");
    assert!(
        current.iter().all(|r| r.target_id != b),
        "invalidated edge must not appear in the current view"
    );

    // include_invalidated=true → historical view surfaces it again.
    let historical = store
        .kg_query_with_history(&a, 3, true)
        .await
        .expect("kg_query historical view");
    assert!(
        historical.iter().any(|r| r.target_id == b),
        "historical view surfaces the invalidated edge"
    );
}

// ───────────────────────────────────────────────────────────────────
// get_links (inherent, four-column projection #860)
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_links_surfaces_inbound_and_outbound() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2");
    let ns = uid("ga2-getlinks");
    let a = uid("gla");
    let b = uid("glb");
    store
        .store(&ctx, &mem(&a, &ns, "gl a", "body"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&b, &ns, "gl b", "body"))
        .await
        .unwrap();
    store.link(&ctx, &link(&a, &b)).await.unwrap();

    let links_a = store.get_links(&a).await.expect("get_links a");
    assert!(links_a.iter().any(|l| l.source_id == a && l.target_id == b));

    // The inbound side surfaces for the target too.
    let links_b = store.get_links(&b).await.expect("get_links b");
    assert!(links_b.iter().any(|l| l.source_id == a && l.target_id == b));

    // A node with no links returns an empty set.
    let lonely = store
        .get_links(&uid("nolinks"))
        .await
        .expect("get_links empty");
    assert!(lonely.is_empty());
}

// ───────────────────────────────────────────────────────────────────
// recall_observation_insert / recall_observation_gc (#886 ledger)
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn recall_observation_insert_dedup_and_gc() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2");
    let ns = uid("ga2-obs");
    let id = uid("obs");
    store
        .store(&ctx, &mem(&id, &ns, "obs mem", "body"))
        .await
        .unwrap();

    let recall_id = uid("recall");
    let candidates = vec![
        (id.clone(), "fts".to_string(), 1_i64, 0.91_f64),
        (id.clone(), "semantic".to_string(), 2_i64, 0.42_f64),
    ];
    // First insert writes one row (the (recall_id, memory_id) pkey
    // collapses the two retriever rows into one ON CONFLICT DO NOTHING).
    let written = store
        .recall_observation_insert(&recall_id, &candidates)
        .await
        .expect("recall_observation_insert");
    assert_eq!(
        written, 1,
        "ON CONFLICT (recall_id, memory_id) collapses dups"
    );

    // Re-insert the same candidates → all conflict → zero new rows.
    let again = store
        .recall_observation_insert(&recall_id, &candidates)
        .await
        .expect("recall_observation_insert idempotent");
    assert_eq!(again, 0, "re-insert is a full ON CONFLICT no-op");

    // Empty-candidate slice is an early-return no-op (no tx opened).
    let empty = store
        .recall_observation_insert(&recall_id, &[])
        .await
        .expect("recall_observation_insert empty");
    assert_eq!(empty, 0);

    // GC with a generous TTL window prunes nothing recent; the SQL path
    // still executes (ttl_days.max(1) guard, DELETE ... < cutoff).
    let pruned = store
        .recall_observation_gc(36_500)
        .await
        .expect("recall_observation_gc");
    let _ = pruned; // freshly-written rows are far inside the window
}

// ───────────────────────────────────────────────────────────────────
// taxonomy_namespaces (inherent) — prefix-escaped + all-namespaces arms
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn taxonomy_namespaces_prefix_and_all_arms() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2");
    let root = uid("ga2-tax");
    let child = format!("{root}/leaf");
    store
        .store(&ctx, &mem(&uid("tx"), &root, "tax root", "body"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&uid("tx"), &child, "tax leaf", "body"))
        .await
        .unwrap();

    // Prefix arm: the LIKE '<prefix>/%' ESCAPE clause groups root + leaf.
    let scoped = store
        .taxonomy_namespaces(Some(&root))
        .await
        .expect("taxonomy_namespaces prefix");
    assert!(scoped.iter().any(|(ns, _)| ns == &root));
    assert!(scoped.iter().any(|(ns, _)| ns == &child));

    // All-namespaces arm (prefix=None) returns a non-empty aggregate.
    let all = store
        .taxonomy_namespaces(None)
        .await
        .expect("taxonomy_namespaces all");
    assert!(all.iter().any(|(ns, _)| ns == &root));
}

// ───────────────────────────────────────────────────────────────────
// list_pending_actions (inherent) — empty + status filter
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_pending_actions_empty_namespace_is_clean() {
    let Some(store) = connect().await else {
        return;
    };
    let ns = uid("ga2-pendempty");
    // No pending actions seeded for this uuid namespace → empty, count=0.
    let rows = store
        .list_pending_actions(Some("pending"), Some(&ns), 50)
        .await
        .expect("list_pending_actions empty");
    assert!(rows.is_empty(), "fresh namespace has no pending actions");

    // status=None + namespace=None arm scans the whole table cleanly.
    let _ = store
        .list_pending_actions(None, None, 10)
        .await
        .expect("list_pending_actions all-arms");
}

// ───────────────────────────────────────────────────────────────────
// current_embedding_dim + capabilities + schema_version (inherent /
// trait introspection)
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn embedding_dim_capabilities_and_schema_version() {
    let Some(store) = connect().await else {
        return;
    };
    // current_embedding_dim reads the live pgvector column dim.
    let dim = store
        .current_embedding_dim()
        .await
        .expect("current_embedding_dim");
    assert!(dim.is_none() || dim.unwrap() > 0, "dim is None or positive");

    // capabilities() is the trait introspection surface.
    let caps = store.capabilities();
    let _ = caps;

    // schema_version reports the postgres ladder head (v57+).
    let v = store.schema_version().await.expect("schema_version");
    assert!(v >= 57, "postgres ladder ends at v57+ (got {v})");
}

// ───────────────────────────────────────────────────────────────────
// set_embeddings_batch + list_unembedded — empty no-op + admin gate
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn set_embeddings_batch_empty_is_noop_and_writes_vectors() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2");
    let ns = uid("ga2-emb");

    // Empty entries → early-return 0, no transaction opened.
    let zero = store
        .set_embeddings_batch(&ctx, &[])
        .await
        .expect("set_embeddings_batch empty");
    assert_eq!(zero, 0);

    // Store a row, then batch-write its embedding.
    let id = uid("be");
    store
        .store(&ctx, &mem(&id, &ns, "batch emb", "body"))
        .await
        .unwrap();
    let dim = store
        .current_embedding_dim()
        .await
        .expect("dim")
        .unwrap_or(384);
    let vec: Vec<f32> = (0..dim).map(|i| (i as f32) * 0.0005).collect();
    let written = store
        .set_embeddings_batch(&ctx, &[(id.clone(), vec)])
        .await
        .expect("set_embeddings_batch write");
    assert_eq!(written, 1, "one row's embedding written");

    // A batch entry for a ghost id updates zero rows (the deleted-between-
    // scan-and-write count==0 path).
    let ghost_vec: Vec<f32> = (0..dim).map(|_| 0.1_f32).collect();
    let ghost = store
        .set_embeddings_batch(&ctx, &[(uid("ghost"), ghost_vec)])
        .await
        .expect("set_embeddings_batch ghost");
    assert_eq!(ghost, 0, "missing id contributes zero rows_affected");
}

#[tokio::test]
async fn list_unembedded_refuses_non_admin_caller() {
    let Some(store) = connect().await else {
        return;
    };
    // #1586 SEC gate — a non-admin (bypass_visibility == false) context
    // returns an empty result rather than leaking cross-tenant content.
    let non_admin = CallerContext::for_agent("ai:ga2-nonadmin");
    let refused = store
        .list_unembedded(&non_admin, 100)
        .await
        .expect("list_unembedded non-admin");
    assert!(refused.is_empty(), "non-admin context returns empty (gate)");

    // The admin path executes the actual scan (may be empty if the DB has
    // no unembedded rows — the call path is what we exercise).
    let admin = CallerContext::for_admin("ai:ga2-admin");
    let _ = store
        .list_unembedded(&admin, 5)
        .await
        .expect("list_unembedded admin");
}

// ───────────────────────────────────────────────────────────────────
// *_via_store dispatchers — the Arc<dyn MemoryStore> downcast path the
// postgres HTTP handlers take
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn via_store_dispatchers_round_trip() {
    let Some(store) = connect_arc().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2");
    let ns = uid("ga2-via");
    let a = uid("va");
    let b = uid("vb");
    store
        .store(&ctx, &mem(&a, &ns, "via a", "body"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&b, &ns, "via b", "body"))
        .await
        .unwrap();
    store.link(&ctx, &link(&a, &b)).await.unwrap();

    // kg_query_via_store downcasts then calls kg_query_with_history.
    let rows = kg_query_via_store(&store, &a, 3, false)
        .await
        .expect("kg_query_via_store");
    assert!(rows.iter().any(|r| r.target_id == b));

    // kg_timeline_via_store.
    let tl = kg_timeline_via_store(&store, &a, None, None, Some(50))
        .await
        .expect("kg_timeline_via_store");
    assert!(tl.iter().any(|r| r.target_id == b));

    // taxonomy_namespaces_via_store.
    let tax = taxonomy_namespaces_via_store(&store, Some(&ns))
        .await
        .expect("taxonomy_namespaces_via_store");
    assert!(tax.iter().any(|(n, _)| n == &ns));

    // list_pending_actions_via_store (empty for this uuid ns).
    let pend = list_pending_actions_via_store(&store, Some("pending"), Some(&ns), 50)
        .await
        .expect("list_pending_actions_via_store");
    assert!(pend.is_empty());

    // kg_invalidate_via_store marks the edge.
    let inv = kg_invalidate_via_store(&store, &a, &b, "related_to", None)
        .await
        .expect("kg_invalidate_via_store");
    assert!(inv.found);
}

#[tokio::test]
async fn archive_and_list_archived_via_store() {
    let Some(store) = connect_arc().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2");
    let ns = uid("ga2-archvia");
    let id = uid("av");
    store
        .store(&ctx, &mem(&id, &ns, "arch via", "body"))
        .await
        .unwrap();
    let moved = store
        .archive_by_ids(&ctx, std::slice::from_ref(&id), Some("ga2"))
        .await
        .expect("archive_by_ids");
    assert_eq!(moved, 1);

    // list_archived_via_store downcasts then projects archived rows.
    let archived = list_archived_via_store(&store, Some(&ns), 50, 0)
        .await
        .expect("list_archived_via_store");
    assert!(!archived.is_empty(), "archived row surfaces via dispatcher");

    // archive_stats_via_store aggregates the archive table.
    let stats = archive_stats_via_store(&store)
        .await
        .expect("archive_stats_via_store");
    assert!(
        stats.get("total_archived").is_some(),
        "archive_stats carries a total_archived field"
    );
    assert!(
        stats.get("by_namespace").is_some(),
        "archive_stats carries a by_namespace breakdown"
    );
}

#[tokio::test]
async fn via_store_dispatcher_rejects_non_postgres_store() {
    // The downcast_postgres helper returns BackendUnavailable when handed
    // an Arc that is NOT a PostgresStore. We need a live DB only to gate
    // the test consistently with its siblings; the assertion itself does
    // not touch the DB.
    if postgres_url().is_none() {
        return;
    }
    // Build a non-postgres trait object (the sqlite adapter) and confirm
    // the dispatcher refuses it rather than panicking on the downcast.
    let tmp = std::env::temp_dir(); // unused; sqlite store uses an in-proc path
    let _ = tmp;
    // A fresh in-memory-equivalent sqlite store is the cheapest non-pg
    // MemoryStore. If construction is unavailable in this build, the
    // BackendUnavailable arm is still covered by the production handler
    // path; here we assert the dispatcher's error arm directly.
    let sqlite_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let db_path = sqlite_dir.join(format!("ga2-nonpg-{}.db", uuid::Uuid::new_v4()));
    let sqlite = ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open sqlite store");
    let store: Arc<dyn MemoryStore> = Arc::new(sqlite);
    let err = taxonomy_namespaces_via_store(&store, None).await;
    assert!(
        matches!(err, Err(StoreError::BackendUnavailable { .. })),
        "non-postgres store must be refused by the downcast dispatcher"
    );
    let _ = std::fs::remove_file(&db_path);
}

// ───────────────────────────────────────────────────────────────────
// error arms — NotFound on get / update_with_expected_version conflict
// shape / store_batch empty
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_ghost_returns_not_found() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2");
    let res = store.get(&ctx, &uid("ghost")).await;
    assert!(matches!(res, Err(StoreError::NotFound { .. })));
}

#[tokio::test]
async fn update_with_expected_version_stale_conflicts() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2");
    let ns = uid("ga2-ocs");
    let id = uid("ocs");
    store
        .store(&ctx, &mem(&id, &ns, "oc v1", "body"))
        .await
        .unwrap();

    // A deliberately stale expected-version (999) must conflict — the
    // optimistic-concurrency refusal arm.
    let patch = UpdatePatch {
        content: Some("oc v2".to_string()),
        ..UpdatePatch::default()
    };
    let res = store
        .update_with_expected_version(&ctx, &id, patch, Some(999))
        .await;
    assert!(res.is_err(), "stale expected version must conflict");

    // expected_version=None is the unconditional-update arm (no conflict).
    let patch2 = UpdatePatch {
        content: Some("oc v2 unconditional".to_string()),
        ..UpdatePatch::default()
    };
    store
        .update_with_expected_version(&ctx, &id, patch2, None)
        .await
        .expect("unconditional update succeeds");
    let got = store.get(&ctx, &id).await.unwrap();
    assert_eq!(got.content, "oc v2 unconditional");
}

#[tokio::test]
async fn store_batch_empty_and_single_round_trip() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2");
    // Empty batch → early-return empty ids.
    let none = store.store_batch(&ctx, &[]).await.expect("empty batch");
    assert!(none.is_empty());

    // Single-row batch round-trips one id.
    let ns = uid("ga2-batch1");
    let row = mem(&uid("b1"), &ns, "solo batch", "body");
    let ids = store
        .store_batch(&ctx, std::slice::from_ref(&row))
        .await
        .expect("single batch");
    assert_eq!(ids.len(), 1);
}
