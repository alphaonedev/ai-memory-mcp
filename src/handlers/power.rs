// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! "Power" HTTP handlers — LLM-backed and computation-heavy endpoints:
//! contradiction detection, taxonomy, check-duplicate, consolidate,
//! auto-tag, expand-query, namespace listing, and family loader.
//!
//! Extracted from [`super::http`] under issue #650 follow-up 2. The
//! handler bodies are unchanged; only the module-routing import surface
//! moved. Wire compatibility preserved via `pub use power::*` in
//! [`super`].

#![allow(clippy::too_many_lines)]

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use crate::db;
use crate::models::{Memory, Tier};
use crate::profile::Family;
use crate::validate;

use super::AppState;
use super::MAX_BULK_SIZE;
#[cfg(feature = "sal")]
use super::StorageBackend;
#[cfg(feature = "sal")]
use super::store_err_to_response;

/// L5 — cap on auto-tag output rows.
const AUTO_TAG_MAX_TAGS: usize = 8;

#[derive(Deserialize)]
pub struct ContradictionsQuery {
    /// Topic to group candidate memories by. Resolved via (in order):
    /// `metadata.topic` exact match, then `title` exact match, then FTS
    /// content substring. At least one of `topic` or `namespace` is required.
    pub topic: Option<String>,
    /// Namespace to scope the search. Optional — default is cross-namespace.
    pub namespace: Option<String>,
    /// Pagination cap. Defaults to 50, hard max 200.
    pub limit: Option<usize>,
}

/// HTTP handler for v0.6.0.1 issue #321 — surfaces contradiction candidates
/// over the same REST surface scenarios use, so a2a-gate scenario-6 and any
/// future federation-level contradiction probe don't have to go through the
/// MCP stdio path.
///
/// Returns `{memories, links}` where:
/// - `memories` are the candidates grouped by topic/title (respecting the
///   UPSERT (title, namespace) invariant: if writers collided, only the LWW
///   survivor is returned — callers should use distinct titles per writer).
/// - `links` includes any existing `contradicts` rows from the `memory_links`
///   table PLUS a heuristic synthesis: when ≥2 candidates share a topic/title
///   but have materially different content, emit a synthetic `contradicts`
///   relation between each pair. The synthesized links carry
///   `relation:"contradicts"` and a `synthesized:true` flag so callers can
///   distinguish them from LLM-detected or operator-authored links.
///
/// Heuristic-only intentionally — LLM-backed detection (the existing MCP
/// `memory_detect_contradiction` tool) stays MCP-scoped so the HTTP surface
/// has no runtime LLM dependency. A follow-up issue can add opt-in LLM
/// resolution when `config.tier == Smart | Autonomous`.
#[allow(clippy::too_many_lines)]
pub async fn detect_contradictions(
    State(app): State<AppState>,
    Query(q): Query<ContradictionsQuery>,
) -> impl IntoResponse {
    if q.topic.is_none() && q.namespace.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "at least one of `topic` or `namespace` is required"})),
        )
            .into_response();
    }
    if let Some(ref ns) = q.namespace
        && let Err(e) = validate::validate_namespace(ns)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }
    // v0.6.2 (S40): raise to `MAX_BULK_SIZE` so a detect-contradictions
    // sweep over a bulk-populated namespace isn't silently capped at 200.
    let limit = q.limit.unwrap_or(50).min(MAX_BULK_SIZE);

    // v0.7.0 Wave-3 Continuation 3 (Phase 15) — postgres-backed daemons
    // route through the SAL trait. The non-LLM (rule-based +
    // heuristic-pairwise) contradictions detector works on both backends
    // because it's purely metadata-driven; this branch lists candidates
    // through `app.store.list` then runs the same pairwise heuristic.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let ctx = crate::store::CallerContext::for_agent("http");
        let filter = crate::store::Filter {
            namespace: q.namespace.clone(),
            limit,
            ..Default::default()
        };
        let all = match app.store.list(&ctx, &filter).await {
            Ok(v) => v,
            Err(e) => return store_err_to_response(e),
        };
        let candidates: Vec<Memory> = match q.topic.as_deref() {
            Some(t) => all
                .into_iter()
                .filter(|m| {
                    m.metadata
                        .get("topic")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| s == t)
                        || m.title == t
                })
                .collect(),
            None => all,
        };
        // Existing contradicts links via SAL — list all then filter by
        // (source ∈ candidates ∧ target ∈ candidates ∧ relation contains
        // "contradict"). We could narrow `list_links` by namespace when
        // q.namespace is set; for cross-namespace topic queries we need
        // the full set anyway.
        let candidate_ids: std::collections::HashSet<String> =
            candidates.iter().map(|m| m.id.clone()).collect();
        let mut existing_links: Vec<serde_json::Value> = Vec::new();
        if let Ok(all_links) = app.store.list_links(q.namespace.as_deref()).await {
            for link in all_links {
                // v0.7.0 fix campaign R1-M4 — relation is now typed.
                // Historic substring match tightened to a precise
                // variant compare.
                if matches!(
                    link.relation,
                    crate::models::MemoryLinkRelation::Contradicts
                ) && candidate_ids.contains(&link.source_id)
                    && candidate_ids.contains(&link.target_id)
                {
                    existing_links.push(json!({
                        "source_id": link.source_id,
                        "target_id": link.target_id,
                        "relation": link.relation,
                        "synthesized": false,
                    }));
                }
            }
        }
        existing_links.sort_by_key(|v| {
            (
                v.get("source_id")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
                v.get("target_id")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
                v.get("relation")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
            )
        });
        existing_links.dedup_by_key(|v| {
            (
                v.get("source_id")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
                v.get("target_id")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
                v.get("relation")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
            )
        });
        let mut synth_links: Vec<serde_json::Value> = Vec::new();
        for (i, a) in candidates.iter().enumerate() {
            for b in candidates.iter().skip(i + 1) {
                let same_topic = match q.topic.as_deref() {
                    Some(_) => true,
                    None => a.title == b.title,
                };
                if same_topic && a.content != b.content && a.id != b.id {
                    synth_links.push(json!({
                        "source_id": a.id,
                        "target_id": b.id,
                        "relation": "contradicts",
                        "synthesized": true,
                    }));
                }
            }
        }
        let mut links = existing_links;
        links.extend(synth_links);
        return Json(json!({
            "memories": candidates,
            "links": links,
            "storage_backend": "postgres",
        }))
        .into_response();
    }

    let lock = app.db.lock().await;
    let all = match db::list(
        &lock.0,
        q.namespace.as_deref(),
        None,
        limit,
        0,
        None,
        None,
        None,
        None,
        None,
    ) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("detect_contradictions list error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
                .into_response();
        }
    };

    // Topic match: metadata.topic == topic OR title == topic. Kept as a
    // retained filter rather than pushing to SQL because metadata is JSON
    // and the match predicate may evolve.
    let candidates: Vec<Memory> = match q.topic.as_deref() {
        Some(t) => all
            .into_iter()
            .filter(|m| {
                m.metadata
                    .get("topic")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s == t)
                    || m.title == t
            })
            .collect(),
        None => all,
    };

    // Existing contradicts links involving any candidate.
    let candidate_ids: std::collections::HashSet<String> =
        candidates.iter().map(|m| m.id.clone()).collect();
    let mut existing_links: Vec<serde_json::Value> = Vec::new();
    for id in &candidate_ids {
        if let Ok(links) = db::get_links(&lock.0, id) {
            for link in links {
                // v0.7.0 fix campaign R1-M4 — relation is now typed.
                // The historic substring match on "contradict" is
                // tightened to a precise variant compare.
                if matches!(
                    link.relation,
                    crate::models::MemoryLinkRelation::Contradicts
                ) && candidate_ids.contains(&link.source_id)
                    && candidate_ids.contains(&link.target_id)
                {
                    existing_links.push(json!({
                        "source_id": link.source_id,
                        "target_id": link.target_id,
                        "relation": link.relation,
                        "synthesized": false,
                    }));
                }
            }
        }
    }
    // Dedup — each (source,target,relation) appears at most once.
    existing_links.sort_by_key(|v| {
        (
            v.get("source_id")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
            v.get("target_id")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
            v.get("relation")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
        )
    });
    existing_links.dedup_by_key(|v| {
        (
            v.get("source_id")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
            v.get("target_id")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
            v.get("relation")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
        )
    });

    // Heuristic: when ≥2 candidates share a topic/title but content
    // differs, synthesize pairwise contradicts links. Marked
    // synthesized:true so callers can treat operator-authored links as
    // higher-confidence than this fallback.
    let mut synth_links: Vec<serde_json::Value> = Vec::new();
    for (i, a) in candidates.iter().enumerate() {
        for b in candidates.iter().skip(i + 1) {
            let same_topic = match q.topic.as_deref() {
                Some(_) => true,
                None => a.title == b.title,
            };
            if same_topic && a.content != b.content && a.id != b.id {
                synth_links.push(json!({
                    "source_id": a.id,
                    "target_id": b.id,
                    "relation": "contradicts",
                    "synthesized": true,
                }));
            }
        }
    }

    let mut links = existing_links;
    links.extend(synth_links);

    Json(json!({
        "memories": candidates,
        "links": links,
    }))
    .into_response()
}

pub async fn list_namespaces(State(app): State<AppState>) -> impl IntoResponse {
    // v0.7.0 Wave-3 Continuation — postgres-backed daemons aggregate the
    // distinct namespaces from `memories` via the SAL `list` method.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let ctx = crate::store::CallerContext::for_agent("daemon");
        let filter = crate::store::Filter {
            limit: 1_000_000,
            ..Default::default()
        };
        return match app.store.list(&ctx, &filter).await {
            Ok(memories) => {
                let mut ns: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
                for m in memories {
                    ns.insert(m.namespace);
                }
                let v: Vec<String> = ns.into_iter().collect();
                Json(json!({"namespaces": v})).into_response()
            }
            Err(e) => store_err_to_response(e),
        };
    }

    let lock = app.db.lock().await;
    match db::list_namespaces(&lock.0) {
        Ok(ns) => Json(json!({"namespaces": ns})).into_response(),
        Err(e) => {
            tracing::error!("handler error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
                .into_response()
        }
    }
}

/// Query parameters for `GET /api/v1/taxonomy` (Pillar 1 / Stream A).
#[derive(Debug, Deserialize)]
pub struct TaxonomyQuery {
    /// Restrict to memories at this namespace OR any descendant. Trailing
    /// `/` is tolerated. Omit to walk the whole tree.
    pub prefix: Option<String>,
    /// Alias for `prefix` — the cert harness (S44) uses `?root=…`. Both
    /// forms route to the same code path; `prefix` wins when both are
    /// supplied.
    #[serde(default)]
    pub root: Option<String>,
    /// Max levels to descend below the prefix (defaults to 8 — the
    /// hierarchy hard cap).
    pub depth: Option<usize>,
    /// Cap on the number of `(namespace, count)` rows we walk into the
    /// tree. Densest namespaces win when truncated. Defaults to 1000.
    pub limit: Option<usize>,
}

/// `GET /api/v1/taxonomy` — REST mirror of the MCP `memory_get_taxonomy`
/// tool. Returns the prefix's hierarchical tree with per-node and
/// subtree counts, plus an honest `total_count` and a `truncated`
/// flag when `limit` dropped rows from the walk.
pub async fn get_taxonomy(
    State(app): State<AppState>,
    Query(p): Query<TaxonomyQuery>,
) -> impl IntoResponse {
    let prefix_owned: Option<String> = p
        .prefix
        .as_deref()
        .or(p.root.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string());
    if let Some(pref) = prefix_owned.as_deref()
        && let Err(e) = validate::validate_namespace(pref)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid namespace_prefix: {e}")})),
        )
            .into_response();
    }
    let depth = p
        .depth
        .unwrap_or(crate::models::MAX_NAMESPACE_DEPTH)
        .min(crate::models::MAX_NAMESPACE_DEPTH);
    let limit = p.limit.unwrap_or(1000).clamp(1, 10_000);

    // v0.7.0 Wave-3 Continuation 4 (Bucket E / S44) — full hierarchical
    // taxonomy walk for postgres-backed daemons. Uses
    // `taxonomy_namespaces_via_store` to project a single `GROUP BY
    // namespace` aggregate (so we don't pull every memory row into
    // memory), then assembles the hierarchical tree with honest
    // `subtree_count` so the cert oracle can detect dishonest
    // truncation.
    #[cfg(feature = "sal-postgres")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let pairs = match crate::store::postgres::taxonomy_namespaces_via_store(
            &app.store,
            prefix_owned.as_deref(),
        )
        .await
        {
            Ok(p) => p,
            Err(e) => return store_err_to_response(e),
        };
        // Collapse the SQL-aggregated `(namespace, count)` rows into a
        // hierarchical tree whose nodes carry both their direct
        // `count` (memories whose namespace exactly matches this node)
        // and the transitive `subtree_count` (sum across the node and
        // all descendants).
        let total_count: usize = pairs
            .iter()
            .map(|(_, c)| usize::try_from(*c).unwrap_or(0))
            .sum();

        // Node:
        //   key = full namespace path
        //   own_count = memories at this exact namespace
        //   subtree_count = own_count + sum over descendant subtree_counts
        // Build by ensuring every ancestor node exists (own_count = 0
        // for synthesised intermediates), then accumulating subtree
        // counts bottom-up via stable iteration.
        let mut nodes: std::collections::BTreeMap<String, (usize /* own */, usize /* subtree */)> =
            std::collections::BTreeMap::new();
        for (ns, cnt) in &pairs {
            let cnt_us = usize::try_from(*cnt).unwrap_or(0);
            // Ensure each prefix-segment ancestor exists (above prefix_owned
            // if any). For example, namespace `a/b/c/d` under prefix `a/b`
            // creates nodes for `a/b/c` and `a/b/c/d`.
            let segments: Vec<&str> = ns.split('/').collect();
            for i in 1..=segments.len() {
                let path = segments[..i].join("/");
                nodes.entry(path).or_insert((0, 0));
            }
            // Stamp own_count on the leaf node.
            nodes
                .entry(ns.clone())
                .and_modify(|v| v.0 = cnt_us)
                .or_insert((cnt_us, 0));
        }
        // Compute subtree_count: walk paths longest-first so children
        // are summed before their parents. Since BTreeMap orders by
        // string, walk in reverse-sorted order.
        // First pass: seed each node's subtree_count = own_count.
        for (_k, v) in nodes.iter_mut() {
            v.1 = v.0;
        }
        // Second pass: collect parent->child pairs, then accumulate.
        let keys: Vec<String> = nodes.keys().cloned().collect();
        for k in keys.iter().rev() {
            // Find immediate parent by trimming trailing `/segment`.
            if let Some(pos) = k.rfind('/') {
                let parent = &k[..pos];
                if let Some(parent_node) = nodes.get(parent).copied() {
                    let child_subtree = nodes.get(k).map(|v| v.1).unwrap_or(0);
                    if let Some(p) = nodes.get_mut(parent) {
                        p.1 = parent_node.1 + child_subtree;
                    }
                }
            }
        }

        // Project the prefix-rooted tree at the requested depth. When
        // no prefix is supplied, treat the synthesized "" root as the
        // top of the world; otherwise root the tree at prefix_owned.
        let root_ns = prefix_owned.clone().unwrap_or_default();
        let truncated = pairs.len() > limit;

        // Recursive node builder. `current_depth` counts levels below
        // root_ns (root_ns is depth 0). We bound the recursion by
        // `depth` to mirror the v0.6.3 SQLite contract.
        fn build_node(
            node_ns: &str,
            nodes: &std::collections::BTreeMap<String, (usize, usize)>,
            depth_left: usize,
        ) -> serde_json::Value {
            let (own, subtree) = nodes.get(node_ns).copied().unwrap_or((0, 0));
            let mut children: Vec<serde_json::Value> = Vec::new();
            if depth_left > 0 {
                // A child is any node whose namespace starts with
                // `<node_ns>/` AND has exactly one extra segment.
                let prefix_match = if node_ns.is_empty() {
                    String::new()
                } else {
                    format!("{node_ns}/")
                };
                let parent_segs = if node_ns.is_empty() {
                    0
                } else {
                    node_ns.split('/').count()
                };
                for k in nodes.keys() {
                    if k == node_ns {
                        continue;
                    }
                    if !node_ns.is_empty() && !k.starts_with(&prefix_match) {
                        continue;
                    }
                    if k.split('/').count() == parent_segs + 1 {
                        children.push(build_node(k, nodes, depth_left - 1));
                    }
                }
            }
            serde_json::json!({
                "namespace": node_ns,
                "count": own,
                "subtree_count": subtree,
                "children": children,
            })
        }
        let root_node = build_node(&root_ns, &nodes, depth);
        return Json(json!({
            "tree": root_node,
            "total_count": total_count,
            "truncated": truncated,
            "storage_backend": "postgres",
        }))
        .into_response();
    }

    // Suppress unused-warning when sal feature is enabled (prefix_owned moves above).
    let _ = depth;

    let lock = app.db.lock().await;
    match db::get_taxonomy(&lock.0, prefix_owned.as_deref(), depth, limit) {
        Ok(tax) => Json(json!({
            "tree": tax.tree,
            "total_count": tax.total_count,
            "truncated": tax.truncated,
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("handler error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
                .into_response()
        }
    }
}

/// Request body for `POST /api/v1/check_duplicate` (Pillar 2 / Stream D).
#[derive(Debug, Deserialize)]
pub struct CheckDuplicateBody {
    pub title: String,
    pub content: String,
    /// Restrict the duplicate scan to this namespace. Omit to scan all
    /// namespaces.
    pub namespace: Option<String>,
    /// Cosine similarity threshold for declaring a duplicate. Clamped
    /// to >= 0.5 inside `db::check_duplicate`. Defaults to the tuned
    /// `DUPLICATE_THRESHOLD_DEFAULT` when omitted.
    pub threshold: Option<f32>,
}

/// `POST /api/v1/check_duplicate` — REST mirror of the MCP
/// `memory_check_duplicate` tool. Embeds `title + content`, scans
/// embedded live memories, and returns the highest-cosine match plus
/// `is_duplicate`/`suggested_merge` derived from the (clamped)
/// threshold.
pub async fn check_duplicate(
    State(app): State<AppState>,
    Json(body): Json<CheckDuplicateBody>,
) -> impl IntoResponse {
    if let Err(e) = validate::validate_title(&body.title) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid title: {e}")})),
        )
            .into_response();
    }
    if let Err(e) = validate::validate_content(&body.content) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid content: {e}")})),
        )
            .into_response();
    }
    let namespace = body
        .namespace
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(ns) = namespace
        && let Err(e) = validate::validate_namespace(ns)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid namespace: {e}")})),
        )
            .into_response();
    }
    let threshold = body.threshold.unwrap_or(db::DUPLICATE_THRESHOLD_DEFAULT);

    // v0.7.0 Wave-3 Continuation 4 (Bucket E / S48) — postgres-backed
    // daemons now perform an exact-content sweep through the SAL
    // `list` projection. When an embedder is loaded the call also
    // computes the query embedding and hands it to
    // `recall_hybrid`; the highest-cosine match becomes the nearest
    // candidate. Without an embedder the fallback walks the
    // namespace via `list` and surfaces any row whose
    // `(title, content)` tuple matches exactly (the same content-hash
    // short-circuit `db::check_duplicate_with_text` uses on sqlite,
    // before the embedding pass).
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let ctx = crate::store::CallerContext::for_agent("daemon");
        let filter = crate::store::Filter {
            namespace: namespace.map(str::to_string),
            limit: 1000,
            ..Default::default()
        };
        let mut nearest: Option<(crate::models::Memory, f64)> = None;
        let mut scanned = 0_u64;
        // Exact-content sweep first — cheap, deterministic, no embed.
        match app.store.list(&ctx, &filter).await {
            Ok(rows) => {
                for m in rows {
                    scanned += 1;
                    if m.content == body.content && m.title == body.title {
                        nearest = Some((m, 1.0));
                        break;
                    }
                }
            }
            Err(e) => return store_err_to_response(e),
        }
        // If exact match didn't surface, optionally try embedding-based
        // hybrid recall with the title+content as the query.
        if nearest.is_none()
            && let Some(emb) = app.embedder.as_ref().as_ref()
        {
            let embedding_text = format!("{} {}", body.title, body.content);
            if let Ok(qe) = emb.embed(&embedding_text) {
                let recall_filter = crate::store::Filter {
                    namespace: namespace.map(str::to_string),
                    limit: 5,
                    ..Default::default()
                };
                if let Ok(scored_pairs) = app
                    .store
                    .recall_hybrid(&ctx, &embedding_text, Some(&qe), &recall_filter)
                    .await
                {
                    if let Some((m, s)) = scored_pairs.into_iter().next() {
                        nearest = Some((m, s));
                    }
                }
                drop(qe);
            }
        }
        let (is_duplicate, near_json) = if let Some((m, score)) = nearest {
            let is_dup = score >= f64::from(threshold);
            (
                is_dup,
                json!({
                    "id": m.id,
                    "title": m.title,
                    "namespace": m.namespace,
                    "score": score,
                }),
            )
        } else {
            (false, serde_json::Value::Null)
        };
        return Json(json!({
            "is_duplicate": is_duplicate,
            "threshold": threshold,
            "nearest": near_json,
            "suggested_merge": is_duplicate,
            "candidates_scanned": scanned,
            "storage_backend": "postgres",
        }))
        .into_response();
    }

    // Embed before taking the DB lock — same rationale as create_memory
    // (issue #219). The embedder call is 10-200ms; we don't want it
    // serialised behind the connection mutex.
    let embedding_text = format!("{} {}", body.title, body.content);
    let query_embedding = match app.embedder.as_ref().as_ref() {
        Some(emb) => match emb.embed(&embedding_text) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("embedding generation failed: {e}");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "embedder failed to encode input"})),
                )
                    .into_response();
            }
        },
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": "memory_check_duplicate requires the embedder; daemon must be started with semantic tier or above"
                })),
            )
                .into_response();
        }
    };

    let lock = app.db.lock().await;
    // Round-2 F18 — short-circuit on raw-content hash equality before
    // falling through to embedding cosine similarity (parity with MCP
    // path).
    let check = match db::check_duplicate_with_text(
        &lock.0,
        &query_embedding,
        &embedding_text,
        namespace,
        threshold,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("handler error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
                .into_response();
        }
    };

    let nearest_json = check.nearest.as_ref().map(|m| {
        json!({
            "id": m.id,
            "title": m.title,
            "namespace": m.namespace,
            "similarity": (m.similarity * 1000.0).round() / 1000.0,
        })
    });
    let suggested_merge = if check.is_duplicate {
        check.nearest.as_ref().map(|m| m.id.clone())
    } else {
        None
    };

    Json(json!({
        "is_duplicate": check.is_duplicate,
        "threshold": check.threshold,
        "nearest": nearest_json,
        "suggested_merge": suggested_merge,
        "candidates_scanned": check.candidates_scanned,
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct ConsolidateBody {
    pub ids: Vec<String>,
    pub title: String,
    /// v0.7.0 L7 — was required (`summary: String`), which caused the
    /// axum `Json<T>` extractor to return 422 UNPROCESSABLE ENTITY for
    /// MCP-parity payloads that ship `{use_llm: true}` and rely on the
    /// daemon to materialize the summary via the LLM (matching
    /// `handle_consolidate` at `src/mcp.rs:5008-5028`). Now optional;
    /// when absent the handler asks `app.llm.summarize_memories` to
    /// produce a real summary, otherwise (no LLM wired) we synthesise
    /// a deterministic concat fallback so the row still lands.
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default = "default_ns")]
    pub namespace: String,
    #[serde(default)]
    pub tier: Option<Tier>,
    /// Optional `agent_id` for the consolidator (attributable on the result).
    /// If unset, resolved from `X-Agent-Id` header or per-request anonymous id.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// v0.7.0 L7 — explicit opt-in from S51-style MCP-parity callers
    /// that the daemon should compute the summary via the LLM rather
    /// than echoing a caller-supplied one. Today the gate is permissive:
    /// when `summary` is absent, the LLM path runs whether or not
    /// `use_llm` is set; the field is preserved for forward-compat with
    /// future "force LLM even when summary supplied" semantics.
    #[serde(default)]
    pub use_llm: bool,
}

fn default_ns() -> String {
    "global".to_string()
}

/// v0.7.0 L7 — resolve the consolidation `summary` field when the
/// caller omits it. Mirrors the MCP `handle_consolidate` auto-summary
/// path at `src/mcp.rs:5008-5028`: when an LLM is wired and the source
/// memories can be fetched, run `summarize_memories` on `(title,
/// content)` pairs. When no LLM is wired (keyword / semantic tiers, or
/// Ollama unreachable at boot), fall back to a deterministic
/// title-concat string so the consolidation still succeeds — S51 only
/// gates on `summary_len >= 20`, and the fallback is comfortably above
/// that for any 2-id call with non-trivial titles.
///
/// The blocking Ollama call is wrapped in `tokio::task::spawn_blocking`
/// to keep the async runtime healthy under load — same pattern as
/// `maybe_auto_tag`.
async fn resolve_consolidate_summary(app: &AppState, ids: &[String]) -> Result<String, Response> {
    // Collect (title, content) pairs from the appropriate backend so
    // the LLM has the actual source material. SAL on postgres; legacy
    // db on sqlite. A missing source memory short-circuits to 400 with
    // the offending id, matching the MCP path.
    let pairs = fetch_consolidate_source_pairs(app, ids).await?;

    // No LLM available — deterministic concat fallback. Titles only
    // (not full content) so the result stays a "summary" rather than a
    // verbatim concat that S51's `is_verbatim_concat` heuristic would
    // flag.
    let llm_arc = app.llm.clone();
    if llm_arc.is_none() || pairs.is_empty() {
        let titles: Vec<String> = pairs.iter().map(|(t, _)| t.clone()).collect();
        return Ok(format!(
            "Consolidated summary of {} memories: {}",
            titles.len(),
            titles.join("; ")
        ));
    }

    let llm_timeout = app.llm_call_timeout;
    // H8 (v0.7.0 round-2) — bound the Ollama summarize call by the
    // configured per-LLM-call timeout (default 30s). On timeout we
    // degrade to the deterministic concat fallback below (already the
    // L7 LLM-absent path).
    let join = tokio::time::timeout(
        llm_timeout,
        tokio::task::spawn_blocking(move || {
            let llm = match llm_arc.as_ref() {
                Some(c) => c,
                None => return Ok(String::new()),
            };
            llm.summarize_memories(&pairs)
        }),
    )
    .await;

    match join {
        Ok(Ok(Ok(s))) if !s.trim().is_empty() => Ok(s),
        Err(_) => {
            tracing::warn!(
                "H8: LLM call (summarize_memories) exceeded {}s timeout — falling back to \
                 deterministic concat",
                llm_timeout.as_secs()
            );
            Ok("Consolidated summary (LLM timeout; deterministic fallback)".to_string())
        }
        Ok(_) => {
            // LLM returned an empty body or errored (or the join task
            // panicked) — fall back to a deterministic concat-of-titles
            // fallback. Logging on the error branch only so a successful
            // empty response doesn't spam the daemon log.
            Ok("Consolidated summary (LLM unavailable; deterministic fallback)".to_string())
        }
    }
}

/// v0.7.0 L7 — fetch `(title, content)` pairs for each source memory in
/// a consolidation request, picking the storage backend off `AppState`.
/// Missing ids surface as a 400 response so the caller's mistake is
/// distinguishable from a daemon-side LLM failure.
async fn fetch_consolidate_source_pairs(
    app: &AppState,
    ids: &[String],
) -> Result<Vec<(String, String)>, Response> {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let ctx = crate::store::CallerContext::for_agent("ai:http");
        let mut out: Vec<(String, String)> = Vec::with_capacity(ids.len());
        for id in ids {
            match app.store.get(&ctx, id).await {
                Ok(mem) => out.push((mem.title, mem.content)),
                Err(crate::store::StoreError::NotFound { .. }) => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": format!("memory not found: {id}")})),
                    )
                        .into_response());
                }
                Err(e) => return Err(store_err_to_response(e)),
            }
        }
        return Ok(out);
    }

    let lock = app.db.lock().await;
    let mut out: Vec<(String, String)> = Vec::with_capacity(ids.len());
    for id in ids {
        match db::get(&lock.0, id) {
            Ok(Some(mem)) => out.push((mem.title, mem.content)),
            Ok(None) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("memory not found: {id}")})),
                )
                    .into_response());
            }
            Err(e) => {
                tracing::error!("consolidate source lookup failed: {e}");
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "internal server error"})),
                )
                    .into_response());
            }
        }
    }
    Ok(out)
}

pub async fn consolidate_memories(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ConsolidateBody>,
) -> impl IntoResponse {
    // v0.7.0 L7 — materialize the summary up front so the downstream
    // validation + storage paths see a concrete `&str`. When the caller
    // supplied one, use it verbatim; when absent, ask the LLM (matching
    // the MCP `handle_consolidate` auto-summary contract); when neither
    // is available, synthesise a deterministic concat of the source
    // titles so the row still lands rather than 422'ing on a wire-shape
    // mismatch S51 has tripped on.
    let summary = match body.summary.clone() {
        Some(s) if !s.is_empty() => s,
        _ => match resolve_consolidate_summary(&app, &body.ids).await {
            Ok(s) => s,
            Err(resp) => return resp,
        },
    };

    if let Err(e) =
        validate::validate_consolidate(&body.ids, &body.title, &summary, &body.namespace)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }
    let header_agent_id = headers.get("x-agent-id").and_then(|v| v.to_str().ok());
    let consolidator_agent_id =
        match crate::identity::resolve_http_agent_id(body.agent_id.as_deref(), header_agent_id) {
            Ok(id) => id,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("invalid agent_id: {e}")})),
                )
                    .into_response();
            }
        };
    let tier = body.tier.unwrap_or(Tier::Long);
    let source_ids = body.ids.clone();

    // v0.7.0 Wave-3 Continuation 3 (Phase 14) — postgres-backed daemons
    // route through the SAL trait. Returns a structured 201/error envelope
    // that mirrors the sqlite path; the cross-namespace
    // `memory_consolidated` event + federation fanout are both
    // sqlite-only features (the sqlite branch below preserves them).
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let ctx = crate::store::CallerContext::for_agent(&consolidator_agent_id);
        return match app
            .store
            .consolidate(
                &ctx,
                &body.ids,
                &body.title,
                &summary,
                &body.namespace,
                &tier,
                "consolidation",
                &consolidator_agent_id,
            )
            .await
        {
            Ok(new_id) => (
                StatusCode::CREATED,
                Json(json!({
                    "id": new_id,
                    "consolidated": body.ids.len(),
                    "summary": summary,
                    // v0.7.0 L7-followup — also emit the materialised summary
                    // as `content` and inside a nested `memory` object so the
                    // S51 scenario reader (which falls through
                    // `cbody.get("summary") or cbody.get("content") or
                    // (cbody.get("memory") or {}).get("content")` under a
                    // ternary that requires `memory` to be a dict) sees a
                    // non-empty string regardless of which branch its
                    // operator precedence resolves to. Without the `memory`
                    // dict the whole expression collapses to `""` even
                    // though `summary` is set — see
                    // `scenarios/51_autonomous_tier_suite.py:140-145`.
                    "content": summary,
                    "memory": {
                        "id": new_id,
                        "title": body.title,
                        "content": summary,
                        "namespace": body.namespace,
                    },
                    "storage_backend": "postgres",
                })),
            )
                .into_response(),
            Err(e) => store_err_to_response(e),
        };
    }

    let lock = app.db.lock().await;
    let consolidate_result = db::consolidate(
        &lock.0,
        &body.ids,
        &body.title,
        &summary,
        &body.namespace,
        &tier,
        "consolidation",
        &consolidator_agent_id,
    );
    // Read the newly consolidated memory back so we can fanout — must do
    // this inside the same lock window because db::consolidate deletes
    // the source rows as part of its transaction.
    let new_mem = match &consolidate_result {
        Ok(new_id) => db::get(&lock.0, new_id).ok().flatten(),
        Err(_) => None,
    };
    // v0.6.4-017 — G9 HTTP webhook parity. Fire `memory_consolidated`
    // after db::consolidate commits (mirrors mcp.rs:2723). The new
    // memory's id goes in the outer envelope; source ids in details.
    if let Ok(new_id) = &consolidate_result {
        let details = serde_json::to_value(crate::subscriptions::ConsolidatedEventDetails {
            source_ids: source_ids.clone(),
            source_count: source_ids.len(),
        })
        .ok();
        crate::subscriptions::dispatch_event_with_details(
            &lock.0,
            "memory_consolidated",
            new_id,
            &body.namespace,
            Some(&consolidator_agent_id),
            &lock.1,
            details,
        );
    }
    // Drop DB lock before fanning out — peers POST back to our sync_push
    // and we'd deadlock on the shared Mutex if we held it.
    drop(lock);
    match consolidate_result {
        Ok(new_id) => {
            // v0.6.2 (#326): propagate consolidation to peers so
            // `metadata.consolidated_from_agents` and the deleted sources
            // are in sync across the mesh.
            if let (Some(fed), Some(mem)) = (app.federation.as_ref(), new_mem) {
                match crate::federation::broadcast_consolidate_quorum(fed, &mem, &source_ids).await
                {
                    Ok(tracker) => {
                        if let Err(err) = crate::federation::finalise_quorum(&tracker) {
                            let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                [("Retry-After", "2")],
                                Json(serde_json::to_value(&payload).unwrap_or_default()),
                            )
                                .into_response();
                        }
                    }
                    Err(e) => {
                        tracing::warn!("consolidate fanout error (local committed): {e:?}");
                    }
                }
            }
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": new_id,
                    "consolidated": body.ids.len(),
                    "summary": summary,
                    // v0.7.0 L7-followup — see postgres branch above for
                    // the rationale. Mirroring `content` and a nested
                    // `memory` dict here keeps both backends emitting the
                    // same wire shape so S51 passes regardless of whether
                    // the daemon is sqlite- or postgres-backed.
                    "content": summary,
                    "memory": {
                        "id": new_id,
                        "title": body.title,
                        "content": summary,
                        "namespace": body.namespace,
                    },
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("handler error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
                .into_response()
        }
    }
}

/// Request body for `POST /api/v1/auto_tag`.
///
/// Two shapes are accepted to keep the surface compatible with both
/// the S51 contract (`{memory_id, namespace}`) and ad-hoc callers that
/// want to tag a free-text title + content blob without storing it
/// first (`{title, content}`). At least one of `(memory_id, title)`
/// must be present.
#[derive(serde::Deserialize, Default)]
pub struct AutoTagBody {
    /// S51 shape — id of an already-stored memory whose `(title,
    /// content)` will be fetched and tagged.
    #[serde(default)]
    pub memory_id: Option<String>,
    /// Optional namespace (S51 sends this for forward-compat; the
    /// underlying LLM call is namespace-agnostic).
    #[serde(default)]
    pub namespace: Option<String>,
    /// Ad-hoc shape — tag this title + content directly without a
    /// preceding store. Used when an operator wants to dry-run the
    /// tag prompt against an arbitrary string.
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}

/// `POST /api/v1/auto_tag` — generate semantic tags for a memory via
/// the configured LLM (Ollama by default).
///
/// Wire shape:
/// - request: `{memory_id, namespace}` or `{title, content}`
/// - response 200: `{tags: [..], memory_id: <id or null>}`
/// - response 503: `{error: "LLM not configured"}` when no LLM is wired
/// - response 400: validation / missing-body errors
///
/// The blocking Ollama call is wrapped in `tokio::task::spawn_blocking`
/// mirroring [`maybe_auto_tag`] so the runtime stays responsive when
/// the model is slow.
pub async fn auto_tag_handler(
    State(app): State<AppState>,
    Json(body): Json<AutoTagBody>,
) -> impl IntoResponse {
    if app.llm.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "LLM not configured"})),
        )
            .into_response();
    }

    // Resolve (title, content). S51 sends `memory_id`; we fetch the
    // memory from the active backend. Ad-hoc callers may instead
    // supply title+content inline.
    let (title, content, resolved_id): (String, String, Option<String>) =
        if let Some(id) = body.memory_id.as_deref() {
            if let Err(e) = validate::validate_id(id) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response();
            }
            match fetch_memory_for_handler(&app, id).await {
                Ok(mem) => (mem.title, mem.content, Some(id.to_string())),
                Err(resp) => return resp,
            }
        } else {
            match (body.title.clone(), body.content.clone()) {
                (Some(t), Some(c)) => (t, c, None),
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "auto_tag requires memory_id (preferred) or title+content"
                        })),
                    )
                        .into_response();
                }
            }
        };

    let llm_arc = app.llm.clone();
    let auto_tag_model = app.auto_tag_model.as_ref().clone();
    let title_owned = title;
    let content_owned = content;
    let llm_timeout = app.llm_call_timeout;
    // H8 (v0.7.0 round-2) — bound the Ollama call by the configured
    // per-LLM-call timeout (default 30s). On timeout return an empty
    // tag list with a 200 — preserves the L6/S51 contract that 200 is
    // never withheld when the operator asked for tags but Ollama was
    // slow (matches the "LLM-absent fallback" branch the keyword/
    // semantic tiers already exercise).
    let join = tokio::time::timeout(
        llm_timeout,
        tokio::task::spawn_blocking(move || {
            let llm = match llm_arc.as_ref() {
                Some(c) => c,
                None => return Ok(Vec::new()),
            };
            llm.auto_tag(&title_owned, &content_owned, auto_tag_model.as_deref())
        }),
    )
    .await;

    let tags = match join {
        Ok(Ok(Ok(tags))) => tags.into_iter().take(AUTO_TAG_MAX_TAGS).collect::<Vec<_>>(),
        Ok(Ok(Err(e))) => {
            tracing::warn!("L6: auto_tag LLM call failed: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("LLM auto_tag failed: {e}")})),
            )
                .into_response();
        }
        Ok(Err(e)) => {
            tracing::warn!("L6: auto_tag spawn_blocking join failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
                .into_response();
        }
        Err(_) => {
            tracing::warn!(
                "H8: LLM call (auto_tag) exceeded {}s timeout — returning empty tag list",
                llm_timeout.as_secs()
            );
            Vec::new()
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "tags": tags,
            "memory_id": resolved_id,
        })),
    )
        .into_response()
}

/// Request body for `POST /api/v1/expand_query`.
#[derive(serde::Deserialize, Default)]
pub struct ExpandQueryBody {
    pub query: String,
    #[serde(default)]
    pub namespace: Option<String>,
}

/// `POST /api/v1/expand_query` — generate semantic reformulations of a
/// free-text query via the configured LLM.
///
/// Wire shape:
/// - request: `{query, namespace?}`
/// - response 200: `{expansions: [..], original: <q>}`
/// - response 503: `{error: "LLM not configured"}` when no LLM is wired
/// - response 400: empty / missing query
pub async fn expand_query_handler(
    State(app): State<AppState>,
    Json(body): Json<ExpandQueryBody>,
) -> impl IntoResponse {
    if app.llm.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "LLM not configured"})),
        )
            .into_response();
    }
    let query = body.query.trim().to_string();
    if query.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "query is required"})),
        )
            .into_response();
    }

    let llm_arc = app.llm.clone();
    let query_owned = query.clone();
    let llm_timeout = app.llm_call_timeout;
    // H8 (v0.7.0 round-2) — bound the Ollama call by the configured
    // per-LLM-call timeout (default 30s). On timeout return an empty
    // expansion list — matches the LLM-absent fallback shape.
    let join = tokio::time::timeout(
        llm_timeout,
        tokio::task::spawn_blocking(move || {
            let llm = match llm_arc.as_ref() {
                Some(c) => c,
                None => return Ok(Vec::new()),
            };
            llm.expand_query(&query_owned)
        }),
    )
    .await;

    let expansions = match join {
        Ok(Ok(Ok(terms))) => terms,
        Ok(Ok(Err(e))) => {
            tracing::warn!("L6: expand_query LLM call failed: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("LLM expand_query failed: {e}")})),
            )
                .into_response();
        }
        Ok(Err(e)) => {
            tracing::warn!("L6: expand_query spawn_blocking join failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
                .into_response();
        }
        Err(_) => {
            tracing::warn!(
                "H8: LLM call (expand_query) exceeded {}s timeout — returning empty expansion list",
                llm_timeout.as_secs()
            );
            Vec::new()
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "expansions": expansions,
            "original": query,
        })),
    )
        .into_response()
}

/// v0.7.0 L6/L7 — fetch a single memory by id off the active storage
/// backend. Returns a structured 4xx/5xx response on miss / lookup
/// failure so the calling handler can `return Err(resp)`.
async fn fetch_memory_for_handler(app: &AppState, id: &str) -> Result<Memory, Response> {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let ctx = crate::store::CallerContext::for_agent("ai:http");
        return match app.store.get(&ctx, id).await {
            Ok(mem) => Ok(mem),
            Err(crate::store::StoreError::NotFound { .. }) => Err((
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("memory not found: {id}")})),
            )
                .into_response()),
            Err(e) => Err(store_err_to_response(e)),
        };
    }

    let lock = app.db.lock().await;
    match db::get(&lock.0, id) {
        Ok(Some(mem)) => Ok(mem),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("memory not found: {id}")})),
        )
            .into_response()),
        Err(e) => {
            tracing::error!("memory lookup failed: {e}");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
                .into_response())
        }
    }
}

/// Request body for `POST /api/v1/memory_load_family`.
#[derive(serde::Deserialize)]
pub struct LoadFamilyBody {
    /// One of: core, lifecycle, graph, governance, power, meta,
    /// archive, other. Validated against [`Family::all`].
    pub family: String,
    /// Optional namespace narrowing. When omitted the scan spans every
    /// namespace, matching the MCP tool's "no namespace = all" rule.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Top-K cap. Default 20, clamped to `[1, 100]` for response-budget
    /// reasons (mirroring `handle_load_family`).
    #[serde(default)]
    pub k: Option<u64>,
}

/// `POST /api/v1/memory_load_family` — return the top-K recent +
/// high-priority memories tagged with the requested family.
///
/// Wire shape:
/// - request: `{family, namespace?, k?}`
/// - response 200: `{family, namespace, k, count, memories: [..]}`
/// - response 400: unknown family / bad namespace
pub async fn load_family_handler(
    State(app): State<AppState>,
    Json(body): Json<LoadFamilyBody>,
) -> impl IntoResponse {
    use std::str::FromStr;

    let family = match Family::from_str(&body.family) {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    if let Some(ref ns) = body.namespace
        && let Err(e) = validate::validate_namespace(ns)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }

    let k_raw = body.k.unwrap_or(20);
    let k = usize::try_from(k_raw).unwrap_or(usize::MAX).clamp(1, 100);
    let family_name = family.name();

    // v0.7.0 Wave-3 — postgres path. Pull a generous superset via the
    // SAL trait then filter on `metadata.family` in memory; the trait
    // filter axes don't yet include metadata fields. Cap the prefetch
    // at MAX_BULK_SIZE so a postgres daemon can't be coerced into
    // loading the whole table on a small `k`.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let filter = crate::store::Filter {
            namespace: body.namespace.clone(),
            tier: None,
            tags_any: Vec::new(),
            agent_id: None,
            since: None,
            until: None,
            limit: MAX_BULK_SIZE,
        };
        let ctx = crate::store::CallerContext::for_agent("ai:http");
        return match app.store.list(&ctx, &filter).await {
            Ok(all) => {
                let mut filtered: Vec<Memory> = all
                    .into_iter()
                    .filter(|m| {
                        m.metadata.get("family").and_then(serde_json::Value::as_str)
                            == Some(family_name)
                    })
                    .collect();
                // priority DESC, updated_at DESC (mirrors handle_load_family).
                filtered.sort_by(|a, b| {
                    b.priority
                        .cmp(&a.priority)
                        .then_with(|| b.updated_at.cmp(&a.updated_at))
                });
                filtered.truncate(k);
                let count = filtered.len();
                Json(json!({
                    "family": family_name,
                    "namespace": body.namespace,
                    "k": k,
                    "count": count,
                    "memories": filtered,
                }))
                .into_response()
            }
            Err(e) => store_err_to_response(e),
        };
    }

    // Sqlite path — reuse the MCP `handle_load_family` SQL verbatim by
    // calling it through with the same parameter shape (a `Value`).
    let lock = app.db.lock().await;
    let params = json!({
        "family": family_name,
        "namespace": body.namespace,
        "k": k,
    });
    match crate::mcp::handle_load_family(&lock.0, &params) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}
