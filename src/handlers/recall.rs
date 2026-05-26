// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Recall HTTP handlers — `/api/v1/recall` GET + POST + the inner
//! response-builder + the request-scope-defaulter helper.
//!
//! Extracted from [`super::http`] under issue #650 follow-up 2. The
//! handler bodies are unchanged; only the module-routing import surface
//! moved. Wire compatibility preserved via `pub use recall::*` in
//! [`super`].

#![allow(clippy::too_many_lines)]

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use crate::db;
use crate::models::{RecallBody, RecallQuery, RecallRequest};
use crate::validate;

use super::AppState;
#[cfg(feature = "sal")]
use super::StorageBackend;
#[cfg(feature = "sal")]
use super::store_err_to_response;

/// v0.7.0 (issue #518) — when `session_default == true` AND the
/// caller omitted a given filter axis, splice in the configured
/// `[agents.defaults.recall_scope]` value IN-PLACE on the canonical
/// [`RecallRequest`] DTO. Returns the spliced `recall_scope_tier`
/// (which has no field on the DTO — it's a postgres-SAL-only filter
/// applied via `Filter.tier`) so the postgres branch in
/// [`recall_response`] can consume it without re-reading the
/// `app.recall_scope` state.
///
/// Resolution: explicit args > recall_scope defaults > compiled
/// defaults.
///
/// #967 — replaces the legacy `apply_recall_scope_defaults` that
/// returned a `(namespace, since, tier, limit)` tuple. Mutating
/// the DTO in place keeps the (already-marshalled) request shape
/// authoritative through the rest of the handler.
fn splice_recall_scope_into(req: &mut RecallRequest, app: &AppState) -> Option<String> {
    let want_splice = req.session_default.unwrap_or(false);
    let scope_opt: Option<&crate::config::RecallScope> = if want_splice {
        app.recall_scope.as_ref().as_ref()
    } else {
        None
    };

    if req.namespace.is_none() {
        req.namespace = scope_opt
            .and_then(|s| s.namespaces.as_ref())
            .and_then(|v| v.first())
            .cloned();
    }

    if req.since.is_none() {
        req.since = scope_opt.and_then(|s| {
            s.since.as_deref().and_then(|d| {
                crate::config::parse_duration_string(d).map(|dur| {
                    let cutoff = chrono::Utc::now() - dur;
                    cutoff.to_rfc3339()
                })
            })
        });
    }

    let tier = scope_opt.and_then(|s| s.tier.clone());

    if req.limit.is_none()
        && let Some(v) = scope_opt.and_then(|s| s.limit)
    {
        req.limit = Some(i64::from(v));
    }

    tier
}

pub async fn recall_memories_get(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(p): Query<RecallQuery>,
) -> impl IntoResponse {
    // #967 — marshal once into the canonical `RecallRequest`. The
    // entry handler still gates on `context` (or its aliases) being
    // non-empty BEFORE constructing the DTO so the typed
    // `400 BAD_REQUEST` envelope stays byte-stable with the v0.7.0
    // wire contract.
    //
    // Accept `context` (canonical), `query` (cert harness alias —
    // S79 uses `?query=…`), or `q` (search-style alias — the parity
    // suite uses `?q=…`). Cert oracles continue to work.
    //
    // #869 audit (Category B — safe default): empty `String` collapses
    // straight into the `is_empty()` guard below, which returns a typed
    // 400 with "context (or query) is required".
    let mut req = RecallRequest::from_http_query(&p);
    if req.context.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "context (or query) is required"})),
        )
            .into_response();
    }
    // Phase P6 (R1): `budget_tokens=0` is now a valid request meaning
    // "return zero memories" — see `db::apply_token_budget`. The
    // earlier Ultrareview #348 hard-reject is replaced by always
    // round-tripping the requested budget in the response so a
    // genuinely buggy uninitialised counter is still observable.
    if let Some(ref a) = req.as_agent
        && let Err(e) = validate::validate_namespace(a)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid as_agent: {e}")})),
        )
            .into_response();
    }
    // v0.7.0 (issue #518) — splice `[agents.defaults.recall_scope]`
    // when `session_default=true` AND the caller omitted the
    // matching filter axis. Resolution: explicit args win.
    let scope_tier = splice_recall_scope_into(&mut req, &app);
    let kinds = p.resolved_kinds();
    // v0.7.0 ship-hardening (2026-05-19): resolve the caller principal
    // from the X-Agent-Id header (synthesizes anonymous on miss) so
    // the SAL visibility filter has the actual request principal.
    // Pre-fix the recall path hardcoded `"daemon"` as the caller,
    // which mismatched the per-request id stamped on every memory
    // and caused the #910 scope=private visibility filter to drop
    // every row the caller actually owned.
    let caller_principal = match crate::handlers::parity::resolve_caller_agent_id(
        None,
        &headers,
        req.as_agent.as_deref(),
    ) {
        Ok(p) => p,
        Err(e) => {
            return (axum::http::StatusCode::FORBIDDEN, Json(json!({"error": e}))).into_response();
        }
    };
    // v0.7.x #1155 — Accept-Provenance header gates Gap 7 derived
    // decoration on the HTTP recall envelope. Default HTTP shape is
    // bare (v0.6.x backwards compat); the header opts callers into
    // the verbose decoration that already ships by default on MCP.
    let provenance_shape = crate::handlers::accept_provenance::resolve_from_headers(&headers);
    recall_response(
        &app,
        &req,
        Some(caller_principal.as_str()),
        scope_tier.as_deref(),
        kinds.as_deref(),
        provenance_shape,
    )
    .await
}

pub async fn recall_memories_post(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RecallBody>,
) -> impl IntoResponse {
    // #967 — same DTO marshal-once shape as the GET path; the body
    // `resolved_query` precedence (`context > query > q`) is
    // applied inside the constructor.
    let mut req = RecallRequest::from_http_body(&body);
    if req.context.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "context (or query) is required"})),
        )
            .into_response();
    }
    // Phase P6 (R1): `budget_tokens=0` is now a valid request — see
    // the matching note on the GET handler above.
    if let Some(ref a) = req.as_agent
        && let Err(e) = validate::validate_namespace(a)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid as_agent: {e}")})),
        )
            .into_response();
    }
    // v0.7.0 (issue #518) — see GET handler for the resolution rule.
    let scope_tier = splice_recall_scope_into(&mut req, &app);
    let kinds = body.resolved_kinds();
    // See GET handler for the caller-resolution rationale.
    let caller_principal = match crate::handlers::parity::resolve_caller_agent_id(
        None,
        &headers,
        req.as_agent.as_deref(),
    ) {
        Ok(p) => p,
        Err(e) => {
            return (axum::http::StatusCode::FORBIDDEN, Json(json!({"error": e}))).into_response();
        }
    };
    // v0.7.x #1155 — same Accept-Provenance gating as the GET path.
    let provenance_shape = crate::handlers::accept_provenance::resolve_from_headers(&headers);
    recall_response(
        &app,
        &req,
        Some(caller_principal.as_str()),
        scope_tier.as_deref(),
        kinds.as_deref(),
        provenance_shape,
    )
    .await
}

/// v0.6.2 (S18): shared HTTP recall implementation. Uses `db::recall_hybrid`
/// (semantic + FTS adaptive blend) when the embedder is loaded — matching
/// how the MCP `memory_recall` handler wires recall at crate::mcp::handle_recall.
/// Gracefully falls back to `db::recall` (keyword-only) when the embedder
/// is not present or embedding the query fails. Closes the gap where the
/// HTTP surface was keyword-only regardless of server tier — scenario-18
/// surfaced the black-hole on peers that fanned out memories but never
/// exercised the semantic recall path.
///
/// v0.7.0 Wave-3 Continuation — when `app.storage_backend` is
/// `Postgres`, dispatch through `app.store.search` for keyword recall.
/// The full hybrid (FTS + semantic + adaptive blend + reranker + touch
/// ops) pipeline remains sqlite-only in v0.7.0; postgres deployments
/// fall back to keyword-only recall through the postgres `to_tsvector`
/// FTS surface, which is functionally equivalent for the keyword half
/// and surfaces a `mode=keyword` envelope so clients can detect the
/// degraded mode without an out-of-band feature probe.
/// #967 canonical-DTO entry. Pre-#967 this took 15 positional
/// args (one per wire field) — now takes a `&RecallRequest` plus
/// the three values the entry handler resolves OUTSIDE the wire
/// shape:
///
///  1. `caller_principal` — derived from the `X-Agent-Id` header
///     (v0.7.0 ship-hardening 2026-05-19, see comment below).
///  2. `recall_scope_tier` — spliced from `app.recall_scope.tier`
///     by the entry handler; has no DTO field because the wire
///     surface does not expose a `tier` filter directly (postgres
///     SAL path applies it via `Filter.tier`).
///  3. `kinds_filter` — the parsed `Vec<MemoryKind>` from the DTO's
///     `kinds: Option<KindsFilter>` field. Pre-parsing here keeps
///     the recall path free of `KindsFilter::parse()` churn on
///     every result-set iteration; the entry handler runs it once.
///
/// All other knobs (namespace, limit, tags, since/until, budget,
/// has_citations, source_uri_prefix, session_id, as_agent) come
/// off the DTO directly.
async fn recall_response(
    app: &AppState,
    req: &RecallRequest,
    caller_principal: Option<&str>,
    recall_scope_tier: Option<&str>,
    kinds_filter: Option<&[crate::models::MemoryKind]>,
    // v0.7.x #1155 — operator opt-in gate for the Gap 7 derived
    // decoration on the HTTP envelope. Defaults to `Minimal`
    // (bare serde shape, v0.6.x backwards-compat default) when the
    // caller omits the `Accept-Provenance` header; flips to
    // `Verbose` (adds `confidence_tier`, `freshness_state`,
    // `latest_link_attest_level` per row) when the header is sent.
    // Asymmetry with MCP (which defaults to verbose=true) is
    // intentional and documented at
    // `src/handlers/accept_provenance.rs`.
    provenance_shape: crate::handlers::accept_provenance::ProvenanceShape,
) -> axum::response::Response {
    let context = req.context.as_str();
    let namespace = req.namespace.as_deref();
    let limit = req.resolved_limit().min(50);
    let tags = req.tags.as_deref();
    let since = req.since.as_deref();
    let until = req.until.as_deref();
    let as_agent = req.as_agent.as_deref();
    let budget_tokens = req.resolved_budget_tokens();
    let has_citations = req.has_citations.unwrap_or(false);
    let source_uri_prefix = req.source_uri_prefix.as_deref();
    let session_id = req.session_id.as_deref();

    let session_tracker = crate::reranker::global_session_recall_tracker();
    // `recall_scope_tier` is consumed only on the postgres SAL branch
    // (line 3026). Suppress the unused-variable lint when the sal
    // feature is off — same idiom as `url_was_synthesized` in
    // hook_subscribers.rs.
    #[cfg(not(feature = "sal"))]
    let _ = recall_scope_tier;
    // v0.7.0 Wave-3 Continuation 2 (Phase 10) — postgres-backed
    // hybrid recall via the SAL trait. Embeds the query AND dispatches
    // through `app.store.recall_hybrid` so the postgres adapter applies
    // the FTS + semantic + adaptive blend pipeline (mirror of
    // db::recall_hybrid in sqlite). Touch ops fire after the response
    // payload is assembled so access_count + TTL extension + auto-
    // promotion + priority ladders apply on postgres exactly as on
    // sqlite.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // Embed the query before issuing the trait call. None when the
        // embedder is unavailable; the trait's recall_hybrid degrades
        // to the FTS-only pool with a synthetic semantic component.
        let query_emb: Option<Vec<f32>> = if let Some(emb) = app.embedder.as_ref().as_ref() {
            match emb.embed(context) {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("recall (postgres): embed failed, keyword-only: {e}");
                    None
                }
            }
        } else {
            None
        };
        let mode = if query_emb.is_some() {
            "hybrid"
        } else {
            "keyword"
        };

        // `as_agent` is the explicit query-param override (admin /
        // act-on-behalf semantics). When set, it overrides the
        // header-derived principal. Otherwise use `caller_principal`
        // (resolved from X-Agent-Id by the entry handler), falling
        // back to "daemon" only when neither is present (legacy
        // pre-#910 behavior, harmless on non-scope=private memories).
        let ctx_caller = crate::store::CallerContext::for_agent(
            as_agent
                .or(caller_principal)
                .unwrap_or("daemon")
                .to_string(),
        );
        let mut filter = crate::store::Filter {
            namespace: namespace.map(str::to_string),
            limit,
            ..Default::default()
        };
        // v0.7.0 (issue #518) — splice `recall_scope.tier` when the
        // caller passed `session_default=true` and omitted an
        // explicit tier filter on the request. The HTTP recall
        // surface today carries no `tier` query parameter, so an
        // explicit-vs-default conflict cannot arise yet — the splice
        // is unconditional when present.
        if let Some(t) = recall_scope_tier
            && let Some(parsed) = crate::models::Tier::from_str(t)
        {
            filter.tier = Some(parsed);
        }
        if let Some(t) = tags {
            filter.tags_any = t
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
        }
        if let Some(s) = since
            && let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s)
        {
            filter.since = Some(dt.into());
        }
        if let Some(u) = until
            && let Ok(dt) = chrono::DateTime::parse_from_rfc3339(u)
        {
            filter.until = Some(dt.into());
        }
        return match app
            .store
            .recall_hybrid(&ctx_caller, context, query_emb.as_deref(), &filter)
            .await
        {
            Ok(scored_pairs) => {
                // v0.7.0 Form 4 (issue #757) — fact-provenance post-filter
                // applies on the postgres SAL path too. Touch ops fire on
                // the FILTERED set so a memory the caller filtered out by
                // provenance does not leak through to the access_count
                // ladder.
                let scored_pairs = crate::cli::recall::apply_form4_recall_filters(
                    scored_pairs,
                    has_citations,
                    source_uri_prefix,
                );
                // v0.7.x Form 6 — apply post-fetch kinds filter on the
                // postgres SAL branch. OR-of-kinds within the param.
                let scored_pairs: Vec<_> = match kinds_filter {
                    None => scored_pairs,
                    Some(allowed) => scored_pairs
                        .into_iter()
                        .filter(|(m, _)| allowed.contains(&m.memory_kind))
                        .collect(),
                };
                // v0.7.0 (issue #518) — per-session recency boost +
                // post-recall record. No-op when `session_id` is None
                // or empty.
                let scored_pairs = crate::reranker::apply_session_recency_boost(
                    scored_pairs,
                    session_id,
                    session_tracker,
                );
                let touch_ids: Vec<String> =
                    scored_pairs.iter().map(|(m, _)| m.id.clone()).collect();
                // #869 — `serde_json::to_value(m).unwrap_or_default()`
                // would have surfaced a `Value::Null` row in the recall
                // payload on a Memory-serialise failure, which the
                // client would parse as a real memory with every field
                // null. `filter_map` + log preserves the rest of the
                // batch and lets operators investigate the bad row.
                //
                // v0.7.x #1155 — `Accept-Provenance: verbose` is
                // honoured on the sqlite branch (decorate_memory adds
                // the Gap 7 derived fields). The postgres branch
                // currently ships the bare serde-roundtripped Memory
                // shape regardless of the header — Form 4/5/6 columns
                // (citations, source_uri, source_span, confidence_source,
                // memory_kind) are still present via serde derives, but
                // the latest_link_attest_level derivation requires a
                // rusqlite::Connection which the postgres SAL branch
                // does not hold. Postgres-side verbose decoration is a
                // tracked follow-up; the substrate's structural NSA
                // CSI MCP coverage at v0.7.x stands at 10/10 with
                // sqlite as the canonical default backend.
                if provenance_shape.is_verbose() {
                    tracing::info!(
                        "recall (postgres): Accept-Provenance: verbose received; \
                         postgres-side verbose decoration not yet implemented — \
                         shipping bare Form 4/5/6 envelope. Sqlite path supports verbose."
                    );
                }
                let scored: Vec<serde_json::Value> = scored_pairs
                    .iter()
                    .filter_map(|(m, s)| match serde_json::to_value(m) {
                        Ok(mut v) => {
                            if let Some(obj) = v.as_object_mut() {
                                obj.insert(
                                    "score".to_string(),
                                    json!((*s * 1000.0).round() / 1000.0),
                                );
                            }
                            Some(v)
                        }
                        Err(e) => {
                            tracing::error!(
                                memory_id = %m.id,
                                "recall (postgres): serialise Memory failed, skipping row: {e}"
                            );
                            None
                        }
                    })
                    .collect();
                // Touch ops AFTER assembling the response payload so the
                // observable response is what the caller wanted (access_count
                // pre-touch); the touch fires inside the trait call's own
                // transaction.
                if let Err(e) = app.store.touch_after_recall(&touch_ids).await {
                    tracing::warn!("recall (postgres): touch_after_recall failed: {e}");
                }
                let mut resp = json!({
                    "memories": scored,
                    "count": scored.len(),
                    "tokens_used": 0,
                    "mode": mode,
                    "storage_backend": "postgres",
                });
                if let Some(b) = budget_tokens {
                    resp["budget_tokens"] = json!(b);
                }
                Json(resp).into_response()
            }
            Err(e) => store_err_to_response(e),
        };
    }

    // Embed the query BEFORE grabbing the DB lock — embed() is CPU-heavy
    // and holding the SQLite mutex across it serialises unrelated writes.
    let query_emb: Option<Vec<f32>> = if let Some(emb) = app.embedder.as_ref().as_ref() {
        match emb.embed(context) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!("recall: embedder query failed, falling back to keyword-only: {e}");
                None
            }
        }
    } else {
        None
    };

    // FX-4 / PERF-2 (2026-05-26) — release the DB mutex across the
    // HNSW search + post-recall decoration. Pre-fix the handler held
    // `db.lock().await` across:
    //   1. the HNSW `idx.search()` (CPU-bound vector walk)
    //   2. `db::recall_hybrid` itself (FTS5 + get_many + touch)
    //   3. the per-row `decorate_memory` loop (N extra round-trips
    //      for `latest_link_attest_level` under verbose provenance)
    // serialising every concurrent recall behind one another at the
    // single-connection mutex. Lock-release boundary (this commit):
    //
    //   a) Take VI lock briefly → run `idx.search()` → drop VI lock.
    //      HNSW search runs OUTSIDE the DB lock so concurrent recalls
    //      overlap their CPU-bound ANN walks.
    //   b) Acquire DB lock briefly → call recall (FTS5 + the batched
    //      `get_many` round-trip for the HNSW hits + touch ops) →
    //      drop DB lock.
    //   c) Post-filters (form4 / kinds / session-recency) run on
    //      owned `Memory` rows OUTSIDE the lock — they're pure CPU.
    //   d) Re-acquire DB lock briefly for `decorate_memory_many`
    //      (one IN(...) SQL emit covers the verbose-provenance
    //      attestation lookup for the full batch) → drop DB lock.
    //
    // Net effect: the DB-mutex hold window covers only the FTS5
    // query and the batched get_many fetch + touch (and a brief
    // re-acquire for verbose decoration), not the HNSW search and
    // not N per-row attestation queries. Regression pin lives at
    // `tests/recall_no_lock_across_hnsw.rs`.

    // Stage (a) — HNSW search OUTSIDE the DB lock. The vector_index
    // mutex is its own lock and does not touch the DB connection,
    // so taking + releasing it here costs nothing in DB-mutex
    // contention. `idx.search()` reads the immutable active graph
    // and returns owned `Vec<VectorHit>`; the guard drops at the
    // end of this scope so the next recall's search can overlap.
    let precomputed_hits: Option<Vec<crate::hnsw::VectorHit>> = if let Some(ref qe) = query_emb {
        let vi_guard = app.vector_index.lock().await;
        let hits = if let Some(idx) = vi_guard.as_ref() {
            let ann_limit = (limit * 5).max(50);
            idx.search(qe, ann_limit)
        } else {
            // No HNSW index → empty hit slice. `semantic_phase`
            // skips the per-hit loop on an empty slice and falls
            // through to the linear-scan branch under the lock
            // (preserving pre-fix behaviour for the no-HNSW path).
            Vec::new()
        };
        Some(hits)
    } else {
        None
    };

    // Stage (b) — DB lock for the FTS5 query + get_many for the
    // pre-computed HNSW hits + touch ops. Scoped tightly so the
    // guard drops as soon as `recall_hybrid_precomputed_hnsw` /
    // `recall` returns.
    let (result, mode) = {
        let lock = app.db.lock().await;
        let short_extend = lock.2.short_extend_secs;
        let mid_extend = lock.2.mid_extend_secs;
        let (result, mode) = if let Some(ref qe) = query_emb {
            // SAFETY: `precomputed_hits` is Some when `query_emb` is
            // Some, by construction of the if-let above. The empty
            // slice case (no HNSW index) still threads through the
            // precomputed-hits path; `semantic_phase` short-circuits
            // on `hits.is_empty()` and the linear-scan fallback at
            // the bottom of the function runs (same behaviour as the
            // pre-fix `idx = None` branch).
            let hits = precomputed_hits
                .as_deref()
                .expect("precomputed_hits set when query_emb is Some");
            let r = db::recall_hybrid_precomputed_hnsw(
                &lock.0,
                context,
                qe,
                namespace,
                limit,
                tags,
                since,
                until,
                hits,
                short_extend,
                mid_extend,
                // #928 SECURITY-medium (Track A P5, 2026-05-20):
                // thread the header-resolved caller_principal as the
                // visibility-filter principal so scope=private rows
                // owned by other agents are NOT leaked when the
                // caller doesn't set body.as_agent. See the matching
                // longer note on the pre-FX-4 code for the rationale.
                as_agent.or(caller_principal),
                budget_tokens,
                app.scoring.as_ref(),
                false,
                // v0.7.0 Cluster-A PERF-3 — push the prefix into SQL
                // on both FTS and semantic branches so the partial
                // idx_memories_source_uri index covers the lookup;
                // the post-fetch apply_form4_recall_filters below
                // remains for the `has_citations` axis.
                source_uri_prefix,
            );
            (r, "hybrid")
        } else {
            let r = db::recall(
                &lock.0,
                context,
                namespace,
                limit,
                tags,
                since,
                until,
                short_extend,
                mid_extend,
                // #928 — same caller_principal fallback as the hybrid
                // branch above; see the longer note there.
                as_agent.or(caller_principal),
                budget_tokens,
                false,
                // v0.7.0 Cluster-A PERF-3 — see hybrid branch above.
                source_uri_prefix,
            );
            (r, "keyword")
        };
        (result, mode)
        // `lock` drops here — every line below this block runs
        // WITHOUT the DB mutex held. short_extend / mid_extend are
        // consumed by the recall call above and are not needed after
        // the lock releases.
    };

    match result {
        Ok((r, outcome)) => {
            // v0.7.0 Form 4 (issue #757) — fact-provenance post-filter.
            // Stage (c) — these post-filters run on OWNED Memory rows;
            // no DB connection needed. The lock is already dropped.
            let r =
                crate::cli::recall::apply_form4_recall_filters(r, has_citations, source_uri_prefix);
            // v0.7.x Form 6 — apply post-fetch kinds filter on the
            // sqlite branch. Cheap because recall already capped
            // r.len() at limit.min(50).
            let r: Vec<_> = match kinds_filter {
                None => r,
                Some(allowed) => r
                    .into_iter()
                    .filter(|(m, _)| allowed.contains(&m.memory_kind))
                    .collect(),
            };
            // v0.7.0 (issue #518) — per-session recency boost +
            // post-recall record on the sqlite branch.
            let r = crate::reranker::apply_session_recency_boost(r, session_id, session_tracker);
            // Stage (d) — verbose-provenance decoration. The
            // per-row `latest_link_attest_level` lookup used to fire
            // N round-trips under the DB lock; FX-4 / PERF-2 routes
            // through `decorate_memory_many` which issues ONE
            // IN(...) SQL emit for the whole batch under a briefly
            // re-acquired lock. The verbose-OFF path stays pure-CPU
            // and runs without the lock.
            //
            // #869 — `Value::Null` masking discipline kept: the
            // serialise step inside `decorate_memory_many` mirrors
            // the per-row `serde_json::to_value(mem).unwrap_or_default()`
            // shape, so a Memory-serialise failure surfaces as the
            // `Value::Null` row that the postgres branch also
            // produces; the sqlite parity here matches the upstream
            // contract (#869) and the pre-#1155 verbose shape.
            //
            // v0.7.x #1155 — Accept-Provenance: verbose shape
            // remains the gate (confidence_tier, freshness_state,
            // latest_link_attest_level). Default HTTP shape stays
            // bare for v0.6.x backwards compat per the existing
            // contract on this surface.
            let scored: Vec<serde_json::Value> = if provenance_shape.is_verbose() {
                // Re-acquire DB lock briefly for the batched
                // attestation lookup; the lock guard drops at the
                // end of this block. One IN(...) SQL emit covers the
                // whole batch instead of N per-row round-trips.
                let lock = app.db.lock().await;
                let out = crate::mcp::decorate_memory_many(&r, true, &lock.0);
                drop(lock);
                out
            } else {
                // Verbose-OFF path: pure-CPU serde shape. No DB
                // access required; the lock is NOT re-acquired here.
                // Mirrors the pre-FX-4 bare-shape branch byte-for-
                // byte, including the #869 `Value::Null` masking
                // discipline (a Memory-serialise failure surfaces as
                // a `Value::Null` row + tracing::error).
                r.iter()
                    .filter_map(|(m, s)| match serde_json::to_value(m) {
                        Ok(mut v) => {
                            if let Some(obj) = v.as_object_mut() {
                                obj.insert(
                                    "score".to_string(),
                                    json!((*s * 1000.0).round() / 1000.0),
                                );
                            }
                            Some(v)
                        }
                        Err(e) => {
                            tracing::error!(
                                memory_id = %m.id,
                                "recall (sqlite): serialise Memory failed, skipping row: {e}"
                            );
                            None
                        }
                    })
                    .collect()
            };
            let mut resp = json!({
                "memories": scored,
                "count": scored.len(),
                "tokens_used": outcome.tokens_used,
                "mode": mode,
            });
            if let Some(b) = budget_tokens {
                resp["budget_tokens"] = json!(b);
                // Phase P6 (R1) meta block — same shape as the MCP path.
                resp["meta"] = json!({
                    "budget_tokens_used": outcome.tokens_used,
                    "budget_tokens_remaining": outcome.tokens_remaining.unwrap_or(0),
                    "memories_dropped": outcome.memories_dropped,
                    "budget_overflow": outcome.budget_overflow,
                });
            }
            Json(resp).into_response()
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
