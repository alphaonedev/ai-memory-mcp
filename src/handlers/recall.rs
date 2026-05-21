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
    recall_response(
        &app,
        &req,
        Some(caller_principal.as_str()),
        scope_tier.as_deref(),
        kinds.as_deref(),
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
    recall_response(
        &app,
        &req,
        Some(caller_principal.as_str()),
        scope_tier.as_deref(),
        kinds.as_deref(),
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

    // v0.7.0 #982 — invert lock acquisition order so the
    // vector_index mutex is taken BEFORE the (singleton) DB mutex.
    // Pre-#982 the handler took DB then VI, which serialized every
    // recall through both locks in DB-first order; HNSW eviction
    // and embedder writes that grab the VI lock alone (e.g.
    // `src/handlers/create.rs:541`) had a different lock-order
    // semantic that risked deadlock if any future code path took DB
    // INSIDE a VI guard. The invert puts the read-path order in
    // line with the rest of the codebase. The deeper perf win
    // (HNSW search OUTSIDE the DB lock so concurrent recalls overlap
    // their CPU-bound ANN walks) is tracked as a follow-up; it
    // requires changing `recall_hybrid` / `recall_hybrid_with_telemetry`
    // / `semantic_phase` to accept precomputed `Option<Vec<VectorHit>>`
    // and threading the change through 4 callers (handler + MCP tool
    // + CLI + SAL adapter). Post-#981 the DB lock hold during
    // semantic_phase is much shorter (1 batched SELECT vs N), so the
    // marginal value of the deep refactor is reduced; this commit
    // ships the order-invert win + caches the TTL config out of the
    // mutex tuple so it doesn't need a re-read on every recall.
    let vi_guard_outer = if query_emb.is_some() {
        Some(app.vector_index.lock().await)
    } else {
        None
    };
    let lock = app.db.lock().await;
    let short_extend = lock.2.short_extend_secs;
    let mid_extend = lock.2.mid_extend_secs;

    let (result, mode) = if let Some(ref qe) = query_emb {
        // The VI guard is held since the outer if-let above; cannot
        // move it into the inner scope without re-acquiring the lock.
        let vi_guard = vi_guard_outer
            .as_ref()
            .expect("vi_guard_outer set when query_emb is Some");
        let vi_ref = vi_guard.as_ref();
        let r = db::recall_hybrid(
            &lock.0,
            context,
            qe,
            namespace,
            limit,
            tags,
            since,
            until,
            vi_ref,
            short_extend,
            mid_extend,
            // #928 SECURITY-medium (Track A P5, 2026-05-20):
            // thread the header-resolved caller_principal as the
            // visibility-filter principal so scope=private rows owned
            // by other agents are NOT leaked when the caller doesn't
            // set body.as_agent. Pre-fix the sqlite path passed only
            // `as_agent` (typically None from real callers) and the
            // visibility_clause short-circuited to "all rows visible".
            // Mirror of the postgres SAL branch's
            // `as_agent.or(caller_principal).unwrap_or("daemon")`.
            as_agent.or(caller_principal),
            budget_tokens,
            app.scoring.as_ref(),
            false,
            // v0.7.0 Cluster-A PERF-3 — push the prefix into SQL on
            // both FTS and semantic branches so the partial
            // idx_memories_source_uri index covers the lookup; the
            // post-fetch apply_form4_recall_filters below remains for
            // the `has_citations` axis.
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

    match result {
        Ok((r, outcome)) => {
            // v0.7.0 Form 4 (issue #757) — fact-provenance post-filter.
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
            // #869 — same `Value::Null` masking fix as the postgres
            // branch above; sqlite branch needs the identical
            // filter_map + log so an encoder regression cannot silently
            // drop fields from a recall row to look like a real null.
            let scored: Vec<serde_json::Value> = r
                .iter()
                .filter_map(|(m, s)| match serde_json::to_value(m) {
                    Ok(mut v) => {
                        if let Some(obj) = v.as_object_mut() {
                            obj.insert("score".to_string(), json!((*s * 1000.0).round() / 1000.0));
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
                .collect();
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
