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

use crate::models::field_names;
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
            Json(json!({"error": crate::errors::msg::invalid("as_agent", e)})),
        )
            .into_response();
    }
    // v1.0.0 #1834 — RFC3339-validate the claim-bitemporal AS-OF at the entry
    // handler (recall_response returns a tuple and cannot surface a 400, so the
    // guard belongs here). A malformed value would otherwise mis-filter via the
    // lexicographic SQL compare.
    if let Some(ref v) = req.valid_at
        && let Err(e) = validate::validate_valid_at(v)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": crate::errors::msg::invalid("valid_at", e)})),
        )
            .into_response();
    }
    // #1579 B4 — negotiate the response format BEFORE doing any work.
    // `json` (default) keeps the legacy envelope; `toon` /
    // `toon_compact` reuse the MCP TOON encoder; anything else is a
    // 400 with the SSOT message.
    let format = match crate::toon::WireFormat::parse_http(req.format.as_deref()) {
        Ok(f) => f,
        Err(e) => return crate::handlers::wire_format::invalid_format_response(&e),
    };
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
    // #2044 (#2032-A / H1 IDOR) — per-agent-key identity gate on the RECALL
    // surface: under `enforce` a shared-key `Claimed` caller acting as a named
    // principal cannot recall the victim's scope=private rows.
    if let Some(resp) = crate::handlers::identity_binding::enforce_for_request(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        &caller_principal,
        "recall_memories_get",
    ) {
        return resp;
    }
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
        format,
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
            Json(json!({"error": crate::errors::msg::invalid("as_agent", e)})),
        )
            .into_response();
    }
    // v1.0.0 #1834 — RFC3339-validate the claim-bitemporal AS-OF (see GET path).
    if let Some(ref v) = req.valid_at
        && let Err(e) = validate::validate_valid_at(v)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": crate::errors::msg::invalid("valid_at", e)})),
        )
            .into_response();
    }
    // #1579 B4 — same format negotiation as the GET path.
    let format = match crate::toon::WireFormat::parse_http(req.format.as_deref()) {
        Ok(f) => f,
        Err(e) => return crate::handlers::wire_format::invalid_format_response(&e),
    };
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
    // #2044 (#2032-A / H1 IDOR) — per-agent-key identity gate (POST recall
    // parity with the GET surface).
    if let Some(resp) = crate::handlers::identity_binding::enforce_for_request(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        &caller_principal,
        "recall_memories_post",
    ) {
        return resp;
    }
    // v0.7.x #1155 — same Accept-Provenance gating as the GET path.
    let provenance_shape = crate::handlers::accept_provenance::resolve_from_headers(&headers);
    recall_response(
        &app,
        &req,
        Some(caller_principal.as_str()),
        scope_tier.as_deref(),
        kinds.as_deref(),
        provenance_shape,
        format,
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
/// The full hybrid (FTS + semantic + adaptive blend + session-recency boost
/// + touch ops) pipeline remains sqlite-only in v0.7.0. #1691: the HTTP
/// surface now runs the autonomous-tier cross-encoder reranker on the
/// hybrid path (sqlite AND postgres SAL) when the resolved tier enables
/// the cross-encoder — the reranker is built at `serve` boot and read via
/// `app.runtime.reranker()`, so the envelope reports `hybrid+rerank`
/// exactly as the MCP/CLI recall paths do (closing the prior n23 gap).
/// Postgres deployments
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
/// #1691 — apply the autonomous-tier cross-encoder rerank stage on the
/// hybrid recall path, unifying the sqlite and postgres-SAL HTTP recall
/// branches with the MCP/CLI recall pipeline.
///
/// No-op (returns `pairs` and `mode` unchanged) on keyword-only recall
/// (`mode != "hybrid"`, i.e. the embedder produced no semantic component)
/// or when no reranker was installed at `serve` boot (`reranker` is
/// `None` — every non-autonomous tier, and all unit-test `AppState`
/// scaffolds). On the hybrid path with a reranker present it re-scores
/// the `(query, content)` pairs via the batched cross-encoder and returns
/// the [`RECALL_MODE_HYBRID_RERANK`] label so the response envelope
/// advertises the stage exactly as the MCP recall path does.
///
/// [`RECALL_MODE_HYBRID_RERANK`]: crate::models::RECALL_MODE_HYBRID_RERANK
fn maybe_apply_rerank<'m>(
    reranker: Option<&crate::reranker::BatchedReranker>,
    mode: &'m str,
    context: &str,
    pairs: Vec<(crate::models::Memory, f64)>,
) -> (Vec<(crate::models::Memory, f64)>, &'m str) {
    match reranker {
        Some(ce) if mode == "hybrid" => (
            ce.rerank(context, pairs),
            crate::models::RECALL_MODE_HYBRID_RERANK,
        ),
        _ => (pairs, mode),
    }
}

/// F-L8a — fold the `semantic_withheld` block into the recall response's
/// `meta` object (creating it if absent), preserving any budget sub-block
/// already merged. Shared by the sqlite (MEASURED) and postgres
/// (UNMEASURED) HTTP recall branches so the wire key is present on both
/// backends. See [`crate::models::SemanticWithheld`].
fn merge_semantic_withheld_meta(
    resp: &mut serde_json::Value,
    sw: &crate::models::SemanticWithheld,
) {
    let value = serde_json::to_value(sw).unwrap_or(serde_json::Value::Null);
    let meta = resp
        .as_object_mut()
        .expect("recall response is always a JSON object")
        .entry("meta".to_string())
        .or_insert_with(|| json!({}));
    if let Some(obj) = meta.as_object_mut() {
        obj.insert("semantic_withheld".to_string(), value);
    }
}

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
    // #1579 B4 — negotiated response format (json default | toon |
    // toon_compact), parsed + validated by the entry handlers.
    format: crate::toon::WireFormat,
) -> axum::response::Response {
    let context = req.context.as_str();
    let namespace = req.namespace.as_deref();
    let limit = req.resolved_limit().min(50);
    let tags = req.tags.as_deref();
    let since = req.since.as_deref();
    let until = req.until.as_deref();
    // v1.0.0 #1834 — claim-bitemporal AS-OF. RFC3339 shape is validated at the
    // entry handlers (GET/POST/MCP/CLI); here it is threaded into the recall
    // SQL where it filters `valid_from`/`valid_until` (end-exclusive).
    let valid_at = req.valid_at.as_deref();
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
    // #1839 (TRACT-gap G31) — time the recall so the already-registered
    // `ai_memory_recall_latency_seconds` histogram (labeled by `mode`) is
    // actually observed instead of reporting permanent zeros. Observability
    // ONLY — no latency governor acts on it (that is the deferred G31 gap).
    let recall_started = std::time::Instant::now();
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
        // v1.0.0 #2577 — route through the ONE bounded funnel
        // (`recall_query_embedding`): process-local cache, then a
        // wall-clock budget, then degrade to keyword. The funnel owns the
        // WARN + the `ai_memory_recall_embed_degraded_total` counter, so a
        // slow provider bounds the read instead of hanging it (and, on the
        // HTTP daemon, instead of holding an admission permit for 30 s).
        let query_emb: Option<Vec<f32>> = app
            .embedder
            .as_ref()
            .as_ref()
            .and_then(|emb| crate::embeddings::recall_query_embedding(emb, context));
        let mode = if query_emb.is_some() {
            crate::models::RECALL_MODE_HYBRID
        } else {
            crate::models::RECALL_MODE_KEYWORD
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
                .unwrap_or(crate::identity::sentinels::DAEMON_PRINCIPAL)
                .to_string(),
        );
        let mut filter = crate::store::Filter {
            namespace: namespace.map(str::to_string),
            limit,
            // v1.0.0 #2167 §3 — stamp the active embedder fingerprint so
            // the SAL recall gate (sqlite comparator / postgres `AND
            // embedding_space = $fp` predicate) never scores a foreign or
            // unverified vector. Only meaningful when we embedded a query.
            active_embedding_space: query_emb.as_ref().and_then(|_| {
                app.embedder
                    .as_ref()
                    .as_ref()
                    .map(|e| e.space_fingerprint())
            }),
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
        // v1.0.0 #1834 — carry the claim-bitemporal AS-OF onto the SAL Filter
        // (RFC3339 shape validated at the entry handlers). Stored as the raw
        // RFC3339 string; the SAL recall/list SQL binds it directly.
        filter.valid_at = valid_at.map(str::to_string);
        // This handler records the POST-form4 / kinds / rerank set under
        // the `recall_id` echoed in the response (touch ops fire on the
        // FILTERED set — comment at apply_form4 below). Without the skip,
        // `PostgresStore::recall_hybrid` (#3180) also appended the
        // PRE-filter set under a different recall_id, so every HTTP pg
        // recall folded 2× — the #3266 access-fold echo amplifier.
        filter.skip_access_ledger = true;
        return match app
            .store
            .recall_hybrid(&ctx_caller, context, query_emb.as_deref(), &filter)
            .await
        {
            Ok(scored_pairs) => {
                // #3348 — SAL adapters enforce tenant visibility, but the HTTP
                // funnel owns the additional ambient-substrate rule because it
                // depends on whether this exact request named a namespace.
                let scored_pairs: Vec<_> = scored_pairs
                    .into_iter()
                    .filter(|(m, _)| {
                        crate::visibility::is_readable_on_query(
                            m,
                            as_agent.or(caller_principal),
                            namespace,
                        )
                    })
                    .collect();
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
                // #1691 — cross-encoder rerank on the hybrid path
                // (postgres SAL), mirroring the MCP recall pipeline
                // (crate::mcp::tools::recall). See [`maybe_apply_rerank`].
                let (scored_pairs, mode) = maybe_apply_rerank(
                    app.runtime.reranker().map(std::convert::AsRef::as_ref),
                    mode,
                    context,
                    scored_pairs,
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
                // PR-C pg-parity (5-agent vote 4d3ea1c5) — restore the
                // `Accept-Provenance: verbose` `latest_link_attest_level`
                // decoration on the postgres recall path. The sqlite branch
                // adds it via `decorate_memory_many`; the pg branch used to
                // drop it (the sqlite decorator needs a rusqlite::Connection
                // the pg adapter does not hold) and only logged a
                // not-yet-implemented notice. The SAL `latest_link_attest_levels`
                // method closes that backend gap with one batched
                // `memory_links` scan + the shared best-of ranking, so the pg
                // verbose envelope now matches sqlite field-for-field.
                // Best-effort: a lookup error degrades to no decoration
                // (fewer fields, never wrong fields) and never blocks recall.
                let attest_map: std::collections::HashMap<String, String> = if provenance_shape
                    .is_verbose()
                {
                    let ids: Vec<&str> = scored_pairs.iter().map(|(m, _)| m.id.as_str()).collect();
                    match app.store.latest_link_attest_levels(&ids).await {
                        Ok(map) => map,
                        Err(e) => {
                            tracing::warn!(
                                "recall (postgres): latest_link_attest_levels failed \
                                     (verbose decoration skipped, non-fatal): {e}"
                            );
                            std::collections::HashMap::new()
                        }
                    }
                } else {
                    std::collections::HashMap::new()
                };
                let scored: Vec<serde_json::Value> = scored_pairs
                    .iter()
                    .filter_map(|(m, s)| match serde_json::to_value(m) {
                        Ok(mut v) => {
                            if let Some(obj) = v.as_object_mut() {
                                obj.insert(
                                    "score".to_string(),
                                    json!(
                                        (*s * crate::SCORE_DISPLAY_ROUND_FACTOR).round()
                                            / crate::SCORE_DISPLAY_ROUND_FACTOR
                                    ),
                                );
                                // PR-C — verbose provenance parity: attach the
                                // strongest incident-edge attestation, matching
                                // the sqlite `decorate_memory_many` wire field.
                                if let Some(level) = attest_map.get(&m.id) {
                                    obj.insert(
                                        "latest_link_attest_level".to_string(),
                                        json!(level),
                                    );
                                }
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
                // v1.0.0 (#1953) — recall is now UNCONDITIONALLY pure: the
                // deprecated `AI_MEMORY_RECALL_TOUCH_SYNC` synchronous-touch
                // opt-back-in was removed (deprecated at birth by the #1869
                // pure-recall vote; one-cycle v0.10.0 deprecation WARN
                // shipped per CHANGELOG.md). The access ladders are applied
                // by the periodic FOLD job (`MemoryStore::fold_recall_accesses`)
                // from the unfolded `recall_observations` ledger rows written
                // just below.
                // #1705 — populate the recall_observations ledger via the
                // SAL trait so postgres-backed daemons record recalls (the
                // write side was sqlite/MCP-only pre-#1705, so a postgres
                // daemon never logged a recall). Best-effort: a ledger error
                // never blocks the recall response. The recall_id is echoed
                // so a caller can cite it on a later memory_store / link.
                let recall_id = uuid::Uuid::new_v4().to_string();
                {
                    #[allow(clippy::cast_possible_wrap)]
                    let candidates: Vec<(String, String, i64, f64)> = scored_pairs
                        .iter()
                        .enumerate()
                        .map(|(i, (m, s))| (m.id.clone(), mode.to_string(), (i + 1) as i64, *s))
                        .collect();
                    if let Err(e) = app
                        .store
                        .record_recall_observation(
                            &recall_id,
                            &candidates,
                            as_agent.or(caller_principal),
                            namespace,
                        )
                        .await
                    {
                        tracing::warn!(
                            "recall (postgres): record_recall_observation failed (non-fatal): {e}"
                        );
                    }
                }
                let mut resp = json!({
                    "memories": scored,
                    "count": scored.len(),
                    "recall_id": recall_id,
                    (field_names::TOKENS_USED): 0,
                    "mode": mode,
                    (field_names::STORAGE_BACKEND): "postgres",
                });
                if let Some(b) = budget_tokens {
                    resp[field_names::BUDGET_TOKENS] = json!(b);
                }
                // F-L8a — the postgres SAL `recall_hybrid` excludes foreign
                // / unverified-space rows in SQL (`AND embedding_space=$fp`)
                // but does NOT count them, so no per-query withheld counter
                // exists on this path today. Emit the block honestly as
                // UNMEASURED (numeric fields omitted) rather than fabricate a
                // `0` that could read as "nothing withheld" — the North-Star
                // "never a WRONG result". Real pg counting is a follow-up.
                merge_semantic_withheld_meta(
                    &mut resp,
                    &crate::models::SemanticWithheld::unmeasured(),
                );
                // #1839 G31 — observe recall latency (postgres path), labeled
                // by the final post-rerank `mode`.
                crate::metrics::record_recall(mode, recall_started.elapsed().as_secs_f64());
                // #1579 B4 — serialize per the negotiated format.
                crate::handlers::wire_format::memories_response(format, resp)
            }
            Err(e) => store_err_to_response(e),
        };
    }

    // Embed the query BEFORE grabbing the DB lock — embed() is CPU-heavy
    // and holding the SQLite mutex across it serialises unrelated writes.
    // v1.0.0 #2577 — bounded funnel (cache -> budget -> degrade-to-keyword).
    // See the postgres branch above; the funnel owns the WARN + counter.
    let query_emb: Option<Vec<f32>> = app
        .embedder
        .as_ref()
        .as_ref()
        .and_then(|emb| crate::embeddings::recall_query_embedding(emb, context));

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

    // v0.9 #1005 (§5.2) — opt-in namespace allowlist for the ANN
    // phase. When AI_MEMORY_VECTOR_NAMESPACE_ALLOWLIST is truthy AND
    // this recall is namespace-filtered, fetch the in-scope embedded
    // id set on the read pool (one indexed SELECT, outside both the
    // vector-index and writer locks) so the search below can walk the
    // nearest-first iterator lazily to k IN-NAMESPACE hits instead of
    // letting the global cutoff starve a small namespace. Flag unset
    // (the default) or no namespace filter: `None` — the search is
    // byte-identical legacy. A fetch error degrades to the legacy
    // unfiltered search (WARN), never blocks the recall.
    let ns_allowlist: Option<Vec<String>> = match namespace {
        Some(ns) if query_emb.is_some() && crate::hnsw::vector_ns_allowlist_enabled() => {
            let ns_owned = ns.to_string();
            match super::transport::flatten_db_op(
                super::read_pool::db_read_op(app.db.clone(), move |conn| {
                    db::vector_recall_allowlist_ids(conn, &ns_owned)
                })
                .await,
            ) {
                Ok(ids) => Some(ids),
                Err(e) => {
                    tracing::warn!(
                        "recall: §5.2 allowlist fetch failed; falling back to legacy \
                         unfiltered ANN search: {e}"
                    );
                    None
                }
            }
        }
        _ => None,
    };

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
            idx.search(qe, ann_limit, ns_allowlist.as_deref())
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

    // #1710 — populate the recall_observations ledger on the sqlite
    // HTTP recall branch too (the postgres branch records in the
    // handler after skip_access_ledger, #1705/#3180; the MCP path
    // does via the free-fn). Closes the §2.5 audit-parity gap: a
    // sqlite-backed daemon answering recall over HTTP never logged
    // the recall. The recall_id is echoed in the response so a
    // caller can cite it on a later memory_store / link.
    //
    // DEADLOCK GUARD: routing this through `app.store.record_recall_observation`
    // would re-acquire `self.state.lock()` WHILE the recall DB lock below
    // is held → deadlock. We instead call the FREE-FN
    // `crate::observations::record_recall_with_identity(&lock.0, ...)`
    // directly on the ALREADY-HELD connection (mirroring the MCP path),
    // so no second lock is ever taken. Recorded INSIDE the lock block,
    // before the guard drops at the end of the block.
    let recall_id = uuid::Uuid::new_v4().to_string();
    // #1580 / v1.0.0 (#1953) — recall is split across the WAL read-pool
    // and the writer, and is now UNCONDITIONALLY pure:
    //
    //   PHASE 1 (read-pool, `db_read_op`): the FTS5 query + `get_many`
    //   for the pre-computed HNSW hits + scoring run on a read-only pool
    //   connection so concurrent recalls overlap instead of serializing
    //   on the single writer mutex. The internal touch inside
    //   `recall_hybrid_precomputed_hnsw` / `recall` is unreachable on
    //   this path (the sync-touch opt-back-in was removed) AND would
    //   no-op on a read-only connection (`PRAGMA query_only = ON`)
    //   regardless — the read phase performs ZERO writes (the
    //   `short_extend`/`mid_extend` arguments are inert here). The
    //   returned `Memory` rows carry pre-touch `access_count`.
    //
    //   PHASE 2 (writer, `db_op`): ONLY the #1710 recall_observations
    //   ledger append runs — the append-only audit ledger is the single
    //   sanctioned recall-time write, and the periodic FOLD job
    //   (`db::fold_recall_accesses`) later applies the access ladders
    //   (access bump / TTL floor-extend / promotion / priority) from the
    //   unfolded rows. The write is best-effort: a failure logs at warn
    //   and never reshapes the response.
    let ctx_owned = context.to_string();
    let ns_owned = namespace.map(str::to_string);
    let tags_owned = tags.map(str::to_string);
    let since_owned = since.map(str::to_string);
    let until_owned = until.map(str::to_string);
    let valid_at_owned = valid_at.map(str::to_string);
    let source_uri_owned = source_uri_prefix.map(str::to_string);
    let agent_owned = as_agent.or(caller_principal).map(str::to_string);
    let caller_owned = caller_principal.map(str::to_string);
    let scoring = app.scoring.clone();
    let qe_owned = query_emb.clone();
    let hits_owned = precomputed_hits.clone();
    // v1.0.0 #2167 §3 — the active embedder fingerprint, owned so it
    // moves into the read-pool closure; gates the sqlite recall so a
    // foreign / unverified vector is never scored.
    let active_space_owned: Option<String> = qe_owned.as_ref().and_then(|_| {
        app.embedder
            .as_ref()
            .as_ref()
            .map(|e| e.space_fingerprint())
    });
    // #3164 — a dispatch failure (a panicking read closure, or a shutting-down
    // runtime) surfaces as an `Err` recall result on the SAME path the
    // substrate's own errors take, so the handler renders one 500 rather than
    // re-panicking the connection task.
    let (result, mode) = match super::read_pool::db_read_op(app.db.clone(), move |conn| {
        if let Some(qe) = qe_owned.as_deref() {
            // SAFETY: `precomputed_hits` is Some when `query_emb` is
            // Some, by construction of the if-let above. The empty
            // slice case (no HNSW index) still threads through the
            // precomputed-hits path; `semantic_phase` short-circuits
            // on `hits.is_empty()` and the linear-scan fallback runs.
            let hits = hits_owned
                .as_deref()
                .expect("precomputed_hits set when query_emb is Some");
            // F-L8a — telemetry-bearing variant so the recall response can
            // surface the space/unverified/dim rows withheld from semantic
            // scoring (the base `recall_hybrid_precomputed_hnsw` wrapper
            // drops the telemetry). MEASURED sqlite funnel.
            let r = db::recall_hybrid_with_telemetry_precomputed_hnsw(
                conn,
                &ctx_owned,
                qe,
                ns_owned.as_deref(),
                limit,
                tags_owned.as_deref(),
                since_owned.as_deref(),
                until_owned.as_deref(),
                hits,
                // #1580 — extends inert on the read-only pool conn; the
                // internal touch no-ops and phase 2 does the real touch.
                0,
                0,
                // #928 SECURITY-medium — visibility-filter principal.
                agent_owned.as_deref(),
                budget_tokens,
                scoring.as_ref(),
                false,
                // v0.7.0 Cluster-A PERF-3 — source_uri prefix pushed to SQL.
                source_uri_owned.as_deref(),
                // v0.8.0 #1720 A3 — owner-keyed visibility caller.
                caller_owned.as_deref(),
                // v1.0.0 #2167 §3 — active embedder fingerprint gate.
                active_space_owned.as_deref(),
                // v1.0.0 #1834 — claim-bitemporal AS-OF instant.
                valid_at_owned.as_deref(),
            );
            (r, crate::models::RECALL_MODE_HYBRID)
        } else {
            // Keyword-only: no semantic scoring ran, so nothing was
            // withheld from it — a zeroed telemetry is the truthful
            // MEASURED value (F-L8a). Append it so both branches share the
            // (rows, outcome, telemetry) shape.
            let r = db::recall(
                conn,
                &ctx_owned,
                ns_owned.as_deref(),
                limit,
                tags_owned.as_deref(),
                since_owned.as_deref(),
                until_owned.as_deref(),
                0,
                0,
                agent_owned.as_deref(),
                budget_tokens,
                false,
                source_uri_owned.as_deref(),
                caller_owned.as_deref(),
                valid_at_owned.as_deref(),
            )
            .map(|(rows, outcome)| (rows, outcome, crate::models::RecallTelemetry::default()));
            (r, crate::models::RECALL_MODE_KEYWORD)
        }
    })
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            return crate::handlers::errors::handler_error_500(&e);
        }
    };

    // #3348 — apply the HTTP ambient-substrate rule before phase 2 records
    // recall observations. A withheld row must neither reach the response nor
    // leave a caller-visible access-ledger trace. Owner/inbox confinement stays
    // delegated to the same canonical predicate.
    let result = result.map(|(rows, outcome, telemetry)| {
        let rows: Vec<_> = rows
            .into_iter()
            .filter(|(m, _)| {
                crate::visibility::is_readable_on_query(m, as_agent.or(caller_principal), namespace)
            })
            .collect();
        (rows, outcome, telemetry)
    });

    // PHASE 2 (writer) — authoritative touch + recall_observations
    // ledger, batched under one brief writer lock. Mirrors the postgres
    // branch's post-response touch + #1705 ledger.
    if let Ok((rows, _, _)) = result.as_ref() {
        #[allow(clippy::cast_possible_wrap)]
        let recorded: Vec<(String, i64, f64)> = rows
            .iter()
            .enumerate()
            .map(|(i, (m, s))| (m.id.clone(), (i + 1) as i64, *s))
            .collect();
        let recall_id_w = recall_id.clone();
        // Owned ledger identity, re-derived from the still-in-scope
        // borrowed params (the phase-1 copies were moved into the pool
        // closure). Mirrors the pre-split `as_agent.or(caller_principal)`
        // + `namespace` stamping.
        let agent_for_ledger = as_agent.or(caller_principal).map(str::to_string);
        let ns_for_ledger = namespace.map(str::to_string);
        if let Err(e) = super::db_op(app.db.clone(), move |guard| {
            // #1710 — record the recalled set into the ledger on the
            // writer connection (no second lock; mirrors the MCP free-fn).
            if crate::observations::table_exists(&guard.0) {
                let candidates: Vec<crate::observations::Candidate<'_>> = recorded
                    .iter()
                    .map(|(id, rank, score)| crate::observations::Candidate {
                        memory_id: id.as_str(),
                        retriever: mode,
                        rank: *rank,
                        score: *score,
                    })
                    .collect();
                if let Err(e) = crate::observations::record_recall_with_identity(
                    &guard.0,
                    &recall_id_w,
                    &candidates,
                    agent_for_ledger.as_deref(),
                    ns_for_ledger.as_deref(),
                ) {
                    tracing::warn!("recall (sqlite-http): record_recall failed (non-fatal): {e}");
                }
            }
        })
        .await
        {
            // #3164 — the ledger write is best-effort telemetry (its own
            // internal failure already only WARNs), so a dispatch failure is
            // logged and the recall response still returns the rows the read
            // phase truthfully produced.
            tracing::warn!(
                target: crate::handlers::transport::DB_OP_TRACE_TARGET,
                error = %e,
                "recall (sqlite-http): observation-ledger write could not be dispatched"
            );
        }
    }

    match result {
        Ok((r, outcome, telemetry)) => {
            // v0.7.0 Form 4 (issue #757) — fact-provenance post-filter.
            // Stage (c) — these post-filters run on OWNED Memory rows;
            // no DB connection needed. The lock is already dropped.
            let r =
                crate::cli::recall::apply_form4_recall_filters(r, has_citations, source_uri_prefix);
            // #1691 — cross-encoder rerank on the hybrid path (sqlite),
            // mirroring the MCP recall pipeline (crate::mcp::tools::recall).
            // See [`maybe_apply_rerank`]; closes the prior n23
            // "HTTP does NOT run the reranker" gap.
            let (r, mode) = maybe_apply_rerank(
                app.runtime.reranker().map(std::convert::AsRef::as_ref),
                mode,
                context,
                r,
            );
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
                                    json!(
                                        (*s * crate::SCORE_DISPLAY_ROUND_FACTOR).round()
                                            / crate::SCORE_DISPLAY_ROUND_FACTOR
                                    ),
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
                // #1710 — echo the recall_id for postgres-parity (line
                // ~553) so a caller can cite it on a later store / link.
                "recall_id": recall_id,
                (field_names::TOKENS_USED): outcome.tokens_used,
                "mode": mode,
            });
            if let Some(b) = budget_tokens {
                resp[field_names::BUDGET_TOKENS] = json!(b);
                // Phase P6 (R1) meta block — same shape as the MCP path.
                resp["meta"] = json!({
                    "budget_tokens_used": outcome.tokens_used,
                    "budget_tokens_remaining": outcome.tokens_remaining.unwrap_or(0),
                    (field_names::MEMORIES_DROPPED): outcome.memories_dropped,
                    "budget_overflow": outcome.budget_overflow,
                });
            }
            // F-L8a — always surface the MEASURED semantic-withheld block
            // (folded into `meta`, alongside any budget sub-block above) so
            // a JSON-only NHI hitting the sqlite HTTP recall sees in-band
            // when `mode:"hybrid"` scored fewer rows than the corpus holds.
            merge_semantic_withheld_meta(
                &mut resp,
                &crate::models::SemanticWithheld::measured(&telemetry),
            );
            // #1839 G31 — observe recall latency (sqlite path), labeled by the
            // final post-rerank `mode`.
            crate::metrics::record_recall(mode, recall_started.elapsed().as_secs_f64());
            // #1579 B4 — serialize per the negotiated format.
            crate::handlers::wire_format::memories_response(format, resp)
        }
        Err(e) => crate::handlers::errors::handler_error_500(&e),
    }
}

#[cfg(test)]
mod issue_1691_rerank_tests {
    //! #1691 — the cross-encoder rerank wrapper that unifies HTTP recall
    //! with the MCP recall pipeline. These pin the gating + mode-flip
    //! logic; the rerank reordering itself is covered by the
    //! `BatchedReranker::rerank` tests in `src/reranker.rs`.
    use super::maybe_apply_rerank;
    use crate::models::{Memory, RECALL_MODE_HYBRID_RERANK};
    use crate::reranker::{BatchedReranker, CrossEncoder};

    fn empty() -> Vec<(Memory, f64)> {
        Vec::new()
    }

    #[test]
    fn no_reranker_is_noop_even_on_hybrid() {
        // Non-autonomous tiers / test scaffolds install no reranker; the
        // mode must NOT flip and the candidate set is returned untouched.
        let (pairs, mode) = maybe_apply_rerank(None, "hybrid", "ctx", empty());
        assert!(pairs.is_empty());
        assert_eq!(mode, "hybrid", "mode must not flip without a reranker");
    }

    #[test]
    fn reranker_skipped_on_keyword_mode() {
        // Keyword-only recall (no semantic component) is never reranked,
        // even when a reranker is installed.
        let r = BatchedReranker::new(CrossEncoder::new());
        let (_, mode) = maybe_apply_rerank(Some(&r), "keyword", "ctx", empty());
        assert_eq!(mode, "keyword", "keyword-only recall must not be reranked");
    }

    #[test]
    fn reranker_flips_mode_on_hybrid() {
        // Hybrid path + installed reranker → the envelope advertises the
        // rerank stage via the canonical mode label, matching MCP.
        let r = BatchedReranker::new(CrossEncoder::new());
        let (_, mode) = maybe_apply_rerank(Some(&r), "hybrid", "ctx", empty());
        assert_eq!(mode, RECALL_MODE_HYBRID_RERANK);
    }
}
