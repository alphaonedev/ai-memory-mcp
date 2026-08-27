// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Memory query / bulk HTTP handlers — `list_memories`,
//! `search_memories`, `forget_memories`, and `bulk_create`.
//!
//! Extracted from [`super::http`] under issue #650 (handler cap ≤1200
//! LOC). Handler bodies are unchanged; only the module surface moved.
//! Wire compatibility preserved via `pub use memories_query::*` in
//! [`super`].

#![allow(clippy::too_many_lines)]

use crate::models::field_names;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::json;

use crate::db;
use crate::models::{ForgetQuery, ListQuery, Memory, SearchQuery};
use crate::validate;

use super::AppState;
#[cfg(feature = "sal")]
use super::StorageBackend;
#[cfg(feature = "sal")]
use super::store_err_to_response;

/// #951 (Track A QC sweep, 2026-05-20) — replaced the local
/// duplicate of `is_visible_to_caller` with a re-export of the
/// canonical helper at [`crate::visibility::is_visible_to_caller`].
/// The local copy was missing the `metadata.target_agent_id` inbox
/// carve-out that the canonical SAL version had — the drift would
/// have silently blocked recipients from seeing their own private-
/// scope inbox messages on list/kg-query paths. Single source now;
/// both `sal` and non-sal builds share the same predicate.
use crate::visibility::is_visible_to_caller;

pub async fn list_memories(
    State(app): State<AppState>,
    headers: HeaderMap,
    Query(p): Query<ListQuery>,
) -> impl IntoResponse {
    // #197: validate agent_id filter values
    if let Some(ref aid) = p.agent_id
        && let Err(e) = validate::validate_agent_id(aid)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid agent_id filter: {e}")})),
        )
            .into_response();
    }

    // #910 (security-medium, 2026-05-19) — resolve the caller via the
    // `X-Agent-Id` header so the scope=private visibility filter below
    // has a known principal to compare `metadata.agent_id` against.
    // Pre-#910 the handler skipped this step entirely and returned
    // every row matching the requested namespace/tier/etc. shape — an
    // attacker could enumerate scope=private rows authored by other
    // agents by listing their namespace. Header-only authentication
    // (no body field on this GET path); anonymous callers get a
    // per-request `anonymous:req-…` id and see only non-private rows.
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let caller = match crate::identity::resolve_http_agent_id(None, header_agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": crate::errors::msg::invalid("agent_id", e)})),
            )
                .into_response();
        }
    };

    // #2044 (#2032-A / H1 IDOR) — per-agent-key identity gate on the BULK read
    // surface: under `enforce` a shared-key `Claimed` caller acting as a named
    // principal cannot enumerate the victim's scope=private rows via the
    // `is_visible_to_caller` filter below.
    if let Some(resp) = crate::handlers::identity_binding::enforce_for_request(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        &caller,
        "list_memories",
    ) {
        return resp;
    }

    // v1.0.0 #1834 — RFC3339-validate the claim-bitemporal AS-OF at the entry
    // surface. `valid_at` is compared lexicographically against stored bounds,
    // so a malformed value would silently mis-filter — reject it as a 400
    // instead. Covers both the SAL (postgres) and direct (sqlite) branches.
    if let Some(v) = p.valid_at.as_deref()
        && let Err(e) = crate::validate::validate_valid_at(v)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": crate::errors::msg::invalid("valid_at", e)})),
        )
            .into_response();
    }

    // v0.7.0 Wave-3 — Postgres-backed daemons dispatch through the
    // SAL trait. The trait's `Filter` shape carries
    // `(namespace, tier, tags_any, agent_id, since, until, limit)`,
    // which is the same projection the legacy `db::list` accepts plus
    // a deterministic ordering. The `min_priority` and `offset`
    // filters that exist only on the SQLite path are not yet exposed
    // through the trait — when set on a Postgres daemon they are
    // silently ignored (logged at debug). Offset can be emulated
    // client-side by raising `limit` and slicing; min_priority is
    // tracked for trait extension in the next wave.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        if p.offset.unwrap_or(0) > 0 {
            tracing::debug!(
                "list_memories on postgres: ?offset is unsupported on the SAL trait; ignored"
            );
        }
        if p.min_priority.is_some() {
            tracing::debug!(
                "list_memories on postgres: ?min_priority is unsupported on the SAL trait; ignored"
            );
        }
        let limit = p.limit.unwrap_or(20).min(app.max_page_size);
        let since = p
            .since
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc));
        let until = p
            .until
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc));
        let filter = crate::store::Filter {
            namespace: p.namespace.clone(),
            tier: p.tier.clone(),
            // #869 audit (Category B — safe default): missing `tags`
            // querystring collapses to empty `Vec<String>` which the
            // SAL `Filter` treats as "no tag filter" — documented.
            tags_any: p
                .tags
                .as_deref()
                .map(|s| s.split(',').map(str::to_string).collect())
                .unwrap_or_default(),
            agent_id: p.agent_id.clone(),
            since,
            until,
            // v1.0.0 #1834 — claim-bitemporal AS-OF from the list DTO (RFC3339
            // validated at the entry guard above).
            valid_at: p.valid_at.clone(),
            limit,
            // #1876 — list DTO paging: this surface serves the first window
            // (no offset param wired yet); the migrate paginator is the
            // OFFSET consumer.
            offset: 0,
            // #2167 — list/search never runs the recall space gate.
            active_embedding_space: None,
            // #2580 — metadata-equality pushdown axis unused on this path.
            metadata_eq: None,
            // #3185/#3127 — keyword-search-only axis; list ignores it.
            source_uri: None,
            // Recall-hybrid only; list ignores it (default false).
            skip_access_ledger: false,
        };
        let ctx = crate::store::CallerContext::for_agent(&caller);
        return match app.store.list(&ctx, &filter).await {
            Ok(mems) => {
                // #910 — post-filter scope=private rows the caller does
                // not own. Done in-process rather than via the SAL
                // `Filter` because the trait's filter shape does not
                // carry a scope axis yet (tracked for the next trait
                // extension wave); the post-filter is correctness-
                // equivalent to a WHERE clause at the SQL layer for
                // the result-set sizes that fit the trait's `limit`.
                let visible: Vec<Memory> = mems
                    .into_iter()
                    .filter(|m| is_visible_to_caller(m, &caller))
                    .collect();
                Json(json!({"memories": &visible, "count": visible.len()})).into_response()
            }
            Err(e) => store_err_to_response(e),
        };
    }

    // v0.6.2 (S40): raise ceiling from 200 → the operator-resolved
    // `app.max_page_size` (compiled default `MAX_BULK_SIZE` = 1000) so bulk
    // fanout scenarios that POST 500+ rows to a leader can verify full
    // peer delivery via a single `GET /memories?limit=N` (previously the
    // list silently capped at 200 regardless of whether fanout worked).
    // Default remains 20 — only explicit `?limit=` callers see the
    // higher ceiling.
    let limit = p.limit.unwrap_or(20).min(app.max_page_size);
    // #1580 — `db::list` is a pure SELECT, so dispatch through the WAL
    // read-pool instead of the single writer mutex. `p` is moved into
    // the closure (its fields are only read by `db::list`); the
    // visibility post-filter is pure CPU on the owned rows and stays
    // outside the pool connection.
    let listed = super::transport::flatten_db_op(
        super::read_pool::db_read_op(app.db.clone(), move |conn| {
            db::list(
                conn,
                p.namespace.as_deref(),
                p.tier.as_ref(),
                limit,
                p.offset.unwrap_or(0),
                p.min_priority,
                p.since.as_deref(),
                p.until.as_deref(),
                p.tags.as_deref(),
                p.agent_id.as_deref(),
                // v1.0.0 #1834 — claim-bitemporal AS-OF (validated at entry).
                p.valid_at.as_deref(),
            )
        })
        .await,
    );
    match listed {
        Ok(mems) => {
            // #910 — see postgres branch comment above. `db::list` does
            // NOT apply the visibility-prefix filter that `db::search`
            // and `db::recall_hybrid` use; that gap is what closed the
            // cross-tenant enumeration vector. Post-filter in-process
            // until the next storage-layer wave threads a `caller`
            // through `db::list` and rewrites the WHERE clause to use
            // the same `visibility_clause` helper as the search path.
            let visible: Vec<Memory> = mems
                .into_iter()
                .filter(|m| is_visible_to_caller(m, &caller))
                .collect();
            Json(json!({"memories": &visible, "count": visible.len()})).into_response()
        }
        Err(e) => crate::handlers::errors::handler_error_500(&e),
    }
}

pub async fn search_memories(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(p): Query<SearchQuery>,
) -> impl IntoResponse {
    // #891: source_uri-only queries are valid (Gap 6 #889 reciprocal
    // queries). Reject only when BOTH q and source_uri are empty.
    let source_uri_empty = p.source_uri.as_deref().is_none_or(|s| s.trim().is_empty());
    if p.q.trim().is_empty() && source_uri_empty {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "query or source_uri is required"})),
        )
            .into_response();
    }
    // #197: validate agent_id filter values
    if let Some(ref aid) = p.agent_id
        && let Err(e) = validate::validate_agent_id(aid)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid agent_id filter: {e}")})),
        )
            .into_response();
    }
    // #151 visibility: validate --as-agent namespace if supplied
    if let Some(ref a) = p.as_agent
        && let Err(e) = validate::validate_namespace(a)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": crate::errors::msg::invalid("as_agent", e)})),
        )
            .into_response();
    }
    // #1579 B4 — negotiate the response format BEFORE doing any work
    // (json default | toon | toon_compact; invalid → 400 with the
    // SSOT message). Mirrors the recall handlers.
    let format = match crate::toon::WireFormat::parse_http(p.format.as_deref()) {
        Ok(f) => f,
        Err(e) => return crate::handlers::wire_format::invalid_format_response(&e),
    };

    // #1922 (CWE-639, tenant-isolation) — bind the visibility `as_agent`
    // to the AUTHENTICATED caller. Pre-fix a caller-supplied `?as_agent=`
    // drove the `visibility_clause` team/unit/org arms with NO parity
    // check (unlike the recall path, which rejects a mismatch via
    // `resolve_caller_agent_id`), so an attacker sent
    // `?as_agent=victimorg/unit/team/x` (with their OWN or NO X-Agent-Id)
    // and `namespace_ancestors` handed the SQL team/unit/org arms the
    // victim's entire subtree — a cross-tenant read of every team/unit/
    // org-scoped row. Mirror recall's parity gate HERE, before EITHER
    // backend branch consumes `p.as_agent`: when `as_agent` is present it
    // MUST equal the header-resolved caller id, else 403. This fails
    // closed for anonymous callers too (a synthesized `anonymous:req-…`
    // id never matches an attacker-chosen namespace).
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let resolved_caller = crate::identity::resolve_http_agent_id(None, header_agent_id)
        .unwrap_or_else(|_| crate::identity::anonymous_request_id());
    if let Some(claimed) = p.as_agent.as_deref()
        && claimed != resolved_caller
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": format!(
                    "agent_id_query_header_mismatch: as_agent {claimed:?} disagrees with \
                     authenticated caller {resolved_caller:?}"
                ),
            })),
        )
            .into_response();
    }

    // #2044 (#2032-A / H1 IDOR) — per-agent-key identity gate on the SEARCH
    // surface (same `visibility_clause`/private-row exposure as list).
    if let Some(resp) = crate::handlers::identity_binding::enforce_for_request(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        &resolved_caller,
        "search_memories",
    ) {
        return resp;
    }

    // v0.7.0 Wave-3 — Postgres-backed daemons dispatch through the
    // SAL trait. #3185/#3127: `PostgresStore::search` is a thin wrapper
    // over `search_with_source_uri`, so `Filter.since`/`until`/`source_uri`
    // actually bind (the pre-fix trait method dropped them — fail-open
    // widening). Result wire-shape matches the legacy `db::search` envelope.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let limit = p.limit.unwrap_or(20).min(app.max_page_size);
        let since = p
            .since
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc));
        let until = p
            .until
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc));
        // #3127 — `?source_uri=` was parsed only on the sqlite branch
        // (below); the postgres early-return dispatched `app.store.search`
        // and DROPPED the filter, returning rows from every source.
        // Validate here so a bad scheme is 400 on both backends, then
        // thread the URI through `Filter.source_uri` into the SSOT
        // (`PostgresStore::search` → `search_with_source_uri`).
        let source_uri = p
            .source_uri
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(uri) = source_uri
            && let Err(e) = validate::validate_source_uri(uri)
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid source_uri filter: {e}")})),
            )
                .into_response();
        }
        let filter = crate::store::Filter {
            namespace: p.namespace.clone(),
            tier: p.tier.clone(),
            // #869 audit (Category B — safe default): missing `tags`
            // querystring collapses to empty `Vec<String>` which the
            // SAL `Filter` treats as "no tag filter" — documented.
            tags_any: p
                .tags
                .as_deref()
                .map(|s| s.split(',').map(str::to_string).collect())
                .unwrap_or_default(),
            agent_id: p.agent_id.clone(),
            since,
            until,
            // v1.0.0 #1834 — the claim-bitemporal AS-OF is scoped to the
            // recall + list surfaces (design 591608d4); the keyword-search
            // surface does not expose it, so no as-of filter applies here.
            valid_at: None,
            limit,
            // #1876 — keyword-search surface serves the first window only.
            offset: 0,
            // #2167 — list/search never runs the recall space gate.
            active_embedding_space: None,
            // #2580 — metadata-equality pushdown axis unused on this path.
            metadata_eq: None,
            // #3185/#3127 — compose `q + source_uri + since` lands on
            // the keyword-search SSOT. None = no URI narrowing.
            source_uri: source_uri.map(str::to_string),
            // Recall-hybrid only; search ignores it (default false).
            skip_access_ledger: false,
        };
        // #942 SECURITY-high (Track A QC sweep, 2026-05-20) — replace
        // the hardcoded `"ai:http"` principal with the header-resolved
        // caller so the SAL #910 scope=private visibility filter
        // actually applies per-caller. Pre-fix every HTTP search ran
        // as the same synthetic principal, so the visibility filter
        // only filtered out rows owned by other-than-"ai:http" —
        // effectively no filter for tenant-facing reads.
        let header_agent_id = headers
            .get(crate::HEADER_AGENT_ID)
            .and_then(|v| v.to_str().ok());
        let caller = crate::identity::resolve_http_agent_id(None, header_agent_id)
            .unwrap_or_else(|_| crate::identity::anonymous_request_id());
        let ctx = crate::store::CallerContext {
            agent_id: caller,
            as_agent: p.as_agent.clone(),
            request_id: None,
            // #910 — tenant-facing path; never bypass the visibility filter.
            bypass_visibility: false,
            // v0.9.0 G10.1 (#1827) — read-only search path; no
            // governance gate runs here, so no token is carried.
            capability: None,
        };
        return match app.store.search(&ctx, &p.q, &filter).await {
            // #1579 B4 — serialize per the negotiated format.
            Ok(r) => crate::handlers::wire_format::search_response(
                format,
                json!({"results": r, "count": r.len(), "query": p.q}),
            ),
            Err(e) => store_err_to_response(e),
        };
    }

    // #942 SECURITY-high (Track A QC sweep, 2026-05-20) — fall back
    // to the header-resolved caller's namespace as the visibility
    // filter principal when `?as_agent=` is not supplied. Pre-fix
    // callers who didn't bother to set `as_agent` got an unfiltered
    // search — including scope=private rows owned by other tenants.
    // `as_agent` semantics: it's the caller's namespace ancestor
    // (agent_id IS the agent's namespace prefix per
    // src/identity/mod.rs); `compute_visibility_prefixes` walks
    // ancestors from there.
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let effective_as_agent: Option<String> = p
        .as_agent
        .clone()
        .or_else(|| crate::identity::resolve_http_agent_id(None, header_agent_id).ok());

    // v0.8.0 #1720 A3 — owner-keyed scope=private visibility caller for
    // the sqlite `db::search` / `db::list_by_source_uri` paths. This is
    // the agent's `metadata.agent_id` (the header-resolved principal),
    // DISTINCT from `effective_as_agent` (the namespace driving the
    // team/unit/org subtree arms). Threaded to the owner-keyed
    // `visibility_clause` private arm. `None` would be fail-closed, but
    // the header resolver always synthesizes a principal here.
    let visibility_caller: Option<String> =
        crate::identity::resolve_http_agent_id(None, header_agent_id).ok();

    // v0.6.2 (S40): mirror the `list_memories` ceiling raise so search
    // over a bulk-populated namespace isn't also capped at 200.
    let limit = p.limit.unwrap_or(20).min(app.max_page_size);
    // v0.7.0 Provenance Gap 6 (#889) — `?source_uri=X` reciprocal
    // filter. Composes with `?q=…`; when `q` is empty + `source_uri`
    // is set, routes through the index-only `list_by_source_uri`
    // path so callers can ask "give me every memory from this
    // document" without typing a search query.
    let source_uri = p
        .source_uri
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    // #1580 — `db::search_with_source_uri` / `db::list_by_source_uri` are
    // pure SELECTs, so both read paths dispatch through the WAL read-pool
    // (`db_read_op`) instead of the single writer mutex. Each closure
    // captures owned copies of the query params it needs (it runs on the
    // blocking pool with a `'static` bound); response serialization stays
    // outside the pool connection. Validation is done before any DB work.
    if let Some(uri) = source_uri {
        if let Err(e) = validate::validate_source_uri(uri) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid source_uri filter: {e}")})),
            )
                .into_response();
        }
        if p.q.trim().is_empty() {
            // #975 — thread the HTTP-resolved visibility principal so
            // the source_uri-only reciprocal endpoint applies the same
            // scope=private gate as the q+source_uri compose path.
            // Pre-fix the reciprocal path bypassed visibility entirely;
            // anonymous callers could read every row in every doc.
            let uri_owned = uri.to_string();
            let ns = p.namespace.clone();
            let eaa = effective_as_agent.clone();
            let vc = visibility_caller.clone();
            let listed = super::transport::flatten_db_op(
                super::read_pool::db_read_op(app.db.clone(), move |conn| {
                    db::list_by_source_uri(
                        conn,
                        &uri_owned,
                        ns.as_deref(),
                        Some(limit),
                        eaa.as_deref(),
                        vc.as_deref(),
                    )
                })
                .await,
            );
            return match listed {
                // #1579 B4 — serialize per the negotiated format.
                Ok(r) => crate::handlers::wire_format::search_response(
                    format,
                    json!({"results": r, "count": r.len(), (field_names::SOURCE_URI): uri}),
                ),
                Err(e) => crate::handlers::errors::handler_error_500(&e),
            };
        }
    }
    let q = p.q.clone();
    let ns = p.namespace.clone();
    let tier = p.tier.clone();
    let min_priority = p.min_priority;
    let since = p.since.clone();
    let until = p.until.clone();
    let tags = p.tags.clone();
    let agent_id = p.agent_id.clone();
    let eaa = effective_as_agent.clone();
    let su_owned: Option<String> = source_uri.map(str::to_string);
    let vc = visibility_caller.clone();
    let searched = super::transport::flatten_db_op(
        super::read_pool::db_read_op(app.db.clone(), move |conn| {
            db::search_with_source_uri(
                conn,
                &q,
                ns.as_deref(),
                tier.as_ref(),
                limit,
                min_priority,
                since.as_deref(),
                until.as_deref(),
                tags.as_deref(),
                agent_id.as_deref(),
                eaa.as_deref(),
                false,
                su_owned.as_deref(),
                vc.as_deref(),
            )
        })
        .await,
    );
    match searched {
        // #1579 B4 — serialize per the negotiated format.
        Ok(r) => crate::handlers::wire_format::search_response(
            format,
            json!({"results": r, "count": r.len(), "query": p.q}),
        ),
        Err(e) => crate::handlers::errors::handler_error_500(&e),
    }
}

pub async fn forget_memories(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ForgetQuery>,
) -> impl IntoResponse {
    // #942 SECURITY-high (Track A QC sweep, 2026-05-20) — admin-only
    // gate on bulk-forget. `db::forget` is a destructive operation
    // that deletes by namespace + pattern + tier filter; it has no
    // per-row caller filter and adding one without a substrate
    // refactor (touching the SQL CTEs that drive the FTS join) is
    // bigger than the QC sweep budget. Restrict to operators in the
    // admin allowlist (introduced by the #957 fix in commit
    // df7f72545) — same posture as `export_memories`.
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, "forget_memories")
    {
        return resp;
    }
    // #3171 — REFUSE a destructive pattern the sanitiser would silently WIDEN,
    // at the request boundary so BOTH backends get the identical contract. The
    // sqlite lane reaches the same check through `forget_fts_query`; postgres
    // builds a `plainto_tsquery` and would otherwise accept an over-cap /
    // operator-bearing / empty-after-sanitisation pattern that drops narrowing
    // AND-conjuncts. A bulk DELETE that is wider than the pattern the caller
    // wrote is unrecoverable data loss, and a refusal that depends on which
    // backend is configured is the #2312 cross-backend-divergence class.
    if let Some(pattern) = body.pattern.as_deref()
        && let Err(reason) = crate::storage::strict_forget_tokens(pattern)
    {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": reason }))).into_response();
    }
    // #1849 (CWE-862) — admin bulk forget with the namespace OMITTED spans
    // EVERY namespace, so the per-namespace delete-governance gate (the
    // per-memory `DELETE` gate + the #1772 MCP forget gate) would be silently
    // bypassed: a `delete:Approve` legal-hold on `compliance/*` is no defence
    // if the operator can erase the gated rows with a single namespace-less
    // forget. Resolve the matched namespaces UNCAPPED (backend-blind via the
    // SAL trait — never the #1602 preview, which would miss a governed
    // namespace whose rows sort past the cap) and REFUSE the whole forget if
    // ANY of them carries a non-`Any` `delete` level, directing the operator to
    // a per-namespace / per-memory delete that the governance pipeline gates.
    // `namespace = Some` is unchanged (the policy applies to that one named
    // namespace through the normal delete path). Skipped when neither pattern
    // nor tier is set (no forget scope — the FORGET_FILTER_REQUIRED error must
    // surface). 5-agent vote 4d3ea1c5.
    //
    // Gated on `sal`: the resolution + policy lookup go through the `app.store`
    // SAL trait (present for every production HTTP daemon — sqlite-SAL and
    // postgres). The non-`sal` build has no `app.store` (mobile/minimal lib
    // target), mirroring the `#[cfg(feature = "sal")]` SAL forget path below.
    #[cfg(feature = "sal")]
    if body.namespace.is_none() && (body.pattern.is_some() || body.tier.is_some()) {
        let matched = match app
            .store
            .forget_distinct_namespaces(body.pattern.as_deref(), body.tier.as_ref())
            .await
        {
            Ok(ns) => ns,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        };
        for ns in &matched {
            let governed = app
                .store
                .resolve_governance_policy(ns)
                .await
                .ok()
                .flatten()
                .is_some_and(|p| !matches!(p.core.delete, crate::models::GovernanceLevel::Any));
            if governed {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": crate::errors::msg::FORGET_GOVERNED_NAMESPACE_REQUIRES_SCOPED_DELETE,
                        "code": crate::errors::error_codes::GOVERNANCE_REFUSED,
                        "namespace": ns,
                    })),
                )
                    .into_response();
            }
        }
    }
    // v0.7.0 Wave-3 Continuation 3 (Phase 13) — route through SAL trait
    // on postgres-backed daemons. Sqlite-backed daemons keep the legacy
    // `db::forget` free-function path verbatim.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let archive_flag = {
            let lock = app.db.lock().await;
            lock.3
        };
        // QC P1 fix (2026-05-20): header-resolved caller so forget()
        // only deletes memories the caller owns. Pre-fix the
        // hardcoded `for_agent("http")` would have let any caller
        // delete memories that matched the namespace/pattern filter
        // regardless of ownership — a destructive privacy bug.
        let ctx = crate::handlers::parity::http_caller_ctx(&headers, None);
        return match app
            .store
            .forget(
                &ctx,
                body.namespace.as_deref(),
                body.pattern.as_deref(),
                body.tier.as_ref(),
                archive_flag,
            )
            .await
        {
            Ok(n) => Json(json!({"deleted": n})).into_response(),
            Err(e) => store_err_to_response(e),
        };
    }

    let lock = app.db.lock().await;
    // v0.8.1 W2.2 (#1821 / gap G30) — collect the victim ids BEFORE the
    // forget so the in-memory HNSW vector can be evicted afterwards. The
    // bulk `db::forget` purges the embedding COLUMN, but the HNSW graph keeps
    // a copy of the vector in RAM and keeps answering nearest-neighbour recall
    // for the forgotten id until the next rebuild (gap G30 channel c). The
    // match set is stable: the same `app.db` mutex is held across the collect
    // and the forget, so no concurrent writer can diverge it. (postgres uses
    // pgvector / DB-side ANN, so its recall drops the row on DELETE — no
    // in-memory eviction needed there.)
    let victim_ids: Vec<String> = db::forget_matches(
        &lock.0,
        body.namespace.as_deref(),
        body.pattern.as_deref(),
        body.tier.as_ref(),
        usize::MAX,
    )
    .map(|rows| rows.into_iter().map(|m| m.id).collect())
    .unwrap_or_default();
    let forget_result = db::forget(
        &lock.0,
        body.namespace.as_deref(),
        body.pattern.as_deref(),
        body.tier.as_ref(),
        lock.3, // archive_on_gc
    );
    // Drop the DB lock BEFORE taking the vector-index lock (the locking
    // discipline pinned at handlers/memories.rs — never hold both).
    drop(lock);
    match forget_result {
        Ok(n) => {
            if !victim_ids.is_empty() {
                let mut idx_lock = app.vector_index.lock().await;
                if let Some(idx) = idx_lock.as_mut() {
                    for id in &victim_ids {
                        idx.remove(id);
                    }
                }
            }
            Json(json!({"deleted": n})).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ============================================================================
// v0.7.0 Wave-3 Continuation 6 — three REST endpoints closing F7 cert-harness
// gaps (S52 `links/verify`, S61 `quota/status`, S65 `kg/find_paths`).
// ============================================================================

// ---------------------------------------------------------------------------
// v0.7.0 L6 — `/api/v1/auto_tag` + `/api/v1/expand_query` (S51 surface)
// ---------------------------------------------------------------------------
//
// S51 (autonomous-tier LLM surface) exercises four HTTP endpoints:
// `auto_tag`, `consolidate`, `expand_query`, `detect_contradiction`.
// Pre-L6 the daemon only registered `consolidate` + `contradictions`;
// the other two were available via MCP only. L6 adds the two missing
// REST endpoints with response shapes that match what S51 reads from
// the body (`tags: [...]` and `expansions: [...]`), gated by
// `app.llm.is_some()` so the keyword / semantic tiers (no LLM wired)
// surface a clean 503 instead of a confusing 500.

// ---------------------------------------------------------------------------
// v0.7.0 L9 — `GET /api/v1/tools/list` (NHI-D-501-postgres-traits)
// ---------------------------------------------------------------------------
//
// HTTP parity for the MCP `tools/list` JSON-RPC method. Surfaces the
// canonical tool catalog the daemon advertises under its resolved
// `Profile`, computed from in-memory configuration only — no DB access
// — so the postgres and sqlite paths return byte-identical bodies.
//
// NHI surfaced this as `NHI-D-501-postgres-traits` because the
// postgres-gated daemon returned the generic 501 envelope for the path
// even though the response is pure enumeration. The 501 was a false
// negative: the handler can be implemented entirely off `app.profile`
// + `app.mcp_config`.

// ---------------------------------------------------------------------------
// v0.7.0 L10 — `POST /api/v1/memory_load_family`
// ---------------------------------------------------------------------------
//
// HTTP parity for the MCP `memory_load_family` tool. Filters memories
// by `metadata.family` (a free-form JSON field stamped by the B1 path)
// and returns the top-k recent + high-priority rows. NHI surfaced
// `NHI-D-501-postgres-loadfamily` for the same reason as L9 — the
// endpoint was 501'd on postgres even though `app.store.list(...)`
// already exposes the underlying scan. The handler now dispatches
// through SAL on postgres and through `db::list` on sqlite, doing a
// post-filter on `metadata.family` in-memory because that field is not
// yet a first-class SAL filter axis.

// #2550/#2551/#2552/#2588/#2594 — `bulk_create` MOVED to
// [`crate::handlers::bulk`]. It had re-implemented the single-create funnel
// instead of calling it; the five issues above were five stages that
// re-implementation omitted. It now shares
// `create::{resolve_create_metadata, build_create_memory}` with
// `POST /api/v1/memories` and carries a truthful per-row outcome ledger.

// ===========================================================================
// #868 — inline tests for `handlers/http.rs`.
//
// The code-review verdict pinned `handlers/http.rs` for "0 inline tests
// across remaining prod LOC". This module establishes the discipline:
// one focused test per #866 stage helper so the next refactor has
// shape-pinning. Not aiming for 100% coverage — the integration suite
// under `tests/` already exercises the orchestrated path end-to-end.
//
// Coverage map (10 tests):
//   - resolve_create_agent_id    (4) header / body / metadata / fallback
//   - resolve_create_conflict_title (3) error → 409, version → suffix, merge → passthrough
//   - embed_create_before_lock   (1) no embedder ⇒ (None, Indexed)
//   - validate_create early-return (1) empty title ⇒ 400
//   - GovernanceRefusal downcast (1) → 403 + GOVERNANCE_REFUSED code
// ===========================================================================
