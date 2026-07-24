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

use crate::models::ConfidenceSource;
use crate::models::field_names;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::db;
use crate::models::{CreateMemory, ForgetQuery, ListQuery, Memory, SearchQuery};
use crate::validate;

use super::AppState;
use super::BULK_FANOUT_CONCURRENCY;
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
            // #2167 — list/search never runs the recall space gate.
            active_embedding_space: None,
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
    let listed = super::read_pool::db_read_op(app.db.clone(), move |conn| {
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
    .await;
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
    // SAL trait. The Postgres adapter's `search` runs the same
    // text-search projection as SQLite's FTS5 path with the trait's
    // `Filter` carried verbatim; result wire-shape matches the
    // legacy `db::search` envelope.
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
            // #2167 — list/search never runs the recall space gate.
            active_embedding_space: None,
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
            let listed = super::read_pool::db_read_op(app.db.clone(), move |conn| {
                db::list_by_source_uri(
                    conn,
                    &uri_owned,
                    ns.as_deref(),
                    Some(limit),
                    eaa.as_deref(),
                    vc.as_deref(),
                )
            })
            .await;
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
    let searched = super::read_pool::db_read_op(app.db.clone(), move |conn| {
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
    .await;
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

pub async fn bulk_create(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(bodies): Json<Vec<CreateMemory>>,
) -> impl IntoResponse {
    if bodies.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({"error": format!("bulk operations limited to {} items", app.max_page_size)}),
            ),
        )
            .into_response();
    }
    let now = Utc::now();

    // #910 SAL-level — resolve the caller so the per-row metadata
    // stamp matches the authenticated principal. Pre-#910 the bulk
    // path stored `body.metadata` verbatim, so rows landed with no
    // agent_id and the subsequent list/get round-trip via the
    // scope=private filter dropped every one of them. Header-only
    // authentication; anonymous callers stamp `anonymous:req-<uuid>`.
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let caller = crate::identity::resolve_http_agent_id(None, header_agent_id)
        .unwrap_or_else(|_| crate::identity::anonymous_request_id());

    // #1919 (CWE-288 / CWE-345) — bulk_create MUST enforce the SAME
    // required-agent-attestation gate (#1751) that single-create
    // (`create_memory`) enforces. Pre-fix bulk bypassed it entirely: a
    // low-privilege caller could POST /memories/bulk with a self-asserted
    // `X-Agent-Id` and UNSIGNED bodies and land unattested rows attributed
    // to ANY agent — the exact cross-tenant identity forgery the #1751
    // attestation-require default was built to prevent. Fail the WHOLE
    // batch (403 ATTESTATION_FAILED, BEFORE any persistence or fanout) when
    // required-attestation is on and ANY row is unsigned, matching the
    // single-create contract. Per-row signature VERIFICATION (forged /
    // unverifiable → row rejected) is applied inside each backend loop
    // below via `stamp_attestation_*`.
    // #1985 — `/memories/bulk` is an HTTP direct-write endpoint, so it
    // classifies as `WriteSurface::HttpDirect`: required by default, the same
    // fail-closed posture as single-create above.
    let require_attest = crate::identity::attest::require_agent_attestation_for(
        crate::identity::attest::WriteSurface::HttpDirect,
    );
    if require_attest
        && bodies.iter().any(|b| {
            b.signature
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
        })
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "code": crate::errors::error_codes::ATTESTATION_FAILED,
                "error": "bulk_create requires every row to carry an agent-attestation \
                          signature when AI_MEMORY_REQUIRE_AGENT_ATTESTATION is set",
            })),
        )
            .into_response();
    }

    // N8 (#2389, CWE-288) — consult the PRE-STORE enforcement gate ONCE for the
    // whole batch BEFORE any write (and before the postgres branch), so
    // `[hooks].enforce_mode = enforce` + `required_events = ["pre_store"]` with
    // no enabled hook DENIES the bulk write (503) exactly as it does on the
    // single-create path (`create::create_memory`, #1924) and the MCP path
    // (#1885). Pre-fix `bulk_create` had ZERO `http_pre_event_gate` consults, so
    // the PE-1 PreStore gate was bypassed on the bulk surface. The gate is a
    // content-invariant PRESENCE check (missing required hook → Deny), so ONE
    // per-request consult is exact parity with single-create — and mirrors the
    // whole-batch fail-closed shape of the #1919 attestation gate above. INERT
    // (`None`) for default (enforce-off) deployments.
    // #2390 (N9) — a bulk store spans N bodies and therefore potentially N
    // namespaces; every distinct one contributes so a hook scoped to ANY of them
    // fires on the batch. `body.namespace` is already resolved (serde
    // `default_namespace()` applies the #1590 ladder), so this needs no DB read.
    // Pre-fix the payload carried no namespace at all and every namespace-scoped
    // `pre_store` hook was silently skipped on the bulk surface.
    let mut bulk_namespaces: Vec<String> = Vec::new();
    for b in &bodies {
        if !bulk_namespaces.contains(&b.namespace) {
            bulk_namespaces.push(b.namespace.clone());
        }
    }
    if let Some(resp) = crate::handlers::create::http_pre_event_gate(
        crate::hooks::HookEvent::PreStore,
        bulk_namespaces,
        json!({
            "agent_id": caller,
            "bulk": true,
            "count": bodies.len(),
        }),
    ) {
        return resp;
    }

    // v0.7.0 Wave-3 Continuation — postgres-backed daemons stream each
    // row through `app.store.store(...)`. Federation fanout below stays
    // sqlite-only because the federation transport assumes the
    // SQLite-on-disk model; postgres deployments use the postgres replica
    // mechanism for cross-node visibility, not HTTP fanout. The wire
    // shape (created+errors counts) matches the sqlite path exactly.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // QC P1 fix (2026-05-20): bulk_create now uses the already-
        // resolved `caller` from headers (line 491 above) instead of
        // the hardcoded "daemon" sentinel. The stored rows still get
        // their `metadata.agent_id` stamped from the request body /
        // X-Agent-Id header inside `app.store.store(...)`; the ctx
        // here is for visibility-filter purposes (e.g., the
        // `governance_pending_create` precondition lookup the SAL
        // path runs internally).
        // v0.9.0 G10.1 (#1827) — edge-parse the optional
        // `X-AI-Memory-Capability` header ONCE into the caller context;
        // inert unless `[capabilities].enabled`. The same token gates
        // every row in the batch.
        let ctx = crate::store::CallerContext::for_agent(caller.clone())
            .with_capability(crate::handlers::capability_from_headers(&headers, &caller));
        let mut errors: Vec<String> = Vec::new();
        let mut pending: Vec<serde_json::Value> = Vec::new();
        // #1481 — collect the governance-Allowed rows and persist them in
        // ONE multi-row INSERT via `store_batch`, instead of streaming a
        // `store()` round-trip per row. Validation / Deny / Pending still
        // accumulate per row exactly as before; only the persistence of
        // the surviving rows is batched.
        let mut allowed: Vec<Memory> = Vec::new();
        // #1911 — mirror the sqlite bulk_create tier-default TTL fallback
        // on the postgres branch too. Pre-#1911 this loop resolved
        // `expires_at` from `body.expires_at`/`body.ttl_secs` only,
        // omitting the `.or(ResolvedTtl::ttl_for_tier)` fallback the
        // sqlite loop applies below — so a tiered row with a configured
        // default TTL but no explicit expiry landed immortal on postgres
        // yet expired on sqlite. `ResolvedTtl` lives in the `app.db`
        // mutex tuple (populated on both backends); snapshot it ONCE
        // before the loop rather than re-locking per row.
        let resolved_ttl = app.db.lock().await.2.clone();
        for body in bodies {
            // #1919 — capture the per-row attestation fields before `body`
            // is partial-moved into the `Memory` literal below.
            let row_sig = body.signature.clone();
            let row_created_at = body.created_at.clone();
            if let Err(e) = validate::RequestValidator::validate_create(&body) {
                // Issue #851: do not echo the caller's title back paired
                // with the raw error — both are caller-influenced, and
                // the combo can be used to verify presence/shape of
                // server-side fields. Sanitize and log instead.
                tracing::warn!("bulk_create(postgres): validate_create failed: {e}");
                errors.push(super::sanitize_bulk_row_error(&e.to_string()).to_string());
                continue;
            }
            let expires_at = crate::handlers::parity::resolve_create_expires_at(
                now,
                body.expires_at.clone(),
                body.ttl_secs,
                resolved_ttl.ttl_for_tier(&body.tier),
            );
            // #910 — stamp metadata.agent_id from the resolved caller
            // so the SAL visibility filter recognises the row as
            // owned by the writer on later get/list/recall.
            let mut metadata_stamped = body.metadata;
            if let Some(obj) = metadata_stamped.as_object_mut() {
                obj.insert(
                    "agent_id".to_string(),
                    serde_json::Value::String(caller.clone()),
                );
            }
            // v0.7.0 #1422 — sister to #1385 (kind) + #1411 (Form-4)
            // single-create fixes. Pre-fix the bulk_create postgres
            // branch validated these fields via RequestValidator above
            // but hardcoded defaults on insert. Resolve here so the
            // struct literal threads the validated values through.
            let memory_kind = body
                .kind
                .as_deref()
                .and_then(crate::models::MemoryKind::from_str)
                .unwrap_or_default();
            let citations = body.citations;
            let source_uri = body.source_uri;
            let source_span = body.source_span;
            // #1919 — mutable so the per-row attestation below can stamp
            // `attest_level` / adopt the signed `created_at`.
            let mut mem = Memory {
                id: Uuid::new_v4().to_string(),
                tier: body.tier,
                namespace: body.namespace,
                title: body.title,
                content: body.content,
                tags: body.tags,
                priority: body.priority.clamp(1, 10),
                // #1591 — omitted confidence resolves to the compiled
                // default with truthful provenance (see below).
                confidence: body
                    .confidence
                    .unwrap_or(crate::models::DEFAULT_CONFIDENCE)
                    .clamp(0.0, 1.0),
                source: body.source,
                access_count: 0,
                created_at: now.to_rfc3339(),
                updated_at: now.to_rfc3339(),
                last_accessed_at: None,
                expires_at,
                metadata: metadata_stamped,
                reflection_depth: 0,
                memory_kind,
                entity_id: None,
                persona_version: None,
                citations,
                source_uri,
                source_span,
                confidence_source: if body.confidence.is_some() {
                    ConfidenceSource::CallerProvided
                } else {
                    ConfidenceSource::Default
                },
                confidence_signals: None,
                confidence_decayed_at: None,
                version: 1,
                lifecycle_state: crate::models::LifecycleState::Open,
                cid: None,
                // #2258 / #1834 — claim-bitemporal VALID-time bounds (validated
                // in `validate_create`, called per-row above). Postgres `store`
                // ON CONFLICT keeps `valid_from` immutably + COALESCEs
                // `valid_until` (parity with the single-create path).
                valid_from: body.valid_from.clone(),
                valid_until: body.valid_until.clone(),
            };

            // #1919 (CWE-288) — per-row agent attestation, mirroring the
            // single-create postgres gate (`create.rs` #626 Layer-3). Verify
            // a presented signature against the caller's bound key and stamp
            // `attest_level`; a forged / unverifiable signature (or, under
            // required-attestation, an unsigned row — already batch-rejected
            // above, kept here as a fail-closed backstop) REJECTS the row into
            // `errors[]` so it is never persisted or fanned out.
            if let Some(sig_b64) = row_sig.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                match crate::identity::attest::prepare_signed_store(
                    sig_b64,
                    row_created_at.as_deref(),
                ) {
                    Ok((sig_bytes, signed_created_at)) => {
                        mem.created_at = signed_created_at.to_string();
                        // #1801→#1954 item 4 — redact to storage form BEFORE the
                        // gate verifies (and before EMIT) so the signed bytes
                        // equal the persisted bytes; the SAL store re-redacts
                        // idempotently.
                        crate::identity::attest::redact_before_sign(&mut mem);
                        if let Err(e) = crate::identity::attest::stamp_attestation_async(
                            app.store.as_ref(),
                            &mut mem,
                            &caller,
                            Some(&sig_bytes),
                            crate::identity::attest::WriteSurface::HttpDirect,
                        )
                        .await
                        {
                            tracing::warn!("bulk_create(postgres): attestation failed: {e}");
                            errors.push(super::sanitize_bulk_row_error(&e.to_string()).to_string());
                            continue;
                        }
                        // #1801→#1954 item 2 — sender EMIT: persist the author's
                        // presented signature so it propagates verbatim across
                        // federation relay hops. Bulk is a HttpDirect signed-store
                        // authoring path with quorum fanout (Stage 2 below), same
                        // as single-create — without this, bulk-authored content
                        // fails multi-hop third-party relay under the strict flip.
                        crate::identity::attest::persist_write_signature(&mut mem, &sig_bytes);
                    }
                    Err(msg) => {
                        errors.push(super::sanitize_bulk_row_error(&msg).to_string());
                        continue;
                    }
                }
            } else if require_attest
                && let Err(e) = crate::identity::attest::stamp_attestation_async(
                    app.store.as_ref(),
                    &mut mem,
                    &caller,
                    None,
                    crate::identity::attest::WriteSurface::HttpDirect,
                )
                .await
            {
                tracing::warn!(
                    "bulk_create(postgres): required attestation rejected unsigned: {e}"
                );
                errors.push(super::sanitize_bulk_row_error(&e.to_string()).to_string());
                continue;
            }

            // F-A2A1.5 (#705) — governance enforcement on the postgres
            // bulk_create path. Mirrors F-A2A1.2 delete/promote and the
            // Wave-3 Continuation 3 create_memory gate. Each row is a
            // Store action against its own namespace, so the standard's
            // `write=` rule must be consulted per row. Deny rows
            // accumulate into `errors`; Pending rows accumulate into
            // `pending` with their pending_id. Without this gate,
            // postgres-backed daemons silently bypassed namespace
            // governance on the bulk-create surface (same A2A bypass
            // cluster fold-A2A1.2 closed on delete/promote/create
            // paths).
            use crate::models::GovernanceDecision;
            let agent_id = mem
                .metadata
                .get("agent_id")
                .and_then(|v| v.as_str())
                .unwrap_or(crate::identity::sentinels::DAEMON_PRINCIPAL);
            let payload_for_pending = serde_json::to_value(&mem).unwrap_or_else(|_| json!({}));
            // #2356 (W1A6-03) — `pre_governance_decision` presence consult
            // BEFORE the per-row governance decision dispatches. A refusal
            // accumulates as a row error (mirroring the Deny arm) so the
            // bulk envelope stays shape-stable.
            if let Err(reason) = crate::mcp::consult_pre_governance_decision_gate(
                &mem.namespace,
                "store",
                agent_id,
                None,
            ) {
                errors.push(format!("{}: {reason}", mem.title));
                continue;
            }
            match app
                .store
                .enforce_governance_action(
                    crate::store::GovernedAction::Store,
                    &mem.namespace,
                    agent_id,
                    None,
                    None,
                    &payload_for_pending,
                    ctx.capability.as_ref(),
                )
                .await
            {
                Ok(GovernanceDecision::Allow) => {}
                Ok(GovernanceDecision::Deny(refusal)) => {
                    errors.push(format!(
                        "{}: bulk_create denied by governance: {reason}",
                        mem.title,
                        reason = refusal.reason,
                    ));
                    continue;
                }
                Ok(GovernanceDecision::Pending(pending_id)) => {
                    pending.push(json!({
                        "title": mem.title,
                        "namespace": mem.namespace,
                        (field_names::PENDING_ID): pending_id,
                    }));
                    continue;
                }
                Err(e) => {
                    errors.push(format!("{}: governance error: {e}", mem.title));
                    continue;
                }
            }

            // #1795 (5-agent vote 4d3ea1c5) — enforce the per-agent daily write
            // quota on the postgres bulk path with PARTIAL-FILL parity to the
            // sqlite branch (#1788). `check_memory_quota` is a pure read (the
            // batched `store_batch` records later), so the cumulative count is
            // `already-allowed + this row`: passing `allowed.len()+1` tests
            // current+k <= max; once the cap is hit, this + every subsequent row
            // goes to errors[] and is not persisted. Exempt paths never reach here.
            let row_quota_bytes = i64::try_from(
                mem.title.len()
                    + mem.content.len()
                    + serde_json::to_string(&mem.metadata)
                        .map(|s| s.len())
                        .unwrap_or(0),
            )
            .unwrap_or(i64::MAX);
            let pending_count = i64::try_from(allowed.len())
                .unwrap_or(i64::MAX)
                .saturating_add(1);
            if let Err(e) = app
                .store
                .check_memory_quota(&ctx, &mem.namespace, pending_count, row_quota_bytes)
                .await
            {
                errors.push(super::sanitize_bulk_row_error(&e.to_string()).to_string());
                continue;
            }

            allowed.push(mem);
        }

        // #1481 — single batched upsert for every Allowed row. The batch
        // is atomic: on success each row counts as `created` (matching
        // the prior per-row semantics, including upserts); on failure the
        // whole batch rolled back, so all Allowed rows report one
        // sanitized error rather than partially-applied state.
        let created: usize = if allowed.is_empty() {
            0
        } else {
            match app.store.store_batch(&ctx, &allowed).await {
                Ok(ids) => ids.len(),
                Err(e) => {
                    // Issue #851: SAL store errors can carry raw sqlx
                    // text. Sanitize before echoing.
                    tracing::warn!("bulk_create(postgres): store_batch failed: {e}");
                    errors.push(super::sanitize_bulk_row_error(&e.to_string()).to_string());
                    0
                }
            }
        };
        return Json(json!({
            "created": created,
            "errors": errors,
            "pending": pending,
        }))
        .into_response();
    }

    // Stage 1 — validate + insert locally. Collect the successfully-inserted
    // `Memory` values so we can fanout each one after we release the DB lock
    // (peers POST to our /sync/push and we'd deadlock on the Mutex if we
    // held it across the network call).
    let mut created_mems: Vec<Memory> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    {
        let lock = app.db.lock().await;
        for body in bodies {
            // #1919 — capture the per-row attestation fields before `body`
            // is partial-moved into the `Memory` literal below.
            let row_sig = body.signature.clone();
            let row_created_at = body.created_at.clone();
            if let Err(e) = validate::RequestValidator::validate_create(&body) {
                // Issue #851: do not echo the caller's title back paired
                // with the raw error. Sanitize and log instead.
                tracing::warn!("bulk_create: validate_create failed: {e}");
                errors.push(super::sanitize_bulk_row_error(&e.to_string()).to_string());
                continue;
            }
            // #1911 — shared SSOT with the postgres bulk branch above.
            let expires_at = crate::handlers::parity::resolve_create_expires_at(
                now,
                body.expires_at.clone(),
                body.ttl_secs,
                lock.2.ttl_for_tier(&body.tier),
            );
            // #910 — stamp metadata.agent_id from the resolved caller
            // (sqlite branch mirror of the postgres branch above).
            let mut metadata_stamped = body.metadata;
            if let Some(obj) = metadata_stamped.as_object_mut() {
                obj.insert(
                    "agent_id".to_string(),
                    serde_json::Value::String(caller.clone()),
                );
            }
            // v0.7.0 #1422 — sister to #1385 + #1411 fix on the sqlite
            // bulk_create branch. Resolve before the struct literal so
            // body's owned fields aren't partial-moved before the kind
            // parse runs.
            let memory_kind = body
                .kind
                .as_deref()
                .and_then(crate::models::MemoryKind::from_str)
                .unwrap_or_default();
            let citations = body.citations;
            let source_uri = body.source_uri;
            let source_span = body.source_span;
            // #2258 / #1834 — claim-bitemporal VALID-time bounds (validated in
            // `validate_create` per-row above). Resolved into locals here so
            // the owned `Option<String>`s aren't partial-moved before the
            // struct literal, matching the citations/source_uri pattern.
            let valid_from = body.valid_from;
            let valid_until = body.valid_until;
            // #1919 — mutable so the per-row attestation below can stamp
            // `attest_level` / adopt the signed `created_at`.
            let mut mem = Memory {
                cid: None, // v0.9.0 G8 (#1825) — stamped by db::insert / read via row_to_memory
                // #2258 / #1834 — sqlite `db::insert` ON CONFLICT keeps
                // `valid_from` immutably + COALESCEs `valid_until`.
                valid_from,
                valid_until,
                id: Uuid::new_v4().to_string(),
                tier: body.tier,
                namespace: body.namespace,
                title: body.title,
                content: body.content,
                tags: body.tags,
                priority: body.priority.clamp(1, 10),
                // #1591 — omitted confidence resolves to the compiled
                // default with truthful provenance (see below).
                confidence: body
                    .confidence
                    .unwrap_or(crate::models::DEFAULT_CONFIDENCE)
                    .clamp(0.0, 1.0),
                source: body.source,
                access_count: 0,
                created_at: now.to_rfc3339(),
                updated_at: now.to_rfc3339(),
                last_accessed_at: None,
                expires_at,
                metadata: metadata_stamped,
                reflection_depth: 0,
                memory_kind,
                entity_id: None,
                persona_version: None,
                citations,
                source_uri,
                source_span,
                confidence_source: if body.confidence.is_some() {
                    ConfidenceSource::CallerProvided
                } else {
                    ConfidenceSource::Default
                },
                confidence_signals: None,
                confidence_decayed_at: None,
                version: 1,
                lifecycle_state: crate::models::LifecycleState::Open,
            };
            // #1919 (CWE-288) — per-row agent attestation, mirroring the
            // single-create sqlite gate (`create.rs` #626 Layer-3). Verify a
            // presented signature against the caller's bound key and stamp
            // `attest_level`; a forged / unverifiable signature (or, under
            // required-attestation, an unsigned row — already batch-rejected
            // above, kept here as a fail-closed backstop) REJECTS the row into
            // `errors[]` so it is never persisted or fanned out.
            if let Some(sig_b64) = row_sig.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                match crate::identity::attest::prepare_signed_store(
                    sig_b64,
                    row_created_at.as_deref(),
                ) {
                    Ok((sig_bytes, signed_created_at)) => {
                        mem.created_at = signed_created_at.to_string();
                        // #1801→#1954 item 4 — redact to storage form BEFORE the
                        // gate verifies (and before EMIT) so the signed bytes
                        // equal the persisted bytes; `db::insert` re-redacts
                        // idempotently.
                        crate::identity::attest::redact_before_sign(&mut mem);
                        if let Err(e) = crate::identity::attest::stamp_attestation_sync(
                            &lock.0,
                            &mut mem,
                            &caller,
                            Some(&sig_bytes),
                            crate::identity::attest::WriteSurface::HttpDirect,
                        ) {
                            tracing::warn!("bulk_create: attestation failed: {e}");
                            errors.push(super::sanitize_bulk_row_error(&e.to_string()).to_string());
                            continue;
                        }
                        // #1801→#1954 item 2 — sender EMIT: persist the author's
                        // presented signature so it propagates verbatim across
                        // federation relay hops. Bulk is a HttpDirect signed-store
                        // authoring path with quorum fanout (Stage 2 below), same
                        // as single-create — without this, bulk-authored content
                        // fails multi-hop third-party relay under the strict flip.
                        crate::identity::attest::persist_write_signature(&mut mem, &sig_bytes);
                    }
                    Err(msg) => {
                        errors.push(super::sanitize_bulk_row_error(&msg).to_string());
                        continue;
                    }
                }
            } else if require_attest
                && let Err(e) = crate::identity::attest::stamp_attestation_sync(
                    &lock.0,
                    &mut mem,
                    &caller,
                    None,
                    crate::identity::attest::WriteSurface::HttpDirect,
                )
            {
                tracing::warn!("bulk_create: required attestation rejected unsigned: {e}");
                errors.push(super::sanitize_bulk_row_error(&e.to_string()).to_string());
                continue;
            }
            // #1788 (5-agent vote 4d3ea1c5) — charge the per-agent daily write
            // quota PER ROW, mirroring the single-write create handler so the
            // bulk surface is no longer a quota-bypass amplifier. A row that
            // would exceed the cap is rejected into `errors[]` and skipped
            // (partial-fill — consistent with this handler's existing per-row
            // validation/governance error semantics); it is NOT persisted.
            // Skip empty principals exactly like the single-write path.
            let bulk_quota_op = crate::quotas::QuotaOp::Memory {
                bytes: i64::try_from(
                    mem.title.len()
                        + mem.content.len()
                        + serde_json::to_string(&mem.metadata)
                            .map(|s| s.len())
                            .unwrap_or(0),
                )
                .unwrap_or(i64::MAX),
            };
            if !caller.is_empty() {
                if let Err(e) =
                    crate::quotas::check_and_record(&lock.0, &caller, &mem.namespace, bulk_quota_op)
                {
                    match e {
                        crate::quotas::QuotaCheckError::Quota(qe) => {
                            errors
                                .push(super::sanitize_bulk_row_error(&qe.to_string()).to_string());
                        }
                        crate::quotas::QuotaCheckError::Sql(se) => {
                            tracing::error!("bulk_create: quota substrate error: {se}");
                            errors.push(crate::errors::msg::QUOTA_CHECK_FAILED.to_string());
                        }
                    }
                    continue;
                }
            }
            match db::insert(&lock.0, &mem) {
                Ok(_) => created_mems.push(mem),
                Err(e) => {
                    // Issue #851: db::insert errors include raw rusqlite
                    // text (constraint names, SQL fragments). Sanitize.
                    tracing::warn!("bulk_create: db::insert failed: {e}");
                    errors.push(super::sanitize_bulk_row_error(&e.to_string()).to_string());
                    // #1788 — refund the quota charge since the insert failed
                    // (mirrors the single-write refund_op path). Best-effort.
                    if !caller.is_empty() {
                        if let Err(re) = crate::quotas::refund_op(
                            &lock.0,
                            &caller,
                            &mem.namespace,
                            bulk_quota_op,
                        ) {
                            crate::quotas::log_refund_op_failed(&caller, &re);
                        }
                    }
                }
            }
        }
    }
    // Stage 2 — federation fanout, once per successfully-inserted row.
    //
    // v0.6.2 (S40): we run each row's `broadcast_store_quorum` *concurrently*
    // via `tokio::task::JoinSet`, bounded by a semaphore so we never have
    // more than `BULK_FANOUT_CONCURRENCY` in-flight fanouts at a time. The
    // prior form looped sequentially and paid one full ack-round-trip per
    // row — 500 rows × ~100ms = 50s, dwarfing the scenario's 20s settle
    // window so peers only received the first ~200 writes in time.
    //
    // Why a bound instead of unbounded? Unbounded (`JoinSet.spawn` for
    // each row at once) fires N × peers concurrent reqwest POSTs. At N=500
    // × 3 peers = 1500 concurrent TCP connects this exhausts ephemeral
    // ports and the reqwest client's connection pool, manifesting as
    // `network: error sending request` on most rows. A bound of 32
    // concurrent fanouts still pipelines the ack round-trip (100ms per
    // row × 500 / 32 ≈ 1.6s wall), well inside the 20s scenario budget.
    //
    // Each row's broadcast still uses the full quorum contract (local +
    // W-1 peer acks or 503). The semaphore only limits concurrency; it
    // does NOT weaken any single row's guarantees. Non-quorum errors
    // land in `errors` with the row id prefix, exactly as before. On a
    // quorum miss we keep going — a single row's miss must not abort the
    // other 499 the caller just paid for (bulk semantics, deliberately
    // weaker than `create_memory`'s 503 short-circuit).
    // Concurrency bound balances:
    //   - Speedup over sequential: N / bound × ack — need bound ≥ a few to
    //     clear 500 rows × 100ms ack inside the scenario's 20s settle.
    //   - Peer-side contention: every concurrent fanout lands a sync_push
    //     POST on the same SQLite Mutex on each peer. Too many in-flight
    //     serialize at the peer's DB lock and either timeout the quorum
    //     window or hit reqwest connection-pool / ephemeral-port limits
    //     on the leader side.
    //
    // 8 is a conservative compromise: 500 × 100ms / 8 ≈ 6.2s wall, comfortably
    // under the scenario's 20s budget while keeping the peer's per-writer
    // queue short enough to avoid timeouts under typical testbook load.
    // Tuned via the `BULK_FANOUT_CONCURRENCY` module constant.
    if let Some(fed) = app.federation.as_ref() {
        let sem = Arc::new(tokio::sync::Semaphore::new(BULK_FANOUT_CONCURRENCY));
        let mut joins: tokio::task::JoinSet<(String, Result<(), String>)> =
            tokio::task::JoinSet::new();
        for mem in &created_mems {
            let fed = fed.clone();
            let mem = mem.clone();
            let sem = sem.clone();
            joins.spawn(async move {
                // `acquire_owned` + a semaphore the task owns a clone of
                // means the permit lives for the task's lifetime — it's
                // released only when the task completes. A closed
                // semaphore would be a bug; surface it via the error
                // channel and keep going.
                let Ok(_permit) = sem.acquire_owned().await else {
                    return (mem.id.clone(), Err("fanout semaphore closed".to_string()));
                };
                let id = mem.id.clone();
                let outcome = match crate::federation::broadcast_store_quorum(&fed, &mem).await {
                    Ok(tracker) => match crate::federation::finalise_quorum(&tracker) {
                        Ok(_) => Ok(()),
                        Err(err) => Err(err.to_string()),
                    },
                    Err(e) => {
                        tracing::warn!(
                            "bulk_create: fanout for {id} failed (local committed): {e:?}"
                        );
                        Ok(())
                    }
                };
                (id, outcome)
            });
        }
        while let Some(res) = joins.join_next().await {
            match res {
                Ok((id, Err(err))) => errors.push(format!("{id}: {err}")),
                Ok((_, Ok(()))) => {}
                Err(e) => tracing::warn!("bulk_create: fanout task join error: {e:?}"),
            }
        }

        // v0.6.2 Patch 2 (S40): terminal catchup batch. Per-row quorum
        // met above, but the post-quorum detach path — even with
        // retry-once in `post_and_classify` — can still leave a peer
        // one row behind under sustained SQLite-mutex contention (v3r26
        // hermes-tls 499/500 and v3r27 ironclaw-off 499/500 both tripped
        // the scenario despite the retry). A single batched `sync_push`
        // per peer with every committed row closes the gap: peer's
        // `insert_if_newer` no-ops rows it already has and applies the
        // missing one. O(1) extra POST per peer vs O(N) per-row retries.
        //
        // Errors are logged and folded into the response `errors` array
        // but do NOT fail the bulk write — quorum was already met, so
        // the HTTP contract is satisfied. The catchup only strengthens
        // eventual consistency within the scenario settle window.
        if !created_mems.is_empty() {
            let catchup_errors = crate::federation::bulk_catchup_push(fed, &created_mems).await;
            for (peer_id, err) in catchup_errors {
                errors.push(format!("catchup to {peer_id}: {err}"));
            }
        }
    }
    Json(json!({"created": created_mems.len(), "errors": errors})).into_response()
}

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
