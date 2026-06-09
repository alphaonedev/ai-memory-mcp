// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Postgres route-gate middleware + storage-error sanitiser.
//!
//! Extracted from [`super::transport`] under issue #650 (handler cap
//! ≤1200 LOC). Function bodies are unchanged; only the module surface
//! moved. Wire compatibility preserved via `pub use postgres_gate::*`
//! in [`super`].

#![allow(clippy::too_many_lines)]

#[cfg(feature = "sal")]
use axum::{
    Json,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
#[cfg(feature = "sal")]
use serde_json::json;

#[cfg(feature = "sal")]
use super::{AppState, StorageBackend};

/// v0.7.0 Wave-3 — uniform 501 NOT IMPLEMENTED response for handlers
/// that have not yet migrated to the [`crate::store::MemoryStore`]
/// trait dispatch path on Postgres-backed daemons.
///
/// Returns a stable, machine-parseable JSON envelope so operator
/// scripts can recognise the v0.7.0 Wave-3 schism without parsing
/// free-form strings:
///
/// ```json
/// {
///   "error": "endpoint not yet implemented for postgres-backed daemon",
///   "endpoint": "<route>",
///   "storage_backend": "postgres",
///   "remediation": "use sqlite-backed daemon or wait for v0.7.x trait coverage"
/// }
/// ```
///
/// Wired into the un-migrated handlers below so a postgres-backed
/// daemon never silently falls back to the empty in-memory SQLite
/// scratch DB and corrupts the operator's mental model of where
/// their data lives. As handlers migrate to the trait this call
/// site count goes to zero.
#[cfg(feature = "sal")]
#[must_use]
pub fn postgres_not_implemented(endpoint: &'static str) -> Response {
    // #934 (Track C, 2026-05-20) — for `/api/v1/find_paths` callers
    // who hit this fallback on a pre-alias binary, point at the
    // canonical `/api/v1/kg/find_paths` so the remediation hint is
    // actually actionable. The alias landed in `src/lib.rs` so
    // /find_paths no longer reaches this gate at runtime on a
    // current binary — this branch survives so historic clients on
    // older binaries still get a useful pointer instead of a
    // confusing "feature missing" message.
    let remediation = if endpoint == super::routes::FIND_PATHS {
        "POST /api/v1/kg/find_paths instead (same handler; the bare /find_paths path is now an alias on v0.7.0+ binaries). Accepts both `source_id`/`target_id` and `from_id`/`to_id` body fields."
    } else {
        "use sqlite-backed daemon or wait for v0.7.x trait coverage"
    };
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "endpoint not yet implemented for postgres-backed daemon",
            "endpoint": endpoint,
            "storage_backend": "postgres",
            "remediation": remediation,
        })),
    )
        .into_response()
}

/// v0.7.0 Wave-3 Continuation — postgres-supported endpoint allow-list.
///
/// Returns `true` if the given (method, path) tuple has a handler that
/// has been migrated to dispatch through the [`crate::store::MemoryStore`]
/// trait when the daemon is postgres-backed. Anything not in this list
/// is shielded by [`postgres_route_gate`] middleware which surfaces
/// 501 NOT IMPLEMENTED rather than letting the un-migrated handler
/// silently fall through to the empty in-memory scratch SQLite database
/// that `bootstrap_serve` opens for the postgres-backed `app.db` field.
///
/// The matching is path-pattern aware:
/// - exact equality for fixed paths (e.g. `/api/v1/memories`)
/// - prefix match for sub-resources (e.g. `/api/v1/memories/{id}`)
///
/// As handlers migrate they get added here. Pre-existing CRUD entries
/// match what Wave-3 phase 3 already wired through `app.store`.
#[cfg(feature = "sal")]
#[must_use]
pub fn postgres_endpoint_supported(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;

    // Health and metadata always pass through — they don't touch user data.
    if path == super::routes::HEALTH
        || path == super::routes::CAPABILITIES
        || path == super::routes::METRICS_BARE
        || path == super::routes::METRICS
    {
        return true;
    }

    // Approval SSE stream — read-only metadata stream, not user-data.
    if path == super::routes::APPROVALS_STREAM && method == Method::GET {
        return true;
    }

    match (method.as_str(), path) {
        // Wave-3 phase 3 — core CRUD (commit c049500).
        ("POST", super::routes::MEMORIES) | ("GET", super::routes::MEMORIES) => true,
        ("GET" | "PUT" | "DELETE", p) if memory_id_path(p) => true,
        ("GET", super::routes::SEARCH) => true,
        ("POST", super::routes::LINKS) => true,
        ("GET", p) if links_id_path(p) => true,
        // Wave-3 continuation — list_pending (read-only).
        ("GET", super::routes::PENDING) => true,
        // Wave-3 continuation — list_agents (read-only).
        ("GET", super::routes::AGENTS) => true,
        // Wave-3 continuation — list_namespaces (read-only).
        ("GET", super::routes::NAMESPACES) => {
            // GET /api/v1/namespaces with no query string lists namespaces.
            // The same path with ?namespace=... fetches a standard which is
            // also gated through SAL via get_namespace_standard_qs.
            true
        }
        // Wave-3 continuation — KG endpoints (postgres adapter has impls).
        ("POST", super::routes::KG_QUERY)
        | ("GET", super::routes::KG_TIMELINE)
        | ("POST", super::routes::KG_INVALIDATE) => true,
        // Continuation 6 — three new HTTP endpoints (S52, S61, S65).
        ("POST", super::routes::KG_FIND_PATHS)
        | ("POST", super::routes::LINKS_VERIFY)
        | ("POST", super::routes::QUOTA_STATUS) => true,
        // Wave-3 continuation — entity registry.
        ("POST", super::routes::ENTITIES) | ("GET", super::routes::ENTITIES_BY_ALIAS) => true,
        // Wave-3 continuation — stats (basic count).
        ("GET", super::routes::STATS) => true,
        // Wave-3 continuation — bulk write.
        ("POST", super::routes::MEMORIES_BULK) => true,
        // Wave-3 continuation — recall fallback (keyword via search).
        ("GET" | "POST", super::routes::RECALL) => true,
        // Wave-3 continuation — archive list/stats (read-only).
        ("GET", super::routes::ARCHIVE) => true,
        ("GET", super::routes::ARCHIVE_STATS) => true,
        // Wave-3 continuation — taxonomy and check_duplicate.
        ("GET", super::routes::TAXONOMY) => true,
        ("POST", super::routes::CHECK_DUPLICATE) => true,
        // Wave-3 continuation — list_subscriptions, inbox.
        ("GET", super::routes::SUBSCRIPTIONS) => true,
        ("GET", super::routes::INBOX) => true,
        // Wave-3 Continuation 2 — federation push/pull (Phase 8).
        ("POST", super::routes::SYNC_PUSH) => true,
        ("GET", super::routes::SYNC_SINCE) => true,
        // Wave-3 Continuation 2 — governance write paths (Phase 11).
        ("POST", p) if pending_decide_path(p) => true,
        ("POST", p) if namespace_standard_post_path(p) => true,
        ("DELETE", p) if namespace_standard_delete_path(p) => true,
        ("POST", super::routes::NAMESPACES) => true,
        ("DELETE", super::routes::NAMESPACES) => true,
        // Wave-3 Continuation 3 — lifecycle write paths (Phase 13/14/16/17/18/19).
        ("POST", super::routes::FORGET) => true,
        ("POST", super::routes::CONSOLIDATE) => true,
        ("GET", super::routes::CONTRADICTIONS) => true,
        // v0.7.0 L6 — S51 autonomous-tier endpoints. Both are
        // LLM-only (no DB access for the request body itself) so the
        // postgres gate just needs to pass them through to the
        // handler, which handles the 503 fallback when no LLM is
        // wired.
        ("POST", super::routes::AUTO_TAG) => true,
        ("POST", super::routes::EXPAND_QUERY) => true,
        // v0.7.0 L9 / L10 — HTTP parity for `tools/list` and
        // `memory_load_family`. `tools/list` is pure config
        // enumeration (no DB); `memory_load_family` reads through the
        // SAL trait on the postgres path.
        ("GET", super::routes::TOOLS_LIST) => true,
        ("POST", super::routes::MEMORY_LOAD_FAMILY) => true,
        ("POST", super::routes::NOTIFY) => true,
        ("POST", super::routes::GC) => true,
        ("POST", super::routes::IMPORT) => true,
        ("GET", super::routes::EXPORT) => true,
        ("POST", super::routes::ARCHIVE) => true,
        ("DELETE", super::routes::ARCHIVE) => true,
        ("POST", p) if archive_restore_path(p) => true,
        // Wave-3 Continuation 3 — remaining write paths the sqlite path
        // already wires through `app.store` in their handlers (these
        // were soft-routed by the legacy db:: free-functions before
        // Continuation 3, so the gate now allow-lists them so the gate
        // doesn't 501 a working sqlite-routed handler on a postgres
        // daemon. Each handler internally enforces postgres-vs-sqlite
        // dispatch, so the gate's job is just to permit the request to
        // reach the handler).
        ("POST", super::routes::AGENTS) => true,
        ("DELETE", super::routes::LINKS) => true,
        ("POST", super::routes::SUBSCRIPTIONS) | ("DELETE", super::routes::SUBSCRIPTIONS) => true,
        ("POST", super::routes::SESSION_START) => true,
        ("POST", p) if memory_promote_path(p) => true,
        ("POST", p) if approvals_decide_path(p) => true,
        // #1548/#1549 — recursive-learning surfaces now routed through
        // the SAL trait on postgres (`MemoryStore::reflect` /
        // `get_reflection_origin` / `list_recall_observations`), so the
        // gate permits them to reach the handler's postgres branch.
        ("POST", super::routes::MEMORY_REFLECT) => true,
        ("POST", super::routes::MEMORY_REFLECTION_ORIGIN) => true,
        ("POST", super::routes::MEMORY_RECALL_OBSERVATIONS) => true,
        _ => false,
    }
}

/// Path matcher for `/api/v1/memories/{id}/promote`.
#[cfg(feature = "sal")]
fn memory_promote_path(p: &str) -> bool {
    let Some(rest) = p.strip_prefix("/api/v1/memories/") else {
        return false;
    };
    rest.ends_with("/promote") && rest.split('/').count() == 2
}

/// Path matcher for `POST /api/v1/approvals/{pending_id}` (HMAC-gated).
#[cfg(feature = "sal")]
fn approvals_decide_path(p: &str) -> bool {
    let Some(rest) = p.strip_prefix("/api/v1/approvals/") else {
        return false;
    };
    !rest.is_empty() && rest != "stream" && !rest.contains('/')
}

/// Path matcher for `/api/v1/archive/{id}/restore`.
#[cfg(feature = "sal")]
fn archive_restore_path(p: &str) -> bool {
    let Some(rest) = p.strip_prefix("/api/v1/archive/") else {
        return false;
    };
    rest.ends_with("/restore") && rest.split('/').count() == 2
}

/// Path matcher for `/api/v1/pending/{id}/approve|reject`.
#[cfg(feature = "sal")]
fn pending_decide_path(p: &str) -> bool {
    let Some(rest) = p.strip_prefix("/api/v1/pending/") else {
        return false;
    };
    matches!(rest.split_once('/'), Some((_, "approve" | "reject")))
}

/// Path matcher for `POST /api/v1/namespaces/{ns}/standard`.
#[cfg(feature = "sal")]
fn namespace_standard_post_path(p: &str) -> bool {
    let Some(rest) = p.strip_prefix("/api/v1/namespaces/") else {
        return false;
    };
    rest.ends_with("/standard") && rest.split('/').count() == 2
}

/// Path matcher for `DELETE /api/v1/namespaces/{ns}/standard`.
#[cfg(feature = "sal")]
fn namespace_standard_delete_path(p: &str) -> bool {
    namespace_standard_post_path(p)
}

/// Path matcher for `/api/v1/memories/{id}` (no further sub-segment).
#[cfg(feature = "sal")]
fn memory_id_path(p: &str) -> bool {
    let Some(rest) = p.strip_prefix("/api/v1/memories/") else {
        return false;
    };
    // Reject the bulk path and any further sub-segments.
    if rest == "bulk" {
        return false;
    }
    !rest.contains('/')
}

/// Path matcher for `/api/v1/links/{id}`.
#[cfg(feature = "sal")]
fn links_id_path(p: &str) -> bool {
    let Some(rest) = p.strip_prefix("/api/v1/links/") else {
        return false;
    };
    !rest.is_empty() && !rest.contains('/')
}

/// v0.7.0 #1410 — registered-route table.
///
/// Returns `true` if the given (method, path) tuple has a
/// corresponding `.route(...)` registration in
/// [`crate::build_router_with_timeout`]. Used by
/// [`postgres_route_gate`] to distinguish "no such route" (let Axum
/// fire its default 404) from "route exists but postgres-unimplemented"
/// (emit the 501 envelope).
///
/// **Why this exists.** The postgres route-gate middleware runs
/// BEFORE Axum's router resolves the request to a handler. Without
/// this table the middleware can't tell `GET /api/v1/nope` (no route
/// registered anywhere) from `GET /api/v1/some_postgres_unsupported_path`
/// (route exists but the postgres adapter has no impl). Pre-#1410 both
/// fell through to the same 501 "not yet implemented" envelope which
/// is a wire-truthfulness violation — a 501 implies a planned-but-pending
/// impl; an unknown URL is a typo or a wrong-version client and must
/// be a 404 per the #1052 wire-truthfulness contract.
///
/// **Maintenance contract.** Every `.route(<path>, get|post|put|delete(...))`
/// registration in [`crate::build_router_with_timeout`] (currently
/// `src/lib.rs` lines ~442-686) MUST have a corresponding entry below.
/// When adding a new route to `build_router_with_timeout`, add an
/// entry here AND extend the matching test under the
/// `transport_postgres_gate_tests` module so the table stays in lockstep
/// with the router. The static `&'static [(&str, &[Method])]` slice for
/// fixed paths is constant-time scanned; path-parameter routes
/// (`/{id}` style) reuse the existing `memory_id_path()` /
/// `links_id_path()` / etc. helpers that already underpin the
/// postgres-supported allowlist.
#[cfg(feature = "sal")]
#[must_use]
pub fn path_is_registered_route(method: &axum::http::Method, path: &str) -> bool {
    // Fixed-path routes — exact (method, path) equality. Order mirrors
    // `crate::build_router_with_timeout` for easy line-by-line
    // verification when a new route lands.
    #[allow(clippy::match_same_arms)]
    let fixed_match = match (method.as_str(), path) {
        // Core health + metadata.
        ("GET", super::routes::HEALTH) => true,
        ("GET", super::routes::METRICS_BARE) => true,
        ("GET", super::routes::METRICS) => true,
        ("GET", super::routes::CAPABILITIES) => true,
        // Memories CRUD + bulk.
        ("GET", super::routes::MEMORIES) => true,
        ("POST", super::routes::MEMORIES) => true,
        ("POST", super::routes::MEMORIES_BULK) => true,
        // Search + recall.
        ("GET", super::routes::SEARCH) => true,
        ("GET", super::routes::RECALL) => true,
        ("POST", super::routes::RECALL) => true,
        // Lifecycle.
        ("POST", super::routes::FORGET) => true,
        ("POST", super::routes::CONSOLIDATE) => true,
        ("GET", super::routes::CONTRADICTIONS) => true,
        // L6 autonomous-tier.
        ("POST", super::routes::AUTO_TAG) => true,
        ("POST", super::routes::EXPAND_QUERY) => true,
        // L9 / L10 — tools/list + load_family.
        ("GET", super::routes::TOOLS_LIST) => true,
        ("POST", super::routes::MEMORY_LOAD_FAMILY) => true,
        // Links.
        ("POST", super::routes::LINKS) => true,
        ("DELETE", super::routes::LINKS) => true,
        // Namespaces (qs form).
        ("GET", super::routes::NAMESPACES) => true,
        ("POST", super::routes::NAMESPACES) => true,
        ("DELETE", super::routes::NAMESPACES) => true,
        // Pillar 1 / Stream A — taxonomy.
        ("GET", super::routes::TAXONOMY) => true,
        // Pillar 2 / Stream D — check_duplicate.
        ("POST", super::routes::CHECK_DUPLICATE) => true,
        // Pillar 2 / Stream B — entities.
        ("POST", super::routes::ENTITIES) => true,
        ("GET", super::routes::ENTITIES_BY_ALIAS) => true,
        // Pillar 2 / Stream C — KG endpoints.
        ("GET", super::routes::KG_TIMELINE) => true,
        ("POST", super::routes::KG_INVALIDATE) => true,
        ("POST", super::routes::KG_QUERY) => true,
        ("POST", super::routes::KG_FIND_PATHS) => true,
        // #934 — bare /find_paths alias.
        ("POST", super::routes::FIND_PATHS) => true,
        // Continuation 6 — link verify + quota status.
        ("POST", super::routes::LINKS_VERIFY) => true,
        ("POST", super::routes::QUOTA_STATUS) => true,
        // Admin / stats / GC.
        ("GET", super::routes::STATS) => true,
        ("POST", super::routes::GC) => true,
        ("GET", super::routes::EXPORT) => true,
        ("POST", super::routes::IMPORT) => true,
        // Archive surface.
        ("GET", super::routes::ARCHIVE) => true,
        ("POST", super::routes::ARCHIVE) => true,
        ("DELETE", super::routes::ARCHIVE) => true,
        ("GET", super::routes::ARCHIVE_STATS) => true,
        // Agents.
        ("GET", super::routes::AGENTS) => true,
        ("POST", super::routes::AGENTS) => true,
        // Pending governance.
        ("GET", super::routes::PENDING) => true,
        // Approvals SSE stream (path form not parameterised).
        ("GET", super::routes::APPROVALS_STREAM) => true,
        // Federation sync.
        ("POST", super::routes::SYNC_PUSH) => true,
        ("GET", super::routes::SYNC_SINCE) => true,
        // Notify / inbox / subscriptions.
        ("POST", super::routes::NOTIFY) => true,
        ("GET", super::routes::INBOX) => true,
        ("POST", super::routes::SUBSCRIPTIONS) => true,
        ("DELETE", super::routes::SUBSCRIPTIONS) => true,
        ("GET", super::routes::SUBSCRIPTIONS) => true,
        ("POST", super::routes::SESSION_START) => true,
        // Cluster E API-2 — Agent Skills (parameterless variants).
        ("POST", super::routes::SKILL_REGISTER) => true,
        ("GET", super::routes::SKILL_LIST) => true,
        // #1095 — share.
        ("POST", super::routes::SHARE) => true,
        // #1111 — 14 MCP-tool parity routes.
        ("POST", super::routes::MEMORY_SMART_LOAD) => true,
        ("POST", super::routes::MEMORY_REFLECT) => true,
        ("POST", super::routes::MEMORY_RECALL_OBSERVATIONS) => true,
        ("POST", super::routes::MEMORY_REFLECTION_ORIGIN) => true,
        ("POST", super::routes::MEMORY_DEPENDENTS_OF_INVALIDATED) => true,
        ("POST", super::routes::MEMORY_EXPORT_REFLECTION) => true,
        ("POST", super::routes::MEMORY_ATOMISE) => true,
        ("POST", super::routes::MEMORY_CALIBRATE_CONFIDENCE) => true,
        ("POST", super::routes::MEMORY_VERIFY) => true,
        ("POST", super::routes::MEMORY_REPLAY) => true,
        ("POST", super::routes::MEMORY_SUBSCRIPTION_REPLAY) => true,
        ("POST", super::routes::MEMORY_SUBSCRIPTION_DLQ_LIST) => true,
        ("POST", super::routes::MEMORY_RULE_LIST) => true,
        ("POST", super::routes::MEMORY_CHECK_AGENT_ACTION) => true,
        _ => false,
    };

    if fixed_match {
        return true;
    }

    // Path-parameter routes — reuse the helpers that already power the
    // postgres-supported allowlist (memory_id_path, links_id_path, etc.)
    // so the two tables can't drift on the {id} shape.
    match (method.as_str(), path) {
        // /api/v1/memories/{id}
        ("GET" | "PUT" | "DELETE", p) if memory_id_path(p) => true,
        // /api/v1/memories/{id}/promote
        ("POST", p) if memory_promote_path(p) => true,
        // /api/v1/links/{id}
        ("GET", p) if links_id_path(p) => true,
        // /api/v1/namespaces/{ns}/standard (GET/POST/DELETE all registered)
        ("GET" | "POST" | "DELETE", p) if namespace_standard_post_path(p) => true,
        // /api/v1/archive/{id}/restore
        ("POST", p) if archive_restore_path(p) => true,
        // /api/v1/pending/{id}/approve|reject
        ("POST", p) if pending_decide_path(p) => true,
        // /api/v1/approvals/{pending_id}
        ("POST", p) if approvals_decide_path(p) => true,
        // /api/v1/skill/{id} (GET)
        ("GET", p) if skill_id_path(p) => true,
        // /api/v1/skill/{id}/resource (GET)
        ("GET", p) if skill_id_sub_path(p, "resource") => true,
        // /api/v1/skill/{id}/export | /promote | /compose (POST)
        ("POST", p)
            if skill_id_sub_path(p, "export")
                || skill_id_sub_path(p, "promote")
                || skill_id_sub_path(p, "compose") =>
        {
            true
        }
        _ => false,
    }
}

/// Path matcher for `/api/v1/skill/{id}` (no further sub-segment).
#[cfg(feature = "sal")]
fn skill_id_path(p: &str) -> bool {
    let Some(rest) = p.strip_prefix("/api/v1/skill/") else {
        return false;
    };
    // Reject the bare list path and any further sub-segments.
    if rest == "list" || rest == "register" || rest.is_empty() {
        return false;
    }
    !rest.contains('/')
}

/// Path matcher for `/api/v1/skill/{id}/<suffix>` (exactly two segments).
#[cfg(feature = "sal")]
fn skill_id_sub_path(p: &str, suffix: &str) -> bool {
    let Some(rest) = p.strip_prefix("/api/v1/skill/") else {
        return false;
    };
    let Some((id, tail)) = rest.split_once('/') else {
        return false;
    };
    !id.is_empty() && tail == suffix
}

/// v0.7.0 Wave-3 Continuation — middleware that gates un-migrated
/// handlers when the daemon is postgres-backed.
///
/// Sits in the request pipeline after `api_key_auth` so authn still
/// applies, then short-circuits any (method, path) tuple not in
/// [`postgres_endpoint_supported`] with a structured 501 response.
///
/// On sqlite-backed daemons this is a pure pass-through — every path
/// is supported because the legacy `db::*` free-function code path is
/// the active path and `app.db` is the real on-disk database.
///
/// This is the load-bearing correctness fix for postgres-backed
/// daemons: without it, any un-migrated handler would silently use
/// the empty in-memory scratch SQLite database that `bootstrap_serve`
/// opens against the `--db` path (which is unused on postgres) and
/// either return empty results (read paths) or write to the wrong
/// database (write paths). The gate makes that impossible.
///
/// **#1410 (2026-05-29) — wire-truthfulness fix.** Pre-#1410 this
/// middleware emitted 501 NOT IMPLEMENTED for ANY (method, path) tuple
/// not in the [`postgres_endpoint_supported`] allowlist — including
/// paths that have no `.route(...)` registration anywhere in
/// [`crate::build_router_with_timeout`]. That fabricated a "deferred
/// implementation" wire signal for typos and wrong-version clients,
/// violating the #1052 wire-truthfulness contract (a 501 implies
/// "planned but pending"; an unknown URL must be a 404). Post-#1410
/// the middleware first consults [`path_is_registered_route`]: if the
/// path has no route registration at all, the request falls through
/// to Axum's default handler (which returns 404); only if the route
/// IS registered but is NOT in the postgres allowlist does the 501
/// envelope land.
#[cfg(feature = "sal")]
pub async fn postgres_route_gate(
    State(app): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    if !matches!(app.storage_backend, StorageBackend::Postgres) {
        return next.run(req).await;
    }

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    if postgres_endpoint_supported(&method, &path) {
        return next.run(req).await;
    }

    // #1410 — distinguish "no route registered" (404) from "route
    // registered but postgres-unimplemented" (501). Pre-#1410 the
    // middleware fabricated a 501 for both, which is a wire-truthfulness
    // violation per the #1052 contract. When the path has no route
    // registration anywhere in the router, fall through so Axum's
    // default 404 fires.
    if !path_is_registered_route(&method, &path) {
        tracing::debug!(
            method = %method,
            path = %path,
            "postgres-backed daemon: passing unrouted path to Axum 404 handler (#1410)"
        );
        return next.run(req).await;
    }

    tracing::debug!(
        method = %method,
        path = %path,
        "postgres-backed daemon: 501 for un-migrated endpoint"
    );

    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "endpoint not yet implemented for postgres-backed daemon",
            "endpoint": path,
            "method": method.as_str(),
            "storage_backend": "postgres",
            "remediation": "use sqlite-backed daemon or wait for v0.7.x trait coverage; \
                            see docs/postgres-age-guide.md for the supported endpoint inventory",
        })),
    )
        .into_response()
}

/// v0.7.0 Wave-3 — translate a [`crate::store::StoreError`] into the
/// daemon's standard HTTP error envelope. Centralised so every
/// trait-routed handler reports backend errors with the same shape.
///
/// v0.7.0 M12 — every variant whose `to_string()` may carry adapter-
/// originating payload (connection strings, file paths, raw sqlx
/// diagnostics) is routed through [`sanitize_store_err_message`]
/// before landing in the HTTP envelope. The raw error is still
/// captured to the structured tracing log for operators; the wire
/// surface only carries the scrubbed message so an authenticated
/// client cannot exfiltrate the postgres URL by triggering a typed
/// error path.
#[cfg(feature = "sal")]
#[must_use]
pub fn store_err_to_response(e: crate::store::StoreError) -> Response {
    use crate::store::StoreError;
    let (status, msg) = match &e {
        StoreError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
        StoreError::Conflict { .. } => (
            StatusCode::CONFLICT,
            sanitize_store_err_message(&e.to_string()),
        ),
        StoreError::PermissionDenied { .. } => (
            StatusCode::FORBIDDEN,
            sanitize_store_err_message(&e.to_string()),
        ),
        StoreError::InvalidInput { .. } => (
            StatusCode::BAD_REQUEST,
            sanitize_store_err_message(&e.to_string()),
        ),
        StoreError::UnsupportedCapability { capability } => (
            StatusCode::NOT_IMPLEMENTED,
            format!("backend does not support capability: {capability}"),
        ),
        StoreError::IntegrityFailed { .. } | StoreError::BackendUnavailable { .. } => {
            tracing::error!("store backend error: {e}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "storage backend unavailable".to_string(),
            )
        }
        _ => {
            tracing::error!("store backend error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error".to_string(),
            )
        }
    };
    (status, Json(json!({"error": msg}))).into_response()
}

/// v0.7.0 M12 — scrub adapter-originating payload from a
/// [`crate::store::StoreError`]'s display string before it lands in an
/// HTTP response. The redaction targets three families of leakage the
/// M12 audit found in real sqlx + filesystem error paths:
///
/// 1. **Connection-string-like fragments** — anything matching the
///    `scheme://user:pass@host[:port]/db` shape. The entire run from
///    the scheme through the next whitespace / quote / brace boundary
///    is replaced with `[redacted-url]` so an authenticated caller
///    cannot read the postgres URL out of a wrapped
///    `sqlx::Error::Configuration("invalid url postgres://…")` (or any
///    other variant whose Display interpolates the connection target).
/// 2. **Absolute filesystem paths** — anything starting with `/` and
///    running through a typical path charset gets replaced with
///    `[redacted-path]`. Closes the
///    `sqlx::Error::Io("/var/lib/postgresql/…")` family.
///
/// The function is deliberately textual (byte scan) rather than
/// variant-aware: the cost of a missed leak (PII / credential
/// exposure) far outweighs the cost of over-sanitization (a slightly
/// less specific error message). Operators who need the raw
/// diagnostic still get it via the structured tracing log emitted at
/// the call site.
#[cfg(feature = "sal")]
#[must_use]
pub fn sanitize_store_err_message(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        // Look for "://" — strong signal of a URL.
        if i + 2 < bytes.len() && &bytes[i..i + 3] == b"://" {
            // Walk backward through any scheme characters we already
            // emitted, then pop them from `out` and replace the whole
            // run with the sentinel.
            let mut scheme_start = i;
            while scheme_start > 0 {
                let c = bytes[scheme_start - 1];
                if c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.' {
                    scheme_start -= 1;
                } else {
                    break;
                }
            }
            let pop = i - scheme_start;
            out.truncate(out.len().saturating_sub(pop));
            out.push_str("[redacted-url]");
            // Skip past "://" plus the rest of the URL run (anything
            // not whitespace/quote/brace/paren/comma/semicolon/angle).
            i += 3;
            while i < bytes.len() {
                let c = bytes[i];
                if c.is_ascii_whitespace()
                    || c == b'"'
                    || c == b'\''
                    || c == b'`'
                    || c == b'{'
                    || c == b'}'
                    || c == b'('
                    || c == b')'
                    || c == b','
                    || c == b';'
                    || c == b'<'
                    || c == b'>'
                {
                    break;
                }
                i += 1;
            }
            continue;
        }

        // Absolute paths — require a separator/boundary before the '/'
        // so we don't gut "1/2" inside an unrelated diagnostic.
        if bytes[i] == b'/'
            && (i == 0
                || matches!(
                    bytes[i - 1],
                    b' ' | b'\t' | b'\n' | b'"' | b'\'' | b'(' | b'[' | b'=' | b':'
                ))
            && i + 1 < bytes.len()
            && (bytes[i + 1].is_ascii_alphanumeric()
                || bytes[i + 1] == b'_'
                || bytes[i + 1] == b'.')
        {
            out.push_str("[redacted-path]");
            i += 1;
            while i < bytes.len() {
                let c = bytes[i];
                if c.is_ascii_alphanumeric() || c == b'/' || c == b'.' || c == b'_' || c == b'-' {
                    i += 1;
                } else {
                    break;
                }
            }
            continue;
        }

        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(all(test, feature = "sal"))]
mod store_err_sanitize_tests {
    use super::sanitize_store_err_message;

    #[test]
    fn sanitize_redacts_postgres_url() {
        let leak = "connection failed for postgres://admin:hunter2@db.internal:5432/ai_memory";
        let clean = sanitize_store_err_message(leak);
        assert!(!clean.contains("postgres://"), "raw scheme leaked: {clean}");
        assert!(!clean.contains("hunter2"), "password leaked: {clean}");
        assert!(!clean.contains("db.internal"), "host leaked: {clean}");
        assert!(
            clean.contains("[redacted-url]"),
            "missing sentinel: {clean}"
        );
    }

    #[test]
    fn sanitize_redacts_filesystem_path() {
        let leak = "open /var/lib/postgresql/data/global/pg_control failed";
        let clean = sanitize_store_err_message(leak);
        assert!(!clean.contains("/var/lib"), "raw path leaked: {clean}");
        assert!(
            clean.contains("[redacted-path]"),
            "missing sentinel: {clean}"
        );
    }

    #[test]
    fn sanitize_passes_through_clean_diagnostics() {
        let clean_input = "memory not found: abc-123";
        let out = sanitize_store_err_message(clean_input);
        assert_eq!(out, clean_input);
    }

    #[test]
    fn sanitize_handles_multiple_leaks() {
        let leak = "sqlx error at postgres://u:p@h/db touching /etc/secret/key";
        let clean = sanitize_store_err_message(leak);
        assert!(!clean.contains("postgres://"));
        assert!(!clean.contains("/etc/secret"));
        assert!(clean.contains("[redacted-url]"));
        assert!(clean.contains("[redacted-path]"));
    }

    #[test]
    fn sanitize_preserves_relative_paths() {
        // A literal "/" surrounded by digits ("1/2") must NOT be
        // treated as a path. Regression test for the boundary check.
        let raw = "ratio 1/2 over 3/4";
        let out = sanitize_store_err_message(raw);
        assert_eq!(out, raw, "fraction-like content must not be redacted");
    }

    #[test]
    fn sanitize_handles_unicode_in_clean_message() {
        let raw = "memory not found: \u{1F4DD}-id-with-emoji";
        let out = sanitize_store_err_message(raw);
        assert!(out.contains("memory not found"));
    }

    #[test]
    fn sanitize_redacts_url_at_start_of_message() {
        let leak = "postgres://u:p@h/db is unreachable";
        let clean = sanitize_store_err_message(leak);
        assert!(clean.starts_with("[redacted-url]"));
    }
}

// ---------------------------------------------------------------------------
// L0.7-6 Tier E coverage — exercise the helper surface that does not
// require a real Axum runtime: percent decoder, constant-time compare,
// store-error wire-shape mapper, postgres endpoint matrix, AppState
// helpers. The router-bound paths (api_key_auth full pipeline,
// JsonOrBadRequest extractor, postgres_route_gate live middleware)
// remain integration-only per coverage/policy.md.
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "sal"))]
mod transport_postgres_gate_tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn postgres_gate_always_passes_health_and_metrics() {
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::HEALTH
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::CAPABILITIES
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::METRICS_BARE
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::METRICS
        ));
    }

    #[test]
    fn postgres_gate_passes_core_crud() {
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::MEMORIES
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::MEMORIES
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::SEARCH
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::LINKS
        ));
    }

    #[test]
    fn postgres_gate_passes_recursive_learning_routes() {
        // #1548/#1549 — reflect / reflection_origin / recall_observations
        // are now SAL-routed on postgres and must pass the gate.
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::MEMORY_REFLECT
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::MEMORY_REFLECTION_ORIGIN
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::MEMORY_RECALL_OBSERVATIONS
        ));
    }

    #[test]
    fn postgres_gate_passes_memory_id_paths() {
        // GET / PUT / DELETE on /api/v1/memories/{id} are supported.
        assert!(postgres_endpoint_supported(
            &Method::GET,
            "/api/v1/memories/abc-123"
        ));
        assert!(postgres_endpoint_supported(
            &Method::PUT,
            "/api/v1/memories/abc-123"
        ));
        assert!(postgres_endpoint_supported(
            &Method::DELETE,
            "/api/v1/memories/abc-123"
        ));
        // POST on a single id is not in the matrix.
        assert!(!postgres_endpoint_supported(
            &Method::POST,
            "/api/v1/memories/abc-123"
        ));
        // /api/v1/memories/bulk is its own endpoint (not memory_id_path).
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::MEMORIES_BULK
        ));
    }

    #[test]
    fn postgres_gate_passes_links_id_paths() {
        assert!(postgres_endpoint_supported(
            &Method::GET,
            "/api/v1/links/link-id-1"
        ));
        // Empty trailing segment must not match.
        assert!(!postgres_endpoint_supported(&Method::GET, "/api/v1/links/"));
    }

    #[test]
    fn postgres_gate_passes_kg_paths() {
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::KG_QUERY
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::KG_TIMELINE
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::KG_INVALIDATE
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::KG_FIND_PATHS
        ));
    }

    #[test]
    fn postgres_gate_passes_quota_verify_entities() {
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::LINKS_VERIFY
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::QUOTA_STATUS
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::ENTITIES
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::ENTITIES_BY_ALIAS
        ));
    }

    #[test]
    fn postgres_gate_passes_archive_paths() {
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::ARCHIVE
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::ARCHIVE_STATS
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::ARCHIVE
        ));
        assert!(postgres_endpoint_supported(
            &Method::DELETE,
            crate::handlers::routes::ARCHIVE
        ));
        // #1563 — the gate previously allow-listed POST
        // /api/v1/archive/purge, a path NO router registers (purge is
        // DELETE /api/v1/archive). The dead arm is removed; pin that
        // the unregistered path is now refused by the gate too.
        assert!(!postgres_endpoint_supported(
            &Method::POST,
            "/api/v1/archive/purge"
        ));
        // archive_restore_path: /api/v1/archive/{id}/restore
        assert!(postgres_endpoint_supported(
            &Method::POST,
            "/api/v1/archive/abc/restore"
        ));
        assert!(!postgres_endpoint_supported(
            &Method::POST,
            "/api/v1/archive/abc/restore/other"
        ));
    }

    #[test]
    fn postgres_gate_passes_namespace_standard_paths() {
        assert!(postgres_endpoint_supported(
            &Method::POST,
            "/api/v1/namespaces/proj/standard"
        ));
        assert!(postgres_endpoint_supported(
            &Method::DELETE,
            "/api/v1/namespaces/proj/standard"
        ));
        assert!(!postgres_endpoint_supported(
            &Method::POST,
            "/api/v1/namespaces/standard"
        ));
    }

    #[test]
    fn postgres_gate_passes_pending_decide_paths() {
        assert!(postgres_endpoint_supported(
            &Method::POST,
            "/api/v1/pending/p1/approve"
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            "/api/v1/pending/p1/reject"
        ));
        // Non-approve-reject suffix must not match.
        assert!(!postgres_endpoint_supported(
            &Method::POST,
            "/api/v1/pending/p1/foo"
        ));
    }

    #[test]
    fn postgres_gate_passes_approvals_decide_paths() {
        assert!(postgres_endpoint_supported(
            &Method::POST,
            "/api/v1/approvals/abc-123"
        ));
        // /api/v1/approvals/stream is excluded from decide path.
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::APPROVALS_STREAM
        ));
    }

    #[test]
    fn postgres_gate_passes_memory_promote_path() {
        assert!(postgres_endpoint_supported(
            &Method::POST,
            "/api/v1/memories/abc/promote"
        ));
        assert!(!postgres_endpoint_supported(
            &Method::POST,
            "/api/v1/memories/abc/promote/extra"
        ));
    }

    #[test]
    fn postgres_gate_passes_remaining_write_paths() {
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::FORGET
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::CONSOLIDATE
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::CONTRADICTIONS
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::AUTO_TAG
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::EXPAND_QUERY
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::TOOLS_LIST
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::MEMORY_LOAD_FAMILY
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::NOTIFY
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::GC
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::IMPORT
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::EXPORT
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::AGENTS
        ));
        assert!(postgres_endpoint_supported(
            &Method::DELETE,
            crate::handlers::routes::LINKS
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::SUBSCRIPTIONS
        ));
        assert!(postgres_endpoint_supported(
            &Method::DELETE,
            crate::handlers::routes::SUBSCRIPTIONS
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::SESSION_START
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::SYNC_PUSH
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::SYNC_SINCE
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::PENDING
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::AGENTS
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::NAMESPACES
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::NAMESPACES
        ));
        assert!(postgres_endpoint_supported(
            &Method::DELETE,
            crate::handlers::routes::NAMESPACES
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::STATS
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::TAXONOMY
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::CHECK_DUPLICATE
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::SUBSCRIPTIONS
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::INBOX
        ));
        assert!(postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::RECALL
        ));
        assert!(postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::RECALL
        ));
    }

    #[test]
    fn postgres_gate_rejects_unknown_paths() {
        // Anything not in the allow-list must return false so the
        // route gate surfaces 501 instead of silently routing to the
        // empty scratch SQLite DB.
        assert!(!postgres_endpoint_supported(
            &Method::POST,
            "/api/v1/this/is/not/a/real/endpoint"
        ));
        assert!(!postgres_endpoint_supported(
            &Method::POST,
            "/api/v1/unknown"
        ));
    }

    // ---------------------------------------------------------------
    // #1410 — `path_is_registered_route` regression tests.
    //
    // These pin the wire-truthfulness contract: an unknown URL is a
    // 404 (no route registered anywhere) and a registered-but-
    // postgres-unimplemented URL is a 501. Pre-#1410 both fell through
    // to the same fabricated 501 envelope.
    // ---------------------------------------------------------------

    #[test]
    fn unknown_path_not_a_registered_route_1410() {
        // The original campaign-finding probe: `/api/v1/this-does-not-exist`
        // (no `.route(...)` registration anywhere in
        // `build_router_with_timeout`). Must return false so the
        // middleware falls through to Axum's default 404 handler.
        assert!(!path_is_registered_route(
            &Method::GET,
            "/api/v1/this-does-not-exist"
        ));
        assert!(!path_is_registered_route(
            &Method::POST,
            "/api/v1/federation/peers"
        ));
        assert!(!path_is_registered_route(
            &Method::POST,
            "/api/v1/totally/fake/path"
        ));
        // Wrong method on a registered path is also "not a registered
        // route" — Axum's router considers (method, path) as the key,
        // and unmatched methods on a real path get 405 from Axum
        // proper. Letting it pass through here lets Axum's typed 405
        // surface instead of a fabricated 501.
        assert!(!path_is_registered_route(
            &Method::PATCH,
            crate::handlers::routes::MEMORIES
        ));
    }

    #[test]
    fn registered_route_table_covers_every_router_registration_1410() {
        // Spot-check that every meaningfully distinct registered
        // route shape resolves through `path_is_registered_route`.
        // This is the maintenance contract for #1410: when a new
        // `.route(...)` lands in `build_router_with_timeout`, this
        // test (or its sibling fixed-table tests above) must pin it.

        // Fixed paths.
        assert!(path_is_registered_route(
            &Method::GET,
            crate::handlers::routes::HEALTH
        ));
        assert!(path_is_registered_route(
            &Method::GET,
            crate::handlers::routes::METRICS_BARE
        ));
        assert!(path_is_registered_route(
            &Method::POST,
            crate::handlers::routes::MEMORIES
        ));
        assert!(path_is_registered_route(
            &Method::GET,
            crate::handlers::routes::MEMORIES
        ));
        assert!(path_is_registered_route(
            &Method::POST,
            crate::handlers::routes::MEMORIES_BULK
        ));
        assert!(path_is_registered_route(
            &Method::GET,
            crate::handlers::routes::SEARCH
        ));
        assert!(path_is_registered_route(
            &Method::POST,
            crate::handlers::routes::FORGET
        ));
        assert!(path_is_registered_route(
            &Method::POST,
            crate::handlers::routes::CONSOLIDATE
        ));
        assert!(path_is_registered_route(
            &Method::POST,
            crate::handlers::routes::SHARE
        ));
        // route_1111 family — POST-only.
        assert!(path_is_registered_route(
            &Method::POST,
            crate::handlers::routes::MEMORY_SMART_LOAD
        ));
        assert!(path_is_registered_route(
            &Method::POST,
            crate::handlers::routes::MEMORY_REFLECT
        ));
        assert!(path_is_registered_route(
            &Method::POST,
            crate::handlers::routes::MEMORY_ATOMISE
        ));
        // KG endpoints.
        assert!(path_is_registered_route(
            &Method::GET,
            crate::handlers::routes::KG_TIMELINE
        ));
        assert!(path_is_registered_route(
            &Method::POST,
            crate::handlers::routes::KG_QUERY
        ));
        assert!(path_is_registered_route(
            &Method::POST,
            crate::handlers::routes::KG_FIND_PATHS
        ));
        // #934 alias.
        assert!(path_is_registered_route(
            &Method::POST,
            crate::handlers::routes::FIND_PATHS
        ));
        // Namespaces (qs form + path form).
        assert!(path_is_registered_route(
            &Method::GET,
            crate::handlers::routes::NAMESPACES
        ));
        assert!(path_is_registered_route(
            &Method::POST,
            crate::handlers::routes::NAMESPACES
        ));
        assert!(path_is_registered_route(
            &Method::DELETE,
            crate::handlers::routes::NAMESPACES
        ));

        // Path-parameter routes.
        // /api/v1/memories/{id}
        assert!(path_is_registered_route(
            &Method::GET,
            "/api/v1/memories/abc-123"
        ));
        assert!(path_is_registered_route(
            &Method::PUT,
            "/api/v1/memories/abc-123"
        ));
        assert!(path_is_registered_route(
            &Method::DELETE,
            "/api/v1/memories/abc-123"
        ));
        // /api/v1/memories/{id}/promote
        assert!(path_is_registered_route(
            &Method::POST,
            "/api/v1/memories/abc-123/promote"
        ));
        // /api/v1/links/{id}
        assert!(path_is_registered_route(
            &Method::GET,
            "/api/v1/links/link-1"
        ));
        // /api/v1/namespaces/{ns}/standard
        assert!(path_is_registered_route(
            &Method::POST,
            "/api/v1/namespaces/proj/standard"
        ));
        assert!(path_is_registered_route(
            &Method::GET,
            "/api/v1/namespaces/proj/standard"
        ));
        assert!(path_is_registered_route(
            &Method::DELETE,
            "/api/v1/namespaces/proj/standard"
        ));
        // /api/v1/archive/{id}/restore
        assert!(path_is_registered_route(
            &Method::POST,
            "/api/v1/archive/abc/restore"
        ));
        // /api/v1/pending/{id}/approve|reject
        assert!(path_is_registered_route(
            &Method::POST,
            "/api/v1/pending/p1/approve"
        ));
        assert!(path_is_registered_route(
            &Method::POST,
            "/api/v1/pending/p1/reject"
        ));
        // /api/v1/approvals/{pending_id}
        assert!(path_is_registered_route(
            &Method::POST,
            "/api/v1/approvals/pa-1"
        ));
        // /api/v1/skill/{id}
        assert!(path_is_registered_route(
            &Method::GET,
            "/api/v1/skill/skill-1"
        ));
        // /api/v1/skill/{id}/<sub>
        assert!(path_is_registered_route(
            &Method::GET,
            "/api/v1/skill/skill-1/resource"
        ));
        assert!(path_is_registered_route(
            &Method::POST,
            "/api/v1/skill/skill-1/export"
        ));
        assert!(path_is_registered_route(
            &Method::POST,
            "/api/v1/skill/skill-1/promote"
        ));
        assert!(path_is_registered_route(
            &Method::POST,
            "/api/v1/skill/skill-1/compose"
        ));

        // `/api/v1/skill/list` IS a real registered route (fixed
        // path, line ~600 of `src/lib.rs`), so it MUST match via
        // the fixed-table arm above. The `skill_id_path` helper
        // specifically excludes `list` / `register` so the {id}
        // path-parameter arm doesn't double-match, but the fixed
        // table covers it independently. This pin makes sure we
        // don't regress into "list is treated as an {id}" or
        // "list is not registered at all".
        assert!(path_is_registered_route(
            &Method::GET,
            crate::handlers::routes::SKILL_LIST
        ));
        // Trailing extras must not match.
        assert!(!path_is_registered_route(
            &Method::POST,
            "/api/v1/skill/skill-1/export/extra"
        ));
        assert!(!path_is_registered_route(
            &Method::POST,
            "/api/v1/archive/abc/restore/extra"
        ));
    }

    #[test]
    fn registered_route_not_in_postgres_allowlist_1410() {
        // `/api/v1/share` (POST) IS a registered route per
        // `build_router_with_timeout` (lines ~624 in `src/lib.rs`),
        // but it is NOT in `postgres_endpoint_supported`. The pre-#1410
        // gate emitted a fabricated 501 for unknown paths AND for this
        // case; post-#1410 the wire surface MUST emit 501 for THIS
        // case (route exists, postgres-unimplemented) AND 404 for the
        // unknown case (no route at all). This test pins the "501
        // case" half of the contract; `unknown_path_not_a_registered_route_1410`
        // pins the "404 case" half.
        assert!(path_is_registered_route(
            &Method::POST,
            crate::handlers::routes::SHARE
        ));
        assert!(!postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::SHARE
        ));
        // Same shape — route_1111 family is registered but not
        // postgres-allowlisted.
        assert!(path_is_registered_route(
            &Method::POST,
            crate::handlers::routes::MEMORY_SMART_LOAD
        ));
        assert!(!postgres_endpoint_supported(
            &Method::POST,
            crate::handlers::routes::MEMORY_SMART_LOAD
        ));
        // Skill surface — registered but not postgres-allowlisted.
        assert!(path_is_registered_route(
            &Method::GET,
            crate::handlers::routes::SKILL_LIST
        ));
        assert!(!postgres_endpoint_supported(
            &Method::GET,
            crate::handlers::routes::SKILL_LIST
        ));
    }

    #[test]
    fn postgres_not_implemented_carries_endpoint_and_remediation() {
        let resp = postgres_not_implemented("/api/v1/test");
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn store_err_to_response_maps_every_variant_to_status() {
        use crate::store::StoreError;
        let r = store_err_to_response(StoreError::NotFound {
            id: "x".to_string(),
        });
        assert_eq!(r.status(), axum::http::StatusCode::NOT_FOUND);

        let r = store_err_to_response(StoreError::Conflict {
            id: "x".to_string(),
        });
        assert_eq!(r.status(), axum::http::StatusCode::CONFLICT);

        let r = store_err_to_response(StoreError::PermissionDenied {
            action: "r".to_string(),
            target: "t".to_string(),
            reason: "x".to_string(),
        });
        assert_eq!(r.status(), axum::http::StatusCode::FORBIDDEN);

        let r = store_err_to_response(StoreError::InvalidInput {
            detail: "bad".to_string(),
        });
        assert_eq!(r.status(), axum::http::StatusCode::BAD_REQUEST);

        let r = store_err_to_response(StoreError::UnsupportedCapability {
            capability: "X".to_string(),
        });
        assert_eq!(r.status(), axum::http::StatusCode::NOT_IMPLEMENTED);

        let r = store_err_to_response(StoreError::IntegrityFailed {
            detail: "d".to_string(),
        });
        assert_eq!(r.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);

        let r = store_err_to_response(StoreError::BackendUnavailable {
            backend: "p".to_string(),
            detail: "d".to_string(),
        });
        assert_eq!(r.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);

        let r = store_err_to_response(StoreError::Backend(crate::store::BoxBackendError::new(
            "raw",
        )));
        assert_eq!(r.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }
}
