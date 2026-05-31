// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! HTTP handlers for the v0.7.0 knowledge-graph + entity surface (#650
//! follow-up per-domain split). Each handler is a thin Axum-layer
//! wrapper around the SAL `MemoryStore` trait (postgres path) or the
//! legacy `db::*` API (sqlite path), shaping the result into the
//! canonical wire envelope.
//!
//! All handlers were extracted verbatim from `src/handlers/http.rs`
//! (commit `12e1253`, lines 4169-5013 + 5192-5419); wire compatibility
//! is preserved via the `pub use kg::*` re-export from
//! `src/handlers/mod.rs`. The split keeps the kg/entity domain in
//! a single ~1 100-line module while shrinking the legacy
//! `handlers/http.rs` toward the long-term ≤600-LOC target.
//!
//! Functions in this module:
//!   - `entity_register`        (POST /api/v1/entities)
//!   - `entity_get_by_alias`    (GET  /api/v1/entities/by_alias)
//!   - `kg_timeline`            (GET  /api/v1/kg/timeline)
//!   - `kg_invalidate`          (POST /api/v1/kg/invalidate)
//!   - `kg_find_paths`          (POST /api/v1/kg/find_paths)
//!   - `kg_query`               (POST /api/v1/kg/query)

#![allow(clippy::too_many_lines)]

use crate::models::Memory;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;

use crate::db;
use crate::validate;

use super::AppState;
#[cfg(feature = "sal")]
use super::StorageBackend;
#[cfg(feature = "sal")]
use super::store_err_to_response;

/// Request body for `POST /api/v1/entities` (Pillar 2 / Stream B).
#[derive(Debug, Deserialize)]
pub struct EntityRegisterBody {
    pub canonical_name: String,
    pub namespace: String,
    /// Aliases that should resolve to this entity. Blanks are skipped;
    /// duplicates collapse via `entity_aliases`'s primary key.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Arbitrary metadata to merge onto the entity memory. `kind` is
    /// always overwritten with `"entity"`.
    #[serde(default)]
    pub metadata: serde_json::Value,
    /// Override the resolved NHI for this request's
    /// `metadata.agent_id`. Falls back to the `X-Agent-Id` header
    /// when omitted.
    pub agent_id: Option<String>,
}

/// Query parameters for `GET /api/v1/entities/by_alias` (Pillar 2 /
/// Stream B).
#[derive(Debug, Deserialize)]
pub struct EntityByAliasQuery {
    pub alias: String,
    pub namespace: Option<String>,
}

/// `POST /api/v1/entities` — REST mirror of the MCP
/// `memory_entity_register` tool. Idempotent on
/// `(canonical_name, namespace)`; merges aliases on re-registration.
pub async fn entity_register(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EntityRegisterBody>,
) -> impl IntoResponse {
    if let Err(e) = validate::validate_title(&body.canonical_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid canonical_name: {e}")})),
        )
            .into_response();
    }
    if let Err(e) = validate::validate_namespace(&body.namespace) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid namespace: {e}")})),
        )
            .into_response();
    }

    let agent_id = body
        .agent_id
        .as_deref()
        .or_else(|| {
            headers
                .get(crate::HEADER_AGENT_ID)
                .and_then(|v| v.to_str().ok())
        })
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if let Some(aid) = agent_id.as_deref()
        && let Err(e) = validate::validate_agent_id(aid)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid agent_id: {e}")})),
        )
            .into_response();
    }

    let extra_metadata = if body.metadata.is_object() {
        body.metadata.clone()
    } else {
        json!({})
    };

    // v0.7.0 Wave-3 Continuation — postgres-backed daemons register
    // the entity as a regular memory (title = canonical_name,
    // namespace = body.namespace, kind=entity in metadata) via the
    // SAL `store` method. The wire shape mirrors the SQLite path.
    //
    // v0.7.0 Wave-3 Continuation 4 (Bucket E / S47) — alias-union
    // persistence on re-register. The SAL `store` method upserts on
    // `(title, namespace)`, but a naive overwrite of `metadata.aliases`
    // erases any aliases registered previously. To preserve the
    // canonical SQLite contract (`db::entity_register` unions aliases
    // across registrations), we first list any matching entity row and
    // union its prior aliases into the incoming set before the upsert.
    // v0.7.0 ARCH-2 FX-C2-batch5 (2026-05-27): the postgres branch now
    // rides the SAL trait `entity_register` (the alias-union walk +
    // upsert is encapsulated inside the adapter, byte-for-byte aligned
    // with the sqlite `db::entity_register` contract). Pre-batch5 the
    // handler open-coded the alias union + `app.store.store` upsert in
    // ~150 LOC; the trait method collapses that to a single call. The
    // governance enforcement gate (F-A2A1.5 / #705) is preserved
    // verbatim — entity rows remain governance-relevant writes and
    // must consult the namespace policy before the underlying upsert.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let aid = agent_id
            .clone()
            .unwrap_or_else(|| "anonymous:entity-register".to_string());
        let ctx = crate::store::CallerContext::for_agent(aid.clone());

        // F-A2A1.5 (#705) — governance enforcement runs BEFORE the
        // entity_register trait call so deny / pending / 403 / 202
        // semantics match the sqlite path. The payload shape is the
        // canonical entity-create body so a downstream approver replay
        // can reconstruct the registration on `execute_pending_action`.
        {
            use crate::models::GovernanceDecision;
            let payload_for_pending = serde_json::json!({
                "title": body.canonical_name,
                "namespace": body.namespace,
                "tier": "long",
                "tags": ["entity"],
                "metadata": &extra_metadata,
                "aliases": &body.aliases,
            });
            match app
                .store
                .enforce_governance_action(
                    crate::store::GovernedAction::Store,
                    &body.namespace,
                    &aid,
                    None,
                    None,
                    &payload_for_pending,
                )
                .await
            {
                Ok(GovernanceDecision::Allow) => {}
                Ok(GovernanceDecision::Deny(refusal)) => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": crate::governance::deny_message(
                                "entity_register",
                                crate::governance::DenyGate::Governance,
                                &refusal.reason,
                            ),
                        })),
                    )
                        .into_response();
                }
                Ok(GovernanceDecision::Pending(pending_id)) => {
                    return (
                        StatusCode::ACCEPTED,
                        Json(json!({
                            "status": "pending",
                            "pending_id": pending_id,
                            "reason": "governance requires approval",
                            "action": "store",
                            "namespace": body.namespace,
                            "storage_backend": "postgres",
                        })),
                    )
                        .into_response();
                }
                Err(e) => return store_err_to_response(e),
            }
        }

        return match app
            .store
            .entity_register(
                &ctx,
                &body.canonical_name,
                &body.namespace,
                &body.aliases,
                &extra_metadata,
                Some(&aid),
            )
            .await
        {
            Ok(reg) => (
                if reg.created {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
                Json(json!({
                    "entity_id": reg.entity_id,
                    "canonical_name": reg.canonical_name,
                    "namespace": reg.namespace,
                    "aliases": reg.aliases,
                    "created": reg.created,
                })),
            )
                .into_response(),
            Err(e) => store_err_to_response(e),
        };
    }

    let lock = app.db.lock().await;
    match db::entity_register(
        &lock.0,
        &body.canonical_name,
        &body.namespace,
        &body.aliases,
        &extra_metadata,
        agent_id.as_deref(),
    ) {
        Ok(reg) => {
            let status = if reg.created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            (
                status,
                Json(json!({
                    "entity_id": reg.entity_id,
                    "canonical_name": reg.canonical_name,
                    "namespace": reg.namespace,
                    "aliases": reg.aliases,
                    "created": reg.created,
                })),
            )
                .into_response()
        }
        Err(e) => {
            // Title-collision errors carry a stable, recognisable
            // substring; surface them as 409 Conflict so callers can
            // distinguish a genuine name clash from internal failure.
            let msg = e.to_string();
            if msg.contains("non-entity memory") {
                return (StatusCode::CONFLICT, Json(json!({"error": msg}))).into_response();
            }
            tracing::error!("handler error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
                .into_response()
        }
    }
}

/// `GET /api/v1/entities/by_alias?alias=<>&namespace=<>` — REST mirror
/// of the MCP `memory_entity_get_by_alias` tool. Returns
/// `{ found: false, ... }` with HTTP 200 when no entity claims the
/// alias under the filter, so callers don't have to disambiguate
/// "no match" from a server error.
pub async fn entity_get_by_alias(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(p): Query<EntityByAliasQuery>,
) -> impl IntoResponse {
    #[cfg(not(feature = "sal"))]
    let _ = &headers;
    let alias = p.alias.trim();
    if alias.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "alias is required"})),
        )
            .into_response();
    }
    let namespace = p
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

    // v0.7.0 ARCH-2 followup (FX-C2-batch3) — postgres-backed daemons
    // route through `MemoryStore::entity_get_by_alias` first for an
    // exact-alias match (the canonical resolution path). When the
    // dedicated trait method returns `Ok(None)` we fall back to the
    // legacy SAL `list` walk to preserve the `m.title.eq_ignore_ascii_case`
    // fallback (alias-or-title match) and `metadata.aliases` array
    // walk. Visibility filtering applies to the fallback path
    // identically to pre-fix behaviour.
    #[cfg(feature = "sal-postgres")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // 1. Trait-method exact-alias match — sqlx-native, single
        //    indexed lookup against `entity_aliases`.
        match app.store.entity_get_by_alias(alias, namespace).await {
            Ok(Some(rec)) => {
                // Apply the post-fix visibility mask: hide the entity
                // if the caller cannot see the underlying memory row.
                let caller = {
                    let header_agent_id = headers
                        .get(crate::HEADER_AGENT_ID)
                        .and_then(|v| v.to_str().ok());
                    crate::identity::resolve_http_agent_id(None, header_agent_id)
                        .unwrap_or_else(|_| format!("anonymous:req-{}", uuid::Uuid::new_v4()))
                };
                let caller_is_admin = crate::handlers::admin_role::is_admin_caller(&app, &caller);
                let ctx_admin =
                    crate::store::CallerContext::for_admin_checked(caller.clone(), caller_is_admin);
                let visible = caller_is_admin
                    || app
                        .store
                        .get(&ctx_admin, &rec.entity_id)
                        .await
                        .ok()
                        .as_ref()
                        .is_none_or(|m| crate::visibility::is_visible_to_caller(m, &caller));
                if visible {
                    return Json(json!({
                        "found": true,
                        "entity_id": rec.entity_id,
                        "canonical_name": rec.canonical_name,
                        "namespace": rec.namespace,
                        "aliases": rec.aliases,
                    }))
                    .into_response();
                }
                // Fall through to fallback-walk shape on visibility mask
                // — emits the `found:false` envelope below.
            }
            Ok(None) => { /* fall through to title-fallback walk */ }
            Err(e) => return store_err_to_response(e),
        }
        // 2. Fallback walk: legacy SAL `list` so the title-eq-alias
        //    branch and `metadata.aliases` array case-insensitive
        //    match stay functional.
        let ctx = crate::handlers::parity::http_caller_ctx(&headers, None);
        let filter = crate::store::Filter {
            namespace: namespace.map(str::to_string),
            limit: 1000,
            ..Default::default()
        };
        return match app.store.list(&ctx, &filter).await {
            Ok(memories) => {
                for m in &memories {
                    let Some(meta) = m.metadata.as_object() else {
                        continue;
                    };
                    let Some(kind) = meta.get("kind").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    if kind != "entity" {
                        continue;
                    }
                    // #869 audit (Category B — safe default): an entity
                    // with no `aliases` array collapses to empty
                    // `Vec<String>`; the lookup falls through to the
                    // `m.title.eq_ignore_ascii_case(alias)` branch.
                    let aliases: Vec<String> = meta
                        .get("aliases")
                        .and_then(|v| v.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    if aliases.iter().any(|a| a.eq_ignore_ascii_case(alias))
                        || m.title.eq_ignore_ascii_case(alias)
                    {
                        return Json(json!({
                            "found": true,
                            "entity_id": m.id,
                            "canonical_name": m.title,
                            "namespace": m.namespace,
                            "aliases": aliases,
                        }))
                        .into_response();
                    }
                }
                Json(json!({
                    "found": false,
                    "entity_id": null,
                    "canonical_name": null,
                    "namespace": null,
                    "aliases": [],
                }))
                .into_response()
            }
            Err(e) => store_err_to_response(e),
        };
    }

    // #947 SECURITY-medium (Track A QC sweep, 2026-05-20) — resolve
    // caller for the visibility post-filter on entity aliases. Pre-fix
    // any caller could resolve a private entity by alias in the sqlite
    // branch. Admin bypasses the filter.
    let caller = {
        let header_agent_id = headers
            .get(crate::HEADER_AGENT_ID)
            .and_then(|v| v.to_str().ok());
        crate::identity::resolve_http_agent_id(None, header_agent_id)
            .unwrap_or_else(|_| format!("anonymous:req-{}", uuid::Uuid::new_v4()))
    };
    let caller_is_admin = crate::handlers::admin_role::is_admin_caller(&app, &caller);

    let lock = app.db.lock().await;
    match db::entity_get_by_alias(&lock.0, alias, namespace) {
        Ok(Some(rec)) => {
            // Mask the entity if the caller cannot see the underlying
            // memory row. The `entity_id` IS the memory id by the
            // entity-as-memory contract; if the row exists and is not
            // visible to the caller, return the found:false shape
            // (existence-leak mask). If the row is missing entirely
            // (e.g. legacy entity-alias row without a backing memory),
            // fall through to the visible path — the alias is a
            // namespace-scoped pointer, not a private secret.
            let visible = caller_is_admin
                || db::get(&lock.0, &rec.entity_id)
                    .ok()
                    .flatten()
                    .as_ref()
                    .is_none_or(|m| crate::visibility::is_visible_to_caller(m, &caller));
            if !visible {
                return Json(json!({
                    "found": false,
                    "entity_id": null,
                    "canonical_name": null,
                    "namespace": null,
                    "aliases": [],
                }))
                .into_response();
            }
            Json(json!({
                "found": true,
                "entity_id": rec.entity_id,
                "canonical_name": rec.canonical_name,
                "namespace": rec.namespace,
                "aliases": rec.aliases,
            }))
            .into_response()
        }
        Ok(None) => Json(json!({
            "found": false,
            "entity_id": null,
            "canonical_name": null,
            "namespace": null,
            "aliases": [],
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

/// Query parameters for `GET /api/v1/kg/timeline` (Pillar 2 / Stream C).
#[derive(Debug, Deserialize)]
pub struct KgTimelineQuery {
    pub source_id: String,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<usize>,
}

/// `GET /api/v1/kg/timeline?source_id=<>&since=<>&until=<>&limit=<>` —
/// REST mirror of the MCP `memory_kg_timeline` tool. Returns outbound
/// link assertions from `source_id` ordered by `valid_from ASC`.
pub async fn kg_timeline(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(p): Query<KgTimelineQuery>,
) -> impl IntoResponse {
    if let Err(e) = validate::validate_id(&p.source_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid source_id: {e}")})),
        )
            .into_response();
    }
    let since = p.since.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let until = p.until.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if let Some(s) = since
        && let Err(e) = validate::validate_expires_at_format(s)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid since: {e}")})),
        )
            .into_response();
    }
    if let Some(u) = until
        && let Err(e) = validate::validate_expires_at_format(u)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid until: {e}")})),
        )
            .into_response();
    }

    // #944 SECURITY-high (Track A QC sweep, 2026-05-20) —
    // caller-vs-source-memory-owner gate. Pre-fix the GET handler
    // took NO `headers: HeaderMap` parameter, so any authenticated
    // caller could read the full outbound link-event timeline
    // (`target_id`, `relation`, `valid_from`, `valid_until`,
    // `observed_by`, `title`, `target_namespace`) for ANY source_id
    // — including memories owned by other tenants. Cross-tenant
    // info-leak on the temporal-graph surface. Mirrors the #938
    // `kg_invalidate` gate shape (commit 54706eeed, same file) and
    // the #937 `delete_memory` shape (commit a582bdc5b).
    let caller = match crate::handlers::parity::resolve_caller_agent_id(None, &headers, None) {
        Ok(c) => c,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": err}))).into_response();
        }
    };

    // Fetch the source memory + verify caller owns it (or is the
    // inbox target, or the row is unowned-legacy, or caller is
    // "daemon" sentinel). Mirrors the gate shape in #938
    // kg_invalidate and #937 delete_memory.
    //
    // #1134: branch on storage_backend so postgres-backed daemons
    // read the source memory from postgres instead of the empty
    // SQLite scratch connection (which made every postgres-backed
    // kg_timeline call return 404 regardless of the actual memory's
    // existence in the live store).
    let extract_owner_target = |mem: &Memory| -> (String, String) {
        let owner = mem
            .metadata
            .get("agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let target = mem
            .metadata
            .get("target_agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        (owner, target)
    };
    let source_owner: Option<(String, String)> = {
        #[cfg(feature = "sal")]
        if matches!(app.storage_backend, StorageBackend::Postgres) {
            let ctx = crate::store::CallerContext::for_agent(caller.clone());
            match app.store.get(&ctx, &p.source_id).await {
                Ok(mem) => Some(extract_owner_target(&mem)),
                Err(e) => {
                    let msg = format!("{e:?}");
                    if msg.contains("NotFound") || msg.contains("not found") {
                        None
                    } else {
                        tracing::error!("kg_timeline: source lookup failed (postgres): {e:?}");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "internal server error"})),
                        )
                            .into_response();
                    }
                }
            }
        } else {
            let lock = app.db.lock().await;
            match db::get(&lock.0, &p.source_id) {
                Ok(Some(mem)) => Some(extract_owner_target(&mem)),
                Ok(None) => None,
                Err(e) => {
                    tracing::error!("kg_timeline: source lookup failed: {e}");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "internal server error"})),
                    )
                        .into_response();
                }
            }
        }
        #[cfg(not(feature = "sal"))]
        {
            let lock = app.db.lock().await;
            match db::get(&lock.0, &p.source_id) {
                Ok(Some(mem)) => Some(extract_owner_target(&mem)),
                Ok(None) => None,
                Err(e) => {
                    tracing::error!("kg_timeline: source lookup failed: {e}");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "internal server error"})),
                    )
                        .into_response();
                }
            }
        }
    };
    let Some((owner, target)) = source_owner else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "found": false,
                "source_id": p.source_id,
                "error": "source memory not found",
            })),
        )
            .into_response();
    };
    let is_unowned_legacy = owner.is_empty();
    if !is_unowned_legacy && owner != caller && target != caller && caller != "daemon" {
        tracing::warn!(
            target: "ai_memory::authz",
            "GET /api/v1/kg/timeline 403: caller {caller} != owner {owner} (source_id={})",
            p.source_id
        );
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "caller does not own this source memory",
                "owner": owner,
                "caller": caller,
                "source_id": p.source_id,
            })),
        )
            .into_response();
    }

    // v0.7.0 ARCH-2 FX-C2-batch5 (2026-05-27): postgres dispatches via
    // the new `MemoryStore::kg_timeline` trait method (the SAL is the
    // canonical kg_timeline surface). The legacy
    // `kg_timeline_via_store` helper stays in place for out-of-tree
    // back-compat but new routes ride the trait. The adapter still
    // resolves AGE vs CTE backend at connect time and projects rows in
    // the shared `KgTimelineRow` shape so the wire envelope stays
    // parity-equal to the SQLite path.
    #[cfg(feature = "sal-postgres")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let limit = p.limit;
        return match app
            .store
            .kg_timeline(&p.source_id, since, until, limit)
            .await
        {
            Ok(events) => {
                let events_json: Vec<serde_json::Value> = events
                    .iter()
                    .map(|e| {
                        json!({
                            "target_id": e.target_id,
                            "relation": e.relation,
                            "valid_from": e.valid_from,
                            "valid_until": e.valid_until,
                            "observed_by": e.observed_by,
                            "title": e.title,
                            "target_namespace": e.target_namespace,
                        })
                    })
                    .collect();
                Json(json!({
                    "source_id": p.source_id,
                    "events": events_json,
                    "count": events.len(),
                }))
                .into_response()
            }
            Err(e) => store_err_to_response(e),
        };
    }

    let lock = app.db.lock().await;
    match db::kg_timeline(&lock.0, &p.source_id, since, until, p.limit) {
        Ok(events) => {
            let events_json: Vec<serde_json::Value> = events
                .iter()
                .map(|e| {
                    json!({
                        "target_id": e.target_id,
                        "relation": e.relation,
                        "valid_from": e.valid_from,
                        "valid_until": e.valid_until,
                        "observed_by": e.observed_by,
                        "title": e.title,
                        "target_namespace": e.target_namespace,
                    })
                })
                .collect();
            Json(json!({
                "source_id": p.source_id,
                "events": events_json,
                "count": events.len(),
            }))
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

/// JSON body for `POST /api/v1/kg/invalidate` (Pillar 2 / Stream C —
/// `memory_kg_invalidate`). The link is identified by its composite
/// key; `valid_until` defaults to wall-clock now when omitted.
#[derive(Debug, Deserialize)]
pub struct KgInvalidateBody {
    pub source_id: String,
    pub target_id: String,
    pub relation: String,
    pub valid_until: Option<String>,
}

/// `POST /api/v1/kg/invalidate` — REST mirror of `memory_kg_invalidate`.
/// 200 with `{found: true, …, previous_valid_until}` when the link
/// existed; 404 with `{found: false}` when no link matches the triple.
pub async fn kg_invalidate(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<KgInvalidateBody>,
) -> impl IntoResponse {
    if let Err(e) = validate::RequestValidator::validate_link_triple(
        &body.source_id,
        &body.target_id,
        &body.relation,
    ) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }
    let valid_until = body
        .valid_until
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(ts) = valid_until
        && let Err(e) = validate::validate_expires_at_format(ts)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid valid_until: {e}")})),
        )
            .into_response();
    }

    // #938 SECURITY-high (Track A QC sweep, 2026-05-20) —
    // caller-vs-source-memory-owner gate. Pre-fix any HTTP caller
    // could forge temporal-graph state by invalidating another
    // tenant's `:supersedes` / `:contradicts` / governance edges via
    // `valid_until = now()`, hiding contradiction history. Mirrors the
    // #930 caller-vs-owner gate shape on update/promote.
    let caller = match crate::handlers::parity::resolve_caller_agent_id(None, &headers, None) {
        Ok(c) => c,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": err}))).into_response();
        }
    };

    // Fetch the source memory + verify caller owns it (or is the
    // inbox target, or the row is unowned-legacy, or caller is
    // "daemon" sentinel). Mirrors the gate shape in #930 update_memory
    // and #936 archive_purge.
    let source_owner: Option<(String, String)> = {
        let lock = app.db.lock().await;
        match db::get(&lock.0, &body.source_id) {
            Ok(Some(mem)) => {
                let owner = mem
                    .metadata
                    .get("agent_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let target = mem
                    .metadata
                    .get("target_agent_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Some((owner, target))
            }
            Ok(None) => None,
            Err(e) => {
                tracing::error!("kg_invalidate: source lookup failed: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "internal server error"})),
                )
                    .into_response();
            }
        }
    };
    let Some((owner, target)) = source_owner else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "found": false,
                "source_id": body.source_id,
                "target_id": body.target_id,
                "relation": body.relation,
                "error": "source memory not found",
            })),
        )
            .into_response();
    };
    let is_unowned_legacy = owner.is_empty();
    if !is_unowned_legacy && owner != caller && target != caller && caller != "daemon" {
        tracing::warn!(
            target: "ai_memory::authz",
            "POST /api/v1/kg/invalidate 403: caller {caller} != owner {owner} (source_id={})",
            body.source_id
        );
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "caller does not own this source memory",
                "owner": owner,
                "caller": caller,
                "source_id": body.source_id,
            })),
        )
            .into_response();
    }

    // v0.7.0 SAL-routing batch-4 (FX-C2) — postgres dispatches via the
    // canonical `MemoryStore::invalidate_link` trait method. The
    // pre-fix `kg_invalidate_via_store` helper (an `as_any_for_postgres`
    // downcast hatch) stays in place for back-compat callers but new
    // routes ride the trait surface — no SAL-boundary bypass.
    #[cfg(feature = "sal-postgres")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return match app
            .store
            .invalidate_link(
                &body.source_id,
                &body.target_id,
                &body.relation,
                valid_until,
            )
            .await
        {
            Ok(res) if res.found => (
                StatusCode::OK,
                Json(json!({
                    "found": true,
                    "source_id": body.source_id,
                    "target_id": body.target_id,
                    "relation": body.relation,
                    "valid_until": res.valid_until,
                    "previous_valid_until": res.previous_valid_until,
                })),
            )
                .into_response(),
            Ok(_) => (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "found": false,
                    "source_id": body.source_id,
                    "target_id": body.target_id,
                    "relation": body.relation,
                })),
            )
                .into_response(),
            Err(e) => store_err_to_response(e),
        };
    }

    let lock = app.db.lock().await;
    match db::invalidate_link(
        &lock.0,
        &body.source_id,
        &body.target_id,
        &body.relation,
        valid_until,
    ) {
        Ok(Some(res)) => (
            StatusCode::OK,
            Json(json!({
                "found": true,
                "source_id": body.source_id,
                "target_id": body.target_id,
                "relation": body.relation,
                "valid_until": res.valid_until,
                "previous_valid_until": res.previous_valid_until,
            })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "found": false,
                "source_id": body.source_id,
                "target_id": body.target_id,
                "relation": body.relation,
            })),
        )
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

/// JSON body for `POST /api/v1/kg/find_paths`.
///
/// `source_id` + `target_id` are required. `max_depth` defaults to the
/// adapter's `FIND_PATHS_DEFAULT_DEPTH`; `max_results` clamps the
/// returned path count.
#[derive(Debug, Deserialize)]
pub struct FindPathsBody {
    /// Source memory id. Accepts the legacy `from_id` alias for
    /// compatibility with the MCP `memory_find_paths` tool, the CLI
    /// `find-paths --from`, and pre-v0.7.0 docs (#934 field-name drift
    /// fix, 2026-05-20).
    #[serde(alias = "from_id")]
    pub source_id: String,
    /// Target memory id. Accepts the legacy `to_id` alias for the same
    /// MCP / CLI / docs compatibility surface as `source_id`.
    #[serde(alias = "to_id")]
    pub target_id: String,
    #[serde(default)]
    pub max_depth: Option<usize>,
    #[serde(default)]
    pub max_results: Option<usize>,
}

/// `POST /api/v1/kg/find_paths` — enumerate up to N paths between two
/// memories. Wraps the SAL [`MemoryStore::find_paths`] surface so both
/// SQLite (recursive CTE) and Postgres (AGE Cypher / CTE fallback)
/// dispatch through the same handler.
///
/// Wire shape: `{paths: [[id, id, ...], ...], count}`. Each inner
/// array is the chain of memory ids from `source_id` to `target_id`,
/// inclusive.
pub async fn kg_find_paths(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<FindPathsBody>,
) -> impl IntoResponse {
    if let Err(e) = validate::validate_id(&body.source_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid source_id: {e}")})),
        )
            .into_response();
    }
    if let Err(e) = validate::validate_id(&body.target_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid target_id: {e}")})),
        )
            .into_response();
    }

    // #910 SAL-level — resolve the caller so the trait method's
    // visibility filter (path-traversal flavour) sees the right
    // principal. Header-only authentication on this POST surface;
    // anonymous callers get a per-request `anonymous:req-…` id.
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let caller = match crate::identity::resolve_http_agent_id(None, header_agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid agent_id: {e}")})),
            )
                .into_response();
        }
    };

    #[cfg(feature = "sal")]
    {
        let ctx = crate::store::CallerContext::for_agent(&caller);
        return match app
            .store
            .find_paths(
                &ctx,
                &body.source_id,
                &body.target_id,
                body.max_depth,
                body.max_results,
            )
            .await
        {
            Ok(paths) => {
                if crate::audit::is_enabled() {
                    crate::audit::emit(crate::audit::EventBuilder::new(
                        crate::audit::AuditAction::Recall,
                        crate::audit::actor("ai:http", "http_body", None),
                        crate::audit::target_memory(
                            body.source_id.clone(),
                            String::new(),
                            Some(format!("find_paths -> {}", body.target_id)),
                            None,
                            None,
                        ),
                    ));
                }
                let count = paths.len();
                Json(json!({
                    "paths": paths,
                    "count": count,
                    "source_id": body.source_id,
                    "target_id": body.target_id,
                }))
                .into_response()
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("max_depth") || msg.contains("depth") {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(json!({"error": msg})),
                    )
                        .into_response();
                }
                store_err_to_response(e)
            }
        };
    }

    #[cfg(not(feature = "sal"))]
    {
        let _ = app;
        let _ = body;
        let _ = caller;
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({"error": "find_paths requires --features sal"})),
        )
            .into_response()
    }
}

/// JSON body for `POST /api/v1/kg/query` (Pillar 2 / Stream C —
/// `memory_kg_query`). POST is used because `allowed_agents` is a list;
/// keeping it in a body avoids over-long query strings and keeps the
/// surface symmetric with `POST /api/v1/kg/invalidate`. `max_depth`
/// defaults to 1 and is bounded by `KG_QUERY_MAX_SUPPORTED_DEPTH`.
#[derive(Debug, Deserialize)]
pub struct KgQueryBody {
    /// Canonical name. Aliased by `from` (S82's wire shape).
    #[serde(default)]
    pub source_id: Option<String>,
    /// `from` alias for `source_id` — the cert harness S82 uses
    /// `{from, to, max_depth, rel_types}`.
    #[serde(default)]
    pub from: Option<String>,
    /// Optional target id — when present the query is interpreted as
    /// a find-path between (`source_id`, `to`); kg_query's existing
    /// surface ignores it but accepting it keeps the wire shape
    /// flexible for the cert harness.
    #[serde(default)]
    pub to: Option<String>,
    pub max_depth: Option<usize>,
    pub valid_at: Option<String>,
    pub allowed_agents: Option<Vec<String>>,
    pub limit: Option<usize>,
    /// NHI-P3-T7 (v0.7.0 NHI testing): when omitted or false, the
    /// "current view" filter excludes edges whose `valid_until` lies
    /// in the past (invalidated via `memory_kg_invalidate`). Pass
    /// `true` to traverse the full historical link graph.
    #[serde(default)]
    pub include_invalidated: bool,
    /// Optional relation-type filter — accepted for forward-compat
    /// with the find_paths shape; unused on the current trait
    /// surface (CTE walks `:related_to` only).
    #[serde(default)]
    pub rel_types: Option<Vec<String>>,
}

/// #910 (security-medium, 2026-05-19) — apply the scope=private
/// visibility filter on `POST /api/v1/kg/query` traversal results.
/// Pre-#910 the handler returned every reachable target node from
/// the recursive-CTE / AGE Cypher walk; a target whose
/// `metadata.scope == "private"` was visible to any caller who could
/// pass `kg_query` validation, including callers other than the
/// target's `metadata.agent_id` owner. The fix mirrors the post-
/// filter applied in `memories_query::list_memories` — a row is
/// visible iff `metadata.scope != "private"` OR
/// `metadata.agent_id == caller`. Rows we cannot fetch (deleted
/// since the traversal, in another namespace the caller cannot
/// read, etc.) fail-closed (excluded).
#[cfg(feature = "sal-postgres")]
async fn kg_query_filter_visible(
    app: &AppState,
    caller: &str,
    target_ids: Vec<String>,
) -> std::collections::HashSet<String> {
    // v0.7.0 F-E3 fix (issue #1436): route through the canonical
    // `crate::visibility::is_visible_to_caller` helper instead of
    // reimplementing the predicate inline. The pre-fix copy was missing
    // the `target_agent_id` inbox carve-out (the same defect class #951
    // closed at the SAL layer — the kg post-filter pre-dated that fix
    // and silently dropped inbox rows the recipient was entitled to
    // see).
    use std::collections::HashSet;
    let mut visible: HashSet<String> = HashSet::with_capacity(target_ids.len());
    let ctx = crate::store::CallerContext::for_agent(caller);
    for id in target_ids {
        if let Ok(mem) = app.store.get(&ctx, &id).await {
            if crate::visibility::is_visible_to_caller(&mem, caller) {
                visible.insert(id);
            }
        }
    }
    visible
}

/// `POST /api/v1/kg/query` — REST mirror of the MCP `memory_kg_query`
/// tool. Returns outbound multi-hop traversal from `source_id` (1..=5
/// hops) filtered by the temporal/agent windows. 400 for invalid
/// IDs/timestamps; 422 when `max_depth` exceeds the supported ceiling
/// (clearer than 500 for what is a documented limitation, not an
/// internal error).
pub async fn kg_query(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<KgQueryBody>,
) -> impl IntoResponse {
    // #910 (security-medium, 2026-05-19) — resolve the caller via the
    // `X-Agent-Id` header so the scope=private visibility filter
    // below has a known principal to compare `metadata.agent_id`
    // against. Pre-#910 `kg_query` returned every reachable target
    // node regardless of the target memory's `metadata.scope` — a
    // caller could enumerate scope=private targets owned by other
    // agents by walking from a public source row. Anonymous callers
    // get a per-request `anonymous:req-…` id and see only
    // non-private targets.
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let caller = match crate::identity::resolve_http_agent_id(None, header_agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid agent_id: {e}")})),
            )
                .into_response();
        }
    };

    // S82's wire shape sends `from` instead of `source_id`; resolve
    // the canonical id from either field with `source_id` taking
    // precedence when both are supplied.
    //
    // #869 audit (Category B — safe default): empty `String` flows
    // into `validate_id` below which returns a typed 400 with the
    // "invalid source_id" envelope.
    let source_id = body
        .source_id
        .clone()
        .or_else(|| body.from.clone())
        .unwrap_or_default();
    if let Err(e) = validate::validate_id(&source_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid source_id: {e}")})),
        )
            .into_response();
    }
    let max_depth = body.max_depth.unwrap_or(1);
    let valid_at = body
        .valid_at
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(t) = valid_at
        && let Err(e) = validate::validate_expires_at_format(t)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid valid_at: {e}")})),
        )
            .into_response();
    }
    let allowed_agents: Option<Vec<String>> = body.allowed_agents.as_ref().map(|v| {
        v.iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    });
    if let Some(agents) = allowed_agents.as_ref() {
        for a in agents {
            if let Err(e) = validate::validate_agent_id(a) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("invalid allowed_agents entry: {e}")})),
                )
                    .into_response();
            }
        }
    }

    // v0.7.0 ARCH-2 FX-C2-batch5 (2026-05-27): postgres dispatches via
    // the new `MemoryStore::kg_query` trait method (the SAL is the
    // canonical kg_query surface). The legacy `kg_query_via_store`
    // helper stays in place for out-of-tree back-compat but new routes
    // ride the trait. Backend (AGE vs CTE) is still resolved at
    // adapter connect time inside `kg_query_with_history`.
    // Temporal/agent filters are applied client-side post-traversal
    // because the AGE Cypher path returns the unfiltered topology —
    // match the SQLite recursive-CTE wire shape.
    #[cfg(feature = "sal-postgres")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return match app
            .store
            .kg_query(&source_id, max_depth, body.include_invalidated)
            .await
        {
            Ok(nodes) => {
                // #910 — fetch each target's metadata, filter by the
                // scope=private visibility rule (see
                // `kg_query_filter_visible`). Pre-#910 every reachable
                // target was returned verbatim regardless of the
                // target's owner / scope.
                let target_ids: Vec<String> = nodes.iter().map(|n| n.target_id.clone()).collect();
                let visible = kg_query_filter_visible(&app, &caller, target_ids).await;
                let nodes: Vec<_> = nodes
                    .into_iter()
                    .filter(|n| visible.contains(&n.target_id))
                    .collect();

                // S82's wire shape — when `to` is supplied, project a
                // single-path `paths` array of node-id chains so the
                // find-paths style consumer can read the result back
                // without a separate `find_paths` route.
                let memories_json: Vec<serde_json::Value> = nodes
                    .iter()
                    .map(|n| {
                        json!({
                            "target_id": n.target_id,
                            "relation": n.relation,
                            "depth": n.depth,
                            "path": n.path,
                        })
                    })
                    .collect();
                let mut paths_json: Vec<serde_json::Value> = Vec::new();
                if let Some(target) = body.to.as_deref() {
                    // Find the first traversal path that ends at `target`
                    // and project the chain as a list of node ids.
                    for n in &nodes {
                        if n.target_id == target {
                            let chain: Vec<String> =
                                n.path.split("->").map(str::to_string).collect();
                            paths_json.push(serde_json::Value::Array(
                                chain.into_iter().map(serde_json::Value::String).collect(),
                            ));
                            break;
                        }
                    }
                } else {
                    for n in &nodes {
                        paths_json.push(serde_json::Value::String(n.path.clone()));
                    }
                }
                Json(json!({
                    "source_id": source_id,
                    "max_depth": max_depth,
                    "memories": memories_json,
                    "paths": paths_json,
                    "count": nodes.len(),
                }))
                .into_response()
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("max_depth") || msg.contains("depth") {
                    (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(json!({"error": msg})),
                    )
                        .into_response()
                } else {
                    store_err_to_response(e)
                }
            }
        };
    }

    // #910 — apply scope=private visibility filter on the SQLite path
    // too. The kg_query DB function returns the full reachable
    // topology with target metadata absent from the row shape; we
    // post-fetch each target's `metadata.scope` / `metadata.agent_id`
    // inside the same lock window so the filter sees an atomic view
    // of the traversal.
    let lock = app.db.lock().await;
    let kg_res = db::kg_query(
        &lock.0,
        &source_id,
        max_depth,
        valid_at,
        allowed_agents.as_deref(),
        body.limit,
        body.include_invalidated,
    );
    let nodes_opt = match &kg_res {
        Ok(nodes) => {
            // v0.7.0 F-E3 fix (#1436): route through the canonical
            // `is_visible_to_caller` helper. Pre-fix the predicate was
            // inlined here missing the inbox carve-out
            // (`target_agent_id` short-circuit) — the same defect class
            // #951 closed at the SAL layer.
            let mut visible: std::collections::HashSet<String> =
                std::collections::HashSet::with_capacity(nodes.len());
            for n in nodes {
                if let Ok(Some(mem)) = db::get(&lock.0, &n.target_id) {
                    if crate::visibility::is_visible_to_caller(&mem, &caller) {
                        visible.insert(n.target_id.clone());
                    }
                }
            }
            Some(visible)
        }
        Err(_) => None,
    };
    drop(lock);
    match kg_res {
        Ok(nodes) => {
            let visible = nodes_opt.unwrap_or_default();
            let nodes: Vec<_> = nodes
                .into_iter()
                .filter(|n| visible.contains(&n.target_id))
                .collect();
            let memories_json: Vec<serde_json::Value> = nodes
                .iter()
                .map(|n| {
                    json!({
                        "target_id": n.target_id,
                        "relation": n.relation,
                        "valid_from": n.valid_from,
                        "valid_until": n.valid_until,
                        "observed_by": n.observed_by,
                        "title": n.title,
                        "target_namespace": n.target_namespace,
                        "depth": n.depth,
                        "path": n.path,
                    })
                })
                .collect();
            let paths_json: Vec<&str> = nodes.iter().map(|n| n.path.as_str()).collect();
            Json(json!({
                "source_id": source_id,
                "max_depth": max_depth,
                "memories": memories_json,
                "paths": paths_json,
                "count": nodes.len(),
            }))
            .into_response()
        }
        Err(e) => {
            // The `kg_query` DB layer raises explicit errors for
            // depth=0 and for max_depth past the supported ceiling;
            // those are caller-fixable, not server faults.
            let msg = e.to_string();
            if msg.contains("max_depth") {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({"error": msg})),
                )
                    .into_response();
            }
            tracing::error!("handler error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
                .into_response()
        }
    }
}
