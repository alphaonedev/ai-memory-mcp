// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Admin HTTP handlers — agent registration, quota, stats, gc, export,
//! import, and the parity `tools/list` mirror.
//!
//! Extracted from [`super::http`] under issue #650 follow-up 2. The
//! handler bodies are unchanged; only the module-routing import surface
//! moved. Wire compatibility preserved via `pub use admin::*` in
//! [`super`].

#![allow(clippy::too_many_lines)]

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
#[cfg(feature = "sal")]
use uuid::Uuid;

use crate::db;
#[cfg(feature = "sal")]
use crate::models::{ConfidenceSource, Tier};
use crate::models::{Memory, MemoryLink, RegisterAgentBody};
use crate::validate;

use super::AppState;
use super::MAX_BULK_SIZE;
#[cfg(feature = "sal")]
use super::StorageBackend;
use super::admin_role::require_admin;
#[cfg(feature = "sal")]
use super::store_err_to_response;

pub async fn register_agent(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterAgentBody>,
) -> impl IntoResponse {
    if let Err(e) = validate::validate_agent_id(&body.agent_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }
    if let Err(e) = validate::validate_agent_type(&body.agent_type) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }
    // #869 audit (Category B — safe default): `capabilities` is
    // `Option<Vec<String>>`; an absent field is semantically equivalent
    // to "agent advertises no capabilities yet" which is exactly the
    // empty-vec default. No serialisation involved.
    let capabilities = body.capabilities.unwrap_or_default();
    if let Err(e) = validate::validate_capabilities(&capabilities) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }

    // #911 (security-medium / SOC2, 2026-05-19) — admin action audit.
    // `register_agent` and `archive_purge` are admin-class state-changing
    // surfaces whose forensic-chain entry was previously silent. The
    // caller agent_id is resolved via the X-Agent-Id header (the same
    // primitive `resolve_http_agent_id` other handlers use); when no
    // header is provided we record the synthesized `anonymous:req-…`
    // actor so the chain entry pins the unattested call. Emitted
    // BEFORE any storage write to preserve the audit trail even if
    // the storage layer fails downstream.
    let header_agent_id = headers.get("x-agent-id").and_then(|v| v.to_str().ok());
    let caller = crate::identity::resolve_http_agent_id(None, header_agent_id)
        .unwrap_or_else(|_| "anonymous:invalid".to_string());
    crate::governance::audit::record_decision(
        &caller,
        "allow",
        "register_agent",
        "",
        json!({
            "new_agent_id": body.agent_id,
            "agent_type": body.agent_type,
            "capabilities": capabilities,
        }),
    );

    // v0.7.0 Wave-3 Continuation 3 — postgres-backed daemons route the
    // agent-registration write through `app.store` so the row lands in
    // the same postgres `_agents` namespace that `list_agents` projects
    // from. Pre-fix this handler wrote through `db::register_agent`
    // against the sqlite scratch `app.db`, leaving postgres-backed
    // daemons with POST→sqlite and GET→postgres asymmetry — registered
    // agents never appeared in the list. Mirrors the import_memories +
    // bulk_create dual-backend dispatch pattern. Federation fanout
    // remains sqlite-only (broadcast_store_quorum uses sqlite-coupled
    // fed-tracker state).
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // #910 — admin surface (registration / list_agents / stats);
        // bypass the SAL visibility filter so admin endpoints see the
        // full row set regardless of metadata.scope.
        let ctx = crate::store::CallerContext::for_admin("daemon");
        let now = Utc::now().to_rfc3339();
        let mut metadata = json!({
            "agent_id": &body.agent_id,
            "agent_type": &body.agent_type,
        });
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                "capabilities".to_string(),
                serde_json::to_value(&capabilities).unwrap_or_else(|_| json!([])),
            );
        }
        let agent_mem = Memory {
            id: Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: "_agents".to_string(),
            title: format!("agent:{}", &body.agent_id),
            content: format!("agent registration for {}", &body.agent_id),
            tags: vec!["_agent_registration".to_string()],
            priority: 5,
            confidence: 1.0,
            source: "api".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata,
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
        };
        return match app.store.store(&ctx, &agent_mem).await {
            Ok(id) => (
                StatusCode::CREATED,
                Json(json!({
                    "id": id,
                    "agent_id": body.agent_id,
                    "agent_type": body.agent_type,
                    "capabilities": capabilities,
                    "storage_backend": "postgres",
                })),
            )
                .into_response(),
            Err(e) => store_err_to_response(e),
        };
    }

    let lock = app.db.lock().await;
    let register_result =
        db::register_agent(&lock.0, &body.agent_id, &body.agent_type, &capabilities);
    // Read the persisted `_agents` row back so we can fan it out to peers.
    // The cluster-wide S12 invariant is that an agent registered on node-1
    // is visible on node-4 — which only holds when the `_agents` namespace
    // replicates via `broadcast_store_quorum`.
    let registered_mem = match &register_result {
        Ok(id) => db::get(&lock.0, id).ok().flatten(),
        Err(_) => None,
    };
    drop(lock);

    match register_result {
        Ok(id) => {
            if let (Some(fed), Some(mem)) = (app.federation.as_ref(), registered_mem.as_ref()) {
                match crate::federation::broadcast_store_quorum(fed, mem).await {
                    Ok(tracker) => {
                        if let Err(err) = crate::federation::finalise_quorum(&tracker) {
                            // #869 — typed 503 envelope via the shared helper.
                            let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                            return super::quorum_not_met_response(&payload);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("register_agent fanout error (local committed): {e:?}");
                    }
                }
            }
            (
                StatusCode::CREATED,
                Json(json!({
                    "registered": true,
                    "id": id,
                    "agent_id": body.agent_id,
                    "agent_type": body.agent_type,
                    "capabilities": capabilities,
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

pub async fn list_agents(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // #946 SECURITY-medium (Track A QC sweep, 2026-05-20) — admin-
    // only gate. Pre-fix any caller could enumerate the full NHI
    // population + agent capabilities + registration timestamps.
    // The handler uses `CallerContext::for_admin` below to bypass
    // the SAL visibility filter; that's correct for operators but
    // was unauthenticated. Mirror the #957 admin pattern.
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, "list_agents") {
        return resp;
    }
    // v0.7.0 Wave-3 Continuation — postgres-backed daemons project from
    // the `_agents` namespace via the SAL `list` trait method, mirroring
    // how sqlite's `db::list_agents` reads from the same namespace.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // #910 — admin surface (registration / list_agents / stats);
        // bypass the SAL visibility filter so admin endpoints see the
        // full row set regardless of metadata.scope.
        let ctx = crate::store::CallerContext::for_admin("daemon");
        let filter = crate::store::Filter {
            namespace: Some("_agents".to_string()),
            limit: 1000,
            ..Default::default()
        };
        return match app.store.list(&ctx, &filter).await {
            Ok(memories) => {
                let agents: Vec<serde_json::Value> = memories
                    .iter()
                    .filter_map(|m| {
                        let meta = m.metadata.as_object()?;
                        let agent_id = meta.get("agent_id")?.as_str()?;
                        let agent_type = meta
                            .get("agent_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let capabilities = meta
                            .get("capabilities")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!([]));
                        Some(json!({
                            "agent_id": agent_id,
                            "agent_type": agent_type,
                            "capabilities": capabilities,
                            "registered_at": m.created_at,
                        }))
                    })
                    .collect();
                (
                    StatusCode::OK,
                    Json(json!({"count": agents.len(), "agents": agents})),
                )
                    .into_response()
            }
            Err(e) => store_err_to_response(e),
        };
    }

    let lock = app.db.lock().await;
    match db::list_agents(&lock.0) {
        Ok(agents) => (
            StatusCode::OK,
            Json(json!({"count": agents.len(), "agents": agents})),
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

/// JSON body for `POST /api/v1/quota/status`.
///
/// `agent_id` is required when the caller wants a single-agent
/// snapshot; omitting it returns the full table (operator surface).
/// `namespace` is accepted for forward-compat — quotas today are
/// agent-scoped, but the wire shape leaves room for namespace-scoped
/// caps in a future wave.
#[derive(Debug, Deserialize)]
pub struct QuotaStatusBody {
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
}

/// `POST /api/v1/quota/status` — read the agent's quota row, or the
/// full table when `agent_id` is omitted. Returns the canonical
/// `QuotaStatus` JSON projection.
///
/// Dispatches via `app.store.quota_status(agent_id)` so postgres-backed
/// daemons read from the postgres `agent_quotas` table rather than the
/// scratch sqlite connection.
pub async fn quota_status_handler(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<QuotaStatusBody>,
) -> impl IntoResponse {
    // #909 (security-medium, 2026-05-19) — sibling of #874/#901/#905/#907.
    // The pre-#909 path accepted `body.agent_id` with no authn binding —
    // any caller could probe `POST /api/v1/quota/status {agent_id:"alice"}`
    // and read alice's quota row (cross-tenant disclosure: count of
    // memories stored, last-reset timestamp, namespace usage stats).
    // Authenticate via `X-Agent-Id` header; when `body.agent_id` is
    // supplied it must MATCH the authenticated caller else 403. The
    // operator-facing list path (body.agent_id absent) is preserved.
    let header_agent_id = headers.get("x-agent-id").and_then(|v| v.to_str().ok());
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
    if let Some(agent_id) = body.agent_id.as_deref() {
        if let Err(e) = validate::validate_agent_id(agent_id) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid agent_id: {e}")})),
            )
                .into_response();
        }
        if agent_id != caller {
            return (
                StatusCode::FORBIDDEN,
                Json(
                    json!({"error": "agent_id body parameter does not match authenticated caller"}),
                ),
            )
                .into_response();
        }

        // Postgres-backed daemons MUST take the SAL trait dispatch — the
        // scratch sqlite connection at `app.db` has no `agent_quotas`
        // rows.
        #[cfg(feature = "sal")]
        if matches!(app.storage_backend, StorageBackend::Postgres) {
            return match app.store.quota_status(agent_id).await {
                Ok(status) => Json(json!(status)).into_response(),
                Err(e) => store_err_to_response(e),
            };
        }

        let lock = app.db.lock().await;
        return match crate::quotas::get_status(&lock.0, agent_id) {
            Ok(status) => Json(json!(status)).into_response(),
            Err(e) => {
                tracing::error!("quota_status handler error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "internal server error"})),
                )
                    .into_response()
            }
        };
    }

    // No agent_id supplied — operator-facing list path.
    //
    // #960 SECURITY-medium (Track A QC sweep, 2026-05-20) — admin-
    // only gate on the list path. Pre-fix any HTTP caller posting
    // `{}` could enumerate the full per-agent quota table. Sibling
    // of #909 (per-agent path) — same disclosure shape.
    if let Err(resp) =
        crate::handlers::admin_role::require_admin(&app, &headers, "quota_status_list")
    {
        return resp;
    }
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return match app.store.quota_status_list().await {
            Ok(rows) => Json(json!({"quotas": rows, "count": rows.len()})).into_response(),
            Err(e) => store_err_to_response(e),
        };
    }

    let lock = app.db.lock().await;
    match crate::quotas::list_status(&lock.0) {
        Ok(rows) => {
            let count = rows.len();
            Json(json!({"quotas": rows, "count": count})).into_response()
        }
        Err(e) => {
            tracing::error!("quota_status list handler error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
                .into_response()
        }
    }
}

pub async fn get_stats(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // #946 SECURITY-medium (Track A QC sweep, 2026-05-20) — admin-only
    // gate. Pre-fix any caller could enumerate full per-tier counts +
    // per-namespace stats + WAL counters; admin-class endpoint.
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, "get_stats") {
        return resp;
    }
    // v0.7.0 Wave-3 Continuation — postgres-backed daemons project a
    // basic count from the SAL `list` method. Detailed per-tier
    // breakdown + DB file size + WAL counters are sqlite-only fields
    // and surface as `null` on postgres so clients see a consistent
    // top-level shape.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // #910 — admin surface (registration / list_agents / stats);
        // bypass the SAL visibility filter so admin endpoints see the
        // full row set regardless of metadata.scope.
        let ctx = crate::store::CallerContext::for_admin("daemon");
        let filter = crate::store::Filter {
            limit: 1_000_000,
            ..Default::default()
        };
        return match app.store.list(&ctx, &filter).await {
            Ok(memories) => {
                let total = memories.len();
                let mut short = 0usize;
                let mut mid = 0usize;
                let mut long = 0usize;
                let mut by_namespace: std::collections::BTreeMap<String, usize> =
                    std::collections::BTreeMap::new();
                for m in &memories {
                    match m.tier {
                        Tier::Short => short += 1,
                        Tier::Mid => mid += 1,
                        Tier::Long => long += 1,
                    }
                    *by_namespace.entry(m.namespace.clone()).or_insert(0) += 1;
                }
                Json(json!({
                    "total_memories": total,
                    "by_tier": {
                        "short": short,
                        "mid": mid,
                        "long": long,
                    },
                    "by_namespace": by_namespace,
                    "storage_backend": "postgres",
                }))
                .into_response()
            }
            Err(e) => store_err_to_response(e),
        };
    }

    let lock = app.db.lock().await;
    match db::stats(&lock.0, &lock.1) {
        Ok(s) => Json(json!(s)).into_response(),
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

pub async fn run_gc(State(app): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    // #1027 (security-critical, 2026-05-21) — admin-role gate. GC
    // permanently sweeps expired rows; pre-#1027 the handler logged
    // the caller to the forensic chain but accepted ANY API-key
    // holder (no admin allowlist membership required). An attacker
    // with the shared API key could force-purge mid-tier-expired
    // rows across tenants in advance of any restore window. The
    // require_admin gate now matches the shape of export_memories
    // (#957) / forget_memories (#956): non-admin callers get a 403
    // FORBIDDEN before any state change.
    let caller = match require_admin(&app, &headers, "run_gc") {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // #913 (security-medium / SOC2, 2026-05-19) — admin/destructive
    // state-change audit. GC permanently sweeps expired rows; the
    // forensic-chain entry MUST land before the storage write so the
    // audit trail captures the operator who triggered the sweep even
    // when the downstream collector errors.
    crate::governance::audit::record_decision(&caller, "allow", "run_gc", "", json!({}));

    // v0.7.0 Wave-3 Continuation 3 (Phase 17) — postgres-backed daemons
    // route through the SAL trait. Returns the same `{expired_deleted}`
    // envelope so wire shape is backend-blind.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let archive_flag = {
            let lock = app.db.lock().await;
            lock.3
        };
        return match app.store.run_gc(archive_flag).await {
            Ok(n) => {
                Json(json!({"expired_deleted": n, "storage_backend": "postgres"})).into_response()
            }
            Err(e) => store_err_to_response(e),
        };
    }

    let lock = app.db.lock().await;
    match db::gc(&lock.0, lock.3) {
        Ok(n) => Json(json!({"expired_deleted": n})).into_response(),
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

pub async fn export_memories(State(app): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    // #957 (security-critical, 2026-05-20) — admin-role gate.
    // Pre-#957 the handler took NO headers, accepted no caller, and
    // dispatched directly to the export path which intentionally
    // bypasses every visibility filter (postgres SAL branch uses
    // `for_agent("export")` — see `src/store/postgres.rs:8577` — and
    // the sqlite branch reads the whole `memories` table via
    // `db::export_all`). The legacy `api_key_auth` middleware passes
    // through when `api_key` is unset (the default — see #946 RCA),
    // so the endpoint was open by default and any authenticated
    // caller could dump every memory across every owner, every
    // namespace, every scope (including `scope=private`) plus every
    // link in the graph.
    //
    // Fix: require the caller's resolved `agent_id` (from
    // `X-Agent-Id`, the same primitive every other handler uses)
    // to appear in the operator-configured `[admin].agent_ids`
    // allowlist before the corpus dump fires. Non-admin callers
    // get `403 Forbidden` with the sanitised
    // `{"error":"admin role required"}` body — intentionally
    // generic so the rejection does not leak the allowlist
    // configuration. The role decision is forensic-chain audited
    // via `governance::audit::record_decision` whether admitted
    // or rejected (`handlers::admin_role::require_admin`).
    let caller = match crate::handlers::admin_role::require_admin(&app, &headers, "export_memories")
    {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // v0.7.0 Wave-3 Continuation 3 (Phase 18) — postgres-backed daemons
    // route through the SAL trait. Wire shape preserved:
    // `{memories, links, count, exported_at}`. The admin gate above
    // is the load-bearing authorisation check; the SAL-level
    // `for_admin(caller)` context just preserves the full-fidelity
    // backup semantic (admin export round-trips every row regardless
    // of `metadata.scope`).
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let _ = &caller; // resolved + audited above; SAL methods are
        // owner-blind under the operator export contract.
        let mems = match app.store.export_memories().await {
            Ok(v) => v,
            Err(e) => return store_err_to_response(e),
        };
        let links = match app.store.export_links().await {
            Ok(v) => v,
            Err(e) => return store_err_to_response(e),
        };
        let count = mems.len();
        return Json(json!({
            "memories": mems,
            "links": links,
            "count": count,
            "exported_at": Utc::now().to_rfc3339(),
            "storage_backend": "postgres",
        }))
        .into_response();
    }

    let _ = &caller;
    let lock = app.db.lock().await;
    match (db::export_all(&lock.0), db::export_links(&lock.0)) {
        (Ok(memories), Ok(links)) => {
            let count = memories.len();
            Json(json!({"memories": memories, "links": links, "count": count, "exported_at": Utc::now().to_rfc3339()})).into_response()
        }
        (Err(e), _) | (_, Err(e)) => {
            tracing::error!("export error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
                .into_response()
        }
    }
}

pub async fn import_memories(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ImportBody>,
) -> impl IntoResponse {
    if body.memories.len() > MAX_BULK_SIZE {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("import limited to {} memories", MAX_BULK_SIZE)})),
        )
            .into_response();
    }

    // #956 (security-medium, 2026-05-20) — admin-role gate + provenance
    // restamp on `/api/v1/import`. Pre-#956 the handler resolved the
    // caller from `X-Agent-Id` but then took `mem.metadata.agent_id`
    // verbatim from the request body. Any authenticated caller could
    // submit `{"memories":[{"metadata":{"agent_id":"alice", ...}}]}`
    // and stamp alice's name on the imported row — same forge primitive
    // #874/#901/#905/#907/#909 closed across other surfaces. Mirrors
    // #957 (export) and the CLI `--trust-source`-off branch at
    // `src/cli/io.rs:97-118`.
    //
    // 1. Gate via `handlers::admin_role::require_admin` — sanitised
    //    `403 {"error":"admin role required"}` on non-admin callers,
    //    audited via `governance::audit::record_decision` whether
    //    admitted or rejected. Empty allowlist (v0.7.0 default) closes
    //    the endpoint to every caller (safe-by-default).
    //
    // 2. For each admitted row, restamp `metadata.agent_id` to the
    //    admin caller and preserve the body's original claim under
    //    `metadata.imported_from_agent_id` (only when the original
    //    differs from the caller — no provenance noise on identical
    //    writes). Mirrors the CLI restamp contract exactly.
    let caller = match crate::handlers::admin_role::require_admin(&app, &headers, "import_memories")
    {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // #913 (security-medium / SOC2, 2026-05-19) — admin/bulk-write audit.
    // Import landings can move thousands of memories in one call; emit a
    // single forensic-chain entry BEFORE the storage writes so the audit
    // trail captures the batch size + caller identity even on partial
    // success.
    crate::governance::audit::record_decision(
        &caller,
        "allow",
        "import_memories",
        "",
        json!({
            "memory_count": body.memories.len(),
            "link_count": body.links.as_ref().map(Vec::len).unwrap_or(0),
        }),
    );

    // #956 provenance restamp closure. Applied per-row on both
    // backends BEFORE validate / governance / store so all downstream
    // consumers (governance enforce, store.store / db::insert) see
    // the admin caller as the row's principal.
    let restamp_agent_id = |mem: &mut Memory| {
        if !mem.metadata.is_object() {
            mem.metadata = json!({});
        }
        if let Some(obj) = mem.metadata.as_object_mut() {
            let original = obj
                .get("agent_id")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string);
            obj.insert(
                "agent_id".to_string(),
                serde_json::Value::String(caller.clone()),
            );
            if let Some(orig) = original
                && orig != caller
            {
                obj.insert(
                    "imported_from_agent_id".to_string(),
                    serde_json::Value::String(orig),
                );
            }
        }
    };
    // v0.7.0 Wave-3 Continuation 3 (Phase 18) — postgres-backed daemons
    // route through the SAL trait. We re-use `app.store.store(...)` per
    // memory (the upsert path that preserves agent_id immutability) and
    // `app.store.link(...)` for each link; partial-success surfaces the
    // same `{imported, errors}` envelope as the sqlite path.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // QC P1 fix (2026-05-20): import_memories now stamps the
        // imported rows under the authenticated `caller` (resolved
        // from X-Agent-Id, line 564) instead of a synthetic
        // "http-import" principal. The SAL store path still applies
        // its `metadata.agent_id` preservation contract — body-
        // supplied agent_id wins when valid (e.g., legitimate
        // re-import of memories already authored by another agent),
        // but the ctx is the auth principal so visibility filters
        // applied INSIDE store_inner (e.g., upsert dedup lookup)
        // see the actual caller.
        let ctx = crate::store::CallerContext::for_agent(caller.clone());
        let mut imported = 0usize;
        let mut errors: Vec<String> = Vec::new();
        let mut pending: Vec<serde_json::Value> = Vec::new();
        for mut mem in body.memories {
            // #956 — restamp before validate / governance / store.
            restamp_agent_id(&mut mem);
            if let Err(e) = validate::RequestValidator::validate_memory(&mem) {
                // Issue #851: never echo the raw `e` to the wire paired
                // with the user-supplied id (the combo reflects the
                // caller's request). Sanitize + log instead.
                tracing::warn!(
                    "import_memories(postgres): validate_memory failed for {}: {e}",
                    mem.id
                );
                errors.push(super::sanitize_bulk_row_error(&e.to_string()).to_string());
                continue;
            }

            // F-A2A1.5 (#705) — governance enforcement on the postgres
            // import path. Mirrors the F-A2A1.2 delete/promote gates and
            // the Wave-3 Continuation 3 create_memory gate: each imported
            // row is a Store action and must be gated by the destination
            // namespace's standard. Deny rows accumulate into `errors`
            // alongside other per-row failures; Pending rows accumulate
            // into `pending` with their pending_id so the caller can
            // drive consensus. Without this gate, postgres-backed
            // daemons silently bypassed namespace governance on the
            // bulk-import surface (same A2A bypass cluster fold-A2A1.2
            // closed on delete/promote/create paths).
            use crate::models::GovernanceDecision;
            // Post-#956 restamp, agent_id is always the admin caller.
            let agent_id = mem
                .metadata
                .get("agent_id")
                .and_then(|v| v.as_str())
                .unwrap_or(caller.as_str());
            let payload_for_pending = serde_json::to_value(&mem).unwrap_or_else(|_| json!({}));
            match app
                .store
                .enforce_governance_action(
                    crate::store::GovernedAction::Store,
                    &mem.namespace,
                    agent_id,
                    None,
                    None,
                    &payload_for_pending,
                )
                .await
            {
                Ok(GovernanceDecision::Allow) => {}
                Ok(GovernanceDecision::Deny(refusal)) => {
                    let mut msg =
                        String::with_capacity(mem.id.len() + 2 + 50 + refusal.reason.len());
                    msg.push_str(&mem.id);
                    msg.push_str(": ");
                    msg.push_str(&crate::governance::deny_message(
                        "import",
                        crate::governance::DenyGate::Governance,
                        &refusal.reason,
                    ));
                    errors.push(msg);
                    continue;
                }
                Ok(GovernanceDecision::Pending(pending_id)) => {
                    pending.push(json!({
                        "id": mem.id,
                        "namespace": mem.namespace,
                        "pending_id": pending_id,
                    }));
                    continue;
                }
                Err(e) => {
                    errors.push(format!("{}: governance error: {e}", mem.id));
                    continue;
                }
            }

            match app.store.store(&ctx, &mem).await {
                Ok(_) => imported += 1,
                Err(e) => {
                    // Issue #851: SAL `store.store` errors can carry raw
                    // sqlx/sqlite text — sanitize before echoing.
                    tracing::warn!(
                        "import_memories(postgres): store.store failed for {}: {e}",
                        mem.id
                    );
                    errors.push(super::sanitize_bulk_row_error(&e.to_string()).to_string());
                }
            }
        }
        // #869 audit (Category B — safe default): `body.links` is
        // `Option<Vec<MemoryLink>>`; an absent field means the bulk
        // import payload carried no links. Empty-vec default produces
        // a zero-iteration loop, which is the documented behaviour.
        for link in body.links.unwrap_or_default() {
            if validate::RequestValidator::validate_link_triple(
                &link.source_id,
                &link.target_id,
                link.relation.as_str(),
            )
            .is_err()
            {
                continue;
            }
            let _ = app.store.link(&ctx, &link).await;
        }
        return Json(json!({
            "imported": imported,
            "errors": errors,
            "pending": pending,
            "storage_backend": "postgres",
        }))
        .into_response();
    }

    let lock = app.db.lock().await;
    let mut imported = 0usize;
    let mut errors = Vec::new();
    for mut mem in body.memories {
        // #956 — restamp before validate / insert.
        restamp_agent_id(&mut mem);
        if let Err(e) = validate::RequestValidator::validate_memory(&mem) {
            // Issue #851: never echo `<id>: <validate error>` paired —
            // the combo reflects the caller's request and the inner
            // string can carry validate template detail. Sanitize + log.
            tracing::warn!(
                "import_memories: validate_memory failed for {}: {e}",
                mem.id
            );
            errors.push(super::sanitize_bulk_row_error(&e.to_string()).to_string());
            continue;
        }
        match db::insert(&lock.0, &mem) {
            Ok(_) => imported += 1,
            Err(e) => {
                // Issue #851: db::insert errors include raw rusqlite
                // text (SQL fragments, constraint names). Sanitize.
                tracing::warn!("import_memories: db::insert failed for {}: {e}", mem.id);
                errors.push(super::sanitize_bulk_row_error(&e.to_string()).to_string());
            }
        }
    }
    // #869 audit (Category B — safe default): sqlite branch mirror of
    // the postgres-branch links loop above; same empty-vec semantics.
    for link in body.links.unwrap_or_default() {
        if validate::RequestValidator::validate_link_triple(
            &link.source_id,
            &link.target_id,
            link.relation.as_str(),
        )
        .is_err()
        {
            continue;
        }
        let _ = db::create_link(
            &lock.0,
            &link.source_id,
            &link.target_id,
            link.relation.as_str(),
        );
    }
    Json(json!({"imported": imported, "errors": errors})).into_response()
}

#[derive(serde::Deserialize)]
pub struct ImportBody {
    pub memories: Vec<Memory>,
    #[serde(default)]
    pub links: Option<Vec<MemoryLink>>,
}

/// `GET /api/v1/tools/list` — enumerate the MCP tools currently
/// advertised under the daemon's resolved [`Profile`]. The response
/// shape mirrors MCP `tools/list`: `{tools: [{name, description, ...}],
/// schema_version: <tag>}`. Backend-agnostic — works on both sqlite
/// and postgres daemons because the data is configuration, not user
/// content.
pub async fn tools_list(State(app): State<AppState>) -> impl IntoResponse {
    // `tool_definitions_for_profile` already applies the C2 / C4
    // trims that match the MCP `tools/list` shape. No further shaping
    // is needed for the HTTP wire — the field names line up with the
    // MCP JSON-RPC payload exactly.
    let defs = crate::mcp::tool_definitions_for_profile(app.profile.as_ref());
    (StatusCode::OK, Json(defs)).into_response()
}
