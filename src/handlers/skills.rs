// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! HTTP handlers for the v0.7.0 skills surface (#650 follow-up
//! per-domain split). Each handler is a thin Axum-layer wrapper that
//! transforms request data into the canonical JSON params the
//! underlying MCP `handle_skill_*` substrate functions expect, then
//! shapes their `Result<Value, String>` into the appropriate HTTP
//! status code.
//!
//! All handlers were extracted verbatim from `src/handlers/http.rs`
//! (commit 88d9a96, lines 7591-7782); wire compatibility is preserved
//! via the `pub use skills::*` re-export from `src/handlers/mod.rs`.
//!
//! # v0.7.0 #949 (Track A QC sweep, 2026-05-20) — admin-role gate on
//! every skill route
//!
//! Pre-#949 none of the 7 routes accepted a `HeaderMap`, resolved the
//! caller, or applied any cross-tenant gate. Skills are executable
//! artefacts (SKILL.md + resources + signing surface) — the supply-
//! chain attack surface is broader than a memory row:
//!
//! - register / promote / compose: WRITE surfaces that mint or
//!   re-mint executable capabilities. Cross-tenant write = forged
//!   provenance on a skill that other agents will subsequently
//!   activate.
//! - export: WRITES to the daemon-host filesystem (target_folder
//!   resolved on the daemon, written under the daemon user). Cross-
//!   tenant export = arbitrary-path write surface from any caller.
//! - list / get / resource: READ surfaces that exfiltrate skill
//!   bodies, manifests, and resource blobs (potentially tagged with
//!   another tenant's `signing_agent`).
//!
//! Posture: **admin-only across all 7 routes** via
//! [`crate::handlers::admin_role::require_admin`]. This is the same
//! shape #957 (`export_memories`) and #946 (`list_agents`) use for
//! their corpus-scale admin surfaces. Skills don't carry a Memory-
//! shaped `metadata.scope` / `metadata.agent_id` in the canonical
//! `Memory` struct the `crate::visibility::is_visible_to_caller`
//! helper operates on — the skill `signing_agent` column is only
//! populated when the daemon boots with a keypair (the default install
//! has none). A per-owner gate based on `signing_agent` would be open
//! by default; the admin gate is closed by default. Per the v0.7.0
//! safe-by-default posture, every skill HTTP surface MUST be admin-
//! only until a future cluster lands a richer skill-ACL model.

use crate::models::field_names;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;

use super::AppState;

/// Tracing target for the skills HTTP handlers (#1558 tracing-target SSOT).
const SKILLS_TRACE_TARGET: &str = "ai_memory::handlers::skills";

/// #3183 — fail-closed guard for the **SQLite-only** skills plane.
///
/// Every handler below reaches the skills substrate through
/// `crate::mcp::handle_skill_*`, which is typed on a
/// `rusqlite::Connection`, so each one takes `app.db.lock()`. On a
/// postgres-backed daemon `app.db` is NOT the operator's database — it is
/// the node-local scratch SQLite file `bootstrap_serve` opens against
/// `--db`: empty, invisible to every peer, and discarded when the
/// container restarts (`src/store/postgres.rs` `migrate_v82`: "postgres
/// ships no skills table"). Persisting an executable artefact there while
/// the daemon advertises a skills plane is a split-brain + claims-truth
/// defect, so the handlers REFUSE instead of writing to the wrong
/// database (North Star: degrade, never corrupt — the worst case on
/// postgres is a loud 501, never a silent local write).
///
/// Returns `Some(501)` carrying the documented postgres envelope from
/// [`crate::handlers::postgres_not_implemented`] — byte-identical in shape
/// to every other un-migrated surface — when the daemon is
/// postgres-backed, and `None` on sqlite.
///
/// This is the defence-in-depth twin of the router-layer gate, not a
/// replacement for it: the 8 `/api/v1/skill/*` paths are absent from
/// [`crate::handlers::postgres_endpoint_supported`], so
/// `postgres_route_gate` already 501s them on the wire, and that
/// partition is frozen by `tests/pg_supported_route_inventory_gate_2799.rs`
/// (`expected_fully_501_paths`). Duplicating the refusal at the handler
/// means a future middleware reorder, a direct in-process call, or a
/// custom router assembled without the gate can never re-open the
/// silent-local-write path. The postgres port is tracked by #2804.
#[cfg(feature = "sal")]
fn refuse_skills_on_postgres(
    app: &AppState,
    endpoint: &'static str,
) -> Option<axum::response::Response> {
    if matches!(app.storage_backend, super::StorageBackend::Postgres) {
        return Some(crate::handlers::postgres_not_implemented(endpoint));
    }
    None
}

/// Non-`sal` builds compile no postgres adapter at all, so
/// `AppState::storage_backend` is structurally
/// [`super::StorageBackend::Sqlite`] and `app.db` IS the operator's
/// database. The guard is a compile-time no-op there (the `sal`-gated
/// [`crate::handlers::postgres_not_implemented`] helper does not exist in
/// this build).
#[cfg(not(feature = "sal"))]
fn refuse_skills_on_postgres(
    _app: &AppState,
    _endpoint: &'static str,
) -> Option<axum::response::Response> {
    None
}

/// `POST /api/v1/skill` — register a new skill from an inline body.
pub async fn skill_register_route(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // #3183 — the skills substrate is sqlite-only; on a postgres-backed
    // daemon `app.db` below is the node-local scratch file, not the
    // operator's store. Refuse BEFORE the admin gate, mirroring the
    // ordering `postgres_route_gate` already enforces on the wire.
    if let Some(resp) = refuse_skills_on_postgres(&app, super::routes::SKILL_REGISTER) {
        return resp;
    }
    // #949 — admin-only. Skill registration mints an executable
    // artefact; non-admin callers MUST NOT be able to plant a row
    // other agents will subsequently activate.
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, "skill_register")
    {
        return resp;
    }
    let lock = app.db.lock().await;
    let kp = (*app.active_keypair).as_ref();
    match crate::mcp::handle_skill_register(&lock.0, &body, kp) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

/// `GET /api/v1/skill/list?namespace=<ns>&filter=<text>`.
///
/// Query params mirror the MCP `namespace` and `filter` keys.
#[derive(Deserialize)]
pub struct SkillListQuery {
    pub namespace: Option<String>,
    pub filter: Option<String>,
    /// #2024 — include RETIRED skills in the listing (default hides them).
    pub include_retired: Option<bool>,
}

pub async fn skill_list_route(
    State(app): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SkillListQuery>,
) -> impl IntoResponse {
    // #3183 — the skills substrate is sqlite-only; on a postgres-backed
    // daemon `app.db` below is the node-local scratch file, not the
    // operator's store. Refuse BEFORE the admin gate, mirroring the
    // ordering `postgres_route_gate` already enforces on the wire.
    if let Some(resp) = refuse_skills_on_postgres(&app, super::routes::SKILL_LIST) {
        return resp;
    }
    // #949 — admin-only. The list payload enumerates every skill in
    // the requested namespace including bodies that may be tagged
    // with another tenant's `signing_agent`. Cross-tenant
    // enumeration of executable artefacts is a supply-chain probe
    // vector.
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, "skill_list") {
        return resp;
    }
    let mut params = json!({});
    if let Some(ns) = q.namespace {
        params["namespace"] = json!(ns);
    }
    if let Some(f) = q.filter {
        params["filter"] = json!(f);
    }
    if let Some(ir) = q.include_retired {
        params[field_names::INCLUDE_RETIRED] = json!(ir);
    }
    let lock = app.db.lock().await;
    match crate::mcp::handle_skill_list(&lock.0, &params) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            // #1261 — never forward the raw substrate error (often a
            // `rusqlite::Error` string carrying SQL fragments) on the
            // HTTP wire. Log the raw text for operators, surface a
            // generic "internal server error" to the caller.
            tracing::error!(
                target: SKILLS_TRACE_TARGET,
                error = %e,
                "skill_list_route: substrate error (sanitized for wire response, #1261)"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": crate::errors::msg::INTERNAL_SERVER_ERROR})),
            )
                .into_response()
        }
    }
}

/// `GET /api/v1/skill/{id}` — full activation payload (body included).
pub async fn skill_get_route(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // #3183 — the skills substrate is sqlite-only; on a postgres-backed
    // daemon `app.db` below is the node-local scratch file, not the
    // operator's store. Refuse BEFORE the admin gate, mirroring the
    // ordering `postgres_route_gate` already enforces on the wire.
    if let Some(resp) = refuse_skills_on_postgres(&app, super::routes::SKILL_ID) {
        return resp;
    }
    // #949 — admin-only. The GET response includes the full
    // (decompressed) skill body — the executable capability bundle.
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, "skill_get") {
        return resp;
    }
    let params = json!({"skill_id": id});
    let lock = app.db.lock().await;
    match crate::mcp::handle_skill_get(&lock.0, &params) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            // Substrate uses a "skill not found:" prefix for the missing
            // case; surface that as 404. Everything else is 500.
            if e.starts_with(crate::errors::msg::SKILL_NOT_FOUND) {
                (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response()
            } else {
                // #1261 — never forward the raw substrate error (often
                // a `rusqlite::Error` string carrying SQL fragments) on
                // the HTTP wire. Log the raw text; emit a generic
                // "internal server error" to the caller.
                tracing::error!(
                    target: SKILLS_TRACE_TARGET,
                    error = %e,
                    "skill_get_route: substrate error (sanitized for wire response, #1261)"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": crate::errors::msg::INTERNAL_SERVER_ERROR})),
                )
                    .into_response()
            }
        }
    }
}

/// `GET /api/v1/skill/{id}/resource?path=<resource_path>`.
#[derive(Deserialize)]
pub struct SkillResourceQuery {
    pub path: String,
}

pub async fn skill_resource_route(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<SkillResourceQuery>,
) -> impl IntoResponse {
    // #3183 — the skills substrate is sqlite-only; on a postgres-backed
    // daemon `app.db` below is the node-local scratch file, not the
    // operator's store. Refuse BEFORE the admin gate, mirroring the
    // ordering `postgres_route_gate` already enforces on the wire.
    if let Some(resp) = refuse_skills_on_postgres(&app, super::routes::SKILL_ID_RESOURCE) {
        return resp;
    }
    // #949 — admin-only. Skill resource blobs are part of the
    // executable bundle (scripts, prompts, fixtures) and inherit
    // the same supply-chain threat surface as the skill body.
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, "skill_resource")
    {
        return resp;
    }
    let params = json!({
        "skill_id": id,
        (field_names::RESOURCE_PATH): q.path,
    });
    let lock = app.db.lock().await;
    match crate::mcp::handle_skill_resource(&lock.0, &params) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            if e.starts_with("resource not found") {
                (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response()
            } else {
                (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response()
            }
        }
    }
}

/// `POST /api/v1/skill/{id}/export`.
///
/// Body: `{ "target_folder": "<path>" }`. The path is resolved on the
/// daemon host, so the operator must ensure it's writable by the
/// daemon user.
#[derive(Deserialize)]
pub struct SkillExportBody {
    pub target_folder: String,
}

pub async fn skill_export_route(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<SkillExportBody>,
) -> impl IntoResponse {
    // #3183 — the skills substrate is sqlite-only; on a postgres-backed
    // daemon `app.db` below is the node-local scratch file, not the
    // operator's store. Refuse BEFORE the admin gate, mirroring the
    // ordering `postgres_route_gate` already enforces on the wire.
    if let Some(resp) = refuse_skills_on_postgres(&app, super::routes::SKILL_ID_EXPORT) {
        return resp;
    }
    // #949 — admin-only. Export writes `target_folder` on the daemon
    // host (resolved by the daemon, written under the daemon user);
    // any non-admin caller would gain an arbitrary-path write
    // primitive on the host filesystem. Same admin-class shape as
    // #957 (`export_memories`).
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, "skill_export") {
        return resp;
    }
    let params = json!({
        "skill_id": id,
        (field_names::TARGET_FOLDER): body.target_folder,
    });
    let lock = app.db.lock().await;
    let kp = (*app.active_keypair).as_ref();
    // #3357 — `lock.1` is the resolved store path; it anchors the default
    // export jail root (`<db parent>/skills-export`).
    match crate::mcp::handle_skill_export(&lock.0, &lock.1, &params, kp) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            if e.starts_with(crate::errors::msg::SKILL_NOT_FOUND) {
                (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response()
            } else {
                (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response()
            }
        }
    }
}

/// `POST /api/v1/skill/{id}/promote`.
///
/// Path `{id}` is the source **reflection** id (not a skill id — the
/// promote verb consumes a reflection and produces a skill). Body
/// carries the new skill's `name`, `description`, and optional
/// `parameters_schema`.
#[derive(Deserialize)]
pub struct SkillPromoteBody {
    pub name: String,
    pub description: String,
    pub parameters_schema: Option<serde_json::Value>,
}

pub async fn skill_promote_route(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<SkillPromoteBody>,
) -> impl IntoResponse {
    // #3183 — the skills substrate is sqlite-only; on a postgres-backed
    // daemon `app.db` below is the node-local scratch file, not the
    // operator's store. Refuse BEFORE the admin gate, mirroring the
    // ordering `postgres_route_gate` already enforces on the wire.
    if let Some(resp) = refuse_skills_on_postgres(&app, super::routes::SKILL_ID_PROMOTE) {
        return resp;
    }
    // #949 — admin-only. Promote consumes a reflection memory and
    // mints a new skill row carrying the promoting agent's signing
    // surface. Cross-tenant promote = laundering an executable
    // capability through someone else's reflection.
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, "skill_promote") {
        return resp;
    }
    let mut params = json!({
        (field_names::REFLECTION_ID): id,
        (field_names::SKILL_NAME): body.name,
        (field_names::SKILL_DESCRIPTION): body.description,
    });
    if let Some(ps) = body.parameters_schema {
        params[field_names::PARAMETERS_SCHEMA] = ps;
    }
    let lock = app.db.lock().await;
    let kp = (*app.active_keypair).as_ref();
    match crate::mcp::handle_skill_promote_from_reflection(&lock.0, &params, kp) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            if e.contains("not found") {
                (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response()
            } else {
                (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response()
            }
        }
    }
}

/// `POST /api/v1/skill/{id}/compose`.
///
/// Body: `{ "budget_tokens": <N?> }`. Returns the skill body plus the
/// reflections declared in its `composes_with_reflections` frontmatter.
#[derive(Deserialize, Default)]
pub struct SkillComposeBody {
    pub budget_tokens: Option<u64>,
}

pub async fn skill_compose_route(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<SkillComposeBody>>,
) -> impl IntoResponse {
    // #3183 — the skills substrate is sqlite-only; on a postgres-backed
    // daemon `app.db` below is the node-local scratch file, not the
    // operator's store. Refuse BEFORE the admin gate, mirroring the
    // ordering `postgres_route_gate` already enforces on the wire.
    if let Some(resp) = refuse_skills_on_postgres(&app, super::routes::SKILL_ID_COMPOSE) {
        return resp;
    }
    // #949 — admin-only. Compose reads the skill body PLUS the
    // reflections declared in `composes_with_reflections` — a
    // multi-row read across the caller and other agents' reflection
    // memories. Cross-tenant compose = exfiltrate the skill author's
    // private reflection chain bundled with the executable body.
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, "skill_compose") {
        return resp;
    }
    let Json(body) = body.unwrap_or(Json(SkillComposeBody::default()));
    let mut params = json!({"skill_id": id});
    if let Some(b) = body.budget_tokens {
        params[field_names::BUDGET_TOKENS] = json!(b);
    }
    let lock = app.db.lock().await;
    match crate::mcp::handle_skill_compositional_context(&lock.0, &params) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            if e.starts_with(crate::errors::msg::SKILL_NOT_FOUND) {
                (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response()
            } else {
                // #1261 — never forward the raw substrate error on
                // the HTTP wire. Log the raw text; emit a generic
                // "internal server error" to the caller.
                tracing::error!(
                    target: SKILLS_TRACE_TARGET,
                    error = %e,
                    "skill_compose_route: substrate error (sanitized for wire response, #1261)"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": crate::errors::msg::INTERNAL_SERVER_ERROR})),
                )
                    .into_response()
            }
        }
    }
}

/// `POST /api/v1/skill/{id}/retire` — #2024 operator-authorized skill
/// retire/unretire. Path `{id}` names the target skill_id; body carries
/// `{ unretire?, reason?, namespace?, name? }`.
#[derive(Deserialize, Default)]
pub struct SkillRetireBody {
    #[serde(default)]
    pub unretire: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

pub async fn skill_retire_route(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<SkillRetireBody>>,
) -> impl IntoResponse {
    // #3183 — the skills substrate is sqlite-only; on a postgres-backed
    // daemon `app.db` below is the node-local scratch file, not the
    // operator's store. Refuse BEFORE the admin gate, mirroring the
    // ordering `postgres_route_gate` already enforces on the wire.
    if let Some(resp) = refuse_skills_on_postgres(&app, super::routes::SKILL_ID_RETIRE) {
        return resp;
    }
    // #2024 — admin-only, like every other skill HTTP surface (#949).
    // Retire toggles the discovery + re-register lifecycle of an
    // executable artefact; cross-tenant retire is a supply-chain lever.
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, "skill_retire") {
        return resp;
    }
    let Json(body) = body.unwrap_or(Json(SkillRetireBody::default()));
    let mut params = json!({
        "skill_id": id,
        "unretire": body.unretire,
    });
    if let Some(r) = body.reason {
        params["reason"] = json!(r);
    }
    if let Some(ns) = body.namespace {
        params["namespace"] = json!(ns);
    }
    if let Some(nm) = body.name {
        params["name"] = json!(nm);
    }
    let lock = app.db.lock().await;
    let kp = (*app.active_keypair).as_ref();
    match crate::mcp::handle_skill_retire(&lock.0, &params, kp) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            if e.starts_with(crate::errors::msg::SKILL_NOT_FOUND) {
                (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response()
            } else {
                (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response()
            }
        }
    }
}

/// `DELETE /api/v1/skill/{id}` — #2024 operator-authorized HARD PURGE of
/// the whole lineage the `{id}` skill belongs to. Body carries
/// `{ force? }` (retire-first gate bypass). Irreversible.
#[derive(Deserialize, Default)]
pub struct SkillDeleteBody {
    #[serde(default)]
    pub force: bool,
}

pub async fn skill_delete_route(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<SkillDeleteBody>>,
) -> impl IntoResponse {
    // #3183 — the skills substrate is sqlite-only; on a postgres-backed
    // daemon `app.db` below is the node-local scratch file, not the
    // operator's store. Refuse BEFORE the admin gate, mirroring the
    // ordering `postgres_route_gate` already enforces on the wire.
    if let Some(resp) = refuse_skills_on_postgres(&app, super::routes::SKILL_ID) {
        return resp;
    }
    // #2024 — admin-only (#949). Purge is irreversible; the substrate's
    // retire-first safety gate (or explicit force) still applies underneath.
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, "skill_delete") {
        return resp;
    }
    let Json(body) = body.unwrap_or(Json(SkillDeleteBody::default()));
    let params = json!({ "skill_id": id, "force": body.force });
    let lock = app.db.lock().await;
    let kp = (*app.active_keypair).as_ref();
    match crate::mcp::handle_skill_delete(&lock.0, &params, kp) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            if e.starts_with(crate::errors::msg::SKILL_NOT_FOUND) {
                (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response()
            } else {
                (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response()
            }
        }
    }
}
