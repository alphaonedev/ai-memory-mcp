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

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;

use super::AppState;

/// `POST /api/v1/skill` — register a new skill from an inline body.
pub async fn skill_register_route(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
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
}

pub async fn skill_list_route(
    State(app): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SkillListQuery>,
) -> impl IntoResponse {
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
    let lock = app.db.lock().await;
    match crate::mcp::handle_skill_list(&lock.0, &params) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            // #1261 — never forward the raw substrate error (often a
            // `rusqlite::Error` string carrying SQL fragments) on the
            // HTTP wire. Log the raw text for operators, surface a
            // generic "internal server error" to the caller.
            tracing::error!(
                target: "ai_memory::handlers::skills",
                error = %e,
                "skill_list_route: substrate error (sanitized for wire response, #1261)"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
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
            if e.starts_with("skill not found") {
                (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response()
            } else {
                // #1261 — never forward the raw substrate error (often
                // a `rusqlite::Error` string carrying SQL fragments) on
                // the HTTP wire. Log the raw text; emit a generic
                // "internal server error" to the caller.
                tracing::error!(
                    target: "ai_memory::handlers::skills",
                    error = %e,
                    "skill_get_route: substrate error (sanitized for wire response, #1261)"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "internal server error"})),
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
    // #949 — admin-only. Skill resource blobs are part of the
    // executable bundle (scripts, prompts, fixtures) and inherit
    // the same supply-chain threat surface as the skill body.
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, "skill_resource")
    {
        return resp;
    }
    let params = json!({
        "skill_id": id,
        "resource_path": q.path,
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
        "target_folder": body.target_folder,
    });
    let lock = app.db.lock().await;
    let kp = (*app.active_keypair).as_ref();
    match crate::mcp::handle_skill_export(&lock.0, &params, kp) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            if e.starts_with("skill not found") {
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
    // #949 — admin-only. Promote consumes a reflection memory and
    // mints a new skill row carrying the promoting agent's signing
    // surface. Cross-tenant promote = laundering an executable
    // capability through someone else's reflection.
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, "skill_promote") {
        return resp;
    }
    let mut params = json!({
        "reflection_id": id,
        "skill_name": body.name,
        "skill_description": body.description,
    });
    if let Some(ps) = body.parameters_schema {
        params["parameters_schema"] = ps;
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
        params["budget_tokens"] = json!(b);
    }
    let lock = app.db.lock().await;
    match crate::mcp::handle_skill_compositional_context(&lock.0, &params) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            if e.starts_with("skill not found") {
                (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response()
            } else {
                // #1261 — never forward the raw substrate error on
                // the HTTP wire. Log the raw text; emit a generic
                // "internal server error" to the caller.
                tracing::error!(
                    target: "ai_memory::handlers::skills",
                    error = %e,
                    "skill_compose_route: substrate error (sanitized for wire response, #1261)"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "internal server error"})),
                )
                    .into_response()
            }
        }
    }
}
