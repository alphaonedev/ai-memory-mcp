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
        // #3762 — forward the renderer's closed-vocabulary text verbatim so
        // HTTP says byte-identically what MCP says; the absolute jail path
        // lives on the operator log at the refusal site, never here.
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
    // #3762 — the `Err` text below is the renderer's closed vocabulary
    // forwarded verbatim (byte-identical with the MCP surface); see the
    // register route above.
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
    let caller = match super::admin_role::require_admin(&app, &headers, "skill_promote") {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let is_admin = crate::identity::is_admin_agent_in(&caller, &app.admin_agent_ids)
        && super::admin_role::is_admin_caller_trusted(&app, &headers, &caller);
    let read_caller = if is_admin {
        None
    } else {
        Some(caller.as_str())
    };
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
    match crate::mcp::handle_skill_promote_for_caller(&lock.0, &params, kp, &caller, read_caller) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            // #3707 / #6115 - the chain may carry a store or driver `Display`
            // (SQL fragments, paths); the caller gets the class text below.
            // #6131 F5 - `mcp_foreign_err` below owns the ONE operator log
            // line for this failure (detail at error for a foreign root, warn
            // for a typed refusal), so this arm does not log it again.
            let status = promote_error_status(&e);
            // #6125 - the same classifier the MCP path of this operation
            // uses: our own typed refusal / not-found text reaches the
            // caller, a foreign (db / fs / codec) root becomes its class
            // constant. `mcp_foreign_err` also owns the operator log line.
            (status, Json(json!({"error": promote_error_message(e)}))).into_response()
        }
    }
}

/// #3707 / #6115 / #6125 - caller-facing message for a failed skill-promote,
/// byte-identical to the text the MCP tool returns for the same chain
/// (`crate::mcp::error_text::mcp_foreign_err`): first-party refusals keep
/// their typed text, store / driver / io text is replaced by its class
/// constant and never crosses to the wire.
fn promote_error_message(e: anyhow::Error) -> String {
    crate::mcp::error_text::mcp_foreign_err("skill_promote_route", e)
}

/// #4622 - HTTP status for a failed skill-promote: 404 only when the chain
/// carries the typed `ReflectionNotFound` root, never by matching error text.
fn promote_error_status(e: &anyhow::Error) -> StatusCode {
    if e.downcast_ref::<crate::errors::ReflectionNotFound>()
        .is_some()
    {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::BAD_REQUEST
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
    // #4059 — explicit HTTP-admin semantics preserved: this route is
    // admin-only (`require_admin` above), and an admin compose reads the
    // declared namespaces under the operator trust-all posture (`None`).
    match crate::mcp::handle_skill_compositional_context(&lock.0, &params, None) {
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

#[cfg(test)]
mod promote_status_4622_tests {
    use super::{promote_error_message, promote_error_status};
    use crate::errors::{MemoryError, ReflectionNotFound};
    use crate::models::{Memory, MemoryKind, Tier};
    use axum::http::StatusCode;
    use serde_json::json;

    const CALLER: &str = "ai:alice4622";

    fn seed(conn: &rusqlite::Connection, title: &str, kind: MemoryKind) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let memory = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            title: title.to_string(),
            content: "body".to_string(),
            namespace: "ns4622".to_string(),
            tier: Tier::Long,
            metadata: json!({"agent_id": CALLER, "scope": "collective"}),
            memory_kind: kind,
            reflection_depth: i32::from(kind == MemoryKind::Reflection),
            created_at: now.clone(),
            updated_at: now,
            ..Memory::default()
        };
        crate::db::insert(conn, &memory).expect("seed memory");
        memory.id
    }

    fn promote(
        conn: &rusqlite::Connection,
        id: &str,
        name: &str,
    ) -> anyhow::Result<serde_json::Value> {
        crate::mcp::handle_skill_promote_for_caller(
            conn,
            &json!({"reflection_id": id, "skill_name": name, "skill_description": "d"}),
            None,
            CALLER,
            Some(CALLER),
        )
    }

    fn db() -> (rusqlite::Connection, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = crate::db::open(&dir.path().join("m.db")).expect("open db");
        (conn, dir)
    }

    /// Pin 1: the MCP wire code and text for a missing reflection.
    #[test]
    fn issue_4622_mcp_code_and_text_are_unchanged() {
        let (conn, _dir) = db();
        let err = promote(&conn, "absent-id", "good-name").expect_err("missing reflection");
        assert_eq!(err.to_string(), "reflection not found: absent-id");
        assert_eq!(format!("{err:#}"), "reflection not found: absent-id");
        // The pre-fix construction, kept here as the byte-for-byte reference.
        let legacy = || crate::errors::refusal("reflection not found: absent-id");
        let legacy_code = MemoryError::from(legacy()).code();
        let legacy_wire = crate::mcp::error_text::mcp_foreign_err("legacy", legacy());
        let wire = crate::mcp::error_text::mcp_foreign_err("now", err);
        assert_eq!(wire, legacy_wire, "MCP wire text is byte-identical");
        let again = promote(&conn, "absent-id", "good-name").expect_err("again");
        let mapped = MemoryError::from(again);
        assert_eq!(mapped.code(), "REFUSED");
        assert_eq!(mapped.code(), legacy_code);
        assert_eq!(mapped.message(), "reflection not found: absent-id");
    }

    /// Pin 2: a different error whose text contains the words is not a 404.
    #[test]
    fn issue_4622_other_error_containing_not_found_is_not_404() {
        let (conn, _dir) = db();
        let id = seed(&conn, "r", MemoryKind::Reflection);
        let err = promote(&conn, &id, "not found").expect_err("bad skill name");
        assert!(err.to_string().contains("not found"), "{err}");
        assert_eq!(promote_error_status(&err), StatusCode::BAD_REQUEST);
    }

    /// #6115: a foreign (store or driver) root never reaches the caller body.
    #[test]
    fn issue_6115_foreign_error_text_is_withheld_from_the_body() {
        let err = anyhow::anyhow!("no such table: skills (SQLITE_ERROR) at /var/db/x.sqlite");
        assert_eq!(
            promote_error_message(err),
            crate::mcp::error_text::DB_ERROR_TEXT
        );
        let rnf = anyhow::Error::new(ReflectionNotFound::new("abc"));
        assert_eq!(promote_error_message(rnf), "reflection not found: abc");
    }

    /// #6126: table-driven body pins beyond the plain-string case - our own
    /// typed refusals survive verbatim, wrapped db / io errors carrying a
    /// path or DSN are replaced by their class constant.
    #[test]
    fn issue_6126_typed_refusal_survives_and_wrapped_foreign_error_is_withheld() {
        use crate::mcp::error_text::DB_ERROR_TEXT;
        let cases: Vec<(&str, anyhow::Error, String)> = vec![
            (
                "typed invalid-input refusal",
                crate::errors::invalid_input("skill 'description' must be <= 1024 characters"),
                "skill 'description' must be <= 1024 characters".to_owned(),
            ),
            (
                "typed own-text refusal",
                crate::errors::refusal("reflection depth 0 is below the promote minimum 1"),
                "reflection depth 0 is below the promote minimum 1".to_owned(),
            ),
            (
                "wrapped database error with DSN and path",
                anyhow::Error::new(rusqlite::Error::InvalidPath("/var/db/x.sqlite".into()))
                    .context("connect svc:hunter2@db.internal:5432 failed"),
                DB_ERROR_TEXT.to_owned(),
            ),
            (
                "wrapped io error with path",
                anyhow::Error::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "/srv/tenant/skills: EACCES",
                ))
                .context("write skill bundle"),
                // The `anyhow` classifier has no io arm: a wrapped io root is the
                // storage constant, identical to the MCP wire text.
                DB_ERROR_TEXT.to_owned(),
            ),
        ];
        for (label, err, expected) in cases {
            let body = promote_error_message(err);
            assert_eq!(body, expected, "{label}");
            for leak in ["hunter2", "postgres://", "/var/db", "/srv/tenant", "EACCES"] {
                assert!(!body.contains(leak), "{label}: {leak} leaked into {body}");
            }
        }
    }

    /// #6125 / #6131 F3: for every refusal shape the HTTP body text equals the
    /// text the REAL MCP handler (`handle_skill_promote_from_reflection`) puts
    /// on the wire for the same input, and the first-party refusals are present
    /// in it. The last case is a foreign root (the namespace governance table is
    /// gone): both transports must answer the storage constant and nothing from
    /// the chain, so a `format!("{e:#}")` body goes red here.
    #[test]
    fn issue_6125_http_body_text_matches_mcp_wire_text() {
        let _agent_id_env_lock = crate::identity::agent_id_env_test_lock();
        let (conn, _dir) = db();
        let id = seed(&conn, "r", MemoryKind::Reflection);
        let (broken, _broken_dir) = db();
        let broken_id = seed(&broken, "r", MemoryKind::Reflection);
        broken
            .execute_batch("DROP TABLE namespace_meta;")
            .expect("break the namespace governance table");
        let long = "x".repeat(1025);
        let db_text = crate::mcp::error_text::DB_ERROR_TEXT;
        for (c, rid, name, desc, needle) in [
            (&conn, id.as_str(), "BadName", "d", "spec \u{a7}3.1"),
            (&conn, id.as_str(), "good-name", long.as_str(), "1024"),
            (
                &conn,
                "absent-id",
                "good-name",
                "d",
                "reflection not found: absent-id",
            ),
            (&broken, broken_id.as_str(), "good-name", "d", db_text),
        ] {
            let params = json!({
                "reflection_id": rid, "skill_name": name, "skill_description": desc,
                "agent_id": CALLER
            });
            let wire = crate::mcp::handle_skill_promote_from_reflection(c, &params, None)
                .expect_err("MCP refused");
            let http_err =
                crate::mcp::handle_skill_promote_for_caller(c, &params, None, CALLER, Some(CALLER))
                    .expect_err("HTTP refused");
            let body = promote_error_message(http_err);
            assert_eq!(body, wire, "HTTP and MCP text diverge for {name}");
            assert!(body.contains(needle), "{needle} missing from {body}");
        }
    }

    /// #6147: the ONE operator log line for a foreign promote failure carries
    /// the whole `anyhow` chain, so the driver root under a context wrapper
    /// reaches the operator; the caller body stays the storage constant.
    #[test]
    fn issue_6147_operator_log_carries_the_inner_database_error() {
        // #4090: tracing capture; run alone in a child (callsite-interest cache).
        if crate::config::run_env_isolated_child_or_spawn(
            "handlers::skills::promote_status_4622_tests::issue_6147_operator_log_carries_the_inner_database_error",
        ) {
            return;
        }
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory db");
        let root = conn
            .execute("DELETE FROM missing_table_6147", [])
            .expect_err("missing table");
        let err = anyhow::Error::new(root).context("skill promote register");
        let (subscriber, sink) = crate::test_support::error_debug_capture();
        let body = tracing::subscriber::with_default(subscriber, || promote_error_message(err));
        let log = crate::test_support::captured_text(&sink);
        let lines: Vec<&str> = log
            .lines()
            .filter(|l| l.contains(crate::mcp::error_text::TRACE_TARGET))
            .collect();
        assert_eq!(lines.len(), 1, "one operator log line: {log}");
        assert!(lines[0].contains("skill promote register"), "{log}");
        assert!(
            lines[0].contains("missing_table_6147"),
            "inner cause lost: {log}"
        );
        assert_eq!(body, crate::mcp::error_text::DB_ERROR_TEXT);
    }

    /// Pin 3: the 404 follows the type, not the Display text.
    #[test]
    fn issue_4622_reworded_display_keeps_404() {
        let err =
            anyhow::Error::new(ReflectionNotFound::new("x")).context("a wholly different wording");
        assert!(!err.to_string().contains("not found"), "{err}");
        assert_eq!(promote_error_status(&err), StatusCode::NOT_FOUND);
    }

    /// Pin 5: a missing or hidden source member still answers 404.
    #[test]
    fn issue_4622_missing_source_member_is_404() {
        let (conn, _dir) = db();
        let id = seed(&conn, "r", MemoryKind::Reflection);
        conn.pragma_update(None, "foreign_keys", false)
            .expect("foreign keys off");
        conn.execute(
            "INSERT INTO memory_links (source_id, target_id, relation, created_at) \
             VALUES (?1, ?2, 'reflects_on', ?3)",
            rusqlite::params![
                id,
                uuid::Uuid::new_v4().to_string(),
                chrono::Utc::now().to_rfc3339()
            ],
        )
        .expect("dangling source edge");
        let err = promote(&conn, &id, "good-name").expect_err("missing source");
        assert_eq!(err.to_string(), format!("reflection not found: {id}"));
        assert_eq!(promote_error_status(&err), StatusCode::NOT_FOUND);
    }

    /// Pin 6: the typed root maps to `Refused`, never `NotFound`.
    #[test]
    fn issue_4622_mapping_to_refused_is_pinned() {
        let mapped = MemoryError::from(anyhow::Error::new(ReflectionNotFound::new("z")));
        assert!(matches!(&mapped, MemoryError::Refused(m) if m == "reflection not found: z"));
        assert_eq!(mapped.code(), "REFUSED");
    }
}
