// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! HTTP `POST /api/v1/capture_turn` — the L4 layered-capture surface for
//! the HTTP daemon (#1416 / RFC-0001).
//!
//! The MCP `memory_capture_turn` tool only ever runs against a local
//! sqlite connection (`ai-memory mcp` opens by `--db`). Postgres-backed
//! daemons therefore had ZERO callable L4 surface despite carrying the
//! v52 `transcript_line_dedup` table. This route closes that gap: it
//! reuses the exact same validation + `Memory`/`SignedEvent`
//! construction as the MCP tool (`crate::mcp::prepare_capture_turn`),
//! then runs the dedup-keyed idempotent transaction through the SAL
//! `MemoryStore::capture_turn_idempotent` method — which both
//! `SqliteStore` and `PostgresStore` implement. Under `--features sal`
//! the single `app.store` path serves both backends; standard builds
//! fall back to the sqlite SSOT free function.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

#[cfg(feature = "sal")]
use super::store_err_to_response;
use super::{AppState, JsonOrBadRequest};
use crate::mcp::{MemoryCaptureTurnRequest, prepare_capture_turn};

/// Build the success envelope shared by every backend path. A dedup hit
/// is a no-op idempotent replay → `200 OK`; a fresh capture wrote rows
/// → `201 Created`. `attest_level` (`self_signed` / `signed_by_peer`)
/// is surfaced only on a fresh write, matching the MCP tool response.
fn capture_turn_ok(result: &crate::models::CaptureTurnResult, attest_level: &str) -> Response {
    if result.dedup_hit {
        (
            StatusCode::OK,
            Json(json!({
                "memory_id": result.memory_id,
                "dedup_hit": true,
                "layer": "L4",
            })),
        )
            .into_response()
    } else {
        (
            StatusCode::CREATED,
            Json(json!({
                "memory_id": result.memory_id,
                "dedup_hit": false,
                "layer": "L4",
                "attest_level": attest_level,
            })),
        )
            .into_response()
    }
}

/// `POST /api/v1/capture_turn` — host-volunteered L4 turn capture.
///
/// Mirrors the MCP `memory_capture_turn` tool over HTTP so postgres-
/// backed daemons gain a callable L4 surface (#1416). The `X-Agent-Id`
/// header authenticates the caller (same precedence as every other
/// HTTP write); a `metadata.agent_id` in the body MUST agree with it
/// (enforced inside `prepare_capture_turn`, #1413).
pub async fn capture_turn(
    State(app): State<AppState>,
    headers: HeaderMap,
    JsonOrBadRequest(req): JsonOrBadRequest<MemoryCaptureTurnRequest>,
) -> impl IntoResponse {
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let agent_id = match crate::identity::resolve_http_agent_id(None, header_agent_id) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    // All validation (agent_id agreement #1413, host-signature
    // verification #1414) + Memory/SignedEvent construction happens here,
    // shared verbatim with the MCP tool. String errors are caller-facing
    // input problems → 400.
    let write = match prepare_capture_turn(&req, &agent_id) {
        Ok(w) => w,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
        }
    };
    let attest_level = write.signed_event.attest_level.clone();

    #[cfg(feature = "sal")]
    let response = {
        // Single SAL path: `app.store` wraps the sqlite OR postgres
        // adapter, so this serves both backends through the trait method.
        let ctx = crate::store::CallerContext::for_agent(agent_id);
        match app.store.capture_turn_idempotent(&ctx, &write).await {
            Ok(result) => capture_turn_ok(&result, &attest_level),
            Err(e) => store_err_to_response(e),
        }
    };

    #[cfg(not(feature = "sal"))]
    let response = {
        // Standard build: no SAL, so reach the sqlite SSOT free function
        // directly under the shared connection lock.
        let state = app.db.clone();
        let lock = state.lock().await;
        match crate::storage::capture_turn_idempotent(&lock.0, &write) {
            Ok(result) => capture_turn_ok(&result, &attest_level),
            Err(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": msg })),
            )
                .into_response(),
        }
    };

    response
}
