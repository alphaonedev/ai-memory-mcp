// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1095 — HTTP route for `memory_share`.
//!
//! Mirrors the MCP shape (`source_memory_id` + `target_agent_id`)
//! and wraps the existing
//! [`crate::mcp::tools::share::handle_share`] substrate primitive so
//! the three surfaces (MCP / HTTP / CLI) share one implementation.
//!
//! The MCP and CLI surfaces also exist post-#1095; the audit lens
//! (SR-4) flagged the three-surface parity gap. CLI lands separately;
//! this module pins the HTTP half.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::AppState;

/// HTTP wire shape for `POST /api/v1/share`.
#[derive(Debug, Deserialize)]
pub struct ShareBody {
    pub source_memory_id: String,
    pub target_agent_id: String,
}

/// `POST /api/v1/share` — copy a memory into the target agent's
/// shared namespace `_shared/<from>→<to>/`. Wraps the existing
/// substrate primitive so the MCP/HTTP/CLI surfaces share one
/// implementation.
///
/// Returns the same JSON envelope as the MCP tool:
/// ```json
/// {
///   "shared_memory_id": "<new uuid>",
///   "source_memory_id": "<input>",
///   "target_namespace": "_shared/<from>→<to>/",
///   "target_agent_id": "<input>",
///   "from_agent_id": "<derived>"
/// }
/// ```
pub async fn share_memory(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<ShareBody>,
) -> impl IntoResponse {
    let params: Value = json!({
        "source_memory_id": body.source_memory_id,
        "target_agent_id": body.target_agent_id,
    });

    // Route through the existing substrate primitive. Lock the DB,
    // dispatch, release. The MCP path uses the same handler so wire
    // shape parity is guaranteed.
    let lock = app.db.lock().await;
    let result = crate::mcp::share::handle_share(&lock.0, &params);
    drop(lock);

    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            // Surface validation / not-found / governance refusal as
            // 400. The substrate primitive returns a String error;
            // map it to a structured envelope so HTTP callers can
            // parse the failure shape uniformly.
            tracing::warn!("share_memory failed: {e}");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}
