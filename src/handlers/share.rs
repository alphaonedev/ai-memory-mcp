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

use crate::models::field_names;
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
    /// #2122 — optional covenant clause-1 rationale override; the shared
    /// copy inherits the source's `metadata.why_trace` when omitted.
    #[serde(default)]
    pub why_trace: Option<String>,
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
    headers: HeaderMap,
    Json(body): Json<ShareBody>,
) -> impl IntoResponse {
    // v1.0.0 #3379 — per-agent-key identity gate BEFORE the caller is resolved
    // from `X-Agent-Id` for the caller-owns-source check below. Without it a
    // shared-transport-key caller could forge `X-Agent-Id: <victim>` and share
    // the victim's `scope=private` rows out to itself. Mirrors the #2044 gate
    // on `get_memory` / `load_family`; inert for zero-config deployments.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "share_memory",
    ) {
        return resp;
    }
    // #3379 — resolve the caller the same way every other gated HTTP read does
    // (`handlers::memories::get_memory`): header id, else a per-request
    // `anonymous:req-…` principal which owns nothing. The substrate primitive
    // then refuses any source this caller cannot read, with the identical
    // not-found body an absent id produces.
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let share_caller = crate::identity::resolve_http_agent_id(None, header_agent_id)
        .unwrap_or_else(|_| crate::identity::anonymous_request_id());

    let mut params: Value = json!({
        (field_names::SOURCE_MEMORY_ID): body.source_memory_id,
        (field_names::TARGET_AGENT_ID): body.target_agent_id,
    });
    // #2122 — thread the caller's covenant clause-1 rationale override
    // (parity with the MCP `why_trace` param + CLI `--why-trace` flag).
    if let Some(wt) = body.why_trace {
        params[crate::storage::META_KEY_WHY_TRACE] = json!(wt);
    }

    // Route through the existing substrate primitive. Lock the DB,
    // dispatch, release. The MCP path uses the same handler so wire
    // shape parity is guaranteed.
    let lock = app.db.lock().await;
    let result = crate::mcp::share::handle_share(&lock.0, &params, Some(&share_caller));
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
