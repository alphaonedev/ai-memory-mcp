// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1111 — 14 missing HTTP routes for the MCP-only tools the
//! SR-4 three-surface-parity audit flagged.
//!
//! Pre-#1111 these handlers existed only on the MCP wire; an HTTP
//! caller asking for `POST /api/v1/memory_smart_load` (or any of the
//! 13 siblings) got 404. Each route here is a thin wrapper around the
//! existing `crate::mcp::handle_<name>` substrate primitive so the JSON
//! envelope is byte-equal across the MCP and HTTP surfaces.
//!
//! ## Routes added
//!
//! | Path                                         | Handler                                    |
//! |----------------------------------------------|--------------------------------------------|
//! | `POST /api/v1/memory_smart_load`             | [`handle_smart_load_http`]                 |
//! | `POST /api/v1/memory_reflect`                | [`handle_reflect_http`]                    |
//! | `POST /api/v1/memory_recall_observations`    | [`handle_recall_observations_http`]        |
//! | `POST /api/v1/memory_reflection_origin`      | [`handle_reflection_origin_http`]          |
//! | `POST /api/v1/memory_dependents_of_invalidated` | [`handle_dependents_of_invalidated_http`] |
//! | `POST /api/v1/memory_export_reflection`      | [`handle_export_reflection_http`]          |
//! | `POST /api/v1/memory_atomise`                | [`handle_atomise_http`]                    |
//! | `POST /api/v1/memory_calibrate_confidence`   | [`handle_calibrate_confidence_http`]       |
//! | `POST /api/v1/memory_verify`                 | [`handle_verify_http`]                     |
//! | `POST /api/v1/memory_replay`                 | [`handle_replay_http`]                     |
//! | `POST /api/v1/memory_subscription_replay`    | [`handle_subscription_replay_http`]        |
//! | `POST /api/v1/memory_subscription_dlq_list`  | [`handle_subscription_dlq_list_http`]      |
//! | `POST /api/v1/memory_rule_list`              | [`handle_rule_list_http`]                  |
//! | `POST /api/v1/memory_check_agent_action`     | [`handle_check_agent_action_http`]         |
//!
//! ## Wire contract
//!
//! Every handler accepts the same JSON body shape the MCP `arguments`
//! bag accepts and returns the same JSON envelope the MCP `tools/call`
//! response wraps. Errors surface as `400 Bad Request` with
//! `{"error": "<substrate string>"}`.
//!
//! Caller identity is extracted via the existing
//! `crate::handlers::parity::resolve_caller_agent_id` chain so the same
//! `X-Agent-Id` header semantics apply across the existing 60 routes
//! and these 14 new ones.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::{Value, json};

use super::AppState;

/// Build the `Bad Request` envelope used by every #1111 handler when
/// the substrate primitive returns `Err(String)`. Kept as a free
/// function so the 14 handlers below stay 3-5 line wrappers.
fn err_response(e: String) -> axum::response::Response {
    tracing::warn!(error = %e, "HTTP route #1111 substrate refusal");
    (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response()
}

/// `POST /api/v1/memory_smart_load` — substrate-routed family
/// load with intent-string keyword + embedder voting. Wraps
/// [`crate::mcp::handle_smart_load`]; embedder is pulled from
/// `AppState` so the HTTP surface picks up the same model the MCP
/// dispatch uses.
pub async fn handle_smart_load_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let lock = app.db.lock().await;
    let embedder = app
        .embedder
        .as_ref()
        .as_ref()
        .map(|e| e as &dyn crate::embeddings::Embed);
    let result = crate::mcp::handle_smart_load(&lock.0, &body, embedder);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_reflect` — substrate reflection over a
/// memory set. Wraps [`crate::mcp::handle_reflect`]. The embedder,
/// vector index, and daemon active keypair flow in from `AppState` so
/// every `reflects_on` edge written here is signed when the operator
/// has a daemon keypair on disk (matching the MCP behaviour).
pub async fn handle_reflect_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let lock = app.db.lock().await;
    let db_path = lock.1.clone();
    let embedder = app
        .embedder
        .as_ref()
        .as_ref()
        .map(|e| e as &dyn crate::embeddings::Embed);
    let vec_lock = app.vector_index.lock().await;
    let vector_index = vec_lock.as_ref();
    let active_keypair = app.active_keypair.as_ref().as_ref();
    let result = crate::mcp::handle_reflect(
        &lock.0,
        &db_path,
        &body,
        embedder,
        vector_index,
        // HTTP callers have no MCP-stdio clientInfo; the substrate
        // primitive falls back to the `body.agent_id` / synthesised id.
        None,
        active_keypair,
    );
    drop(vec_lock);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_recall_observations` — Provenance Gap 3
/// recall-consumption observation read. Read-only over the
/// `recall_observations` table; no caller-ownership gate (already
/// scoped per-row by `agent_id`).
pub async fn handle_recall_observations_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_recall_observations(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_reflection_origin` — walk a reflection
/// memory backward along `reflects_on` edges to surface the original
/// observation set. Read-only.
pub async fn handle_reflection_origin_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_reflection_origin(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_dependents_of_invalidated` — surface the
/// transitive closure of memories that derive from an invalidated row.
/// L2-3 / #668 substrate. Read-only.
pub async fn handle_dependents_of_invalidated_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_dependents_of_invalidated(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_export_reflection` — export a reflection
/// memory + its full reflects_on lineage as a structured JSON bundle.
/// Read-only; no caller-ownership gate (the lineage walk uses
/// substrate visibility filters).
pub async fn handle_export_reflection_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_export_reflection(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_atomise` — WT-1-F atomiser. Decomposes a
/// long-form memory into atomic propositions. HTTP dispatch passes
/// `handler: None` so the substrate uses its default per-tier
/// behaviour (no live LLM curator). Operators who want the
/// LLM-curated atomisation path drive it through MCP where the daemon
/// owns the `AtomiseToolHandler`. The tier is pulled from
/// `AppState.tier_config` so HTTP and MCP agree on feature-tier
/// gating.
pub async fn handle_atomise_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let lock = app.db.lock().await;
    let tier = app.tier_config.tier;
    let result = crate::mcp::tools::handle_atomise(&lock.0, &body, None, tier, None);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_calibrate_confidence` — Form 5 calibration
/// driver. Reads `confidence_shadow_observations`, emits per-
/// (namespace, source) baselines over the window. Read-only over the
/// shadow-observations table.
pub async fn handle_calibrate_confidence_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_calibrate_confidence(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_verify` — verify a link's per-edge
/// Ed25519 signature against the bound `observed_by` public key.
/// Read-only.
pub async fn handle_verify_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_verify(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_replay` — substrate audit-chain replay
/// for a memory id. Caller-ownership gate is enforced inside
/// [`crate::mcp::handle_replay`] (issue #1075 SR-1 #1 HIGH).
pub async fn handle_replay_http(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // Resolve caller id so the substrate ownership gate has a
    // header-attributed principal. Mirror the inbox handler.
    let body_agent = body.get("agent_id").and_then(Value::as_str);
    let caller = match crate::handlers::parity::resolve_caller_agent_id(body_agent, &headers, None)
    {
        Ok(id) => id,
        Err(e) => return err_response(e),
    };
    let mut owned = body.clone();
    if let Some(obj) = owned.as_object_mut() {
        obj.insert("agent_id".to_string(), Value::String(caller.clone()));
    }
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_replay(&lock.0, &owned, Some(&caller));
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_subscription_replay` — replay HMAC-signed
/// webhook deliveries for a subscription. Caller-ownership gate
/// enforced inside [`crate::mcp::handle_subscription_replay`] (issue
/// #1115 SR-1 #5 HIGH): only the subscription's owner can replay it.
pub async fn handle_subscription_replay_http(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let body_agent = body.get("agent_id").and_then(Value::as_str);
    let caller = match crate::handlers::parity::resolve_caller_agent_id(body_agent, &headers, None)
    {
        Ok(id) => id,
        Err(e) => return err_response(e),
    };
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_subscription_replay(&lock.0, &body, Some(&caller));
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_subscription_dlq_list` — list dead-lettered
/// webhook deliveries. Caller-ownership gate enforced inside
/// [`crate::mcp::handle_subscription_dlq_list`] (issue #1118 SR-1 #6
/// HIGH): non-admin callers can only see DLQ rows for their own
/// subscriptions.
pub async fn handle_subscription_dlq_list_http(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let body_agent = body.get("agent_id").and_then(Value::as_str);
    let caller = match crate::handlers::parity::resolve_caller_agent_id(body_agent, &headers, None)
    {
        Ok(id) => id,
        Err(e) => return err_response(e),
    };
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_subscription_dlq_list(&lock.0, &body, Some(&caller));
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_rule_list` — list the substrate-level
/// agent-action governance rules. Read-only.
pub async fn handle_rule_list_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_rule_list(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_check_agent_action` — dry-run an agent
/// action against the substrate rules table. Read-only over the rules
/// table; writes a `governance.check` audit row (audit emit failure
/// surfaces as 500 via the substrate primitive).
pub async fn handle_check_agent_action_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_check_agent_action(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}
