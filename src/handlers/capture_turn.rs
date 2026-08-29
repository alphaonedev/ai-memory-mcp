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

use crate::models::field_names;
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
                (field_names::ATTEST_LEVEL): attest_level,
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
#[allow(clippy::too_many_lines)]
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

    // #3225 — MCP `handle_capture_turn` runs K9 `Permissions::evaluate` +
    // K3 `enforce_governance` before the idempotent write. HTTP used to
    // skip both (prepare + `capture_turn_idempotent` only), so a Deny
    // rule / namespace standard that MCP would refuse was an ungated
    // HTTP write. Mirror MCP: Deny → 403, Ask/Pending → 202, before
    // any durable write. A dedup-hit is a no-op, so gating first is
    // safe (a denied namespace refuses uniformly whether or not the
    // turn was already captured).
    if let Some(resp) = http_capture_turn_k9_gate(&write, &agent_id) {
        return resp;
    }

    #[cfg(feature = "sal")]
    let response = {
        let capability = match crate::handlers::capability_from_headers(&headers, &agent_id) {
            Ok(c) => c,
            Err(resp) => return resp,
        };
        if let Some(resp) =
            http_capture_turn_governance_via_store(&app, &write, &agent_id, capability.as_ref())
                .await
        {
            return resp;
        }
        // Single SAL path: `app.store` wraps the sqlite OR postgres
        // adapter, so this serves both backends through the trait method.
        let ctx = crate::store::CallerContext::for_agent(agent_id).with_capability(capability);
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
        if let Some(resp) = http_capture_turn_governance_via_db(&lock.0, &write, &agent_id) {
            return resp;
        }
        // #2121 — tenant HTTP surface: never substrate-authored (parity with
        // the SAL branch above, whose `for_agent` ctx has
        // `bypass_visibility = false`).
        match crate::storage::capture_turn_idempotent(&lock.0, &write, false) {
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

/// Action label for the L4 capture-turn write gate. Matches the MCP
/// `ACTION_CAPTURE_TURN` spelling so Deny/Ask/Pending envelopes stay
/// cross-surface identical (#3225).
const ACTION_CAPTURE_TURN: &str = "capture_turn";

/// #3225 — K9 permission gate (backend-blind). Deny → 403; Ask → 202.
fn http_capture_turn_k9_gate(
    write: &crate::models::CaptureTurnWrite,
    agent_id: &str,
) -> Option<Response> {
    use crate::permissions::{Op, PermissionContext, Permissions};
    let gate_namespace = write.memory.namespace.clone();
    let payload = json!({
        "id": write.memory.id,
        "title": write.memory.title,
        "namespace": gate_namespace,
    });
    let ctx = PermissionContext {
        op: Op::MemoryStore,
        namespace: gate_namespace.clone(),
        agent_id: agent_id.to_string(),
        payload,
    };
    match Permissions::evaluate(&ctx, &[]) {
        crate::permissions::Decision::Allow | crate::permissions::Decision::Modify(_) => None,
        crate::permissions::Decision::Deny(reason) => Some(
            (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": crate::governance::deny_message(
                        ACTION_CAPTURE_TURN,
                        crate::governance::DenyGate::PermissionRule,
                        &reason,
                    ),
                })),
            )
                .into_response(),
        ),
        crate::permissions::Decision::Ask(prompt) => Some(
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "status": "ask",
                    "reason": prompt,
                    "action": ACTION_CAPTURE_TURN,
                    "namespace": gate_namespace,
                })),
            )
                .into_response(),
        ),
    }
}

/// #3225 — namespace-governance gate on the SAL path (sqlite-SAL + postgres).
/// Deny → 403; Pending → 202. Probe error → the typed store-error envelope.
#[cfg(feature = "sal")]
async fn http_capture_turn_governance_via_store(
    app: &AppState,
    write: &crate::models::CaptureTurnWrite,
    agent_id: &str,
    capability: Option<&crate::governance::capability::CapabilityToken>,
) -> Option<Response> {
    use crate::models::GovernanceDecision;
    let ns = &write.memory.namespace;
    let payload = json!({
        "id": write.memory.id,
        "title": write.memory.title,
        "namespace": ns,
    });
    if let Some(resp) = super::create::http_pre_governance_decision_gate(
        ns,
        "store",
        agent_id,
        Some(&write.memory.id),
    ) {
        return Some(resp);
    }
    match app
        .store
        .enforce_governance_action(
            crate::store::GovernedAction::Store,
            ns,
            agent_id,
            Some(&write.memory.id),
            Some(agent_id),
            &payload,
            capability,
        )
        .await
    {
        Ok(GovernanceDecision::Allow) => None,
        Ok(GovernanceDecision::Deny(refusal)) => {
            // #3292 M7 — unowned-standard Owner lock must not 403 a
            // legitimate capture. MCP `memory_capture_turn` allow-through
            // (`is_unowned_owner_lock`); HTTP was stricter (over-refuse).
            if refusal.is_unowned_owner_lock() {
                None
            } else {
                Some(
                    (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": crate::governance::deny_message(
                                ACTION_CAPTURE_TURN,
                                crate::governance::DenyGate::Governance,
                                &refusal.reason,
                            ),
                        })),
                    )
                        .into_response(),
                )
            }
        }
        Ok(GovernanceDecision::Pending(pending_id)) => Some(
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "status": "pending",
                    (field_names::PENDING_ID): pending_id,
                    "reason": crate::errors::msg::GOVERNANCE_REQUIRES_APPROVAL,
                    "action": ACTION_CAPTURE_TURN,
                    "namespace": ns,
                })),
            )
                .into_response(),
        ),
        Err(e) => Some(store_err_to_response(e)),
    }
}

/// #3225 — namespace-governance gate on the non-SAL sqlite path.
#[cfg(not(feature = "sal"))]
fn http_capture_turn_governance_via_db(
    conn: &rusqlite::Connection,
    write: &crate::models::CaptureTurnWrite,
    agent_id: &str,
) -> Option<Response> {
    use crate::models::{GovernanceDecision, GovernedAction};
    let ns = &write.memory.namespace;
    let payload = json!({
        "id": write.memory.id,
        "title": write.memory.title,
        "namespace": ns,
    });
    if let Some(resp) = super::create::http_pre_governance_decision_gate(
        ns,
        "store",
        agent_id,
        Some(&write.memory.id),
    ) {
        return Some(resp);
    }
    match crate::db::enforce_governance(
        conn,
        GovernedAction::Store,
        ns,
        agent_id,
        Some(&write.memory.id),
        Some(agent_id),
        &payload,
        None,
    ) {
        Ok(GovernanceDecision::Allow) => None,
        Ok(GovernanceDecision::Deny(refusal)) => {
            // #3292 M7 — MCP↔HTTP parity: unowned-owner-lock allow-through.
            if refusal.is_unowned_owner_lock() {
                None
            } else {
                Some(
                    (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": crate::governance::deny_message(
                                ACTION_CAPTURE_TURN,
                                crate::governance::DenyGate::Governance,
                                &refusal.reason,
                            ),
                        })),
                    )
                        .into_response(),
                )
            }
        }
        Ok(GovernanceDecision::Pending(pending_id)) => Some(
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "status": "pending",
                    (field_names::PENDING_ID): pending_id,
                    "reason": crate::errors::msg::GOVERNANCE_REQUIRES_APPROVAL,
                    "action": ACTION_CAPTURE_TURN,
                    "namespace": ns,
                })),
            )
                .into_response(),
        ),
        Err(e) => Some(crate::handlers::errors::governance_error_500(&e)),
    }
}
