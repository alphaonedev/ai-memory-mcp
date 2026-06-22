// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1718 v0.8.0 Pillar-1 — HTTP write surface for federated coordination
//! action-state transitions (and, in a sibling, signals).
//!
//! The coordination primitives (actions / leases / signals) previously had a
//! local MCP write surface but no HTTP route, so they had no federation fanout
//! path (fanout lives in HTTP handlers — `app.federation` is only reachable
//! from `AppState`). This module is the SEND side of #1718: a local action
//! transition is applied, then — when the daemon is federation-configured —
//! fanned out to peers under W-of-N quorum, mirroring the memory-store write
//! path (`handlers::create_memory` → `broadcast_store_quorum` → `finalise_quorum`,
//! 503-on-miss, NO rollback per ADR-0001).
//!
//! Like `create_memory`, the local write is dual-path: the default build writes
//! through `app.db` + the `crate::actions` free-functions (sqlite), and under
//! `--features sal` a Postgres-backed daemon dispatches through the SAL trait
//! (`app.store`). The federation fanout below is backend-agnostic.
//!
//! **Node-granular attestation (5-agent vote `c2fa96aa` / `4d3ea1c5`).** The
//! broadcast op is signed with the daemon's `active_keypair` and attests
//! `claimed_by = the node's resolved agent id`, so a receiving peer verifies it
//! against the sending node's *already-enrolled* public key (the same key the
//! peer holds for the `/sync/push` envelope check). The receiver's fail-closed
//! gate (`federation::receive_auth`) then accepts it. Federation thus operates
//! at node granularity; the local action's caller-supplied `claimed_by` (the
//! actor) stays a local concern.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::{Json, http::StatusCode};
use serde::Deserialize;
use serde_json::json;

use crate::handlers::AppState;

/// Request body for `POST /api/v1/actions/{id}/transition`.
#[derive(Debug, Clone, Deserialize)]
pub struct ActionTransitionRequest {
    /// Target [`crate::models::ActionState`] (canonical `as_str` spelling, e.g.
    /// `"claimed"` / `"in_progress"` / `"done"`).
    pub to: String,
    /// Optional actor the local action is claimed by (local concern). The
    /// federated broadcast attests the NODE, not this value (see module docs).
    #[serde(default)]
    pub claimed_by: Option<String>,
}

/// `POST /api/v1/actions/{id}/transition` — apply a coordination-action state
/// transition locally, then fan it out to peers under W-of-N quorum when the
/// daemon is federation-configured.
///
/// Mirrors [`crate::handlers::create_memory`]: the local write lands FIRST; a
/// failed quorum returns `503` (typed `QuorumNotMet` envelope) and does NOT roll
/// back the local write (ADR-0001). With no federation configured, the local
/// transition is the whole operation (single-node fast path).
pub async fn transition_action(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(action_id): Path<String>,
    Json(body): Json<ActionTransitionRequest>,
) -> impl IntoResponse {
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let node_agent_id = match crate::identity::resolve_http_agent_id(None, header_agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": crate::errors::msg::invalid("agent_id", e)})),
            )
                .into_response();
        }
    };
    let Some(to) = crate::models::ActionState::from_str(&body.to) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid action state: {}", body.to)})),
        )
            .into_response();
    };
    let now = chrono::Utc::now().timestamp();

    // Local write (dual-path): sqlite via app.db + crate::actions (default),
    // postgres via the SAL trait (under --features sal).
    let local = {
        #[cfg(feature = "sal")]
        {
            if matches!(
                app.storage_backend,
                crate::handlers::StorageBackend::Postgres
            ) {
                local_transition_via_store(
                    &app,
                    &action_id,
                    &node_agent_id,
                    to,
                    body.claimed_by.as_deref(),
                    now,
                )
                .await
            } else {
                local_transition_via_db(&app, &action_id, to, body.claimed_by.as_deref(), now).await
            }
        }
        #[cfg(not(feature = "sal"))]
        {
            local_transition_via_db(&app, &action_id, to, body.claimed_by.as_deref(), now).await
        }
    };
    let (updated, from_state, namespace) = match local {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    let mut response = json!({
        "id": updated.id,
        "state": updated.state.as_str(),
        (crate::mcp::param_names::CLAIMED_BY): updated.claimed_by,
        "updated_at": updated.updated_at,
    });

    // Federation fanout (W-of-N) — only when configured. Per ADR-0001 a failed
    // quorum returns 503 but does NOT roll back the local write above.
    if let Some(fed) = app.federation.as_ref() {
        let op = build_signed_transition_op(
            app.active_keypair.as_ref().as_ref(),
            &action_id,
            &namespace,
            from_state,
            to,
            &node_agent_id,
            now,
        );
        match crate::federation::broadcast_action_transition_quorum(fed, &op).await {
            Ok(tracker) => match crate::federation::finalise_quorum(&tracker) {
                Ok(got) => {
                    response["quorum_acks"] = json!(got);
                    return (StatusCode::OK, Json(response)).into_response();
                }
                Err(err) => {
                    let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                    return super::quorum_not_met_response(&payload);
                }
            },
            Err(err) => {
                let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                return super::quorum_not_met_response(&payload);
            }
        }
    }

    // Single-node fast path: no peers configured.
    (StatusCode::OK, Json(response)).into_response()
}

/// Map a [`crate::actions::CasOutcome`] to either the updated action or the
/// caller-facing error response. Shared by both backends.
fn map_cas_outcome(
    outcome: crate::actions::CasOutcome,
    action_id: &str,
) -> Result<crate::models::Action, Response> {
    use crate::actions::CasOutcome;
    match outcome {
        CasOutcome::Applied(a) => Ok(a),
        CasOutcome::StateMismatch { current } => Err((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "action state changed concurrently",
                "current_state": current.as_str(),
            })),
        )
            .into_response()),
        CasOutcome::Illegal { from, to } => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": crate::actions::illegal_transition_detail(from, to)})),
        )
            .into_response()),
        CasOutcome::NotFound => Err(action_not_found(action_id)),
    }
}

/// The shared `404 action not found` response (one spelling of the message,
/// per the pm-v3.1 literal gate).
fn action_not_found(action_id: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": format!("action not found: {action_id}")})),
    )
        .into_response()
}

/// Sqlite local write: read current state (for the broadcast `from_state`) then
/// atomic CAS, all under the shared `app.db` connection lock. Returns
/// `(updated_action, from_state, namespace)` or a caller-facing error response.
async fn local_transition_via_db(
    app: &AppState,
    action_id: &str,
    to: crate::models::ActionState,
    claimed_by: Option<&str>,
    now: i64,
) -> Result<(crate::models::Action, crate::models::ActionState, String), Response> {
    let lock = app.db.lock().await;
    let current = match crate::actions::get(&lock.0, action_id) {
        Ok(Some(a)) => a,
        Ok(None) => {
            return Err(action_not_found(action_id));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("action_get failed: {e}")})),
            )
                .into_response());
        }
    };
    let from_state = current.state;
    let outcome =
        crate::actions::transition_cas(&lock.0, action_id, from_state, to, claimed_by, now)
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("action_transition failed: {e}")})),
                )
                    .into_response()
            })?;
    let updated = map_cas_outcome(outcome, action_id)?;
    Ok((updated, from_state, current.namespace))
}

/// Postgres local write via the SAL trait. Same contract as
/// [`local_transition_via_db`].
#[cfg(feature = "sal")]
async fn local_transition_via_store(
    app: &AppState,
    action_id: &str,
    node_agent_id: &str,
    to: crate::models::ActionState,
    claimed_by: Option<&str>,
    now: i64,
) -> Result<(crate::models::Action, crate::models::ActionState, String), Response> {
    let ctx = crate::store::CallerContext::for_agent(node_agent_id.to_string());
    let current = match app.store.action_get(&ctx, action_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return Err(action_not_found(action_id));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("action_get failed: {e}")})),
            )
                .into_response());
        }
    };
    let from_state = current.state;
    let outcome = app
        .store
        .action_transition_cas(&ctx, action_id, from_state, to, claimed_by, now)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("action_transition failed: {e}")})),
            )
                .into_response()
        })?;
    let updated = map_cas_outcome(outcome, action_id)?;
    Ok((updated, from_state, current.namespace))
}

/// Build the broadcast [`ActionTransitionOp`], signing it with the daemon's
/// keypair and attesting `claimed_by = node_agent_id` so receivers verify
/// against the node's enrolled key (vote `c2fa96aa`). When no signing keypair
/// is present the op is broadcast unsigned (receivers gate it via
/// `AI_MEMORY_FED_REQUIRE_TRANSITION_SIG`).
///
/// [`ActionTransitionOp`]: crate::federation::sync::ActionTransitionOp
fn build_signed_transition_op(
    keypair: Option<&crate::identity::keypair::AgentKeypair>,
    action_id: &str,
    namespace: &str,
    from_state: crate::models::ActionState,
    to_state: crate::models::ActionState,
    node_agent_id: &str,
    now: i64,
) -> crate::federation::sync::ActionTransitionOp {
    let nonce = fresh_nonce();
    let (signature, signer_pubkey) = match keypair {
        Some(kp) if kp.can_sign() => {
            let signable = crate::identity::sign::SignableTransition {
                action_id,
                namespace,
                from_state: from_state.as_str(),
                to_state: to_state.as_str(),
                claimed_by: Some(node_agent_id),
                nonce: &nonce,
                created_at: now,
            };
            match crate::identity::sign::sign_transition(kp, &signable) {
                Ok(sig) => (sig, kp.public.to_bytes().to_vec()),
                Err(e) => {
                    tracing::warn!("transition_action: sign_transition failed: {e}");
                    (Vec::new(), Vec::new())
                }
            }
        }
        _ => (Vec::new(), Vec::new()),
    };
    crate::federation::sync::ActionTransitionOp {
        action_id: action_id.to_string(),
        from_state,
        to_state,
        claimed_by: Some(node_agent_id.to_string()),
        vector_clock: serde_json::Value::Null,
        updated_at: now,
        signature,
        signer_pubkey,
        nonce,
    }
}

/// 16 random bytes from the platform CSPRNG — the per-delivery anti-replay
/// nonce bound into the signed transition surface.
fn fresh_nonce() -> Vec<u8> {
    use rand_core::RngCore;
    let mut nonce = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);
    nonce.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ActionState;

    #[test]
    fn signed_op_verifies_against_node_key_and_attests_node() {
        let node = "ai:node-1";
        let kp = crate::identity::keypair::generate(node).expect("kp");
        let op = build_signed_transition_op(
            Some(&kp),
            "act-1",
            "_act",
            ActionState::Pending,
            ActionState::Claimed,
            node,
            1_700_000_000,
        );
        assert_eq!(op.claimed_by.as_deref(), Some(node));
        assert_eq!(op.signer_pubkey, kp.public.to_bytes().to_vec());
        assert_eq!(op.nonce.len(), 16);
        assert!(!op.signature.is_empty());
        let signable = crate::identity::sign::SignableTransition {
            action_id: "act-1",
            namespace: "_act",
            from_state: "pending",
            to_state: "claimed",
            claimed_by: Some(node),
            nonce: &op.nonce,
            created_at: 1_700_000_000,
        };
        assert!(crate::identity::verify::verify_transition(
            &signable,
            &op.signature,
            &op.signer_pubkey,
        ));
    }

    #[test]
    fn unsigned_op_when_no_keypair() {
        let op = build_signed_transition_op(
            None,
            "act-1",
            "_act",
            ActionState::Pending,
            ActionState::Claimed,
            "ai:node-1",
            1_700_000_000,
        );
        assert!(op.signature.is_empty());
        assert!(op.signer_pubkey.is_empty());
        assert_eq!(op.nonce.len(), 16);
    }

    #[test]
    fn fresh_nonce_is_16_bytes_and_varies() {
        let a = fresh_nonce();
        let b = fresh_nonce();
        assert_eq!(a.len(), 16);
        assert_eq!(b.len(), 16);
        assert_ne!(a, b, "two nonces must differ (CSPRNG)");
    }
}
