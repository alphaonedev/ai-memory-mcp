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

/// Response field carrying the W-of-N acknowledgement count on a successful
/// fanout (one spelling, pm-v3.1 literal gate).
const QUORUM_ACKS_FIELD: &str = "quorum_acks";

/// Rejection detail for a non-terminal `state` on the checkpoint-resolve route
/// (one spelling, pm-v3.1 literal gate). Mirrors the MCP handler's wording.
const CHECKPOINT_STATE_INVALID: &str = "state must be one of: resolved, rejected";

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

/// Request body for `POST /api/v1/signals`. `from_agent` is NOT taken from the
/// body — it is the authenticated caller (the node), mirroring the `create_memory`
/// provenance posture.
#[derive(Debug, Clone, Deserialize)]
pub struct SendSignalRequest {
    /// Namespace the signal is sent within.
    pub namespace: String,
    /// Free-text subject line.
    pub subject: String,
    /// Recipient agent, or `None` for a namespace broadcast.
    #[serde(default)]
    pub to_agent: Option<String>,
    /// JSON-typed payload.
    #[serde(default)]
    pub body: serde_json::Value,
    /// Canonical [`crate::models::SignalType`] spelling; defaults when absent.
    #[serde(default)]
    pub signal_type: Option<String>,
    /// Threads a response back onto its request.
    #[serde(default)]
    pub in_reply_to: Option<String>,
    /// Groups the signal into a conversation thread.
    #[serde(default)]
    pub correlation_id: Option<String>,
    /// JSON array of related signal/memory ids.
    #[serde(default)]
    pub reference_ids: Option<serde_json::Value>,
    /// #3011 — optional retention TTL in seconds; sets `expires_at = now + ttl`.
    #[serde(default)]
    pub ttl_secs: Option<i64>,
}

/// #2391 — request body for `POST /api/v1/checkpoints/{id}/resolve`.
///
/// `resolved_by` is deliberately NOT a body field: the resolver is the
/// authenticated caller (the node), mirroring [`SendSignalRequest`]'s
/// `from_agent` provenance posture. A body-supplied resolver could not be
/// attested against the sending node's enrolled key on the receiving peer.
#[derive(Debug, Clone, Deserialize)]
pub struct CheckpointResolveHttpRequest {
    /// Terminal resolution state — `"resolved"` or `"rejected"`.
    pub state: String,
    /// Structured resolution verdict (free-form string).
    #[serde(default)]
    pub resolution: Option<String>,
    /// Human-readable note explaining the resolution. Advisory prose — NOT part
    /// of the attested resolution tuple.
    #[serde(default)]
    pub resolution_note: Option<String>,
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
    if let Some(cb) = body.claimed_by.as_deref()
        && let Err(e) = crate::validate::validate_agent_id(cb)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": crate::errors::msg::invalid(
                crate::mcp::param_names::CLAIMED_BY,
                e,
            )})),
        )
            .into_response();
    }

    // Local write (dual-path): sqlite via app.db + crate::actions (default),
    // postgres via the SAL trait (under --features sal). The #3009/#3226
    // lease-holder bind lives inside each local-write helper so sqlite and
    // postgres cannot drift.
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
                    response[QUORUM_ACKS_FIELD] = json!(got);
                    return (StatusCode::OK, Json(response)).into_response();
                }
                Err(err) => {
                    let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                    return super::under_replicated_response(&payload);
                }
            },
            Err(err) => {
                let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                return super::under_replicated_response(&payload);
            }
        }
    }

    // Single-node fast path: no peers configured.
    (StatusCode::OK, Json(response)).into_response()
}

/// `POST /api/v1/signals` — send a signal locally, then fan it out to peers
/// under W-of-N quorum when the daemon is federation-configured. Mirrors
/// [`transition_action`]: local write FIRST, 503 on a failed quorum (no
/// rollback, ADR-0001), single-node fast path when no peers. The signal is
/// signed with the daemon's keypair (backend-agnostic) BEFORE insert + broadcast
/// so the inserted row and the broadcast carry the same verifying signature
/// (peers apply signals accept-and-flag — see `federation::receive_auth`).
pub async fn send_signal(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SendSignalRequest>,
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
    // #3226 — reject an unknown `signal_type` like MCP `handle_signal_send`
    // (A6-13 / #3007 sibling). An ABSENT value still defaults; a PRESENT
    // but unknown token is 400, never silently coerced to `notify`.
    let signal_type = match body.signal_type.as_deref() {
        Some(s) => match crate::models::SignalType::from_str(s) {
            Some(t) => t,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("invalid signal_type: {s}")})),
                )
                    .into_response();
            }
        },
        None => crate::models::SignalType::default(),
    };
    let now = chrono::Utc::now().timestamp();
    // #3011 — wire `signals.expires_at` from an optional `ttl_secs` (validated +
    // overflow-checked), so the gc pruner can reap the caller-declared-ephemeral
    // signal.
    let expires_at = match body.ttl_secs {
        Some(ttl) => {
            if let Err(e) = crate::validate::validate_ttl_secs(Some(ttl)) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("invalid ttl_secs: {e}")})),
                )
                    .into_response();
            }
            match now.checked_add(ttl) {
                Some(v) => Some(v),
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": crate::coordination_guard::TTL_SECS_OVERFLOW})),
                    )
                        .into_response();
                }
            }
        }
        None => None,
    };
    let mut signal = crate::models::Signal {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: body.namespace,
        from_agent: node_agent_id,
        to_agent: body.to_agent,
        subject: body.subject,
        body: body.body,
        signal_type,
        in_reply_to: body.in_reply_to,
        correlation_id: body.correlation_id,
        reference_ids: body.reference_ids.unwrap_or_else(|| json!([])),
        created_at: now,
        expires_at,
        delivered_at: None,
        read_at: None,
        acknowledged_at: None,
        signature: Vec::new(),
        sender_pubkey: Vec::new(),
    };
    // #2994 — the coordination write plane bypasses the memory-lane storage
    // funnel, so screen the caller-origin credential vectors (subject / body)
    // BEFORE signing + insert + the `/sync/push` EGRESS: refuse under
    // `SECRET_SCREEN_MODE=refuse`, mask under `redact`, byte-identical under
    // `off`. A refusal is a `400` (a caller pasted a credential into a signal).
    if let Err(refusal) = crate::secret_screen::screen_text_field_for_caller(&mut signal.subject)
        .and_then(|()| crate::secret_screen::screen_json_field_for_caller(&mut signal.body))
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": refusal.to_string()})),
        )
            .into_response();
    }
    // Sign with the daemon keypair (backend-agnostic) so the inserted row + the
    // broadcast carry the same verifying signature. Unsigned when no keypair.
    if let Some(kp) = app.active_keypair.as_ref().as_ref() {
        if kp.can_sign() {
            if let Err(e) = crate::signals::sign_into(&mut signal, kp) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("sign signal failed: {e}")})),
                )
                    .into_response();
            }
        }
    }
    // #1807 — charge the sender's per-namespace storage quota for the signal
    // payload BEFORE insert (storage_only; a signal carries no metadata object,
    // so the byte cap IS the payload-size limit). The quota accounting row
    // always lives on the sqlite `app.db` connection regardless of the storage
    // backend — same as the federation-receive postgres path — so this charge
    // is backend-uniform. A quota breach returns 429 QUOTA_EXCEEDED, mirroring
    // the memory create path. T-exempt precedent-copy; 5-agent review
    // (memory `4d3ea1c5`) deemed #1807 legitimate.
    if !signal.from_agent.is_empty() {
        let bytes = crate::quotas::coordination_payload_bytes(
            &[&signal.subject],
            &[&signal.body, &signal.reference_ids],
        );
        let charge = {
            let conn = app.db.lock().await;
            crate::quotas::check_and_record_storage_only(
                &conn.0,
                &signal.from_agent,
                &signal.namespace,
                bytes,
            )
        };
        if let Err(e) = charge {
            return match e {
                crate::quotas::QuotaCheckError::Quota(qe) => (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                        "code": crate::errors::error_codes::QUOTA_EXCEEDED,
                        "error": qe.to_string(),
                        "limit": qe.limit.as_str(),
                        "current": qe.current,
                        "max": qe.max,
                        "agent_id": qe.agent_id,
                    })),
                )
                    .into_response(),
                crate::quotas::QuotaCheckError::Sql(se) => {
                    tracing::error!("signal quota substrate error: {se}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": crate::errors::msg::QUOTA_CHECK_FAILED})),
                    )
                        .into_response()
                }
            };
        }
    }
    // Local insert (dual-path: postgres via SAL under --features sal, else sqlite).
    let insert_res: Result<(), Response> = {
        #[cfg(feature = "sal")]
        {
            if matches!(
                app.storage_backend,
                crate::handlers::StorageBackend::Postgres
            ) {
                let ctx = crate::store::CallerContext::for_agent(signal.from_agent.clone());
                app.store
                    .signal_send(&ctx, &signal, None)
                    .await
                    .map(|_| ())
                    .map_err(|e| signal_insert_error(&e.to_string()))
            } else {
                let lock = app.db.lock().await;
                crate::signals::insert(&lock.0, &signal)
                    .map(|_| ())
                    .map_err(|e| signal_insert_error(&e.to_string()))
            }
        }
        #[cfg(not(feature = "sal"))]
        {
            let lock = app.db.lock().await;
            crate::signals::insert(&lock.0, &signal)
                .map(|_| ())
                .map_err(|e| signal_insert_error(&e.to_string()))
        }
    };
    if let Err(resp) = insert_res {
        return resp;
    }

    let mut response = json!({
        "id": signal.id,
        (crate::mcp::param_names::NAMESPACE): signal.namespace,
        (crate::mcp::param_names::FROM_AGENT): signal.from_agent,
        (crate::mcp::param_names::SIGNAL_TYPE): signal.signal_type.as_str(),
        (crate::models::field_names::CREATED_AT): signal.created_at,
    });

    if let Some(fed) = app.federation.as_ref() {
        match crate::federation::broadcast_signal_create_quorum(fed, &signal).await {
            Ok(tracker) => match crate::federation::finalise_quorum(&tracker) {
                Ok(got) => {
                    response[QUORUM_ACKS_FIELD] = json!(got);
                    return (StatusCode::OK, Json(response)).into_response();
                }
                Err(err) => {
                    let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                    return super::under_replicated_response(&payload);
                }
            },
            Err(err) => {
                let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                return super::under_replicated_response(&payload);
            }
        }
    }

    (StatusCode::OK, Json(response)).into_response()
}

/// Shared `500` response for a failed signal insert (one spelling, literal gate).
fn signal_insert_error(detail: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("signal insert failed: {detail}")})),
    )
        .into_response()
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
    if let Some(cb) = claimed_by {
        let lease = match crate::actions::lease_get(&lock.0, action_id) {
            Ok(l) => l,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("lease_get failed: {e}")})),
                )
                    .into_response());
            }
        };
        if let Err(msg) = crate::actions::authorize_claimed_by(cb, lease.as_ref(), now, action_id) {
            return Err((StatusCode::FORBIDDEN, Json(json!({"error": msg}))).into_response());
        }
    }
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
    // Wave-2 B5 — local action CAS is a record-plane mutation. Reads
    // (the `get` above) stay live; the write is fenced (ERRORS-09).
    if let Err(e) = crate::storage::record_stop::gate_storage_conn(&lock.0) {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "code": crate::errors::error_codes::RECORD_STOPPED,
                "error": e.to_string(),
            })),
        )
            .into_response());
    }
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
    if let Some(cb) = claimed_by {
        let lease = match app.store.lease_get(&ctx, action_id).await {
            Ok(l) => l,
            Err(e) => return Err(super::store_err_to_response(e)),
        };
        if let Err(msg) = crate::actions::authorize_claimed_by(cb, lease.as_ref(), now, action_id) {
            return Err((StatusCode::FORBIDDEN, Json(json!({"error": msg}))).into_response());
        }
    }
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

/// `POST /api/v1/checkpoints/{id}/resolve` — resolve a commit-checkpoint
/// locally, then fan the resolution out to peers under W-of-N quorum when the
/// daemon is federation-configured.
///
/// #2391 — this is the SEND leg of the FED-RQ-01 (#1936) checkpoint-federation
/// transport. The receive leg (`handlers::federation_receive` +
/// [`crate::checkpoints::apply_inbound_resolution`]) and the broadcast fn
/// ([`crate::federation::broadcast_checkpoint_resolution_quorum`]) both shipped
/// at v1.0.0, but checkpoints were the ONE coordination primitive #1718 never
/// gave an HTTP route — and fanout is only reachable from a handler that holds
/// [`AppState::federation`]. The result was a broadcast fn with ZERO production
/// callers: two nodes running this build could never exchange a checkpoint
/// resolution, which is the §25.2 epoch-freeze contract's only cross-node
/// mechanism. This route closes that leg.
///
/// Mirrors [`transition_action`] / [`send_signal`] exactly: local write FIRST,
/// `503` on a failed quorum with NO rollback (ADR-0001), single-node fast path
/// when no peers are configured.
///
/// **Node-granular attestation.** `resolved_by` is the NODE's resolved agent id
/// (never a body field), and the resolution is signed with the daemon's
/// `active_keypair` — so a receiving peer verifies it against the sending
/// node's already-enrolled public key, which is exactly what the fail-closed
/// `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG` gate
/// ([`crate::federation::receive_auth::authorize_remote_checkpoint_resolution`])
/// requires. Same posture as [`build_signed_transition_op`] (vote `c2fa96aa`)
/// and [`send_signal`]'s `from_agent`.
pub async fn resolve_checkpoint(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(checkpoint_id): Path<String>,
    Json(body): Json<CheckpointResolveHttpRequest>,
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
    // Only the two terminal resolution states are accepted — same filter as the
    // MCP `memory_checkpoint_resolve` handler.
    let Some(state) = crate::models::CheckpointState::from_str(&body.state).filter(|s| {
        matches!(
            s,
            crate::models::CheckpointState::Resolved | crate::models::CheckpointState::Rejected
        )
    }) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": CHECKPOINT_STATE_INVALID})),
        )
            .into_response();
    };
    let now = chrono::Utc::now().timestamp();

    // Local write (dual-path): sqlite via app.db + crate::checkpoints (default),
    // postgres via the SAL `checkpoint_resolve` trait method (under --features
    // sal). The fanout below sits ABOVE this split, so it is backend-agnostic:
    // a postgres-backed daemon federates checkpoint resolutions identically.
    // (#1552's lesson was a fanout wired INSIDE backend-specific branches, so
    // the postgres arm silently skipped it — this shape structurally cannot.)
    let resolved: Result<crate::checkpoints::ResolveOutcome, Response> = {
        #[cfg(feature = "sal")]
        {
            if matches!(
                app.storage_backend,
                crate::handlers::StorageBackend::Postgres
            ) {
                let ctx = crate::store::CallerContext::for_agent(node_agent_id.clone());
                app.store
                    .checkpoint_resolve(
                        &ctx,
                        &checkpoint_id,
                        state,
                        &node_agent_id,
                        body.resolution.as_deref(),
                        body.resolution_note.as_deref(),
                        now,
                        app.active_keypair.as_ref().as_ref(),
                    )
                    .await
                    .map_err(|e| checkpoint_resolve_error(&e.to_string()))
            } else {
                local_resolve_via_db(&app, &checkpoint_id, state, &node_agent_id, &body, now).await
            }
        }
        #[cfg(not(feature = "sal"))]
        {
            local_resolve_via_db(&app, &checkpoint_id, state, &node_agent_id, &body, now).await
        }
    };
    // #2995 — first-resolution-wins: an already-resolved checkpoint is a `409`
    // conflict (prior verdict kept), NOT a silent overwrite of the freeze anchor.
    let cp = match resolved {
        Ok(crate::checkpoints::ResolveOutcome::Resolved(cp)) => *cp,
        Ok(crate::checkpoints::ResolveOutcome::NotFound) => {
            return checkpoint_not_found(&checkpoint_id);
        }
        Ok(crate::checkpoints::ResolveOutcome::Conflict(existing)) => {
            return checkpoint_conflict(&checkpoint_id, &existing);
        }
        Err(resp) => return resp,
    };

    // #1722 coordination observability — best-effort audit row, attributed to
    // the resolving node. The audit table always lives on the sqlite `app.db`
    // connection regardless of the storage backend (same posture as the
    // `send_signal` quota charge), so this is backend-uniform.
    {
        let conn = app.db.lock().await;
        crate::coordination_audit::emit(
            &conn.0,
            crate::coordination_audit::CHECKPOINT_RESOLVE,
            &node_agent_id,
            &[&checkpoint_id, &node_agent_id, state.as_str()],
        );
    }

    let mut response = json!({
        (crate::mcp::param_names::ID): cp.id,
        (crate::mcp::param_names::STATE): cp.state.as_str(),
        (crate::mcp::param_names::RESOLVED_BY): cp.resolved_by,
        (crate::models::field_names::RESOLVED_AT): cp.resolved_at,
        (crate::models::field_names::ATTEST_LEVEL): if cp.signature.is_empty() {
            crate::models::AttestLevel::Unsigned.as_str()
        } else {
            crate::models::AttestLevel::SelfSigned.as_str()
        },
    });

    // Federation fanout (W-of-N) — only when configured. NOTE: every DB lock
    // above is released before this await; the fanout is a network round-trip
    // per peer and must never hold the shared sqlite connection.
    if let Some(fed) = app.federation.as_ref() {
        match crate::federation::broadcast_checkpoint_resolution_quorum(fed, &cp).await {
            Ok(tracker) => match crate::federation::finalise_quorum(&tracker) {
                Ok(got) => {
                    response[QUORUM_ACKS_FIELD] = json!(got);
                    return (StatusCode::OK, Json(response)).into_response();
                }
                Err(err) => {
                    let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                    return super::under_replicated_response(&payload);
                }
            },
            Err(err) => {
                let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                return super::under_replicated_response(&payload);
            }
        }
    }

    // Single-node fast path: no peers configured.
    (StatusCode::OK, Json(response)).into_response()
}

/// Sqlite local resolve under the shared `app.db` connection lock. The guard is
/// scoped to this fn so it is dropped before the caller's federation await.
async fn local_resolve_via_db(
    app: &AppState,
    checkpoint_id: &str,
    state: crate::models::CheckpointState,
    node_agent_id: &str,
    body: &CheckpointResolveHttpRequest,
    now: i64,
) -> Result<crate::checkpoints::ResolveOutcome, Response> {
    let lock = app.db.lock().await;
    crate::checkpoints::resolve(
        &lock.0,
        checkpoint_id,
        state,
        node_agent_id,
        body.resolution.as_deref(),
        body.resolution_note.as_deref(),
        now,
        app.active_keypair.as_ref().as_ref(),
    )
    .map_err(|e| checkpoint_resolve_error(&e.to_string()))
}

/// Shared `500` for a failed checkpoint resolve (one spelling, literal gate).
fn checkpoint_resolve_error(detail: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("checkpoint resolve failed: {detail}")})),
    )
        .into_response()
}

/// Shared `404 checkpoint not found` response (one spelling, literal gate).
fn checkpoint_not_found(checkpoint_id: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": format!("checkpoint not found: {checkpoint_id}")})),
    )
        .into_response()
}

/// #2995 — shared `409 checkpoint already resolved` response for the
/// first-resolution-wins refusal. Reports who won so the caller can reconcile.
fn checkpoint_conflict(checkpoint_id: &str, existing: &crate::models::Checkpoint) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "error": format!("checkpoint {checkpoint_id} already resolved; first resolution wins"),
            (crate::mcp::param_names::STATE): existing.state.as_str(),
            (crate::mcp::param_names::RESOLVED_BY): existing.resolved_by,
        })),
    )
        .into_response()
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
