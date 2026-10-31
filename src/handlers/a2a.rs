// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8444 - HTTP handlers for the Google Agent2Agent (A2A 1.0) standard
//! binding: the Agent Card and the ONE JSON-RPC 2.0 endpoint. Protocol shapes
//! live in [`crate::a2a`]; this module owns authentication, storage and
//! dispatch.
//!
//! # Posture P1 (strict, fail-closed)
//!
//! Both routes sit behind the existing [`super::api_key_auth`] middleware (no
//! exemption is added). On top of that, every JSON-RPC method requires a
//! credential-bound principal: the `x-api-key` is hashed and looked up in the
//! enrolled per-agent key registry, and the agent id found there is the ONLY
//! identity the binding uses. `X-Agent-Id` and every id inside the request body
//! are never consulted, so a remote caller cannot choose who its content is
//! attributed to. A shared-key-only or keyless caller has no credential-bound
//! principal and is refused with `401` on JSON-RPC methods.
//!
//! Tasks are owned by that principal; an unknown id and another caller's id
//! are the same `-32001` / `404`.

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use super::AppState;
use crate::a2a::wire::{
    CancelTaskRequest, GetTaskRequest, JsonRpcId, ListTasksRequest, ListTasksResponse,
    SendMessageResponse, TaskState,
};
use crate::a2a::{
    self, A2aError, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, Method, RpcRequest, SendInput, state,
};
use crate::models::field_names;
use crate::storage::a2a_tasks::{A2aTaskFilter, A2aTaskRow, A2aTaskUpdate};

#[cfg(feature = "sal")]
use super::StorageBackend;

type A2aResult<T> = Result<T, A2aError>;

fn version_header() -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("a2a-version"),
        HeaderValue::from_static(a2a::A2A_PROTOCOL_VERSION),
    )
}

fn with_version(status: StatusCode, body: Value) -> Response {
    let (name, value) = version_header();
    (status, [(name, value)], Json(body)).into_response()
}

fn error_response(id: &JsonRpcId, err: &A2aError) -> Response {
    let status = StatusCode::from_u16(err.http_status).unwrap_or(StatusCode::BAD_REQUEST);
    with_version(status, a2a::error_envelope(id, err))
}

/// The credential-bound principal of this request: the agent id enrolled for
/// the presented `x-api-key`. `None` for a shared-key or keyless caller.
fn authenticated_agent(app: &AppState, headers: &HeaderMap) -> Option<String> {
    let token = headers.get(crate::HEADER_API_KEY)?.to_str().ok()?;
    let digest = super::identity_binding::api_key_sha256_hex(token);
    app.enrolled_agent_keys.snapshot().get(&digest).cloned()
}

fn unauthenticated_response() -> Response {
    with_version(
        StatusCode::UNAUTHORIZED,
        json!({"error": "a per-agent api key is required"}),
    )
}

/// `GET /.well-known/agent-card.json` - the Agent Card, served to any caller
/// that passed `api_key_auth` (the card is NOT public).
pub async fn agent_card(State(_app): State<AppState>, headers: HeaderMap) -> Response {
    let host = headers.get("host").and_then(|v| v.to_str().ok());
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok());
    let card = a2a::agent_card(&a2a::base_url(host, proto));
    match a2a::to_value(&card) {
        Ok(body) => with_version(StatusCode::OK, body),
        Err(e) => error_response(&JsonRpcId::Null, &e),
    }
}

/// `POST /api/v1/a2a` - the JSON-RPC 2.0 endpoint.
pub async fn a2a_rpc(State(app): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(agent) = authenticated_agent(&app, &headers) else {
        return unauthenticated_response();
    };
    if !is_json_content_type(&headers) {
        return error_response(&JsonRpcId::Null, &A2aError::content_type_not_supported());
    }
    let version = headers
        .get(a2a::HEADER_A2A_VERSION)
        .map(|v| v.to_str().unwrap_or("?"));
    if let Err(e) = a2a::check_version(version) {
        return error_response(&JsonRpcId::Null, &e);
    }
    let req = match a2a::parse_rpc(&body) {
        Ok(r) => r,
        Err((id, e)) => return error_response(&id, &e),
    };
    let method = match a2a::classify_method(&req.method) {
        Ok(m) => m,
        Err(e) => return error_response(&req.id, &e),
    };
    match dispatch(&app, &agent, method, &req).await {
        Ok(result) => with_version(StatusCode::OK, a2a::result_envelope(&req.id, result)),
        Err(e) => error_response(&req.id, &e),
    }
}

/// Whether the request declares a JSON media type: `application/json` or any
/// `+json` suffix type, parameters ignored, case-insensitive (conformance 270).
fn is_json_content_type(headers: &HeaderMap) -> bool {
    let Some(raw) = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let essence = raw
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    essence == crate::MIME_JSON || essence.ends_with("+json")
}

async fn dispatch(
    app: &AppState,
    agent: &str,
    method: Method,
    req: &RpcRequest,
) -> A2aResult<Value> {
    match method {
        Method::SendMessage => send_message(app, agent, &req.params).await,
        Method::GetTask => get_task(app, agent, &req.params).await,
        Method::ListTasks => list_tasks(app, agent, &req.params).await,
        Method::CancelTask => cancel_task(app, agent, &req.params).await,
    }
}

fn checked_id(id: &str) -> A2aResult<()> {
    if id.is_empty() || id.len() > a2a::MAX_ID_LEN {
        return Err(A2aError::invalid_params("id is required"));
    }
    Ok(())
}

async fn get_task(app: &AppState, agent: &str, params: &Value) -> A2aResult<Value> {
    let req: GetTaskRequest = a2a::parse_params(params)?;
    checked_id(&req.id)?;
    let history_length = a2a::history_length(req.history_length);
    let row = store_get(app, agent, &req.id)
        .await?
        .ok_or_else(A2aError::task_not_found)?;
    a2a::to_value(&a2a::task_from_row(&row, history_length, true)?)
}

async fn cancel_task(app: &AppState, agent: &str, params: &Value) -> A2aResult<Value> {
    let req: CancelTaskRequest = a2a::parse_params(params)?;
    checked_id(&req.id)?;
    let id = req.id;
    let row = store_get(app, agent, &id)
        .await?
        .ok_or_else(A2aError::task_not_found)?;
    if state::is_terminal(&row.state) {
        return Err(A2aError::task_not_cancelable());
    }
    let update = A2aTaskUpdate {
        status_timestamp: a2a::now_timestamp(),
        history: None,
        artifacts: None,
    };
    let won = store_cas(
        app,
        agent,
        &id,
        &state::NON_TERMINAL,
        state::CANCELED,
        &update,
    )
    .await?;
    if !won {
        // Lost the compare-and-set: a concurrent completion (or cancel) made
        // the task terminal first.
        return Err(A2aError::task_not_cancelable());
    }
    let row = store_get(app, agent, &id)
        .await?
        .ok_or_else(A2aError::task_not_found)?;
    a2a::to_value(&a2a::task_from_row(&row, None, true)?)
}

async fn list_tasks(app: &AppState, agent: &str, params: &Value) -> A2aResult<Value> {
    let req: ListTasksRequest = a2a::parse_params(params)?;
    let page_size = match req.page_size {
        None => DEFAULT_PAGE_SIZE,
        // Below 1 is invalid; above the cap is clamped to `MAX_PAGE_SIZE`.
        Some(n) => usize::try_from(n)
            .ok()
            .filter(|n| *n >= 1)
            .map(|n| n.min(MAX_PAGE_SIZE))
            .ok_or_else(|| A2aError::invalid_params("pageSize must be at least 1"))?,
    };
    let offset = match req.page_token.as_deref() {
        None | Some("") => 0,
        Some(t) => t
            .parse::<usize>()
            .map_err(|_| A2aError::invalid_params("pageToken is invalid"))?,
    };
    // `TASK_STATE_UNSPECIFIED` is the proto default: no filter.
    let status = match req.status {
        None | Some(TaskState::Unspecified) => None,
        Some(s) => match a2a::to_value(&s)? {
            Value::String(text) => Some(text),
            _ => return Err(A2aError::internal()),
        },
    };
    let history_length = a2a::history_length(req.history_length);
    let include_artifacts = req.include_artifacts.unwrap_or(false);
    let filter = A2aTaskFilter {
        context_id: req.context_id,
        state: status,
        status_timestamp_after: req.status_timestamp_after.map(a2a::format_timestamp),
        offset,
        limit: page_size,
    };
    let page = store_list(app, agent, &filter).await?;
    let next = offset.saturating_add(page.rows.len());
    let next_token = if next < page.total && !page.rows.is_empty() {
        next.to_string()
    } else {
        String::new()
    };
    let tasks = page
        .rows
        .iter()
        .map(|r| a2a::task_from_row(r, history_length, include_artifacts))
        .collect::<A2aResult<Vec<_>>>()?;
    a2a::to_value(&ListTasksResponse {
        tasks,
        next_page_token: next_token,
        page_size: i32::try_from(page_size).map_err(|_| A2aError::internal())?,
        total_size: i32::try_from(page.total).map_err(|_| A2aError::internal())?,
    })
}

async fn send_message(app: &AppState, agent: &str, params: &Value) -> A2aResult<Value> {
    let input = a2a::parse_send_message(params)?;
    crate::validate::validate_content(&input.text)
        .map_err(|_| A2aError::invalid_params("message text is invalid or too large"))?;
    let task_id = open_task(app, agent, &input).await?;
    // SUBMITTED -> WORKING. Losing this CAS means a concurrent CancelTask
    // already ended the task: report its state, store nothing.
    let working = A2aTaskUpdate {
        status_timestamp: a2a::now_timestamp(),
        history: None,
        artifacts: None,
    };
    let started = store_cas(
        app,
        agent,
        &task_id,
        &state::NON_TERMINAL,
        state::WORKING,
        &working,
    )
    .await?;
    if !started {
        return current_task(app, agent, &task_id).await;
    }
    let stamp = a2a::system_stamp(agent, &input.role);
    let memory_id = match store_message(app, agent, &input.text, &stamp).await {
        Ok(id) => id,
        Err(e) => {
            let failed = A2aTaskUpdate {
                status_timestamp: a2a::now_timestamp(),
                history: None,
                artifacts: None,
            };
            // Best effort: the original error is what the caller sees.
            let _ = store_cas(
                app,
                agent,
                &task_id,
                &[state::WORKING],
                state::FAILED,
                &failed,
            )
            .await;
            return Err(e);
        }
    };
    let done = A2aTaskUpdate {
        status_timestamp: a2a::now_timestamp(),
        history: None,
        artifacts: Some(a2a::to_value(&vec![a2a::receipt_artifact(&memory_id)])?),
    };
    // WORKING -> COMPLETED. If a concurrent CancelTask won, the task stays
    // CANCELED and that is what is reported; the stored message is a
    // delivered inbox row either way.
    let _ = store_cas(
        app,
        agent,
        &task_id,
        &[state::WORKING],
        state::COMPLETED,
        &done,
    )
    .await?;
    current_task(app, agent, &task_id).await
}

async fn current_task(app: &AppState, agent: &str, id: &str) -> A2aResult<Value> {
    let row = store_get(app, agent, id)
        .await?
        .ok_or_else(A2aError::internal)?;
    let task = a2a::task_from_row(&row, None, true)?;
    a2a::to_value(&SendMessageResponse::Task(task))
}

/// Create the task for a new message, or continue the caller's non-terminal
/// task when the message names one. Returns the task id.
async fn open_task(app: &AppState, agent: &str, input: &SendInput) -> A2aResult<String> {
    let now = a2a::now_timestamp();
    let message_json = a2a::to_value(&input.message)?;
    if let Some(task_id) = input.message.task_id.as_deref() {
        let row = store_get(app, agent, task_id)
            .await?
            .ok_or_else(A2aError::task_not_found)?;
        if state::is_terminal(&row.state) {
            return Err(A2aError::task_not_found());
        }
        if input
            .message
            .context_id
            .as_deref()
            .is_some_and(|c| c != row.context_id)
        {
            return Err(A2aError::invalid_params(
                "contextId does not match the task",
            ));
        }
        // Append the message to the task history through the same CAS used
        // for every other transition. The message itself is durable in the
        // inbox either way; `history` is the task's convenience view.
        let mut history = row.history.as_array().cloned().unwrap_or_default();
        history.push(message_json);
        let update = A2aTaskUpdate {
            status_timestamp: now,
            history: Some(Value::Array(history)),
            artifacts: None,
        };
        let moved = store_cas(
            app,
            agent,
            task_id,
            &state::NON_TERMINAL,
            state::SUBMITTED,
            &update,
        )
        .await?;
        if !moved {
            return Err(A2aError::task_not_found());
        }
        return Ok(task_id.to_string());
    }
    let id = uuid::Uuid::new_v4().to_string();
    let context_id = input
        .message
        .context_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let row = A2aTaskRow {
        id: id.clone(),
        context_id,
        agent_id: agent.to_string(),
        state: state::SUBMITTED.to_string(),
        status_timestamp: now.clone(),
        history: json!([message_json]),
        artifacts: json!([]),
        metadata: json!({"storage": "ai-memory-inbox"}),
        created_at: now.clone(),
        updated_at: now,
    };
    store_insert(app, &row).await?;
    Ok(id)
}

// --- storage dispatch -------------------------------------------------------
//
// Postgres-backed daemons route through the `MemoryStore` trait; SQLite (and
// the default, SAL-less build) uses the storage-layer functions on `app.db`.
// Both reach the same `a2a_tasks` contract.

#[cfg(feature = "sal")]
fn is_postgres(app: &AppState) -> bool {
    matches!(app.storage_backend, StorageBackend::Postgres)
}

#[cfg(feature = "sal")]
fn store_failure(e: &crate::store::StoreError) -> A2aError {
    tracing::warn!(target: "a2a", "a2a storage failure: {e}");
    match e {
        crate::store::StoreError::InvalidInput { .. } => {
            A2aError::invalid_params("message was rejected")
        }
        _ => A2aError::internal(),
    }
}

fn sqlite_failure(e: &anyhow::Error) -> A2aError {
    tracing::warn!(target: "a2a", "a2a storage failure: {e}");
    A2aError::internal()
}

async fn store_insert(app: &AppState, row: &A2aTaskRow) -> A2aResult<()> {
    #[cfg(feature = "sal")]
    if is_postgres(app) {
        return app
            .store
            .a2a_task_insert(row)
            .await
            .map_err(|e| store_failure(&e));
    }
    let lock = app.db.lock().await;
    crate::storage::a2a_tasks::a2a_task_insert(&lock.0, row).map_err(|e| sqlite_failure(&e))
}

async fn store_get(app: &AppState, agent: &str, id: &str) -> A2aResult<Option<A2aTaskRow>> {
    #[cfg(feature = "sal")]
    if is_postgres(app) {
        return app
            .store
            .a2a_task_get(agent, id)
            .await
            .map_err(|e| store_failure(&e));
    }
    let lock = app.db.lock().await;
    crate::storage::a2a_tasks::a2a_task_get(&lock.0, agent, id).map_err(|e| sqlite_failure(&e))
}

async fn store_list(
    app: &AppState,
    agent: &str,
    filter: &A2aTaskFilter,
) -> A2aResult<crate::storage::a2a_tasks::A2aTaskPage> {
    #[cfg(feature = "sal")]
    if is_postgres(app) {
        return app
            .store
            .a2a_task_list(agent, filter)
            .await
            .map_err(|e| store_failure(&e));
    }
    let lock = app.db.lock().await;
    crate::storage::a2a_tasks::a2a_task_list(&lock.0, agent, filter).map_err(|e| sqlite_failure(&e))
}

async fn store_cas(
    app: &AppState,
    agent: &str,
    id: &str,
    from_states: &[&str],
    to_state: &str,
    update: &A2aTaskUpdate,
) -> A2aResult<bool> {
    #[cfg(feature = "sal")]
    if is_postgres(app) {
        return app
            .store
            .a2a_task_transition(agent, id, from_states, to_state, update)
            .await
            .map_err(|e| store_failure(&e));
    }
    let lock = app.db.lock().await;
    crate::storage::a2a_tasks::a2a_task_transition(
        &lock.0,
        agent,
        id,
        from_states,
        to_state,
        update,
    )
    .map_err(|e| sqlite_failure(&e))
}

/// Store the message in the authenticated caller's inbox through the native
/// notify path (quota, TTL, wake bus, webhooks, federation fan-out), with the
/// system stamp applied at memory formation. Returns the stored memory id.
async fn store_message(
    app: &AppState,
    agent: &str,
    text: &str,
    stamp: &serde_json::Map<String, Value>,
) -> A2aResult<String> {
    #[cfg(feature = "sal")]
    if is_postgres(app) {
        let ctx = crate::store::CallerContext::for_agent(agent);
        let id = app
            .store
            .notify_stamped(
                &ctx,
                agent,
                a2a::A2A_INBOX_SUBJECT,
                text,
                None,
                None,
                None,
                Some(stamp),
            )
            .await
            .map_err(|e| store_failure(&e))?;
        crate::write_events::agent_notified_webhook_postgres(
            app,
            &crate::write_events::AgentNotified {
                recipient_agent_id: agent,
                sender_agent_id: agent,
                inbox_row_id: &id,
                namespace: &crate::inbox_namespace(agent),
                content: text,
            },
        )
        .await;
        if let Ok(mem) = app.store.get(&ctx, &id).await {
            let _ = super::parity::fanout_or_pending(app, &mem).await;
        }
        return Ok(id);
    }
    let params = json!({
        (field_names::TARGET_AGENT_ID): agent,
        "title": a2a::A2A_INBOX_SUBJECT,
        "payload": text,
    });
    let (result, fanout_mem) = {
        let lock = app.db.lock().await;
        let ttl = lock.2.clone();
        let path = lock.1.clone();
        let result = crate::mcp::handle_notify_as_sender_stamped(
            &lock.0, &path, &params, &ttl, agent, stamp,
        );
        let mem = result
            .as_ref()
            .ok()
            .and_then(|v| v.get("id").and_then(Value::as_str))
            .and_then(|id| crate::db::get(&lock.0, id).ok().flatten());
        (result, mem)
    };
    let value = result.map_err(|e| match e {
        crate::errors::MemoryError::ValidationFailed(_) => {
            A2aError::invalid_params("message was rejected")
        }
        other => {
            tracing::warn!(target: "a2a", "a2a notify failure: {}", other.message());
            A2aError::internal()
        }
    })?;
    if let Some(mem) = fanout_mem.as_ref() {
        let _ = super::parity::fanout_or_pending(app, mem).await;
    }
    value
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(A2aError::internal)
}
