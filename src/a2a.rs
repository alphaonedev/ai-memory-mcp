// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8444 - the Google Agent2Agent (A2A 1.0) standard binding, pure protocol
//! layer: JSON-RPC 2.0 envelope, the A2A error table, request parsing, the
//! Agent Card builder and the Task wire shape. No I/O, no auth, no storage -
//! those live in `handlers::a2a`.
//!
//! The wire types and error codes come from the official Linux Foundation
//! `a2a-lf` crate (operator-approved Option B), re-exported ONCE through
//! [`wire`]. Dispatch, authentication, the error-to-HTTP-status mapping and
//! storage stay first-party. No server or client trait of that project is
//! used.
//!
//! # What this binding serves (shape S1, posture P1)
//!
//! * `GET /.well-known/agent-card.json` - the Agent Card, behind the existing
//!   `api_key_auth` (an unauthenticated GET is `401`).
//! * `POST /api/v1/a2a` - ONE JSON-RPC 2.0 endpoint: `SendMessage` (answered
//!   synchronously: the call returns the COMPLETED task), `GetTask`,
//!   `ListTasks`, `CancelTask`.
//! * Declared unsupported, with the spec's typed errors: streaming and
//!   subscribe (`-32004`), extended card (`-32004`), the four push
//!   notification config methods (`-32003`).
//!
//! # Transport and versioning rules
//!
//! * S1 exposes the JSON-RPC binding ONLY. The `A2A-Version` rule
//!   ([`check_version`]) is enforced on that binding; if a REST binding is ever
//!   added it must call the same check so the gap cannot reappear.
//! * A request whose body is not JSON (`-32700`) or is not a JSON-RPC request
//!   object (`-32600`) is answered with HTTP `200` and a JSON-RPC error
//!   envelope, as JSON-RPC 2.0 over HTTP requires; every other error uses the
//!   status of [`http_status_for`].
//! * `ListTasks` `pageSize` is capped at [`MAX_PAGE_SIZE`] regardless of the
//!   caller's value; the response reports the effective size.

use std::collections::HashMap;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::storage::a2a_tasks::{A2aHistoryEntry, A2aTaskRow};

/// The ONE place the `a2a-lf` crate is named. Inside this crate `crate::a2a`
/// is this module, so the extern crate is always reached as `::a2a`.
pub mod wire {
    pub use ::a2a::{
        A2AError, AgentCapabilities, AgentCard, AgentInterface, AgentSkill, ApiKeySecurityScheme,
        Artifact, CancelTaskRequest, GetTaskRequest, JsonRpcError, JsonRpcId, JsonRpcResponse,
        ListTasksRequest, ListTasksResponse, Message, Part, PartContent, Role, SecurityRequirement,
        SecurityScheme, SendMessageRequest, SendMessageResponse, TRANSPORT_PROTOCOL_JSONRPC, Task,
        TaskState, TaskStatus, VERSION, error_code, methods,
    };
}

use wire::{
    A2AError, AgentCapabilities, AgentCard, AgentInterface, AgentSkill, ApiKeySecurityScheme,
    Artifact, JsonRpcId, JsonRpcResponse, Message, Part, PartContent, Role, SecurityScheme,
    SendMessageRequest, Task, TaskState, TaskStatus, error_code, methods,
};

/// The protocol version this binding speaks (`Major.Minor`).
pub const A2A_PROTOCOL_VERSION: &str = wire::VERSION;
/// Request and response header carrying the protocol version.
pub const HEADER_A2A_VERSION: &str = "A2A-Version";
/// JSON-RPC endpoint path.
pub const A2A_RPC_PATH: &str = "/api/v1/a2a";
/// Agent Card well-known path.
pub const AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
/// Inbox subject every inbound A2A message is stored under. The role and the
/// sender are NEVER part of the subject (both are remote-influenced).
pub const A2A_INBOX_SUBJECT: &str = "A2A SendMessage";
/// Required `jsonrpc` member value.
pub const JSONRPC_VERSION: &str = "2.0";

/// System metadata key: the AUTHENTICATED agent id the inbound content is
/// attributed to. Key name and value conventions are defined by #8443 (role
/// grounding); stamped directly here until that module lands on the chain.
// #8443/#8449 own the swap to the role-grounding key; whichever lands second does the swap.
pub const META_CONTENT_PRINCIPAL: &str = "content_principal"; // key defined by #8443
/// System metadata key: the remote-chosen role string, an UNTRUSTED label.
pub const META_A2A_ROLE: &str = "a2a_role";

/// Longest accepted `messageId` / `contextId` / `taskId` / role string.
pub const MAX_ID_LEN: usize = 128;

/// Text of the task status message a `SendMessage` reply carries when the
/// message is stored locally but its federation fan-out missed quorum.
pub const REPLICATION_PENDING_TEXT: &str =
    "stored locally; federation quorum not met, replication is pending";

/// Process-wide count of A2A messages whose federation fan-out missed quorum.
static REPLICATION_PENDING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Count one A2A message whose federation fan-out missed quorum.
pub fn note_replication_pending() {
    REPLICATION_PENDING.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// How many A2A messages missed federation quorum since the process started.
#[must_use]
pub fn replication_pending_total() -> u64 {
    REPLICATION_PENDING.load(std::sync::atomic::Ordering::Relaxed)
}

/// The agent status message of a task whose latest message is stored locally
/// but not yet replicated to federation quorum.
#[must_use]
pub fn replication_pending_message(task_id: &str, context_id: &str) -> Message {
    let mut m = Message::new(
        Role::Agent,
        vec![Part::text(REPLICATION_PENDING_TEXT.to_string())],
    );
    m.message_id = uuid::Uuid::new_v4().to_string();
    m.context_id = Some(context_id.to_string());
    m.task_id = Some(task_id.to_string());
    m
}

/// Bound on the compare-and-set attempts of one message completion. Each lost
/// attempt means another request moved the task in between; the bound turns
/// a pathological livelock into a `-32004` instead of an unbounded loop.
pub const A2A_COMPLETION_CAS_ATTEMPTS: usize = 8;
/// Message of the `-32603` internal error; never carries substrate text.
const INTERNAL_ERROR_MESSAGE: &str = "internal error";
/// `ListTasks` default page size (spec: 1..=100, default 50).
pub const DEFAULT_PAGE_SIZE: usize = 50;
/// Handler-side cap on `pageSize`: a larger request is clamped to this value
/// (never rejected, never honoured), so one call cannot read an unbounded page.
pub const MAX_PAGE_SIZE: usize = 100;

/// Stored task states (the `TASK_STATE_*` wire strings; the storage layer
/// keeps them as text, a unit test ties each to the crate's `TaskState`).
pub mod state {
    /// Accepted, not yet processing.
    pub const SUBMITTED: &str = "TASK_STATE_SUBMITTED";
    /// Being processed.
    pub const WORKING: &str = "TASK_STATE_WORKING";
    /// Finished successfully (terminal).
    pub const COMPLETED: &str = "TASK_STATE_COMPLETED";
    /// Finished with an error (terminal).
    pub const FAILED: &str = "TASK_STATE_FAILED";
    /// Canceled by the caller (terminal).
    pub const CANCELED: &str = "TASK_STATE_CANCELED";
    /// The states a task can still leave.
    pub const NON_TERMINAL: [&str; 2] = [SUBMITTED, WORKING];

    /// Whether `s` is terminal. An unreadable state counts as terminal
    /// (fail closed: it can no longer be changed).
    #[must_use]
    pub fn is_terminal(s: &str) -> bool {
        serde_json::from_value::<super::wire::TaskState>(serde_json::Value::String(s.to_string()))
            .map_or(true, |t| t.is_terminal())
    }
}

/// One A2A / JSON-RPC error: the spec code, the HTTP status this binding
/// answers with, and the message. The wire object is produced by the crate's
/// `A2AError::to_jsonrpc_error` (code, message, `google.rpc.ErrorInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A2aError {
    /// JSON-RPC error code.
    pub code: i32,
    /// HTTP status the binding answers with (first-party mapping).
    pub http_status: u16,
    /// Human-readable message (never echoes request content).
    pub message: String,
}

/// First-party error-code to HTTP-status table. The crate's own mapping
/// answers `501` for an unknown method; this binding answers `404`.
#[must_use]
pub fn http_status_for(code: i32) -> u16 {
    match code {
        // JSON-RPC over HTTP: a request that never became a valid call is
        // still a delivered HTTP exchange (conformance 272).
        error_code::PARSE_ERROR | error_code::INVALID_REQUEST => 200,
        error_code::TASK_NOT_FOUND | error_code::METHOD_NOT_FOUND => 404,
        error_code::INTERNAL_ERROR | error_code::INVALID_AGENT_RESPONSE => 500,
        _ => 400,
    }
}

impl A2aError {
    fn new(code: i32, message: &str) -> Self {
        Self {
            code,
            http_status: http_status_for(code),
            message: message.to_string(),
        }
    }

    /// `-32700` malformed JSON.
    #[must_use]
    pub fn parse_error() -> Self {
        Self::new(error_code::PARSE_ERROR, "invalid JSON payload")
    }
    /// `-32600` not a valid JSON-RPC request object.
    #[must_use]
    pub fn invalid_request(message: &str) -> Self {
        Self::new(error_code::INVALID_REQUEST, message)
    }
    /// `-32601` unknown method.
    #[must_use]
    pub fn method_not_found() -> Self {
        Self::new(error_code::METHOD_NOT_FOUND, "method not found")
    }
    /// `-32602` invalid params.
    #[must_use]
    pub fn invalid_params(message: &str) -> Self {
        Self::new(error_code::INVALID_PARAMS, message)
    }
    /// `-32603` internal error (HTTP 500).
    #[must_use]
    pub fn internal() -> Self {
        Self::new(error_code::INTERNAL_ERROR, INTERNAL_ERROR_MESSAGE)
    }
    /// `-32001` TaskNotFound: unknown id AND another caller's id (HTTP 404).
    #[must_use]
    pub fn task_not_found() -> Self {
        Self::new(error_code::TASK_NOT_FOUND, "task not found")
    }
    /// `-32002` TaskNotCancelable: the task is already terminal.
    #[must_use]
    pub fn task_not_cancelable() -> Self {
        Self::new(
            error_code::TASK_NOT_CANCELABLE,
            "task is in a terminal state and cannot be canceled",
        )
    }
    /// `-32003` PushNotificationNotSupported.
    #[must_use]
    pub fn push_not_supported() -> Self {
        Self::new(
            error_code::PUSH_NOTIFICATION_NOT_SUPPORTED,
            "push notifications are not supported",
        )
    }
    /// `-32004` UnsupportedOperation.
    #[must_use]
    pub fn unsupported_operation() -> Self {
        Self::new(
            error_code::UNSUPPORTED_OPERATION,
            "this operation is not supported",
        )
    }
    /// `-32004` UnsupportedOperation with a caller-actionable message (for
    /// example a follow-up to a task already in a terminal state; spec 3.1.1:
    /// terminal tasks "cannot accept further messages"). `message` must never
    /// echo request content.
    #[must_use]
    pub fn unsupported_operation_because(message: &str) -> Self {
        Self::new(error_code::UNSUPPORTED_OPERATION, message)
    }
    /// `-32004` for a follow-up message to a task of the caller that is in the
    /// terminal state `state` (a stored `TASK_STATE_*` string).
    #[must_use]
    pub fn task_terminal(state: &str) -> Self {
        Self::unsupported_operation_because(&format!(
            "task is in terminal state {state} and cannot accept further messages"
        ))
    }
    /// `-32004` for a follow-up that lost the race to another change of the
    /// same task before anything was stored (a retry can succeed).
    #[must_use]
    pub fn task_changed_concurrently() -> Self {
        Self::unsupported_operation_because(
            "task was modified concurrently and cannot accept this message; retry",
        )
    }
    /// `-32004` for a completion that ran out of compare-and-set attempts.
    /// The inbox memory is already stored (unlinked), so the message says
    /// nothing about a retry, which would deliver it twice.
    #[must_use]
    pub fn task_completion_exhausted() -> Self {
        Self::unsupported_operation_because(
            "task was modified concurrently and cannot accept this message",
        )
    }
    /// `-32005` ContentTypeNotSupported (a file part).
    #[must_use]
    pub fn content_type_not_supported() -> Self {
        Self::new(
            error_code::CONTENT_TYPE_NOT_SUPPORTED,
            "file parts are not supported; send text or data parts",
        )
    }
    /// `-32009` VersionNotSupported.
    #[must_use]
    pub fn version_not_supported() -> Self {
        Self::new(
            error_code::VERSION_NOT_SUPPORTED,
            "unsupported A2A-Version; this server speaks 1.0",
        )
    }

    /// The `error` member of the JSON-RPC envelope, with the
    /// `google.rpc.ErrorInfo` detail the spec asks for.
    #[must_use]
    pub fn to_error_object(&self) -> wire::JsonRpcError {
        A2AError::new(self.code, self.message.clone()).to_jsonrpc_error()
    }
}

/// Serialise a wire value; a serialisation failure is an internal error.
///
/// # Errors
///
/// `-32603` when the value cannot be serialised.
pub fn to_value<T: Serialize>(v: &T) -> Result<Value, A2aError> {
    serde_json::to_value(v).map_err(|e| {
        tracing::warn!(target: "a2a", "a2a serialisation failure: {e}");
        A2aError::internal()
    })
}

/// The body answered when an envelope cannot be serialised: a well-formed
/// JSON-RPC `-32603` with a `null` id (never a bare `null` body).
fn internal_error_envelope() -> Value {
    serde_json::json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": Value::Null,
        "error": {"code": error_code::INTERNAL_ERROR, "message": INTERNAL_ERROR_MESSAGE},
    })
}

/// The serialised envelope, or the fixed `-32603` envelope plus a warn log
/// when serialisation failed.
fn envelope_or_internal_error(serialised: Result<Value, serde_json::Error>) -> Value {
    serialised.unwrap_or_else(|e| {
        tracing::warn!(target: "a2a", "a2a envelope serialisation failure: {e}");
        internal_error_envelope()
    })
}

/// `{jsonrpc, id, error}` envelope.
#[must_use]
pub fn error_envelope(id: &JsonRpcId, err: &A2aError) -> Value {
    let resp = JsonRpcResponse::error(id.clone(), err.to_error_object());
    envelope_or_internal_error(serde_json::to_value(resp))
}

/// `{jsonrpc, id, result}` envelope.
#[must_use]
pub fn result_envelope(id: &JsonRpcId, result: Value) -> Value {
    envelope_or_internal_error(serde_json::to_value(JsonRpcResponse::success(
        id.clone(),
        result,
    )))
}

/// A parsed JSON-RPC request.
#[derive(Debug, Clone, PartialEq)]
pub struct RpcRequest {
    /// Echoed request id (string, integer or null).
    pub id: JsonRpcId,
    /// Method name.
    pub method: String,
    /// `params` (an empty object when absent).
    pub params: Value,
}

/// Parse a JSON-RPC 2.0 request body.
///
/// # Errors
///
/// `-32700` for malformed JSON and `-32600` for a body that is not a valid
/// request object. The echoed id is `null` whenever it cannot be trusted.
pub fn parse_rpc(body: &[u8]) -> Result<RpcRequest, (JsonRpcId, A2aError)> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| (JsonRpcId::Null, A2aError::parse_error()))?;
    let Some(obj) = value.as_object() else {
        return Err((
            JsonRpcId::Null,
            A2aError::invalid_request("request must be a JSON object"),
        ));
    };
    let id = match obj.get("id") {
        None | Some(Value::Null) => JsonRpcId::Null,
        Some(Value::String(s)) => JsonRpcId::String(s.clone()),
        Some(Value::Number(n)) if n.as_i64().is_some() => {
            JsonRpcId::Number(n.as_i64().unwrap_or_default())
        }
        Some(_) => {
            return Err((
                JsonRpcId::Null,
                A2aError::invalid_request("id must be a string, an integer or null"),
            ));
        }
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some(JSONRPC_VERSION) {
        return Err((id, A2aError::invalid_request("jsonrpc must be \"2.0\"")));
    }
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        return Err((id, A2aError::invalid_request("method is required")));
    };
    let params = match obj.get("params") {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(v @ Value::Object(_)) => v.clone(),
        Some(_) => {
            return Err((id, A2aError::invalid_params("params must be an object")));
        }
    };
    Ok(RpcRequest {
        id,
        method: method.to_string(),
        params,
    })
}

/// Check the `A2A-Version` request header: absent or `1.0` is accepted, any
/// other value is not served.
///
/// The spec (section on service parameters) says: "Agents MUST interpret empty
/// value as 0.3". This server does not speak 0.3, so an EMPTY value is read as
/// 0.3 and answered `-32009` VersionNotSupported (HTTP 400), exactly like any
/// other unsupported version. An ABSENT header is a different case: the
/// sentence covers an empty value, not a missing one, and every 1.0 client
/// that predates the header (or a plain HTTP tool) sends none, so absent is
/// served as `1.0`, the only version this endpoint can answer. Do not
/// "tighten" absent to an error or "relax" empty to `1.0`: either breaks one
/// of the two rules above (conformance 271 pins both).
///
/// # Errors
///
/// `-32009` for any version other than `1.0`.
pub fn check_version(header: Option<&str>) -> Result<(), A2aError> {
    match header.map(str::trim) {
        None | Some(A2A_PROTOCOL_VERSION) => Ok(()),
        Some(_) => Err(A2aError::version_not_supported()),
    }
}

/// The served methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `SendMessage`.
    SendMessage,
    /// `GetTask`.
    GetTask,
    /// `ListTasks`.
    ListTasks,
    /// `CancelTask`.
    CancelTask,
}

/// Map a method name to a served method, or the typed refusal.
///
/// # Errors
///
/// `-32004` for streaming / subscribe / extended card, `-32003` for the push
/// notification config methods, `-32601` for anything else.
pub fn classify_method(name: &str) -> Result<Method, A2aError> {
    match name {
        methods::SEND_MESSAGE => Ok(Method::SendMessage),
        methods::GET_TASK => Ok(Method::GetTask),
        methods::LIST_TASKS => Ok(Method::ListTasks),
        methods::CANCEL_TASK => Ok(Method::CancelTask),
        methods::SEND_STREAMING_MESSAGE
        | methods::SUBSCRIBE_TO_TASK
        | methods::GET_EXTENDED_AGENT_CARD => Err(A2aError::unsupported_operation()),
        methods::CREATE_PUSH_CONFIG
        | methods::GET_PUSH_CONFIG
        | methods::LIST_PUSH_CONFIGS
        | methods::DELETE_PUSH_CONFIG => Err(A2aError::push_not_supported()),
        _ => Err(A2aError::method_not_found()),
    }
}

fn valid_label(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(|c| !c.is_control())
}

/// Deserialise typed request params; any shape error is `-32602`.
///
/// # Errors
///
/// `-32602` when `params` does not match `T`.
pub fn parse_params<T: serde::de::DeserializeOwned>(params: &Value) -> Result<T, A2aError> {
    serde_json::from_value(params.clone()).map_err(|_| A2aError::invalid_params("invalid params"))
}

/// Convert an optional `historyLength` to a count. The spec requires a
/// non-negative integer ("Must be non-negative integer"), so a negative value
/// is a validation error (conformance 195).
///
/// # Errors
///
/// `-32602` for a negative `historyLength`.
pub fn history_length(raw: Option<i32>) -> Result<Option<usize>, A2aError> {
    raw.map(|n| {
        usize::try_from(n)
            .map_err(|_| A2aError::invalid_params("historyLength must be a non-negative integer"))
    })
    .transpose()
}

/// A validated inbound message.
#[derive(Debug, Clone, PartialEq)]
pub struct SendInput {
    /// The message as received (its ids go into the content-free history
    /// entry; its content goes only to the inbox memory).
    pub message: Message,
    /// Remote-chosen role string (an UNTRUSTED label).
    pub role: String,
    /// Text parts concatenated in order, `data` parts as JSON text.
    pub text: String,
}

/// Validate `SendMessage` params and flatten the message to text.
///
/// # Errors
///
/// `-32602` for a malformed message, `-32005` for a file part (`raw`, `url`
/// or the legacy `file` member), `-32003` when push notification config is
/// requested.
pub fn parse_send_message(params: &Value) -> Result<SendInput, A2aError> {
    // The crate's `Part` has no legacy `file` variant, so the refusal of file
    // content is decided on the raw JSON before typed parsing.
    if let Some(parts) = params
        .get("message")
        .and_then(|m| m.get("parts"))
        .and_then(Value::as_array)
    {
        let has_file = parts
            .iter()
            .filter_map(Value::as_object)
            .any(|p| p.contains_key("raw") || p.contains_key("url") || p.contains_key("file"));
        if has_file {
            return Err(A2aError::content_type_not_supported());
        }
    }
    let req: SendMessageRequest = parse_params(params)?;
    if req
        .configuration
        .as_ref()
        .is_some_and(|c| c.task_push_notification_config.is_some())
    {
        return Err(A2aError::push_not_supported());
    }
    let message = req.message;
    if !valid_label(&message.message_id, MAX_ID_LEN) {
        return Err(A2aError::invalid_params("message.messageId is required"));
    }
    for (key, value) in [
        ("contextId", message.context_id.as_deref()),
        ("taskId", message.task_id.as_deref()),
    ] {
        if value.is_some_and(|v| !valid_label(v, MAX_ID_LEN)) {
            return Err(A2aError::invalid_params(&format!("{key} is invalid")));
        }
    }
    if message.role == Role::Unspecified {
        return Err(A2aError::invalid_params("message.role is required"));
    }
    if message.parts.is_empty() {
        return Err(A2aError::invalid_params("message.parts must not be empty"));
    }
    let mut chunks: Vec<String> = Vec::with_capacity(message.parts.len());
    for part in &message.parts {
        match &part.content {
            PartContent::Text(t) => chunks.push(t.clone()),
            PartContent::Data(d) => chunks.push(d.to_string()),
            PartContent::Raw(_) | PartContent::Url(_) => {
                return Err(A2aError::content_type_not_supported());
            }
        }
    }
    let role = match serde_json::to_value(&message.role) {
        Ok(Value::String(s)) => s,
        _ => return Err(A2aError::invalid_params("message.role is invalid")),
    };
    Ok(SendInput {
        message,
        role,
        text: chunks.concat(),
    })
}

/// The system metadata stamped onto the inbox memory at formation:
/// `content_principal` is the AUTHENTICATED agent id (from the credential,
/// never a header or the body) and `a2a_role` the remote-chosen role label.
#[must_use]
pub fn system_stamp(authenticated_agent: &str, role: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(
        META_CONTENT_PRINCIPAL.to_string(),
        Value::String(authenticated_agent.to_string()),
    );
    m.insert(META_A2A_ROLE.to_string(), Value::String(role.to_string()));
    m
}

/// The artifact acknowledging the stored memory.
#[must_use]
pub fn receipt_artifact(memory_id: &str) -> Artifact {
    Artifact {
        artifact_id: format!("receipt-{memory_id}"),
        name: Some("memory-receipt".to_string()),
        description: None,
        parts: vec![
            Part::text(format!("stored as memory {memory_id}")).with_media_type("text/plain"),
        ],
        metadata: None,
        extensions: None,
    }
}

/// A2A timestamp text (RFC 3339, UTC, millisecond precision).
#[must_use]
pub fn format_timestamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// The current time as A2A timestamp text.
#[must_use]
pub fn now_timestamp() -> String {
    format_timestamp(Utc::now())
}

/// The content-free history entries of a stored row, oldest first.
///
/// # Errors
///
/// `-32603` when the stored history does not decode (corrupt JSON is refused,
/// never replaced by an empty history).
pub fn history_entries(row: &A2aTaskRow) -> Result<Vec<A2aHistoryEntry>, A2aError> {
    serde_json::from_value(row.history.clone()).map_err(|_| {
        tracing::warn!(target: "a2a", "stored a2a task has an unreadable history");
        A2aError::internal()
    })
}

/// The last `history_length` entries (`None` keeps all, `Some(0)` none), so the
/// handler reads only the memories the response will show.
#[must_use]
pub fn history_window(
    entries: Vec<A2aHistoryEntry>,
    history_length: Option<usize>,
) -> Vec<A2aHistoryEntry> {
    let keep = history_length.map_or(entries.len(), |n| n.min(entries.len()));
    entries[entries.len() - keep..].to_vec()
}

/// The wire `Message` of one history entry, rendered from the inbox memory's
/// `content` (read through the normal memory read path by the handler).
#[must_use]
pub fn message_from_entry(entry: &A2aHistoryEntry, content: &str) -> Message {
    let role =
        serde_json::from_value(Value::String(entry.role.clone())).unwrap_or(Role::Unspecified);
    let mut m = Message::new(role, vec![Part::text(content.to_string())]);
    m.message_id = entry.message_id.clone();
    m.context_id = Some(entry.context_id.clone());
    m.task_id = Some(entry.task_id.clone());
    m
}

/// The typed Task for a stored row and its already rendered `history` (the
/// handler reads each entry's content from the inbox memory; an empty vector
/// omits `history`).
///
/// # Errors
///
/// `-32603` when the stored row does not decode (never expected: rows are
/// written by this module).
pub fn task_from_row(
    row: &A2aTaskRow,
    history: Vec<Message>,
    include_artifacts: bool,
) -> Result<Task, A2aError> {
    let decode = |what: &str| {
        tracing::warn!(target: "a2a", "stored a2a task has an unreadable {what}");
        A2aError::internal()
    };
    let task_state: TaskState =
        serde_json::from_value(Value::String(row.state.clone())).map_err(|_| decode("state"))?;
    let timestamp = DateTime::parse_from_rfc3339(&row.status_timestamp)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| decode("timestamp"))?;
    let history = (!history.is_empty()).then_some(history);
    let artifacts = if include_artifacts {
        let a: Vec<Artifact> =
            serde_json::from_value(row.artifacts.clone()).map_err(|_| decode("artifacts"))?;
        Some(a)
    } else {
        None
    };
    let metadata: HashMap<String, Value> =
        serde_json::from_value(row.metadata.clone()).map_err(|_| decode("metadata"))?;
    Ok(Task {
        id: row.id.clone(),
        context_id: row.context_id.clone(),
        status: TaskStatus {
            state: task_state,
            message: None,
            timestamp: Some(timestamp),
        },
        artifacts,
        history,
        metadata: Some(metadata),
    })
}

/// Env var naming the externally reachable base URL of this daemon (scheme and
/// authority, no path), advertised in the Agent Card. When it is unset or not
/// a valid base URL the card advertises the daemon's own scheme and bind
/// address instead. The request's `Host` and `X-Forwarded-Proto` headers are
/// NEVER consulted (they are caller-controlled).
pub const ENV_PUBLIC_URL: &str = "AI_MEMORY_PUBLIC_URL";
/// Longest accepted public base URL.
const MAX_PUBLIC_URL_LEN: usize = 255;
/// Base URL advertised before the daemon has recorded its own (tests, or a
/// card requested through a router built without a daemon).
const DEFAULT_CARD_BASE_URL: &str = "http://localhost";

/// The valid form of a configured public base URL: `http://` or `https://`
/// authority only: a non-empty host and an optional port 1-65535; no path,
/// userinfo, query, fragment, whitespace, control characters or backslash;
/// at most 255 bytes; trailing slashes trimmed. `None` for anything else
/// (fail closed). The daemon serves A2A at its own fixed route; a path prefix
/// belongs to the reverse proxy in front of it, never to the advertised base.
///
/// decision: a non-empty RFC 3986 host and a canonical 1-65535 port over the
/// bare RFC 3986 authority because RFC 9110 requires a host for http(s) and an
/// empty host, a malformed host or an out-of-range port would make the card
/// advertise an unusable base.
#[must_use]
pub fn valid_public_url(raw: &str) -> Option<String> {
    let t = raw.trim().trim_end_matches('/');
    let rest = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))?;
    let ok = t.len() <= MAX_PUBLIC_URL_LEN
        && rest.chars().all(|c| {
            !c.is_whitespace() && !c.is_control() && !matches!(c, '@' | '?' | '#' | '\\' | '/')
        })
        && valid_authority(rest);
    ok.then(|| t.to_string())
}

/// `host[:port]` of a public base URL (RFC 3986 `host [ ":" port ]`). The
/// host is non-empty: a bracketed IPv6 literal (parsed as an
/// [`std::net::Ipv6Addr`], with an optional `%25` zone of unreserved or
/// percent-encoded characters), or a `reg-name` (ALPHA, DIGIT, `-._~`,
/// sub-delims and `%HH` escapes, so an IPv4 address is a `reg-name`). The
/// port, when a colon follows the host, is 1 to 5 digits in 1..=65535 with no
/// leading zero, so the published URL never echoes a non-canonical port.
///
/// decision: the RFC 3986 grammar over the earlier "any byte but a bracket"
/// predicate because a host with angle brackets, quotes or a non-ASCII letter
/// would make the card advertise an unusable base (sec r5 INFO-2).
fn valid_authority(authority: &str) -> bool {
    let (host_ok, port) = if let Some(inner) = authority.strip_prefix('[') {
        let Some((literal, after)) = inner.split_once(']') else {
            return false;
        };
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p),
            None if after.is_empty() => None,
            None => return false,
        };
        (valid_ipv6_literal(literal), port)
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (valid_reg_name(host), Some(port)),
            None => (valid_reg_name(authority), None),
        }
    };
    host_ok && port.is_none_or(valid_port)
}

/// A port of 1 to 5 digits, 1..=65535, without a leading zero.
fn valid_port(port: &str) -> bool {
    (1..=5).contains(&port.len())
        && port.bytes().all(|b| b.is_ascii_digit())
        && (port.len() == 1 || !port.starts_with('0'))
        && port.parse::<u16>().is_ok_and(|n| n >= 1)
}

/// The text between the brackets of an IPv6 host: an address, optionally
/// followed by `%25` and a non-empty zone id (RFC 6874).
fn valid_ipv6_literal(literal: &str) -> bool {
    let (addr, zone) = match literal.split_once("%25") {
        Some((addr, zone)) => (addr, Some(zone)),
        None => (literal, None),
    };
    addr.parse::<std::net::Ipv6Addr>().is_ok()
        && zone.is_none_or(|z| !z.is_empty() && escaped_text(z, is_unreserved))
}

/// A non-empty RFC 3986 `reg-name`: unreserved, sub-delims and `%HH` only.
fn valid_reg_name(host: &str) -> bool {
    !host.is_empty() && escaped_text(host, |b| is_unreserved(b) || is_sub_delim(b))
}

/// RFC 3986 `unreserved`: ALPHA, DIGIT and `-._~`.
const fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// RFC 3986 `sub-delims`.
const fn is_sub_delim(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

/// Every byte of `text` satisfies `allowed`, or is a `%` followed by two hex
/// digits. One pass, no allocation; a non-ASCII byte is never allowed.
fn escaped_text(text: &str, allowed: fn(u8) -> bool) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hex_ok = bytes
                .get(i + 1..i + 3)
                .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit));
            if !hex_ok {
                return false;
            }
            i += 3;
        } else if allowed(b) {
            i += 1;
        } else {
            return false;
        }
    }
    true
}

/// The base URL the Agent Card advertises: a valid configured `public_url`
/// wins; otherwise `{scheme}://{bind_addr}` where the scheme is `https` when
/// the daemon serves TLS. Pure: the caller supplies every input.
#[must_use]
pub fn resolve_card_base_url(public_url: Option<&str>, tls: bool, bind_addr: &str) -> String {
    if let Some(url) = public_url {
        if let Some(valid) = valid_public_url(url) {
            return valid;
        }
        tracing::warn!(
            target: "a2a",
            "{ENV_PUBLIC_URL} is not a valid http(s) base URL; advertising the bind address"
        );
    }
    let scheme = if tls { "https" } else { "http" };
    format!("{scheme}://{bind_addr}")
}

static CARD_BASE_URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Record the card base URL once, at daemon start (the first call wins).
pub fn set_card_base_url(base: String) {
    let _ = CARD_BASE_URL.set(base);
}

/// Daemon start: resolve the card base URL from [`ENV_PUBLIC_URL`], the TLS
/// state and the bind address, and record it. Never reads request headers.
pub fn init_card_base_url(tls: bool, bind_addr: &str) {
    let configured = std::env::var(ENV_PUBLIC_URL).ok();
    set_card_base_url(resolve_card_base_url(configured.as_deref(), tls, bind_addr));
}

/// The recorded card base URL, or a fixed default before one is set.
#[must_use]
pub fn card_base_url() -> &'static str {
    CARD_BASE_URL
        .get()
        .map_or(DEFAULT_CARD_BASE_URL, String::as_str)
}

/// The Agent Card. Declares exactly what is served: JSON-RPC only, no
/// streaming, no push, no extended card, no extensions, one inbox skill, the
/// `apiKey` (header `x-api-key`) security scheme, and no `signatures`. The
/// description names no namespace, agent id or deployment fact.
#[must_use]
pub fn agent_card(base: &str) -> AgentCard {
    let modes = || vec!["text/plain".to_string(), crate::MIME_JSON.to_string()];
    AgentCard {
        name: "ai-memory".to_string(),
        description: "Persistent memory for AI agents. Messages sent to this agent are stored in the authenticated caller's memory inbox.".to_string(),
        version: crate::PKG_VERSION.to_string(),
        supported_interfaces: vec![AgentInterface::new(
            format!("{base}{A2A_RPC_PATH}"),
            wire::TRANSPORT_PROTOCOL_JSONRPC,
        )],
        capabilities: AgentCapabilities {
            streaming: Some(false),
            push_notifications: Some(false),
            extensions: Some(Vec::new()),
            extended_agent_card: Some(false),
        },
        default_input_modes: modes(),
        default_output_modes: modes(),
        skills: vec![AgentSkill {
            id: "memory-inbox".to_string(),
            name: "Memory inbox".to_string(),
            description: "Store a message in the authenticated caller's memory inbox and track it as a task.".to_string(),
            tags: vec!["memory".to_string(), "inbox".to_string()],
            examples: None,
            input_modes: None,
            output_modes: None,
            security_requirements: None,
        }],
        provider: None,
        documentation_url: None,
        icon_url: None,
        security_schemes: Some(HashMap::from([(
            "apiKey".to_string(),
            SecurityScheme::ApiKey(ApiKeySecurityScheme {
                location: "header".to_string(),
                name: "x-api-key".to_string(),
                description: Some(
                    "Per-agent API key presented in the x-api-key request header.".to_string(),
                ),
            }),
        )])),
        security_requirements: Some(vec![HashMap::from([("apiKey".to_string(), Vec::new())])]),
        signatures: None,
    }
}

/// Recursively rebuild `v` with every object's keys sorted, whatever the
/// `serde_json` map implementation is.
fn sort_keys(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let sorted: std::collections::BTreeMap<&String, Value> =
                m.iter().map(|(k, x)| (k, sort_keys(x))).collect();
            Value::Object(sorted.into_iter().map(|(k, x)| (k.clone(), x)).collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(sort_keys).collect()),
        other => other.clone(),
    }
}

/// Canonical bytes of a serialisable wire value: sorted keys, compact. The
/// crate stores card maps in a `HashMap` (nondeterministic order), so anything
/// signed or attested over Agent Card bytes MUST be taken from this form.
///
/// # Errors
///
/// `-32603` when the value cannot be serialised.
pub fn canonical_bytes<T: Serialize>(v: &T) -> Result<Vec<u8>, A2aError> {
    let value = to_value(v)?;
    serde_json::to_vec(&sort_keys(&value)).map_err(|_| A2aError::internal())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn id(n: i64) -> JsonRpcId {
        JsonRpcId::Number(n)
    }

    #[test]
    fn parse_rpc_distinguishes_malformed_json_from_invalid_request() {
        let (_, e) = parse_rpc(b"{not json").expect_err("malformed");
        assert_eq!(e.code, -32700);
        let (_, e) = parse_rpc(b"[1]").expect_err("array");
        assert_eq!(e.code, -32600);
        let (got, e) = parse_rpc(br#"{"jsonrpc":"1.0","id":7,"method":"x"}"#).expect_err("version");
        assert_eq!((got, e.code), (id(7), -32600));
        let (_, e) = parse_rpc(br#"{"jsonrpc":"2.0","id":1.5,"method":"x"}"#).expect_err("frac id");
        assert_eq!(e.code, -32600);
    }

    #[test]
    fn classify_method_table() {
        assert_eq!(classify_method("SendMessage"), Ok(Method::SendMessage));
        for m in [
            "SendStreamingMessage",
            "SubscribeToTask",
            "GetExtendedAgentCard",
        ] {
            assert_eq!(classify_method(m).expect_err("unsupported").code, -32004);
        }
        for m in [
            "CreateTaskPushNotificationConfig",
            "GetTaskPushNotificationConfig",
            "ListTaskPushNotificationConfigs",
            "DeleteTaskPushNotificationConfig",
        ] {
            assert_eq!(classify_method(m).expect_err("push").code, -32003);
        }
        assert_eq!(classify_method("Nope").expect_err("unknown").code, -32601);
    }

    #[test]
    fn http_status_table_is_first_party() {
        for (code, status) in [
            (-32001, 404),
            (-32002, 400),
            (-32003, 400),
            (-32004, 400),
            (-32005, 400),
            (-32006, 500),
            (-32007, 400),
            (-32008, 400),
            (-32009, 400),
            (-32700, 200),
            (-32600, 200),
            (-32601, 404),
            (-32602, 400),
            (-32603, 500),
        ] {
            assert_eq!(http_status_for(code), status, "code {code}");
        }
    }

    #[test]
    fn version_header_rule() {
        assert!(check_version(None).is_ok());
        assert!(check_version(Some("1.0")).is_ok());
        assert_eq!(check_version(Some("0.3")).expect_err("old").code, -32009);
        assert_eq!(check_version(Some("")).expect_err("empty").code, -32009);
    }

    #[test]
    fn send_message_flattens_text_and_data_and_rejects_files() {
        let ok = json!({"message": {"messageId": "m1", "role": "ROLE_USER",
            "parts": [{"text": "a"}, {"data": {"k": 1}}, {"text": "b"}]}});
        let got = parse_send_message(&ok).expect("parse");
        assert_eq!(got.text, "a{\"k\":1}b");
        assert_eq!(got.role, "ROLE_USER");
        for member in ["raw", "url", "file"] {
            let bad = json!({"message": {"messageId": "m1", "role": "ROLE_USER",
                "parts": [{member: "x"}]}});
            assert_eq!(parse_send_message(&bad).expect_err("file").code, -32005);
        }
        let unknown_role = json!({"message": {"messageId": "m1", "role": "operator",
            "parts": [{"text": "a"}]}});
        assert_eq!(
            parse_send_message(&unknown_role).expect_err("role").code,
            -32602
        );
        let push = json!({"message": {"messageId": "m1", "role": "ROLE_USER",
            "parts": [{"text": "a"}]},
            "configuration": {"taskPushNotificationConfig": {"url": "https://x", "taskId": "t"}}});
        assert_eq!(parse_send_message(&push).expect_err("push").code, -32003);
    }

    #[test]
    fn stamp_carries_authenticated_principal_and_role_label() {
        let m = system_stamp("alice", "ROLE_AGENT");
        assert_eq!(m[META_CONTENT_PRINCIPAL], "alice");
        assert_eq!(m[META_A2A_ROLE], "ROLE_AGENT");
    }

    #[test]
    fn card_declares_only_what_is_served() {
        let c = to_value(&agent_card("https://h.example")).expect("card");
        assert_eq!(c["capabilities"]["streaming"], false);
        assert_eq!(c["capabilities"]["pushNotifications"], false);
        assert!(c.get("signatures").is_none());
        assert_eq!(c["supportedInterfaces"][0]["protocolBinding"], "JSONRPC");
        assert!(c["securitySchemes"].get("mtls").is_none());
    }

    #[test]
    fn stored_state_strings_match_the_crate_task_state() {
        for (s, t) in [
            (state::SUBMITTED, TaskState::Submitted),
            (state::WORKING, TaskState::Working),
            (state::COMPLETED, TaskState::Completed),
            (state::FAILED, TaskState::Failed),
            (state::CANCELED, TaskState::Canceled),
        ] {
            assert_eq!(serde_json::to_value(&t).expect("ser"), json!(s));
            assert_eq!(state::is_terminal(s), t.is_terminal());
        }
        assert!(
            state::is_terminal("garbage"),
            "unreadable state fails closed"
        );
    }

    // --- serialisation evidence: exact wire JSON, pinned against literals
    // --- taken from the A2A 1.0 specification examples. A future a2a-lf bump
    // --- that changes the wire shape turns these red.

    const SPEC_SEND_MESSAGE_REQUEST: &str =
        r#"{"message":{"messageId":"msg-1","role":"ROLE_USER","parts":[{"text":"hello"}]}}"#;
    const SPEC_TASK: &str = r#"{"id":"task-1","contextId":"ctx-1","status":{"state":"TASK_STATE_COMPLETED","timestamp":"2026-10-31T12:00:00Z"},"artifacts":[{"artifactId":"receipt-m1","name":"memory-receipt","parts":[{"text":"stored as memory m1","mediaType":"text/plain"}]}],"history":[{"messageId":"msg-1","role":"ROLE_USER","parts":[{"text":"hello"}]}],"metadata":{"storage":"ai-memory-inbox"}}"#;
    const SPEC_AGENT_CARD: &str = r#"{"name":"ai-memory","description":"Persistent memory for AI agents. Messages sent to this agent are stored in the authenticated caller's memory inbox.","version":"@VERSION@","supportedInterfaces":[{"url":"https://h.example/api/v1/a2a","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],"capabilities":{"streaming":false,"pushNotifications":false,"extensions":[],"extendedAgentCard":false},"defaultInputModes":["text/plain","application/json"],"defaultOutputModes":["text/plain","application/json"],"skills":[{"id":"memory-inbox","name":"Memory inbox","description":"Store a message in the authenticated caller's memory inbox and track it as a task.","tags":["memory","inbox"]}],"securitySchemes":{"apiKey":{"apiKeySecurityScheme":{"location":"header","name":"x-api-key","description":"Per-agent API key presented in the x-api-key request header."}}},"securityRequirements":[{"schemes":{"apiKey":{"list":[]}}}]}"#;

    #[test]
    fn pin_send_message_request_round_trips_exactly() {
        let req: SendMessageRequest =
            serde_json::from_str(SPEC_SEND_MESSAGE_REQUEST).expect("deserialize");
        assert_eq!(
            serde_json::to_string(&req).expect("serialize"),
            SPEC_SEND_MESSAGE_REQUEST
        );
        let again: SendMessageRequest =
            serde_json::from_value(serde_json::to_value(&req).expect("ser")).expect("de");
        assert_eq!(again, req);
    }

    #[test]
    fn pin_task_with_status_artifacts_history_round_trips_exactly() {
        let task: Task = serde_json::from_str(SPEC_TASK).expect("deserialize");
        assert_eq!(serde_json::to_string(&task).expect("serialize"), SPEC_TASK);
        assert_eq!(task.status.state, TaskState::Completed);
        let again: Task =
            serde_json::from_value(serde_json::to_value(&task).expect("ser")).expect("de");
        assert_eq!(again, task);
        // The first-party receipt artifact is the one pinned above.
        let art = receipt_artifact("m1");
        assert_eq!(Some(vec![art]), task.artifacts);
    }

    #[test]
    fn pin_agent_card_round_trips_exactly() {
        // The card holds HashMap fields (upstream a2a-rs #361): compare PARSED
        // values, never bytes.
        let want = SPEC_AGENT_CARD.replace("@VERSION@", crate::PKG_VERSION);
        let card = agent_card("https://h.example");
        let got: Value = serde_json::to_value(&card).expect("serialize");
        let want_value: Value = serde_json::from_str(&want).expect("literal parses");
        assert_eq!(got, want_value);
        let again: AgentCard = serde_json::from_str(&want).expect("deserialize");
        assert_eq!(again, card);
    }

    #[test]
    fn agent_card_canonical_bytes_are_stable_with_many_security_schemes() {
        let scheme = |name: &str| {
            SecurityScheme::ApiKey(ApiKeySecurityScheme {
                location: "header".to_string(),
                name: name.to_string(),
                description: None,
            })
        };
        let build = |names: &[&str]| {
            let mut card = agent_card("https://h.example");
            let mut schemes = HashMap::new();
            for n in names {
                schemes.insert((*n).to_string(), scheme(n));
            }
            // The requirement list is an ordered array; only the scheme map
            // insertion order (hence HashMap iteration order) varies.
            let reqs = ["k1", "k2", "k3"]
                .iter()
                .map(|n| HashMap::from([((*n).to_string(), Vec::new())]))
                .collect::<Vec<HashMap<String, Vec<String>>>>();
            card.security_schemes = Some(schemes);
            card.security_requirements = Some(reqs);
            card
        };
        let a = build(&["k1", "k2", "k3"]);
        let b = build(&["k3", "k1", "k2"]);
        let first = canonical_bytes(&a).expect("canonical");
        for _ in 0..8 {
            assert_eq!(canonical_bytes(&b).expect("canonical"), first);
            assert_eq!(canonical_bytes(&a).expect("canonical"), first);
        }
    }

    #[test]
    fn public_url_validation_and_card_base_resolution() {
        // #8444 r2 code MEDIUM-3 / LOW-7: the card URL comes from configuration
        // and the daemon's own scheme, never from the request.
        assert_eq!(
            resolve_card_base_url(None, false, "127.0.0.1:9077"),
            "http://127.0.0.1:9077"
        );
        assert_eq!(
            resolve_card_base_url(None, true, "127.0.0.1:9077"),
            "https://127.0.0.1:9077",
            "a TLS daemon advertises https"
        );
        assert_eq!(
            resolve_card_base_url(Some("https://mem.example.org/"), false, "0.0.0.0:9077"),
            "https://mem.example.org",
            "a configured public URL wins and is trimmed"
        );
        // Userinfo URL assembled at runtime so no credential-shaped literal sits in the source.
        let userinfo_url = format!("https://{}@evil.example", ["user", "pw"].join(":"));
        // #8444 r4 sec INFO-1: a control character, built at runtime.
        let control_url = format!("https://h{}.example", char::from(1_u8));
        for hostile in [
            "javascript:alert(1)",
            "http://",
            "https://a b/c",
            userinfo_url.as_str(),
            "https://evil.example/?x=1",
            "https://evil.example#f",
            "https://mem.example.org/prefix",
            "ftp://x.example",
            "https://a\\b",
            "",
            control_url.as_str(),
            "https://:8443",
            "https://h.example:99999",
            "https://h.example:65536",
            "https://h.example:",
            "https://h.example:0",
            "https://h.example:8a",
        ] {
            assert_eq!(
                resolve_card_base_url(Some(hostile), true, "1.2.3.4:5"),
                "https://1.2.3.4:5",
                "invalid public url {hostile:?} must be ignored"
            );
        }
        assert!(valid_public_url(&format!("https://{}", "a".repeat(300))).is_none());
        // #8444 r4 sec INFO-2: the accepted authority forms.
        for good in [
            "https://h.example:8443",
            "http://127.0.0.1:1",
            "https://h.example:65535",
            "https://[::1]:9077",
            "https://[::1]",
        ] {
            assert_eq!(valid_public_url(good).as_deref(), Some(good), "{good}");
        }
        assert!(valid_public_url("https://[::1]x").is_none());
        assert!(valid_public_url("https://[]:80").is_none());
    }

    /// RFC 3986 `reg-name` characters beyond ALPHA / DIGIT (unreserved
    /// punctuation and sub-delims), written out independently of the code
    /// under test so the sweep below is an oracle, not a tautology.
    const REG_NAME_PUNCT_8444: &str = "-._~!$&'()*+,;=";

    #[test]
    fn port_with_a_leading_zero_is_refused_8444() {
        // #8444 r5 code INFO-B: a non-canonical port is never echoed.
        for bad in [
            "https://h.example:08443",
            "https://h.example:00080",
            "https://h.example:01",
            "http://h.example:00",
            "https://[::1]:08443",
        ] {
            assert!(valid_public_url(bad).is_none(), "{bad}");
            assert_eq!(
                resolve_card_base_url(Some(bad), true, "1.2.3.4:5"),
                "https://1.2.3.4:5",
                "{bad}"
            );
        }
        for good in ["https://h.example:80", "https://h.example:1"] {
            assert_eq!(valid_public_url(good).as_deref(), Some(good), "{good}");
        }
    }

    #[test]
    fn bracket_checks_are_pinned_8444() {
        // #8444 r5 sec INFO-1: an unbalanced bracket and a stray bracket in
        // a reg-name each refuse on their own.
        for bad in [
            "https://[::1",
            "https://h]x.example",
            "https://h[x.example",
            "https://[::1]]",
            "https://[[::1]]",
            "https://[::1]x",
            "https://[]:80",
        ] {
            assert!(valid_public_url(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn host_predicate_is_rfc_3986_8444() {
        // #8444 r5 sec INFO-2: a bracketed host is an IPv6 literal (optional
        // `%25` zone), anything else is an RFC 3986 reg-name.
        for bad in [
            "https://[evil]",
            "https://[not-v6]:80",
            "https://[1.2.3.4]",
            "https://[::1%25]",
            "https://[::1%eth0]",
            "https://[::1%25e th]",
            "https://h<x>.example",
            "https://h\"x.example",
            "https://h{x}.example",
            "https://h|x.example",
            "https://h%2.example",
            "https://h%zzx.example",
            "https://h%.example",
            "https://h%2",
            "https://h\u{e9}x.example",
            "https://\u{200b}.example",
        ] {
            assert!(valid_public_url(bad).is_none(), "{bad}");
        }
        for good in [
            "https://[::1]",
            "https://[2001:db8::1]:8443",
            "https://[fe80::1%25eth0]",
            "https://[::ffff:1.2.3.4]",
            "https://h.example",
            "http://127.0.0.1:9077",
            "https://h_x.example",
            "https://h~x.example",
            "https://h%2Fx.example",
            "https://a.b-c.example:65535",
        ] {
            assert_eq!(valid_public_url(good).as_deref(), Some(good), "{good}");
        }
    }

    #[test]
    fn reg_name_byte_sweep_matches_the_rfc_set_8444() {
        // Every ASCII byte in the middle of a host: accepted exactly when it
        // is ALPHA, DIGIT, unreserved punctuation or a sub-delim. `%` needs
        // two hex digits and `:` begins a (non-numeric) port, so both refuse
        // on their own.
        for b in 0_u8..=127 {
            let c = char::from(b);
            let url = format!("https://h{c}x.example");
            let expected = c.is_ascii_alphanumeric() || REG_NAME_PUNCT_8444.contains(c);
            assert_eq!(
                valid_public_url(&url).is_some(),
                expected,
                "byte {b:#04x} in {url:?}"
            );
        }
    }

    #[test]
    fn hostile_public_url_stays_linear_8444() {
        // 100K+ inputs of every shape that reaches the host predicate refuse
        // in a bounded time (the length bound short-circuits before any scan).
        const BIG: usize = 120_000;
        const CEILING: std::time::Duration = std::time::Duration::from_millis(500);
        let started = std::time::Instant::now();
        for url in [
            format!("https://{}", "a".repeat(BIG)),
            format!("https://[{}]", ":".repeat(BIG)),
            format!("https://{}:80", "%".repeat(BIG)),
            format!("https://h.example:{}", "0".repeat(BIG)),
            format!("https://{}", "[".repeat(BIG)),
        ] {
            assert!(valid_public_url(&url).is_none());
        }
        assert!(started.elapsed() < CEILING, "{:?}", started.elapsed());
    }

    #[test]
    fn negative_history_length_is_invalid_params() {
        // #8444 r2 code LOW-8.
        assert_eq!(history_length(None), Ok(None));
        assert_eq!(history_length(Some(0)), Ok(Some(0)));
        assert_eq!(history_length(Some(3)), Ok(Some(3)));
        let e = history_length(Some(-5)).expect_err("negative");
        assert_eq!((e.code, e.http_status), (-32602, 400));
    }

    #[test]
    fn serialisation_failure_answers_a_well_formed_internal_error() {
        // #8444 r2 code LOW-4: never a bare `null` body.
        let failure = serde_json::from_str::<Value>("{").expect_err("invalid json");
        let body = envelope_or_internal_error(Err(failure));
        assert_eq!(
            body,
            json!({"jsonrpc": "2.0", "id": null,
                   "error": {"code": -32603, "message": "internal error"}})
        );
        let ok = envelope_or_internal_error(Ok(json!({"k": 1})));
        assert_eq!(ok, json!({"k": 1}));
    }

    #[test]
    fn terminal_follow_up_errors_are_unsupported_operation() {
        // #8444 r2 code MEDIUM-1 / sec MEDIUM-2.
        let e = A2aError::task_terminal("TASK_STATE_COMPLETED");
        assert_eq!((e.code, e.http_status), (-32004, 400));
        assert!(e.message.contains("TASK_STATE_COMPLETED"));
        let e = A2aError::task_changed_concurrently();
        assert_eq!((e.code, e.http_status), (-32004, 400));
        let e = A2aError::task_completion_exhausted();
        assert_eq!((e.code, e.http_status), (-32004, 400));
        assert!(!e.message.contains("retry"), "{e:?}");
    }

    #[test]
    fn history_window_keeps_the_last_entries() {
        let entries = (0..4)
            .map(|i| A2aHistoryEntry {
                message_id: format!("m{i}"),
                ..A2aHistoryEntry::default()
            })
            .collect::<Vec<_>>();
        assert_eq!(history_window(entries.clone(), None).len(), 4);
        assert_eq!(history_window(entries.clone(), Some(0)).len(), 0);
        let last = history_window(entries.clone(), Some(2));
        assert_eq!(last[0].message_id, "m2");
        assert_eq!(history_window(entries, Some(99)).len(), 4);
    }

    #[test]
    fn rendered_history_message_carries_ids_and_content() {
        let entry = A2aHistoryEntry {
            message_id: "m1".into(),
            role: "ROLE_USER".into(),
            context_id: "c1".into(),
            task_id: "t1".into(),
            memory_id: "mem".into(),
        };
        let m = message_from_entry(&entry, "hello");
        assert_eq!(m.message_id, "m1");
        assert_eq!(m.role, Role::User);
        assert_eq!(m.context_id.as_deref(), Some("c1"));
        assert_eq!(m.task_id.as_deref(), Some("t1"));
        assert_eq!(m.text(), Some("hello"));
    }

    #[test]
    fn canonical_bytes_match_a_golden_string() {
        // #8444 r2 code INFO-1: a golden byte string, independent of the
        // implementation under test.
        let map = HashMap::from([("k3", 3), ("k1", 1), ("k2", 2)]);
        let value = json!({"b": 1, "a": {"d": 4, "c": [{"z": 0, "y": 1}]}});
        assert_eq!(
            canonical_bytes(&map).expect("canonical"),
            br#"{"k1":1,"k2":2,"k3":3}"#
        );
        assert_eq!(
            canonical_bytes(&value).expect("canonical"),
            br#"{"a":{"c":[{"y":1,"z":0}],"d":4},"b":1}"#
        );
    }

    fn error_object_without_timestamp(e: &A2aError) -> Value {
        let mut v = serde_json::to_value(e.to_error_object()).expect("ser");
        v["data"][0]["metadata"]
            .as_object_mut()
            .expect("metadata")
            .remove("timestamp");
        v
    }

    #[test]
    fn pin_error_task_not_found_32001() {
        let got = error_object_without_timestamp(&A2aError::task_not_found());
        assert_eq!(
            got,
            json!({"code": -32001, "message": "task not found", "data": [{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": "TASK_NOT_FOUND",
                "domain": "a2a-protocol.org",
                "metadata": {}
            }]})
        );
        let env = error_envelope(&id(1), &A2aError::task_not_found());
        assert_eq!(env["jsonrpc"], "2.0");
        assert_eq!(env["id"], 1);
        assert_eq!(env["error"]["code"], -32001);
        assert!(env.get("result").is_none());
    }

    #[test]
    fn pin_error_unsupported_operation_32004() {
        let got = error_object_without_timestamp(&A2aError::unsupported_operation());
        assert_eq!(
            got,
            json!({"code": -32004, "message": "this operation is not supported", "data": [{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": "UNSUPPORTED_OPERATION",
                "domain": "a2a-protocol.org",
                "metadata": {}
            }]})
        );
    }

    #[test]
    fn round_trip_every_emitted_wire_struct() {
        let msg = Message::new(
            Role::Agent,
            vec![Part::text("t"), Part::data(json!({"k": 1}))],
        );
        let art = receipt_artifact("m9");
        let status = TaskStatus {
            state: TaskState::Working,
            message: None,
            timestamp: Some(Utc::now()),
        };
        let resp = wire::ListTasksResponse {
            tasks: vec![],
            next_page_token: String::new(),
            page_size: 50,
            total_size: 0,
        };
        macro_rules! round_trip {
            ($t:ty, $v:expr) => {{
                let v: $t = $v;
                let s = serde_json::to_string(&v).expect("ser");
                let back: $t = serde_json::from_str(&s).expect("de");
                assert_eq!(back, v, stringify!($t));
            }};
        }
        round_trip!(Message, msg.clone());
        round_trip!(Artifact, art);
        round_trip!(TaskStatus, status);
        round_trip!(wire::ListTasksResponse, resp);
        round_trip!(AgentCard, agent_card("http://localhost"));
        round_trip!(
            wire::SendMessageResponse,
            wire::SendMessageResponse::Message(msg)
        );
        round_trip!(wire::JsonRpcError, A2aError::internal().to_error_object());
        round_trip!(JsonRpcId, JsonRpcId::String("x".to_string()));
    }
}
