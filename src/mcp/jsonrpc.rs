// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! JSON-RPC 2.0 wire-layer constants (#1558 batch 3).
//!
//! The MCP stdio transport speaks JSON-RPC 2.0; every version tag,
//! reserved error code, method name, and protocol-revision string the
//! dispatcher emits or matches on lives here as one named const. These
//! are wire-contract values — a drifted copy at one site silently
//! breaks interop with every MCP client, so scattering them as inline
//! literals is exactly the failure mode the #1558 campaign removes.
//!
//! Error codes are the JSON-RPC 2.0 spec's reserved range
//! (<https://www.jsonrpc.org/specification#error_object>).

/// The JSON-RPC protocol version tag carried in every request and
/// response envelope (`"jsonrpc": "2.0"`).
pub const VERSION: &str = "2.0";

/// Invalid JSON was received by the server (spec `-32700 Parse error`).
pub const PARSE_ERROR: i64 = -32700;

/// The JSON sent is not a valid Request object (spec `-32600 Invalid
/// Request`).
pub const INVALID_REQUEST: i64 = -32600;

/// The method does not exist / is not available (spec `-32601 Method
/// not found`). Also used for `tools/call` against an unknown or
/// not-loaded tool — the MCP-idiomatic mapping.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// Invalid method parameter(s) (spec `-32602 Invalid params`).
pub const INVALID_PARAMS: i64 = -32602;

/// Internal JSON-RPC error (spec `-32603 Internal error`). Used for
/// application refusals that are not a protocol violation, e.g. a
/// record-stop write fence on `tools/call`.
pub const INTERNAL_ERROR: i64 = -32603;

/// MCP protocol revisions this server implements end to end, NEWEST FIRST
/// (#6157). `initialize` echoes the client's requested `protocolVersion`
/// when it is a member and otherwise answers with the newest entry (the
/// spec's "respond with another version you support" downgrade); see
/// [`negotiate_protocol_revision`].
///
/// The list is deliberately truthful: a revision belongs here only after
/// every behavioural delta of that revision is implemented and tested.
/// `2025-03-26` is NOT listed because it makes JSON-RPC batch receipt a
/// MUST and adds the Streamable HTTP transport; the stdio loop parses one
/// request object per line and answers a JSON array with `-32700`, so
/// claiming it would advertise semantics the server does not implement.
/// `2025-06-18` and `2026-07-28` are likewise unaudited. The pin
/// `tests/mcp_protocol_revision_ssot_6157.rs` keeps every fixture and doc
/// that names a `protocolVersion` inside this list.
pub const SUPPORTED_PROTOCOL_REVISIONS: &[&str] = &[NEWEST_PROTOCOL_REVISION];

/// The newest entry of [`SUPPORTED_PROTOCOL_REVISIONS`]: what a client that
/// asks for an unsupported (or no) revision is answered with. Keep this the
/// first element of the list.
pub const NEWEST_PROTOCOL_REVISION: &str = "2024-11-05";

/// Longest slice of a client-supplied `protocolVersion` echoed into the
/// stderr diagnostic (the value is untrusted and rendered `{:?}`-escaped).
const DIAGNOSTIC_ECHO_MAX_CHARS: usize = 64;

/// Resolve the `protocolVersion` to answer an `initialize` with.
///
/// Returns `(revision, downgraded)`. A string `params.protocolVersion`
/// that is a member of [`SUPPORTED_PROTOCOL_REVISIONS`] is echoed with
/// `downgraded == false`. An unsupported, missing or non-string value
/// yields the newest supported revision with `downgraded == true`, so the
/// caller can emit a diagnostic. Total: it never fails and never panics
/// (fail closed to the newest revision the server really speaks).
#[must_use]
pub fn negotiate_protocol_revision(params: &serde_json::Value) -> (&'static str, bool) {
    match params
        .get("protocolVersion")
        .and_then(serde_json::Value::as_str)
        .and_then(|asked| {
            SUPPORTED_PROTOCOL_REVISIONS
                .iter()
                .copied()
                .find(|r| *r == asked)
        }) {
        Some(supported) => (supported, false),
        None => (NEWEST_PROTOCOL_REVISION, true),
    }
}

/// The stderr line emitted when `initialize` downgrades the client
/// (#6157). Never carries more than [`DIAGNOSTIC_ECHO_MAX_CHARS`] of the
/// untrusted request value, `{:?}`-escaped.
#[must_use]
pub fn protocol_downgrade_diagnostic(params: &serde_json::Value, answered: &str) -> String {
    let asked = match params.get("protocolVersion") {
        None => "<missing>".to_string(),
        Some(serde_json::Value::String(s)) => {
            let clipped: String = s.chars().take(DIAGNOSTIC_ECHO_MAX_CHARS).collect();
            format!("{clipped:?}")
        }
        Some(_) => "<non-string>".to_string(),
    };
    format!(
        "ai-memory: MCP initialize downgrade: client protocolVersion {asked} is not supported; responding with {answered} (supported: {SUPPORTED_PROTOCOL_REVISIONS:?})"
    )
}

/// `initialize` — MCP handshake; carries `clientInfo` + capabilities.
pub const METHOD_INITIALIZE: &str = "initialize";

/// `notifications/initialized` — post-handshake client notification.
pub const METHOD_NOTIFICATIONS_INITIALIZED: &str = "notifications/initialized";

/// `ping` — liveness probe.
pub const METHOD_PING: &str = "ping";

/// `tools/list` — tool-catalog enumeration.
pub const METHOD_TOOLS_LIST: &str = "tools/list";

/// `tools/call` — tool dispatch.
pub const METHOD_TOOLS_CALL: &str = "tools/call";

/// `prompts/list` — prompt-catalog enumeration.
pub const METHOD_PROMPTS_LIST: &str = "prompts/list";

/// `prompts/get` — prompt-content fetch.
pub const METHOD_PROMPTS_GET: &str = "prompts/get";

/// `resources/list` — resource-catalog enumeration (declared for
/// wire-shape completeness; the dispatcher currently has no resources
/// surface).
pub const METHOD_RESOURCES_LIST: &str = "resources/list";

/// `resources/read` — resource fetch (declared for wire-shape
/// completeness; see [`METHOD_RESOURCES_LIST`]).
pub const METHOD_RESOURCES_READ: &str = "resources/read";
