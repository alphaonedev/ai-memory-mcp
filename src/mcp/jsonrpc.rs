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

/// MCP protocol revision advertised in the `initialize` result's
/// `protocolVersion` field.
pub const PROTOCOL_REVISION: &str = "2024-11-05";

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
