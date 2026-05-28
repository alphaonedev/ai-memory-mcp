// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 (#1389) — MCP `memory_capture_turn` handler. Substrate-side
//! implementation of the L4 layer of the layered-capture architecture
//! per RFC-0001 (`docs/rfc/RFC-0001-mcp-turn-capture.md`).
//!
//! # What this tool does
//!
//! Hosts (Claude Code / Codex CLI / Gemini CLI / IDE plugins / future
//! MCP-aware harnesses) call `memory_capture_turn` once per
//! conversation turn to volunteer the turn content directly into the
//! substrate. The substrate stores it idempotently by
//! `(host_session_id, host_turn_index)` and writes a `signed_events`
//! row tagged `layer = "L4"` so audit can prove which layer caught
//! each turn.
//!
//! # Why L4 is THE FIX
//!
//! Layered defense (per architecture memo `f62cb182`):
//!
//! - **L1** — agent discipline (`memory_capture_nag`) catches the
//!   common case "agent forgot."
//! - **L2** — `recover-previous-session` catches SIGKILL between
//!   sessions on the same host.
//! - **L3** — substrate filesystem-notify watcher catches mid-session
//!   crashes + concurrent multi-session capture.
//! - **L4** — THIS tool — host volunteers turns directly via MCP
//!   protocol. No transcript scraping. No format coupling. The trust
//!   boundary is the protocol contract. **Survives 50 years of
//!   vendor churn** because the substrate doesn't depend on any
//!   single host's implementation details.
//!
//! # Performance contract
//!
//! Per issue #1394 + the operator's "optimal performance" directive:
//! synchronous dispatch < 10 ms p95 under release-build conditions.
//! Substrate path: sha256 of canonical bytes + dedup-table SELECT on
//! `(host_session_id, host_turn_index)` + (on miss) memory INSERT +
//! `transcript_line_dedup` INSERT + `signed_events` chain row in a
//! single transaction.
//!
//! # Idempotency contract (per RFC-0001 §"Idempotency contract")
//!
//! Two calls with the same `(host_session_id, host_turn_index)`
//! produce exactly one memory. The second call returns
//! `dedup_hit: true` + the existing memory_id. Re-delivery on host
//! reconnect is safe.
//!
//! # Status (v0.7.0 ship slice)
//!
//! The Request struct + Tool impl + dispatch wiring land first
//! (this commit). The substantive storage transaction lands in a
//! follow-up slice on the same branch (`feat/1389-layered-capture`)
//! — the skeleton handler returns a stub envelope with
//! `dedup_hit: false` + a placeholder memory_id so the wire shape
//! is exercisable from MCP clients during the implementation cycle.

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::mcp::registry::McpTool;

/// `memory_capture_turn` request body per RFC-0001 §"Tool input schema".
///
/// Field-by-field doc comments become the schemars-generated
/// `description` strings in the MCP `inputSchema`. The schema doubles
/// as the wire contract for every MCP-aware host that volunteers
/// turns.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
#[allow(dead_code)] // Skeleton phase — fields read by the storage
// transaction landing in the follow-up slice.
pub struct MemoryCaptureTurnRequest {
    /// Opaque identifier the host issues per conversation session.
    /// Stable across turns within a session; distinct across
    /// sessions. Used as one half of the dedup key
    /// `(host_session_id, host_turn_index)`.
    pub host_session_id: String,

    /// Monotonically increasing per-`(host_session_id)` turn counter.
    /// Starts at 0 for the first turn. The substrate uses
    /// `(host_session_id, host_turn_index)` as the canonical dedup
    /// key so re-delivery of the same turn is idempotent.
    pub host_turn_index: i64,

    /// Speaker classification — `user` / `assistant` / `tool_use` /
    /// `tool_result` / `system` / `other`. Drives downstream
    /// memory_kind assignment in the v0.8 decision-detector
    /// classifier.
    pub role: String,

    /// Verbatim turn text. The substrate preserves this byte-for-byte;
    /// classifiers run separately downstream via the existing
    /// atomiser / curator surface.
    pub content: String,

    /// Identifier for the host implementation (e.g. `"claude-code"`,
    /// `"codex"`, `"gemini"`, `"cursor"`, `"cline"`). Surfaced in the
    /// audit trail + the operator-facing per-host coverage report.
    /// When omitted, defaults to `"unknown"`.
    #[serde(default)]
    pub host_kind: Option<String>,

    /// Version string for the host implementation. Surfaced in the
    /// audit trail so future format drift can be diagnosed by host
    /// version.
    #[serde(default)]
    pub host_version: Option<String>,

    /// Optional summary of tool invocations within this assistant
    /// turn. Each entry is `{tool: string, brief: string}`. The
    /// substrate preserves the list verbatim but does not (at v0.7.0)
    /// classify or index per-tool-call.
    #[serde(default)]
    pub tool_calls: Vec<ToolCallSummary>,

    /// RFC3339 instant the host emitted the turn. Used as the
    /// recovered memory's `created_at` so the timeline matches the
    /// original conversation rather than the capture-call wall-clock.
    /// When omitted, the substrate stamps with its current clock.
    #[serde(default)]
    pub timestamp_iso: Option<String>,

    /// Optional Ed25519 signature over the canonical-bytes encoding
    /// `host_session_id || 0x00 || host_turn_index || 0x00 || role ||
    /// 0x00 || content`. When present + verified, the substrate
    /// writes `attest_level = "signed_by_peer"` on the resulting
    /// memory. When absent, `attest_level = "self_signed"`.
    #[serde(default)]
    pub host_signature_b64: Option<String>,

    /// Ed25519 pubkey the substrate should verify
    /// `host_signature_b64` against. The pubkey MUST be pre-enrolled
    /// via the existing federation peer-allowlist mechanism.
    /// Unenrolled pubkeys cause the call to fail with
    /// `HOST_PUBKEY_NOT_ENROLLED`.
    #[serde(default)]
    pub host_pubkey_b64: Option<String>,

    /// Substrate namespace the turn lands in. Defaults to the
    /// agent's resolved default namespace per the calling context.
    #[serde(default)]
    pub namespace: Option<String>,

    /// Optional arbitrary metadata the host wants to preserve
    /// alongside the turn. Reserved keys (`agent_id`, `entity_id`,
    /// `mentioned_entity_id`) follow the existing
    /// `crate::validate::RequestValidator` rules.
    #[serde(default)]
    pub metadata: Option<Value>,
}

/// Summary of one tool call within an assistant turn. Mirrors the
/// `crate::recover::parsers::ToolCallSummary` shape so L2/L3 +
/// L4 capture surfaces produce the same downstream memory shape.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
#[allow(dead_code)] // Skeleton phase — fields read by the storage
// transaction landing in the follow-up slice.
pub struct ToolCallSummary {
    /// Tool name (e.g. `"Bash"`, `"Read"`,
    /// `"mcp__memory__memory_store"`).
    pub tool: String,
    /// One-line target/brief. For `Bash`, the `description` arg; for
    /// `Read`, the file path; for an MCP tool, the first 1-2 fields
    /// of the request struct. Truncated to 200 chars by convention.
    pub brief: String,
}

/// Zero-sized `McpTool` registration for the v0.7.0 D1.6 recipe.
pub struct MemoryCaptureTurnTool;

impl McpTool for MemoryCaptureTurnTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_CAPTURE_TURN
    }

    fn description() -> &'static str {
        "L4 host-volunteered turn capture per RFC-0001 (mcp-turn-capture). \
         Idempotent by (host_session_id, host_turn_index)."
    }

    fn docs() -> &'static str {
        "v0.7.0 #1389 L4: host volunteers each conversation turn directly \
         via the MCP protocol. Substrate stores it idempotently and writes \
         a signed_events row tagged layer=L4. Replaces transcript-file \
         scraping with a clean protocol-level contract. Full design at \
         docs/rfc/RFC-0001-mcp-turn-capture.md. Closes the #1388 substrate \
         failure mode at the protocol layer."
    }

    fn input_schema() -> Value {
        let schema = schemars::schema_for!(MemoryCaptureTurnRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }

    fn family() -> &'static str {
        // Lifecycle — capture is a substrate-lifecycle primitive
        // (every host-volunteered turn produces one memory row).
        "lifecycle"
    }
}

/// Handler entrypoint dispatched from `crate::mcp::handle_request`.
///
/// Substantive storage logic (sha256 dedup table SELECT + memory
/// INSERT + transcript_line_dedup INSERT + signed_events row in a
/// single transaction) lands in a follow-up commit on this branch.
/// The skeleton here returns the wire-stable envelope shape so MCP
/// clients can exercise the surface during the implementation cycle.
///
/// # Errors
///
/// Returns a string-stable error code per the MCP-spec error
/// convention (see `crate::mcp::handle_request`'s 2025-03-26
/// `§"Tool result"` comment):
///
/// - `INVALID_INPUT: <reason>` — request failed deserialization or
///   schema validation.
/// - `HOST_PUBKEY_NOT_ENROLLED: <pubkey>` — `host_signature_b64`
///   present but `host_pubkey_b64` is not in the federation peer
///   allowlist.
/// - `SIGNATURE_INVALID: <detail>` — `host_signature_b64` did not
///   verify against `host_pubkey_b64`.
/// - `QUOTA_EXCEEDED: <namespace>` — per-namespace K8 quota
///   exhausted (when the storage slice lands).
pub fn handle_capture_turn(_conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let req: MemoryCaptureTurnRequest =
        serde_json::from_value(params.clone()).map_err(|e| format!("INVALID_INPUT: {e}"))?;

    // Wire-stable response envelope per RFC-0001 §"Tool result".
    // Skeleton: returns dedup_hit:false + a placeholder memory_id
    // until the storage transaction lands in the follow-up slice.
    Ok(json!({
        "memory_id": format!("placeholder-{}-{}",
            req.host_session_id, req.host_turn_index),
        "dedup_hit": false,
        "layer": "L4",
        "elapsed_ms": 0_u64,
        "skeleton_note": "v0.7.0 #1389 L4 substrate handler — storage transaction slice pending; \
            wire shape is stable per RFC-0001."
    }))
}

#[cfg(test)]
mod d1_6_1389_tests {
    //! D1.6 (#987) parity tests for the L4 `memory_capture_turn` tool.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;

    #[test]
    fn capture_turn_tool_metadata() {
        assert_eq!(MemoryCaptureTurnTool::name(), "memory_capture_turn");
        assert_eq!(MemoryCaptureTurnTool::family(), "lifecycle");
        // Description + docs are non-empty so the MCP capability
        // surface advertises a meaningful tool to discovery callers.
        assert!(!MemoryCaptureTurnTool::description().is_empty());
        assert!(!MemoryCaptureTurnTool::docs().is_empty());
    }

    #[test]
    fn input_schema_is_valid_json() {
        let schema = MemoryCaptureTurnTool::input_schema();
        // The schemars-derived schema must serialize as a JSON
        // object with required + properties keys per the JSON Schema
        // draft spec.
        let obj = schema.as_object().expect("schema is an object");
        assert!(
            obj.contains_key("properties"),
            "schema must advertise properties"
        );
        // Sanity-check that the four required fields are required.
        let required = obj
            .get("required")
            .and_then(Value::as_array)
            .expect("required is an array");
        let required_names: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
        for name in &["host_session_id", "host_turn_index", "role", "content"] {
            assert!(
                required_names.contains(name),
                "required must include {name}"
            );
        }
    }
}

#[cfg(test)]
mod handler_tests {
    //! Skeleton handler tests — the wire shape is stable; the
    //! placeholder behavior is exercised here. The substantive
    //! storage tests land in the follow-up commit alongside the
    //! transactional path.
    use super::*;

    fn fresh_conn() -> rusqlite::Connection {
        crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    #[test]
    fn handler_accepts_minimal_request() {
        let conn = fresh_conn();
        let resp = handle_capture_turn(
            &conn,
            &json!({
                "host_session_id": "session-a",
                "host_turn_index": 0,
                "role": "user",
                "content": "hello"
            }),
        )
        .expect("ok");
        assert_eq!(resp["dedup_hit"].as_bool(), Some(false));
        assert_eq!(resp["layer"].as_str(), Some("L4"));
        assert!(resp["memory_id"].as_str().is_some());
    }

    #[test]
    fn handler_rejects_missing_required_fields() {
        let conn = fresh_conn();
        let resp = handle_capture_turn(&conn, &json!({ "host_session_id": "x" }));
        let err = resp.expect_err("missing required fields must error");
        assert!(
            err.starts_with("INVALID_INPUT"),
            "error must use INVALID_INPUT prefix, got: {err}"
        );
    }

    #[test]
    fn handler_rejects_unknown_fields() {
        let conn = fresh_conn();
        let resp = handle_capture_turn(
            &conn,
            &json!({
                "host_session_id": "session-a",
                "host_turn_index": 0,
                "role": "user",
                "content": "hello",
                "rogue_field": "should reject"
            }),
        );
        let err = resp.expect_err("unknown field must error per schemars(deny_unknown_fields)");
        assert!(err.starts_with("INVALID_INPUT"), "got: {err}");
    }

    #[test]
    fn handler_accepts_full_request_with_tool_calls() {
        let conn = fresh_conn();
        let resp = handle_capture_turn(
            &conn,
            &json!({
                "host_session_id": "session-a",
                "host_turn_index": 5,
                "role": "assistant",
                "content": "running command",
                "host_kind": "claude-code",
                "host_version": "1.0.0",
                "tool_calls": [
                    {"tool": "Bash", "brief": "list files"}
                ],
                "timestamp_iso": "2026-05-28T12:00:00Z",
                "namespace": "test"
            }),
        )
        .expect("ok");
        // memory_id must encode both halves of the dedup key in the
        // skeleton's placeholder form.
        let memory_id = resp["memory_id"].as_str().expect("memory_id is a string");
        assert!(memory_id.contains("session-a"));
        assert!(memory_id.contains('5'));
    }
}
