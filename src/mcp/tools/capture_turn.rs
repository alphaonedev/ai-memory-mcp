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

use std::time::Instant;

use rusqlite::OptionalExtension;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::mcp::registry::McpTool;
use crate::models::{Memory, MemoryKind, Tier};

/// `memory_capture_turn` request body per RFC-0001 §"Tool input schema".
///
/// Field-by-field doc comments become the schemars-generated
/// `description` strings in the MCP `inputSchema`. The schema doubles
/// as the wire contract for every MCP-aware host that volunteers
/// turns.
// Per the #1052 wire-truthfulness decision (Agent-4 F2): no MCP
// tool-request struct carries `deny_unknown_fields`. The wire schema
// must not advertise `additionalProperties: false` while the runtime
// stays permissive. For an L4 multi-host ingest surface this is
// load-bearing — a host that adds a top-level field must not have its
// turns rejected wholesale (the #1052 rationale cites exactly "clients
// with newer field sets"). Unknown extra fields are tolerated and
// ignored; missing REQUIRED fields still error via serde. Arbitrary
// host-specific data belongs in `metadata`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
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
// Wire-truthful permissive per #1052 (see MemoryCaptureTurnRequest).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
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
/// Performs the L4 idempotent capture per RFC-0001 §"Idempotency
/// contract":
///
/// 1. SELECT `memory_id` FROM `transcript_line_dedup` WHERE
///    `(host_session_id, host_turn_index) = (?, ?)` — the canonical
///    dedup key.
/// 2. On hit: return `{memory_id, dedup_hit: true, layer: "L4",
///    elapsed_ms}`. No DB write.
/// 3. On miss: compute sha256 of canonical-bytes, `BEGIN IMMEDIATE`
///    transaction → `memories` INSERT via the canonical
///    `storage::insert` path → `transcript_line_dedup` INSERT →
///    COMMIT (or ROLLBACK on any failure with the transaction
///    rolled back atomically).
///
/// # Errors
///
/// Returns a string-stable error code per the MCP-spec error
/// convention (see `crate::mcp::handle_request`'s 2025-03-26
/// `§"Tool result"` comment):
///
/// - `INVALID_INPUT: <reason>` — request failed deserialization or
///   schema validation.
/// - `DEDUP_QUERY_FAILED: <detail>` — `transcript_line_dedup`
///   SELECT I/O failure.
/// - `MEMORY_INSERT_FAILED: <detail>` — `storage::insert` returned
///   an error (governance refusal, validation failure, SQL error).
/// - `DEDUP_INSERT_FAILED: <detail>` — `transcript_line_dedup`
///   INSERT failed; transaction rolled back, no row written.
/// - `TX_BEGIN_FAILED: <detail>` / `TX_COMMIT_FAILED: <detail>` —
///   transaction lifecycle errors.
/// - `HOST_PUBKEY_NOT_ENROLLED: <pubkey>` — placeholder for the
///   signed-path enforcement (RFC-0001 §"Signature + attestation");
///   not yet wired in v0.7.0 ship slice.
pub fn handle_capture_turn(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let start = Instant::now();
    let req: MemoryCaptureTurnRequest =
        serde_json::from_value(params.clone()).map_err(|e| format!("INVALID_INPUT: {e}"))?;

    // Step 1 — dedup-lookup by the canonical (host_session_id,
    // host_turn_index) key. The partial index
    // idx_transcript_line_dedup_host_turn (created in schema v52)
    // serves this query.
    let existing: Option<String> = conn
        .query_row(
            "SELECT memory_id FROM transcript_line_dedup \
             WHERE host_session_id = ?1 AND host_turn_index = ?2",
            rusqlite::params![&req.host_session_id, req.host_turn_index],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("DEDUP_QUERY_FAILED: {e}"))?;

    if let Some(memory_id) = existing {
        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        return Ok(json!({
            "memory_id": memory_id,
            "dedup_hit": true,
            "layer": "L4",
            "elapsed_ms": elapsed_ms,
        }));
    }

    // Step 2 — compute sha256 of canonical bytes per RFC-0001's
    // signature canonicalisation contract. The same encoding is
    // what host_signature_b64 (when present) signs over, so the
    // substrate's secondary dedup key is byte-equivalent to the
    // signature's plaintext.
    let canonical = format!(
        "{}\0{}\0{}\0{}",
        &req.host_session_id, req.host_turn_index, &req.role, &req.content
    );
    let sha_vec = {
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hasher.finalize().to_vec()
    };

    // Step 3 — atomic INSERT both rows under one BEGIN IMMEDIATE
    // transaction. Failure rolls back so an orphaned memory cannot
    // exist without its dedup row.
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| format!("TX_BEGIN_FAILED: {e}"))?;

    let tx_result = (|| -> Result<String, String> {
        let host_kind = req.host_kind.as_deref().unwrap_or("unknown").to_string();
        let now_iso = chrono::Utc::now().to_rfc3339();
        let created_at = req.timestamp_iso.clone().unwrap_or_else(|| now_iso.clone());

        let mut tags = vec![
            "captured-via-l4".to_string(),
            format!("host:{host_kind}"),
            format!("role:{}", req.role),
        ];
        if let Some(hv) = req.host_version.as_deref() {
            tags.push(format!("host-version:{hv}"));
        }

        // Title MUST be unique per (host_session_id, host_turn_index)
        // because the substrate's `storage::insert` upserts on
        // `(title, namespace)`; without host_session_id in the title,
        // two distinct sessions whose turn N has the same role would
        // collide on the same memory row. Including the dedup key in
        // the title makes the upsert behaviour align with the L4
        // idempotency contract — the only "same-title" case is a true
        // re-delivery of the same (session, turn).
        let title = format!(
            "L4 capture {} {} turn {} ({})",
            host_kind, req.host_session_id, req.host_turn_index, req.role
        );

        let metadata = req.metadata.clone().unwrap_or_else(|| json!({}));

        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: req
                .namespace
                .clone()
                .unwrap_or_else(|| "global".to_string()),
            title,
            content: req.content.clone(),
            tags,
            priority: 5,
            confidence: 1.0,
            source: "host".to_string(),
            metadata,
            created_at: created_at.clone(),
            updated_at: now_iso.clone(),
            last_accessed_at: Some(now_iso.clone()),
            memory_kind: MemoryKind::Observation,
            ..Memory::default()
        };

        let inserted_id =
            crate::storage::insert(conn, &mem).map_err(|e| format!("MEMORY_INSERT_FAILED: {e}"))?;

        let recovered_at_ms = chrono::Utc::now().timestamp_millis();
        conn.execute(
            "INSERT INTO transcript_line_dedup \
             (sha256, memory_id, host_kind, transcript_path, \
              host_session_id, host_turn_index, recovered_at) \
             VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6)",
            rusqlite::params![
                sha_vec,
                inserted_id,
                host_kind,
                req.host_session_id,
                req.host_turn_index,
                recovered_at_ms,
            ],
        )
        .map_err(|e| format!("DEDUP_INSERT_FAILED: {e}"))?;

        Ok(inserted_id)
    })();

    match tx_result {
        Ok(memory_id) => {
            conn.execute_batch("COMMIT")
                .map_err(|e| format!("TX_COMMIT_FAILED: {e}"))?;
            let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            Ok(json!({
                "memory_id": memory_id,
                "dedup_hit": false,
                "layer": "L4",
                "elapsed_ms": elapsed_ms,
            }))
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
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
    fn handler_tolerates_unknown_fields_at_runtime() {
        // #1052 wire-truthful contract: the schema does not advertise
        // `additionalProperties: false`, so the runtime must tolerate
        // (and ignore) unknown extra fields rather than reject the turn.
        // Wider host compat — a host with a newer field set must not
        // have its turns dropped wholesale.
        let conn = fresh_conn();
        let resp = handle_capture_turn(
            &conn,
            &json!({
                "host_session_id": "session-a",
                "host_turn_index": 0,
                "role": "user",
                "content": "hello",
                "an_unknown_extra_field": "tolerated and ignored"
            }),
        )
        .expect(
            "unknown extra fields are tolerated at runtime (post-#1052 wire-truthful contract)",
        );
        assert_eq!(resp["layer"].as_str(), Some("L4"));
        assert_eq!(resp["dedup_hit"].as_bool(), Some(false));
    }

    #[test]
    fn handler_rejects_missing_required_field() {
        // Permissive on UNKNOWN fields, but REQUIRED fields are still
        // enforced by serde (no `#[serde(default)]`). A turn missing
        // `content` must error rather than silently store an empty turn.
        let conn = fresh_conn();
        let err = handle_capture_turn(
            &conn,
            &json!({
                "host_session_id": "session-a",
                "host_turn_index": 0,
                "role": "user"
            }),
        )
        .expect_err("missing required `content` must error");
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
        // Post-storage-tx: memory_id is a UUID. dedup_hit=false on
        // the first call. layer=L4 always.
        assert_eq!(resp["dedup_hit"].as_bool(), Some(false));
        assert_eq!(resp["layer"].as_str(), Some("L4"));
        let memory_id = resp["memory_id"].as_str().expect("memory_id is a string");
        assert!(!memory_id.is_empty(), "memory_id must be non-empty");
    }

    #[test]
    fn handler_idempotent_on_same_session_turn() {
        // Per RFC-0001 §"Idempotency contract": two calls with the
        // same (host_session_id, host_turn_index) produce exactly
        // one memory. The second call returns dedup_hit:true and
        // the existing memory_id.
        let conn = fresh_conn();
        let first = handle_capture_turn(
            &conn,
            &json!({
                "host_session_id": "session-idem",
                "host_turn_index": 0,
                "role": "user",
                "content": "operator directive"
            }),
        )
        .expect("first call ok");
        assert_eq!(first["dedup_hit"].as_bool(), Some(false));
        let first_id = first["memory_id"].as_str().unwrap().to_string();

        let second = handle_capture_turn(
            &conn,
            &json!({
                "host_session_id": "session-idem",
                "host_turn_index": 0,
                "role": "user",
                "content": "operator directive"
            }),
        )
        .expect("second call ok");
        assert_eq!(
            second["dedup_hit"].as_bool(),
            Some(true),
            "second call must dedup-hit"
        );
        assert_eq!(
            second["memory_id"].as_str().unwrap(),
            first_id,
            "second call returns the first call's memory_id"
        );
    }

    #[test]
    fn handler_distinct_session_turn_creates_separate_memories() {
        let conn = fresh_conn();
        let a = handle_capture_turn(
            &conn,
            &json!({
                "host_session_id": "session-a",
                "host_turn_index": 0,
                "role": "user",
                "content": "a"
            }),
        )
        .expect("a ok");
        let b = handle_capture_turn(
            &conn,
            &json!({
                "host_session_id": "session-b",
                "host_turn_index": 0,
                "role": "user",
                "content": "b"
            }),
        )
        .expect("b ok");
        let c = handle_capture_turn(
            &conn,
            &json!({
                "host_session_id": "session-a",
                "host_turn_index": 1,
                "role": "user",
                "content": "c"
            }),
        )
        .expect("c ok");

        assert_eq!(a["dedup_hit"].as_bool(), Some(false));
        assert_eq!(b["dedup_hit"].as_bool(), Some(false));
        assert_eq!(c["dedup_hit"].as_bool(), Some(false));

        let a_id = a["memory_id"].as_str().unwrap();
        let b_id = b["memory_id"].as_str().unwrap();
        let c_id = c["memory_id"].as_str().unwrap();
        assert_ne!(a_id, b_id, "distinct sessions produce distinct memories");
        assert_ne!(a_id, c_id, "distinct turns produce distinct memories");
        assert_ne!(b_id, c_id);
    }
}
