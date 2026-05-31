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

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64_STD;
use rusqlite::OptionalExtension;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::mcp::registry::McpTool;
use crate::models::{Memory, MemoryKind, Tier};
use crate::signed_events::{self, SignedEvent};

/// Env var carrying the operator's per-host Ed25519 pubkey allowlist
/// for L4 `memory_capture_turn` signature verification (#1414).
/// Comma-separated base64-encoded 32-byte pubkeys. Unset / empty =
/// no host signatures accepted (every `host_signature_b64` +
/// `host_pubkey_b64` payload errors with `HOST_PUBKEY_NOT_ENROLLED`).
///
/// Mirrors the `AI_MEMORY_ADMIN_AGENT_IDS` shape — an operator-
/// curated allowlist read at call time, no daemon-restart required
/// for enrollment changes (each call re-reads the env). Documented
/// in CLAUDE.md §"Environment Variables".
pub(crate) const L4_HOST_PUBKEY_ALLOWLIST_ENV: &str = "AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST";

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
    /// classify or index per-tool-call. Reserved for v0.7.x atom-
    /// per-tool indexing; the field is wire-stable today so hosts
    /// can already populate it without breakage.
    #[serde(default)]
    #[allow(dead_code)]
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
/// - `HOST_PUBKEY_NOT_ENROLLED: <pubkey>` — `host_pubkey_b64` is not
///   on the operator's L4 host-pubkey allowlist
///   (`AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST` env). Per #1414.
/// - `SIGNED_EVENTS_APPEND_FAILED: <detail>` — substrate failed to
///   write the L4 audit row. Per #1415.
///
/// # Security (post-#1413 critical fix)
///
/// - **agent_id agreement** — when `req.metadata.agent_id` is present
///   it MUST equal the resolved `caller_agent_id` (mirroring
///   `resolve_http_agent_id`'s body-header agreement contract).
///   Mismatch returns `INVALID_INPUT` and refuses the write.
/// - **Signature verification** — when `host_signature_b64` and
///   `host_pubkey_b64` are present, the pubkey is checked against the
///   `AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST` env-var allowlist
///   (`HOST_PUBKEY_NOT_ENROLLED` on miss) and the signature is verified
///   via Ed25519 over the canonical-bytes encoding
///   `host_session_id || 0x00 || host_turn_index || 0x00 || role ||
///   0x00 || content` (`INVALID_INPUT: signature_verification_failed`
///   on mismatch). On success the L4 audit row carries
///   `attest_level = "signed_by_peer"`; absent both fields yields
///   `attest_level = "self_signed"`; exactly one of the two fields
///   present errors with `INVALID_INPUT`.
/// - **`signed_events` chain row** — the substrate writes one row per
///   successful capture inside the BEGIN IMMEDIATE transaction with
///   `event_type = "memory_capture_turn"`, the resolved `attest_level`,
///   and `payload_hash = sha256(canonical bytes)` so audit can prove
///   which layer caught each turn (#1415).
pub fn handle_capture_turn(
    conn: &rusqlite::Connection,
    params: &Value,
    caller_agent_id: Option<&str>,
) -> Result<Value, String> {
    let start = Instant::now();
    let req: MemoryCaptureTurnRequest =
        serde_json::from_value(params.clone()).map_err(|e| format!("INVALID_INPUT: {e}"))?;

    // v0.7.0 #1413 — resolve effective caller for the agent_id agreement
    // check + signed_events row attribution. MCP stdio captures the host
    // identity at `initialize.clientInfo.name`; when present, the
    // dispatcher threads it via `ctx.mcp_client`. When absent, we still
    // mint a per-request fallback so audit attribution is never empty.
    let caller = caller_agent_id.unwrap_or("anonymous:mcp-unknown");

    // v0.7.0 #1413 — agent_id agreement check. If the caller stamped a
    // `metadata.agent_id` it MUST equal the resolved caller — otherwise
    // an attacker with MCP-stdio access could forge memories attributed
    // to other identities. Mirrors `resolve_http_agent_id`'s body-header
    // agreement contract.
    if let Some(meta_agent) = req
        .metadata
        .as_ref()
        .and_then(|v| v.get("agent_id"))
        .and_then(|v| v.as_str())
        && meta_agent != caller
    {
        return Err(format!(
            "INVALID_INPUT: metadata.agent_id ({meta_agent:?}) does not match resolved caller ({caller:?})"
        ));
    }

    // v0.7.0 #1414 — host-signature verification. The wire schema
    // advertises a signed-by-peer path; the handler must actually
    // enforce it. Cases:
    //   (sig, pubkey) both Some → check allowlist + verify Ed25519
    //   exactly one Some → INVALID_INPUT (paired-fields contract)
    //   both None → unsigned ("self_signed") capture path
    let canonical = format!(
        "{}\0{}\0{}\0{}",
        &req.host_session_id, req.host_turn_index, &req.role, &req.content
    );
    let sha_vec = {
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hasher.finalize().to_vec()
    };

    let (sig_bytes_opt, attest_level): (Option<Vec<u8>>, String) =
        verify_host_signature(&req, canonical.as_bytes())?;

    // Step 1 — dedup-lookup by the canonical (host_session_id,
    // host_turn_index) key. The partial index
    // idx_transcript_line_dedup_host_turn (created in schema v52) is
    // gated `WHERE host_session_id IS NOT NULL`; adding the explicit
    // IS NOT NULL predicate to the SELECT guarantees the planner
    // hits the partial index across SQLite versions (#1394 / R5.F5.1).
    let existing: Option<String> = conn
        .query_row(
            "SELECT memory_id FROM transcript_line_dedup \
             WHERE host_session_id IS NOT NULL \
               AND host_session_id = ?1 \
               AND host_turn_index = ?2",
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

    // Step 3 — atomic INSERT both rows + signed_events chain row
    // under one BEGIN IMMEDIATE transaction. Failure rolls back so an
    // orphaned memory cannot exist without its dedup row OR its audit
    // row.
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
            format!("attest:{attest_level}"),
        ];
        if let Some(hv) = req.host_version.as_deref() {
            tags.push(format!("host-version:{hv}"));
        }

        // Title MUST be unique per (host_session_id, host_turn_index)
        // because the substrate's `storage::insert` upserts on
        // `(title, namespace)`; without host_session_id in the title,
        // two distinct sessions whose turn N has the same role would
        // collide on the same memory row.
        let title = format!(
            "L4 capture {} {} turn {} ({})",
            host_kind, req.host_session_id, req.host_turn_index, req.role
        );

        // v0.7.0 #1413 — stamp `metadata.agent_id` with the resolved
        // caller so the inserted memory carries the authenticated-via-
        // MCP-handshake identity. If the caller did not supply metadata
        // we synthesize an object with just the agent_id. If they did
        // supply metadata WITHOUT agent_id we patch it in. If they
        // supplied WITH a matching agent_id (verified by the agreement
        // check above) we preserve it verbatim.
        let metadata = {
            let mut m = req.metadata.clone().unwrap_or_else(|| json!({}));
            if let Some(obj) = m.as_object_mut() {
                obj.entry("agent_id".to_string())
                    .or_insert_with(|| Value::String(caller.to_string()));
            }
            m
        };

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

        // v0.7.0 #1415 — emit signed_events chain row inside the same
        // tx so audit can prove L4 caught the turn. attest_level reflects
        // whether the host provided a verified Ed25519 signature
        // (#1414). Failure aborts the tx so memory/dedup rows are
        // rolled back atomically — the audit chain never lags the data.
        let signed_event = SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: caller.to_string(),
            event_type: crate::signed_events::event_types::MEMORY_CAPTURE_TURN.to_string(),
            payload_hash: sha_vec.clone(),
            signature: sig_bytes_opt.clone(),
            attest_level: attest_level.clone(),
            timestamp: now_iso.clone(),
            ..SignedEvent::default()
        };
        signed_events::append_signed_event_no_tx(conn, &signed_event)
            .map_err(|e| format!("SIGNED_EVENTS_APPEND_FAILED: {e}"))?;

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
                "attest_level": attest_level,
                "elapsed_ms": elapsed_ms,
            }))
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// v0.7.0 #1414 — parse + verify the host signature pair, returning
/// `(sig_bytes_opt, attest_level)` for downstream use in the
/// signed_events row.
///
/// Contract:
/// - both `host_signature_b64` and `host_pubkey_b64` present →
///   pubkey allowlist check → Ed25519 verify → ("signed_by_peer")
/// - exactly one of the two present → `INVALID_INPUT` (paired-fields)
/// - both absent → (`None`, "self_signed")
fn verify_host_signature(
    req: &MemoryCaptureTurnRequest,
    canonical_bytes: &[u8],
) -> Result<(Option<Vec<u8>>, String), String> {
    match (req.host_signature_b64.as_deref(), req.host_pubkey_b64.as_deref()) {
        (None, None) => Ok((None, "self_signed".to_string())),
        (Some(_), None) | (None, Some(_)) => Err(
            "INVALID_INPUT: host_signature_b64 and host_pubkey_b64 must both be present or both absent"
                .to_string(),
        ),
        (Some(sig_b64), Some(pubkey_b64)) => {
            let pubkey_bytes = B64_STD
                .decode(pubkey_b64)
                .map_err(|e| format!("INVALID_INPUT: host_pubkey_b64 not valid base64: {e}"))?;
            let pubkey_arr: [u8; 32] = pubkey_bytes.try_into().map_err(|_| {
                "INVALID_INPUT: host_pubkey_b64 must decode to 32 bytes (Ed25519)".to_string()
            })?;

            if !is_host_pubkey_enrolled(&pubkey_arr) {
                return Err(format!("HOST_PUBKEY_NOT_ENROLLED: {pubkey_b64}"));
            }

            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr).map_err(
                |e| format!("INVALID_INPUT: host_pubkey_b64 not a valid Ed25519 key: {e}"),
            )?;

            let sig_bytes = B64_STD
                .decode(sig_b64)
                .map_err(|e| format!("INVALID_INPUT: host_signature_b64 not valid base64: {e}"))?;
            let sig_arr: [u8; 64] = sig_bytes.clone().try_into().map_err(|_| {
                "INVALID_INPUT: host_signature_b64 must decode to 64 bytes (Ed25519)".to_string()
            })?;
            let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

            verifying_key
                .verify_strict(canonical_bytes, &signature)
                .map_err(|e| {
                    format!("INVALID_INPUT: signature_verification_failed: {e}")
                })?;

            Ok((Some(sig_bytes), "signed_by_peer".to_string()))
        }
    }
}

/// Check the env-var allowlist for a host pubkey. Re-reads the env
/// on every call so operators can adjust enrollment without daemon
/// restart. An unset / empty env means no host signatures are
/// accepted (every signed-path call yields `HOST_PUBKEY_NOT_ENROLLED`)
/// — the conservative default per the v0.7.0 sole-authority rule.
fn is_host_pubkey_enrolled(pubkey: &[u8; 32]) -> bool {
    let Ok(raw) = std::env::var(L4_HOST_PUBKEY_ALLOWLIST_ENV) else {
        return false;
    };
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(bytes) = B64_STD.decode(entry)
            && bytes.len() == 32
            && bytes.as_slice() == pubkey
        {
            return true;
        }
    }
    false
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

    /// Test helper — calls the handler with no MCP-handshake caller
    /// (`None`). The agent_id agreement check at #1413 is a no-op
    /// when the request body carries no `metadata.agent_id`, so
    /// every legacy test continues to pass under the new signature.
    fn call_handler(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
        handle_capture_turn(conn, params, None)
    }

    #[test]
    fn handler_accepts_minimal_request() {
        let conn = fresh_conn();
        let resp = call_handler(
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
        let resp = call_handler(&conn, &json!({ "host_session_id": "x" }));
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
        let resp = call_handler(
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
        let err = call_handler(
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
        let resp = call_handler(
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
        let first = call_handler(
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

        let second = call_handler(
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
        let a = call_handler(
            &conn,
            &json!({
                "host_session_id": "session-a",
                "host_turn_index": 0,
                "role": "user",
                "content": "a"
            }),
        )
        .expect("a ok");
        let b = call_handler(
            &conn,
            &json!({
                "host_session_id": "session-b",
                "host_turn_index": 0,
                "role": "user",
                "content": "b"
            }),
        )
        .expect("b ok");
        let c = call_handler(
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
