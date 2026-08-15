// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — `memory_checkpoint_*` MCP stdio tools. Thin
//! wrappers over the `crate::checkpoints` sqlite free-functions that expose the
//! attested-checkpoint coordination substrate (ROADMAP §11.4) to MCP callers.
//! Mirrors the `crate::signals` / `mcp::tools::signal` split: the handlers hold
//! a bare `rusqlite::Connection` (not a SAL store), so they call the
//! free-functions directly. `handle_checkpoint_resolve` additionally takes the
//! dispatch context's `active_keypair` so the resolution is Ed25519-attested in
//! place via [`crate::checkpoints::resolve`] when a signing keypair is
//! available.

use crate::identity::keypair::AgentKeypair;
use crate::mcp::param_names;
use serde_json::{Value, json};

/// JSON response field carrying the serialized checkpoint object (SSOT for the
/// repeated output key across the `memory_checkpoint_*` handlers).
const RESP_CHECKPOINT: &str = "checkpoint";

/// MCP handler for `memory_checkpoint_create`. Builds a
/// [`crate::models::Checkpoint`] from the request params in the
/// [`crate::models::CheckpointState::Pending`] state, inserts it, and returns
/// the created checkpoint as JSON plus its id.
///
/// # Errors
/// Returns the stringified `rusqlite` error on insert failure.
pub fn handle_checkpoint_create(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let namespace = params
        .get(param_names::NAMESPACE)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let title = params
        .get(param_names::TITLE)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let condition_type = params
        .get(param_names::CONDITION_TYPE)
        .and_then(Value::as_str)
        .and_then(crate::models::ConditionType::from_str)
        .unwrap_or_default();
    let condition = params
        .get(param_names::CONDITION)
        .cloned()
        .unwrap_or_else(|| json!({}));
    let created_by = params
        .get(param_names::CREATED_BY)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let deadline_at = params.get(param_names::DEADLINE_AT).and_then(Value::as_i64);
    let metadata = params
        .get(param_names::METADATA)
        .cloned()
        .unwrap_or_else(|| json!({}));

    let cp = crate::models::Checkpoint {
        id: uuid::Uuid::new_v4().to_string(),
        namespace,
        title,
        condition_type,
        condition,
        state: crate::models::CheckpointState::Pending,
        created_by,
        resolved_by: None,
        resolution: None,
        resolution_note: None,
        signature: vec![],
        resolver_pubkey: vec![],
        created_at: chrono::Utc::now().timestamp(),
        deadline_at,
        resolved_at: None,
        metadata,
    };

    // #1807 — validate supplied metadata size + charge the creator's
    // per-namespace storage quota for the condition + metadata payload
    // (storage_only). An unspecified-creator checkpoint (empty `created_by`)
    // is not charged. Metadata defaults to an empty object, but an explicit
    // JSON null is not a validatable object, so validation only runs when a
    // metadata object was supplied. T-exempt precedent-copy; 5-agent review
    // (memory `4d3ea1c5`) deemed #1807 legitimate.
    if !cp.metadata.is_null() {
        crate::validate::validate_metadata(&cp.metadata).map_err(|e| e.to_string())?;
    }
    if !cp.created_by.is_empty() {
        let bytes =
            crate::quotas::coordination_payload_bytes(&[&cp.title], &[&cp.condition, &cp.metadata]);
        crate::quotas::check_and_record_storage_only(conn, &cp.created_by, &cp.namespace, bytes)
            .map_err(|e| e.to_string())?;
    }

    crate::checkpoints::insert(conn, &cp).map_err(|e| e.to_string())?;

    // #1722 — coordination observability: best-effort audit row for the
    // create, attributed to the creating agent (`created_by`, "" when
    // unspecified). Identity = checkpoint id / creator / "create".
    crate::coordination_audit::emit(
        conn,
        crate::coordination_audit::CHECKPOINT_CREATE,
        &cp.created_by,
        &[&cp.id, &cp.created_by, "create"],
    );

    Ok(json!({
        (param_names::ID): cp.id,
        (RESP_CHECKPOINT): serde_json::to_value(&cp).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_checkpoint_resolve`. Resolves a pending checkpoint
/// to `resolved` / `rejected`, attesting the resolution in place when `keypair`
/// is `Some` and `can_sign()`. Returns the resolved checkpoint plus the
/// resulting attestation level (`self_signed` vs `unsigned`).
///
/// # Errors
/// Returns an error string when `state` is not a valid resolution state, when
/// no row matches the id, or on the stringified `rusqlite` update error.
pub fn handle_checkpoint_resolve(
    conn: &rusqlite::Connection,
    params: &Value,
    keypair: Option<&AgentKeypair>,
) -> Result<Value, String> {
    let id = params
        .get(param_names::ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let state = params
        .get(param_names::STATE)
        .and_then(Value::as_str)
        .and_then(crate::models::CheckpointState::from_str)
        .filter(|s| {
            matches!(
                s,
                crate::models::CheckpointState::Resolved | crate::models::CheckpointState::Rejected
            )
        })
        .ok_or_else(|| "state must be one of: resolved, rejected".to_string())?;
    let resolved_by = params
        .get(param_names::RESOLVED_BY)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let resolution = params.get(param_names::RESOLUTION).and_then(Value::as_str);
    let resolution_note = params
        .get(param_names::RESOLUTION_NOTE)
        .and_then(Value::as_str);
    let now = chrono::Utc::now().timestamp();

    let resolved = crate::checkpoints::resolve(
        conn,
        id,
        state,
        resolved_by,
        resolution,
        resolution_note,
        now,
        keypair,
    )
    .map_err(|e| e.to_string())?;
    match resolved {
        None => Err(format!("checkpoint not found: {id}")),
        Some(cp) => {
            // #1722 — coordination observability: best-effort audit row for the
            // resolution, attributed to the resolving agent (`resolved_by`).
            // Identity = checkpoint id / resolver / target state.
            crate::coordination_audit::emit(
                conn,
                crate::coordination_audit::CHECKPOINT_RESOLVE,
                resolved_by,
                &[id, resolved_by, state.as_str()],
            );
            let attest_level = if cp.signature.is_empty() {
                crate::models::AttestLevel::Unsigned.as_str()
            } else {
                crate::models::AttestLevel::SelfSigned.as_str()
            };
            Ok(json!({
                (RESP_CHECKPOINT): serde_json::to_value(&cp).map_err(|e| e.to_string())?,
                "attest_level": attest_level,
            }))
        }
    }
}

/// MCP handler for `memory_checkpoint_query`. Lists a namespace's checkpoints
/// narrowed by an optional `condition_type` AND an optional `state`,
/// newest-first, capped at `limit` (default 50).
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_checkpoint_query(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let namespace = params
        .get(param_names::NAMESPACE)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let condition_type = params
        .get(param_names::CONDITION_TYPE)
        .and_then(Value::as_str)
        .and_then(crate::models::ConditionType::from_str);
    let state = params
        .get(param_names::STATE)
        .and_then(Value::as_str)
        .and_then(crate::models::CheckpointState::from_str);
    let limit = params
        .get(param_names::LIMIT)
        .and_then(Value::as_i64)
        .unwrap_or(50);
    let limit = usize::try_from(limit).unwrap_or(50);

    let checkpoints = crate::checkpoints::query(conn, namespace, condition_type, state, limit)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "checkpoints": serde_json::to_value(&checkpoints).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_checkpoint_verify`. Fetches a checkpoint by id and
/// reports its Ed25519 attested-resolution verification status. The
/// `checkpoint` field is `null` when no row matches, mirroring how
/// `memory_signal_read` reports an absent row.
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_checkpoint_verify(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let id = params
        .get(param_names::ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let found = crate::checkpoints::get(conn, id).map_err(|e| e.to_string())?;
    match found {
        None => Ok(json!({ (RESP_CHECKPOINT): Value::Null, "verified": false })),
        Some(cp) => Ok(json!({
            (RESP_CHECKPOINT): serde_json::to_value(&cp).map_err(|e| e.to_string())?,
            "verified": crate::checkpoints::verify(&cp),
        })),
    }
}

// --- per-tool McpTool impls (v0.8.0 Pillar 1, #1709) ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_checkpoint_create`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct CheckpointCreateRequest {
    pub namespace: String,

    pub title: String,

    /// Condition type (`approval` / `external_signal` /
    /// `condition_predicate` / `deadline`). Defaults to `approval`.
    #[serde(default)]
    pub condition_type: Option<String>,

    /// JSON condition spec for the gate. Defaults to `{}`.
    #[serde(default)]
    pub condition: Value,

    /// Agent id that created the checkpoint.
    #[serde(default)]
    pub created_by: Option<String>,

    /// Epoch-seconds deadline after which the checkpoint may expire.
    #[serde(default)]
    pub deadline_at: Option<i64>,

    /// Arbitrary JSON metadata. Defaults to `{}`.
    #[serde(default)]
    pub metadata: Value,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_checkpoint_resolve`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct CheckpointResolveRequest {
    pub id: String,

    /// Resolution state — one of `resolved` / `rejected`.
    pub state: String,

    pub resolved_by: String,

    /// Structured resolution payload (free-form string).
    #[serde(default)]
    pub resolution: Option<String>,

    /// Human-readable note explaining the resolution.
    #[serde(default)]
    pub resolution_note: Option<String>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_checkpoint_query`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct CheckpointQueryRequest {
    pub namespace: String,

    /// Narrow to a single condition type when set.
    #[serde(default)]
    pub condition_type: Option<String>,

    /// Narrow to a single lifecycle state when set.
    #[serde(default)]
    pub state: Option<String>,

    #[serde(default)]
    pub limit: Option<i64>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_checkpoint_verify`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct CheckpointVerifyRequest {
    pub id: String,
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_checkpoint_create`.
#[allow(dead_code)]
pub struct CheckpointCreateTool;

impl McpTool for CheckpointCreateTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_CHECKPOINT_CREATE
    }
    fn description() -> &'static str {
        "Create a pending attested-checkpoint coordination gate (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): create a checkpoint in the pending state, gated on an external condition."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<CheckpointCreateRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_checkpoint_resolve`.
#[allow(dead_code)]
pub struct CheckpointResolveTool;

impl McpTool for CheckpointResolveTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_CHECKPOINT_RESOLVE
    }
    fn description() -> &'static str {
        "Resolve a checkpoint (resolved/rejected), Ed25519-attested when signing (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): resolve a checkpoint; the resolution self-signs when a signing keypair is available."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<CheckpointResolveRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_checkpoint_query`.
#[allow(dead_code)]
pub struct CheckpointQueryTool;

impl McpTool for CheckpointQueryTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_CHECKPOINT_QUERY
    }
    fn description() -> &'static str {
        "Query checkpoints by namespace/condition_type/state, newest-first (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): list a namespace's checkpoints, optionally narrowed by condition_type and state."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<CheckpointQueryRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_checkpoint_verify`.
#[allow(dead_code)]
pub struct CheckpointVerifyTool;

impl McpTool for CheckpointVerifyTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_CHECKPOINT_VERIFY
    }
    fn description() -> &'static str {
        "Fetch a checkpoint by id and verify its attested resolution (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): fetch a checkpoint and verify its Ed25519 attested-resolution signature."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<CheckpointVerifyRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_6_1709_tests {
    //! D1.6 (#987) parity tests for the Pillar-1 `memory_checkpoint_*` tools.
    use super::*;

    #[test]
    fn checkpoint_create_tool_metadata() {
        assert_eq!(CheckpointCreateTool::name(), "memory_checkpoint_create");
        assert_eq!(CheckpointCreateTool::family(), "power");
        assert!(!CheckpointCreateTool::description().is_empty());
        assert!(!CheckpointCreateTool::docs().is_empty());
    }

    #[test]
    fn checkpoint_resolve_tool_metadata() {
        assert_eq!(CheckpointResolveTool::name(), "memory_checkpoint_resolve");
        assert_eq!(CheckpointResolveTool::family(), "power");
        assert!(!CheckpointResolveTool::description().is_empty());
        assert!(!CheckpointResolveTool::docs().is_empty());
    }

    #[test]
    fn checkpoint_query_tool_metadata() {
        assert_eq!(CheckpointQueryTool::name(), "memory_checkpoint_query");
        assert_eq!(CheckpointQueryTool::family(), "power");
        assert!(!CheckpointQueryTool::description().is_empty());
        assert!(!CheckpointQueryTool::docs().is_empty());
    }

    #[test]
    fn checkpoint_verify_tool_metadata() {
        assert_eq!(CheckpointVerifyTool::name(), "memory_checkpoint_verify");
        assert_eq!(CheckpointVerifyTool::family(), "power");
        assert!(!CheckpointVerifyTool::description().is_empty());
        assert!(!CheckpointVerifyTool::docs().is_empty());
    }

    #[test]
    fn checkpoint_create_schema_requires_core_fields() {
        let schema = CheckpointCreateTool::input_schema();
        let obj = schema.as_object().expect("schema is an object");
        assert!(
            obj.contains_key("properties"),
            "schema must advertise properties"
        );
        let required = obj
            .get("required")
            .and_then(Value::as_array)
            .expect("required is an array");
        let required_names: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
        for name in &["namespace", "title"] {
            assert!(
                required_names.contains(name),
                "required must include {name}"
            );
        }
    }
}

#[cfg(test)]
mod handler_tests {
    use super::*;

    fn fresh() -> rusqlite::Connection {
        crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    #[test]
    fn create_query_resolve_verify_roundtrips_over_mcp() {
        let conn = fresh();
        // Create a pending checkpoint.
        let created = handle_checkpoint_create(
            &conn,
            &json!({
                "namespace": "_cp",
                "title": "ship the release",
                "condition_type": "approval",
                "condition": {"who": "operator"},
                "created_by": "agent-a",
            }),
        )
        .expect("create ok");
        let id = created[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();
        assert_eq!(created["checkpoint"]["state"].as_str(), Some("pending"));
        assert_eq!(
            created["checkpoint"]["condition_type"].as_str(),
            Some("approval")
        );

        // Query for the namespace finds it.
        let queried =
            handle_checkpoint_query(&conn, &json!({ "namespace": "_cp" })).expect("query ok");
        let arr = queried["checkpoints"]
            .as_array()
            .expect("checkpoints array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"].as_str(), Some(id.as_str()));

        // Query narrowed by state=pending still finds it.
        let pending =
            handle_checkpoint_query(&conn, &json!({ "namespace": "_cp", "state": "pending" }))
                .expect("query ok");
        assert_eq!(pending["checkpoints"].as_array().expect("array").len(), 1);

        // Resolve it (unsigned — no keypair).
        let resolved = handle_checkpoint_resolve(
            &conn,
            &json!({
                "id": id,
                "state": "resolved",
                "resolved_by": "agent-b",
                "resolution": "approved",
                "resolution_note": "looks good",
            }),
            None,
        )
        .expect("resolve ok");
        assert_eq!(resolved["attest_level"].as_str(), Some("unsigned"));
        assert_eq!(resolved["checkpoint"]["state"].as_str(), Some("resolved"));
        assert_eq!(
            resolved["checkpoint"]["resolved_by"].as_str(),
            Some("agent-b")
        );

        // Verify reports false for the unsigned resolution.
        let verified = handle_checkpoint_verify(&conn, &json!({ "id": id })).expect("verify ok");
        assert_eq!(verified["verified"].as_bool(), Some(false));
        assert_eq!(verified["checkpoint"]["state"].as_str(), Some("resolved"));
    }

    #[test]
    fn verify_absent_returns_null_checkpoint() {
        let conn = fresh();
        let got = handle_checkpoint_verify(&conn, &json!({ "id": "missing" })).expect("verify ok");
        assert!(got["checkpoint"].is_null());
        assert_eq!(got["verified"].as_bool(), Some(false));
    }

    #[test]
    fn resolve_rejects_invalid_state() {
        let conn = fresh();
        let created = handle_checkpoint_create(&conn, &json!({ "namespace": "_cp", "title": "t" }))
            .expect("create ok");
        let id = created[param_names::ID].as_str().expect("id present");
        let err = handle_checkpoint_resolve(
            &conn,
            &json!({ "id": id, "state": "pending", "resolved_by": "x" }),
            None,
        )
        .expect_err("invalid state must error");
        assert!(err.contains("resolved"), "error names valid states: {err}");
    }

    #[test]
    fn resolve_missing_id_errors() {
        let conn = fresh();
        let err = handle_checkpoint_resolve(
            &conn,
            &json!({ "id": "nope", "state": "resolved", "resolved_by": "x" }),
            None,
        )
        .expect_err("missing id must error");
        assert!(err.contains("not found"), "error reports absence: {err}");
    }

    /// #1722 — resolving a checkpoint appends one
    /// `coordination.checkpoint_resolve` audit row attributed to the
    /// resolving agent; the append-only chain stays intact.
    #[test]
    fn resolve_emits_signed_events_audit_row_1722() {
        let conn = fresh();
        let created = handle_checkpoint_create(
            &conn,
            &json!({ "namespace": "_cp", "title": "t", "created_by": "agent-a" }),
        )
        .expect("create ok");
        let id = created[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();

        handle_checkpoint_resolve(
            &conn,
            &json!({ "id": id, "state": "resolved", "resolved_by": "agent-b" }),
            None,
        )
        .expect("resolve ok");

        let (count, agent): (i64, String) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(agent_id), '') FROM signed_events \
                 WHERE event_type = ?1",
                rusqlite::params![crate::coordination_audit::CHECKPOINT_RESOLVE],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query audit row");
        assert_eq!(count, 1, "one coordination.checkpoint_resolve row");
        assert_eq!(agent, "agent-b", "row attributed to the resolver");

        let report = crate::signed_events::verify_audit_trail(&conn, None, None).expect("verify");
        assert!(report.chain_intact, "chain must verify; report={report:?}");
    }

    #[test]
    fn create_defaults_condition_type_to_approval() {
        let conn = fresh();
        let created = handle_checkpoint_create(&conn, &json!({ "namespace": "_cp", "title": "t" }))
            .expect("create ok");
        assert_eq!(
            created["checkpoint"]["condition_type"].as_str(),
            Some("approval")
        );
        assert!(
            created["checkpoint"]["created_at"]
                .as_i64()
                .expect("created_at")
                > 0
        );
    }
}
