// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — `memory_action_create` + `memory_action_get`
//! MCP stdio tools. Thin wrappers over the `crate::actions` sqlite
//! free-functions that expose the coordination-action substrate to MCP
//! callers. Mirrors the `crate::observations` /
//! `mcp::tools::recall_observations` split: the handlers hold a bare
//! `rusqlite::Connection` (not a SAL store), so they call the
//! free-functions directly.

use crate::mcp::param_names;
use serde_json::{Value, json};

/// MCP handler for `memory_action_create`. Builds an [`crate::models::Action`]
/// from the request params and inserts it, returning the created action
/// as JSON.
///
/// # Errors
/// Returns the stringified `rusqlite` error on insert failure.
pub fn handle_action_create(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let namespace = params
        .get(param_names::NAMESPACE)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let kind = params
        .get(param_names::KIND)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let title = params
        .get(param_names::TITLE)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let payload = params
        .get(param_names::PAYLOAD)
        .cloned()
        .unwrap_or(Value::Null);
    let priority = params
        .get(param_names::PRIORITY)
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let agent_id = params
        .get(param_names::AGENT_ID)
        .and_then(Value::as_str)
        .map(str::to_string);
    let metadata = params
        .get(param_names::METADATA)
        .cloned()
        .unwrap_or(Value::Null);

    let now = chrono::Utc::now().timestamp();
    let action = crate::models::Action {
        id: uuid::Uuid::new_v4().to_string(),
        namespace,
        kind,
        state: crate::models::ActionState::Pending,
        title,
        payload,
        priority,
        agent_id,
        claimed_by: None,
        vector_clock: json!({}),
        metadata,
        created_at: now,
        updated_at: now,
    };

    let id = crate::actions::create(conn, &action).map_err(|e| e.to_string())?;
    Ok(json!({
        (param_names::ID): id,
        "action": serde_json::to_value(&action).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_action_get`. Fetches an action by id. The
/// `action` field is `null` when no row matches, mirroring how
/// `memory_get` reports an absent row.
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_action_get(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let id = params
        .get(param_names::ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let found = crate::actions::get(conn, id).map_err(|e| e.to_string())?;
    let action = match found {
        Some(a) => serde_json::to_value(&a).map_err(|e| e.to_string())?,
        None => Value::Null,
    };
    Ok(json!({ "action": action }))
}

// --- per-tool McpTool impls (v0.8.0 Pillar 1, #1709) ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_action_create`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionCreateRequest {
    pub namespace: String,

    pub kind: String,

    pub title: String,

    #[serde(default)]
    pub payload: Value,

    #[serde(default)]
    pub priority: i64,

    #[serde(default)]
    pub agent_id: Option<String>,

    #[serde(default)]
    pub metadata: Value,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_action_get`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionGetRequest {
    pub id: String,
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_action_create`.
#[allow(dead_code)]
pub struct ActionCreateTool;

impl McpTool for ActionCreateTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_CREATE
    }
    fn description() -> &'static str {
        "Create a coordination action (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): insert a pending coordination action into the action DAG."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionCreateRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_action_get`.
#[allow(dead_code)]
pub struct ActionGetTool;

impl McpTool for ActionGetTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_GET
    }
    fn description() -> &'static str {
        "Fetch a coordination action by id (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): return one coordination action by id, or null when absent."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionGetRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_6_1709_tests {
    //! D1.6 (#987) parity tests for the Pillar-1 `memory_action_*` tools.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;

    #[test]
    fn action_create_tool_metadata() {
        assert_eq!(ActionCreateTool::name(), "memory_action_create");
        assert_eq!(ActionCreateTool::family(), "power");
        assert!(!ActionCreateTool::description().is_empty());
        assert!(!ActionCreateTool::docs().is_empty());
    }

    #[test]
    fn action_get_tool_metadata() {
        assert_eq!(ActionGetTool::name(), "memory_action_get");
        assert_eq!(ActionGetTool::family(), "power");
        assert!(!ActionGetTool::description().is_empty());
        assert!(!ActionGetTool::docs().is_empty());
    }

    #[test]
    fn action_create_schema_requires_core_fields() {
        let schema = ActionCreateTool::input_schema();
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
        for name in &["namespace", "kind", "title"] {
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
    fn create_then_get_roundtrips_over_mcp() {
        let conn = fresh();
        let created = handle_action_create(
            &conn,
            &json!({
                "namespace": "_act",
                "kind": "test.kind",
                "title": "t",
                "payload": {"a": 1},
                "priority": 5,
                "agent_id": "agent-x",
            }),
        )
        .expect("create ok");
        let id = created[param_names::ID].as_str().expect("id present");
        assert_eq!(created["action"]["state"].as_str(), Some("pending"));

        let got = handle_action_get(&conn, &json!({ "id": id })).expect("get ok");
        assert_eq!(got["action"]["namespace"].as_str(), Some("_act"));
        assert_eq!(got["action"]["kind"].as_str(), Some("test.kind"));
        assert_eq!(got["action"]["priority"].as_i64(), Some(5));
        assert_eq!(got["action"]["agent_id"].as_str(), Some("agent-x"));
    }

    #[test]
    fn get_absent_returns_null_action() {
        let conn = fresh();
        let got = handle_action_get(&conn, &json!({ "id": "missing" })).expect("get ok");
        assert!(got["action"].is_null());
    }

    #[test]
    fn create_defaults_unspecified_optionals() {
        let conn = fresh();
        let created = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t" }),
        )
        .expect("create ok");
        assert_eq!(created["action"]["priority"].as_i64(), Some(0));
        assert!(created["action"]["agent_id"].is_null());
        // created_at/updated_at are populated, non-zero unix seconds.
        let created_at = created["action"]["created_at"]
            .as_i64()
            .expect("created_at present");
        assert!(created_at > 0);
    }
}
