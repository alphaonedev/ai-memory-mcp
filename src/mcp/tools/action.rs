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

/// MCP handler for `memory_action_transition`. State-guarded transition
/// of one action via [`crate::actions::transition`]. Returns the updated
/// action; errors on a missing row, an invalid target state name, or an
/// illegal transition.
///
/// # Errors
/// - `action not found: <id>` when no row matches.
/// - `illegal action transition: <from> -> <to>` on a guard refusal.
/// - `invalid state` when `to` is not a known [`crate::models::ActionState`].
/// - The stringified `rusqlite` error on query failure.
pub fn handle_action_transition(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let id = params
        .get(param_names::ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let to_name = params
        .get(param_names::TO)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let to =
        crate::models::ActionState::from_str(to_name).ok_or_else(|| "invalid state".to_string())?;
    let claimed_by = params
        .get(param_names::CLAIMED_BY)
        .and_then(Value::as_str)
        .map(str::to_string);

    let now = chrono::Utc::now().timestamp();
    match crate::actions::transition(conn, id, to, claimed_by.as_deref(), now)
        .map_err(|e| e.to_string())?
    {
        crate::actions::TransitionOutcome::NotFound => Err(format!("action not found: {id}")),
        crate::actions::TransitionOutcome::Illegal { from, to } => {
            Err(crate::actions::illegal_transition_detail(from, to))
        }
        crate::actions::TransitionOutcome::Updated(a) => Ok(json!({
            "action": serde_json::to_value(&a).map_err(|e| e.to_string())?,
        })),
    }
}

/// MCP handler for `memory_action_list`. Lists actions filtered by
/// optional `namespace` / `state`, newest-first, capped at `limit`
/// (default 50).
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_action_list(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let namespace = params
        .get(param_names::NAMESPACE)
        .and_then(Value::as_str)
        .map(str::to_string);
    let state = match params.get(param_names::STATE).and_then(Value::as_str) {
        Some(s) => Some(
            crate::models::ActionState::from_str(s).ok_or_else(|| "invalid state".to_string())?,
        ),
        None => None,
    };
    let limit = params
        .get(param_names::LIMIT)
        .and_then(Value::as_i64)
        .unwrap_or(50);
    let limit = usize::try_from(limit).unwrap_or(50);

    let actions = crate::actions::list(conn, namespace.as_deref(), state, limit)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "actions": serde_json::to_value(&actions).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_action_add_edge`. Inserts a typed DAG edge
/// between two actions via [`crate::actions::add_edge`].
///
/// # Errors
/// - `invalid edge_type` when `edge_type` is not a known
///   [`crate::models::EdgeType`].
/// - The stringified `rusqlite` error on insert failure.
pub fn handle_action_add_edge(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let from_action = params
        .get(param_names::FROM_ACTION)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let to_action = params
        .get(param_names::TO_ACTION)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let edge_type_name = params
        .get(param_names::EDGE_TYPE)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let edge_type = crate::models::EdgeType::from_str(edge_type_name)
        .ok_or_else(|| "invalid edge_type".to_string())?;

    let now = chrono::Utc::now().timestamp();
    crate::actions::add_edge(conn, from_action, to_action, edge_type, now)
        .map_err(|e| e.to_string())?;
    Ok(json!({ "ok": true }))
}

/// MCP handler for `memory_action_edges`. Lists every edge touching the
/// given action via [`crate::actions::edges_for`].
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_action_edges(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let action_id = params
        .get(param_names::ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let edges = crate::actions::edges_for(conn, action_id).map_err(|e| e.to_string())?;
    Ok(json!({
        "edges": serde_json::to_value(&edges).map_err(|e| e.to_string())?,
    }))
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

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_action_transition`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionTransitionRequest {
    pub id: String,

    /// Target state name (`pending` / `claimed` / `in_progress` /
    /// `done` / `failed` / `abandoned`).
    pub to: String,

    #[serde(default)]
    pub claimed_by: Option<String>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_action_list`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionListRequest {
    #[serde(default)]
    pub namespace: Option<String>,

    /// Optional state-name filter.
    #[serde(default)]
    pub state: Option<String>,

    #[serde(default)]
    pub limit: Option<i64>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_action_add_edge`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionAddEdgeRequest {
    pub from_action: String,

    pub to_action: String,

    /// Edge kind (`requires` / `unlocks` / `blocks` / `gated_by` /
    /// `sibling`).
    pub edge_type: String,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_action_edges`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionEdgesRequest {
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

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_action_transition`.
#[allow(dead_code)]
pub struct ActionTransitionTool;

impl McpTool for ActionTransitionTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_TRANSITION
    }
    fn description() -> &'static str {
        "State-guarded transition of a coordination action (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): move an action to a new state if the transition is legal."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionTransitionRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_action_list`.
#[allow(dead_code)]
pub struct ActionListTool;

impl McpTool for ActionListTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_LIST
    }
    fn description() -> &'static str {
        "List coordination actions by namespace/state (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): query the action DAG, filtered by namespace/state, newest-first."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionListRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_action_add_edge`.
#[allow(dead_code)]
pub struct ActionAddEdgeTool;

impl McpTool for ActionAddEdgeTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_ADD_EDGE
    }
    fn description() -> &'static str {
        "Add a typed DAG edge between two coordination actions (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): insert a typed dependency edge into the action DAG."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionAddEdgeRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_action_edges`.
#[allow(dead_code)]
pub struct ActionEdgesTool;

impl McpTool for ActionEdgesTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_EDGES
    }
    fn description() -> &'static str {
        "List DAG edges for a coordination action (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): return every typed edge touching an action."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionEdgesRequest>()
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
    fn action_transition_tool_metadata() {
        assert_eq!(ActionTransitionTool::name(), "memory_action_transition");
        assert_eq!(ActionTransitionTool::family(), "power");
        assert!(!ActionTransitionTool::description().is_empty());
        assert!(!ActionTransitionTool::docs().is_empty());
    }

    #[test]
    fn action_list_tool_metadata() {
        assert_eq!(ActionListTool::name(), "memory_action_list");
        assert_eq!(ActionListTool::family(), "power");
        assert!(!ActionListTool::description().is_empty());
        assert!(!ActionListTool::docs().is_empty());
    }

    #[test]
    fn action_add_edge_tool_metadata() {
        assert_eq!(ActionAddEdgeTool::name(), "memory_action_add_edge");
        assert_eq!(ActionAddEdgeTool::family(), "power");
        assert!(!ActionAddEdgeTool::description().is_empty());
        assert!(!ActionAddEdgeTool::docs().is_empty());
    }

    #[test]
    fn action_edges_tool_metadata() {
        assert_eq!(ActionEdgesTool::name(), "memory_action_edges");
        assert_eq!(ActionEdgesTool::family(), "power");
        assert!(!ActionEdgesTool::description().is_empty());
        assert!(!ActionEdgesTool::docs().is_empty());
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
    fn transition_list_edges_roundtrip_over_mcp() {
        let conn = fresh();
        let created = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t" }),
        )
        .expect("create ok");
        let id = created[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();

        // Legal transition pending -> claimed.
        let moved = handle_action_transition(
            &conn,
            &json!({ "id": id, "to": "claimed", "claimed_by": "holder-1" }),
        )
        .expect("transition ok");
        assert_eq!(moved["action"]["state"].as_str(), Some("claimed"));
        assert_eq!(moved["action"]["claimed_by"].as_str(), Some("holder-1"));

        // Illegal transition claimed -> done is reported as an error.
        let illegal = handle_action_transition(&conn, &json!({ "id": id, "to": "done" }));
        assert!(illegal.is_err());

        // Unknown id is an error.
        let absent = handle_action_transition(&conn, &json!({ "id": "missing", "to": "claimed" }));
        assert!(absent.is_err());

        // List filtered by state.
        let listed = handle_action_list(&conn, &json!({ "state": "claimed" })).expect("list ok");
        let arr = listed["actions"].as_array().expect("actions array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"].as_str(), Some(id.as_str()));

        // Add a second action + an edge between them.
        let other = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t2" }),
        )
        .expect("create ok");
        let other_id = other[param_names::ID].as_str().expect("id present");
        let added = handle_action_add_edge(
            &conn,
            &json!({ "from_action": id, "to_action": other_id, "edge_type": "requires" }),
        )
        .expect("add_edge ok");
        assert_eq!(added["ok"].as_bool(), Some(true));

        let edges = handle_action_edges(&conn, &json!({ "id": id })).expect("edges ok");
        let edge_arr = edges["edges"].as_array().expect("edges array");
        assert_eq!(edge_arr.len(), 1);
        assert_eq!(edge_arr[0]["edge_type"].as_str(), Some("requires"));
    }

    #[test]
    fn transition_invalid_state_name_errors() {
        let conn = fresh();
        let created = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t" }),
        )
        .expect("create ok");
        let id = created[param_names::ID].as_str().expect("id present");
        let bad = handle_action_transition(&conn, &json!({ "id": id, "to": "bogus" }));
        assert!(bad.is_err());

        let bad_edge = handle_action_add_edge(
            &conn,
            &json!({ "from_action": id, "to_action": id, "edge_type": "bogus" }),
        );
        assert!(bad_edge.is_err());
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
