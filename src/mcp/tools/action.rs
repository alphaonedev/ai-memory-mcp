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

    // #1722 — coordination observability: best-effort audit row for the
    // create, attributed to the action's owning agent (`agent_id`, "" when
    // unowned). Identity = action id / kind / "create".
    let actor = action.agent_id.as_deref().unwrap_or_default();
    crate::coordination_audit::emit(
        conn,
        crate::coordination_audit::ACTION_CREATE,
        actor,
        &[&id, &action.kind, "create"],
    );

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
        crate::actions::TransitionOutcome::Updated(a) => {
            // #1722 — coordination observability: best-effort audit row for
            // the transition, attributed to the claiming agent (`claimed_by`,
            // "" when none was supplied). Identity = action id / target state
            // / claimer.
            let actor = claimed_by.as_deref().unwrap_or_default();
            crate::coordination_audit::emit(
                conn,
                crate::coordination_audit::ACTION_TRANSITION,
                actor,
                &[id, to_name, actor],
            );
            Ok(json!({
                "action": serde_json::to_value(&a).map_err(|e| e.to_string())?,
            }))
        }
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

    // #1722 — coordination observability: best-effort audit row for the edge
    // insert. The add-edge handler carries NO actor/principal field, so the
    // row records the event + payload hash with an empty actor; identity =
    // from_action / to_action / edge_type so the specific edge is committed.
    crate::coordination_audit::emit(
        conn,
        crate::coordination_audit::ACTION_ADD_EDGE,
        "",
        &[from_action, to_action, edge_type_name],
    );

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

/// MCP handler for `memory_action_frontier`. Returns the ranked UNBLOCKED
/// frontier (#1709 §11.4) for a namespace: pending actions whose
/// `requires` / `gated_by` prerequisites are all `done` and that no active
/// `blocks` edge holds, ordered `priority DESC, created_at ASC`, capped at
/// `limit` (default 20).
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_action_frontier(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let namespace = params
        .get(param_names::NAMESPACE)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let limit = params
        .get(param_names::LIMIT)
        .and_then(Value::as_i64)
        .unwrap_or(20);
    let limit = usize::try_from(limit).unwrap_or(20);
    let actions = crate::actions::frontier(conn, namespace, limit).map_err(|e| e.to_string())?;
    Ok(json!({
        "actions": serde_json::to_value(&actions).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_action_next`. Returns the single highest-ranked
/// UNBLOCKED action a caller should pick up next (#1709 §11.4) — the top of
/// the frontier query. When `agent_id` is supplied, the candidate set is
/// narrowed to actions with no owner OR owned by the caller. The `action`
/// field is `null` when the frontier is empty.
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_action_next(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let namespace = params
        .get(param_names::NAMESPACE)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let agent_id = params
        .get(param_names::AGENT_ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let found =
        crate::actions::next_action(conn, namespace, agent_id).map_err(|e| e.to_string())?;
    let action = match found {
        Some(a) => serde_json::to_value(&a).map_err(|e| e.to_string())?,
        None => Value::Null,
    };
    Ok(json!({ "action": action }))
}

/// MCP handler for `memory_lease_acquire`. Acquires a single-holder lease
/// on an action via [`crate::actions::lease_acquire`]. The `expires_at`
/// timestamp is computed internally from `ttl_secs` (default 60) so callers
/// never marshal wall-clock time.
///
/// # Errors
/// - `lease conflict: <id> held by another holder` when a non-expired lease
///   is held by a different holder.
/// - The stringified `rusqlite` error on query/insert failure.
pub fn handle_lease_acquire(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let action_id = params
        .get(param_names::ACTION_ID)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let holder = params
        .get(param_names::HOLDER)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let ttl_secs = params
        .get(param_names::TTL_SECS)
        .and_then(Value::as_i64)
        .unwrap_or(60);

    let now = chrono::Utc::now().timestamp();
    let expires_at = now + ttl_secs;
    match crate::actions::lease_acquire(conn, action_id, holder, now, expires_at)
        .map_err(|e| e.to_string())?
    {
        crate::actions::LeaseAcquire::Conflict => Err(format!(
            "lease conflict: {action_id} held by another holder"
        )),
        crate::actions::LeaseAcquire::Acquired(l) => {
            // #1722 — coordination observability: best-effort audit row for the
            // acquire, attributed to the lease `holder`. Identity = action id /
            // holder.
            crate::coordination_audit::emit(
                conn,
                crate::coordination_audit::LEASE_ACQUIRE,
                holder,
                &[action_id, holder],
            );
            Ok(json!({
                "lease": serde_json::to_value(&l).map_err(|e| e.to_string())?,
            }))
        }
    }
}

/// MCP handler for `memory_lease_renew`. Heartbeat-renews an owned lease via
/// [`crate::actions::lease_renew`]. `expires_at` is computed internally from
/// `ttl_secs` (default 60).
///
/// # Errors
/// - `no lease held by <holder> on <action_id>` when no lease matches.
/// - The stringified `rusqlite` error on query/update failure.
pub fn handle_lease_renew(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let action_id = params
        .get(param_names::ACTION_ID)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let holder = params
        .get(param_names::HOLDER)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let ttl_secs = params
        .get(param_names::TTL_SECS)
        .and_then(Value::as_i64)
        .unwrap_or(60);

    let now = chrono::Utc::now().timestamp();
    let expires_at = now + ttl_secs;
    match crate::actions::lease_renew(conn, action_id, holder, now, expires_at)
        .map_err(|e| e.to_string())?
    {
        None => Err(format!("no lease held by {holder} on {action_id}")),
        Some(l) => {
            // #1722 — coordination observability: best-effort audit row for the
            // renew, attributed to the lease `holder`. Identity = action id /
            // holder.
            crate::coordination_audit::emit(
                conn,
                crate::coordination_audit::LEASE_RENEW,
                holder,
                &[action_id, holder],
            );
            Ok(json!({
                "lease": serde_json::to_value(&l).map_err(|e| e.to_string())?,
            }))
        }
    }
}

/// MCP handler for `memory_lease_release`. Releases an owned lease via
/// [`crate::actions::lease_release`]. Returns `released: <bool>` — `false`
/// when no matching lease existed.
///
/// # Errors
/// Returns the stringified `rusqlite` error on delete failure.
pub fn handle_lease_release(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let action_id = params
        .get(param_names::ACTION_ID)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let holder = params
        .get(param_names::HOLDER)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let released =
        crate::actions::lease_release(conn, action_id, holder).map_err(|e| e.to_string())?;

    // #1722 — coordination observability: best-effort audit row for the
    // release, attributed to the lease `holder`. Only emit when a row was
    // actually removed (a no-op release by a non-owner writes nothing).
    // Identity = action id / holder.
    if released {
        crate::coordination_audit::emit(
            conn,
            crate::coordination_audit::LEASE_RELEASE,
            holder,
            &[action_id, holder],
        );
    }

    Ok(json!({ "released": released }))
}

/// MCP handler for `memory_lease_get`. Reads the lease on an action via
/// [`crate::actions::lease_get`]. The `lease` field is `null` when no lease
/// row exists, mirroring how `memory_action_get` reports an absent row.
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_lease_get(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let action_id = params
        .get(param_names::ACTION_ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let found = crate::actions::lease_get(conn, action_id).map_err(|e| e.to_string())?;
    let lease = match found {
        Some(l) => serde_json::to_value(&l).map_err(|e| e.to_string())?,
        None => Value::Null,
    };
    Ok(json!({ "lease": lease }))
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

/// v0.8.0 Pillar 1 (#1709 §11.4) — request body for `memory_action_frontier`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionFrontierRequest {
    pub namespace: String,

    /// Max rows to return (default 20).
    #[serde(default)]
    pub limit: Option<i64>,
}

/// v0.8.0 Pillar 1 (#1709 §11.4) — request body for `memory_action_next`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionNextRequest {
    pub namespace: String,

    /// When set, narrow the candidate set to actions with no owner OR owned
    /// by this agent.
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_lease_acquire`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct LeaseAcquireRequest {
    pub action_id: String,

    pub holder: String,

    /// Lease lifetime in seconds (default 60). `expires_at` is computed
    /// internally as `now + ttl_secs`.
    #[serde(default)]
    pub ttl_secs: Option<i64>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_lease_renew`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct LeaseRenewRequest {
    pub action_id: String,

    pub holder: String,

    /// New lease lifetime in seconds (default 60). `expires_at` is computed
    /// internally as `now + ttl_secs`.
    #[serde(default)]
    pub ttl_secs: Option<i64>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_lease_release`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct LeaseReleaseRequest {
    pub action_id: String,

    pub holder: String,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_lease_get`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct LeaseGetRequest {
    pub action_id: String,
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

/// v0.8.0 Pillar 1 (#1709 §11.4) — `McpTool` impl for `memory_action_frontier`.
#[allow(dead_code)]
pub struct ActionFrontierTool;

impl McpTool for ActionFrontierTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_FRONTIER
    }
    fn description() -> &'static str {
        "Rank the UNBLOCKED coordination-action frontier (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709 §11.4): the ranked frontier of pending actions whose prerequisites/gates are done and that no active blocker holds."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionFrontierRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709 §11.4) — `McpTool` impl for `memory_action_next`.
#[allow(dead_code)]
pub struct ActionNextTool;

impl McpTool for ActionNextTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_NEXT
    }
    fn description() -> &'static str {
        "Return the top UNBLOCKED coordination action to do next (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709 §11.4): the single highest-ranked unblocked action; optionally narrowed to the caller's owned/unowned work."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionNextRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_lease_acquire`.
#[allow(dead_code)]
pub struct LeaseAcquireTool;

impl McpTool for LeaseAcquireTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_LEASE_ACQUIRE
    }
    fn description() -> &'static str {
        "Acquire a single-holder lease on a coordination action (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): take an exclusive, TTL-bounded lease on an action; conflicts if held."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<LeaseAcquireRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_lease_renew`.
#[allow(dead_code)]
pub struct LeaseRenewTool;

impl McpTool for LeaseRenewTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_LEASE_RENEW
    }
    fn description() -> &'static str {
        "Heartbeat-renew an owned lease on a coordination action (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): extend an owned lease's TTL; errors if no lease is held by the caller."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<LeaseRenewRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_lease_release`.
#[allow(dead_code)]
pub struct LeaseReleaseTool;

impl McpTool for LeaseReleaseTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_LEASE_RELEASE
    }
    fn description() -> &'static str {
        "Release an owned lease on a coordination action (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): release an owned lease; reports whether a row was removed."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<LeaseReleaseRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_lease_get`.
#[allow(dead_code)]
pub struct LeaseGetTool;

impl McpTool for LeaseGetTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_LEASE_GET
    }
    fn description() -> &'static str {
        "Read the lease on a coordination action (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): return the lease on an action, or null when none is held."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<LeaseGetRequest>()
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
    fn action_frontier_tool_metadata() {
        assert_eq!(ActionFrontierTool::name(), "memory_action_frontier");
        assert_eq!(ActionFrontierTool::family(), "power");
        assert!(!ActionFrontierTool::description().is_empty());
        assert!(!ActionFrontierTool::docs().is_empty());
    }

    #[test]
    fn action_next_tool_metadata() {
        assert_eq!(ActionNextTool::name(), "memory_action_next");
        assert_eq!(ActionNextTool::family(), "power");
        assert!(!ActionNextTool::description().is_empty());
        assert!(!ActionNextTool::docs().is_empty());
    }

    #[test]
    fn lease_acquire_tool_metadata() {
        assert_eq!(LeaseAcquireTool::name(), "memory_lease_acquire");
        assert_eq!(LeaseAcquireTool::family(), "power");
        assert!(!LeaseAcquireTool::description().is_empty());
        assert!(!LeaseAcquireTool::docs().is_empty());
    }

    #[test]
    fn lease_renew_tool_metadata() {
        assert_eq!(LeaseRenewTool::name(), "memory_lease_renew");
        assert_eq!(LeaseRenewTool::family(), "power");
        assert!(!LeaseRenewTool::description().is_empty());
        assert!(!LeaseRenewTool::docs().is_empty());
    }

    #[test]
    fn lease_release_tool_metadata() {
        assert_eq!(LeaseReleaseTool::name(), "memory_lease_release");
        assert_eq!(LeaseReleaseTool::family(), "power");
        assert!(!LeaseReleaseTool::description().is_empty());
        assert!(!LeaseReleaseTool::docs().is_empty());
    }

    #[test]
    fn lease_get_tool_metadata() {
        assert_eq!(LeaseGetTool::name(), "memory_lease_get");
        assert_eq!(LeaseGetTool::family(), "power");
        assert!(!LeaseGetTool::description().is_empty());
        assert!(!LeaseGetTool::docs().is_empty());
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
    fn lease_acquire_renew_release_get_roundtrip_over_mcp() {
        let conn = fresh();
        // A lease references a real action row, so create one first.
        let created = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t" }),
        )
        .expect("create ok");
        let id = created[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();

        // Acquire by holder-a.
        let acquired = handle_lease_acquire(
            &conn,
            &json!({ "action_id": id, "holder": "holder-a", "ttl_secs": 120 }),
        )
        .expect("acquire ok");
        assert_eq!(acquired["lease"]["holder"].as_str(), Some("holder-a"));
        assert_eq!(acquired["lease"]["action_id"].as_str(), Some(id.as_str()));

        // A different holder hits the conflict error path.
        let conflict =
            handle_lease_acquire(&conn, &json!({ "action_id": id, "holder": "holder-b" }));
        assert!(conflict.is_err());

        // get returns the held lease.
        let got = handle_lease_get(&conn, &json!({ "action_id": id })).expect("get ok");
        assert_eq!(got["lease"]["holder"].as_str(), Some("holder-a"));

        // Renew by the owner succeeds.
        let renewed = handle_lease_renew(
            &conn,
            &json!({ "action_id": id, "holder": "holder-a", "ttl_secs": 90 }),
        )
        .expect("renew ok");
        assert_eq!(renewed["lease"]["holder"].as_str(), Some("holder-a"));

        // Renew by a non-owner is the no-lease error path.
        let no_lease = handle_lease_renew(&conn, &json!({ "action_id": id, "holder": "holder-b" }));
        assert!(no_lease.is_err());

        // Release by a non-owner removes nothing.
        let not_released =
            handle_lease_release(&conn, &json!({ "action_id": id, "holder": "holder-b" }))
                .expect("release ok");
        assert_eq!(not_released["released"].as_bool(), Some(false));

        // Release by the owner removes it; get then reports null.
        let released =
            handle_lease_release(&conn, &json!({ "action_id": id, "holder": "holder-a" }))
                .expect("release ok");
        assert_eq!(released["released"].as_bool(), Some(true));
        let absent = handle_lease_get(&conn, &json!({ "action_id": id })).expect("get ok");
        assert!(absent["lease"].is_null());
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

    #[test]
    fn frontier_and_next_over_mcp() {
        let conn = fresh();
        // A pending action with no blocking edges is on the frontier; a
        // second action requiring a still-pending prerequisite is not.
        let a = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "ready", "priority": 9 }),
        )
        .expect("create A ok");
        let a_id = a[param_names::ID].as_str().expect("id A").to_string();

        let blocked = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "blocked", "priority": 5 }),
        )
        .expect("create blocked ok");
        let blocked_id = blocked[param_names::ID]
            .as_str()
            .expect("id blocked")
            .to_string();
        let prereq = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "prereq", "priority": 1 }),
        )
        .expect("create prereq ok");
        let prereq_id = prereq[param_names::ID].as_str().expect("id prereq");
        handle_action_add_edge(
            &conn,
            &json!({ "from_action": blocked_id, "to_action": prereq_id, "edge_type": "requires" }),
        )
        .expect("add requires edge ok");

        // Frontier finds the ready action, not the blocked one.
        let f =
            handle_action_frontier(&conn, &json!({ "namespace": "_act" })).expect("frontier ok");
        let ids: Vec<&str> = f["actions"]
            .as_array()
            .expect("actions array")
            .iter()
            .filter_map(|a| a["id"].as_str())
            .collect();
        assert!(
            ids.contains(&a_id.as_str()),
            "the ready action is on the frontier"
        );
        assert!(
            !ids.contains(&blocked_id.as_str()),
            "the blocked action is absent from the frontier"
        );

        // next returns the top frontier row (A, priority 9).
        let n = handle_action_next(&conn, &json!({ "namespace": "_act" })).expect("next ok");
        assert_eq!(n["action"]["id"].as_str(), Some(a_id.as_str()));

        // An empty namespace yields a null next action.
        let empty = handle_action_next(&conn, &json!({ "namespace": "_empty" })).expect("next ok");
        assert!(empty["action"].is_null());
    }

    /// #1722 — a legal action transition appends one
    /// `coordination.action_transition` audit row attributed to the claiming
    /// agent; the append-only chain stays intact.
    #[test]
    fn transition_emits_signed_events_audit_row_1722() {
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

        handle_action_transition(
            &conn,
            &json!({ "id": id, "to": "claimed", "claimed_by": "holder-1" }),
        )
        .expect("transition ok");

        let (count, agent): (i64, String) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(agent_id), '') FROM signed_events \
                 WHERE event_type = ?1",
                rusqlite::params![crate::coordination_audit::ACTION_TRANSITION],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query audit row");
        assert_eq!(count, 1, "one coordination.action_transition row");
        assert_eq!(agent, "holder-1", "row attributed to the claiming agent");

        let report = crate::signed_events::verify_audit_trail(&conn, None).expect("verify");
        assert!(report.chain_intact, "chain must verify; report={report:?}");
    }

    /// #1722 — a lease acquire appends one `coordination.lease_acquire` audit
    /// row attributed to the holder; the append-only chain stays intact.
    #[test]
    fn lease_acquire_emits_signed_events_audit_row_1722() {
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

        handle_lease_acquire(
            &conn,
            &json!({ "action_id": id, "holder": "holder-a", "ttl_secs": 120 }),
        )
        .expect("acquire ok");

        let (count, agent): (i64, String) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(agent_id), '') FROM signed_events \
                 WHERE event_type = ?1",
                rusqlite::params![crate::coordination_audit::LEASE_ACQUIRE],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query audit row");
        assert_eq!(count, 1, "one coordination.lease_acquire row");
        assert_eq!(agent, "holder-a", "row attributed to the lease holder");

        let report = crate::signed_events::verify_audit_trail(&conn, None).expect("verify");
        assert!(report.chain_intact, "chain must verify; report={report:?}");
    }
}
