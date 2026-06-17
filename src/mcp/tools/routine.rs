// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — `memory_routine_*` MCP stdio tools. Thin wrappers
//! over the `crate::routines` sqlite free-functions that expose the
//! parameterised action+edge-template substrate (ROADMAP §11.4) to MCP callers.
//! Mirrors the `crate::checkpoints` / `mcp::tools::checkpoint` split: the
//! handlers hold a bare `rusqlite::Connection` (not a SAL store), so they call
//! the free-functions directly. `handle_routine_freeze` additionally takes the
//! dispatch context's `active_keypair` so the freeze-attestation is
//! Ed25519-signed in place via [`crate::routines::routine_freeze`] when a
//! signing keypair is available.
//!
//! A routine is created in the `Draft` state with a JSON `template` carrying
//! `{{parameter}}` placeholders; it must be `Frozen` (immutable, regulatory
//! hold) before it can be `run`. A run materialises the template under a
//! concrete `{{param}} -> value` argument binding into first-class
//! `crate::actions` rows (+ their DAG edges), recording the created action ids
//! on the run row. Materialisation is fail-safe: ANY parse error records the
//! run as `Failed` (with the error string) rather than panicking or losing the
//! run record.

use crate::identity::keypair::AgentKeypair;
use crate::mcp::param_names;
use crate::models::{
    Action, ActionState, AttestLevel, EdgeType, Routine, RoutineRun, RoutineRunState, RoutineState,
};
use serde_json::{Value, json};

/// JSON response field carrying the serialized routine object (SSOT for the
/// repeated output key across the `memory_routine_*` handlers).
const RESP_ROUTINE: &str = "routine";

/// JSON response field carrying the serialized routine-run object (SSOT for the
/// repeated output key across the `memory_routine_*` handlers).
const RESP_RUN: &str = "run";

/// MCP handler for `memory_routine_create`. Builds a [`crate::models::Routine`]
/// from the request params in the [`crate::models::RoutineState::Draft`] state,
/// inserts it, and returns the created routine as JSON plus its id.
///
/// # Errors
/// Returns an error string when `namespace` / `name` are missing, or the
/// stringified `rusqlite` error on insert failure.
pub fn handle_routine_create(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let namespace = params
        .get(param_names::NAMESPACE)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "namespace is required".to_string())?
        .to_string();
    let name = params
        .get(param_names::NAME)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "name is required".to_string())?
        .to_string();
    let template = params
        .get(param_names::TEMPLATE)
        .cloned()
        .unwrap_or_else(|| json!({}));
    let parameters = params
        .get(param_names::PARAMETERS)
        .cloned()
        .unwrap_or_else(|| json!([]));
    let created_by = params
        .get(param_names::CREATED_BY)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let metadata = params
        .get(param_names::METADATA)
        .cloned()
        .unwrap_or_else(|| json!({}));

    let r = Routine {
        id: uuid::Uuid::new_v4().to_string(),
        namespace,
        name,
        template,
        parameters,
        state: RoutineState::Draft,
        created_by,
        created_at: chrono::Utc::now().timestamp(),
        frozen_at: None,
        signature: vec![],
        signer_pubkey: vec![],
        metadata,
    };

    crate::routines::routine_insert(conn, &r).map_err(|e| e.to_string())?;

    // #1722 — coordination observability: best-effort audit row for the
    // create, attributed to the creating agent (`created_by`, "" when
    // unspecified). Identity = routine id / name / "create".
    crate::coordination_audit::emit(
        conn,
        crate::coordination_audit::ROUTINE_CREATE,
        &r.created_by,
        &[&r.id, &r.name, "create"],
    );

    Ok(json!({
        (param_names::ID): r.id,
        (RESP_ROUTINE): serde_json::to_value(&r).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_routine_freeze`. Flips a routine Draft → Frozen
/// (idempotent on an already-frozen routine), attesting the frozen template in
/// place when `keypair` is `Some` and `can_sign()`. Returns the frozen routine
/// plus the resulting attestation level (`self_signed` vs `unsigned`).
///
/// # Errors
/// Returns an error string when `id` is missing, when no row matches the id,
/// or on the stringified `rusqlite` update error.
pub fn handle_routine_freeze(
    conn: &rusqlite::Connection,
    params: &Value,
    keypair: Option<&AgentKeypair>,
) -> Result<Value, String> {
    let id = params
        .get(param_names::ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "id is required".to_string())?;
    let now = chrono::Utc::now().timestamp();

    let frozen =
        crate::routines::routine_freeze(conn, id, now, keypair).map_err(|e| e.to_string())?;
    match frozen {
        None => Err(format!("routine not found: {id}")),
        Some(r) => {
            // #1722 — coordination observability: best-effort audit row for the
            // freeze, attributed to the routine's creating agent
            // (`created_by`). Identity = routine id / creator / "freeze".
            crate::coordination_audit::emit(
                conn,
                crate::coordination_audit::ROUTINE_FREEZE,
                &r.created_by,
                &[&r.id, &r.created_by, "freeze"],
            );
            let attest_level = if r.signature.is_empty() {
                AttestLevel::Unsigned.as_str()
            } else {
                AttestLevel::SelfSigned.as_str()
            };
            Ok(json!({
                (RESP_ROUTINE): serde_json::to_value(&r).map_err(|e| e.to_string())?,
                (crate::models::field_names::ATTEST_LEVEL): attest_level,
            }))
        }
    }
}

/// Recursively substitute `{{key}}` placeholders inside every `Value::String`
/// of `v` with the matching `arguments[key]`. A string value (`Value::String`)
/// is substituted verbatim; any other JSON value is stringified via
/// [`Value::to_string`] (so a numeric / boolean / object argument is injected as
/// its JSON text). Unmatched placeholders are left verbatim. Non-string nodes
/// recurse into arrays / objects; scalars pass through unchanged.
fn substitute_placeholders(v: &Value, arguments: &serde_json::Map<String, Value>) -> Value {
    match v {
        Value::String(s) => {
            let mut out = s.clone();
            for (key, val) in arguments {
                let needle = format!("{{{{{key}}}}}");
                if out.contains(&needle) {
                    let replacement = match val {
                        Value::String(sv) => sv.clone(),
                        other => other.to_string(),
                    };
                    out = out.replace(&needle, &replacement);
                }
            }
            Value::String(out)
        }
        Value::Array(arr) => Value::Array(
            arr.iter()
                .map(|e| substitute_placeholders(e, arguments))
                .collect(),
        ),
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, val) in map {
                out.insert(k.clone(), substitute_placeholders(val, arguments));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Materialise a frozen routine's `template` under a concrete `arguments`
/// binding into first-class [`crate::actions`] rows (+ their DAG edges).
///
/// The template is expected to be a JSON object with an optional `"actions"`
/// array — each element an object `{kind, title, payload?, priority?}` — and an
/// optional `"edges"` array — each element `{from, to, type?}` where `from` /
/// `to` are 0-based indices into the just-created actions array. Every string
/// field of an action spec (`kind`, `title`, and string values inside
/// `payload`) has its `{{name}}` placeholders substituted from `arguments`.
/// Returns the created action ids in template order.
///
/// Every parse step is a graceful `Err(String)` — a malformed template never
/// panics; the caller records the run as `Failed` with the returned message.
fn materialize_template(
    conn: &rusqlite::Connection,
    routine: &Routine,
    arguments: &serde_json::Map<String, Value>,
    now: i64,
) -> Result<Vec<String>, String> {
    let template = routine
        .template
        .as_object()
        .ok_or_else(|| "routine template must be a JSON object".to_string())?;

    let mut created_ids: Vec<String> = Vec::new();

    if let Some(actions_val) = template.get("actions") {
        let actions = actions_val
            .as_array()
            .ok_or_else(|| "template `actions` must be an array".to_string())?;
        for (i, spec) in actions.iter().enumerate() {
            let spec_obj = spec
                .as_object()
                .ok_or_else(|| format!("template action [{i}] must be an object"))?;
            let kind_raw = spec_obj
                .get("kind")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("template action [{i}] is missing a string `kind`"))?;
            let title_raw = spec_obj
                .get("title")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("template action [{i}] is missing a string `title`"))?;
            // Substitute placeholders in the string fields + the payload.
            let kind =
                match substitute_placeholders(&Value::String(kind_raw.to_string()), arguments) {
                    Value::String(s) => s,
                    _ => kind_raw.to_string(),
                };
            let title =
                match substitute_placeholders(&Value::String(title_raw.to_string()), arguments) {
                    Value::String(s) => s,
                    _ => title_raw.to_string(),
                };
            let payload = spec_obj
                .get("payload")
                .map_or_else(|| json!({}), |p| substitute_placeholders(p, arguments));
            let priority = spec_obj
                .get("priority")
                .and_then(Value::as_i64)
                .unwrap_or(0);

            let action = Action {
                id: uuid::Uuid::new_v4().to_string(),
                namespace: routine.namespace.clone(),
                kind,
                state: ActionState::Pending,
                title,
                payload,
                priority,
                agent_id: Some(routine.created_by.clone()),
                claimed_by: None,
                vector_clock: json!({}),
                metadata: json!({}),
                created_at: now,
                updated_at: now,
            };
            crate::actions::create(conn, &action).map_err(|e| e.to_string())?;
            created_ids.push(action.id);
        }
    }

    if let Some(edges_val) = template.get("edges") {
        let edges = edges_val
            .as_array()
            .ok_or_else(|| "template `edges` must be an array".to_string())?;
        for (i, spec) in edges.iter().enumerate() {
            let spec_obj = spec
                .as_object()
                .ok_or_else(|| format!("template edge [{i}] must be an object"))?;
            let from_idx = spec_obj
                .get("from")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("template edge [{i}] needs a numeric `from` index"))?;
            let to_idx = spec_obj
                .get("to")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("template edge [{i}] needs a numeric `to` index"))?;
            let from_id = created_ids
                .get(usize::try_from(from_idx).unwrap_or(usize::MAX))
                .ok_or_else(|| {
                    format!("template edge [{i}] `from` index {from_idx} out of range")
                })?;
            let to_id = created_ids
                .get(usize::try_from(to_idx).unwrap_or(usize::MAX))
                .ok_or_else(|| format!("template edge [{i}] `to` index {to_idx} out of range"))?;
            let edge_type = spec_obj
                .get("type")
                .and_then(Value::as_str)
                .and_then(EdgeType::from_str)
                .unwrap_or(EdgeType::Sibling);
            crate::actions::add_edge(conn, from_id, to_id, edge_type, now)
                .map_err(|e| e.to_string())?;
        }
    }

    Ok(created_ids)
}

/// MCP handler for `memory_routine_run`. Materialises a FROZEN routine under a
/// concrete argument binding into first-class action (+ edge) rows, recording
/// the created action ids on a `routine_runs` row.
///
/// The run row is created in the `Running` state BEFORE materialisation so a
/// materialisation failure is recorded (state `Failed`, with the error string)
/// rather than lost — the handler returns `Ok` carrying the failed run plus the
/// error, never a hard `Err` that would discard the run record.
///
/// # Errors
/// Returns an error string when the routine id / arguments are missing, when no
/// routine matches the id, when the routine is not `Frozen`, or on a
/// stringified `rusqlite` error inserting the run row.
pub fn handle_routine_run(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let routine_id = params
        .get(param_names::ROUTINE_ID)
        .or_else(|| params.get(param_names::ID))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "routine_id is required".to_string())?;
    let arguments = params
        .get(param_names::ARGUMENTS)
        .and_then(Value::as_object)
        .ok_or_else(|| "arguments is required (a JSON object of {{param}} -> value)".to_string())?
        .clone();

    // (1) Load the routine; it must exist AND be frozen before a run.
    let routine = crate::routines::routine_get(conn, routine_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("routine not found: {routine_id}"))?;
    if routine.state != RoutineState::Frozen {
        return Err("routine must be frozen before it can be run".to_string());
    }

    // (2) Insert the run row in the Running state before materialising.
    let now = chrono::Utc::now().timestamp();
    let run = RoutineRun {
        id: uuid::Uuid::new_v4().to_string(),
        routine_id: routine_id.to_string(),
        namespace: routine.namespace.clone(),
        arguments: Value::Object(arguments.clone()),
        state: RoutineRunState::Running,
        created_action_ids: json!([]),
        started_at: now,
        finished_at: None,
        error: None,
        metadata: json!({}),
    };
    let run_id = crate::routines::run_insert(conn, &run).map_err(|e| e.to_string())?;

    // #1722 — coordination observability: best-effort audit row for the run,
    // attributed to the routine's owning agent (`created_by`, "" when
    // unspecified) since the run materialises actions under that principal.
    // Identity = routine id / run id / "run". Emitted once the run row is
    // recorded (it persists in both the failed and completed paths below).
    crate::coordination_audit::emit(
        conn,
        crate::coordination_audit::ROUTINE_RUN,
        &routine.created_by,
        &[routine_id, &run_id, "run"],
    );

    // (3) Materialise the template — a SINGLE match folds the success /
    // failure paths so the failed run is always recorded, never lost.
    match materialize_template(conn, &routine, &arguments, now) {
        Err(err) => {
            let failed = crate::routines::run_set_state(
                conn,
                &run_id,
                RoutineRunState::Failed,
                Some(now),
                None,
                Some(&err),
            )
            .map_err(|e| e.to_string())?;
            Ok(json!({
                (RESP_RUN): serde_json::to_value(&failed).map_err(|e| e.to_string())?,
                "error": err,
            }))
        }
        Ok(created_action_ids) => {
            let ids_json = json!(created_action_ids);
            let completed = crate::routines::run_set_state(
                conn,
                &run_id,
                RoutineRunState::Completed,
                Some(now),
                Some(&ids_json),
                None,
            )
            .map_err(|e| e.to_string())?;
            Ok(json!({
                (RESP_RUN): serde_json::to_value(&completed).map_err(|e| e.to_string())?,
                "created_action_ids": ids_json,
            }))
        }
    }
}

/// MCP handler for `memory_routine_status`. Fetches a routine run by id. The
/// `run` field is `null` when no row matches, mirroring how
/// `memory_checkpoint_verify` reports an absent row.
///
/// # Errors
/// Returns an error string when `run_id` is missing, or the stringified
/// `rusqlite` error on query failure.
pub fn handle_routine_status(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let run_id = params
        .get(param_names::RUN_ID)
        .or_else(|| params.get(param_names::ID))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "run_id is required".to_string())?;
    let found = crate::routines::run_get(conn, run_id).map_err(|e| e.to_string())?;
    Ok(json!({
        (RESP_RUN): match found {
            Some(r) => serde_json::to_value(&r).map_err(|e| e.to_string())?,
            None => Value::Null,
        },
    }))
}

/// MCP handler for `memory_routine_list`. Lists a namespace's routines,
/// newest-first, optionally narrowed by `state`, capped at `limit` (default 50).
///
/// # Errors
/// Returns an error string when `namespace` is missing, or the stringified
/// `rusqlite` error on query failure.
pub fn handle_routine_list(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let namespace = params
        .get(param_names::NAMESPACE)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "namespace is required".to_string())?;
    let state = params
        .get(param_names::STATE)
        .and_then(Value::as_str)
        .and_then(RoutineState::from_str);
    let limit = params
        .get(param_names::LIMIT)
        .and_then(Value::as_i64)
        .unwrap_or(50);
    let limit = usize::try_from(limit).unwrap_or(50);

    let routines =
        crate::routines::routine_list(conn, namespace, state, limit).map_err(|e| e.to_string())?;
    Ok(json!({
        "routines": serde_json::to_value(&routines).map_err(|e| e.to_string())?,
    }))
}

// --- per-tool McpTool impls (v0.8.0 Pillar 1, #1709) ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_routine_create`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct RoutineCreateRequest {
    pub namespace: String,

    pub name: String,

    /// JSON action+edge declarations carrying `{{parameter}}` placeholders.
    /// Defaults to `{}`.
    #[serde(default)]
    pub template: Value,

    /// JSON array of declared parameter names. Defaults to `[]`.
    #[serde(default)]
    pub parameters: Value,

    /// Agent id that created the routine.
    #[serde(default)]
    pub created_by: Option<String>,

    /// Arbitrary JSON metadata. Defaults to `{}`.
    #[serde(default)]
    pub metadata: Value,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_routine_freeze`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct RoutineFreezeRequest {
    pub id: String,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_routine_run`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct RoutineRunRequest {
    pub routine_id: String,

    /// Concrete `{{param}} -> value` bindings substituted into the template.
    pub arguments: Value,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_routine_status`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct RoutineStatusRequest {
    pub run_id: String,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_routine_list`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct RoutineListRequest {
    pub namespace: String,

    /// Narrow to a single lifecycle state (`draft` / `frozen`) when set.
    #[serde(default)]
    pub state: Option<String>,

    #[serde(default)]
    pub limit: Option<i64>,
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_routine_create`.
#[allow(dead_code)]
pub struct RoutineCreateTool;

impl McpTool for RoutineCreateTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ROUTINE_CREATE
    }
    fn description() -> &'static str {
        "Create a draft routine — a parameterised action+edge template (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): create a routine in the draft state from a JSON template with `{{parameter}}` placeholders; freeze it before it can be run."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<RoutineCreateRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_routine_freeze`.
#[allow(dead_code)]
pub struct RoutineFreezeTool;

impl McpTool for RoutineFreezeTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ROUTINE_FREEZE
    }
    fn description() -> &'static str {
        "Freeze a routine (draft -> frozen), Ed25519-attested when signing (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): freeze a routine into its immutable regulatory-hold form; the frozen template self-signs when a signing keypair is available."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<RoutineFreezeRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_routine_run`.
#[allow(dead_code)]
pub struct RoutineRunTool;

impl McpTool for RoutineRunTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ROUTINE_RUN
    }
    fn description() -> &'static str {
        "Run a frozen routine — materialise its template into action rows (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): materialise a frozen routine under a concrete argument binding into first-class action+edge rows; a malformed template records the run as failed rather than panicking."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<RoutineRunRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_routine_status`.
#[allow(dead_code)]
pub struct RoutineStatusTool;

impl McpTool for RoutineStatusTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ROUTINE_STATUS
    }
    fn description() -> &'static str {
        "Fetch a routine run by id, with its state and created action ids (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): fetch a routine run by id; the run field is null when no row matches."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<RoutineStatusRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_routine_list`.
#[allow(dead_code)]
pub struct RoutineListTool;

impl McpTool for RoutineListTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ROUTINE_LIST
    }
    fn description() -> &'static str {
        "List a namespace's routines by state, newest-first (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): list a namespace's routines, optionally narrowed by lifecycle state, newest-first."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<RoutineListRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_6_1709_tests {
    //! D1.6 (#987) parity tests for the Pillar-1 `memory_routine_*` tools.
    use super::*;

    #[test]
    fn routine_create_tool_metadata() {
        assert_eq!(RoutineCreateTool::name(), "memory_routine_create");
        assert_eq!(RoutineCreateTool::family(), "power");
        assert!(!RoutineCreateTool::description().is_empty());
        assert!(!RoutineCreateTool::docs().is_empty());
    }

    #[test]
    fn routine_freeze_tool_metadata() {
        assert_eq!(RoutineFreezeTool::name(), "memory_routine_freeze");
        assert_eq!(RoutineFreezeTool::family(), "power");
        assert!(!RoutineFreezeTool::description().is_empty());
        assert!(!RoutineFreezeTool::docs().is_empty());
    }

    #[test]
    fn routine_run_tool_metadata() {
        assert_eq!(RoutineRunTool::name(), "memory_routine_run");
        assert_eq!(RoutineRunTool::family(), "power");
        assert!(!RoutineRunTool::description().is_empty());
        assert!(!RoutineRunTool::docs().is_empty());
    }

    #[test]
    fn routine_status_tool_metadata() {
        assert_eq!(RoutineStatusTool::name(), "memory_routine_status");
        assert_eq!(RoutineStatusTool::family(), "power");
        assert!(!RoutineStatusTool::description().is_empty());
        assert!(!RoutineStatusTool::docs().is_empty());
    }

    #[test]
    fn routine_list_tool_metadata() {
        assert_eq!(RoutineListTool::name(), "memory_routine_list");
        assert_eq!(RoutineListTool::family(), "power");
        assert!(!RoutineListTool::description().is_empty());
        assert!(!RoutineListTool::docs().is_empty());
    }

    #[test]
    fn routine_create_schema_requires_core_fields() {
        let schema = RoutineCreateTool::input_schema();
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
        for name in &["namespace", "name"] {
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

    /// Create -> freeze (unsigned) -> run with arguments {{what}} -> assert the
    /// single materialised action's title is the SUBSTITUTED value, the run is
    /// Completed, status returns it, and list finds the routine.
    #[test]
    fn create_freeze_run_status_list_roundtrips_over_mcp() {
        let conn = fresh();
        // Create a routine whose one action's title is a `{{what}}` placeholder.
        let created = handle_routine_create(
            &conn,
            &json!({
                "namespace": "_rt",
                "name": "deploy",
                "template": {"actions": [{"kind": "task.do", "title": "{{what}}"}]},
                "parameters": ["what"],
                "created_by": "agent-a",
            }),
        )
        .expect("create ok");
        let routine_id = created[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();
        assert_eq!(created["routine"]["state"].as_str(), Some("draft"));

        // Freeze (no keypair -> unsigned).
        let frozen =
            handle_routine_freeze(&conn, &json!({ "id": routine_id }), None).expect("freeze ok");
        assert_eq!(frozen["attest_level"].as_str(), Some("unsigned"));
        assert_eq!(frozen["routine"]["state"].as_str(), Some("frozen"));

        // Run with arguments {{what}} = "ship it".
        let ran = handle_routine_run(
            &conn,
            &json!({ "routine_id": routine_id, "arguments": {"what": "ship it"} }),
        )
        .expect("run ok");
        let action_ids = ran["created_action_ids"]
            .as_array()
            .expect("created_action_ids array");
        assert_eq!(action_ids.len(), 1, "one action materialised");
        assert_eq!(ran["run"]["state"].as_str(), Some("completed"));
        let run_id = ran["run"]["id"].as_str().expect("run id").to_string();

        // The created action's title is the SUBSTITUTED value (proves
        // `{{param}}` substitution worked).
        let action_id = action_ids[0].as_str().expect("action id");
        let action = crate::actions::get(&conn, action_id)
            .expect("get action")
            .expect("action present");
        assert_eq!(action.title, "ship it", "{{what}} substituted to argument");

        // Status returns the run.
        let status = handle_routine_status(&conn, &json!({ "run_id": run_id })).expect("status ok");
        assert_eq!(status["run"]["state"].as_str(), Some("completed"));
        assert_eq!(status["run"]["id"].as_str(), Some(run_id.as_str()));

        // List finds the routine.
        let listed = handle_routine_list(&conn, &json!({ "namespace": "_rt" })).expect("list ok");
        let arr = listed["routines"].as_array().expect("routines array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"].as_str(), Some(routine_id.as_str()));
    }

    /// #1722 — running a frozen routine appends one `coordination.routine_run`
    /// audit row attributed to the routine's owning agent; the append-only
    /// chain stays intact.
    #[test]
    fn run_emits_signed_events_audit_row_1722() {
        let conn = fresh();
        let created = handle_routine_create(
            &conn,
            &json!({
                "namespace": "_rt",
                "name": "deploy",
                "template": {"actions": [{"kind": "task.do", "title": "{{what}}"}]},
                "created_by": "agent-a",
            }),
        )
        .expect("create ok");
        let routine_id = created[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();
        handle_routine_freeze(&conn, &json!({ "id": routine_id }), None).expect("freeze ok");

        handle_routine_run(
            &conn,
            &json!({ "routine_id": routine_id, "arguments": {"what": "ship it"} }),
        )
        .expect("run ok");

        let (count, agent): (i64, String) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(agent_id), '') FROM signed_events \
                 WHERE event_type = ?1",
                rusqlite::params![crate::coordination_audit::ROUTINE_RUN],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query audit row");
        assert_eq!(count, 1, "one coordination.routine_run row");
        assert_eq!(agent, "agent-a", "row attributed to the routine owner");

        let report = crate::signed_events::verify_audit_trail(&conn, None).expect("verify");
        assert!(report.chain_intact, "chain must verify; report={report:?}");
    }

    #[test]
    fn run_unfrozen_routine_errors() {
        let conn = fresh();
        let created =
            handle_routine_create(&conn, &json!({ "namespace": "_rt", "name": "draft-only" }))
                .expect("create ok");
        let routine_id = created[param_names::ID].as_str().expect("id present");
        let err = handle_routine_run(&conn, &json!({ "routine_id": routine_id, "arguments": {} }))
            .expect_err("running a draft routine must error");
        assert!(
            err.contains("frozen"),
            "error explains the freeze requirement: {err}"
        );
    }

    #[test]
    fn run_malformed_template_records_failed_run_not_panic() {
        let conn = fresh();
        // `actions` is a string, not an array — materialisation must fail
        // gracefully and record the run as Failed (not panic, not lose the run).
        let created = handle_routine_create(
            &conn,
            &json!({
                "namespace": "_rt",
                "name": "broken",
                "template": {"actions": "not-an-array"},
            }),
        )
        .expect("create ok");
        let routine_id = created[param_names::ID].as_str().expect("id present");
        handle_routine_freeze(&conn, &json!({ "id": routine_id }), None).expect("freeze ok");

        let ran = handle_routine_run(&conn, &json!({ "routine_id": routine_id, "arguments": {} }))
            .expect("run returns Ok carrying the failed run, never a hard Err");
        assert_eq!(ran["run"]["state"].as_str(), Some("failed"));
        assert!(
            ran["error"].as_str().unwrap_or_default().contains("array"),
            "failure records the parse error: {:?}",
            ran["error"]
        );
        // The run record persisted with the error string.
        let run_id = ran["run"]["id"].as_str().expect("run id");
        let status = handle_routine_status(&conn, &json!({ "run_id": run_id })).expect("status ok");
        assert_eq!(status["run"]["state"].as_str(), Some("failed"));
        assert!(status["run"]["error"].as_str().is_some());
    }

    #[test]
    fn status_absent_returns_null_run() {
        let conn = fresh();
        let got = handle_routine_status(&conn, &json!({ "run_id": "missing" })).expect("status ok");
        assert!(got["run"].is_null());
    }

    #[test]
    fn list_filters_by_state() {
        let conn = fresh();
        let a = handle_routine_create(&conn, &json!({ "namespace": "_rt", "name": "a" }))
            .expect("create a");
        handle_routine_create(&conn, &json!({ "namespace": "_rt", "name": "b" }))
            .expect("create b");
        // Freeze only `a`.
        handle_routine_freeze(&conn, &json!({ "id": a[param_names::ID] }), None).expect("freeze a");

        let frozen = handle_routine_list(&conn, &json!({ "namespace": "_rt", "state": "frozen" }))
            .expect("list frozen");
        assert_eq!(frozen["routines"].as_array().expect("array").len(), 1);
        let drafts = handle_routine_list(&conn, &json!({ "namespace": "_rt", "state": "draft" }))
            .expect("list drafts");
        assert_eq!(drafts["routines"].as_array().expect("array").len(), 1);
    }
}
