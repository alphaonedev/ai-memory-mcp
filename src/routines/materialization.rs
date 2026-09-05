// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared routine template parsing and atomic SQLite materialisation (#3359).

use crate::models::{Action, ActionState, EdgeType, Routine};
use serde_json::{Value, json};

pub(crate) struct Materialization {
    pub actions: Vec<Action>,
    pub edges: Vec<(String, String, EdgeType)>,
}

/// Bound substitutions while allocating, including repeated placeholders and
/// replacements that introduce a later placeholder. Each field gets the same
/// serialized JSON ceiling as a direct create; the direct validator also checks
/// the narrower title/kind limits after substitution.
fn substitute_field(
    v: &Value,
    arguments: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Value, FieldLimitError> {
    let mut remaining = crate::coordination_guard::MAX_PAYLOAD_BYTES;
    substitute_placeholders(v, arguments, field, &mut remaining)
}

#[derive(Debug)]
struct FieldLimitError {
    field: String,
}

impl std::fmt::Display for FieldLimitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} exceeds the materialised field limit",
            self.field
        )
    }
}

impl std::error::Error for FieldLimitError {}

fn field_limit_error(field: &str) -> FieldLimitError {
    FieldLimitError {
        field: field.to_string(),
    }
}

fn consume_budget(remaining: &mut usize, bytes: usize, field: &str) -> Result<(), FieldLimitError> {
    *remaining = remaining
        .checked_sub(bytes)
        .ok_or_else(|| field_limit_error(field))?;
    Ok(())
}

fn substitute_placeholders(
    v: &Value,
    arguments: &serde_json::Map<String, Value>,
    field: &str,
    remaining: &mut usize,
) -> Result<Value, FieldLimitError> {
    match v {
        Value::String(s) => {
            let mut out = s.clone();
            for (key, val) in arguments {
                let needle = format!("{{{{{key}}}}}");
                let count = out.matches(&needle).count();
                if count > 0 {
                    let replacement = val.as_str().map_or_else(|| val.to_string(), str::to_string);
                    let expanded = out
                        .len()
                        .checked_sub(count.saturating_mul(needle.len()))
                        .and_then(|n| {
                            count
                                .checked_mul(replacement.len())
                                .and_then(|extra| n.checked_add(extra))
                        })
                        .ok_or_else(|| field_limit_error(field))?;
                    if expanded > *remaining {
                        return Err(field_limit_error(field));
                    }
                    out = out.replace(&needle, &replacement);
                }
            }
            let out = Value::String(out);
            consume_budget(remaining, out.to_string().len(), field)?;
            Ok(out)
        }
        Value::Array(arr) => {
            consume_budget(remaining, 2 + arr.len().saturating_sub(1), field)?;
            arr.iter()
                .map(|v| substitute_placeholders(v, arguments, field, remaining))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        Value::Object(map) => {
            consume_budget(remaining, 2 + map.len().saturating_sub(1), field)?;
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, val) in map {
                consume_budget(
                    remaining,
                    Value::String(key.clone()).to_string().len() + 1,
                    field,
                )?;
                out.insert(
                    key.clone(),
                    substitute_placeholders(val, arguments, field, remaining)?,
                );
            }
            Ok(Value::Object(out))
        }
        other => {
            consume_budget(remaining, other.to_string().len(), field)?;
            Ok(other.clone())
        }
    }
}

pub(crate) fn plan(
    routine: &Routine,
    arguments: &Value,
    now: i64,
) -> Result<Materialization, String> {
    if routine.state != crate::models::RoutineState::Frozen {
        return Err(crate::routines::ROUTINE_NOT_FROZEN.to_string());
    }
    crate::coordination_guard::require_payload_size("template", &routine.template)?;
    crate::coordination_guard::require_payload_size("arguments", arguments)?;
    let arguments = arguments
        .as_object()
        .ok_or_else(|| "arguments must be a JSON object".to_string())?;
    let template = routine
        .template
        .as_object()
        .ok_or_else(|| "routine template must be a JSON object".to_string())?;

    // #3010 — REJECT unknown top-level template keys instead of silently
    // dropping them. `materialize_template` recognizes only `actions` + `edges`;
    // pre-fix a template of `{steps:[...]}` materialized ZERO actions yet the run
    // still reported `state:completed, error:null` (indistinguishable from a run
    // that did its job — the #2444 shape), and `{actions,edges,UNKNOWN_KEY}`
    // dropped UNKNOWN_KEY. The check runs BEFORE any action is inserted so an
    // unrecognized-key template is an ATOMIC reject (no partial materialisation),
    // recorded as a Failed run by the caller.
    const RECOGNIZED_KEYS: [&str; 2] = ["actions", "edges"];
    for key in template.keys() {
        if !RECOGNIZED_KEYS.contains(&key.as_str()) {
            return Err(format!(
                "unrecognized template key '{key}' (recognized keys: actions, edges)"
            ));
        }
    }

    let mut planned_actions = Vec::new();
    let mut planned_edges = Vec::new();

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
                match substitute_field(&Value::String(kind_raw.to_string()), arguments, "kind")
                    .map_err(|e| e.to_string())?
                {
                    Value::String(s) => s,
                    _ => kind_raw.to_string(),
                };
            let title =
                match substitute_field(&Value::String(title_raw.to_string()), arguments, "title")
                    .map_err(|e| e.to_string())?
                {
                    Value::String(s) => s,
                    _ => title_raw.to_string(),
                };
            let payload = spec_obj
                .get("payload")
                .map(|p| substitute_field(p, arguments, "payload"))
                .transpose()
                .map_err(|e| e.to_string())?
                .unwrap_or_else(|| json!({}));
            let priority = crate::mcp::param_guard::optional_i64(spec, "priority")?.unwrap_or(0);

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
                metadata: spec_obj
                    .get("metadata")
                    .map(|v| substitute_field(v, arguments, "metadata"))
                    .transpose()
                    .map_err(|e| e.to_string())?
                    .unwrap_or_else(|| json!({})),
                created_at: now,
                updated_at: now,
            };
            planned_actions.push(action);
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
            let from_action = planned_actions
                .get(usize::try_from(from_idx).unwrap_or(usize::MAX))
                .ok_or_else(|| {
                    format!("template edge [{i}] `from` index {from_idx} out of range")
                })?;
            let to_action = planned_actions
                .get(usize::try_from(to_idx).unwrap_or(usize::MAX))
                .ok_or_else(|| format!("template edge [{i}] `to` index {to_idx} out of range"))?;
            let edge_type = match spec_obj.get("type") {
                None => EdgeType::Sibling,
                Some(value) => value
                    .as_str()
                    .and_then(EdgeType::from_str)
                    .ok_or_else(|| format!("template edge [{i}] has invalid edge type"))?,
            };
            planned_edges.push((from_action.id.clone(), to_action.id.clone(), edge_type));
        }
    }

    if planned_actions.is_empty() {
        return Err(
            "routine template materialised zero actions (no `actions` entries)".to_string(),
        );
    }
    Ok(Materialization {
        actions: planned_actions,
        edges: planned_edges,
    })
}

/// Materialise actions and edges with the direct-create guard/quota funnel.
///
/// # Errors
/// Invalid templates, action guards, quota refusals and persistence errors roll
/// back the entire DAG and every charge.
pub fn materialize_template(
    conn: &rusqlite::Connection,
    routine: &Routine,
    arguments: &Value,
    now: i64,
) -> Result<Vec<String>, String> {
    let plan = plan(routine, arguments, now)?;
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
    let mut ids = Vec::with_capacity(plan.actions.len());
    for action in plan.actions {
        ids.push(crate::actions::create_guarded_in_transaction(&tx, action)?.id);
    }
    for (from, to, edge_type) in plan.edges {
        match crate::actions::add_edge(&tx, &from, &to, edge_type, now)
            .map_err(|e| e.to_string())?
        {
            crate::actions::AddEdgeOutcome::Added => {}
            crate::actions::AddEdgeOutcome::SelfEdge => {
                return Err("template edge is a self-edge (from == to)".to_string());
            }
            crate::actions::AddEdgeOutcome::WouldCycle => {
                return Err(
                    "template edge would close a cycle in the action ordering DAG".to_string(),
                );
            }
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(ids)
}
