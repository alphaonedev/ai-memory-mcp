// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared routine template parsing and atomic SQLite materialisation (#3359).

use crate::models::{Action, ActionState, EdgeType, Routine};
use serde_json::{Value, json};

/// An ownerless legacy routine cannot be admitted for an enforced caller.
pub const ROUTINE_OWNER_UNKNOWN: &str = "ROUTINE_OWNER_UNKNOWN";

/// Resolve owner-only run admission before any run, audit, DAG or quota write.
/// SAL supplies its authenticated `agent_id`; `as_agent` and admin visibility
/// bypasses do not grant execution. An absent caller retains the MCP/local
/// single-operator identity ladder (#3506, ERRORS-09).
///
/// # Errors
/// Refuses unknown owners under an enforced caller, invalid identities and
/// caller/owner mismatches using the existing governance-subject contract.
pub(crate) fn authorize_run(owner: &str, caller: Option<&str>) -> anyhow::Result<String> {
    let enforced = crate::identity::resolve_mcp_read_visibility_caller()?;
    if owner.is_empty() && (enforced.is_some() || caller.is_some()) {
        anyhow::bail!(ROUTINE_OWNER_UNKNOWN);
    }
    let actor = crate::identity::resolve_governance_subject(Some(owner), None, "run routine")?;
    if let Some(caller) = caller {
        crate::validate::validate_agent_id(caller)?;
        let caller =
            crate::identity::resolve_governance_subject(Some(caller), None, "run routine")?;
        if caller != actor {
            anyhow::bail!(
                "agent_id mismatch: caller '{caller}' may only run routine as itself \
                 (requested '{actor}')"
            );
        }
    }
    Ok(actor)
}

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

/// #3369 — the closed `type` vocabulary a frozen parameter may declare.
const PARAMETER_TYPES: [&str; 7] = [
    "string", "number", "integer", "boolean", "object", "array", "any",
];

/// #3369 — one declared parameter, normalised from either `parameters`
/// shape (see [`validate_arguments_against_parameters`]).
struct DeclaredParameter {
    name: String,
    required: bool,
    ty: Option<String>,
}

/// #3369 — read one parameter SPEC (`true` / `false` / `null` / an object
/// with optional `required` + `type`) for `name`.
fn declared_parameter_from_spec(name: &str, spec: &Value) -> Result<DeclaredParameter, String> {
    let (required, ty) = match spec {
        Value::Bool(required) => (*required, None),
        Value::Null => (false, None),
        Value::Object(map) => {
            let required = match map.get("required") {
                None | Some(Value::Null) => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => {
                    return Err(format!(
                        "routine parameter '{name}' has a non-boolean `required` flag"
                    ));
                }
            };
            let ty = match map.get("type") {
                None | Some(Value::Null) => None,
                Some(Value::String(t)) if PARAMETER_TYPES.contains(&t.as_str()) => Some(t.clone()),
                Some(Value::String(t)) => {
                    return Err(format!(
                        "routine parameter '{name}' declares unsupported type '{t}' \
                         (supported: {})",
                        PARAMETER_TYPES.join(", ")
                    ));
                }
                Some(_) => {
                    return Err(format!(
                        "routine parameter '{name}' has a non-string `type`"
                    ));
                }
            };
            (required, ty)
        }
        _ => {
            return Err(format!(
                "routine parameter '{name}' must be declared as a boolean, null or an object"
            ));
        }
    };
    Ok(DeclaredParameter {
        name: name.to_string(),
        required,
        ty,
    })
}

/// #3369 — normalise the frozen `parameters` declaration. Two shapes are
/// accepted, both already in the wild: a JSON ARRAY of names (`["t"]`, every
/// name REQUIRED — the array form has no way to say otherwise) or of
/// `{name, required?, type?}` objects; or a JSON OBJECT keyed by name whose
/// value is a spec (`{"t": {"required": true, "type": "integer"}}`,
/// `{"t": true}`). `null` / an empty value declares nothing. Any other
/// shape is refused (fail-closed: the declaration was attested at freeze,
/// so an unreadable one must not silently enforce nothing).
fn declared_parameters(parameters: &Value) -> Result<Vec<DeclaredParameter>, String> {
    match parameters {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, item)| match item {
                Value::String(name) if !name.trim().is_empty() => Ok(DeclaredParameter {
                    name: name.clone(),
                    required: true,
                    ty: None,
                }),
                Value::Object(map) => {
                    let name = map
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|n| !n.trim().is_empty())
                        .ok_or_else(|| {
                            format!("routine parameters[{i}] must carry a non-empty string `name`")
                        })?;
                    declared_parameter_from_spec(name, item)
                }
                _ => Err(format!(
                    "routine parameters[{i}] must be a parameter name or a {{name, required, type}} object"
                )),
            })
            .collect(),
        Value::Object(map) => map
            .iter()
            .map(|(name, spec)| declared_parameter_from_spec(name, spec))
            .collect(),
        _ => Err("routine parameters must be a JSON array or object".to_string()),
    }
}

/// #3369 — does `value` satisfy the declared `type` token?
fn argument_matches_type(value: &Value, ty: &str) -> bool {
    match ty {
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        _ => true,
    }
}

/// #3369 — enforce the frozen `parameters` declaration against the run's
/// `arguments`: every `required` parameter must be present (JSON `null`
/// does not count as supplied) and every supplied declared parameter must
/// match its declared `type`. Undeclared arguments are admitted (the
/// pre-#3369 default declaration is `[]`); an unbound placeholder is caught
/// separately by [`find_unresolved_placeholder`].
///
/// # Errors
/// A refusal string naming the offending parameter.
pub(crate) fn validate_arguments_against_parameters(
    parameters: &Value,
    arguments: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    for param in declared_parameters(parameters)? {
        match arguments.get(&param.name) {
            None | Some(Value::Null) if param.required => {
                return Err(format!(
                    "routine run is missing required parameter '{}' (declared in the \
                     frozen parameters)",
                    param.name
                ));
            }
            Some(value) => {
                if let Some(ty) = &param.ty
                    && !value.is_null()
                    && !argument_matches_type(value, ty)
                {
                    return Err(format!(
                        "routine argument '{}' must be of type {ty} (declared in the frozen \
                         parameters)",
                        param.name
                    ));
                }
            }
            None => {}
        }
    }
    Ok(())
}

/// #3369 — the first `{{name}}` placeholder still present anywhere in
/// `value` after substitution (strings, recursively through arrays and
/// objects, including object keys). A placeholder name is a non-empty run
/// of `[A-Za-z0-9_.-]` between `{{` and `}}`, optionally padded with
/// whitespace; braces around anything else are plain text.
fn find_unresolved_placeholder(value: &Value) -> Option<String> {
    fn in_str(s: &str) -> Option<String> {
        let mut rest = s;
        while let Some(start) = rest.find("{{") {
            let after = &rest[start + 2..];
            let Some(end) = after.find("}}") else {
                return None;
            };
            let name = after[..end].trim();
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
            {
                return Some(name.to_string());
            }
            rest = &after[end + 2..];
        }
        None
    }
    match value {
        Value::String(s) => in_str(s),
        Value::Array(items) => items.iter().find_map(find_unresolved_placeholder),
        Value::Object(map) => map
            .iter()
            .find_map(|(k, v)| in_str(k).or_else(|| find_unresolved_placeholder(v))),
        _ => None,
    }
}

pub(crate) fn plan(
    routine: &Routine,
    arguments: &Value,
    now: i64,
    caller: Option<&str>,
) -> Result<Materialization, String> {
    let actor = authorize_run(&routine.created_by, caller).map_err(|e| e.to_string())?;
    if routine.state != crate::models::RoutineState::Frozen {
        return Err(crate::routines::ROUTINE_NOT_FROZEN.to_string());
    }
    // #3616: present attestations must verify, including legacy untagged or
    // incomplete pairs. Never downgrade a failed attestation to unsigned.
    if (!routine.signature.is_empty() || !routine.signer_pubkey.is_empty())
        && !crate::routines::verify(routine)
    {
        return Err(
            "routine freeze attestation verification failed; review the template and parameters, then re-freeze with memory_routine_freeze using an active signing key before running"
                .to_string(),
        );
    }
    crate::coordination_guard::require_payload_size("template", &routine.template)?;
    crate::coordination_guard::require_payload_size("arguments", arguments)?;
    let arguments = arguments
        .as_object()
        .ok_or_else(|| "arguments must be a JSON object".to_string())?;
    // #3369 — the frozen `parameters` declaration is signed into the freeze
    // attestation; honour it before any substitution so a missing required
    // parameter or a wrongly-typed argument refuses the run instead of
    // silently materialising literal `{{placeholder}}` text.
    validate_arguments_against_parameters(&routine.parameters, arguments)?;
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
            let metadata = spec_obj
                .get("metadata")
                .map(|v| substitute_field(v, arguments, "metadata"))
                .transpose()
                .map_err(|e| e.to_string())?
                .unwrap_or_else(|| json!({}));

            // #3369 — a placeholder the arguments did not bind must never
            // land as literal `{{name}}` text: refuse the whole run (atomic;
            // nothing is inserted yet) naming the placeholder and the field.
            for (field, value) in [
                ("kind", &Value::String(kind.clone())),
                ("title", &Value::String(title.clone())),
                ("payload", &payload),
                ("metadata", &metadata),
            ] {
                if let Some(name) = find_unresolved_placeholder(value) {
                    return Err(format!(
                        "unresolved placeholder '{{{{{name}}}}}' in template action [{i}] \
                         field `{field}`: pass `{name}` in arguments"
                    ));
                }
            }

            let action = Action {
                id: uuid::Uuid::new_v4().to_string(),
                namespace: routine.namespace.clone(),
                kind,
                state: ActionState::Pending,
                title,
                payload,
                priority,
                agent_id: Some(actor.clone()),
                claimed_by: None,
                vector_clock: json!({}),
                metadata,
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
    materialize_template_for_caller(conn, routine, arguments, now, None)
}

pub(crate) fn materialize_template_for_caller(
    conn: &rusqlite::Connection,
    routine: &Routine,
    arguments: &Value,
    now: i64,
    caller: Option<&str>,
) -> Result<Vec<String>, String> {
    let plan = plan(routine, arguments, now, caller)?;
    // BEGIN IMMEDIATE (#5084, the #2250 class): create_guarded_in_transaction
    // reads (record-stop gate, quota row) before it writes.
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    let mut ids = Vec::with_capacity(plan.actions.len());
    for action in plan.actions {
        ids.push(
            crate::actions::create_guarded_in_transaction(&tx, action)
                .map_err(|e| e.message())?
                .id,
        );
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
