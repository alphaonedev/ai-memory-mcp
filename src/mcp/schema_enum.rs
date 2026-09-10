// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3378 unit 2 — inline JSON-Schema `enum` lists for closed MCP string
//! fields (`to` / `edge_type` / `signal_type` / `condition_type` /
//! `state`).
//!
//! Request structs keep `String` / `Option<String>` so handler
//! deserialize + `from_str` error text stay byte-identical. The
//! schemars `schema_with` hooks here are discovery-only: they inline
//! `{ "type": "string", "enum": [...] }` (plus `null` on optional
//! fields) on the property itself so an NHI reading
//! `properties.<name>.enum` does not have to walk `$ref` /
//! `definitions`. Values come from the domain `ALL` / `CALLER_MINTABLE`
//! / `RESOLUTION` arrays (SSOT with `as_str` / `from_str`).
//!
//! `memory_swarm_rewind.to` is a SHA, not a closed vocabulary, and is
//! deliberately not wired here.

use schemars::r#gen::SchemaGenerator;
use schemars::schema::{InstanceType, Schema, SchemaObject};
use serde_json::Value;

use crate::models::{
    ActionState, CheckpointState, ConditionType, EdgeType, RoutineState, SignalType,
};

fn closed_string_enum(names: impl IntoIterator<Item = &'static str>, optional: bool) -> Schema {
    let mut values: Vec<Value> = names
        .into_iter()
        .map(|s| Value::String(s.to_string()))
        .collect();
    let instance_type = if optional {
        values.push(Value::Null);
        vec![InstanceType::String, InstanceType::Null].into()
    } else {
        InstanceType::String.into()
    };
    Schema::Object(SchemaObject {
        instance_type: Some(instance_type),
        enum_values: Some(values),
        ..Default::default()
    })
}

fn wire_names<T: Copy>(all: &[T], as_str: fn(&T) -> &'static str) -> Vec<&'static str> {
    all.iter().map(as_str).collect()
}

/// `memory_action_transition.to` — required.
pub fn action_state(_gen: &mut SchemaGenerator) -> Schema {
    closed_string_enum(wire_names(&ActionState::ALL, ActionState::as_str), false)
}

/// `memory_action_list.state` — optional filter.
pub fn action_state_optional(_gen: &mut SchemaGenerator) -> Schema {
    closed_string_enum(wire_names(&ActionState::ALL, ActionState::as_str), true)
}

/// `memory_action_add_edge.edge_type` — required.
pub fn edge_type(_gen: &mut SchemaGenerator) -> Schema {
    closed_string_enum(wire_names(&EdgeType::ALL, EdgeType::as_str), false)
}

/// `memory_signal_send.signal_type` — optional, defaults to `notify`.
pub fn signal_type_optional(_gen: &mut SchemaGenerator) -> Schema {
    closed_string_enum(wire_names(&SignalType::ALL, SignalType::as_str), true)
}

/// `memory_checkpoint_create.condition_type` — optional, caller-mintable
/// subset only (reserved substrate anchors refused at create).
pub fn condition_type_caller_mintable_optional(_gen: &mut SchemaGenerator) -> Schema {
    closed_string_enum(
        wire_names(&ConditionType::CALLER_MINTABLE, ConditionType::as_str),
        true,
    )
}

/// `memory_checkpoint_query.condition_type` — optional filter over every
/// parseable kind, including reserved (a caller may query substrate
/// anchors it cannot mint).
pub fn condition_type_optional(_gen: &mut SchemaGenerator) -> Schema {
    closed_string_enum(wire_names(&ConditionType::ALL, ConditionType::as_str), true)
}

/// `memory_checkpoint_resolve.state` — required `resolved` / `rejected`.
pub fn checkpoint_resolution_state(_gen: &mut SchemaGenerator) -> Schema {
    closed_string_enum(
        wire_names(&CheckpointState::RESOLUTION, CheckpointState::as_str),
        false,
    )
}

/// `memory_checkpoint_query.state` — optional lifecycle filter.
pub fn checkpoint_state_optional(_gen: &mut SchemaGenerator) -> Schema {
    closed_string_enum(
        wire_names(&CheckpointState::ALL, CheckpointState::as_str),
        true,
    )
}

/// `memory_routine_list.state` — optional `draft` / `frozen` filter.
pub fn routine_state_optional(_gen: &mut SchemaGenerator) -> Schema {
    closed_string_enum(wire_names(&RoutineState::ALL, RoutineState::as_str), true)
}
