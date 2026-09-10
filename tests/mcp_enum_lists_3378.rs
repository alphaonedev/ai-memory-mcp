// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3378 unit 2 — closed MCP params advertise their legal values as
//! inline JSON-Schema `enum` lists on `tools/list`.
//!
//! Denied (the 2026-09-02 MCP-sweep findings, re-verified on
//! `origin/chain/next` after unit 1): `to` / `edge_type` /
//! `signal_type` / `condition_type` / `state` shipped as
//! `type=string` with no `enum`, so the closed vocabularies were
//! undiscoverable from the wire.
//!
//! Allowed: those fields (except `memory_swarm_rewind.to`, a SHA)
//! carry `enum` arrays matching the domain SSOT. Optional fields also
//! include JSON `null`. `memory_checkpoint_create.condition_type`
//! advertises the caller-mintable subset only.

use ai_memory::mcp::tool_definitions_for_profile;
use ai_memory::models::{
    ActionState, CheckpointState, ConditionType, EdgeType, RoutineState, SignalType,
};
use ai_memory::profile::Profile;
use serde_json::Value;

fn tool_prop(tool_name: &str, prop: &str) -> Value {
    let defs = tool_definitions_for_profile(&Profile::full());
    let tools = defs["tools"].as_array().expect("tools array");
    for tool in tools {
        if tool.get("name").and_then(Value::as_str) != Some(tool_name) {
            continue;
        }
        let path = format!("/inputSchema/properties/{prop}");
        if let Some(v) = tool.pointer(&path) {
            return v.clone();
        }
        panic!("missing {tool_name}.inputSchema.properties.{prop}");
    }
    panic!("missing tool {tool_name} on tools/list")
}

fn string_enum(prop: &Value) -> (Vec<String>, bool) {
    let Some(arr) = prop.get("enum").and_then(Value::as_array) else {
        panic!("expected enum array, got {prop}");
    };
    let mut names = Vec::new();
    let mut has_null = false;
    for v in arr {
        match v {
            Value::Null => has_null = true,
            Value::String(s) => names.push(s.clone()),
            other => panic!("unexpected enum entry {other}"),
        }
    }
    (names, has_null)
}

fn as_strs<T: Copy>(all: &[T], as_str: fn(&T) -> &'static str) -> Vec<String> {
    all.iter().map(|v| as_str(v).to_string()).collect()
}

#[test]
fn action_transition_to_advertises_action_state_3378() {
    let prop = tool_prop("memory_action_transition", "to");
    assert_eq!(prop.get("type").and_then(Value::as_str), Some("string"));
    let (names, has_null) = string_enum(&prop);
    assert!(!has_null, "required to must not enumerate null");
    assert_eq!(names, as_strs(&ActionState::ALL, ActionState::as_str));
}

#[test]
fn action_list_state_advertises_action_state_optional_3378() {
    let prop = tool_prop("memory_action_list", "state");
    let (names, has_null) = string_enum(&prop);
    assert!(has_null, "optional state must enumerate null");
    assert_eq!(names, as_strs(&ActionState::ALL, ActionState::as_str));
}

#[test]
fn action_add_edge_type_advertises_edge_type_3378() {
    let prop = tool_prop("memory_action_add_edge", "edge_type");
    assert_eq!(prop.get("type").and_then(Value::as_str), Some("string"));
    let (names, has_null) = string_enum(&prop);
    assert!(!has_null);
    assert_eq!(names, as_strs(&EdgeType::ALL, EdgeType::as_str));
}

#[test]
fn signal_send_type_advertises_signal_type_3378() {
    let prop = tool_prop("memory_signal_send", "signal_type");
    let (names, has_null) = string_enum(&prop);
    assert!(has_null);
    assert_eq!(names, as_strs(&SignalType::ALL, SignalType::as_str));
}

#[test]
fn checkpoint_create_condition_type_is_caller_mintable_3378() {
    let prop = tool_prop("memory_checkpoint_create", "condition_type");
    let (names, has_null) = string_enum(&prop);
    assert!(has_null);
    assert_eq!(
        names,
        as_strs(&ConditionType::CALLER_MINTABLE, ConditionType::as_str)
    );
    for reserved in [
        "audit_head_witness",
        "governance_verdict",
        "governance_enforcement",
        "peer_head_entanglement",
        "re_anchor",
    ] {
        assert!(
            !names.iter().any(|n| n == reserved),
            "create must not advertise reserved kind {reserved}"
        );
    }
}

#[test]
fn checkpoint_query_condition_type_advertises_all_kinds_3378() {
    let prop = tool_prop("memory_checkpoint_query", "condition_type");
    let (names, has_null) = string_enum(&prop);
    assert!(has_null);
    assert_eq!(names, as_strs(&ConditionType::ALL, ConditionType::as_str));
}

#[test]
fn checkpoint_resolve_state_is_resolved_or_rejected_3378() {
    let prop = tool_prop("memory_checkpoint_resolve", "state");
    assert_eq!(prop.get("type").and_then(Value::as_str), Some("string"));
    let (names, has_null) = string_enum(&prop);
    assert!(!has_null);
    assert_eq!(
        names,
        as_strs(&CheckpointState::RESOLUTION, CheckpointState::as_str)
    );
}

#[test]
fn checkpoint_query_state_advertises_checkpoint_state_3378() {
    let prop = tool_prop("memory_checkpoint_query", "state");
    let (names, has_null) = string_enum(&prop);
    assert!(has_null);
    assert_eq!(
        names,
        as_strs(&CheckpointState::ALL, CheckpointState::as_str)
    );
}

#[test]
fn routine_list_state_advertises_draft_frozen_3378() {
    let prop = tool_prop("memory_routine_list", "state");
    let (names, has_null) = string_enum(&prop);
    assert!(has_null);
    assert_eq!(names, as_strs(&RoutineState::ALL, RoutineState::as_str));
}

#[test]
fn swarm_rewind_to_stays_free_string_3378() {
    let prop = tool_prop("memory_swarm_rewind", "to");
    assert_eq!(prop.get("type").and_then(Value::as_str), Some("string"));
    assert!(
        prop.get("enum").is_none(),
        "swarm_rewind.to is a SHA, not a closed vocabulary: {prop}"
    );
}
