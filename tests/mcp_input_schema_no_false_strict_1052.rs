// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 issue #1052 (Agent-4 F2) — MCP wire-schema honesty pin.
//!
//! Pre-#1052 every MCP tool-request struct carried
//! `#[schemars(deny_unknown_fields)]` (emits `additionalProperties:
//! false` on the wire) but intentionally omitted
//! `#[serde(deny_unknown_fields)]` so the runtime silently tolerated
//! unknown fields. That advertised-strict / accepted-permissive
//! asymmetry was the security-as-trust bug: clients obeying the wire
//! schema rejected inputs the server happily accepted, AND clients
//! sending typos had them silently dropped (no -32602) with
//! surprising "no filter applied" behaviour downstream.
//!
//! The #1052 fix drops `#[schemars(deny_unknown_fields)]` everywhere
//! so the wire schema becomes truthful. This integration test pins
//! the contract: the canonical `tool_definitions()` payload must NOT
//! emit `additionalProperties: false` on any tool's inputSchema or
//! on any nested $defs object — re-introducing the attribute on any
//! struct is a visible, intentional change that fails this test.

use ai_memory::mcp::tool_definitions;
use serde_json::Value;

/// Walk a JSON value and yield true if any `additionalProperties:
/// false` (or `additional_properties: false`) appears anywhere in the
/// tree. The `tool_definitions()` payload nests inputSchema objects
/// deeply (top-level + nested definitions for `$ref`-resolved
/// untagged enums), so a recursive walk is the right shape.
fn contains_additional_properties_false(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if (k == "additionalProperties" || k == "additional_properties")
                    && v == &Value::Bool(false)
                {
                    return true;
                }
                if contains_additional_properties_false(v) {
                    return true;
                }
            }
            false
        }
        Value::Array(items) => items.iter().any(contains_additional_properties_false),
        _ => false,
    }
}

#[test]
fn tool_definitions_input_schemas_do_not_advertise_strict_additional_properties_1052() {
    let defs = tool_definitions();
    let tools = defs
        .get("tools")
        .and_then(Value::as_array)
        .expect("tool_definitions emits `tools` array");
    let mut offenders: Vec<String> = Vec::new();
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("<unnamed>");
        // The wire-truthful posture (post-#1052) is that NO tool's
        // inputSchema may carry `additionalProperties: false`. The
        // `inputSchema` payload is what clients consume; checking the
        // whole tool entry catches any future field that nests a
        // sub-schema (e.g. an output schema) carrying the attribute.
        if contains_additional_properties_false(tool) {
            offenders.push(name.to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "#1052: post-fix the wire schema must be truthful (no \
         `additionalProperties: false` on any tool inputSchema). \
         Offending tools: {offenders:?}. If you intentionally want \
         a strict tool, ALSO add `#[serde(deny_unknown_fields)]` to \
         the corresponding request struct and update the dispatch \
         error mapping to emit -32602 — then update this test."
    );
}

#[test]
fn at_least_one_tool_carries_a_non_strict_input_schema_1052() {
    // Defensive sanity check: this test would FALSE PASS if
    // tool_definitions() suddenly returned an empty array. Assert
    // that at least one tool's inputSchema EXISTS so the
    // contains_additional_properties_false walk above had something
    // meaningful to scan.
    let defs = tool_definitions();
    let tools = defs
        .get("tools")
        .and_then(Value::as_array)
        .expect("tool_definitions emits `tools` array");
    let with_schema = tools
        .iter()
        .filter(|t| {
            t.get("inputSchema")
                .and_then(Value::as_object)
                .is_some_and(|m| !m.is_empty())
        })
        .count();
    assert!(
        with_schema > 0,
        "tool_definitions must return at least one tool with a \
         populated inputSchema; got {with_schema}"
    );
}
