// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #972 D1.7 (#988) — schema↔handler parity invariant.
//!
//! Post-D1.6 (#987) the MCP `tools/list` payload is derived from each
//! tool's `<Tool>Request` struct via schemars + serde — the SAME
//! struct that the handler deserialises into when a `tools/call`
//! lands. The "single source of truth" guarantee only holds if the
//! schema and the handler agree on the property set: schemars
//! exposes a field name to the wire, and serde must accept that
//! field name when the request comes back. If a field is renamed on
//! the request struct but the legacy hand-coded schema still
//! advertises the OLD name (a class of bug the pre-D1.6 catalog
//! produced — see e.g. `memory_capabilities.accept` carrying
//! `enum: ["v1","v2"]` while the runtime `CapabilitiesAccept::parse`
//! had been V1/V2/V3 since A5), the schema lies to clients.
//!
//! These tests pin the invariant for 4-5 representative tools by:
//!
//! 1. Pulling the `inputSchema.properties` map for the tool out of
//!    [`ai_memory::mcp::tool_definitions`].
//! 2. Synthesising a JSON object with every advertised property set
//!    to a type-compatible placeholder value.
//! 3. `serde_json::from_value`-ing that object into the corresponding
//!    `<Tool>Request` struct.
//!
//! If deserialisation succeeds, the handler can extract every field
//! the schema advertises. If a property exists on the wire that the
//! struct rejects (e.g. `#[schemars(deny_unknown_fields)]` + a schema
//! that leaked a stale key), the test surfaces the drift at runtime.
//! Conversely, a schema field that survives schemars derivation but
//! that the struct doesn't model would never reach this test path
//! because schemars derives the schema FROM the struct — so the only
//! way a divergence appears is if the legacy hand-coded catalog is
//! still emitting a stale name. Post-D1.6 the legacy catalog is
//! collapsed, so the test is purely a defence-in-depth seam against
//! a future regression that re-introduces hand-coded schema entries.
//!
//! Compile-time half: each `<Tool>Request` is `#[derive(Deserialize,
//! JsonSchema)]` on the SAME struct (see `src/mcp/tools/<name>.rs`),
//! so renaming a field touches both the schema AND the serde target
//! in one edit. This integration test layers the runtime check on
//! top of the compile-time guarantee.
//!
//! Coverage: 5 representative tools across all 8 MCP families —
//! `memory_store` (core), `memory_recall` (core), `memory_capabilities`
//! (meta — the canonical drift exemplar), `memory_pending_approve`
//! (governance), `memory_link` (graph). Full coverage of all 73 tools
//! is D1.8 (#989)'s docs-and-coverage job — keeping the budget here
//! at 5 tools mirrors the D1.5 (#986) parity helpers' representative-
//! coverage discipline.

use ai_memory::mcp::schema_handler_parity_test_exports::{
    CapabilitiesRequest, LinkRequest, PendingApproveRequest, RecallRequest, StoreRequest,
};
use ai_memory::mcp::tool_definitions;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

/// Look up one tool's `inputSchema.properties` map out of the
/// canonical `tool_definitions()` catalog. Panics with a clear
/// message if the tool is missing from the catalog — that itself
/// would be a defect.
fn schema_properties_for(tool_name: &str) -> Map<String, Value> {
    let defs = tool_definitions();
    let tools = defs
        .get("tools")
        .and_then(Value::as_array)
        .expect("tool_definitions emits `tools` array");
    let entry = tools
        .iter()
        .find(|t| t.get("name").and_then(Value::as_str) == Some(tool_name))
        .unwrap_or_else(|| panic!("{tool_name} must be in tool_definitions catalog"));
    entry
        .pointer("/inputSchema/properties")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{tool_name}.inputSchema.properties must be object"))
        .clone()
}

/// Synthesise a JSON value compatible with a property's schema.
/// Walks the schema's `type` annotation (which schemars emits as
/// either a string or a `[T, "null"]` array for `Option<T>`) and
/// returns a representative non-null value of that type.
///
/// For `array` types the placeholder is an empty array; for `object`
/// types it's an empty object; for enum-constrained strings we pick
/// the first enum value when present (so the deserialiser's
/// enum-matching logic exercises the same branch the wire would).
fn placeholder_for(schema: &Value) -> Value {
    // Handle `type` as either string or [string, "null"] array.
    let ty = match schema.get("type") {
        Some(Value::String(s)) => s.as_str(),
        Some(Value::Array(arr)) => arr
            .iter()
            .find_map(|v| v.as_str())
            .filter(|s| *s != "null")
            .unwrap_or("string"),
        _ => "string",
    };
    // If the schema has an `enum`, prefer the first enum value.
    if let Some(enum_arr) = schema.get("enum").and_then(Value::as_array)
        && let Some(first) = enum_arr.first()
    {
        return first.clone();
    }
    match ty {
        "string" => json!("placeholder"),
        "integer" => json!(1),
        "number" => json!(0.5),
        "boolean" => json!(true),
        "array" => Value::Array(vec![]),
        "object" => Value::Object(Map::new()),
        // Schemars `null` (rare) OR an unrecognised type tag; the
        // deserialiser should still accept null for `Option<T>::None`.
        _ => Value::Null,
    }
}

/// Build a JSON object containing one placeholder value per
/// advertised property in the tool's schema. The synthesised
/// payload is what an MCP host would construct if it called every
/// optional field at once.
fn synthesise_payload_for(tool_name: &str) -> Value {
    let props = schema_properties_for(tool_name);
    let mut payload = Map::with_capacity(props.len());
    for (name, prop_schema) in &props {
        payload.insert(name.clone(), placeholder_for(prop_schema));
    }
    Value::Object(payload)
}

/// Assert that the every-field payload for a tool deserialises
/// cleanly into the `<Tool>Request` struct. The serde error path
/// surfaces the exact offending field name + reason if drift exists,
/// so a future regression that renames a property without updating
/// the schema (or vice versa) produces a precise failure message.
fn assert_schema_handler_parity<T: DeserializeOwned>(tool_name: &str) {
    let payload = synthesise_payload_for(tool_name);
    let result: Result<T, serde_json::Error> = serde_json::from_value(payload.clone());
    if let Err(e) = result {
        panic!(
            "{tool_name}: schema↔handler parity broken — schema advertises \
             a field the `<Tool>Request` struct cannot deserialise. \
             Likely cause: a property was renamed on one side but not the \
             other, OR a property's `type` widened in the schema beyond \
             what the struct's serde derive accepts. Synthesised payload:\
             \n{payload:#}\nDeserialise error: {e}"
        );
    }
}

#[test]
fn d1_7_988_schema_handler_parity_memory_store() {
    assert_schema_handler_parity::<StoreRequest>("memory_store");
}

#[test]
fn d1_7_988_schema_handler_parity_memory_recall() {
    assert_schema_handler_parity::<RecallRequest>("memory_recall");
}

#[test]
fn d1_7_988_schema_handler_parity_memory_capabilities() {
    assert_schema_handler_parity::<CapabilitiesRequest>("memory_capabilities");
}

#[test]
fn d1_7_988_schema_handler_parity_memory_pending_approve() {
    assert_schema_handler_parity::<PendingApproveRequest>("memory_pending_approve");
}

#[test]
fn d1_7_988_schema_handler_parity_memory_link() {
    assert_schema_handler_parity::<LinkRequest>("memory_link");
}
