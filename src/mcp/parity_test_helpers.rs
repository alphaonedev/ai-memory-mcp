// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #972 D1.5 (#986) — shared parity-test helpers for the
//! schemars-derived `McpTool` impls vs. the legacy hand-coded
//! `tool_definitions()` catalog.
//!
//! Each `d1_5_986_tests` mod under `src/mcp/tools/<tool>.rs` calls
//! [`legacy_props`], [`derived_props_for`], [`assert_property_set_parity`],
//! and [`assert_descriptions_match`] so the 4-helper boilerplate isn't
//! duplicated 30+ times across the family migration. The helpers
//! preserve the byte-for-byte invariant that D1.3 (#984) and D1.4
//! (#985) pin via the same shape (load_family.rs::d1_3_984_tests).
//!
//! Cfg-test only — these helpers are not compiled into the production
//! binary.

use serde_json::Value;

/// Resolve the legacy hand-coded `inputSchema.properties` map for one
/// tool out of [`crate::mcp::registry::tool_definitions`]. The legacy
/// catalog is the source-of-truth the D1.x split is migrating away
/// from (deleted in D1.6 (#987)); during the D1.1-D1.5 window both
/// surfaces coexist and the per-tool parity tests pin the new
/// schemars-derived schema against this map byte-for-byte.
pub(crate) fn legacy_props(tool_name: &str) -> serde_json::Map<String, Value> {
    let defs = crate::mcp::registry::tool_definitions();
    let tools = defs
        .get("tools")
        .and_then(Value::as_array)
        .expect("tool_definitions emits `tools` array");
    let entry = tools
        .iter()
        .find(|t| t.get("name").and_then(Value::as_str) == Some(tool_name))
        .unwrap_or_else(|| panic!("{tool_name} must be in legacy catalog"));
    entry
        .pointer("/inputSchema/properties")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{tool_name}.inputSchema.properties must be object"))
        .clone()
}

/// Resolve the schemars-derived `properties` map for a `JsonSchema`
/// request type regardless of whether schemars emits the properties
/// directly under the root or under a `$ref`-resolved
/// `definitions/<Type>/properties` path. schemars 0.8 emits the
/// direct form; future versions may relocate. The fallback path lets
/// the parity helpers survive the relocation.
pub(crate) fn derived_props_for<T: schemars::JsonSchema>() -> serde_json::Map<String, Value> {
    let schema = schemars::schema_for!(T);
    let v = serde_json::to_value(schema).expect("schema -> value");
    // Empty / unit-like request structs (tools whose legacy schema is
    // `"properties": {}`) produce no `properties` key at all — schemars
    // omits the map when there are no fields. Treat that as an empty
    // properties map so the parity helpers can compare against the
    // legacy empty object.
    if let Some(props) = v.get("properties").and_then(Value::as_object) {
        return props.clone();
    }
    if let Some(props) = v
        .pointer(&format!(
            "/definitions/{}/properties",
            std::any::type_name::<T>().rsplit("::").next().unwrap_or("")
        ))
        .and_then(Value::as_object)
    {
        return props.clone();
    }
    serde_json::Map::new()
}

/// Pin property-set parity between the legacy hand-coded
/// `inputSchema.properties` map and the schemars-derived one. Every
/// legacy property must be present in the derived schema and vice
/// versa; a symmetric diff between the two key sets surfaces missing
/// or extra fields verbatim.
pub(crate) fn assert_property_set_parity(
    tool_name: &str,
    derived: &serde_json::Map<String, Value>,
) {
    let legacy = legacy_props(tool_name);
    let legacy_keys: std::collections::BTreeSet<&str> = legacy.keys().map(String::as_str).collect();
    let derived_keys: std::collections::BTreeSet<&str> =
        derived.keys().map(String::as_str).collect();
    assert_eq!(
        legacy_keys,
        derived_keys,
        "{tool_name}: property set drift; diff = {:?}",
        legacy_keys
            .symmetric_difference(&derived_keys)
            .collect::<Vec<_>>()
    );
}

/// Pin per-property `description` strings byte-for-byte against the
/// legacy hand-coded catalog. Legacy may omit `description` on rare
/// properties (e.g. open-ended `metadata`); the helper only asserts
/// equality when the legacy entry carries a non-null string. The
/// schemars-derived description comes from the per-field
/// `///`-doc-comment on the `<Tool>Request` struct.
pub(crate) fn assert_descriptions_match(tool_name: &str, derived: &serde_json::Map<String, Value>) {
    let legacy = legacy_props(tool_name);
    for (name, legacy_prop) in &legacy {
        if let Some(want) = legacy_prop.get("description").and_then(Value::as_str) {
            let got = derived
                .get(name)
                .and_then(|p| p.get("description"))
                .and_then(Value::as_str);
            assert_eq!(
                got,
                Some(want),
                "{tool_name}.{name}: description must match legacy byte-for-byte"
            );
        }
    }
}
