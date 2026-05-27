// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// QUAL-15 (med/low review batch) — file-level `#![cfg(test)]` so the
// `pub fn` items below carrying `panic!` bodies are self-evidently
// test-only when read in isolation. Previously the gate lived at the
// mount point in `src/mcp/mod.rs::mod d1_4_985_helpers;`, requiring a
// grep-up-the-tree to confirm the file was not shipped in production.
#![cfg(test)]

//! v0.7.0 #972 D1.4 (#985) — shared test helpers for the per-tool
//! schema-parity tests added under D1.4.
//!
//! Each per-tool module (`get.rs`, `list.rs`, `search.rs`,
//! `kg_query.rs`, …) carries its own `d1_4_985_tests` mod that calls
//! the four helpers below to assert byte-for-byte description parity
//! and property-set parity against the legacy hand-coded entry in
//! [`crate::mcp::registry::tool_definitions`].
//!
//! Reuses the allowed-diffs catalog documented in d1_2_983_tests:
//!
//! 1. `type`: legacy concrete; schemars `Option<T>` → nullable union.
//! 2. `default`: legacy typed; schemars `null` for every `Option<T>`.
//! 3. `enum`: schemars may drop / tighten; runtime parser tolerates.
//! 4. `additionalProperties: false` from
//!
//! Match-exactly contracts asserted by these helpers:
//!
//! - Property names (every legacy property present in derived & vice versa)
//! - Per-property `description` byte-equal where the legacy entry has one.

use serde_json::Value;

/// Pull the legacy hand-coded `inputSchema.properties` map for a
/// named tool out of [`crate::mcp::registry::tool_definitions`].
pub fn legacy_props(tool_name: &str) -> serde_json::Map<String, Value> {
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

/// Resolve the schemars-derived `properties` object regardless of
/// whether schemars emits it directly or under a `$ref`-resolved
/// `definitions/<TypeName>/properties` path.
pub fn derived_props_for<T: schemars::JsonSchema>() -> serde_json::Map<String, Value> {
    let schema = schemars::schema_for!(T);
    let v = serde_json::to_value(schema).expect("schema → value");
    if let Some(props) = v.get("properties").and_then(Value::as_object) {
        return props.clone();
    }
    let short = std::any::type_name::<T>().rsplit("::").next().unwrap_or("");
    v.pointer(&format!("/definitions/{short}/properties"))
        .and_then(Value::as_object)
        .cloned()
        .expect("schemars schema must have properties at a known path")
}

/// Assert the legacy and derived property sets cover the same keys.
pub fn assert_property_set_parity(tool_name: &str, derived: &serde_json::Map<String, Value>) {
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

/// Assert per-property `description` byte-equality for every legacy
/// property that has one.
pub fn assert_descriptions_match(tool_name: &str, derived: &serde_json::Map<String, Value>) {
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
