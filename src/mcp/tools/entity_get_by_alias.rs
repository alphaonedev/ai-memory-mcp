// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_entity_get_by_alias` handler.

use crate::mcp::registry::McpTool;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.4 (#985): per-tool McpTool impl for `memory_entity_get_by_alias` (graph family) ---

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_entity_get_by_alias`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct EntityGetByAliasRequest {
    /// Alias; whitespace trimmed.
    pub alias: String,

    /// Namespace filter.
    #[serde(default)]
    pub namespace: Option<String>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_entity_get_by_alias`.
#[allow(dead_code)]
pub struct EntityGetByAliasTool;

impl McpTool for EntityGetByAliasTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ENTITY_GET_BY_ALIAS
    }
    fn description() -> &'static str {
        "Resolve an alias to its registered entity."
    }
    fn docs() -> &'static str {
        "Pillar 2 / Stream B: resolve alias to entity. Without namespace, most-recently-created wins. Null when no match."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(EntityGetByAliasRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "graph"
    }
}

pub(super) fn handle_entity_get_by_alias(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let alias = params["alias"].as_str().ok_or("alias is required")?;
    let namespace = params["namespace"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(ns) = namespace {
        validate::validate_namespace(ns).map_err(|e| e.to_string())?;
    }

    match db::entity_get_by_alias(conn, alias, namespace).map_err(|e| e.to_string())? {
        Some(rec) => Ok(json!({
            "found": true,
            "entity_id": rec.entity_id,
            "canonical_name": rec.canonical_name,
            "namespace": rec.namespace,
            "aliases": rec.aliases,
        })),
        None => Ok(json!({
            "found": false,
            "entity_id": null,
            "canonical_name": null,
            "namespace": null,
            "aliases": [],
        })),
    }
}

#[cfg(test)]
mod d1_4_985_tests {
    //! D1.4 (#985) — schema-parity for `memory_entity_get_by_alias`.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_entity_get_by_alias_parity_985() {
        let derived = derived_props_for::<EntityGetByAliasRequest>();
        assert_property_set_parity("memory_entity_get_by_alias", &derived);
        assert_descriptions_match("memory_entity_get_by_alias", &derived);
    }

    #[test]
    fn memory_entity_get_by_alias_tool_metadata_985() {
        assert_eq!(EntityGetByAliasTool::name(), "memory_entity_get_by_alias");
        assert_eq!(EntityGetByAliasTool::family(), "graph");
    }
}
