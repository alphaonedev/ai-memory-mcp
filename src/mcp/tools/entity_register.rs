// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_entity_register` handler.

use crate::mcp::registry::McpTool;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.4 (#985): per-tool McpTool impl for `memory_entity_register` (graph family) ---

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_entity_register`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct EntityRegisterRequest {
    /// Display name (entity memory title).
    pub canonical_name: String,

    /// Entity namespace.
    pub namespace: String,

    /// Aliases; blanks skipped, deduped.
    #[serde(default)]
    pub aliases: Option<Vec<String>>,

    /// Metadata; 'kind' is forced to 'entity'.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,

    /// Override metadata.agent_id.
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_entity_register`.
#[allow(dead_code)]
pub struct EntityRegisterTool;

impl McpTool for EntityRegisterTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ENTITY_REGISTER
    }
    fn description() -> &'static str {
        "Register an entity (canonical name + aliases) under a namespace."
    }
    fn docs() -> &'static str {
        "Pillar 2 / Stream B: register entity as long-tier memory (metadata.kind='entity'). Idempotent on (canonical_name, namespace); merges new aliases. Errors if name collides with a non-entity row."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(EntityRegisterRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "graph"
    }
}

pub(super) fn handle_entity_register(
    conn: &rusqlite::Connection,
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let canonical_name = params["canonical_name"]
        .as_str()
        .ok_or("canonical_name is required")?;
    let namespace = params["namespace"]
        .as_str()
        .ok_or("namespace is required")?;
    let aliases: Vec<String> = params["aliases"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let extra_metadata = if params["metadata"].is_object() {
        params["metadata"].clone()
    } else {
        json!({})
    };
    let explicit_agent_id = params["agent_id"].as_str();

    validate::validate_title(canonical_name).map_err(|e| e.to_string())?;
    validate::validate_namespace(namespace).map_err(|e| e.to_string())?;
    if let Some(aid) = explicit_agent_id {
        validate::validate_agent_id(aid).map_err(|e| e.to_string())?;
    }

    let agent_id = crate::identity::resolve_agent_id(explicit_agent_id, mcp_client)
        .map_err(|e| e.to_string())?;

    let reg = db::entity_register(
        conn,
        canonical_name,
        namespace,
        &aliases,
        &extra_metadata,
        Some(&agent_id),
    )
    .map_err(|e| e.to_string())?;

    Ok(json!({
        "entity_id": reg.entity_id,
        "canonical_name": reg.canonical_name,
        "namespace": reg.namespace,
        "aliases": reg.aliases,
        "created": reg.created,
    }))
}

// ---- C-5 (#699): close the lib-tier gap in entity_register.rs
// (currently 94.34%). Higher-level dispatcher tests cover the
// canonical_name/namespace required arms; these focus on the
// validator `.map_err(...)` branches and the metadata-object/
// agent_id presence paths. ----
#[cfg(test)]
mod tests {
    use super::*;

    fn open_conn() -> rusqlite::Connection {
        crate::db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    #[test]
    fn handle_entity_register_invalid_title_maps_validator_error() {
        // Line 34: `validate_title(canonical_name).map_err(...)`. An
        // empty title is rejected by the validator.
        let conn = open_conn();
        let err = handle_entity_register(
            &conn,
            &json!({
                "canonical_name": "",
                "namespace": "test-ns",
            }),
            None,
        )
        .unwrap_err();
        assert!(!err.is_empty(), "expected non-empty validator error");
    }

    #[test]
    fn handle_entity_register_invalid_agent_id_maps_validator_error() {
        // Line 37: `validate_agent_id(aid).map_err(...)`. The explicit
        // `agent_id` is provided but contains a forbidden character.
        let conn = open_conn();
        let err = handle_entity_register(
            &conn,
            &json!({
                "canonical_name": "Alice",
                "namespace": "test-ns",
                "agent_id": "bad agent id with spaces",
            }),
            None,
        )
        .unwrap_err();
        assert!(err.contains("agent_id"), "got: {err}");
    }

    #[test]
    fn handle_entity_register_happy_path_with_metadata_and_aliases() {
        // Drives lines 27-31 (metadata.is_object() arm), the aliases
        // filter_map collection, and the final success-return JSON.
        let conn = open_conn();
        let result = handle_entity_register(
            &conn,
            &json!({
                "canonical_name": "Bob the Builder",
                "namespace": "characters",
                "aliases": ["bob", "builder", 42 /* non-string is filtered */],
                "metadata": {"role": "construction"},
                "agent_id": "alice",
            }),
            None,
        )
        .expect("entity_register should succeed");
        assert_eq!(result["canonical_name"], "Bob the Builder");
        assert_eq!(result["namespace"], "characters");
        assert_eq!(result["created"], true);
        let aliases = result["aliases"].as_array().expect("aliases array");
        // The non-string `42` was filtered by the filter_map.
        assert!(aliases.iter().all(|v| v.is_string()));
    }
}

#[cfg(test)]
mod d1_4_985_tests {
    //! D1.4 (#985) — schema-parity for `memory_entity_register`.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_entity_register_parity_985() {
        let derived = derived_props_for::<EntityRegisterRequest>();
        assert_property_set_parity("memory_entity_register", &derived);
        assert_descriptions_match("memory_entity_register", &derived);
    }

    #[test]
    fn memory_entity_register_tool_metadata_985() {
        assert_eq!(EntityRegisterTool::name(), "memory_entity_register");
        assert_eq!(EntityRegisterTool::family(), "graph");
    }
}
