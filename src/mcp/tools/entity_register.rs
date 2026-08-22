// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_entity_register` handler.

use crate::mcp::param_names;
use crate::mcp::registry::McpTool;
use crate::models::field_names;
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

    /// Metadata; 'kind' is forced to 'entity'. #3171 — applied ONLY when
    /// this call MINTS the entity; on the idempotent re-register path it is
    /// silently discarded (see the tool docs).
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,

    /// Owner stamp written to `metadata.agent_id`. #3171 — it now WINS over
    /// an inline `metadata.agent_id` (which never crosses `validate_agent_id`),
    /// and like `metadata` it applies only on first registration.
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
        "Pillar 2 / Stream B: register entity as long-tier memory (metadata.kind='entity'). \
         Idempotent on (canonical_name, namespace); merges new aliases. Errors if name \
         collides with a non-entity row. #3171: the idempotent path merges ALIASES ONLY — \
         on a re-register (`created:false`) `metadata` and `agent_id` are silently \
         DISCARDED, not merged, so this tool cannot be used to re-stamp an existing \
         entity's metadata or owner."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<EntityRegisterRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Graph.name()
    }
}

pub fn handle_entity_register(
    conn: &rusqlite::Connection,
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let canonical_name = params[param_names::CANONICAL_NAME]
        .as_str()
        .ok_or("canonical_name is required")?;
    let namespace = params["namespace"]
        .as_str()
        .ok_or(crate::errors::msg::NAMESPACE_REQUIRED)?;
    // #3171 — a PRESENT-but-wrong-typed `aliases` / `metadata` used to be
    // silently dropped and the call answered `created: true`, so a caller that
    // sent `aliases: "alpha"` (a bare string) registered an entity with NO
    // aliases and no way to tell. Refuse the contradictory value; ABSENT still
    // takes the documented default.
    let aliases: Vec<String> = match params.get(param_names::ALIASES) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|v| {
                v.as_str()
                    .map(String::from)
                    .ok_or_else(|| "aliases must be an array of strings".to_string())
            })
            .collect::<Result<Vec<String>, String>>()?,
        Some(_) => return Err("aliases must be an array of strings".to_string()),
    };
    let extra_metadata = match params.get(param_names::METADATA) {
        None | Some(Value::Null) => json!({}),
        Some(v @ Value::Object(_)) => v.clone(),
        Some(_) => return Err("metadata must be an object".to_string()),
    };
    let explicit_agent_id = params[param_names::AGENT_ID].as_str();

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
        (field_names::CANONICAL_NAME): reg.canonical_name,
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
        let conn = open_conn();
        let result = handle_entity_register(
            &conn,
            &json!({
                "canonical_name": "Bob the Builder",
                "namespace": "characters",
                "aliases": ["bob", "builder"],
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
        assert!(aliases.iter().all(|v| v.is_string()));
    }

    /// #3171 — a PRESENT-but-wrong-typed `aliases` used to be dropped so
    /// `aliases: "alpha"` registered an entity with NO aliases and answered
    /// `created: true`. Refuse the contradictory value.
    #[test]
    fn entity_register_refuses_non_array_aliases_3171() {
        let conn = open_conn();
        let err = handle_entity_register(
            &conn,
            &json!({
                "canonical_name": "Alice",
                "namespace": "people",
                "aliases": "alpha",
            }),
            None,
        )
        .unwrap_err();
        assert!(err.contains("aliases"), "got: {err}");
    }

    /// #3171 — a PRESENT-but-wrong-typed `metadata` used to be dropped.
    #[test]
    fn entity_register_refuses_non_object_metadata_3171() {
        let conn = open_conn();
        let err = handle_entity_register(
            &conn,
            &json!({
                "canonical_name": "Alice",
                "namespace": "people",
                "metadata": ["not", "an", "object"],
            }),
            None,
        )
        .unwrap_err();
        assert!(err.contains("metadata"), "got: {err}");
    }

    /// #3171 U2 — an inline `metadata.agent_id` used to WIN over the id the
    /// handler had just put through `validate_agent_id`, so a reserved
    /// sentinel (`daemon`) never crossed `RESERVED_AGENT_IDS` (#977). The
    /// resolved id now overwrites the inline value.
    #[test]
    fn entity_register_resolved_id_wins_over_inline_metadata_agent_id_3171() {
        let conn = open_conn();
        let result = handle_entity_register(
            &conn,
            &json!({
                "canonical_name": "Eve",
                "namespace": "people",
                "agent_id": "alice",
                "metadata": {"agent_id": "daemon", "team": "x"},
            }),
            None,
        )
        .expect("alice-stamped register must succeed");
        let id = result["entity_id"].as_str().expect("entity_id");
        let mem = db::get(&conn, id).expect("get").expect("row");
        assert_eq!(
            mem.metadata["agent_id"].as_str(),
            Some("alice"),
            "resolved id must win over inline metadata.agent_id; got {}",
            mem.metadata
        );
        assert_eq!(mem.metadata["team"].as_str(), Some("x"));
        assert_eq!(mem.metadata["kind"].as_str(), Some("entity"));
    }

    /// #3171 — an explicit reserved sentinel is refused at the wire
    /// validator, not laundered into the owner stamp.
    #[test]
    fn entity_register_refuses_reserved_explicit_agent_id_3171() {
        let conn = open_conn();
        let err = handle_entity_register(
            &conn,
            &json!({
                "canonical_name": "Eve",
                "namespace": "people",
                "agent_id": "daemon",
            }),
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("reserved") || err.contains("agent_id"),
            "got: {err}"
        );
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
