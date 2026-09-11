// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_entity_get_by_alias` handler.

use crate::mcp::registry::McpTool;
use crate::models::field_names;
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
        crate::mcp::registry::input_schema_for::<EntityGetByAliasRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Graph.name()
    }
}

pub fn handle_entity_get_by_alias(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
) -> Result<Value, String> {
    let alias = params["alias"].as_str().ok_or("alias is required")?;
    let namespace = params["namespace"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(ns) = namespace {
        validate::validate_namespace(ns).map_err(|e| e.to_string())?;
    }

    // v1.0.0 #3598 — mirror the #3232 HTTP disposition (`handlers::kg`):
    // an alias resolves ONLY when the caller can read the BACKING entity
    // memory (`rec.entity_id` IS that row's id — `entity_aliases` joins on
    // it). A hidden backing row answers the SAME `found: false` envelope an
    // unknown alias does, so the registry is not an existence oracle. The
    // predicate names the row's OWN namespace (the #3549 read-funnel
    // contract); an unfetchable row is HIDDEN (fail closed).
    let backing_row_readable = |id: &str| -> bool {
        // Unfiltered read (`get_any`, #3270): the gate is lifecycle-neutral.
        match db::get_any(conn, id) {
            Ok(Some(mem)) => {
                crate::visibility::is_readable_on_query(&mem, caller, Some(mem.namespace.as_str()))
            }
            Ok(None) | Err(_) => false,
        }
    };
    match db::entity_get_by_alias(conn, alias, namespace).map_err(|e| e.to_string())? {
        Some(rec) if backing_row_readable(&rec.entity_id) => Ok(json!({
            "found": true,
            "entity_id": rec.entity_id,
            (field_names::CANONICAL_NAME): rec.canonical_name,
            "namespace": rec.namespace,
            "aliases": rec.aliases,
        })),
        Some(_) | None => Ok(json!({
            "found": false,
            "entity_id": null,
            (field_names::CANONICAL_NAME): null,
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

#[cfg(test)]
mod authority_gate_3598_tests {
    //! v1.0.0 #3598 — DENIED / ALLOWED matrix for the
    //! `memory_entity_get_by_alias` read gate: a foreign owner's private
    //! entity answers the same `found: false` envelope an unknown alias does.
    use super::*;
    use crate::storage as db;

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn register_private_entity(conn: &rusqlite::Connection, owner: &str) -> String {
        db::entity_register(
            conn,
            "Alice Smith",
            "team/alpha",
            &["ally".to_string()],
            &json!({"scope": "private"}),
            Some(owner),
        )
        .expect("entity_register")
        .entity_id
    }

    #[test]
    fn foreign_owner_private_entity_is_not_found_for_another_caller_3598() {
        let conn = fresh_conn();
        register_private_entity(&conn, "ai:alice");
        let out = handle_entity_get_by_alias(
            &conn,
            &json!({"alias": "ally", "namespace": "team/alpha"}),
            Some("ai:bob"),
        )
        .expect("ok");
        assert_eq!(out["found"], false, "{out}");
        assert!(out["entity_id"].is_null(), "entity id must not leak: {out}");
        assert!(out["namespace"].is_null(), "namespace must not leak: {out}");
    }

    #[test]
    fn owner_resolves_their_own_entity_3598() {
        let conn = fresh_conn();
        let id = register_private_entity(&conn, "ai:alice");
        let out = handle_entity_get_by_alias(
            &conn,
            &json!({"alias": "ally", "namespace": "team/alpha"}),
            Some("ai:alice"),
        )
        .expect("ok");
        assert_eq!(out["found"], true, "{out}");
        assert_eq!(out["entity_id"], id);
    }
}
