// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_lineage` handler (v0.9.0 G13-mem, #1859).
//!
//! The memory-derivation lineage-DAG query surface: walks the provenance
//! subset P = {`derived_from`, `reflects_on`, `derives_from`} of
//! `memory_links` from a root memory, returning its ANCESTORS (the older
//! memories it was derived from, transitively) or DESCENDANTS (the newer
//! memories derived from it). Tombstoned ancestors ARE included — a
//! consolidated-away source is still an ancestor; conserving it is the
//! whole point of the lineage-DAG.

use crate::mcp::registry::McpTool;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

/// v0.9.0 G13-mem (#1859) — the `direction` wire literal for an
/// ancestors walk (the default).
pub const LINEAGE_DIRECTION_ANCESTORS: &str = "ancestors";
/// v0.9.0 G13-mem (#1859) — the `direction` wire literal for a
/// descendants walk.
pub const LINEAGE_DIRECTION_DESCENDANTS: &str = "descendants";

/// v0.9.0 G13-mem (#1859) — request body for `memory_lineage`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct LineageRequest {
    /// Root memory id to walk from.
    pub id: String,

    /// "ancestors" (default) or "descendants".
    #[serde(default)]
    pub direction: Option<String>,

    /// Max hops, default 5, ceiling 5.
    #[serde(default)]
    pub max_depth: Option<i64>,
}

/// v0.9.0 G13-mem (#1859) — `McpTool` impl for `memory_lineage`.
#[allow(dead_code)]
pub struct LineageTool;

impl McpTool for LineageTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_LINEAGE
    }
    fn description() -> &'static str {
        "Walk a memory's derivation lineage (ancestors or descendants) over provenance links."
    }
    fn docs() -> &'static str {
        "G13: directional walk over the provenance relations derived_from/reflects_on/derives_from. \
         Returns {id, cid, relation, depth} per node; tombstoned ancestors included. max_depth<=5."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<LineageRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Graph.name()
    }
}

/// v0.9.0 G13-mem (#1859) — `memory_lineage` handler. Backend dispatch
/// lives in the SAL: the SQLite path goes through `db::lineage_ancestors`
/// / `db::lineage_descendants` (recursive CTE); a Postgres deployment
/// routes through `PostgresStore::lineage_traverse`, which dispatches on
/// the resolved [`crate::store::KgBackend`] (AGE Cypher when installed —
/// with the deferred-projection CTE reroute — recursive CTE otherwise).
/// The wire shape is identical across backends: `nodes` is a
/// shortest-hop-deduplicated list of `{id, cid, relation, depth}` ordered
/// by depth then id.
pub fn handle_lineage(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
) -> Result<Value, String> {
    let id = params["id"]
        .as_str()
        .ok_or(crate::errors::msg::ID_REQUIRED)?;
    validate::validate_id(id).map_err(|e| e.to_string())?;

    // #1800 discipline — when a visibility caller is resolved, gate on the
    // ROOT memory's ownership: if the root row exists and is not visible to
    // the caller, refuse rather than leak its provenance neighborhood. A
    // `None` caller (single-tenant trust-all) or a missing root proceeds
    // unchanged (mirrors `handle_find_paths`).
    if let Some(caller) = caller
        && let Ok(Some(mem)) = db::get(conn, id)
        && !crate::visibility::is_visible_to_caller(&mem, caller)
    {
        return Err(crate::errors::msg::CALLER_NOT_SOURCE_MEMORY_OWNER.to_string());
    }

    let direction = params[crate::mcp::param_names::DIRECTION]
        .as_str()
        .unwrap_or(LINEAGE_DIRECTION_ANCESTORS);
    let max_depth = params["max_depth"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(db::LINEAGE_MAX_DEPTH);

    let nodes = match direction {
        LINEAGE_DIRECTION_ANCESTORS => db::lineage_ancestors(conn, id, max_depth),
        LINEAGE_DIRECTION_DESCENDANTS => db::lineage_descendants(conn, id, max_depth),
        other => {
            return Err(format!(
                "invalid direction '{other}' (expected '{LINEAGE_DIRECTION_ANCESTORS}' or \
                 '{LINEAGE_DIRECTION_DESCENDANTS}')"
            ));
        }
    }
    // Depth-budget violations surface their message verbatim (the
    // kg_query/find_paths convention) so callers can tell "you asked for
    // too much" from a real fault.
    .map_err(|e| e.to_string())?;

    // v1.0.0 R20 (#1958) — surface the root's read-time min-propagated trust
    // tier: min(own attest_level, all recorded ancestors' attest_levels) over
    // P. It is a property of the root (its ancestry), independent of the walk
    // direction, so it is computed once here. ESTIMABLE — bounded by recorded
    // provenance completeness.
    let propagated_trust = db::propagated_trust_tier(conn, id, db::LINEAGE_MAX_DEPTH)
        .map(|t| t.as_str())
        .unwrap_or_else(|_| crate::trust::TrustTier::Unattested.as_str());

    Ok(json!({
        "id": id,
        "direction": direction,
        "nodes": nodes,
        "count": nodes.len(),
        "propagated_trust": propagated_trust,
    }))
}

#[cfg(test)]
mod g13_1859_tests {
    //! G13-mem (#1859) — schema-parity + handler behavior for
    //! `memory_lineage`.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_lineage_parity_1859() {
        let derived = derived_props_for::<LineageRequest>();
        assert_property_set_parity("memory_lineage", &derived);
        assert_descriptions_match("memory_lineage", &derived);
    }

    #[test]
    fn memory_lineage_tool_metadata_1859() {
        assert_eq!(LineageTool::name(), "memory_lineage");
        assert_eq!(LineageTool::family(), "graph");
    }

    #[test]
    fn memory_lineage_rejects_missing_id_and_bad_direction() {
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        let err = handle_lineage(&conn, &json!({}), None).unwrap_err();
        assert_eq!(err, crate::errors::msg::ID_REQUIRED);

        let err = handle_lineage(
            &conn,
            &json!({"id": "11111111-1111-4111-8111-111111111111", "direction": "sideways"}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("invalid direction"), "got: {err}");
    }

    #[test]
    fn memory_lineage_empty_walk_returns_zero_count() {
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        let mem = crate::models::Memory {
            id: "22222222-2222-4222-8222-222222222222".to_string(),
            title: "root".to_string(),
            content: "no provenance".to_string(),
            ..Default::default()
        };
        db::insert(&conn, &mem).unwrap();
        let out = handle_lineage(&conn, &json!({"id": mem.id}), None).unwrap();
        assert_eq!(out["count"], 0);
        assert_eq!(out["direction"], "ancestors");
        assert!(out["nodes"].as_array().unwrap().is_empty());
    }
}
