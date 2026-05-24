// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_find_paths` handler.

use crate::mcp::registry::McpTool;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.4 (#985): per-tool McpTool impl for `memory_find_paths` (graph family) ---

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_find_paths`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct FindPathsRequest {
    /// Path origin.
    pub source_id: String,

    /// Path destination.
    pub target_id: String,

    /// Max hops, default 4, ceiling 7.
    #[serde(default)]
    pub max_depth: Option<i64>,

    /// Max paths (shortest-first), default 10, ceiling 50.
    #[serde(default)]
    pub max_results: Option<i64>,

    /// When true, include historically-invalidated edges.
    #[serde(default)]
    pub include_invalidated: Option<bool>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_find_paths`.
#[allow(dead_code)]
pub struct FindPathsTool;

impl McpTool for FindPathsTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_FIND_PATHS
    }
    fn description() -> &'static str {
        "Enumerate up to N paths through the KG between two memories (BFS, max_depth<=7)."
    }
    fn docs() -> &'static str {
        "J7: undirected BFS over memory_links with cycle detection. Returns id chains source-first. max_depth<=7, max_results<=50."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(FindPathsRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "graph"
    }
}

/// v0.7 J7 — `memory_find_paths` handler. Enumerates up to `max_results`
/// paths through the KG between two memories using BFS with cycle
/// detection. Backend dispatch lives in the SAL — the SQLite path goes
/// through `db::find_paths` (recursive CTE); a Postgres deployment
/// would route through `PostgresStore::find_paths` which dispatches on
/// the resolved [`crate::store::KgBackend`] (Cypher when AGE is
/// installed, recursive CTE otherwise). The wire shape is identical
/// across backends: `paths` is a list of id chains where each chain
/// has `source_id` first and `target_id` last.

pub fn handle_find_paths(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let source_id = params["source_id"]
        .as_str()
        .ok_or("source_id is required")?;
    let target_id = params["target_id"]
        .as_str()
        .ok_or("target_id is required")?;
    validate::validate_id(source_id).map_err(|e| e.to_string())?;
    validate::validate_id(target_id).map_err(|e| e.to_string())?;

    let max_depth = params["max_depth"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok());
    let max_results = params["max_results"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok());
    // NHI-P3-T7 (v0.7.0 NHI testing): default to "current view" —
    // exclude edges whose `valid_until` lies in the past. Caller can
    // pass `include_invalidated=true` to traverse the full historical
    // link graph (still covered by `memory_kg_timeline`).
    let include_invalidated = params["include_invalidated"].as_bool().unwrap_or(false);

    let paths = db::find_paths(
        conn,
        source_id,
        target_id,
        max_depth,
        max_results,
        include_invalidated,
    )
    .map_err(|e| {
        // Match the kg_query convention: depth-budget violations
        // surface their error message verbatim so callers can
        // distinguish "you asked for too much" from a real fault.
        e.to_string()
    })?;

    Ok(json!({
        "source_id": source_id,
        "target_id": target_id,
        "paths": paths,
        "count": paths.len(),
    }))
}

#[cfg(test)]
mod d1_4_985_tests {
    //! D1.4 (#985) — schema-parity for `memory_find_paths`.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_find_paths_parity_985() {
        let derived = derived_props_for::<FindPathsRequest>();
        assert_property_set_parity("memory_find_paths", &derived);
        assert_descriptions_match("memory_find_paths", &derived);
    }

    #[test]
    fn memory_find_paths_tool_metadata_985() {
        assert_eq!(FindPathsTool::name(), "memory_find_paths");
        assert_eq!(FindPathsTool::family(), "graph");
    }
}
