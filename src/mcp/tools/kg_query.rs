// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_kg_query` handler.

use crate::mcp::registry::McpTool;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.4 (#985): per-tool McpTool impl for `memory_kg_query` (graph family) ---

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_kg_query`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct KgQueryRequest {
    /// Source memory ID.
    pub source_id: String,

    /// Hops, 1..=5.
    #[serde(default)]
    pub max_depth: Option<i64>,

    /// RFC3339; keep links valid at instant. Omit to skip temporal filter.
    #[serde(default)]
    pub valid_at: Option<String>,

    /// Observed-by allowlist. Empty array = zero rows.
    #[serde(default)]
    pub allowed_agents: Option<Vec<String>>,

    /// Cap across all depths [1,1000].
    #[serde(default)]
    pub limit: Option<i64>,

    /// When true, traverse historically-invalidated edges.
    #[serde(default)]
    pub include_invalidated: Option<bool>,

    #[schemars(description = "#889 traverse by source_uri.")]
    #[serde(default)]
    pub by_source_uri: Option<String>,

    /// Restrict to namespace.
    #[serde(default)]
    pub namespace: Option<String>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_kg_query`.
#[allow(dead_code)]
pub struct KgQueryTool;

impl McpTool for KgQueryTool {
    fn name() -> &'static str {
        "memory_kg_query"
    }
    fn description() -> &'static str {
        "Outbound KG traversal from a source memory (<=5 hops)."
    }
    fn docs() -> &'static str {
        "Pillar 2 / Stream C: BFS/CTE traversal with cycle detection. Each row carries valid_from/valid_until/observed_by + target title/namespace. Filters chain across every hop. max_depth ceiling 5."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(KgQueryRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "graph"
    }
}

pub(super) fn handle_kg_query(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    // v0.7.0 Provenance Gap 6 (#889) — reciprocal "subgraph rooted at
    // every memory sharing source_uri" entrypoint. When
    // `by_source_uri` is supplied, every memory carrying that URI is
    // returned alongside its outbound links so callers see the full
    // forest rooted at the document. The traversal is unbounded (one
    // hop, since the goal is "what else is from this document") and
    // bypasses the `source_id`-required argument check.
    let by_source_uri = params["by_source_uri"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(uri) = by_source_uri {
        validate::validate_source_uri(uri).map_err(|e| e.to_string())?;
        let namespace = params["namespace"].as_str();
        let limit = params["limit"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok());
        // #975 — accept an `as_agent` MCP param so callers that
        // identify themselves get the post-#942 scope=private
        // visibility gate on the reciprocal source-uri endpoint.
        // Absent param leaves `as_agent = None` which preserves the
        // pre-#975 unfiltered behaviour for substrate-internal callers.
        let as_agent = params["as_agent"].as_str();
        if let Some(a) = as_agent {
            validate::validate_namespace(a).map_err(|e| e.to_string())?;
        }
        let roots = db::list_by_source_uri(conn, uri, namespace, limit, as_agent)
            .map_err(|e| e.to_string())?;
        let memories_json: Vec<Value> = roots
            .iter()
            .map(|m| {
                json!({
                    "target_id": m.id,
                    "title": m.title,
                    "target_namespace": m.namespace,
                    "depth": 0,
                    "source_uri": m.source_uri,
                })
            })
            .collect();
        return Ok(json!({
            "by_source_uri": uri,
            "memories": memories_json,
            "count": roots.len(),
        }));
    }

    let source_id = params["source_id"]
        .as_str()
        .ok_or("source_id is required")?;
    validate::validate_id(source_id).map_err(|e| e.to_string())?;

    let max_depth = params["max_depth"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(1);

    let valid_at = params["valid_at"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(t) = valid_at {
        validate::validate_expires_at_format(t).map_err(|e| e.to_string())?;
    }

    let allowed_agents: Option<Vec<String>> = params["allowed_agents"].as_array().map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(str::trim).filter(|s| !s.is_empty()))
            .map(str::to_string)
            .collect()
    });
    if let Some(agents) = allowed_agents.as_ref() {
        for a in agents {
            validate::validate_agent_id(a).map_err(|e| e.to_string())?;
        }
    }

    let limit = params["limit"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok());

    // NHI-P3-T7 (v0.7.0 NHI testing): default to "current view" —
    // exclude edges whose `valid_until` lies in the past. Pass
    // `include_invalidated=true` to traverse the full historical graph.
    let include_invalidated = params["include_invalidated"].as_bool().unwrap_or(false);

    let nodes = db::kg_query(
        conn,
        source_id,
        max_depth,
        valid_at,
        allowed_agents.as_deref(),
        limit,
        include_invalidated,
    )
    .map_err(|e| e.to_string())?;

    let memories_json: Vec<Value> = nodes
        .iter()
        .map(|n| {
            json!({
                "target_id": n.target_id,
                "relation": n.relation,
                "valid_from": n.valid_from,
                "valid_until": n.valid_until,
                "observed_by": n.observed_by,
                "title": n.title,
                "target_namespace": n.target_namespace,
                "depth": n.depth,
                "path": n.path,
            })
        })
        .collect();
    let paths_json: Vec<&str> = nodes.iter().map(|n| n.path.as_str()).collect();

    Ok(json!({
        "source_id": source_id,
        "max_depth": max_depth,
        "memories": memories_json,
        "paths": paths_json,
        "count": nodes.len(),
    }))
}

#[cfg(test)]
mod d1_4_985_tests {
    //! D1.4 (#985) — schema-parity for `memory_kg_query`.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_kg_query_parity_985() {
        let derived = derived_props_for::<KgQueryRequest>();
        assert_property_set_parity("memory_kg_query", &derived);
        assert_descriptions_match("memory_kg_query", &derived);
    }

    #[test]
    fn memory_kg_query_tool_metadata_985() {
        assert_eq!(KgQueryTool::name(), "memory_kg_query");
        assert_eq!(KgQueryTool::family(), "graph");
    }
}
