// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_search` handler.

use crate::mcp::registry::McpTool;
use crate::models::Tier;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.4 (#985): per-tool McpTool impl for `memory_search` (core family) ---

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_search`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
#[schemars(deny_unknown_fields)]
pub struct SearchRequest {
    pub query: String,

    #[serde(default)]
    pub namespace: Option<String>,

    #[serde(default)]
    pub tier: Option<String>,

    #[serde(default)]
    pub limit: Option<i64>,

    /// Exact metadata.agent_id filter.
    #[serde(default)]
    pub agent_id: Option<String>,

    #[schemars(description = "#151 scope-visibility agent.")]
    #[serde(default)]
    pub as_agent: Option<String>,

    /// WT-1-E: include atomised sources.
    #[serde(default)]
    pub include_archived: Option<bool>,

    /// Response format. toon_compact saves 79%.
    #[serde(default)]
    pub format: Option<String>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_search`.
#[allow(dead_code)]
pub struct SearchTool;

impl McpTool for SearchTool {
    fn name() -> &'static str {
        "memory_search"
    }
    fn description() -> &'static str {
        "Search memories by exact keyword match (AND semantics)."
    }
    fn docs() -> &'static str {
        "Exact keyword AND search. Deterministic; no fuzzy/semantic. Filters: namespace, tier, agent_id, as_agent (Task 1.5 scope). WT-1-E: atomised sources hidden by default."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(SearchRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "core"
    }
}

pub(super) fn handle_search(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let query = params["query"].as_str();
    let namespace = params["namespace"].as_str();
    let tier = params["tier"].as_str().and_then(Tier::from_str);
    // Ultrareview #339: saturate instead of panic on 32-bit targets
    // where u64 may exceed usize::MAX. A malicious client passing
    // limit=2^63 would otherwise take down the daemon.
    let limit = usize::try_from(params["limit"].as_u64().unwrap_or(20)).unwrap_or(usize::MAX);

    let agent_id = params["agent_id"].as_str();
    if let Some(aid) = agent_id {
        validate::validate_agent_id(aid).map_err(|e| e.to_string())?;
    }
    let as_agent = params["as_agent"].as_str();
    if let Some(a) = as_agent {
        validate::validate_namespace(a).map_err(|e| e.to_string())?;
    }
    // v0.7.0 WT-1-E — atom-preference search semantics. See
    // `mcp::tools::recall::handle_recall` for the full contract.
    let include_archived = params["include_archived"].as_bool().unwrap_or(false);
    // v0.7.0 Provenance Gap 6 (#889) — reciprocal source filter.
    // When `source_uri` is supplied + non-empty, results are
    // narrowed to memories whose `source_uri` column exactly matches.
    // The partial `idx_memories_source_uri` index (v38) covers the
    // lookup so the reciprocal "everything from this document"
    // query is O(log N), not O(N) JSON-path scan.
    let source_uri = params["source_uri"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(uri) = source_uri {
        validate::validate_source_uri(uri).map_err(|e| e.to_string())?;
    }

    // When `query` is empty but `source_uri` is supplied, route through
    // the index-only `list_by_source_uri` so callers can ask "give me
    // every memory from this document" without typing a query token.
    if query.unwrap_or("").trim().is_empty() {
        if let Some(uri) = source_uri {
            // #975 — propagate the caller's `as_agent` to the reciprocal
            // source-uri endpoint so the MCP source_uri-only path
            // respects the same scope=private gate as `search_with_source_uri`.
            let results =
                db::list_by_source_uri(conn, uri, namespace, Some(limit.min(200)), as_agent)
                    .map_err(|e| e.to_string())?;
            return Ok(json!({"results": results, "count": results.len()}));
        }
        return Err("query is required".into());
    }

    let results = db::search_with_source_uri(
        conn,
        query.unwrap_or(""),
        namespace,
        tier.as_ref(),
        limit.min(200),
        None,
        None,
        None,
        None,
        agent_id,
        as_agent,
        include_archived,
        source_uri,
    )
    .map_err(|e| e.to_string())?;
    Ok(json!({"results": results, "count": results.len()}))
}

#[cfg(test)]
mod d1_4_985_tests {
    //! D1.4 (#985) — schema-parity for `memory_search`.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_search_parity_985() {
        let derived = derived_props_for::<SearchRequest>();
        assert_property_set_parity("memory_search", &derived);
        assert_descriptions_match("memory_search", &derived);
    }

    #[test]
    fn memory_search_tool_metadata_985() {
        assert_eq!(SearchTool::name(), "memory_search");
        assert_eq!(SearchTool::family(), "core");
    }
}
