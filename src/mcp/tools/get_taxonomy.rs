// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_get_taxonomy` handler.

use crate::mcp::registry::McpTool;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.4 (#985): per-tool McpTool impl for `memory_get_taxonomy` (graph family) ---

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_get_taxonomy`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct GetTaxonomyRequest {
    /// Restrict to this namespace + descendants. Trailing '/' tolerated.
    #[serde(default)]
    pub namespace_prefix: Option<String>,

    /// Max descent. Deeper rows roll up into boundary subtree_count.
    #[serde(default)]
    pub depth: Option<i64>,

    /// Row cap. Densest namespaces win on truncation.
    #[serde(default)]
    pub limit: Option<i64>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_get_taxonomy`.
#[allow(dead_code)]
pub struct GetTaxonomyTool;

impl McpTool for GetTaxonomyTool {
    fn name() -> &'static str {
        "memory_get_taxonomy"
    }
    fn description() -> &'static str {
        "Return a hierarchical tree of namespaces with memory counts."
    }
    fn docs() -> &'static str {
        "Pillar 1 / Stream A: namespace tree (live rows only). Each node has count + subtree_count. Response includes total_count and truncated flag."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(GetTaxonomyRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "graph"
    }
}

pub(super) fn handle_get_taxonomy(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    // Defaults match the JSON schema. Trailing '/' is forgiven so MCP
    // clients can pass either `"alpha"` or `"alpha/"` without an extra
    // round trip — the underlying validate_namespace rejects the
    // trailing slash form, so we strip it before validating.
    let prefix_raw = params
        .get("namespace_prefix")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let prefix_owned: Option<String> = prefix_raw.map(|s| s.trim_end_matches('/').to_string());
    if let Some(p) = prefix_owned.as_deref() {
        validate::validate_namespace(p).map_err(|e| e.to_string())?;
    }
    let depth = usize::try_from(params.get("depth").and_then(Value::as_u64).unwrap_or(8))
        .unwrap_or(usize::MAX)
        .min(crate::models::MAX_NAMESPACE_DEPTH);
    let limit = usize::try_from(params.get("limit").and_then(Value::as_u64).unwrap_or(1000))
        .unwrap_or(usize::MAX)
        .clamp(1, 10_000);

    let tax =
        db::get_taxonomy(conn, prefix_owned.as_deref(), depth, limit).map_err(|e| e.to_string())?;
    Ok(json!({
        "tree": tax.tree,
        "total_count": tax.total_count,
        "truncated": tax.truncated,
    }))
}

#[cfg(test)]
mod d1_4_985_tests {
    //! D1.4 (#985) — schema-parity for `memory_get_taxonomy`.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_get_taxonomy_parity_985() {
        let derived = derived_props_for::<GetTaxonomyRequest>();
        assert_property_set_parity("memory_get_taxonomy", &derived);
        assert_descriptions_match("memory_get_taxonomy", &derived);
    }

    #[test]
    fn memory_get_taxonomy_tool_metadata_985() {
        assert_eq!(GetTaxonomyTool::name(), "memory_get_taxonomy");
        assert_eq!(GetTaxonomyTool::family(), "graph");
    }
}
