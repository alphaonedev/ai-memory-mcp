// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_kg_timeline` handler.

use crate::mcp::registry::McpTool;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.4 (#985): per-tool McpTool impl for `memory_kg_timeline` (graph family) ---

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_kg_timeline`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct KgTimelineRequest {
    /// Source memory ID (typically an entity_id).
    pub source_id: String,

    /// RFC3339 inclusive lower bound on valid_from.
    #[serde(default)]
    pub since: Option<String>,

    /// RFC3339 inclusive upper bound on valid_from.
    #[serde(default)]
    pub until: Option<String>,

    /// Cap [1,1000].
    #[serde(default)]
    pub limit: Option<i64>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_kg_timeline`.
#[allow(dead_code)]
pub struct KgTimelineTool;

impl McpTool for KgTimelineTool {
    fn name() -> &'static str {
        "memory_kg_timeline"
    }
    fn description() -> &'static str {
        "Ordered fact timeline for an entity (outbound KG links by valid_from)."
    }
    fn docs() -> &'static str {
        "Pillar 2 / Stream C: outbound links from source_id ordered valid_from ASC. Includes valid_from/valid_until/observed_by + target title/namespace. NULL valid_from rows excluded. Cross-namespace."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(KgTimelineRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "graph"
    }
}

pub(super) fn handle_kg_timeline(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let source_id = params["source_id"]
        .as_str()
        .ok_or("source_id is required")?;
    validate::validate_id(source_id).map_err(|e| e.to_string())?;
    let since = params["since"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let until = params["until"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(s) = since {
        validate::validate_expires_at_format(s).map_err(|e| e.to_string())?;
    }
    if let Some(u) = until {
        validate::validate_expires_at_format(u).map_err(|e| e.to_string())?;
    }
    let limit = params["limit"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok());

    let events =
        db::kg_timeline(conn, source_id, since, until, limit).map_err(|e| e.to_string())?;

    let events_json: Vec<Value> = events
        .iter()
        .map(|e| {
            json!({
                "target_id": e.target_id,
                "relation": e.relation,
                "valid_from": e.valid_from,
                "valid_until": e.valid_until,
                "observed_by": e.observed_by,
                "title": e.title,
                "target_namespace": e.target_namespace,
            })
        })
        .collect();

    Ok(json!({
        "source_id": source_id,
        "events": events_json,
        "count": events.len(),
    }))
}

#[cfg(test)]
mod d1_4_985_tests {
    //! D1.4 (#985) — schema-parity for `memory_kg_timeline`.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_kg_timeline_parity_985() {
        let derived = derived_props_for::<KgTimelineRequest>();
        assert_property_set_parity("memory_kg_timeline", &derived);
        assert_descriptions_match("memory_kg_timeline", &derived);
    }

    #[test]
    fn memory_kg_timeline_tool_metadata_985() {
        assert_eq!(KgTimelineTool::name(), "memory_kg_timeline");
        assert_eq!(KgTimelineTool::family(), "graph");
    }
}
