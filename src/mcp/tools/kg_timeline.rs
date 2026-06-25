// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_kg_timeline` handler.

use crate::mcp::registry::McpTool;
use crate::models::field_names;
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
        crate::mcp::registry::tool_names::MEMORY_KG_TIMELINE
    }
    fn description() -> &'static str {
        "Ordered fact timeline for an entity (outbound KG links by valid_from)."
    }
    fn docs() -> &'static str {
        "Pillar 2 / Stream C: outbound links from source_id ordered valid_from ASC. Includes valid_from/valid_until/observed_by + target title/namespace. NULL valid_from rows excluded. Cross-namespace."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<KgTimelineRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Graph.name()
    }
}

pub fn handle_kg_timeline(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
) -> Result<Value, String> {
    let source_id = params["source_id"]
        .as_str()
        .ok_or(crate::errors::msg::SOURCE_ID_REQUIRED)?;
    validate::validate_id(source_id).map_err(|e| e.to_string())?;

    // #1800 — mirror the #944 HTTP caller-vs-source-owner gate onto the
    // MCP surface. When a visibility caller is resolved (operator opted
    // in via AI_MEMORY_AGENT_ID), gate on the SOURCE memory's ownership:
    // if the source row exists and is not visible to the caller, refuse
    // rather than leak its outbound link-event timeline (target title /
    // namespace / relation / valid_from). A `None` caller (single-tenant
    // trust-all) or a missing source row proceeds unchanged. Gates on
    // source_id only, matching the HTTP twin.
    if let Some(caller) = caller
        && let Ok(Some(mem)) = db::get(conn, source_id)
        && !crate::visibility::is_visible_to_caller(&mem, caller)
    {
        return Err(crate::errors::msg::CALLER_NOT_SOURCE_MEMORY_OWNER.to_string());
    }
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

    let mut events =
        db::kg_timeline(conn, source_id, since, until, limit).map_err(|e| e.to_string())?;

    // #1804 (SECURITY) — per-TARGET visibility filter. The source-owner gate
    // above guards WHO can query a timeline, but the events disclose each
    // linked TARGET's title + namespace; without this a caller could leak a
    // victim's `scope=private` memory metadata by rooting a link at it and
    // reading the timeline. Drop any event whose target memory is not visible
    // to the caller (mirrors `get_links` / postgres `find_paths` per-row
    // filtering). `None` caller = single-tenant trust-all (unchanged); a
    // missing target row has no metadata to leak so it is retained.
    if let Some(caller) = caller {
        events.retain(|e| {
            db::get(conn, &e.target_id)
                .ok()
                .flatten()
                .is_none_or(|m| crate::visibility::is_visible_to_caller(&m, caller))
        });
    }

    let events_json: Vec<Value> = events
        .iter()
        .map(|e| {
            json!({
                "target_id": e.target_id,
                "relation": e.relation,
                (field_names::VALID_FROM): e.valid_from,
                (field_names::VALID_UNTIL): e.valid_until,
                (field_names::OBSERVED_BY): e.observed_by,
                "title": e.title,
                (field_names::TARGET_NAMESPACE): e.target_namespace,
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
