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

    // #3498: an ID anchor does not opt into substrate reads, even in the
    // single-tenant posture. Use the unfiltered row so hidden lifecycle states
    // cannot skip the source check (#3270); lookup failures fail closed.
    {
        match db::get_any(conn, source_id) {
            Ok(Some(mem)) if !crate::visibility::is_readable_on_query(&mem, caller, None) => {
                return Err(crate::errors::msg::CALLER_NOT_SOURCE_MEMORY_OWNER.to_string());
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!("handle_kg_timeline: source ownership lookup failed: {e}");
                return Err(crate::errors::msg::INTERNAL_SERVER_ERROR.to_string());
            }
        }
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

    // #3498/#3270: apply the same rule to every returned target, including
    // hidden lifecycle states. A lookup error drops the event; a genuinely
    // absent target retains the historical dangling-edge behavior.
    {
        events.retain(|e| match db::get_any(conn, &e.target_id) {
            Ok(Some(m)) => crate::visibility::is_readable_on_query(&m, caller, None),
            Ok(None) => true,
            Err(_) => false,
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

    /// v1.0.0 #3270 — the source-owner gate is TOTAL over a HIDDEN source. A
    /// non-owner must be refused before the outbound link-event timeline even
    /// when the source row is tombstoned (which #3235 made `db::get` hide,
    /// silently skipping the pre-fix gate).
    #[test]
    fn memory_kg_timeline_hidden_source_refuses_non_owner() {
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        let source_id = "66666666-6666-4666-8666-666666666666";
        let mut src = crate::models::Memory {
            id: source_id.to_string(),
            title: "private source".to_string(),
            content: "secret".to_string(),
            ..Default::default()
        };
        src.metadata = json!({ "agent_id": "alice" });
        db::insert(&conn, &src).unwrap();
        conn.execute(
            "UPDATE memories SET lifecycle_state = 'tombstoned' WHERE id = ?1",
            rusqlite::params![source_id],
        )
        .unwrap();

        let err =
            handle_kg_timeline(&conn, &json!({ "source_id": source_id }), Some("bob")).unwrap_err();
        assert_eq!(err, crate::errors::msg::CALLER_NOT_SOURCE_MEMORY_OWNER);

        // Owner still proceeds (empty timeline, not an authz refusal).
        let out =
            handle_kg_timeline(&conn, &json!({ "source_id": source_id }), Some("alice")).unwrap();
        assert_eq!(out["count"], 0);
    }
}
