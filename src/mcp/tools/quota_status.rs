// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_quota_status` handler.

use serde_json::{Value, json};
/// v0.7 K8 — MCP handler for `memory_quota_status`. Reports per-agent
/// quota usage (memories/day, storage bytes, links/day) for the
/// operator-facing surface. When `agent_id` is provided, returns a
/// single row (auto-inserting a default row if the agent has none).
/// When omitted, returns every quota row in the substrate, sorted by
/// agent_id ASC. Family: `Power` (operator-scoped, not data-plane).

pub fn handle_quota_status(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    if let Some(agent_id) = params.get("agent_id").and_then(Value::as_str) {
        let row = crate::quotas::get_status(conn, agent_id).map_err(|e| e.to_string())?;
        Ok(json!({
            "agent_id": agent_id,
            "quota": row,
        }))
    } else {
        let rows = crate::quotas::list_status(conn).map_err(|e| e.to_string())?;
        Ok(json!({
            "count": rows.len(),
            "quotas": rows,
        }))
    }
}

// --- D1.5 (#986): per-tool McpTool impl for memory_quota_status ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_quota_status`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
#[schemars(deny_unknown_fields)]
pub struct QuotaStatusRequest {
    /// Restrict to one agent.
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_quota_status`.
#[allow(dead_code)]
pub struct QuotaStatusTool;

impl McpTool for QuotaStatusTool {
    fn name() -> &'static str {
        "memory_quota_status"
    }
    fn description() -> &'static str {
        "Report per-agent quota usage. Operator-facing."
    }
    fn docs() -> &'static str {
        "K8: quota usage (memories/day, storage, links/day). Omit agent_id for all."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(QuotaStatusRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "power"
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_quota_status`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn quota_status_parity_986() {
        let derived = derived_props_for::<QuotaStatusRequest>();
        assert_property_set_parity("memory_quota_status", &derived);
        assert_descriptions_match("memory_quota_status", &derived);
    }

    #[test]
    fn quota_status_tool_metadata_986() {
        assert_eq!(QuotaStatusTool::name(), "memory_quota_status");
        assert_eq!(QuotaStatusTool::family(), "power");
    }
}

#[cfg(test)]
mod tests {
    //! Coverage C-2 — focused tests for `handle_quota_status`.
    //!
    //! Two paths to cover:
    //! - per-agent: a missing row auto-inserts and surfaces the default quota
    //! - list: returns every row in the substrate

    use super::*;
    use crate::storage as db;

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    // Per-agent path: auto-inserts a default row if absent.
    #[test]
    fn per_agent_returns_quota_for_unknown_id() {
        let conn = fresh_conn();
        let resp = handle_quota_status(&conn, &json!({"agent_id": "ai:alice"})).expect("ok");
        assert_eq!(resp["agent_id"].as_str(), Some("ai:alice"));
        let quota = &resp["quota"];
        assert!(quota.is_object());
        assert_eq!(quota["agent_id"].as_str(), Some("ai:alice"));
        // Defaults should set non-zero ceilings.
        assert!(quota["max_memories_per_day"].as_i64().unwrap_or(0) > 0);
    }

    // List path: omitted agent_id returns the count + rows shape.
    #[test]
    fn list_path_returns_count_and_rows() {
        let conn = fresh_conn();
        // Pre-populate via the per-agent path so list has data to show.
        let _ = handle_quota_status(&conn, &json!({"agent_id": "ai:bob"})).expect("seed bob");
        let _ = handle_quota_status(&conn, &json!({"agent_id": "ai:carol"})).expect("seed carol");
        let resp = handle_quota_status(&conn, &json!({})).expect("ok");
        assert!(resp["count"].as_u64().unwrap() >= 2);
        let quotas = resp["quotas"].as_array().expect("quotas array");
        assert!(quotas.len() >= 2);
    }

    // List path on empty DB returns count=0 and empty array.
    #[test]
    fn list_path_empty_db_returns_zero() {
        let conn = fresh_conn();
        let resp = handle_quota_status(&conn, &json!({})).expect("ok");
        assert_eq!(resp["count"].as_u64(), Some(0));
        assert_eq!(resp["quotas"].as_array().unwrap().len(), 0);
    }

    // Per-agent path on the same id twice is idempotent.
    #[test]
    fn per_agent_idempotent_repeated_reads() {
        let conn = fresh_conn();
        let one = handle_quota_status(&conn, &json!({"agent_id": "ai:dup"})).expect("ok1");
        let two = handle_quota_status(&conn, &json!({"agent_id": "ai:dup"})).expect("ok2");
        assert_eq!(one["agent_id"], two["agent_id"]);
        assert_eq!(
            one["quota"]["max_memories_per_day"],
            two["quota"]["max_memories_per_day"]
        );
    }
}
