// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_quota_status` handler.

use serde_json::{Value, json};

/// v0.7 K8 — MCP handler for `memory_quota_status`. Reports per-agent
/// quota usage (memories/day, storage bytes, links/day) for the
/// operator-facing surface.
///
/// ## Argument shape
///
/// - `agent_id` (optional) — restrict to one agent. When omitted,
///   every quota row in the substrate is returned.
/// - `namespace` (optional, v0.7.0 #1156) — restrict to one namespace.
///   When supplied alongside `agent_id`, returns that single
///   `(agent_id, namespace)` row (auto-inserting a default row if the
///   tuple has none). When supplied without `agent_id`, returns every
///   row in that namespace. When omitted alongside `agent_id`, returns
///   the **aggregate** view: counters summed across every namespace
///   the agent has written into, with `namespace = "_global"`. When
///   omitted alongside `agent_id` omitted, returns every row in the
///   substrate sorted by `(agent_id ASC, namespace ASC)`.
///
/// Family: `Power` (operator-scoped, not data-plane).
///
/// NSA CSI MCP recommendation (c) — defense-in-depth blast-radius
/// controls. Per-namespace allotments bound a compromised agent's
/// reach without affecting their write capacity in unrelated
/// namespaces.
pub fn handle_quota_status(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let agent_id = params.get("agent_id").and_then(Value::as_str);
    let namespace = params.get("namespace").and_then(Value::as_str);

    match (agent_id, namespace) {
        // Single (agent, namespace) row.
        (Some(aid), Some(ns)) => {
            let row = crate::quotas::get_status(conn, aid, ns).map_err(|e| e.to_string())?;
            Ok(json!({
                "agent_id": aid,
                "namespace": ns,
                "quota": row,
            }))
        }
        // Per-agent aggregate (rolled-up across every namespace).
        (Some(aid), None) => {
            let row = crate::quotas::get_aggregate_status(conn, aid).map_err(|e| e.to_string())?;
            Ok(json!({
                "agent_id": aid,
                "namespace": crate::quotas::GLOBAL_NAMESPACE,
                "quota": row,
            }))
        }
        // Per-namespace listing (every agent that has written in this ns).
        (None, Some(ns)) => {
            let rows = crate::quotas::list_status(conn, Some(ns)).map_err(|e| e.to_string())?;
            Ok(json!({
                "count": rows.len(),
                "namespace": ns,
                "quotas": rows,
            }))
        }
        // Full substrate listing.
        (None, None) => {
            let rows = crate::quotas::list_status(conn, None).map_err(|e| e.to_string())?;
            Ok(json!({
                "count": rows.len(),
                "quotas": rows,
            }))
        }
    }
}

// --- D1.5 (#986): per-tool McpTool impl for memory_quota_status ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_quota_status`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct QuotaStatusRequest {
    /// Restrict to one agent.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Restrict to one namespace (v0.7.0 #1156 — per-namespace K8
    /// dimension). When supplied with `agent_id`, returns the single
    /// `(agent_id, namespace)` row. When supplied without `agent_id`,
    /// returns every agent's row in that namespace. When omitted,
    /// the aggregate view is returned for an agent_id or the full
    /// substrate listing otherwise.
    #[serde(default)]
    pub namespace: Option<String>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_quota_status`.
#[allow(dead_code)]
pub struct QuotaStatusTool;

impl McpTool for QuotaStatusTool {
    fn name() -> &'static str {
        "memory_quota_status"
    }
    fn description() -> &'static str {
        "Report per-agent + per-namespace quota usage. Operator-facing."
    }
    fn docs() -> &'static str {
        "K8/#1156: per-agent + per-namespace quota usage (memories/day, \
         storage bytes, links/day). Omit agent_id for all. Omit namespace \
         for the aggregate view (sum across namespaces). Supply both for \
         the single row."
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
    //! Four paths to cover:
    //! - per-(agent, namespace): a missing row auto-inserts and
    //!   surfaces the default quota
    //! - per-agent aggregate (no namespace): rolls up across namespaces
    //! - per-namespace listing (no agent_id): filters to one namespace
    //! - full listing: returns every row in the substrate

    use super::*;
    use crate::storage as db;

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    #[test]
    fn per_agent_returns_aggregate_for_unknown_id() {
        let conn = fresh_conn();
        let resp = handle_quota_status(&conn, &json!({"agent_id": "ai:alice"})).expect("ok");
        assert_eq!(resp["agent_id"].as_str(), Some("ai:alice"));
        // No explicit namespace → aggregate view with `_global` label.
        assert_eq!(resp["namespace"].as_str(), Some("_global"));
        let quota = &resp["quota"];
        assert!(quota.is_object());
        assert_eq!(quota["agent_id"].as_str(), Some("ai:alice"));
        // Defaults should set non-zero ceilings.
        assert!(quota["max_memories_per_day"].as_i64().unwrap_or(0) > 0);
    }

    #[test]
    fn per_agent_namespace_returns_single_row() {
        let conn = fresh_conn();
        let resp = handle_quota_status(
            &conn,
            &json!({"agent_id": "ai:alice", "namespace": "team/policies"}),
        )
        .expect("ok");
        assert_eq!(resp["agent_id"].as_str(), Some("ai:alice"));
        assert_eq!(resp["namespace"].as_str(), Some("team/policies"));
        let quota = &resp["quota"];
        assert_eq!(quota["namespace"].as_str(), Some("team/policies"));
    }

    #[test]
    fn list_path_returns_count_and_rows() {
        let conn = fresh_conn();
        let _ = handle_quota_status(&conn, &json!({"agent_id": "ai:bob"})).expect("seed bob");
        let _ = handle_quota_status(&conn, &json!({"agent_id": "ai:carol"})).expect("seed carol");
        let resp = handle_quota_status(&conn, &json!({})).expect("ok");
        assert!(resp["count"].as_u64().unwrap() >= 2);
        let quotas = resp["quotas"].as_array().expect("quotas array");
        assert!(quotas.len() >= 2);
    }

    #[test]
    fn list_path_namespace_filter_only_returns_matching_rows() {
        let conn = fresh_conn();
        let _ = handle_quota_status(
            &conn,
            &json!({"agent_id": "ai:bob", "namespace": "team/policies"}),
        )
        .expect("seed");
        let _ = handle_quota_status(
            &conn,
            &json!({"agent_id": "ai:carol", "namespace": "team/policies"}),
        )
        .expect("seed");
        let _ = handle_quota_status(
            &conn,
            &json!({"agent_id": "ai:bob", "namespace": "alice/scratch"}),
        )
        .expect("seed");
        let resp = handle_quota_status(&conn, &json!({"namespace": "team/policies"})).expect("ok");
        assert_eq!(resp["namespace"].as_str(), Some("team/policies"));
        let quotas = resp["quotas"].as_array().expect("quotas array");
        for q in quotas {
            assert_eq!(q["namespace"].as_str(), Some("team/policies"));
        }
    }

    #[test]
    fn list_path_empty_db_returns_zero() {
        let conn = fresh_conn();
        let resp = handle_quota_status(&conn, &json!({})).expect("ok");
        assert_eq!(resp["count"].as_u64(), Some(0));
        assert_eq!(resp["quotas"].as_array().unwrap().len(), 0);
    }

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
