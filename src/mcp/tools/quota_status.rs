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
