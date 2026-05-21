// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 L2-2 (S6-M1) — MCP `memory_reflection_origin` handler.
//!
//! Returns the cross-peer federation provenance for a reflection
//! memory: which peer delivered the row to this host, who originally
//! signed it, the depth it carried in transit, and the receiver's
//! local cap at arrival time. See
//! [`crate::federation::reflection_bookkeeping`] for the substrate
//! contract.

use serde_json::{Value, json};

/// MCP `memory_reflection_origin` handler. Returns the structured
/// origin record for a memory id, or a clean "this memory is not a
/// reflection" envelope when the id exists but `reflection_depth == 0`.
///
/// Wire shape:
///
/// ```json
/// {
///   "memory_id": "...",
///   "peer_origin": "ai:peer-a@host:pid-1234",
///   "signing_agent": "ai:claude@host:pid-1234",
///   "original_depth": 2,
///   "local_depth_at_arrival": 3,
///   "is_reflection": true
/// }
/// ```
///
/// On unknown id → returns an error string the MCP layer surfaces as
/// `-32602 "memory not found: <id>"`. Non-reflection ids return a
/// well-formed envelope with `is_reflection = false` so callers can
/// branch without parsing the error path.
pub(super) fn handle_reflection_origin(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let memory_id = params["memory_id"]
        .as_str()
        .ok_or("memory_id is required")?;
    if memory_id.is_empty() {
        return Err("memory_id cannot be empty".to_string());
    }
    let origin = crate::federation::reflection_bookkeeping::reflection_origin(conn, memory_id)
        .map_err(|e| format!("reflection_origin substrate error: {e}"))?;
    match origin {
        Some(record) => Ok(json!({
            "memory_id": record.memory_id,
            "peer_origin": record.peer_origin,
            "signing_agent": record.signing_agent,
            "original_depth": record.original_depth,
            "local_depth_at_arrival": record.local_depth_at_arrival,
            "is_reflection": record.is_reflection,
        })),
        None => Err(format!("memory not found: {memory_id}")),
    }
}

// --- D1.5 (#986): per-tool McpTool impl for memory_reflection_origin ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_reflection_origin`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
#[schemars(deny_unknown_fields)]
pub struct ReflectionOriginRequest {
    /// Memory ID.
    pub memory_id: String,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_reflection_origin`.
#[allow(dead_code)]
pub struct ReflectionOriginTool;

impl McpTool for ReflectionOriginTool {
    fn name() -> &'static str {
        "memory_reflection_origin"
    }
    fn description() -> &'static str {
        "Inspect the cross-peer provenance of a reflection memory."
    }
    fn docs() -> &'static str {
        "L2-2 (S6-M1): {memory_id, peer_origin, signing_agent, original_depth, local_depth_at_arrival, is_reflection}. Non-reflections return envelope with is_reflection=false. Unknown ids => error."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(ReflectionOriginRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "power"
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_reflection_origin`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn reflection_origin_parity_986() {
        let derived = derived_props_for::<ReflectionOriginRequest>();
        assert_property_set_parity("memory_reflection_origin", &derived);
        assert_descriptions_match("memory_reflection_origin", &derived);
    }

    #[test]
    fn reflection_origin_tool_metadata_986() {
        assert_eq!(ReflectionOriginTool::name(), "memory_reflection_origin");
        assert_eq!(ReflectionOriginTool::family(), "power");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage as db;

    fn fresh_db() -> rusqlite::Connection {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        db::open(tmp.path()).expect("db::open")
    }

    #[test]
    fn handle_unknown_id_returns_not_found() {
        let conn = fresh_db();
        let err = handle_reflection_origin(&conn, &json!({"memory_id": "nope-id"})).unwrap_err();
        assert!(err.contains("not found"), "expected not-found error: {err}");
    }

    #[test]
    fn handle_missing_param_returns_error() {
        let conn = fresh_db();
        let err = handle_reflection_origin(&conn, &json!({})).unwrap_err();
        assert!(err.contains("memory_id"), "expected param error: {err}");
    }

    #[test]
    fn handle_non_reflection_returns_envelope_with_flag() {
        let conn = fresh_db();
        // Insert a plain memory (depth = 0).
        let now = chrono::Utc::now().to_rfc3339();
        let mem = crate::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Mid,
            namespace: "test".to_string(),
            title: "plain".to_string(),
            content: "body".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({"agent_id": "ai:test"}),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
        };
        let id = db::insert(&conn, &mem).expect("insert");
        let out = handle_reflection_origin(&conn, &json!({"memory_id": id})).unwrap();
        assert_eq!(out["is_reflection"].as_bool(), Some(false));
        assert_eq!(out["original_depth"].as_i64(), Some(0));
    }
}
