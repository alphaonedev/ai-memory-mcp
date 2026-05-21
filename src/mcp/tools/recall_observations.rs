// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 Gap 3 (#886) — `memory_recall_observations` read-side MCP
//! tool. Returns recent rows from the `recall_observations` ledger
//! filtered by recall_id, consumed-flag, and an optional time window.

use crate::observations;
use serde_json::{Value, json};

const DEFAULT_LIMIT: usize = 200;
const MAX_LIMIT: usize = 1000;

/// MCP handler. Filters compose with AND. Returns the ledger rows
/// most-recent-first, JSON-shaped via `observations::Observation`.
pub fn handle_recall_observations(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let recall_id = params
        .get("recall_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let consumed = params.get("consumed").and_then(Value::as_bool);
    let since = params
        .get("since")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let until = params
        .get("until")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let limit = params
        .get("limit")
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .map_or(DEFAULT_LIMIT, |n| n.min(MAX_LIMIT));

    let rows = observations::list_observations(conn, recall_id, consumed, since, until, limit)
        .map_err(|e| e.to_string())?;
    let count = rows.len();
    Ok(json!({
        "observations": rows,
        "count": count,
    }))
}

// --- D1.5 (#986): per-tool McpTool impl for memory_recall_observations ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_recall_observations`.
///
/// The legacy hand-coded entry in [`crate::mcp::registry::tool_definitions`]
/// omits the `description` field on most properties (only field names
/// + types are declared). The schemars-derived schema mirrors that
/// shape via the field naming alone.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
#[schemars(deny_unknown_fields)]
pub struct RecallObservationsRequest {
    #[serde(default)]
    pub recall_id: Option<String>,

    #[serde(default)]
    pub consumed: Option<bool>,

    #[serde(default)]
    pub since: Option<String>,

    #[serde(default)]
    pub until: Option<String>,

    #[serde(default)]
    pub limit: Option<i64>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_recall_observations`.
#[allow(dead_code)]
pub struct RecallObservationsTool;

impl McpTool for RecallObservationsTool {
    fn name() -> &'static str {
        "memory_recall_observations"
    }
    fn description() -> &'static str {
        "List recall_observations (#886)."
    }
    fn docs() -> &'static str {
        "Gap 3 (#886): recall-consumption ledger filter."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(RecallObservationsRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "meta"
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_recall_observations`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn recall_observations_parity_986() {
        let derived = derived_props_for::<RecallObservationsRequest>();
        assert_property_set_parity("memory_recall_observations", &derived);
        assert_descriptions_match("memory_recall_observations", &derived);
    }

    #[test]
    fn recall_observations_tool_metadata_986() {
        assert_eq!(RecallObservationsTool::name(), "memory_recall_observations");
        assert_eq!(RecallObservationsTool::family(), "meta");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observations::{Candidate, mark_consumed, record_recall};
    use rusqlite::params;

    fn fresh() -> rusqlite::Connection {
        // Go through `storage::open` so SCHEMA + the migration ladder
        // both apply cleanly (the ladder ALTERs columns on tables the
        // SCHEMA constant creates).
        crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn seed_memory(conn: &rusqlite::Connection, id: &str) {
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at) \
             VALUES (?1, 'long', 'test', ?2, 'c', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')",
            params![id, format!("title-{id}")],
        )
        .unwrap();
    }

    #[test]
    fn handle_recall_observations_filters_by_recall_id_and_consumed() {
        let conn = fresh();
        for id in &["m1", "m2", "m3", "consumer"] {
            seed_memory(&conn, id);
        }
        record_recall(
            &conn,
            "r1",
            &[
                Candidate {
                    memory_id: "m1",
                    retriever: "hybrid",
                    rank: 1,
                    score: 0.9,
                },
                Candidate {
                    memory_id: "m2",
                    retriever: "hybrid",
                    rank: 2,
                    score: 0.8,
                },
            ],
        )
        .unwrap();
        record_recall(
            &conn,
            "r2",
            &[Candidate {
                memory_id: "m3",
                retriever: "fts5",
                rank: 1,
                score: 0.4,
            }],
        )
        .unwrap();
        mark_consumed(&conn, "r1", &["m1"], "consumer").unwrap();

        let r = handle_recall_observations(&conn, &json!({"recall_id": "r1"})).expect("ok");
        assert_eq!(r["count"].as_u64(), Some(2));

        let only_consumed =
            handle_recall_observations(&conn, &json!({"consumed": true})).expect("ok");
        assert_eq!(only_consumed["count"].as_u64(), Some(1));
        assert_eq!(
            only_consumed["observations"][0]["memory_id"].as_str(),
            Some("m1")
        );
    }
}
