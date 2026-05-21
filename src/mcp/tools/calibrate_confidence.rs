// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 Form 5 (issue #758) — MCP handler for
//! `memory_calibrate_confidence`.
//!
//! Operator-callable equivalent of the `ai-memory calibrate confidence
//! --from-shadow` CLI driver. Reads
//! `confidence_shadow_observations` for the last `days` days (default
//! 30) and emits a [`crate::confidence::calibrate::CalibrationReport`]
//! envelope with per-(namespace, source) baselines.
//!
//! Family::Power surface — operator/observability, not data-plane.

use serde_json::{Value, json};

use crate::confidence::calibrate::{DEFAULT_WINDOW_DAYS, calibrate_from_shadow};

/// Wire shape:
///
/// ```json
/// {
///   "report": {
///     "window_days": 30,
///     "total_observations": 42,
///     "baselines": [
///       { "namespace": "ns", "source": "user", "count": 12,
///         "median": 0.62, "mean": 0.61, "buckets": [0,0,1,2,3,3,2,1,0,0] }
///     ]
///   }
/// }
/// ```
///
/// Errors:
/// * `days must be a positive integer` — caller passed `days <= 0`.
/// * `memory_calibrate_confidence substrate error: ...` — SQL error.
pub(super) fn handle_calibrate_confidence(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let days = params
        .get("days")
        .and_then(Value::as_i64)
        .unwrap_or(DEFAULT_WINDOW_DAYS);
    if days <= 0 {
        return Err("days must be a positive integer".to_string());
    }

    let report = calibrate_from_shadow(conn, days, chrono::Utc::now())
        .map_err(|e| format!("memory_calibrate_confidence substrate error: {e}"))?;

    Ok(json!({ "report": report }))
}

// --- D1.5 (#986): per-tool McpTool impl for memory_calibrate_confidence ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_calibrate_confidence`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
#[schemars(deny_unknown_fields)]
pub struct CalibrateConfidenceRequest {
    /// Window days.
    #[serde(default)]
    pub days: Option<i64>,

    /// json envelope or ASCII table.
    #[serde(default)]
    pub output_format: Option<String>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_calibrate_confidence`.
#[allow(dead_code)]
pub struct CalibrateConfidenceTool;

impl McpTool for CalibrateConfidenceTool {
    fn name() -> &'static str {
        "memory_calibrate_confidence"
    }
    fn description() -> &'static str {
        "Scan confidence_shadow_observations and emit per-source baselines (Form 5)."
    }
    fn docs() -> &'static str {
        "Form 5 (#758): read-only calibration sweep over shadow-mode observations (AI_MEMORY_CONFIDENCE_SHADOW=1). Returns CalibrationReport {window_days, total_observations, baselines:[{namespace, source, count, median, mean, buckets}]}. Default window 30d. Family::Power — refuses on keyword tier."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(CalibrateConfidenceRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "power"
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_calibrate_confidence`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn calibrate_confidence_parity_986() {
        let derived = derived_props_for::<CalibrateConfidenceRequest>();
        assert_property_set_parity("memory_calibrate_confidence", &derived);
        assert_descriptions_match("memory_calibrate_confidence", &derived);
    }

    #[test]
    fn calibrate_confidence_tool_metadata_986() {
        assert_eq!(
            CalibrateConfidenceTool::name(),
            "memory_calibrate_confidence"
        );
        assert_eq!(CalibrateConfidenceTool::family(), "power");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::open as open_storage;
    use rusqlite::Connection;
    use serde_json::json;

    fn open_tmp() -> (Connection, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("test.db");
        let _ = open_storage(&path).expect("open storage");
        let conn = Connection::open(&path).expect("open conn");
        (conn, dir)
    }

    #[test]
    fn empty_db_returns_empty_baselines() {
        let (conn, _dir) = open_tmp();
        let v = handle_calibrate_confidence(&conn, &json!({})).expect("ok");
        assert_eq!(v["report"]["total_observations"], 0);
        assert!(v["report"]["baselines"].as_array().unwrap().is_empty());
    }

    #[test]
    fn rejects_non_positive_days() {
        let (conn, _dir) = open_tmp();
        let err = handle_calibrate_confidence(&conn, &json!({"days": 0})).expect_err("must reject");
        assert!(err.contains("positive integer"));
        let err =
            handle_calibrate_confidence(&conn, &json!({"days": -1})).expect_err("must reject");
        assert!(err.contains("positive integer"));
    }

    #[test]
    fn default_days_used_when_omitted() {
        let (conn, _dir) = open_tmp();
        let v = handle_calibrate_confidence(&conn, &json!({})).expect("ok");
        assert_eq!(
            v["report"]["window_days"].as_i64().unwrap(),
            DEFAULT_WINDOW_DAYS
        );
    }
}
