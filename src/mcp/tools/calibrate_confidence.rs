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

use crate::confidence::calibrate::{
    CalibrationAudience, DEFAULT_WINDOW_DAYS, calibrate_from_shadow,
};

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
/// `audience` (v1.0.0 #3507) is the caller gate: the report is a
/// CALLER-SCOPED aggregate, so the substrate needs to be told whose rows it
/// may aggregate. It is a required argument rather than something resolved
/// inside this function because the two surfaces that reach here resolve a
/// caller differently — MCP from `AI_MEMORY_AGENT_ID`
/// (`identity::resolve_mcp_read_visibility_caller`), HTTP from `X-Agent-Id`
/// plus the admin allow-list — and a hidden default here would silently
/// re-open the global sweep on whichever surface forgot.
///
/// Errors:
/// * `days must be non-negative` — caller passed `days < 0`.
/// * `days must not exceed 36500 days` — caller exceeded the bounded
///   calibration window.
/// * `memory_calibrate_confidence substrate error: ...` — SQL error.
pub fn handle_calibrate_confidence(
    conn: &rusqlite::Connection,
    params: &Value,
    audience: &CalibrationAudience,
) -> Result<Value, String> {
    let days = params
        .get("days")
        .and_then(Value::as_i64)
        .unwrap_or(DEFAULT_WINDOW_DAYS);
    if days < 0 {
        return Err("days must be non-negative".to_string());
    }
    if days > crate::validate::MAX_DURATION_DAYS {
        return Err(format!(
            "days must not exceed {} days (got {days})",
            crate::validate::MAX_DURATION_DAYS
        ));
    }

    let report = calibrate_from_shadow(conn, days, chrono::Utc::now(), audience)
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
pub struct CalibrateConfidenceRequest {
    /// Window days (0..=36500).
    #[serde(default)]
    pub days: Option<i64>,

    /// **IGNORED** (#3171). Declared since D1.5 and read by NO handler on
    /// any surface — the response is always the JSON envelope. Left declared
    /// rather than removed so a client already sending it is not refused;
    /// do not rely on it to select a format.
    #[serde(default)]
    pub output_format: Option<String>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_calibrate_confidence`.
#[allow(dead_code)]
pub struct CalibrateConfidenceTool;

impl McpTool for CalibrateConfidenceTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_CALIBRATE_CONFIDENCE
    }
    fn description() -> &'static str {
        // First sentence MUST be ≤32 bytes (purpose): `wire_compact_descriptions`
        // (`compact_description`, MAX=32) is what `tools/list` ships. The
        // IGNORED caveat is the second sentence so it is honest without
        // replacing the tool's purpose on the wire (#3397 review). Full
        // disclosure lives in `docs()`; wire-level survival of a trailing
        // caveat is #3378.
        "Calibrate confidence baselines. output_format is ignored. Scan confidence_shadow_observations; emit per-source baselines (Form 5)."
    }
    fn docs() -> &'static str {
        "Form 5 (#758): read-only calibration sweep over shadow-mode observations (AI_MEMORY_CONFIDENCE_SHADOW=1). Returns CalibrationReport {window_days, total_observations, baselines:[{namespace, source, count, median, mean, buckets}]}. Default window 30d. Family::Power — refuses on keyword tier. output_format is IGNORED (#3171/#3397) — the response is always the JSON envelope; the field stays declared so existing clients are not refused. The field description is stripped from tools/list and compact_description MAX=32 keeps only the purpose sentence, so this docs() sentence is the load-bearing IGNORED disclosure."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<CalibrateConfidenceRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
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

    /// #3397 — purpose first on the wire; IGNORED disclosure in `docs()`.
    /// compact_description MAX=32 keeps only the first sentence, so that
    /// sentence must be the tool purpose (≤32 bytes including the `.`).
    /// The inert-field caveat is the second sentence of `description()`
    /// and the load-bearing copy lives in `docs()`. Denied path: a
    /// description that still looks like a working format selector.
    #[test]
    fn calibrate_purpose_first_ignored_in_docs_3397() {
        let desc = CalibrateConfidenceTool::description();
        let docs = CalibrateConfidenceTool::docs();
        let (first, rest) = desc
            .split_once('.')
            .expect("description has a first sentence");
        assert!(
            first.len() < 32,
            "purpose sentence must be ≤32 bytes so compact_description keeps it, got len={} {first:?}",
            first.len() + 1
        );
        assert!(
            first.to_ascii_lowercase().contains("calibrate")
                && first.to_ascii_lowercase().contains("confidence"),
            "first sentence must be the tool purpose, got: {desc}"
        );
        assert!(
            rest.to_ascii_lowercase()
                .contains("output_format is ignored."),
            "second sentence must disclose the inert field, got: {desc}"
        );
        assert!(
            docs.contains("IGNORED") || docs.to_ascii_lowercase().contains("ignored"),
            "verbose docs must also disclose the inert field, got: {docs}"
        );
        assert!(
            !desc.contains("json envelope or ASCII table"),
            "must not advertise output_format as a working selector, got: {desc}"
        );
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
        let v = handle_calibrate_confidence(&conn, &json!({}), &CalibrationAudience::admin())
            .expect("ok");
        assert_eq!(v["report"]["total_observations"], 0);
        assert!(v["report"]["baselines"].as_array().unwrap().is_empty());
    }

    #[test]
    fn rejects_negative_days() {
        let (conn, _dir) = open_tmp();
        let err =
            handle_calibrate_confidence(&conn, &json!({"days": -1}), &CalibrationAudience::admin())
                .expect_err("must reject");
        assert!(err.contains("non-negative"));
    }

    #[test]
    fn default_days_used_when_omitted() {
        let (conn, _dir) = open_tmp();
        let v = handle_calibrate_confidence(&conn, &json!({}), &CalibrationAudience::admin())
            .expect("ok");
        assert_eq!(
            v["report"]["window_days"].as_i64().unwrap(),
            DEFAULT_WINDOW_DAYS
        );
    }

    #[test]
    fn bounded_days_refuse_huge_and_allow_maximum_3384() {
        let (conn, _dir) = open_tmp();
        let err = handle_calibrate_confidence(
            &conn,
            &json!({"days": i64::MAX}),
            &CalibrationAudience::admin(),
        )
        .expect_err("huge calibration window must be refused without panicking");
        assert!(err.contains("must not exceed 36500"), "got: {err}");

        let zero =
            handle_calibrate_confidence(&conn, &json!({"days": 0}), &CalibrationAudience::admin())
                .expect("zero is the documented empty-window calibration shape");
        assert_eq!(zero["report"]["window_days"].as_i64(), Some(0));
        assert_eq!(zero["report"]["total_observations"].as_u64(), Some(0));

        let value = handle_calibrate_confidence(
            &conn,
            &json!({"days": crate::validate::MAX_DURATION_DAYS}),
            &CalibrationAudience::admin(),
        )
        .expect("maximum bounded window remains valid");
        assert_eq!(
            value["report"]["window_days"].as_i64(),
            Some(crate::validate::MAX_DURATION_DAYS)
        );
    }
}
