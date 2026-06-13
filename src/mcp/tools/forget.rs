// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_forget` and `memory_stats` handlers.

use crate::db;
use crate::models::Tier;
use serde_json::{Value, json};
use std::path::Path;

/// #1602 — cap on the per-response forget listing (`rows` on dry-run,
/// `deleted_ids` on a live run). Bounds the response payload on huge
/// match sets; `truncated: true` signals the listing was cut here
/// while the `would_delete` / `deleted` counts stay exact.
pub(crate) const DRY_RUN_PREVIEW_CAP: usize = 50;

/// #1602 — fetch the matched rows for a forget preview / audit
/// listing: up to [`DRY_RUN_PREVIEW_CAP`] rows plus the `truncated`
/// flag (computed by over-fetching one row past the cap).
fn forget_preview(
    conn: &rusqlite::Connection,
    namespace: Option<&str>,
    pattern: Option<&str>,
    tier: Option<&Tier>,
) -> Result<(Vec<db::ForgetMatch>, bool), String> {
    let mut rows = db::forget_matches(conn, namespace, pattern, tier, DRY_RUN_PREVIEW_CAP + 1)
        .map_err(|e| e.to_string())?;
    let truncated = rows.len() > DRY_RUN_PREVIEW_CAP;
    rows.truncate(DRY_RUN_PREVIEW_CAP);
    Ok((rows, truncated))
}

pub(super) fn handle_forget(
    conn: &rusqlite::Connection,
    params: &Value,
    archive: bool,
) -> Result<Value, String> {
    let namespace = params["namespace"].as_str();
    let pattern = params["pattern"].as_str();
    let tier = params["tier"].as_str().and_then(Tier::from_str);
    let dry_run = params["dry_run"].as_bool().unwrap_or(false);

    if dry_run {
        let count =
            db::forget_count(conn, namespace, pattern, tier.as_ref()).map_err(|e| e.to_string())?;
        // #1602 — sighted preview: the matched rows (id/title/
        // namespace/tier) ride along with the count so callers can see
        // WHAT a destructive pattern is about to remove. The
        // `would_delete` count stays byte-compatible (exact, uncapped).
        let (rows, truncated) = forget_preview(conn, namespace, pattern, tier.as_ref())?;
        let rows_json = serde_json::to_value(rows).map_err(|e| e.to_string())?;
        return Ok(json!({
            "would_delete": count,
            "dry_run": true,
            "rows": rows_json,
            "truncated": truncated,
        }));
    }

    // #1602 — capture the matched ids BEFORE deletion so the live-run
    // response can carry `deleted_ids`; rows are archived on forget,
    // so recovery via memory_archive_restore becomes one call instead
    // of an archive-list expedition. Same connection, synchronous
    // dispatch — the set cannot drift between the SELECT and DELETE.
    let (matched, truncated) = forget_preview(conn, namespace, pattern, tier.as_ref())?;
    let deleted_ids: Vec<String> = matched.into_iter().map(|m| m.id).collect();
    let deleted =
        db::forget(conn, namespace, pattern, tier.as_ref(), archive).map_err(|e| e.to_string())?;
    Ok(json!({
        "deleted": deleted,
        "archived": archive,
        "deleted_ids": deleted_ids,
        "truncated": truncated,
    }))
}

pub(super) fn handle_stats(conn: &rusqlite::Connection, db_path: &Path) -> Result<Value, String> {
    let stats = db::stats(conn, db_path).map_err(|e| e.to_string())?;
    serde_json::to_value(stats).map_err(|e| e.to_string())
}

// --- D1.5 (#986): per-tool McpTool impl for memory_stats ---
// --- D1.6 (#987): per-tool McpTool impl for memory_forget ---
//
// `memory_forget` belongs to Family::Lifecycle. D1.4 (#985) did not migrate
// it; D1.6 (#987) closes the coverage gap here, alongside `memory_stats`
// (already in this file from D1.5).

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.6 (#987) — request body for `memory_forget`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ForgetRequest {
    #[serde(default)]
    pub namespace: Option<String>,

    /// Full-text pattern; every whitespace-separated token must match
    /// (AND semantics — #1601).
    #[serde(default)]
    pub pattern: Option<String>,

    #[serde(default)]
    pub tier: Option<String>,

    /// Preview without deleting.
    #[serde(default)]
    pub dry_run: Option<bool>,
}

/// v0.7.0 #972 D1.6 (#987) — `McpTool` impl for `memory_forget`.
#[allow(dead_code)]
pub struct ForgetTool;

impl McpTool for ForgetTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_FORGET
    }
    fn description() -> &'static str {
        "Bulk delete memories matching a pattern, namespace, or tier (archives first)."
    }
    fn docs() -> &'static str {
        // #1601 — pattern matching is conservative AND, not fuzzy OR.
        // #1602 — dry_run lists the matched rows; live runs list ids.
        "Bulk delete by pattern/namespace/tier. Pattern uses AND semantics: every \
         whitespace-separated token must match (#1601). Archives first (recover via \
         memory_archive_restore). dry_run previews the matched rows \
         (id/title/namespace/tier, capped + truncated flag); live runs return \
         deleted_ids (same cap)."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ForgetRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Lifecycle.name()
    }
}

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_stats`. The
/// legacy schema is `properties: {}` — empty struct.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct StatsRequest {}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_stats`.
#[allow(dead_code)]
pub struct StatsTool;

impl McpTool for StatsTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_STATS
    }
    fn description() -> &'static str {
        "Get memory store statistics (counts, tier breakdown, sizes)."
    }
    fn docs() -> &'static str {
        "Totals, per-tier + namespace tallies, archive + DB size."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<StatsRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Meta.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_stats`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn stats_parity_986() {
        let derived = derived_props_for::<StatsRequest>();
        assert_property_set_parity("memory_stats", &derived);
        assert_descriptions_match("memory_stats", &derived);
    }

    #[test]
    fn stats_tool_metadata_986() {
        assert_eq!(StatsTool::name(), "memory_stats");
        assert_eq!(StatsTool::family(), "meta");
    }
}

#[cfg(test)]
mod d1_6_987_tests {
    //! D1.6 (#987) — schema parity for `memory_forget`.
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn forget_parity_987() {
        let derived = derived_props_for::<ForgetRequest>();
        assert_property_set_parity("memory_forget", &derived);
        assert_descriptions_match("memory_forget", &derived);
    }

    #[test]
    fn forget_tool_metadata_987() {
        assert_eq!(ForgetTool::name(), "memory_forget");
        assert_eq!(ForgetTool::family(), "lifecycle");
    }
}

#[cfg(test)]
mod tests {
    //! Coverage C-2 — focused tests for `handle_forget` + `handle_stats`.

    use super::*;
    use crate::models::Memory;
    use crate::storage as db;

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn insert_one(conn: &rusqlite::Connection, ns: &str, title: &str, tier: Tier) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("body for {title}"),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": "ai:test"}),
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
        db::insert(conn, &mem).expect("insert")
    }

    // Dry-run path: returns would_delete count without removing rows.
    #[test]
    fn forget_dry_run_counts_without_deleting() {
        let conn = fresh_conn();
        let _ = insert_one(&conn, "forget-ns", "a", Tier::Short);
        let _ = insert_one(&conn, "forget-ns", "b", Tier::Short);
        let resp = handle_forget(
            &conn,
            &json!({"namespace": "forget-ns", "dry_run": true}),
            false,
        )
        .expect("ok");
        assert_eq!(resp["dry_run"], true);
        assert_eq!(resp["would_delete"].as_u64(), Some(2));
        // Rows must still exist.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE namespace = 'forget-ns'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    // Real-delete path: removes matching rows, returns deleted count.
    #[test]
    fn forget_deletes_matching_rows() {
        let conn = fresh_conn();
        let _ = insert_one(&conn, "del-ns", "a", Tier::Short);
        let _ = insert_one(&conn, "del-ns", "b", Tier::Short);
        let resp = handle_forget(
            &conn,
            &json!({"namespace": "del-ns", "dry_run": false}),
            false,
        )
        .expect("ok");
        assert_eq!(resp["deleted"].as_u64(), Some(2));
        assert_eq!(resp["archived"], false);
    }

    // Archive flag wired through verbatim.
    #[test]
    fn forget_with_archive_propagates_flag() {
        let conn = fresh_conn();
        let _ = insert_one(&conn, "arc-ns", "a", Tier::Mid);
        let resp = handle_forget(&conn, &json!({"namespace": "arc-ns"}), true).expect("ok");
        assert_eq!(resp["archived"], true);
        assert_eq!(resp["deleted"].as_u64(), Some(1));
    }

    // Tier filter is parsed and forwarded.
    #[test]
    fn forget_with_tier_filter() {
        let conn = fresh_conn();
        let _ = insert_one(&conn, "tier-ns", "s", Tier::Short);
        let _ = insert_one(&conn, "tier-ns", "m", Tier::Mid);
        let resp = handle_forget(
            &conn,
            &json!({"namespace": "tier-ns", "tier": Tier::Short.as_str()}),
            false,
        )
        .expect("ok");
        // Only the short-tier row should be deleted.
        assert_eq!(resp["deleted"].as_u64(), Some(1));
    }

    // Invalid tier string falls back to None (tier not applied).
    #[test]
    fn forget_with_invalid_tier_string_treated_as_none() {
        let conn = fresh_conn();
        let _ = insert_one(&conn, "bad-tier-ns", "x", Tier::Mid);
        let resp = handle_forget(
            &conn,
            &json!({"namespace": "bad-tier-ns", "tier": "not-a-tier", "dry_run": true}),
            false,
        )
        .expect("ok");
        assert_eq!(resp["would_delete"].as_u64(), Some(1));
    }

    // Substrate error path: no namespace, no pattern, no tier → error.
    #[test]
    fn forget_no_filter_returns_error() {
        let conn = fresh_conn();
        let err = handle_forget(&conn, &json!({"dry_run": true}), false).unwrap_err();
        assert!(!err.is_empty());
    }

    // handle_stats — returns a serializable stats object.
    #[test]
    fn stats_returns_object_shape() {
        let conn = fresh_conn();
        let _ = insert_one(&conn, "stats-ns", "a", Tier::Short);
        let resp = handle_stats(&conn, Path::new(":memory:")).expect("ok");
        assert!(resp.is_object(), "stats must be an object");
    }

    // #1602 — dry-run is a sighted preview: the matched rows'
    // id/title/namespace/tier ride along with the count.
    #[test]
    fn forget_dry_run_lists_matched_rows_1602() {
        let conn = fresh_conn();
        let id_a = insert_one(&conn, "preview-ns", "alpha row", Tier::Short);
        let id_b = insert_one(&conn, "preview-ns", "beta row", Tier::Short);
        let resp = handle_forget(
            &conn,
            &json!({"namespace": "preview-ns", "dry_run": true}),
            false,
        )
        .expect("ok");
        assert_eq!(resp["would_delete"].as_u64(), Some(2));
        assert_eq!(resp["truncated"], false);
        let rows = resp["rows"].as_array().expect("rows array");
        assert_eq!(rows.len(), 2);
        let ids: Vec<&str> = rows.iter().filter_map(|r| r["id"].as_str()).collect();
        assert!(ids.contains(&id_a.as_str()) && ids.contains(&id_b.as_str()));
        let titles: Vec<&str> = rows.iter().filter_map(|r| r["title"].as_str()).collect();
        assert!(titles.contains(&"alpha row") && titles.contains(&"beta row"));
        assert!(rows.iter().all(|r| r["namespace"] == "preview-ns"));
        assert!(rows.iter().all(|r| r["tier"] == Tier::Short.as_str()));
    }

    // #1602 — a corpus larger than the preview cap sets truncated=true,
    // caps the listing, and keeps the count exact.
    #[test]
    fn forget_dry_run_truncates_past_preview_cap_1602() {
        let conn = fresh_conn();
        let total = DRY_RUN_PREVIEW_CAP + 5;
        for i in 0..total {
            let _ = insert_one(&conn, "cap-ns", &format!("row {i}"), Tier::Short);
        }
        let resp = handle_forget(
            &conn,
            &json!({"namespace": "cap-ns", "dry_run": true}),
            false,
        )
        .expect("ok");
        assert_eq!(resp["would_delete"].as_u64(), Some(total as u64));
        assert_eq!(resp["truncated"], true);
        assert_eq!(
            resp["rows"].as_array().map(Vec::len),
            Some(DRY_RUN_PREVIEW_CAP)
        );
    }

    // #1602 — live run returns the deleted ids so archive recovery is
    // one memory_archive_restore call.
    #[test]
    fn forget_live_run_returns_deleted_ids_1602() {
        let conn = fresh_conn();
        let id_a = insert_one(&conn, "live-ns", "a", Tier::Mid);
        let id_b = insert_one(&conn, "live-ns", "b", Tier::Mid);
        let resp = handle_forget(&conn, &json!({"namespace": "live-ns"}), true).expect("ok");
        assert_eq!(resp["deleted"].as_u64(), Some(2));
        assert_eq!(resp["truncated"], false);
        let ids: Vec<&str> = resp["deleted_ids"]
            .as_array()
            .expect("deleted_ids array")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(ids.contains(&id_a.as_str()) && ids.contains(&id_b.as_str()));
    }
}
