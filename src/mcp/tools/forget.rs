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
    owner: Option<&str>,
) -> Result<(Vec<db::ForgetMatch>, bool), String> {
    // #1772 — owner-scope the preview when the multi-tenant opt-in is on so
    // the dry-run / live-run match listing reflects exactly what
    // `forget_for_caller` would delete; `None` preserves trust-all default.
    let mut rows = match owner {
        Some(c) => db::forget_matches_for_caller(
            conn,
            namespace,
            pattern,
            tier,
            DRY_RUN_PREVIEW_CAP + 1,
            c,
        ),
        None => db::forget_matches(conn, namespace, pattern, tier, DRY_RUN_PREVIEW_CAP + 1),
    }
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

    // #1772 — owner gate: when the multi-tenant opt-in is on
    // (`AI_MEMORY_AGENT_ID` set), bulk forget only ever touches the CALLER's
    // own rows (+ legacy unstamped rows). The MCP forget path calls raw
    // `db::*` directly (bypassing the HTTP owner gate), so the scoping is
    // applied here by resolving the ENFORCED-read caller. `None` (unset) =
    // single-tenant trust-all default → byte-unchanged behaviour. Mirrors the
    // #1786 promote keying.
    let owner = crate::identity::resolve_read_visibility_caller();

    // #1772 — namespace-conditional governance gate (5-agent vote 4d3ea1c5 → C).
    // Single-id `handle_delete` runs the K9 permission pipeline + Task-1.9
    // `enforce_governance(Delete)` on its one resolved memory; this bulk path
    // bypassed both. `enforce_governance` / `PermissionContext` are
    // single-namespace + single-owner BY SIGNATURE, so a coherent gate is only
    // well-defined when BOTH (a) a SPECIFIC namespace is named — a
    // cross-namespace `namespace=None` forget spans many policies with no
    // single one to apply — AND (b) the multi-tenant owner opt-in is on
    // (`owner = Some(caller)`), where the owner-scope below guarantees every
    // matched row is caller-owned, so the Owner level resolves `caller == owner`
    // instead of false-denying on a None owner (`evaluate_level`:
    // Delete+Owner+None => Deny "no resolvable owner"). When namespace is None,
    // or in the single-operator trust-all default (owner None), the gate is
    // skipped: per-namespace governance is not enforceable across all
    // namespaces, and the trust-all default keeps bulk cleanup byte-unchanged
    // (the unanimous no-regression finding). `enforce_governance` is itself
    // allow-on-silence + honours AI_MEMORY_PERMISSIONS_MODE, so an un-governed
    // namespace is always Allow and this is a no-op there. Runs before the
    // dry_run branch so the preview surfaces the same refusal as a live run.
    if let (Some(ns), Some(caller)) = (namespace, owner.as_deref()) {
        use crate::models::{GovernanceDecision, GovernanceLevel, GovernedAction};
        let payload = json!({
            "namespace": ns,
            "pattern": pattern,
            "tier": tier.as_ref().map(Tier::as_str),
            "bulk": true,
        });
        // A `delete: Approve` namespace cannot coherently queue ONE pending row
        // for a pattern matching an unbounded set, so refuse it up front (under
        // Enforce) BEFORE `enforce_governance` would queue a stray
        // `pending_actions` row — direct the caller to per-memory
        // `memory_delete`, which queues a single reviewable action.
        if crate::config::active_permissions_mode() == crate::config::PermissionsMode::Enforce
            && db::resolve_governance_policy(conn, ns)
                .is_some_and(|p| matches!(p.core.delete, GovernanceLevel::Approve))
        {
            return Err(crate::governance::deny_message(
                "forget",
                crate::governance::DenyGate::Governance,
                crate::errors::msg::GOVERNANCE_REQUIRES_APPROVAL,
            ));
        }
        // Task-1.9 governance (namespace-standard delete level). memory_owner =
        // caller is correct: the owner-scope restricts the match set to
        // caller-owned rows, so the Owner level resolves caller == owner;
        // Registered + signed-rule levels gate here too.
        match db::enforce_governance(
            conn,
            GovernedAction::Delete,
            ns,
            caller,
            None,
            Some(caller),
            &payload,
        )
        .map_err(|e| e.to_string())?
        {
            GovernanceDecision::Allow => {}
            GovernanceDecision::Deny(refusal) => {
                return Err(crate::governance::deny_message(
                    "forget",
                    crate::governance::DenyGate::Governance,
                    &refusal.reason,
                ));
            }
            // Approve was refused above under Enforce; under Advisory/Off
            // enforce_governance returns Allow, so a Pending here is defensive.
            GovernanceDecision::Pending(_) => {
                return Err(crate::governance::deny_message(
                    "forget",
                    crate::governance::DenyGate::Governance,
                    crate::errors::msg::GOVERNANCE_REQUIRES_APPROVAL,
                ));
            }
        }
    }

    if dry_run {
        let count = match owner {
            Some(ref c) => db::forget_count_for_caller(conn, namespace, pattern, tier.as_ref(), c),
            None => db::forget_count(conn, namespace, pattern, tier.as_ref()),
        }
        .map_err(|e| e.to_string())?;
        // #1602 — sighted preview: the matched rows (id/title/
        // namespace/tier) ride along with the count so callers can see
        // WHAT a destructive pattern is about to remove. The
        // `would_delete` count stays byte-compatible (exact, uncapped).
        let (rows, truncated) =
            forget_preview(conn, namespace, pattern, tier.as_ref(), owner.as_deref())?;
        let rows_json = serde_json::to_value(rows).map_err(|e| e.to_string())?;
        return Ok(json!({
            "would_delete": count,
            "dry_run": true,
            "rows": rows_json,
            "truncated": truncated,
        }));
    }

    // #1602 — capture the matched ids BEFORE deletion so the live-run
    // response can carry `deleted_ids`; when `archive` is true (wired from
    // archive_on_gc) the rows are archived on forget, so recovery via
    // memory_archive_restore becomes one call instead of an archive-list
    // expedition — but with archive_on_gc=false (`archive` false) this is a
    // permanent hard-delete (#1772). Same connection, synchronous dispatch —
    // the set cannot drift between the SELECT and DELETE.
    let (matched, truncated) =
        forget_preview(conn, namespace, pattern, tier.as_ref(), owner.as_deref())?;
    let deleted_ids: Vec<String> = matched.into_iter().map(|m| m.id).collect();
    let deleted = match owner {
        Some(ref c) => db::forget_for_caller(conn, namespace, pattern, tier.as_ref(), archive, c),
        None => db::forget(conn, namespace, pattern, tier.as_ref(), archive),
    }
    .map_err(|e| e.to_string())?;
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
        "Bulk delete memories matching a pattern, namespace, or tier (archived first when archive-on-gc is on, else permanent)."
    }
    fn docs() -> &'static str {
        // #1601 — pattern matching is conservative AND, not fuzzy OR.
        // #1602 — dry_run lists the matched rows; live runs list ids.
        // #1772 — archive is conditional on archive_on_gc; the response's
        // `archived` field reports the actual disposition per call.
        "Bulk delete by pattern/namespace/tier. Pattern uses AND semantics: every \
         whitespace-separated token must match (#1601). When archive-on-gc is enabled \
         (the default) matched rows are archived first, so recovery via \
         memory_archive_restore is one call; when archive-on-gc is disabled this is a \
         permanent hard-delete with no recoverable copy (the response's `archived` \
         field reports which happened). dry_run previews the matched rows \
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
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        db::insert(conn, &mem).expect("insert")
    }

    // Dry-run path: returns would_delete count without removing rows.
    #[test]
    fn forget_dry_run_counts_without_deleting() {
        let _envg = crate::identity::agent_id_env_test_lock();
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
        let _envg = crate::identity::agent_id_env_test_lock();
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
        let _envg = crate::identity::agent_id_env_test_lock();
        let conn = fresh_conn();
        let _ = insert_one(&conn, "arc-ns", "a", Tier::Mid);
        let resp = handle_forget(&conn, &json!({"namespace": "arc-ns"}), true).expect("ok");
        assert_eq!(resp["archived"], true);
        assert_eq!(resp["deleted"].as_u64(), Some(1));
    }

    // Tier filter is parsed and forwarded.
    #[test]
    fn forget_with_tier_filter() {
        let _envg = crate::identity::agent_id_env_test_lock();
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
        let _envg = crate::identity::agent_id_env_test_lock();
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
        let _envg = crate::identity::agent_id_env_test_lock();
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
        let _envg = crate::identity::agent_id_env_test_lock();
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
        let _envg = crate::identity::agent_id_env_test_lock();
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

    // #1772 — insert a memory carrying an explicit `metadata` (so the test can
    // control `agent_id` — owned by `owner`, or unstamped via `{}`).
    fn insert_meta(conn: &rusqlite::Connection, ns: &str, title: &str, metadata: Value) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
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
            metadata,
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
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        db::insert(conn, &mem).expect("insert")
    }

    // #1772 — with AI_MEMORY_AGENT_ID set (multi-tenant opt-in), a bulk forget
    // deletes ONLY the caller's own rows + legacy unstamped rows; a different
    // named owner's row SURVIVES. Dry-run reports the same matched set (parity).
    #[test]
    fn forget_owner_scoped_1772() {
        let _envg = crate::identity::agent_id_env_test_lock();
        let conn = fresh_conn();
        let ns = "forget-own-1772";
        let id_alice = insert_meta(&conn, ns, "alice row", json!({"agent_id": "ai:alice"}));
        let id_bob = insert_meta(&conn, ns, "bob row", json!({"agent_id": "ai:bob"}));
        let id_unstamped = insert_meta(&conn, ns, "unstamped row", json!({}));

        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:alice") };

        // Dry-run parity: must report exactly alice's + the unstamped row.
        let preview = handle_forget(&conn, &json!({"namespace": ns, "dry_run": true}), true)
            .expect("dry-run ok");
        assert_eq!(preview["would_delete"].as_u64(), Some(2), "dry-run count");
        let preview_ids: Vec<&str> = preview["rows"]
            .as_array()
            .expect("rows array")
            .iter()
            .filter_map(|r| r["id"].as_str())
            .collect();
        assert!(preview_ids.contains(&id_alice.as_str()));
        assert!(preview_ids.contains(&id_unstamped.as_str()));
        assert!(
            !preview_ids.contains(&id_bob.as_str()),
            "bob's row must not appear in alice's preview"
        );

        // Live run (archive=true): deletes alice's + unstamped; bob survives.
        let resp = handle_forget(&conn, &json!({"namespace": ns}), true).expect("live ok");
        assert_eq!(resp["deleted"].as_u64(), Some(2), "live deleted count");

        assert!(
            db::get(&conn, &id_bob).expect("get bob").is_some(),
            "bob's row must SURVIVE a cross-owner forget"
        );
        assert!(
            db::get(&conn, &id_alice).expect("get alice").is_none(),
            "alice's own row must be gone"
        );
        assert!(
            db::get(&conn, &id_unstamped)
                .expect("get unstamped")
                .is_none(),
            "the legacy unstamped row must be gone (unstamped-inclusive)"
        );

        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
    }

    // #1772 — install a namespace standard on `ns` gating `delete` at
    // `delete_level`, owned by `owner` (so Owner-level checks have a target).
    fn install_delete_policy(
        conn: &rusqlite::Connection,
        ns: &str,
        delete_level: crate::models::GovernanceLevel,
        owner: &str,
    ) {
        use crate::models::{CorePolicy, GovernancePolicy, default_metadata};
        let policy = GovernancePolicy {
            core: CorePolicy {
                delete: delete_level,
                ..CorePolicy::default()
            },
            ..Default::default()
        };
        let now = chrono::Utc::now().to_rfc3339();
        let mut metadata = default_metadata();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert("agent_id".to_string(), Value::String(owner.to_string()));
            obj.insert(
                "governance".to_string(),
                serde_json::to_value(&policy).unwrap(),
            );
        }
        let standard = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: format!("_standards-{ns}"),
            title: format!("std-{ns}"),
            content: "policy".to_string(),
            tags: vec![],
            priority: 9,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata,
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
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        let sid = db::insert(conn, &standard).expect("insert standard");
        db::set_namespace_standard(conn, ns, &sid, None).expect("set standard");
    }

    // #1772 — namespace-conditional governance gate (5-agent vote 4d3ea1c5 → C).
    // When a SPECIFIC namespace carries a delete policy AND the multi-tenant
    // owner opt-in is on, bulk forget honours the same Task-1.9
    // `enforce_governance(Delete)` gate single-id `memory_delete` runs; the
    // single-operator trust-all default (env unset → owner None) skips it
    // (the unanimous no-regression finding).
    #[test]
    fn forget_governance_gate_1772() {
        let _envg = crate::identity::agent_id_env_test_lock();
        let _modeg = crate::config::lock_permissions_mode_for_test();
        crate::config::override_active_permissions_mode_for_test(
            crate::config::PermissionsMode::Enforce,
        );
        let conn = fresh_conn();

        // (1) delete:Approve under Enforce + multi-tenant opt-in → REFUSED
        //     (bulk cannot coherently pend a per-row approval), dry-run too.
        let ns_appr = "gov-forget-approve-1772";
        install_delete_policy(
            &conn,
            ns_appr,
            crate::models::GovernanceLevel::Approve,
            "ai:alice",
        );
        let id_appr = insert_meta(&conn, ns_appr, "appr row", json!({"agent_id": "ai:alice"}));
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:alice") };
        let err = handle_forget(&conn, &json!({"namespace": ns_appr}), true).unwrap_err();
        assert!(
            err.contains("approval") || err.contains("governance"),
            "approve-policy bulk forget must be refused; got: {err}"
        );
        assert!(
            db::get(&conn, &id_appr).expect("get appr").is_some(),
            "row must survive a refused forget"
        );
        assert!(
            handle_forget(&conn, &json!({"namespace": ns_appr, "dry_run": true}), true).is_err(),
            "dry-run must surface the same governance refusal"
        );

        // (2) delete:Owner, caller IS the owner → ALLOWED (owner-scope
        //     guarantees caller owns matched rows → Owner resolves caller==owner).
        let ns_own = "gov-forget-owner-1772";
        install_delete_policy(
            &conn,
            ns_own,
            crate::models::GovernanceLevel::Owner,
            "ai:alice",
        );
        let id_own = insert_meta(&conn, ns_own, "own row", json!({"agent_id": "ai:alice"}));
        let ok =
            handle_forget(&conn, &json!({"namespace": ns_own}), true).expect("owner forget ok");
        assert_eq!(ok["deleted"].as_u64(), Some(1), "owner may forget own rows");
        assert!(
            db::get(&conn, &id_own).expect("get own").is_none(),
            "owner's row must be deleted"
        );

        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };

        // (3) NO REGRESSION: same Approve namespace, single-operator default
        //     (env unset → owner None) → gate SKIPPED, forget proceeds.
        let id_appr2 = insert_meta(&conn, ns_appr, "appr row2", json!({"agent_id": "ai:alice"}));
        let ok2 = handle_forget(&conn, &json!({"namespace": ns_appr}), true)
            .expect("single-operator forget must not be governance-gated");
        assert!(
            ok2["deleted"].as_u64().unwrap_or(0) >= 1,
            "single-operator forget proceeds despite the Approve policy"
        );
        assert!(
            db::get(&conn, &id_appr2).expect("get appr2").is_none(),
            "single-operator forget deleted the row"
        );

        crate::config::clear_permissions_mode_override_for_test();
    }
}
