// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_promote` handler.

use crate::mcp::registry::McpTool;
use crate::models::Tier;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::Path;

// --- D1.6 (#987): per-tool McpTool impl for `memory_promote` (lifecycle family) ---

/// v0.7.0 #972 D1.6 (#987) — request body for `memory_promote`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct PromoteRequest {
    pub id: String,

    #[schemars(
        description = "#831: 'mid' keeps expires_at; 'long' clears it. Downgrades rejected."
    )]
    #[serde(default)]
    pub target_tier: Option<String>,

    /// Task 1.7: clone target (must be a proper ancestor).
    #[serde(default)]
    pub to_namespace: Option<String>,
}

/// v0.7.0 #972 D1.6 (#987) — `McpTool` impl for `memory_promote`.
#[allow(dead_code)]
pub struct PromoteTool;

impl McpTool for PromoteTool {
    fn name() -> &'static str {
        "memory_promote"
    }
    fn description() -> &'static str {
        "Promote a memory to long (or chosen tier) / ancestor namespace."
    }
    fn docs() -> &'static str {
        "Default: bump to long (clears expiry); short->long and mid->long are single-call. #831: target_tier ('mid'|'long') stops on intermediate. Task 1.7: to_namespace clones to an ancestor + derived_from link."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(PromoteRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "lifecycle"
    }
}

#[cfg(test)]
mod d1_6_987_tests {
    //! D1.6 (#987) — schema parity for `memory_promote`.
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn promote_parity_987() {
        let derived = derived_props_for::<PromoteRequest>();
        assert_property_set_parity("memory_promote", &derived);
        assert_descriptions_match("memory_promote", &derived);
    }

    #[test]
    fn promote_tool_metadata_987() {
        assert_eq!(PromoteTool::name(), "memory_promote");
        assert_eq!(PromoteTool::family(), "lifecycle");
    }
}

pub(super) fn handle_promote(
    conn: &rusqlite::Connection,
    db_path: &Path,
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let id = params["id"].as_str().ok_or("id is required")?;
    validate::validate_id(id).map_err(|e| e.to_string())?;
    // Resolve prefix if exact ID not found; capture the memory so governance
    // has owner context (Task 1.9).
    let target = if let Some(m) = db::get(conn, id).map_err(|e| e.to_string())? {
        m
    } else if let Some(m) = db::get_by_prefix(conn, id).map_err(|e| e.to_string())? {
        m
    } else {
        return Err("memory not found".into());
    };
    let resolved_id = target.id.clone();
    // P5 (G9): snapshot fields needed for the post-success webhook.
    let snapshot_namespace = target.namespace.clone();
    let snapshot_owner: Option<String> = target
        .metadata
        .get("agent_id")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // Task 1.9: governance enforcement (promote-side).
    {
        use crate::models::{GovernanceDecision, GovernedAction};
        let agent_id = crate::identity::resolve_agent_id(params["agent_id"].as_str(), mcp_client)
            .map_err(|e| e.to_string())?;
        let mem_owner = target
            .metadata
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let payload = json!({
            "id": resolved_id,
            "to_namespace": params["to_namespace"].as_str(),
        });
        match db::enforce_governance(
            conn,
            GovernedAction::Promote,
            &target.namespace,
            &agent_id,
            Some(&resolved_id),
            mem_owner.as_deref(),
            &payload,
        )
        .map_err(|e| e.to_string())?
        {
            GovernanceDecision::Allow => {}
            GovernanceDecision::Deny(refusal) => {
                return Err(crate::governance::deny_message(
                    "promote",
                    crate::governance::DenyGate::Governance,
                    &refusal.reason,
                ));
            }
            GovernanceDecision::Pending(pending_id) => {
                // v0.7.0 K4 — see the store-side companion call.
                crate::subscriptions::dispatch_approval_requested(conn, &pending_id, db_path);
                return Ok(json!({
                    "status": "pending",
                    "pending_id": pending_id,
                    "reason": "governance requires approval",
                    "action": "promote",
                    "memory_id": resolved_id,
                }));
            }
        }
    }

    // Task 1.7: optional vertical promotion to an ancestor namespace.
    // When `to_namespace` is supplied, clone (don't move) the memory to the
    // target and link clone → source with `derived_from`. Original is
    // untouched; tier is NOT changed by this path.
    if let Some(to_ns) = params["to_namespace"].as_str() {
        validate::validate_namespace(to_ns).map_err(|e| e.to_string())?;
        let clone_id =
            db::promote_to_namespace(conn, &resolved_id, to_ns).map_err(|e| e.to_string())?;
        // P5 (G9): fire `memory_promote` webhook for vertical mode AFTER
        // the clone commits. memory_id = source id (subscribers can
        // distinguish via `mode` and `clone_id` in the details block).
        let details = serde_json::to_value(crate::subscriptions::PromoteEventDetails {
            mode: "vertical".to_string(),
            tier: None,
            to_namespace: Some(to_ns.to_string()),
            clone_id: Some(clone_id.clone()),
        })
        .ok();
        crate::subscriptions::dispatch_event_with_details(
            conn,
            "memory_promote",
            &resolved_id,
            &snapshot_namespace,
            snapshot_owner.as_deref(),
            db_path,
            details,
        );
        return Ok(json!({
            "promoted": true,
            "mode": "vertical",
            "source_id": resolved_id,
            "clone_id": clone_id,
            "to_namespace": to_ns,
        }));
    }

    // Default: tier promotion to long (historical behavior). Issue #831
    // — accept an optional `target_tier` parameter so callers can land
    // on `mid` as an intermediate step instead of jumping straight to
    // `long`. Omitting `target_tier` preserves the historical
    // highest-reachable-tier behaviour (short→long / mid→long in a
    // single call), which the v0.7.0 CLAUDE.md docs pin under
    // "Data Model" + "Recall Pipeline → Touch operations".
    let target_tier = match params["target_tier"].as_str() {
        None => Tier::Long,
        Some("long") => Tier::Long,
        Some("mid") => Tier::Mid,
        Some("short") => {
            return Err(
                "target_tier 'short' is not a valid promote target (would be a downgrade)".into(),
            );
        }
        Some(other) => {
            return Err(format!(
                "target_tier must be one of 'mid' or 'long' (got '{other}')"
            ));
        }
    };
    // Mid-tier promotions must KEEP a live expires_at (mid is a
    // 7-day-TTL bucket, not permanent). `db::update`'s expires_at
    // contract: `Some("")` clears, `None` preserves the existing
    // value. Long is permanent → clear. Mid → preserve whatever
    // expiry the row already had (the upstream touch path is what
    // refreshes it).
    let expires_at_arg: Option<&str> = match target_tier {
        Tier::Long => Some(""),          // empty string clears expires_at
        Tier::Mid | Tier::Short => None, // preserve existing expiry
    };
    let (found, _) = db::update(
        conn,
        &resolved_id,
        None,
        None,
        Some(&target_tier),
        None,
        None,
        None,
        None,
        expires_at_arg,
        None,
    )
    .map_err(|e| e.to_string())?;
    if !found {
        return Err("memory not found".into());
    }
    // P5 (G9): fire `memory_promote` webhook for the default tier-upgrade
    // path AFTER the update commits. The webhook `tier` field reflects
    // the requested target (long by default, or whatever `target_tier`
    // resolved to).
    let tier_str = target_tier.as_str().to_string();
    let details = serde_json::to_value(crate::subscriptions::PromoteEventDetails {
        mode: "tier".to_string(),
        tier: Some(tier_str.clone()),
        to_namespace: None,
        clone_id: None,
    })
    .ok();
    crate::subscriptions::dispatch_event_with_details(
        conn,
        "memory_promote",
        &resolved_id,
        &snapshot_namespace,
        snapshot_owner.as_deref(),
        db_path,
        details,
    );
    Ok(json!({"promoted": true, "mode": "tier", "id": resolved_id, "tier": tier_str}))
}

// ---- C-5 (#699): close lib-tier gaps in promote.rs (currently 93.39%).
// The MCP envelope path already exercises governance Allow/Deny/Pending,
// vertical mode, and the tier-promote happy path. These tests bolt down
// the `id is required` and validator-error branches that the high-level
// dispatcher tests don't hit at the lib-only tier. ----
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn open_conn() -> rusqlite::Connection {
        crate::db::open(Path::new(":memory:")).expect("open in-memory db")
    }

    #[test]
    fn handle_promote_missing_id_errors() {
        // Line 16: `id is required`.
        let conn = open_conn();
        let err = handle_promote(&conn, Path::new(":memory:"), &json!({}), None).unwrap_err();
        assert!(err.contains("id"), "got: {err}");
    }

    #[test]
    fn handle_promote_invalid_id_maps_validator_error() {
        // Line 17: `validate_id(id).map_err(...)`. A non-UUID string is
        // rejected by the validator.
        let conn = open_conn();
        let err = handle_promote(
            &conn,
            Path::new(":memory:"),
            &json!({"id": "not-a-uuid"}),
            None,
        )
        .unwrap_err();
        assert!(!err.is_empty(), "expected non-empty validator error");
    }

    #[test]
    fn handle_promote_unknown_uuid_returns_memory_not_found() {
        // Line 25: `memory not found` when both `db::get` and
        // `db::get_by_prefix` return None.
        let conn = open_conn();
        let err = handle_promote(
            &conn,
            Path::new(":memory:"),
            &json!({"id": "00000000-0000-0000-0000-000000000000"}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }
}
