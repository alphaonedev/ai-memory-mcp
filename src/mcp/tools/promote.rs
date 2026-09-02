// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_promote` handler.

use crate::mcp::param_names;
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

    // v0.9.0 G10.1 (#1827) — optional macaroon capability token. Plain `//`
    // so schemars emits only the concise attribute description.
    #[serde(default)]
    #[schemars(
        description = "#1827 capability token (cap1:..) — may flip a governance Deny/Pending on this promote to Allow within its caveats."
    )]
    pub capability: Option<String>,

    /// #3171 — the governance / capability-binding subject for this promote.
    /// Bound to the caller under the multi-tenant posture.
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// v0.7.0 #972 D1.6 (#987) — `McpTool` impl for `memory_promote`.
#[allow(dead_code)]
pub struct PromoteTool;

impl McpTool for PromoteTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_PROMOTE
    }
    fn description() -> &'static str {
        "Promote a memory to long (or chosen tier) / ancestor namespace."
    }
    fn docs() -> &'static str {
        "Default: bump to long (clears expiry); short->long and mid->long are single-call. #831: target_tier ('mid'|'long') stops on intermediate. Task 1.7: to_namespace clones to an ancestor + derived_from link. #3171: `id` also accepts a UNIQUE ID PREFIX — an over-short prefix resolves to whichever row matches first."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<PromoteRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Lifecycle.name()
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
    let id = params["id"]
        .as_str()
        .ok_or(crate::errors::msg::ID_REQUIRED)?;
    validate::validate_id(id).map_err(|e| e.to_string())?;
    // Resolve prefix if exact ID not found; capture the memory so governance
    // has owner context (Task 1.9).
    let target = if let Some(m) = db::get(conn, id).map_err(|e| e.to_string())? {
        m
    } else if let Some(m) = db::get_by_prefix(conn, id).map_err(|e| e.to_string())? {
        m
    } else {
        return Err(crate::errors::msg::MEMORY_NOT_FOUND.into());
    };
    let resolved_id = target.id.clone();
    // P5 (G9): snapshot fields needed for the post-success webhook.
    let snapshot_namespace = target.namespace.clone();
    let snapshot_owner: Option<String> = target
        .metadata
        .get(param_names::AGENT_ID)
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // #1786 — owner gate: refuse a cross-owner promote / namespace-clone. The
    // MCP promote path calls raw `db::*` directly (bypassing the HTTP
    // `require_caller_owns_memory`, #930). Keyed on the ENFORCED-read caller
    // (`resolve_read_visibility_caller`, env-only) so it fires ONLY when
    // `AI_MEMORY_AGENT_ID` is set (multi-tenant opt-in); single-operator
    // trust-all default byte-unchanged. `allow_inbox = false`.
    if let Some(caller) = crate::identity::resolve_read_visibility_caller() {
        if !crate::visibility::caller_owns_for_mutation(&target, &caller, false) {
            return Err(crate::errors::msg::CALLER_DOES_NOT_OWN_MEMORY.into());
        }
    }

    // #3202 Fable HIGH (2) — destination Store-class gate FIRST so a
    // SOURCE `promote: Approve` cannot queue (and later execute) a clone
    // into a dest whose `write` policy Denies the caller. Dest Pending
    // still queues a store-vertical pending (execute arm already clones).
    let dest_agent_id: Option<String> =
        if let Some(to_ns) = params[crate::models::field_names::TO_NAMESPACE].as_str() {
            validate::validate_namespace(to_ns).map_err(|e| e.to_string())?;
            validate::reject_reserved_write_namespace(to_ns).map_err(|e| e.to_string())?;
            use crate::models::{GovernanceDecision, GovernedAction};
            let dest_agent_id = crate::identity::resolve_governance_subject(
                params[param_names::AGENT_ID].as_str(),
                mcp_client,
                "promote",
            )
            .map_err(|e| e.to_string())?;
            let dest_capability = crate::governance::capability::parse_presented_token(
                params[param_names::CAPABILITY].as_str(),
                &dest_agent_id,
            )
            .map_err(|rej| crate::governance::capability::edge_reject_message(&rej))?;
            let dest_payload = json!({
                "id": resolved_id,
                (crate::models::field_names::TO_NAMESPACE): to_ns,
                "mode": "vertical",
            });
            crate::mcp::consult_pre_governance_decision_gate(
                to_ns,
                "promote",
                &dest_agent_id,
                Some(&resolved_id),
            )?;
            match db::enforce_governance(
                conn,
                GovernedAction::Store,
                to_ns,
                &dest_agent_id,
                None,
                None,
                &dest_payload,
                dest_capability.as_ref(),
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
                    crate::subscriptions::dispatch_approval_requested(conn, &pending_id, db_path);
                    return Ok(json!({
                        "status": "pending",
                        "pending_id": pending_id,
                        "reason": crate::errors::msg::GOVERNANCE_REQUIRES_APPROVAL,
                        "action": "promote",
                        "memory_id": resolved_id,
                        (crate::models::field_names::TO_NAMESPACE): to_ns,
                    }));
                }
            }
            crate::governance::audit::record_decision(
                &dest_agent_id,
                "allow",
                crate::mcp::registry::tool_names::MEMORY_PROMOTE,
                to_ns,
                dest_payload,
            );
            Some(dest_agent_id)
        } else {
            None
        };

    // Task 1.9: governance enforcement (promote-side).
    {
        use crate::models::{GovernanceDecision, GovernedAction};
        // #3171 — the governance / capability-binding / mandatory-hook SUBJECT
        // must not be caller-chosen. `resolve_agent_id` gives the WIRE
        // `params.agent_id` precedence over the env identity, so a caller could
        // pick the principal its own promote was judged as while the #1786
        // ownership gate above stayed keyed on the ENV caller — two controls
        // that can never agree. Bind the subject to the enforced-read caller
        // under the multi-tenant posture; single-operator default unchanged.
        let agent_id = crate::identity::resolve_governance_subject(
            params[param_names::AGENT_ID].as_str(),
            mcp_client,
            "promote",
        )
        .map_err(|e| e.to_string())?;
        let mem_owner = target
            .metadata
            .get(param_names::AGENT_ID)
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let payload = json!({
            "id": resolved_id,
            "to_namespace": params["to_namespace"].as_str(),
        });
        // v0.9.0 G10.1 (#1827) — edge-parse the optional `capability`
        // param ONCE; inert unless `[capabilities].enabled`.
        let capability = crate::governance::capability::parse_presented_token(
            params[param_names::CAPABILITY].as_str(),
            &agent_id,
        )
        .map_err(|rej| crate::governance::capability::edge_reject_message(&rej))?;
        // #2356 (W1A6-03) — `pre_governance_decision` mandatory-hook-presence
        // consult BEFORE the governance decision dispatches.
        crate::mcp::consult_pre_governance_decision_gate(
            &target.namespace,
            "promote",
            &agent_id,
            Some(&resolved_id),
        )?;
        match db::enforce_governance(
            conn,
            GovernedAction::Promote,
            &target.namespace,
            &agent_id,
            Some(&resolved_id),
            mem_owner.as_deref(),
            &payload,
            capability.as_ref(),
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
                    "reason": crate::errors::msg::GOVERNANCE_REQUIRES_APPROVAL,
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
    if let Some(to_ns) = params[crate::models::field_names::TO_NAMESPACE].as_str() {
        let dest_agent_id = dest_agent_id.ok_or_else(|| {
            "internal: vertical dest gate did not stash the dest subject".to_string()
        })?;
        let clone_id =
            db::promote_to_namespace(conn, &resolved_id, to_ns, Some(dest_agent_id.as_str()))
                .map_err(|e| e.to_string())?;
        // P5 (G9): fire `memory_promote` webhook for vertical mode AFTER
        // the clone commits. memory_id = source id (subscribers can
        // distinguish via `mode` and `clone_id` in the details block).
        // #3403 — through the shared write-event funnel. Pre-#3403 this arm
        // used `tool_names::MEMORY_PROMOTE` while the tier arm below used a
        // bare `"memory_promote"` literal: the exact per-site drift the
        // funnel now makes unrepresentable.
        crate::write_events::promote(
            conn,
            db_path,
            &resolved_id,
            &snapshot_namespace,
            snapshot_owner.as_deref(),
            &crate::subscriptions::PromoteEventDetails {
                mode: "vertical".to_string(),
                tier: None,
                to_namespace: Some(to_ns.to_string()),
                clone_id: Some(clone_id.clone()),
            },
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
    //
    // The string literals in the match arms below are the canonical
    // wire deserializer for `target_tier`; they pair byte-for-byte with
    // `Tier::as_str` outputs (see `src/models/memory.rs`). Per pm-v3.1
    // PR6 (#1174), this site is intentionally kept as raw literals
    // because it consumes caller-supplied wire input — anywhere else
    // that *constructs* a tier wire value routes through
    // `Tier::<X>.as_str()`.
    // v0.7.0 F-C6 fix (issue #1432): route the tier wire string through
    // the canonical `Tier::from_str` SSOT instead of an inline match
    // that duplicates the parser body. The promote-specific guard
    // (reject Short as a downgrade target) stays explicit; the
    // unrecognized-tier and missing-value paths preserve byte-equal
    // error messages.
    let target_tier = match params["target_tier"].as_str() {
        None => Tier::Long,
        Some("short") => {
            return Err(
                "target_tier 'short' is not a valid promote target (would be a downgrade)".into(),
            );
        }
        Some(other) => match Tier::from_str(other) {
            Some(t) => t,
            None => {
                return Err(format!(
                    "target_tier must be one of 'mid' or 'long' (got '{other}')"
                ));
            }
        },
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
        return Err(crate::errors::msg::MEMORY_NOT_FOUND.into());
    }
    // P5 (G9): fire `memory_promote` webhook for the default tier-upgrade
    // path AFTER the update commits. The webhook `tier` field reflects
    // the requested target (long by default, or whatever `target_tier`
    // resolved to).
    let tier_str = target_tier.as_str().to_string();
    // #3403 — through the shared write-event funnel. This arm previously
    // carried a bare `"memory_promote"` string literal while the vertical
    // arm above used `tool_names::MEMORY_PROMOTE`; the funnel now owns the
    // single binding.
    crate::write_events::promote(
        conn,
        db_path,
        &resolved_id,
        &snapshot_namespace,
        snapshot_owner.as_deref(),
        &crate::subscriptions::PromoteEventDetails {
            mode: "tier".to_string(),
            tier: Some(tier_str.clone()),
            to_namespace: None,
            clone_id: None,
        },
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

    /// #3202 — vertical promotion must clear the DESTINATION namespace's
    /// governance, not only the source's.
    ///
    /// Pre-fix the Task-1.9 block evaluated `GovernedAction::Promote` against
    /// `target.namespace` (the SOURCE) and the destination got nothing but
    /// `reject_reserved_write_namespace`. But vertical promotion is a WRITE
    /// into `to_ns` — it lands a full copy of the row there — so an operator
    /// who set `write: Owner` on an ancestor namespace still had every row a
    /// caller could read from a descendant cloned into it. The ancestor is
    /// normally the MORE protected namespace, which makes this a governance
    /// boundary that could be crossed by construction.
    ///
    /// The source policy is deliberately permissive here so the assertion can
    /// only be satisfied by the destination gate.
    #[test]
    fn promote_to_namespace_enforces_destination_governance_3202() {
        use crate::models::{CorePolicy, GovernanceLevel, GovernancePolicy};
        let _envg = crate::identity::agent_id_env_test_lock();
        let _modeg = crate::config::lock_permissions_mode_for_test();
        crate::config::override_active_permissions_mode_for_test(
            crate::config::PermissionsMode::Enforce,
        );
        let conn = open_conn();

        // Destination `acme` — write: Owner, and the standard is owned by
        // ai:alice, so ai:bob is not the namespace owner.
        let dest_std = insert_owned(&conn, "acme-std", "acme", "ai:alice");
        let dest_policy = serde_json::to_value(GovernancePolicy {
            core: CorePolicy {
                write: GovernanceLevel::Owner,
                ..CorePolicy::default()
            },
            ..GovernancePolicy::default()
        })
        .expect("policy serialises");
        crate::db::set_row_metadata(
            &conn,
            &dest_std,
            &json!({"agent_id": "ai:alice", "governance": dest_policy}).to_string(),
        )
        .expect("stamp dest policy");
        crate::db::set_namespace_standard(&conn, "acme", &dest_std, None).expect("bind dest");

        // Source `acme/sub` — its OWN standard, fully permissive, so the
        // SOURCE gate cannot be what refuses.
        let src_std = insert_owned(&conn, "sub-std", "acme/sub", "ai:bob");
        let permissive = serde_json::to_value(GovernancePolicy::default()).expect("serialises");
        crate::db::set_row_metadata(
            &conn,
            &src_std,
            &json!({"agent_id": "ai:bob", "governance": permissive}).to_string(),
        )
        .expect("stamp src policy");
        crate::db::set_namespace_standard(&conn, "acme/sub", &src_std, None).expect("bind src");

        let row = insert_owned(&conn, "row", "acme/sub", "ai:bob");

        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:bob") };
        let err = handle_promote(
            &conn,
            Path::new(":memory:"),
            &json!({"id": row, "to_namespace": "acme"}),
            None,
        )
        .expect_err("a non-owner promote into a write:Owner ancestor must refuse");
        assert!(
            err.contains("not the owner"),
            "the DESTINATION owner gate must be what refuses; got: {err}"
        );

        // The clone must not exist: a refused promote writes nothing.
        assert!(
            crate::db::find_by_title_namespace(&conn, "row", "acme")
                .expect("probe")
                .is_none(),
            "a refused promote must not land the clone in the destination"
        );

        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
    }

    /// #3202 Fable HIGH (2) — SOURCE `promote: Approve` must NOT queue when
    /// the destination `write` policy refuses. Dest gate runs first.
    #[test]
    fn promote_source_approve_cannot_bypass_dest_owner_3202() {
        use crate::models::{CorePolicy, GovernanceLevel, GovernancePolicy};
        let _envg = crate::identity::agent_id_env_test_lock();
        let _modeg = crate::config::lock_permissions_mode_for_test();
        crate::config::override_active_permissions_mode_for_test(
            crate::config::PermissionsMode::Enforce,
        );
        let conn = open_conn();

        let dest_std = insert_owned(&conn, "acme3-std", "acme3", "ai:alice");
        let dest_policy = serde_json::to_value(GovernancePolicy {
            core: CorePolicy {
                write: GovernanceLevel::Owner,
                ..CorePolicy::default()
            },
            ..GovernancePolicy::default()
        })
        .expect("policy serialises");
        crate::db::set_row_metadata(
            &conn,
            &dest_std,
            &json!({"agent_id": "ai:alice", "governance": dest_policy}).to_string(),
        )
        .expect("stamp dest");
        crate::db::set_namespace_standard(&conn, "acme3", &dest_std, None).expect("bind dest");

        let src_std = insert_owned(&conn, "sub3-std", "acme3/sub", "ai:bob");
        let src_approve = serde_json::to_value(GovernancePolicy {
            core: CorePolicy {
                promote: GovernanceLevel::Approve,
                ..CorePolicy::default()
            },
            ..GovernancePolicy::default()
        })
        .expect("serialises");
        crate::db::set_row_metadata(
            &conn,
            &src_std,
            &json!({"agent_id": "ai:bob", "governance": src_approve}).to_string(),
        )
        .expect("stamp src");
        crate::db::set_namespace_standard(&conn, "acme3/sub", &src_std, None).expect("bind src");

        let row = insert_owned(&conn, "row-bypass", "acme3/sub", "ai:bob");
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:bob") };
        let err = handle_promote(
            &conn,
            Path::new(":memory:"),
            &json!({"id": row, "to_namespace": "acme3"}),
            None,
        )
        .expect_err("dest Owner must refuse even when source promote is Approve");
        assert!(
            err.contains("not the owner"),
            "DESTINATION owner gate must refuse; got: {err}"
        );
        assert!(
            crate::db::find_by_title_namespace(&conn, "row-bypass", "acme3")
                .expect("probe")
                .is_none(),
            "must not clone"
        );
        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
    }

    /// #3202 — `write: Approve` on the destination QUEUES the promote instead
    /// of cloning, exactly as a direct `memory_store` into that namespace
    /// would; and an ALLOWED promote re-stamps the clone's provenance so the
    /// destination row is owned by the acting caller with the origin preserved.
    #[test]
    fn promote_destination_approve_queues_and_allow_restamps_3202() {
        use crate::models::{CorePolicy, GovernanceLevel, GovernancePolicy};
        let _envg = crate::identity::agent_id_env_test_lock();
        let _modeg = crate::config::lock_permissions_mode_for_test();
        crate::config::override_active_permissions_mode_for_test(
            crate::config::PermissionsMode::Enforce,
        );
        let conn = open_conn();

        let dest_std = insert_owned(&conn, "acme2-std", "acme2", "ai:alice");
        let approve = serde_json::to_value(GovernancePolicy {
            core: CorePolicy {
                write: GovernanceLevel::Approve,
                ..CorePolicy::default()
            },
            ..GovernancePolicy::default()
        })
        .expect("serialises");
        crate::db::set_row_metadata(
            &conn,
            &dest_std,
            &json!({"agent_id": "ai:alice", "governance": approve}).to_string(),
        )
        .expect("stamp");
        crate::db::set_namespace_standard(&conn, "acme2", &dest_std, None).expect("bind");

        let src_std = insert_owned(&conn, "sub2-std", "acme2/sub", "ai:bob");
        let permissive = serde_json::to_value(GovernancePolicy::default()).expect("serialises");
        crate::db::set_row_metadata(
            &conn,
            &src_std,
            &json!({"agent_id": "ai:bob", "governance": permissive}).to_string(),
        )
        .expect("stamp");
        crate::db::set_namespace_standard(&conn, "acme2/sub", &src_std, None).expect("bind");

        let row = insert_owned(&conn, "row2", "acme2/sub", "ai:bob");
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:bob") };
        let queued = handle_promote(
            &conn,
            Path::new(":memory:"),
            &json!({"id": row, "to_namespace": "acme2"}),
            None,
        )
        .expect("Approve queues rather than erroring");
        assert_eq!(queued["status"].as_str(), Some("pending"));
        assert!(queued["pending_id"].as_str().is_some_and(|s| !s.is_empty()));

        // Now open the destination and re-promote: the clone lands, owned by
        // the ACTING caller, with the origin preserved (never overwritten).
        // Drop the multi-tenant env so the #1786 source-owner gate does not
        // refuse bob promoting alice's row; pass `agent_id` on the wire so
        // the single-operator ladder still restamps the clone as bob.
        let open = serde_json::to_value(GovernancePolicy::default()).expect("serialises");
        crate::db::set_row_metadata(
            &conn,
            &dest_std,
            &json!({"agent_id": "ai:alice", "governance": open}).to_string(),
        )
        .expect("reopen");
        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
        let row3 = insert_owned(&conn, "row3", "acme2/sub", "ai:alice");
        handle_promote(
            &conn,
            Path::new(":memory:"),
            &json!({"id": row3, "to_namespace": "acme2", "agent_id": "ai:bob"}),
            None,
        )
        .expect("open destination allows");
        let clone_id = crate::db::find_by_title_namespace(&conn, "row3", "acme2")
            .expect("probe")
            .expect("clone landed");
        let clone = crate::db::get(&conn, &clone_id)
            .expect("read clone")
            .expect("clone present");
        assert_eq!(
            clone.metadata["agent_id"].as_str(),
            Some("ai:bob"),
            "the clone is attributed to the ACTING caller, not the source author"
        );
        assert_eq!(
            clone.metadata["promoted_from_agent_id"].as_str(),
            Some("ai:alice"),
            "the original authorship must be PRESERVED, never overwritten"
        );
        assert_eq!(
            clone.metadata["promoted_from_namespace"].as_str(),
            Some("acme2/sub")
        );
        assert!(clone.metadata["promoted_from"].as_str().is_some());

        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
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

    fn insert_owned(conn: &rusqlite::Connection, title: &str, ns: &str, owner: &str) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = crate::models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("c {title}"),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": owner}),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: vec![],
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

    /// #2357 (W1A4-08) — vertical promotion CLONES a row into `to_namespace`;
    /// the write-reserved `_peer_head_entanglement` target is refused.
    #[test]
    fn issue_2357_promote_rejects_reserved_to_namespace() {
        let conn = open_conn();
        let id = insert_owned(&conn, "issue-2357-promote", "promo-2357", "ai:alice");
        let err = handle_promote(
            &conn,
            Path::new(":memory:"),
            &json!({
                "id": id,
                "to_namespace": crate::identity::equivocation::PEER_HEAD_ENTANGLEMENT_NAMESPACE,
            }),
            None,
        )
        .expect_err("reserved to_namespace must be refused");
        assert!(err.contains("reserved"), "got: {err}");
    }

    #[test]
    fn cross_owner_promote_refused_1786() {
        // #1786 — with AI_MEMORY_AGENT_ID set (the multi-tenant opt-in) a
        // cross-owner promote is REFUSED by the owner gate, and the owner passes
        // it. (Unset = trust-all single-tenant default, gate skipped — covered by
        // the other promote tests that run without the env set.)
        // #1874 — crate-wide lock (was a module-local mutex, which could not
        // exclude the cross-module readers/mutators of AI_MEMORY_AGENT_ID).
        let _envg = crate::identity::agent_id_env_test_lock();
        let conn = open_conn();
        let id = insert_owned(&conn, "alice-row", "promo-gate-1786", "ai:alice");

        // Caller ai:bob (≠ owner) → refused by the owner gate.
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:bob") };
        let err = handle_promote(&conn, Path::new(":memory:"), &json!({"id": id}), None)
            .expect_err("cross-owner promote must be refused");
        assert!(err.contains("does not own"), "got: {err}");

        // Caller ai:alice (owner) → passes the owner gate (later gates are
        // out of scope for this test; assert only that the OWNER gate allows).
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:alice") };
        if let Err(e) = handle_promote(&conn, Path::new(":memory:"), &json!({"id": id}), None) {
            assert!(
                !e.contains("does not own"),
                "owner must pass the owner gate, got: {e}"
            );
        }

        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
    }
}
