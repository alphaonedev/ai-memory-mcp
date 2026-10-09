// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4419 — the approved-pending replay re-admission, split out of
//! `storage/mod.rs` (qual_10 headroom). `execute_pending_action` stays in
//! `storage/mod.rs` and calls [`readmit_pending_requester`] before every
//! side-effecting arm; [`refuse_unapproved_destination_store`] is the #3202
//! destination-store check the promote arm runs, now built on the same
//! decide-only admission ([`decide_admission_without_queue`]).

use super::*;

/// #3202 / #4419 — decide `agent_id`'s CURRENT admission for `action` in
/// `namespace` WITHOUT queueing. [`enforce_governance`] would insert a second
/// pending on `Approve`; this consults the same policy / level / ungoverned
/// path (and, for a store with a real memory payload, the same
/// `required_scope` refusal) and returns the bare decision, so a replay
/// executor can treat Deny or still-Pending as a refusal. `Off` and `Advisory`
/// admit, exactly as the live gate does (Advisory logs rather than blocks by
/// contract).
pub(super) fn decide_admission_without_queue(
    conn: &Connection,
    action: GovernedAction,
    namespace: &str,
    agent_id: &str,
    memory_owner: Option<&str>,
    payload: Option<&serde_json::Value>,
) -> Result<GovernanceDecision> {
    use crate::config::{PermissionsMode, active_permissions_mode};
    let mode = active_permissions_mode();
    if mode == PermissionsMode::Off || mode == PermissionsMode::Advisory {
        return Ok(GovernanceDecision::Allow);
    }
    let Some(policy) = resolve_governance_policy(conn, namespace)? else {
        return Ok(ungoverned_namespace_decision(
            mode, action, namespace, agent_id,
        ));
    };
    let level = match action {
        GovernedAction::Store | GovernedAction::Reflect => &policy.core.write,
        GovernedAction::Delete => &policy.core.delete,
        GovernedAction::Promote => &policy.core.promote,
    };
    let ns_owner = namespace_owner(conn, namespace)?;
    let mut decision = evaluate_level(
        conn,
        action,
        namespace,
        level,
        agent_id,
        memory_owner,
        ns_owner.as_deref(),
    )?;
    if matches!(action, GovernedAction::Store)
        && matches!(decision, GovernanceDecision::Allow)
        && let Some(payload) = payload
        && let Some(required) = policy.core.required_scope
        && let Some(refusal) = crate::governance::required_scope_refusal(
            required,
            payload,
            action,
            policy.core.write.clone(),
            agent_id,
            namespace,
        )
    {
        decision = GovernanceDecision::Deny(refusal);
    }
    Ok(decision)
}

/// #4419 — re-run the REQUESTER's current write admission for the action an
/// approved pending replays (CWE-613 / CWE-863: a standard tightened after
/// the request was queued — `write: any` to `write: owner` — must refuse the
/// replay exactly as it refuses a fresh request by the same principal).
/// Decides only, never queues a second pending; a Deny or a still-Pending
/// verdict is a typed [`GovernanceRefusal`] and an audit row. The vertical
/// promote store arm re-checks the DESTINATION namespace; the promote arm's
/// own destination check (#3202) still runs in the arm.
pub(super) fn readmit_pending_requester(conn: &Connection, pa: &PendingAction) -> Result<()> {
    let owner_of = |memory_id: Option<&str>| -> Result<Option<String>> {
        let Some(id) = memory_id else {
            return Ok(None);
        };
        Ok(get_any(conn, id)?.and_then(|m| {
            m.metadata
                .get(crate::META_KEY_AGENT_ID)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        }))
    };
    let payload_namespace = || {
        pa.payload
            .get("namespace")
            .and_then(serde_json::Value::as_str)
            .map_or_else(|| pa.namespace.clone(), str::to_string)
    };
    let (action, namespace, memory_owner, payload) = match pa.action_type.as_str() {
        "store" => {
            let is_vertical_promote = pa.payload.get(field_names::MODE).and_then(|v| v.as_str())
                == Some(field_names::MODE_VERTICAL);
            if is_vertical_promote {
                let to_ns = pa
                    .payload
                    .get(field_names::TO_NAMESPACE)
                    .and_then(|v| v.as_str())
                    .map_or_else(|| pa.namespace.clone(), str::to_string);
                (GovernedAction::Store, to_ns, None, None)
            } else {
                (
                    GovernedAction::Store,
                    payload_namespace(),
                    None,
                    Some(&pa.payload),
                )
            }
        }
        "delete" => (
            GovernedAction::Delete,
            pa.namespace.clone(),
            owner_of(pa.memory_id.as_deref())?,
            None,
        ),
        "promote" => (
            GovernedAction::Promote,
            pa.namespace.clone(),
            owner_of(pa.memory_id.as_deref())?,
            None,
        ),
        "reflect" => (GovernedAction::Reflect, payload_namespace(), None, None),
        // An unknown action_type is refused by the arm match below.
        _ => return Ok(()),
    };
    let decision = decide_admission_without_queue(
        conn,
        action,
        &namespace,
        &pa.requested_by,
        memory_owner.as_deref(),
        payload,
    )?;
    let reason = match decision {
        GovernanceDecision::Allow => return Ok(()),
        GovernanceDecision::Deny(refusal) => {
            emit_pending_action_event(
                conn,
                pa,
                "pending_action.refused_stale_admission_deny",
                None,
            );
            refusal.reason
        }
        GovernanceDecision::Pending(_) => {
            emit_pending_action_event(
                conn,
                pa,
                "pending_action.refused_stale_admission_pending",
                None,
            );
            "the write now requires an approval that was not granted".to_string()
        }
    };
    tracing::warn!(
        target: crate::governance::GOVERNANCE_GATE_TRACE_TARGET,
        pending_id = %pa.id,
        requested_by = %pa.requested_by,
        namespace = %namespace,
        action = ?action,
        "approved pending replay refused: the requester is no longer admitted (#4419)"
    );
    Err(anyhow::Error::new(GovernanceRefusal {
        reason: format!(
            "requester '{}' is no longer admitted to {} in '{namespace}': {reason}",
            pa.requested_by,
            action.as_str()
        ),
    }))
}

/// #3202 Fable HIGH (2) — evaluate destination `write` at execute time
/// WITHOUT queueing. `enforce_governance` would insert a second pending
/// on `Approve`; this consults the same policy/level/ungoverned path and
/// treats Deny or still-Pending as a refuse.
pub(super) fn refuse_unapproved_destination_store(
    conn: &Connection,
    pa: &PendingAction,
    to_ns: &str,
) -> Result<()> {
    let decision = decide_admission_without_queue(
        conn,
        GovernedAction::Store,
        to_ns,
        &pa.requested_by,
        None,
        None,
    )?;
    match decision {
        GovernanceDecision::Allow => Ok(()),
        GovernanceDecision::Deny(refusal) => {
            emit_pending_action_event(conn, pa, "pending_action.refused_destination_deny", None);
            Err(anyhow::Error::new(StorageError::InvalidArgument {
                reason: format!("destination write into {to_ns} denied: {}", refusal.reason),
            }))
        }
        GovernanceDecision::Pending(_) => {
            emit_pending_action_event(conn, pa, "pending_action.refused_destination_pending", None);
            Err(anyhow::Error::new(StorageError::InvalidArgument {
                reason: format!(
                    "destination write into {to_ns} requires approval that was not granted"
                ),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Tier;

    fn test_db() -> Connection {
        open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn make_memory(title: &str, ns: &str, tier: Tier, priority: i32) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("Content for {title}"),
            priority,
            confidence: 1.0,
            source: "test".to_string(),
            created_at: now.clone(),
            updated_at: now,
            ..Memory::default()
        }
    }

    /// #4419 — an approved pending replays the requester's write WITHOUT
    /// re-checking the requester's CURRENT admission: a standard tightened
    /// after the request was queued (`write: any` -> `write: owner`) still
    /// lands the write on approve, although a fresh request by the same
    /// principal is refused. The replay must re-run the requester's admission
    /// (deciding only, never queueing a second pending) and refuse.
    #[test]
    fn approved_replay_rechecks_the_requesters_current_admission_4419() {
        use crate::config::{
            PermissionsMode, lock_permissions_mode_for_test,
            override_active_permissions_mode_for_test,
        };
        use crate::models::GovernedAction;
        let _gate = lock_permissions_mode_for_test();
        override_active_permissions_mode_for_test(PermissionsMode::Enforce);

        let conn = test_db();
        let ns = "gov4419/replay";
        let mut standard = make_memory("std-4419", "_standards-4419", Tier::Long, 9);
        standard.metadata =
            serde_json::json!({"agent_id": "ai:owner", "governance": {"write": "any"}});
        let sid = insert(&conn, &standard).unwrap();
        set_namespace_standard(&conn, ns, &sid, None).unwrap();

        let queue_approved = |title: &str| {
            let mut m = make_memory(title, ns, Tier::Mid, 5);
            m.metadata = serde_json::json!({"agent_id": "ai:req"});
            let payload = serde_json::to_value(&m).unwrap();
            let pid =
                queue_pending_action(&conn, GovernedAction::Store, ns, None, "ai:req", &payload)
                    .unwrap();
            assert!(decide_pending_action(&conn, &pid, true, "ai:owner").unwrap());
            pid
        };
        let stale = queue_approved("stale-replay-4419");
        let fresh = queue_approved("fresh-replay-4419");

        // Control: still admitted while the standard says `write: any`.
        execute_pending_action(&conn, &fresh).expect("admitted replay lands");
        let count = |title: &str| -> i64 {
            conn.query_row(
                "SELECT COUNT(*) FROM memories WHERE namespace = ?1 AND title = ?2",
                params![ns, title],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(count("fresh-replay-4419"), 1);

        // Tighten the standard AFTER the request was queued and approved.
        let tightened =
            serde_json::json!({"agent_id": "ai:owner", "governance": {"write": "owner"}});
        update(
            &conn,
            &sid,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&tightened),
        )
        .unwrap();
        let err = execute_pending_action(&conn, &stale)
            .expect_err("a requester no longer admitted must be refused at replay");
        assert!(
            format!("{err:#}").contains("no longer admitted"),
            "got: {err:#}"
        );
        assert_eq!(
            count("stale-replay-4419"),
            0,
            "the stale replay must not land"
        );
        // Deciding only: the refused replay queued no second pending.
        let pending: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_actions WHERE status = 'pending'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pending, 0, "a refused replay never queues a second pending");

        override_active_permissions_mode_for_test(PermissionsMode::Advisory);
    }

    /// #4419 — an approved `reflect` replay reads its sources under the
    /// read-visibility posture exactly like the direct funnel: under the
    /// enforced multi-tenant opt-in (`AI_MEMORY_AGENT_ID` set) the REQUESTER
    /// is the visibility caller, so a private source owned by another
    /// principal is refused at execute (no reflection lands) while the
    /// requester's own source replays. The approver's process identity never
    /// widens the read.
    #[test]
    fn approved_reflect_replay_reads_sources_as_the_requester_4419() {
        use crate::models::GovernedAction;
        let _envg = crate::identity::agent_id_env_test_lock();
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:approver-process") };

        let conn = test_db();
        let ns = "gov4419/reflect";
        let seed = |title: &str, owner: &str| -> String {
            let mut m = make_memory(title, ns, Tier::Mid, 5);
            m.metadata = serde_json::json!({"agent_id": owner, "scope": "private"});
            insert(&conn, &m).unwrap()
        };
        let foreign = seed("foreign-src-4419", "ai:other");
        let own = seed("own-src-4419", "ai:req");

        let queue_approved = |title: &str, source_id: &str| -> String {
            let payload = serde_json::json!({
                field_names::SOURCE_IDS: [source_id],
                "title": title,
                "content": "synthesis over one source",
                "namespace": ns,
                "agent_id": "ai:req",
                "proposed_depth": 1,
            });
            let pid =
                queue_pending_action(&conn, GovernedAction::Reflect, ns, None, "ai:req", &payload)
                    .unwrap();
            assert!(decide_pending_action(&conn, &pid, true, "ai:approver-process").unwrap());
            pid
        };
        let over_foreign = queue_approved("reflect-foreign-4419", &foreign);
        let over_own = queue_approved("reflect-own-4419", &own);

        let err = execute_pending_action(&conn, &over_foreign)
            .expect_err("a source the requester cannot read must refuse the replay");
        assert!(
            format!("{err:#}").contains("reflect execute failed"),
            "got: {err:#}"
        );
        let count = |title: &str| -> i64 {
            conn.query_row(
                "SELECT COUNT(*) FROM memories WHERE namespace = ?1 AND title = ?2",
                params![ns, title],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(count("reflect-foreign-4419"), 0, "no reflection may land");

        let landed = execute_pending_action(&conn, &over_own)
            .expect("the requester's own source replays")
            .expect("reflect returns the new id");
        assert_eq!(count("reflect-own-4419"), 1);
        assert_eq!(
            get(&conn, &landed)
                .unwrap()
                .expect("reflection row")
                .metadata["agent_id"],
            "ai:req"
        );

        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
    }
}
