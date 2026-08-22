// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — `memory_action_create` + `memory_action_get`
//! MCP stdio tools. Thin wrappers over the `crate::actions` sqlite
//! free-functions that expose the coordination-action substrate to MCP
//! callers. Mirrors the `crate::observations` /
//! `mcp::tools::recall_observations` split: the handlers hold a bare
//! `rusqlite::Connection` (not a SAL store), so they call the
//! free-functions directly.

use crate::mcp::param_names;
use serde_json::{Value, json};

/// #2997 — piggyback the lease-expiry sweep on the MCP coordination read /
/// lease surfaces so an MCP-stdio-only deployment (the default topology — no
/// `bootstrap_serve` background `lease_sweep`, and no HTTP route to create an
/// action or acquire a lease) still reclaims a dead worker's expired lease AND
/// requeues its stranded `claimed` action back to `pending`. Without this, an
/// action a dead worker claimed is stranded forever (`action_frontier` returns
/// `[]` while `action_get` shows `state:claimed, claimed_by:ai:dead-worker`),
/// reconciled by no surface.
///
/// Best-effort: a sweep failure is logged, never surfaced to the caller — the
/// caller's own op (frontier / next / lease acquire / lease get) still runs.
fn sweep_expired_leases_best_effort(conn: &rusqlite::Connection) {
    let now = chrono::Utc::now().timestamp();
    if let Err(e) = crate::actions::sweep_expired_leases_audited(conn, now) {
        tracing::warn!(
            target: "coordination.lease_sweep",
            "mcp piggybacked lease sweep failed (best-effort): {e}"
        );
    }
}

/// MCP handler for `memory_action_create`. Builds an [`crate::models::Action`]
/// from the request params and inserts it, returning the created action
/// as JSON.
///
/// # Errors
/// Returns the stringified `rusqlite` error on insert failure.
pub fn handle_action_create(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let namespace = params
        .get(param_names::NAMESPACE)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let kind = params
        .get(param_names::KIND)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut title = params
        .get(param_names::TITLE)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut payload = params
        .get(param_names::PAYLOAD)
        .cloned()
        .unwrap_or(Value::Null);
    let priority = params
        .get(param_names::PRIORITY)
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let agent_id = params
        .get(param_names::AGENT_ID)
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut metadata = params
        .get(param_names::METADATA)
        .cloned()
        .unwrap_or(Value::Null);

    // #2998 — validate the coordination create inputs (namespace + text/payload
    // length caps + a validated, ALWAYS-attributed actor) before building the
    // row. An omitted `agent_id` resolves to the durable ambient id so the
    // write is always quota-charged (closing the omit-agent_id uncharged +
    // unbounded gap); a caller-supplied `agent_id` is shape-validated so
    // whitespace / control chars cannot be log-injected into the audit trail.
    crate::coordination_guard::require_namespace(&namespace)?;
    crate::coordination_guard::require_text(
        param_names::TITLE,
        &title,
        crate::coordination_guard::MAX_TEXT_FIELD_BYTES,
    )?;
    crate::coordination_guard::require_text(
        param_names::KIND,
        &kind,
        crate::coordination_guard::MAX_KIND_BYTES,
    )?;
    crate::coordination_guard::require_payload_size(param_names::PAYLOAD, &payload)?;
    let actor = crate::coordination_guard::resolve_actor(agent_id.as_deref())?;

    // #2994 — the coordination write plane bypasses the memory-lane storage
    // funnel, so screen the caller-origin credential vectors here: refuse under
    // `SECRET_SCREEN_MODE=refuse`, mask under `redact`, byte-identical under
    // `off`. Screens the same fields the #2994 evidence stored verbatim
    // (title / payload) plus metadata; `kind` is a short discriminator and is
    // left unscreened so a redact never mangles it.
    crate::secret_screen::screen_text_field_for_caller(&mut title).map_err(|r| r.to_string())?;
    crate::secret_screen::screen_json_field_for_caller(&mut payload).map_err(|r| r.to_string())?;
    if !metadata.is_null() {
        crate::secret_screen::screen_json_field_for_caller(&mut metadata)
            .map_err(|r| r.to_string())?;
    }

    let now = chrono::Utc::now().timestamp();
    let action = crate::models::Action {
        id: uuid::Uuid::new_v4().to_string(),
        namespace,
        kind,
        state: crate::models::ActionState::Pending,
        title,
        payload,
        priority,
        agent_id: Some(actor),
        claimed_by: None,
        vector_clock: json!({}),
        metadata,
        created_at: now,
        updated_at: now,
    };

    // #1807 — bound the coordination create-path: validate supplied metadata
    // size (same limit as memory writes) and charge the owning agent's
    // per-namespace storage quota (storage_only — a coordination object is
    // storage, not an authored memory; mirrors the federation-receive signal
    // precedent). An unowned action (empty `agent_id`) is not charged
    // (operator-as-actor, same exemption as the memory write path). Absent
    // metadata defaults to JSON null, which is not a validatable object, so
    // validation only runs when metadata was actually supplied. T-exempt
    // precedent-copy; 5-agent review (memory `4d3ea1c5`) deemed #1807 legitimate.
    if !action.metadata.is_null() {
        crate::validate::validate_metadata(&action.metadata).map_err(|e| e.to_string())?;
    }
    let quota_actor = action.agent_id.as_deref().unwrap_or_default();
    if !quota_actor.is_empty() {
        let bytes = crate::quotas::coordination_payload_bytes(
            &[&action.title, &action.kind],
            &[&action.payload, &action.metadata],
        );
        crate::quotas::check_and_record_storage_only(conn, quota_actor, &action.namespace, bytes)
            .map_err(|e| e.to_string())?;
    }

    let id = crate::actions::create(conn, &action).map_err(|e| e.to_string())?;

    // #1722 — coordination observability: best-effort audit row for the
    // create, attributed to the action's owning agent (`agent_id`, "" when
    // unowned). Identity = action id / kind / "create".
    let actor = action.agent_id.as_deref().unwrap_or_default();
    crate::coordination_audit::emit(
        conn,
        crate::coordination_audit::ACTION_CREATE,
        actor,
        &[&id, &action.kind, "create"],
    );

    Ok(json!({
        (param_names::ID): id,
        "action": serde_json::to_value(&action).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_action_get`. Fetches an action by id. The
/// `action` field is `null` when no row matches, mirroring how
/// `memory_get` reports an absent row.
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_action_get(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let id = params
        .get(param_names::ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let found = crate::actions::get(conn, id).map_err(|e| e.to_string())?;
    let action = match found {
        Some(a) => serde_json::to_value(&a).map_err(|e| e.to_string())?,
        None => Value::Null,
    };
    Ok(json!({ "action": action }))
}

/// MCP handler for `memory_action_transition`. State-guarded transition
/// of one action via [`crate::actions::transition`]. Returns the updated
/// action; errors on a missing row, an invalid target state name, or an
/// illegal transition.
///
/// # Errors
/// - `action not found: <id>` when no row matches.
/// - `illegal action transition: <from> -> <to>` on a guard refusal.
/// - `invalid state` when `to` is not a known [`crate::models::ActionState`].
/// - The stringified `rusqlite` error on query failure.
pub fn handle_action_transition(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let id = params
        .get(param_names::ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let to_name = params
        .get(param_names::TO)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let to =
        crate::models::ActionState::from_str(to_name).ok_or_else(|| "invalid state".to_string())?;
    let claimed_by = params
        .get(param_names::CLAIMED_BY)
        .and_then(Value::as_str)
        .map(str::to_string);

    let now = chrono::Utc::now().timestamp();

    // #3009 — the LOCAL transition lane took `claimed_by` verbatim, consulted no
    // lease and checked no identity, so two agents could each believe they own
    // an action and a `claimed_by` with embedded newlines flowed into the
    // coordination_audit identity fields. Mirror the federation lane's
    // actor→lease binding on the local lane: (1) shape-validate a caller-
    // supplied `claimed_by`; (2) BIND it to the live lease holder — a
    // transition whose `claimed_by` is not the current (non-expired) lease
    // holder is refused. Actions coordinated without a lease are unbound
    // (leases are the ownership primitive), so this never blocks the
    // lease-free flow.
    if let Some(cb) = claimed_by.as_deref() {
        crate::validate::validate_agent_id(cb).map_err(|e| e.to_string())?;
        if let Some(lease) = crate::actions::lease_get(conn, id).map_err(|e| e.to_string())? {
            if lease.expires_at > now && lease.holder != cb {
                return Err(format!(
                    "claimed_by '{cb}' is not the live lease holder '{}' on action {id}",
                    lease.holder
                ));
            }
        }
    }

    match crate::actions::transition(conn, id, to, claimed_by.as_deref(), now)
        .map_err(|e| e.to_string())?
    {
        crate::actions::TransitionOutcome::NotFound => Err(format!("action not found: {id}")),
        crate::actions::TransitionOutcome::Illegal { from, to } => {
            Err(crate::actions::illegal_transition_detail(from, to))
        }
        crate::actions::TransitionOutcome::Updated(a) => {
            // #1722 — coordination observability: best-effort audit row for
            // the transition, attributed to the claiming agent (`claimed_by`,
            // "" when none was supplied). Identity = action id / target state
            // / claimer.
            let actor = claimed_by.as_deref().unwrap_or_default();
            crate::coordination_audit::emit(
                conn,
                crate::coordination_audit::ACTION_TRANSITION,
                actor,
                &[id, to_name, actor],
            );
            Ok(json!({
                "action": serde_json::to_value(&a).map_err(|e| e.to_string())?,
            }))
        }
    }
}

/// MCP handler for `memory_action_list`. Lists actions filtered by
/// optional `namespace` / `state`, newest-first, capped at `limit`
/// (default 50).
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_action_list(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let namespace = params
        .get(param_names::NAMESPACE)
        .and_then(Value::as_str)
        .map(str::to_string);
    let state = match params.get(param_names::STATE).and_then(Value::as_str) {
        Some(s) => Some(
            crate::models::ActionState::from_str(s).ok_or_else(|| "invalid state".to_string())?,
        ),
        None => None,
    };
    let limit = params
        .get(param_names::LIMIT)
        .and_then(Value::as_i64)
        .unwrap_or(50);
    let limit = usize::try_from(limit).unwrap_or(50);

    let actions = crate::actions::list(conn, namespace.as_deref(), state, limit)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "actions": serde_json::to_value(&actions).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_action_add_edge`. Inserts a typed DAG edge
/// between two actions via [`crate::actions::add_edge`].
///
/// # Errors
/// - `invalid edge_type` when `edge_type` is not a known
///   [`crate::models::EdgeType`].
/// - The stringified `rusqlite` error on insert failure.
pub fn handle_action_add_edge(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let from_action = params
        .get(param_names::FROM_ACTION)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let to_action = params
        .get(param_names::TO_ACTION)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let edge_type_name = params
        .get(param_names::EDGE_TYPE)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let edge_type = crate::models::EdgeType::from_str(edge_type_name)
        .ok_or_else(|| "invalid edge_type".to_string())?;

    let now = chrono::Utc::now().timestamp();
    // #3008 — refuse a self-edge / ordering-cycle edge (both permanently wedge
    // the frontier) instead of silently accepting it.
    match crate::actions::add_edge(conn, from_action, to_action, edge_type, now)
        .map_err(|e| e.to_string())?
    {
        crate::actions::AddEdgeOutcome::SelfEdge => {
            return Err(format!(
                "refused self-edge {from_action} --{edge_type_name}--> {from_action}: an action \
                 cannot depend on itself"
            ));
        }
        crate::actions::AddEdgeOutcome::WouldCycle => {
            return Err(format!(
                "refused edge {from_action} --{edge_type_name}--> {to_action}: it would close a \
                 cycle in the action ordering DAG (mutual deadlock)"
            ));
        }
        crate::actions::AddEdgeOutcome::Added => {}
    }

    // #1722 — coordination observability: best-effort audit row for the edge
    // insert. The add-edge handler carries NO actor/principal field, so the
    // row records the event + payload hash with an empty actor; identity =
    // from_action / to_action / edge_type so the specific edge is committed.
    crate::coordination_audit::emit(
        conn,
        crate::coordination_audit::ACTION_ADD_EDGE,
        "",
        &[from_action, to_action, edge_type_name],
    );

    Ok(json!({ "ok": true }))
}

/// MCP handler for `memory_action_edges`. Lists every edge touching the
/// given action via [`crate::actions::edges_for`].
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_action_edges(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let action_id = params
        .get(param_names::ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let edges = crate::actions::edges_for(conn, action_id).map_err(|e| e.to_string())?;
    Ok(json!({
        "edges": serde_json::to_value(&edges).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_action_frontier`. Returns the ranked UNBLOCKED
/// frontier (#1709 §11.4) for a namespace: pending actions whose
/// `requires` / `gated_by` prerequisites are all `done` and that no active
/// `blocks` edge holds, ordered `priority DESC, created_at ASC`, capped at
/// `limit` (default 20).
///
/// # Recovery of stranded work (#2419)
///
/// This surface is PENDING-only by design and #2419 did NOT change it. What
/// changed is that work can no longer get stuck outside it: when a holder's
/// lease expires, [`crate::actions::sweep_expired_leases`] returns a still-
/// `claimed` action to `pending` over the already-legal state-machine edge, so
/// the node re-appears here by itself. An `in_progress` action is deliberately
/// NOT auto-requeued (no legal `in_progress -> pending` edge — re-offering work
/// a live worker may still be executing would risk double execution); it stays
/// reachable via `memory_action_list { state: "in_progress" }`.
///
/// # Errors
/// Returns `"namespace is required"` when the schema-required `namespace`
/// is missing/blank (#3171), or the stringified `rusqlite` error on query
/// failure.
pub fn handle_action_frontier(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    // #2997 — reclaim expired leases + requeue stranded claimed actions before
    // computing the frontier, so a dead worker's action re-appears here.
    sweep_expired_leases_best_effort(conn);
    // #3171 — `namespace` is schema-REQUIRED. Pre-fix it was read with
    // `unwrap_or_default()`, so a malformed call queried the `""` namespace
    // and got a plausible EMPTY-SUCCESS frontier instead of an error — a
    // worker fleet would read "no work" and idle. Refuse instead (ERRORS-08).
    let namespace = crate::mcp::param_guard::require_str(params, param_names::NAMESPACE)?;
    let limit = params
        .get(param_names::LIMIT)
        .and_then(Value::as_i64)
        .unwrap_or(20);
    let limit = usize::try_from(limit).unwrap_or(20);
    let actions = crate::actions::frontier(conn, namespace, limit).map_err(|e| e.to_string())?;
    Ok(json!({
        "actions": serde_json::to_value(&actions).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_action_next`. Returns the single highest-ranked
/// UNBLOCKED action a caller should pick up next (#1709 §11.4) — the top of
/// the frontier query. When `agent_id` is supplied, the candidate set is
/// narrowed to actions with no owner OR owned by the caller. The `action`
/// field is `null` when the frontier is empty.
///
/// # Errors
/// Returns `"namespace is required"` when the schema-required `namespace`
/// is missing/blank (#3171), or the stringified `rusqlite` error on query
/// failure.
pub fn handle_action_next(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    // #2997 — sweep before selecting the next action (see handle_action_frontier).
    sweep_expired_leases_best_effort(conn);
    // #3171 — see `handle_action_frontier`: `namespace` is schema-REQUIRED and
    // must not degrade into an empty-namespace query that answers `action:
    // null` (indistinguishable from "the frontier is empty").
    let namespace = crate::mcp::param_guard::require_str(params, param_names::NAMESPACE)?;
    let agent_id = params
        .get(param_names::AGENT_ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let found =
        crate::actions::next_action(conn, namespace, agent_id).map_err(|e| e.to_string())?;
    let action = match found {
        Some(a) => serde_json::to_value(&a).map_err(|e| e.to_string())?,
        None => Value::Null,
    };
    Ok(json!({ "action": action }))
}

/// MCP handler for `memory_lease_acquire`. Acquires a single-holder lease
/// on an action via [`crate::actions::lease_acquire`]. The `expires_at`
/// timestamp is computed internally from `ttl_secs` (default 60) so callers
/// never marshal wall-clock time.
///
/// This is the SQLITE-LOCAL MCP-stdio lease surface: it holds a bare
/// `rusqlite::Connection` and calls the `crate::actions::*` free-function
/// directly (MCP stdio is structurally sqlite-only, #1675). It is the ONLY
/// production caller of the lease acquire operation at v1.0.0 — a
/// postgres-backed daemon has no lease-acquire surface (leases are node-local
/// and do not federate). See the #2513 reachability note on
/// [`crate::store::MemoryStore::lease_acquire`]: a future pg-reachable lease
/// wire surface MUST dispatch through the SAL trait (`app.store.lease_acquire`),
/// not this handler.
///
/// # Errors
/// - `lease conflict: <id> held by another holder` when a non-expired lease
///   is held by a different holder.
/// - The stringified `rusqlite` error on query/insert failure.
pub fn handle_lease_acquire(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    // #2997 — reclaim any expired leases (and requeue their stranded actions)
    // before this acquire, so a dead holder's lease + claim is reconciled.
    sweep_expired_leases_best_effort(conn);
    // #3171 — `action_id` and `holder` are BOTH schema-REQUIRED, and both were
    // read with `unwrap_or_default()`. An empty `holder` is not merely a
    // fail-open empty success: `lease_acquire`'s upsert guard is
    // `WHERE leases.expires_at <= ? OR leases.holder = ?`, so TWO DISTINCT
    // agents that each omit `holder` both resolve to `""`, the second is
    // treated as a same-holder RE-acquire, and both believe they hold the
    // exclusive lease — a DOUBLE GRANT of a single-holder lease, which
    // `crate::actions::lease_acquire`'s own contract calls a correctness /
    // safety violation ("the worst case is a spurious Conflict a caller
    // retries, never two winners"). Refuse instead.
    let action_id = crate::mcp::param_guard::require_str(params, param_names::ACTION_ID)?;
    let holder = crate::mcp::param_guard::require_str(params, param_names::HOLDER)?;
    let ttl_secs = params
        .get(param_names::TTL_SECS)
        .and_then(Value::as_i64)
        .unwrap_or(60);

    // #1806 — clamp the caller-supplied TTL (reject <=0 / >1yr) + checked add,
    // mirroring the memory-write path (validate::validate_ttl_secs). Without it
    // an unbounded ttl_secs mints a never-reclaimed lease (coordination
    // starvation) and `now + ttl_secs` overflow-panics on i64::MAX.
    crate::validate::validate_ttl_secs(Some(ttl_secs)).map_err(|e| e.to_string())?;
    // Minor (A6-13) — acquiring a lease on a MISSING action would surface the
    // raw `leases.action_id` FK-constraint violation; return the typed
    // not-found instead (mirrors `handle_action_transition`'s not-found shape).
    if crate::actions::get(conn, action_id)
        .map_err(|e| e.to_string())?
        .is_none()
    {
        return Err(format!("action not found: {action_id}"));
    }
    let now = chrono::Utc::now().timestamp();
    let expires_at = now
        .checked_add(ttl_secs)
        .ok_or_else(|| crate::coordination_guard::TTL_SECS_OVERFLOW.to_string())?;
    match crate::actions::lease_acquire(conn, action_id, holder, now, expires_at)
        .map_err(|e| e.to_string())?
    {
        crate::actions::LeaseAcquire::Conflict => Err(format!(
            "lease conflict: {action_id} held by another holder"
        )),
        crate::actions::LeaseAcquire::Acquired(l) => {
            // #1722 — coordination observability: best-effort audit row for the
            // acquire, attributed to the lease `holder`. Identity = action id /
            // holder.
            crate::coordination_audit::emit(
                conn,
                crate::coordination_audit::LEASE_ACQUIRE,
                holder,
                &[action_id, holder],
            );
            Ok(json!({
                "lease": serde_json::to_value(&l).map_err(|e| e.to_string())?,
            }))
        }
    }
}

/// MCP handler for `memory_lease_renew`. Heartbeat-renews an owned lease via
/// [`crate::actions::lease_renew`]. `expires_at` is computed internally from
/// `ttl_secs` (default 60).
///
/// # Errors
/// - `no lease held by <holder> on <action_id>` when no lease matches.
/// - The stringified `rusqlite` error on query/update failure.
pub fn handle_lease_renew(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    // #3171 — see `handle_lease_acquire`: both are schema-REQUIRED. A blank
    // `holder` renewed whatever an empty-holder acquire had minted.
    let action_id = crate::mcp::param_guard::require_str(params, param_names::ACTION_ID)?;
    let holder = crate::mcp::param_guard::require_str(params, param_names::HOLDER)?;
    let ttl_secs = params
        .get(param_names::TTL_SECS)
        .and_then(Value::as_i64)
        .unwrap_or(60);

    // #1806 — clamp + checked add (see lease_acquire).
    crate::validate::validate_ttl_secs(Some(ttl_secs)).map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().timestamp();
    let expires_at = now
        .checked_add(ttl_secs)
        .ok_or_else(|| crate::coordination_guard::TTL_SECS_OVERFLOW.to_string())?;
    match crate::actions::lease_renew(conn, action_id, holder, now, expires_at)
        .map_err(|e| e.to_string())?
    {
        None => Err(format!("no lease held by {holder} on {action_id}")),
        Some(l) => {
            // #1722 — coordination observability: best-effort audit row for the
            // renew, attributed to the lease `holder`. Identity = action id /
            // holder.
            crate::coordination_audit::emit(
                conn,
                crate::coordination_audit::LEASE_RENEW,
                holder,
                &[action_id, holder],
            );
            Ok(json!({
                "lease": serde_json::to_value(&l).map_err(|e| e.to_string())?,
            }))
        }
    }
}

/// MCP handler for `memory_lease_release`. Releases an owned lease via
/// [`crate::actions::lease_release`]. Returns `released: <bool>` — `false`
/// when no matching lease existed.
///
/// # Errors
/// Returns the stringified `rusqlite` error on delete failure.
pub fn handle_lease_release(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    // #3171 — both are schema-REQUIRED. Pre-fix a malformed call deleted on
    // `("", "")` and answered `released: false`, indistinguishable from "you do
    // not hold that lease" — a worker would conclude it had already released.
    let action_id = crate::mcp::param_guard::require_str(params, param_names::ACTION_ID)?;
    let holder = crate::mcp::param_guard::require_str(params, param_names::HOLDER)?;
    let released =
        crate::actions::lease_release(conn, action_id, holder).map_err(|e| e.to_string())?;

    // #1722 — coordination observability: best-effort audit row for the
    // release, attributed to the lease `holder`. Only emit when a row was
    // actually removed (a no-op release by a non-owner writes nothing).
    // Identity = action id / holder.
    if released {
        crate::coordination_audit::emit(
            conn,
            crate::coordination_audit::LEASE_RELEASE,
            holder,
            &[action_id, holder],
        );
    }

    Ok(json!({ "released": released }))
}

/// MCP handler for `memory_lease_get`. Reads the lease on an action via
/// [`crate::actions::lease_get`]. The `lease` field is `null` when no lease
/// row exists, mirroring how `memory_action_get` reports an absent row.
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_lease_get(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    // #3171 — schema-REQUIRED: `lease: null` for a blank id reads as "there is
    // no lease on that action", which is a different claim from "you did not
    // name an action".
    let action_id = crate::mcp::param_guard::require_str(params, param_names::ACTION_ID)?;
    let found = crate::actions::lease_get(conn, action_id).map_err(|e| e.to_string())?;
    let lease = match found {
        Some(l) => serde_json::to_value(&l).map_err(|e| e.to_string())?,
        None => Value::Null,
    };
    Ok(json!({ "lease": lease }))
}

// --- per-tool McpTool impls (v0.8.0 Pillar 1, #1709) ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_action_create`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionCreateRequest {
    pub namespace: String,

    pub kind: String,

    pub title: String,

    #[serde(default)]
    pub payload: Value,

    #[serde(default)]
    pub priority: i64,

    #[serde(default)]
    pub agent_id: Option<String>,

    #[serde(default)]
    pub metadata: Value,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_action_get`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionGetRequest {
    pub id: String,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_action_transition`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionTransitionRequest {
    pub id: String,

    /// Target state name (`pending` / `claimed` / `in_progress` /
    /// `done` / `failed` / `abandoned`).
    pub to: String,

    #[serde(default)]
    pub claimed_by: Option<String>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_action_list`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionListRequest {
    #[serde(default)]
    pub namespace: Option<String>,

    /// Optional state-name filter.
    #[serde(default)]
    pub state: Option<String>,

    #[serde(default)]
    pub limit: Option<i64>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_action_add_edge`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionAddEdgeRequest {
    pub from_action: String,

    pub to_action: String,

    /// Edge kind (`requires` / `unlocks` / `blocks` / `gated_by` /
    /// `sibling`).
    pub edge_type: String,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_action_edges`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionEdgesRequest {
    pub id: String,
}

/// v0.8.0 Pillar 1 (#1709 §11.4) — request body for `memory_action_frontier`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionFrontierRequest {
    pub namespace: String,

    /// Max rows to return (default 20).
    #[serde(default)]
    pub limit: Option<i64>,
}

/// v0.8.0 Pillar 1 (#1709 §11.4) — request body for `memory_action_next`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ActionNextRequest {
    pub namespace: String,

    /// When set, narrow the candidate set to actions with no owner OR owned
    /// by this agent.
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_lease_acquire`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct LeaseAcquireRequest {
    pub action_id: String,

    pub holder: String,

    /// Lease lifetime in seconds (default 60). `expires_at` is computed
    /// internally as `now + ttl_secs`.
    #[serde(default)]
    pub ttl_secs: Option<i64>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_lease_renew`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct LeaseRenewRequest {
    pub action_id: String,

    pub holder: String,

    /// New lease lifetime in seconds (default 60). `expires_at` is computed
    /// internally as `now + ttl_secs`.
    #[serde(default)]
    pub ttl_secs: Option<i64>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_lease_release`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct LeaseReleaseRequest {
    pub action_id: String,

    pub holder: String,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_lease_get`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct LeaseGetRequest {
    pub action_id: String,
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_action_create`.
#[allow(dead_code)]
pub struct ActionCreateTool;

impl McpTool for ActionCreateTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_CREATE
    }
    fn description() -> &'static str {
        "Create a coordination action (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): insert a pending coordination action into the action DAG."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionCreateRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_action_get`.
#[allow(dead_code)]
pub struct ActionGetTool;

impl McpTool for ActionGetTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_GET
    }
    fn description() -> &'static str {
        "Fetch a coordination action by id (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): return one coordination action by id, or null when absent."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionGetRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_action_transition`.
#[allow(dead_code)]
pub struct ActionTransitionTool;

impl McpTool for ActionTransitionTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_TRANSITION
    }
    fn description() -> &'static str {
        "State-guarded transition of a coordination action (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): move an action to a new state if the transition is legal."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionTransitionRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_action_list`.
#[allow(dead_code)]
pub struct ActionListTool;

impl McpTool for ActionListTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_LIST
    }
    fn description() -> &'static str {
        "List coordination actions by namespace/state (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): query the action DAG, filtered by namespace/state, newest-first."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionListRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_action_add_edge`.
#[allow(dead_code)]
pub struct ActionAddEdgeTool;

impl McpTool for ActionAddEdgeTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_ADD_EDGE
    }
    fn description() -> &'static str {
        "Add a typed DAG edge between two coordination actions (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): insert a typed dependency edge into the action DAG."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionAddEdgeRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_action_edges`.
#[allow(dead_code)]
pub struct ActionEdgesTool;

impl McpTool for ActionEdgesTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_EDGES
    }
    fn description() -> &'static str {
        "List DAG edges for a coordination action (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): return every typed edge touching an action."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionEdgesRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709 §11.4) — `McpTool` impl for `memory_action_frontier`.
#[allow(dead_code)]
pub struct ActionFrontierTool;

impl McpTool for ActionFrontierTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_FRONTIER
    }
    fn description() -> &'static str {
        "Rank the UNBLOCKED coordination-action frontier (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709 §11.4): the ranked frontier of pending actions whose prerequisites/gates are done and that no active blocker holds. \
         Recovery contract (#2419): the frontier lists PENDING actions only, so an action a worker claimed is deliberately absent while that worker holds it. \
         If the worker dies, its lease expires and the background lease sweep transitions the action `claimed` -> `pending` over the existing legal edge (clearing `claimed_by`) — \
         it then re-appears here on its own and no work is stranded. \
         An action already advanced to `in_progress` is NOT auto-requeued (there is no legal `in_progress` -> `pending` edge); use `memory_action_list` with state=`in_progress` to census those, \
         and `memory_action_transition` to resolve them explicitly."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionFrontierRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709 §11.4) — `McpTool` impl for `memory_action_next`.
#[allow(dead_code)]
pub struct ActionNextTool;

impl McpTool for ActionNextTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ACTION_NEXT
    }
    fn description() -> &'static str {
        "Return the top UNBLOCKED coordination action to do next (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709 §11.4): the single highest-ranked unblocked action; optionally narrowed to the caller's owned/unowned work."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ActionNextRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_lease_acquire`.
#[allow(dead_code)]
pub struct LeaseAcquireTool;

impl McpTool for LeaseAcquireTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_LEASE_ACQUIRE
    }
    fn description() -> &'static str {
        "Acquire a single-holder lease on a coordination action (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): take an exclusive, TTL-bounded lease on an action; conflicts if held. \
         The TTL is a liveness contract (#2419): when it lapses the background sweep reclaims the lease AND, if the action is still `claimed`, \
         returns it to `pending` so it re-appears on `memory_action_frontier` instead of being stranded. Heartbeat via `memory_lease_renew` to keep it."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<LeaseAcquireRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_lease_renew`.
#[allow(dead_code)]
pub struct LeaseRenewTool;

impl McpTool for LeaseRenewTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_LEASE_RENEW
    }
    fn description() -> &'static str {
        "Heartbeat-renew an owned lease on a coordination action (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): extend a lease's TTL; errors if no lease matches the supplied \
         `holder`. #3171: ownership is decided ENTIRELY by the self-asserted `holder` \
         string — this tool receives no caller identity, so `holder` is a coordination \
         token, not an authenticated principal; treat it as unguessable. \
         Renew before expiry (#2419): a lapsed lease is reclaimed by the background sweep, which also returns a still-`claimed` action to `pending` for another holder."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<LeaseRenewRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_lease_release`.
#[allow(dead_code)]
pub struct LeaseReleaseTool;

impl McpTool for LeaseReleaseTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_LEASE_RELEASE
    }
    fn description() -> &'static str {
        "Release an owned lease on a coordination action (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): release a lease; reports whether a row was removed. #3171: the \
         lease released is the one matching the self-asserted `holder` — this tool \
         receives no caller identity, so any caller that knows a holder string can \
         release that holder's lease."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<LeaseReleaseRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_lease_get`.
#[allow(dead_code)]
pub struct LeaseGetTool;

impl McpTool for LeaseGetTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_LEASE_GET
    }
    fn description() -> &'static str {
        "Read the lease on a coordination action (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): return the lease on an action, or null when none is held."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<LeaseGetRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_6_1709_tests {
    //! D1.6 (#987) parity tests for the Pillar-1 `memory_action_*` tools.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;

    #[test]
    fn action_create_tool_metadata() {
        assert_eq!(ActionCreateTool::name(), "memory_action_create");
        assert_eq!(ActionCreateTool::family(), "power");
        assert!(!ActionCreateTool::description().is_empty());
        assert!(!ActionCreateTool::docs().is_empty());
    }

    #[test]
    fn action_get_tool_metadata() {
        assert_eq!(ActionGetTool::name(), "memory_action_get");
        assert_eq!(ActionGetTool::family(), "power");
        assert!(!ActionGetTool::description().is_empty());
        assert!(!ActionGetTool::docs().is_empty());
    }

    #[test]
    fn action_transition_tool_metadata() {
        assert_eq!(ActionTransitionTool::name(), "memory_action_transition");
        assert_eq!(ActionTransitionTool::family(), "power");
        assert!(!ActionTransitionTool::description().is_empty());
        assert!(!ActionTransitionTool::docs().is_empty());
    }

    #[test]
    fn action_list_tool_metadata() {
        assert_eq!(ActionListTool::name(), "memory_action_list");
        assert_eq!(ActionListTool::family(), "power");
        assert!(!ActionListTool::description().is_empty());
        assert!(!ActionListTool::docs().is_empty());
    }

    #[test]
    fn action_add_edge_tool_metadata() {
        assert_eq!(ActionAddEdgeTool::name(), "memory_action_add_edge");
        assert_eq!(ActionAddEdgeTool::family(), "power");
        assert!(!ActionAddEdgeTool::description().is_empty());
        assert!(!ActionAddEdgeTool::docs().is_empty());
    }

    #[test]
    fn action_edges_tool_metadata() {
        assert_eq!(ActionEdgesTool::name(), "memory_action_edges");
        assert_eq!(ActionEdgesTool::family(), "power");
        assert!(!ActionEdgesTool::description().is_empty());
        assert!(!ActionEdgesTool::docs().is_empty());
    }

    #[test]
    fn action_frontier_tool_metadata() {
        assert_eq!(ActionFrontierTool::name(), "memory_action_frontier");
        assert_eq!(ActionFrontierTool::family(), "power");
        assert!(!ActionFrontierTool::description().is_empty());
        assert!(!ActionFrontierTool::docs().is_empty());
    }

    #[test]
    fn action_next_tool_metadata() {
        assert_eq!(ActionNextTool::name(), "memory_action_next");
        assert_eq!(ActionNextTool::family(), "power");
        assert!(!ActionNextTool::description().is_empty());
        assert!(!ActionNextTool::docs().is_empty());
    }

    #[test]
    fn lease_acquire_tool_metadata() {
        assert_eq!(LeaseAcquireTool::name(), "memory_lease_acquire");
        assert_eq!(LeaseAcquireTool::family(), "power");
        assert!(!LeaseAcquireTool::description().is_empty());
        assert!(!LeaseAcquireTool::docs().is_empty());
    }

    #[test]
    fn lease_renew_tool_metadata() {
        assert_eq!(LeaseRenewTool::name(), "memory_lease_renew");
        assert_eq!(LeaseRenewTool::family(), "power");
        assert!(!LeaseRenewTool::description().is_empty());
        assert!(!LeaseRenewTool::docs().is_empty());
    }

    #[test]
    fn lease_release_tool_metadata() {
        assert_eq!(LeaseReleaseTool::name(), "memory_lease_release");
        assert_eq!(LeaseReleaseTool::family(), "power");
        assert!(!LeaseReleaseTool::description().is_empty());
        assert!(!LeaseReleaseTool::docs().is_empty());
    }

    #[test]
    fn lease_get_tool_metadata() {
        assert_eq!(LeaseGetTool::name(), "memory_lease_get");
        assert_eq!(LeaseGetTool::family(), "power");
        assert!(!LeaseGetTool::description().is_empty());
        assert!(!LeaseGetTool::docs().is_empty());
    }

    #[test]
    fn action_create_schema_requires_core_fields() {
        let schema = ActionCreateTool::input_schema();
        let obj = schema.as_object().expect("schema is an object");
        assert!(
            obj.contains_key("properties"),
            "schema must advertise properties"
        );
        let required = obj
            .get("required")
            .and_then(Value::as_array)
            .expect("required is an array");
        let required_names: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
        for name in &["namespace", "kind", "title"] {
            assert!(
                required_names.contains(name),
                "required must include {name}"
            );
        }
    }
}

#[cfg(test)]
mod handler_tests {
    use super::*;

    fn fresh() -> rusqlite::Connection {
        crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    #[test]
    fn create_then_get_roundtrips_over_mcp() {
        let conn = fresh();
        let created = handle_action_create(
            &conn,
            &json!({
                "namespace": "_act",
                "kind": "test.kind",
                "title": "t",
                "payload": {"a": 1},
                "priority": 5,
                "agent_id": "agent-x",
            }),
        )
        .expect("create ok");
        let id = created[param_names::ID].as_str().expect("id present");
        assert_eq!(created["action"]["state"].as_str(), Some("pending"));

        let got = handle_action_get(&conn, &json!({ "id": id })).expect("get ok");
        assert_eq!(got["action"]["namespace"].as_str(), Some("_act"));
        assert_eq!(got["action"]["kind"].as_str(), Some("test.kind"));
        assert_eq!(got["action"]["priority"].as_i64(), Some(5));
        assert_eq!(got["action"]["agent_id"].as_str(), Some("agent-x"));
    }

    /// #3171 — an OMITTED `holder` must be refused, because
    /// `unwrap_or_default()` collapsed every anonymous holder to `""` and
    /// that DOUBLE-GRANTS a single-holder coordination lease.
    ///
    /// `crate::actions::lease_acquire`'s upsert guard is
    /// `WHERE leases.expires_at <= ?now OR leases.holder = ?holder`. With two
    /// distinct agents both defaulting to `""`, the second acquire matched the
    /// same-holder arm and SUCCEEDED — both workers then believed they held
    /// exclusive coordination authority over the action, which that function's
    /// own contract calls a correctness/safety violation ("the worst case is a
    /// spurious Conflict a caller retries, never two winners"). Refusing the
    /// blank at the MCP boundary is what keeps that invariant true.
    #[test]
    fn lease_handlers_refuse_blank_required_args_3171() {
        let conn = fresh();
        let created = handle_action_create(
            &conn,
            &json!({"namespace": "_act", "kind": "k", "title": "t", "payload": {}}),
        )
        .expect("create ok");
        let id = created[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();

        // Two DIFFERENT agents, each omitting `holder`, must not both win.
        let first = handle_lease_acquire(&conn, &json!({ "action_id": id }));
        assert_eq!(
            first.expect_err("blank holder refused"),
            "holder is required"
        );
        for bad in [
            json!({ "action_id": id.clone(), "holder": "" }),
            json!({ "action_id": id.clone(), "holder": "   " }),
            json!({ "action_id": id.clone(), "holder": 7 }),
        ] {
            assert_eq!(
                handle_lease_acquire(&conn, &bad).expect_err("refused"),
                "holder is required",
                "{bad}"
            );
        }
        assert_eq!(
            handle_lease_acquire(&conn, &json!({ "holder": "w1" })).expect_err("refused"),
            "action_id is required"
        );

        // renew / release / get refuse the same blanks rather than answering
        // "no lease held" / "released: false" / "lease: null".
        assert_eq!(
            handle_lease_renew(&conn, &json!({ "action_id": id.clone() })).expect_err("refused"),
            "holder is required"
        );
        assert_eq!(
            handle_lease_release(&conn, &json!({ "action_id": id.clone() })).expect_err("refused"),
            "holder is required"
        );
        assert_eq!(
            handle_lease_get(&conn, &json!({})).expect_err("refused"),
            "action_id is required"
        );

        // CONTROL: a well-formed acquire still wins, and a DIFFERENT named
        // holder is then correctly refused as a conflict rather than granted.
        handle_lease_acquire(&conn, &json!({ "action_id": id.clone(), "holder": "w1" }))
            .expect("named holder acquires");
        let conflict = handle_lease_acquire(&conn, &json!({ "action_id": id, "holder": "w2" }))
            .expect_err("a second distinct holder must NOT be granted");
        assert!(conflict.contains("conflict"), "got: {conflict}");
    }

    #[test]
    fn get_absent_returns_null_action() {
        let conn = fresh();
        let got = handle_action_get(&conn, &json!({ "id": "missing" })).expect("get ok");
        assert!(got["action"].is_null());
    }

    /// #1806 (SECURITY) — lease TTL must be clamped: an unbounded / negative /
    /// over-1-year ttl_secs is refused (no overflow panic, no never-reclaimed
    /// forever-lease starvation), mirroring the memory-write validate path.
    #[test]
    fn lease_acquire_rejects_unbounded_and_negative_ttl_1806() {
        let conn = fresh();
        let created = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t", "agent_id": "a" }),
        )
        .expect("create ok");
        let id = created[param_names::ID].as_str().expect("id").to_string();

        for bad in [i64::MAX, -1, 400i64 * 24 * 3600] {
            let r = handle_lease_acquire(
                &conn,
                &json!({ "action_id": id, "holder": "h", "ttl_secs": bad }),
            );
            assert!(
                r.is_err(),
                "#1806: ttl_secs={bad} must be rejected, got {r:?}"
            );
            let rn = handle_lease_renew(
                &conn,
                &json!({ "action_id": id, "holder": "h", "ttl_secs": bad }),
            );
            assert!(
                rn.is_err(),
                "#1806: renew ttl_secs={bad} must be rejected, got {rn:?}"
            );
        }
    }

    /// #1807 (SECURITY) — coordination create-paths must be quota'd + payload-
    /// bounded. (a) An action whose metadata exceeds the memory-write metadata
    /// size limit is refused. (b) Once the owning agent's per-namespace storage
    /// cap is reached, a further create is refused with the quota error — while
    /// a fresh-namespace create under the default 100 MiB cap still succeeds
    /// (the gate rejects ONLY at the cap, so normal coordination is unaffected).
    #[test]
    fn action_create_enforces_metadata_size_and_storage_quota_1807() {
        let conn = fresh();

        // (a) oversized metadata is refused (>65_536 serialized bytes).
        let huge = "x".repeat(70_000);
        let r = handle_action_create(
            &conn,
            &json!({
                "namespace": "_act", "kind": "k", "title": "t", "agent_id": "a",
                "metadata": { "big": huge },
            }),
        );
        assert!(
            r.is_err(),
            "#1807: oversized metadata must be rejected, got {r:?}"
        );

        // Blast-radius: a normal create on a fresh DB (default cap) succeeds.
        handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t", "agent_id": "a",
                     "payload": {"x": 1} }),
        )
        .expect("#1807: normal create under default cap must succeed");

        // (b) drop the agent's per-namespace cap to its current usage, then the
        // next non-empty create exceeds it and is refused by the storage quota.
        conn.execute(
            "UPDATE agent_quotas SET max_storage_bytes = current_storage_bytes
             WHERE agent_id = 'a' AND namespace = '_act'",
            [],
        )
        .expect("pin cap to current usage");
        let over = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t", "agent_id": "a",
                     "payload": {"more": "data-past-the-cap"} }),
        );
        assert!(
            over.is_err(),
            "#1807: over-cap create must be refused, got {over:?}"
        );

        // Unowned action (no agent_id) is never charged — still creates fine
        // even with the (different) default-keyed quota row.
        handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t" }),
        )
        .expect("#1807: unowned create is uncharged and succeeds");
    }

    #[test]
    fn transition_list_edges_roundtrip_over_mcp() {
        let conn = fresh();
        let created = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t" }),
        )
        .expect("create ok");
        let id = created[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();

        // Legal transition pending -> claimed.
        let moved = handle_action_transition(
            &conn,
            &json!({ "id": id, "to": "claimed", "claimed_by": "holder-1" }),
        )
        .expect("transition ok");
        assert_eq!(moved["action"]["state"].as_str(), Some("claimed"));
        assert_eq!(moved["action"]["claimed_by"].as_str(), Some("holder-1"));

        // Illegal transition claimed -> done is reported as an error.
        let illegal = handle_action_transition(&conn, &json!({ "id": id, "to": "done" }));
        assert!(illegal.is_err());

        // Unknown id is an error.
        let absent = handle_action_transition(&conn, &json!({ "id": "missing", "to": "claimed" }));
        assert!(absent.is_err());

        // List filtered by state.
        let listed = handle_action_list(&conn, &json!({ "state": "claimed" })).expect("list ok");
        let arr = listed["actions"].as_array().expect("actions array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"].as_str(), Some(id.as_str()));

        // Add a second action + an edge between them.
        let other = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t2" }),
        )
        .expect("create ok");
        let other_id = other[param_names::ID].as_str().expect("id present");
        let added = handle_action_add_edge(
            &conn,
            &json!({ "from_action": id, "to_action": other_id, "edge_type": "requires" }),
        )
        .expect("add_edge ok");
        assert_eq!(added["ok"].as_bool(), Some(true));

        let edges = handle_action_edges(&conn, &json!({ "id": id })).expect("edges ok");
        let edge_arr = edges["edges"].as_array().expect("edges array");
        assert_eq!(edge_arr.len(), 1);
        assert_eq!(edge_arr[0]["edge_type"].as_str(), Some("requires"));
    }

    #[test]
    fn transition_invalid_state_name_errors() {
        let conn = fresh();
        let created = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t" }),
        )
        .expect("create ok");
        let id = created[param_names::ID].as_str().expect("id present");
        let bad = handle_action_transition(&conn, &json!({ "id": id, "to": "bogus" }));
        assert!(bad.is_err());

        let bad_edge = handle_action_add_edge(
            &conn,
            &json!({ "from_action": id, "to_action": id, "edge_type": "bogus" }),
        );
        assert!(bad_edge.is_err());
    }

    /// #3009 — the transition lane binds `claimed_by` to the live lease holder:
    /// a caller transitioning with a `claimed_by` that is not the current lease
    /// holder is refused (so two agents cannot each believe they own the
    /// action); a control-char `claimed_by` is refused (log-injection guard).
    #[test]
    fn transition_binds_claimed_by_to_live_lease_holder_3009() {
        let conn = fresh();
        let created = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t" }),
        )
        .expect("create ok");
        let id = created[param_names::ID].as_str().expect("id").to_string();

        // Worker w1 acquires the lease.
        handle_lease_acquire(
            &conn,
            &json!({ "action_id": id, "holder": "ai:w1", "ttl_secs": 120 }),
        )
        .expect("acquire ok");

        // w2 (not the lease holder) is refused.
        let err = handle_action_transition(
            &conn,
            &json!({ "id": id, "to": "claimed", "claimed_by": "ai:w2" }),
        )
        .expect_err("a non-holder transition must be refused");
        assert!(err.contains("not the live lease holder"), "{err}");

        // The lease holder w1 can transition.
        handle_action_transition(
            &conn,
            &json!({ "id": id, "to": "claimed", "claimed_by": "ai:w1" }),
        )
        .expect("the lease holder transitions ok");

        // A control-char claimed_by is refused (audit log-injection guard).
        assert!(
            handle_action_transition(
                &conn,
                &json!({ "id": id, "to": "in_progress", "claimed_by": "bad\nid" })
            )
            .is_err(),
            "control-char claimed_by refused"
        );
    }

    /// #3008 — the add-edge handler refuses a self-edge and an ordering cycle
    /// with a descriptive error (instead of silently wedging the frontier).
    #[test]
    fn add_edge_handler_refuses_self_edge_and_cycle_3008() {
        let conn = fresh();
        for t in ["a", "b"] {
            handle_action_create(
                &conn,
                &json!({ "namespace": "_act", "kind": "k", "title": t, "agent_id": "ai:w" }),
            )
            .expect("create ok");
        }
        // Fetch ids by listing (create returns them, but list is simpler here).
        let listed = handle_action_list(&conn, &json!({ "namespace": "_act" })).expect("list");
        let ids: Vec<String> = listed["actions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["id"].as_str().unwrap().to_string())
            .collect();
        let (a_id, b_id) = (&ids[0], &ids[1]);

        // Self-edge refused with a descriptive message.
        let self_err = handle_action_add_edge(
            &conn,
            &json!({ "from_action": a_id, "to_action": a_id, "edge_type": "requires" }),
        )
        .expect_err("self-edge refused");
        assert!(self_err.contains("self-edge"), "{self_err}");

        // a requires b is fine; b requires a would cycle → refused.
        handle_action_add_edge(
            &conn,
            &json!({ "from_action": a_id, "to_action": b_id, "edge_type": "requires" }),
        )
        .expect("a requires b ok");
        let cycle_err = handle_action_add_edge(
            &conn,
            &json!({ "from_action": b_id, "to_action": a_id, "edge_type": "requires" }),
        )
        .expect_err("cycle refused");
        assert!(cycle_err.contains("cycle"), "{cycle_err}");
    }

    /// #2997 — on an MCP-stdio-only deployment (no background sweep), the
    /// coordination read/lease surfaces piggyback the lease-expiry sweep: a dead
    /// worker's expired lease is reclaimed and its stranded `claimed` action is
    /// requeued to `pending`, so `memory_action_frontier` surfaces it again
    /// instead of stranding it forever.
    #[test]
    fn frontier_sweeps_expired_leases_and_requeues_stranded_action_2997() {
        let conn = fresh();
        let created = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t" }),
        )
        .expect("create ok");
        let id = created[param_names::ID].as_str().expect("id").to_string();

        // A dead worker claims the action, holding a lease that is ALREADY
        // expired (inserted directly to bypass the ttl>0 clamp).
        handle_action_transition(
            &conn,
            &json!({ "id": id, "to": "claimed", "claimed_by": "ai:dead-worker" }),
        )
        .expect("claim ok");
        let now = chrono::Utc::now().timestamp();
        crate::actions::lease_acquire(&conn, &id, "ai:dead-worker", now - 100, now - 1)
            .expect("acquire an already-expired lease");

        // The claimed action is stranded (absent from the frontier); the
        // frontier handler's piggybacked sweep reclaims + requeues it.
        let f =
            handle_action_frontier(&conn, &json!({ "namespace": "_act" })).expect("frontier ok");
        let ids: Vec<&str> = f["actions"]
            .as_array()
            .expect("actions array")
            .iter()
            .filter_map(|a| a["id"].as_str())
            .collect();
        assert!(
            ids.contains(&id.as_str()),
            "the stranded action is requeued and back on the frontier"
        );

        // It is pending again with the dead holder's claim cleared.
        let got = crate::actions::get(&conn, &id)
            .expect("get")
            .expect("present");
        assert_eq!(got.state, crate::models::ActionState::Pending);
        assert!(
            got.claimed_by.is_none(),
            "the dead worker's claim is cleared"
        );
    }

    /// A6-13 — acquiring a lease on a MISSING action returns a typed not-found,
    /// not the raw `leases.action_id` FK-constraint error.
    #[test]
    fn lease_acquire_missing_action_is_typed_not_found() {
        let conn = fresh();
        let err = handle_lease_acquire(&conn, &json!({ "action_id": "nope", "holder": "h" }))
            .expect_err("a lease on a missing action must be a typed not-found");
        assert!(err.contains("action not found"), "{err}");
    }

    #[test]
    fn lease_acquire_renew_release_get_roundtrip_over_mcp() {
        let conn = fresh();
        // A lease references a real action row, so create one first.
        let created = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t" }),
        )
        .expect("create ok");
        let id = created[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();

        // Acquire by holder-a.
        let acquired = handle_lease_acquire(
            &conn,
            &json!({ "action_id": id, "holder": "holder-a", "ttl_secs": 120 }),
        )
        .expect("acquire ok");
        assert_eq!(acquired["lease"]["holder"].as_str(), Some("holder-a"));
        assert_eq!(acquired["lease"]["action_id"].as_str(), Some(id.as_str()));

        // A different holder hits the conflict error path.
        let conflict =
            handle_lease_acquire(&conn, &json!({ "action_id": id, "holder": "holder-b" }));
        assert!(conflict.is_err());

        // get returns the held lease.
        let got = handle_lease_get(&conn, &json!({ "action_id": id })).expect("get ok");
        assert_eq!(got["lease"]["holder"].as_str(), Some("holder-a"));

        // Renew by the owner succeeds.
        let renewed = handle_lease_renew(
            &conn,
            &json!({ "action_id": id, "holder": "holder-a", "ttl_secs": 90 }),
        )
        .expect("renew ok");
        assert_eq!(renewed["lease"]["holder"].as_str(), Some("holder-a"));

        // Renew by a non-owner is the no-lease error path.
        let no_lease = handle_lease_renew(&conn, &json!({ "action_id": id, "holder": "holder-b" }));
        assert!(no_lease.is_err());

        // Release by a non-owner removes nothing.
        let not_released =
            handle_lease_release(&conn, &json!({ "action_id": id, "holder": "holder-b" }))
                .expect("release ok");
        assert_eq!(not_released["released"].as_bool(), Some(false));

        // Release by the owner removes it; get then reports null.
        let released =
            handle_lease_release(&conn, &json!({ "action_id": id, "holder": "holder-a" }))
                .expect("release ok");
        assert_eq!(released["released"].as_bool(), Some(true));
        let absent = handle_lease_get(&conn, &json!({ "action_id": id })).expect("get ok");
        assert!(absent["lease"].is_null());
    }

    #[test]
    fn create_defaults_unspecified_optionals() {
        let conn = fresh();
        let created = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t" }),
        )
        .expect("create ok");
        assert_eq!(created["action"]["priority"].as_i64(), Some(0));
        // #2998 — an omitted agent_id no longer stores NULL: the create resolves
        // the durable ambient actor so every action is attributed + quota-charged.
        assert!(
            created["action"]["agent_id"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "omitted agent_id resolves to a non-empty ambient actor"
        );
        // created_at/updated_at are populated, non-zero unix seconds.
        let created_at = created["action"]["created_at"]
            .as_i64()
            .expect("created_at present");
        assert!(created_at > 0);
    }

    /// #2998 — the create surface validates its inputs and ALWAYS attributes a
    /// resolved actor: a path-traversal namespace, an empty title, an oversized
    /// payload, and a control-char `agent_id` (log-injection into the audit
    /// identity fields) are all refused; an omitted `agent_id` resolves to a
    /// non-empty ambient actor so the write is charged rather than uncharged.
    #[test]
    fn action_create_validates_inputs_and_attributes_actor_2998() {
        let conn = fresh();
        assert!(
            handle_action_create(
                &conn,
                &json!({ "namespace": "../../etc/passwd", "kind": "k", "title": "t" })
            )
            .is_err(),
            "path-traversal namespace refused"
        );
        assert!(
            handle_action_create(
                &conn,
                &json!({ "namespace": "_act", "kind": "k", "title": "  " })
            )
            .is_err(),
            "empty title refused"
        );
        let big = "x".repeat(70_000);
        assert!(
            handle_action_create(
                &conn,
                &json!({ "namespace": "_act", "kind": "k", "title": "t", "payload": { "b": big } })
            )
            .is_err(),
            "oversized payload refused"
        );
        assert!(
            handle_action_create(
                &conn,
                &json!({ "namespace": "_act", "kind": "k", "title": "t", "agent_id": "bad\nid" })
            )
            .is_err(),
            "control-char agent_id refused (log-injection guard)"
        );
        let ok = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t" }),
        )
        .expect("benign create ok");
        assert!(
            ok["action"]["agent_id"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "omitted agent_id resolves to a non-empty ambient actor"
        );
    }

    #[test]
    fn frontier_and_next_over_mcp() {
        let conn = fresh();
        // A pending action with no blocking edges is on the frontier; a
        // second action requiring a still-pending prerequisite is not.
        let a = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "ready", "priority": 9 }),
        )
        .expect("create A ok");
        let a_id = a[param_names::ID].as_str().expect("id A").to_string();

        let blocked = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "blocked", "priority": 5 }),
        )
        .expect("create blocked ok");
        let blocked_id = blocked[param_names::ID]
            .as_str()
            .expect("id blocked")
            .to_string();
        let prereq = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "prereq", "priority": 1 }),
        )
        .expect("create prereq ok");
        let prereq_id = prereq[param_names::ID].as_str().expect("id prereq");
        handle_action_add_edge(
            &conn,
            &json!({ "from_action": blocked_id, "to_action": prereq_id, "edge_type": "requires" }),
        )
        .expect("add requires edge ok");

        // Frontier finds the ready action, not the blocked one.
        let f =
            handle_action_frontier(&conn, &json!({ "namespace": "_act" })).expect("frontier ok");
        let ids: Vec<&str> = f["actions"]
            .as_array()
            .expect("actions array")
            .iter()
            .filter_map(|a| a["id"].as_str())
            .collect();
        assert!(
            ids.contains(&a_id.as_str()),
            "the ready action is on the frontier"
        );
        assert!(
            !ids.contains(&blocked_id.as_str()),
            "the blocked action is absent from the frontier"
        );

        // next returns the top frontier row (A, priority 9).
        let n = handle_action_next(&conn, &json!({ "namespace": "_act" })).expect("next ok");
        assert_eq!(n["action"]["id"].as_str(), Some(a_id.as_str()));

        // An empty namespace yields a null next action.
        let empty = handle_action_next(&conn, &json!({ "namespace": "_empty" })).expect("next ok");
        assert!(empty["action"].is_null());
    }

    /// #1722 — a legal action transition appends one
    /// `coordination.action_transition` audit row attributed to the claiming
    /// agent; the append-only chain stays intact.
    #[test]
    fn transition_emits_signed_events_audit_row_1722() {
        let conn = fresh();
        let created = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t" }),
        )
        .expect("create ok");
        let id = created[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();

        handle_action_transition(
            &conn,
            &json!({ "id": id, "to": "claimed", "claimed_by": "holder-1" }),
        )
        .expect("transition ok");

        let (count, agent): (i64, String) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(agent_id), '') FROM signed_events \
                 WHERE event_type = ?1",
                rusqlite::params![crate::coordination_audit::ACTION_TRANSITION],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query audit row");
        assert_eq!(count, 1, "one coordination.action_transition row");
        assert_eq!(agent, "holder-1", "row attributed to the claiming agent");

        let report = crate::signed_events::verify_audit_trail(&conn, None, None).expect("verify");
        assert!(report.chain_intact, "chain must verify; report={report:?}");
    }

    /// #1722 — a lease acquire appends one `coordination.lease_acquire` audit
    /// row attributed to the holder; the append-only chain stays intact.
    #[test]
    fn lease_acquire_emits_signed_events_audit_row_1722() {
        let conn = fresh();
        let created = handle_action_create(
            &conn,
            &json!({ "namespace": "_act", "kind": "k", "title": "t" }),
        )
        .expect("create ok");
        let id = created[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();

        handle_lease_acquire(
            &conn,
            &json!({ "action_id": id, "holder": "holder-a", "ttl_secs": 120 }),
        )
        .expect("acquire ok");

        let (count, agent): (i64, String) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(agent_id), '') FROM signed_events \
                 WHERE event_type = ?1",
                rusqlite::params![crate::coordination_audit::LEASE_ACQUIRE],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query audit row");
        assert_eq!(count, 1, "one coordination.lease_acquire row");
        assert_eq!(agent, "holder-a", "row attributed to the lease holder");

        let report = crate::signed_events::verify_audit_trail(&conn, None, None).expect("verify");
        assert!(report.chain_intact, "chain must verify; report={report:?}");
    }

    // -----------------------------------------------------------------
    // #3171 — schema-REQUIRED `namespace` must be refused when
    // missing/blank, never silently queried as "".
    // -----------------------------------------------------------------

    /// A missing / blank / non-string `namespace` is REFUSED on both
    /// frontier and next. Pre-#3171 `unwrap_or_default()` answered the
    /// malformed call with an EMPTY-SUCCESS frontier (`actions: []` /
    /// `action: null`), indistinguishable from "there is no work" — a
    /// worker fleet would idle forever on a typo'd argument.
    #[test]
    fn frontier_and_next_refuse_missing_or_blank_namespace_3171() {
        let conn = fresh();
        for bad in [json!({}), json!({ "namespace": "" }), json!({ "namespace": "   " }), json!({ "namespace": 7 })] {
            let e = handle_action_frontier(&conn, &bad).expect_err("frontier refuses");
            assert_eq!(e, "namespace is required", "frontier: {bad}");
            let e = handle_action_next(&conn, &bad).expect_err("next refuses");
            assert_eq!(e, "namespace is required", "next: {bad}");
        }
        // CONTROL: a well-formed call still succeeds (and is empty here).
        let ok = handle_action_frontier(&conn, &json!({ "namespace": "_act" })).expect("ok");
        assert_eq!(ok["actions"].as_array().expect("array").len(), 0);
    }
}
