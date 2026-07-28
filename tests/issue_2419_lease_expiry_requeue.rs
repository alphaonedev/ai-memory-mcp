// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2419 — an action stranded in a non-terminal, non-`pending` state must be
//! RECOVERABLE.
//!
//! **The defect.** `memory_action_frontier` selects `state = 'pending'` only. A
//! worker that claimed an action and then died left the node in `claimed`
//! forever: not done, not leased by anyone (the hourly sweep already deleted
//! the expired lease row), and invisible to every `frontier` / `next` caller.
//! The work was permanently lost unless an operator happened to know to run a
//! full `memory_action_list` census by hand — which is exactly what this
//! campaign had to do for three stale DAG nodes.
//!
//! **The fix under test.** The lease-expiry sweep now ALSO transitions such an
//! action `claimed -> pending` over the ALREADY-LEGAL state-machine edge, in
//! the same transaction as the lease delete. No new state, no schema change, no
//! new read surface — the node reappears on `frontier` by itself because it IS
//! pending again.
//!
//! **Load-bearing (R-203).** Every assertion below FAILS against the unfixed
//! sweep: `frontier` returns an empty vec and the action's state is still
//! `claimed` after the sweep. The pre-fix `sweep_expired_leases*` deleted the
//! lease row and stopped there.

use ai_memory::actions;
use ai_memory::models::{Action, ActionState};

fn fresh() -> rusqlite::Connection {
    ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

const NS: &str = "_act_2419";
const NOW: i64 = 1_700_000_000;

fn action(id: &str) -> Action {
    Action {
        id: id.to_string(),
        namespace: NS.to_string(),
        kind: "test.kind".to_string(),
        state: ActionState::Pending,
        title: "stranded work".to_string(),
        payload: serde_json::json!({}),
        priority: 5,
        agent_id: None,
        claimed_by: None,
        vector_clock: serde_json::json!({}),
        metadata: serde_json::json!({}),
        created_at: NOW,
        updated_at: NOW,
    }
}

/// Drive a node to `claimed` under a lease that is ALREADY expired — the exact
/// shape a worker that died mid-claim leaves behind.
fn claimed_with_expired_lease(conn: &rusqlite::Connection, id: &str, holder: &str) {
    actions::create(conn, &action(id)).expect("create");
    let outcome = actions::transition(conn, id, ActionState::Claimed, Some(holder), NOW)
        .expect("claim transition");
    assert!(
        matches!(outcome, actions::TransitionOutcome::Updated(_)),
        "pending -> claimed must apply"
    );
    actions::lease_acquire(conn, id, holder, NOW, NOW - 1).expect("lease_acquire");
}

fn state_of(conn: &rusqlite::Connection, id: &str) -> ActionState {
    actions::get(conn, id).expect("get").expect("row").state
}

/// THE regression. A claimed node whose lease expired is invisible to the
/// documented `frontier` read surface; after the sweep it must be visible again
/// WITHOUT the read surface having changed.
#[test]
fn expired_lease_requeues_stranded_claimed_node_onto_frontier_2419() {
    let conn = fresh();
    claimed_with_expired_lease(&conn, "act-stranded", "holder-dead");

    // Pre-condition: the defect's signature — the node exists, is not terminal,
    // and the frontier cannot see it.
    assert_eq!(state_of(&conn, "act-stranded"), ActionState::Claimed);
    assert!(
        actions::frontier(&conn, NS, 50)
            .expect("frontier")
            .is_empty(),
        "a claimed node is (correctly) not on the pending frontier before the sweep"
    );

    assert_eq!(
        actions::sweep_expired_leases_audited(&conn, NOW).expect("sweep"),
        1,
        "the expired lease is reclaimed"
    );

    // FAILS pre-fix: state stays `claimed` and the frontier stays empty.
    assert_eq!(
        state_of(&conn, "act-stranded"),
        ActionState::Pending,
        "lease expiry must requeue the stranded claimed node to pending"
    );
    let ids: Vec<String> = actions::frontier(&conn, NS, 50)
        .expect("frontier")
        .into_iter()
        .map(|a| a.id)
        .collect();
    assert_eq!(
        ids,
        vec!["act-stranded".to_string()],
        "the requeued node is visible on the frontier again"
    );

    // `next` — the claim surface — must hand the recovered work to a caller.
    let next = actions::next_action(&conn, NS, None)
        .expect("next")
        .expect("some");
    assert_eq!(next.id, "act-stranded");
    assert_eq!(
        next.claimed_by, None,
        "the dead holder's claim is cleared so a fresh holder can take it"
    );
}

/// The requeue leaves a FORCED-reversion audit row distinct from a
/// caller-requested transition, so an operator can tell the two apart.
#[test]
fn requeue_emits_distinct_forced_reversion_audit_row_2419() {
    let conn = fresh();
    claimed_with_expired_lease(&conn, "act-audited", "holder-x");
    actions::sweep_expired_leases_audited(&conn, NOW).expect("sweep");

    let count = |event_type: &str| -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
            rusqlite::params![event_type, "holder-x"],
            |r| r.get(0),
        )
        .expect("count")
    };
    // FAILS pre-fix: the requeue slug is never emitted (0 rows).
    assert_eq!(
        count(ai_memory::coordination_audit::ACTION_LEASE_EXPIRE_REQUEUE),
        1,
        "one forced-requeue audit row attributed to the reclaimed holder"
    );
    assert_eq!(
        count(ai_memory::coordination_audit::LEASE_SWEEP_RECLAIM),
        1,
        "the pre-existing lease-reclaim audit row is unchanged (#2371)"
    );
    assert_eq!(
        count(ai_memory::coordination_audit::ACTION_TRANSITION),
        0,
        "a FORCED reversion must NOT masquerade as a caller-requested transition"
    );
}

/// Data integrity: the requeue is CAS-guarded on `state = 'claimed'`. A worker
/// that is genuinely progressing (`in_progress`) but whose lease lapsed is NOT
/// yanked back to pending — `in_progress -> pending` is not a legal edge, and
/// re-offering live work would risk double execution.
#[test]
fn in_progress_node_is_not_requeued_by_lease_expiry_2419() {
    let conn = fresh();
    claimed_with_expired_lease(&conn, "act-live", "holder-live");
    actions::transition(
        &conn,
        "act-live",
        ActionState::InProgress,
        Some("holder-live"),
        NOW,
    )
    .expect("claimed -> in_progress");

    assert_eq!(
        actions::sweep_expired_leases_audited(&conn, NOW).expect("sweep"),
        1,
        "the lease is still reclaimed"
    );
    assert_eq!(
        state_of(&conn, "act-live"),
        ActionState::InProgress,
        "an in-progress node keeps its state (no illegal in_progress -> pending)"
    );
    // Documented residual: it is not on the frontier, but it IS listable, and
    // the lease-reclaim audit row records that its holder lost the lease.
    assert!(
        actions::frontier(&conn, NS, 50)
            .expect("frontier")
            .is_empty()
    );
    let listed = actions::list(&conn, Some(NS), Some(ActionState::InProgress), 50).expect("list");
    assert_eq!(listed.len(), 1, "still reachable via memory_action_list");
}

/// A terminal node whose lease lapsed is never resurrected — `done -> pending`
/// is not a legal edge and the CAS guard rejects it. Guards the North-Star
/// "never produce WRONG results" bar: completed work must not re-enter the
/// frontier.
#[test]
fn terminal_node_is_never_resurrected_by_lease_expiry_2419() {
    let conn = fresh();
    claimed_with_expired_lease(&conn, "act-done", "holder-done");
    actions::transition(
        &conn,
        "act-done",
        ActionState::InProgress,
        Some("holder-done"),
        NOW,
    )
    .expect("claimed -> in_progress");
    actions::transition(
        &conn,
        "act-done",
        ActionState::Done,
        Some("holder-done"),
        NOW,
    )
    .expect("in_progress -> done");

    actions::sweep_expired_leases_audited(&conn, NOW).expect("sweep");

    assert_eq!(state_of(&conn, "act-done"), ActionState::Done);
    assert!(
        actions::frontier(&conn, NS, 50)
            .expect("frontier")
            .is_empty(),
        "a done node must never re-enter the frontier"
    );
}

/// A LIVE lease is untouched: neither the lease nor the action state moves,
/// so a heartbeating worker is never interrupted.
#[test]
fn live_lease_is_untouched_by_the_sweep_2419() {
    let conn = fresh();
    actions::create(&conn, &action("act-live-lease")).expect("create");
    actions::transition(
        &conn,
        "act-live-lease",
        ActionState::Claimed,
        Some("holder-alive"),
        NOW,
    )
    .expect("claim");
    actions::lease_acquire(&conn, "act-live-lease", "holder-alive", NOW, NOW + 600)
        .expect("lease_acquire");

    assert_eq!(
        actions::sweep_expired_leases_audited(&conn, NOW).expect("sweep"),
        0,
        "a live lease is not reclaimed"
    );
    assert_eq!(state_of(&conn, "act-live-lease"), ActionState::Claimed);
    assert!(
        actions::lease_get(&conn, "act-live-lease")
            .expect("lease_get")
            .is_some(),
        "the live lease row survives"
    );
}

/// The sweep is idempotent + self-consistent across repeated runs: a second
/// pass finds nothing to reclaim and does not re-transition the already-pending
/// node (which a fresh holder may have legitimately re-claimed by then).
#[test]
fn sweep_is_idempotent_after_requeue_2419() {
    let conn = fresh();
    claimed_with_expired_lease(&conn, "act-idem", "holder-1");
    assert_eq!(
        actions::sweep_expired_leases_audited(&conn, NOW).expect("sweep 1"),
        1
    );
    assert_eq!(
        actions::sweep_expired_leases_audited(&conn, NOW).expect("sweep 2"),
        0,
        "nothing left to reclaim"
    );
    assert_eq!(state_of(&conn, "act-idem"), ActionState::Pending);

    // A fresh holder re-claims the recovered work under a LIVE lease; the next
    // sweep must leave it alone.
    actions::transition(
        &conn,
        "act-idem",
        ActionState::Claimed,
        Some("holder-2"),
        NOW,
    )
    .expect("re-claim");
    actions::lease_acquire(&conn, "act-idem", "holder-2", NOW, NOW + 600).expect("lease_acquire");
    assert_eq!(
        actions::sweep_expired_leases_audited(&conn, NOW).expect("sweep 3"),
        0
    );
    assert_eq!(state_of(&conn, "act-idem"), ActionState::Claimed);
}

/// The `claimed -> pending` edge the requeue rides must stay legal. If a future
/// state-machine edit removes it, the requeue would silently become a no-op and
/// the #2419 defect would return — this pins the dependency explicitly.
#[test]
fn claimed_to_pending_edge_remains_legal_2419() {
    assert!(
        ActionState::Claimed.can_transition_to(ActionState::Pending),
        "the lease-expiry requeue depends on this edge being legal"
    );
    assert!(
        !ActionState::InProgress.can_transition_to(ActionState::Pending),
        "in_progress -> pending is deliberately NOT legal (documented residual)"
    );
}
