// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8759 (SECURITY) — `memory_action_transition` must take its acting identity
//! from the AUTHENTICATED MCP principal (`AI_MEMORY_AGENT_ID`), never from the
//! caller-supplied `claimed_by`. The field stays on the wire, but it may only be
//! COMPARED to the principal: a difference is refused with the named
//! `acting_identity_mismatch` error and leaves the stored action untouched.
//!
//! Pre-fix, agent B (`ai:bob-act`) drove an action leased by agent A
//! (`ai:alice-act`) to `done` by naming A as `claimed_by`, and the audit row
//! then attributed the transition to A.
//!
//! The table below is (claimed identity) x (lease live / no lease) for the
//! MCP stdio transport on the sqlite backend (the only backend the MCP handler
//! reaches; the HTTP x {sqlite, postgres} cells live in
//! `tests/http_transition_claimed_by_3226.rs`).

use serde_json::{Value, json};

use super::{
    handle_action_create, handle_action_get, handle_action_transition, handle_lease_acquire,
    handle_lease_release, handle_lease_renew,
};
use crate::mcp::param_names;

const ALICE: &str = "ai:alice-act";
const BOB: &str = "ai:bob-act";
const MALFORMED_CLAIM: &str = "bad\nid";
/// A set-but-invalid process identity: the principal resolver must fail
/// CLOSED on it, never fall back to the single-operator posture.
const MALFORMED_ENV_ID: &str = "bad id with spaces";
const NS: &str = "_act_8759";
const LEASE_TTL_SECS: i64 = 600;

/// The MCP principal for the current test THREAD, through the crate's
/// thread-local `AI_MEMORY_AGENT_ID` seam (`identity::test_agent_id`): no
/// process-global env mutation, so a parallel test can neither see nor clobber
/// it, and the override is disarmed on drop (including on unwind).
struct AgentEnv {
    guard: std::cell::RefCell<Option<crate::identity::test_agent_id::AgentIdOverride>>,
}

impl AgentEnv {
    fn new() -> Self {
        Self {
            guard: std::cell::RefCell::new(None),
        }
    }

    /// Resolve `id` as the principal (drops the previous override FIRST so
    /// the restore chain stays single-level).
    fn set(&self, id: &str) {
        let mut slot = self.guard.borrow_mut();
        *slot = None;
        *slot = Some(crate::identity::test_agent_id::AgentIdOverride::set(id));
    }

    /// Resolve as if `AI_MEMORY_AGENT_ID` were absent (single-operator).
    fn unset(&self) {
        let mut slot = self.guard.borrow_mut();
        *slot = None;
        *slot = Some(crate::identity::test_agent_id::AgentIdOverride::unset());
    }
}

fn fresh() -> rusqlite::Connection {
    crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn mismatch(caller: &str, claimed: &str) -> String {
    format!(
        "acting_identity_mismatch: caller '{caller}' may only transition an action as itself \
         (claimed_by '{claimed}')"
    )
}

/// `(state, claimed_by)` of the stored action.
fn stored(conn: &rusqlite::Connection, id: &str) -> (String, Option<String>) {
    let got = handle_action_get(conn, &json!({ "id": id })).expect("action_get");
    (
        got["action"]["state"].as_str().expect("state").to_string(),
        got["action"][param_names::CLAIMED_BY]
            .as_str()
            .map(str::to_string),
    )
}

fn transition_audit_rows(conn: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT agent_id FROM signed_events WHERE event_type = ?1 ORDER BY rowid")
        .expect("prepare");
    stmt.query_map(
        rusqlite::params![crate::coordination_audit::ACTION_TRANSITION],
        |r| r.get::<_, String>(0),
    )
    .expect("query")
    .map(|r| r.expect("row"))
    .collect()
}

/// As ALICE: create an action, lease it, and claim it. Returns its id.
fn alice_claims(conn: &rusqlite::Connection, env: &AgentEnv) -> String {
    env.set(ALICE);
    let created = handle_action_create(
        conn,
        &json!({ "namespace": NS, "kind": "k", "title": "t", "agent_id": ALICE }),
    )
    .expect("create ok");
    let id = created[param_names::ID].as_str().expect("id").to_string();
    handle_lease_acquire(
        conn,
        &json!({ "action_id": id.clone(), "holder": ALICE, "ttl_secs": LEASE_TTL_SECS }),
    )
    .expect("alice acquires her lease");
    handle_action_transition(
        conn,
        &json!({ "id": id.clone(), "to": "claimed", "claimed_by": ALICE }),
    )
    .expect("the principal may claim as itself");
    id
}

/// One table row: the claimed identity B sends, and the exact refusal.
struct Row {
    label: &'static str,
    claimed_by: Option<&'static str>,
    expected: fn(&str) -> String,
}

/// #8759 table over the claimed identity (equal / different / absent /
/// malformed) while A's lease is LIVE. B is the principal throughout; every
/// row is refused with its exact error and the stored action is unchanged.
#[test]
fn mcp_transition_claimed_identity_table_live_lease_8759() {
    let env = AgentEnv::new();
    let conn = fresh();
    let id = alice_claims(&conn, &env);
    let before = stored(&conn, &id);
    assert_eq!(before, ("claimed".to_string(), Some(ALICE.to_string())));
    let audit_before = transition_audit_rows(&conn);

    env.set(BOB);
    let rows = [
        Row {
            label: "different (names the holder)",
            claimed_by: Some(ALICE),
            expected: |_| mismatch(BOB, ALICE),
        },
        Row {
            label: "equal (B as itself, but not the holder)",
            claimed_by: Some(BOB),
            expected: |id| {
                format!("claimed_by '{BOB}' is not the live lease holder '{ALICE}' on action {id}")
            },
        },
        Row {
            label: "absent",
            claimed_by: None,
            expected: |id| {
                format!(
                    "action {id} is held by lease holder '{ALICE}': a transition on a leased \
                     action must supply claimed_by matching the holder"
                )
            },
        },
        Row {
            label: "malformed",
            claimed_by: Some(MALFORMED_CLAIM),
            expected: |_| {
                crate::validate::validate_agent_id(MALFORMED_CLAIM)
                    .expect_err("the claim is malformed")
                    .to_string()
            },
        },
    ];
    for to in ["in_progress", "done"] {
        for row in &rows {
            let mut args = json!({ "id": id.clone(), "to": to });
            if let Some(cb) = row.claimed_by {
                args[param_names::CLAIMED_BY] = Value::from(cb);
            }
            let err = handle_action_transition(&conn, &args)
                .expect_err("a non-principal transition must be refused");
            assert_eq!(err, (row.expected)(&id), "row `{}` to {to}", row.label);
            assert_eq!(
                stored(&conn, &id),
                before,
                "row `{}` to {to}: the refusal must leave the action unchanged",
                row.label
            );
        }
    }
    assert_eq!(
        transition_audit_rows(&conn),
        audit_before,
        "a refused transition must not emit an audit row"
    );

    // CONTROL: the principal that holds the lease still transitions.
    env.set(ALICE);
    handle_action_transition(
        &conn,
        &json!({ "id": id.clone(), "to": "in_progress", "claimed_by": ALICE }),
    )
    .expect("the holder transitions as itself");
    assert_eq!(
        stored(&conn, &id),
        ("in_progress".to_string(), Some(ALICE.to_string()))
    );
}

/// #8759 — with NO lease the bind still holds: the lease is not the only
/// ownership guard, the principal is. Pre-fix B could stamp A's name on any
/// lease-free action.
#[test]
fn mcp_transition_claimed_identity_table_no_lease_8759() {
    let env = AgentEnv::new();
    let conn = fresh();
    let id = alice_claims(&conn, &env);
    let released =
        handle_lease_release(&conn, &json!({ "action_id": id.clone(), "holder": ALICE }))
            .expect("release");
    assert_eq!(released["released"], true);
    let before = stored(&conn, &id);

    env.set(BOB);
    // different: refused, unchanged.
    let err = handle_action_transition(
        &conn,
        &json!({ "id": id.clone(), "to": "in_progress", "claimed_by": ALICE }),
    )
    .expect_err("B must not transition as A");
    assert_eq!(err, mismatch(BOB, ALICE));
    assert_eq!(stored(&conn, &id), before);

    // malformed: refused with the shape error, unchanged.
    let err = handle_action_transition(
        &conn,
        &json!({ "id": id.clone(), "to": "in_progress", "claimed_by": MALFORMED_CLAIM }),
    )
    .expect_err("malformed claim refused");
    assert_eq!(
        err,
        crate::validate::validate_agent_id(MALFORMED_CLAIM)
            .expect_err("malformed")
            .to_string()
    );
    assert_eq!(stored(&conn, &id), before);

    // equal: accepted, and the recorded claimant is the principal.
    handle_action_transition(
        &conn,
        &json!({ "id": id.clone(), "to": "in_progress", "claimed_by": BOB }),
    )
    .expect("B may transition as itself");
    assert_eq!(
        stored(&conn, &id),
        ("in_progress".to_string(), Some(BOB.to_string()))
    );
    assert_eq!(
        transition_audit_rows(&conn).last().map(String::as_str),
        Some(BOB),
        "the audit row is attributed to the principal"
    );
}

/// #8759 — fail closed on a set-but-malformed process identity: it is a
/// refusal, never a silent fall-back to the single-operator posture.
#[test]
fn mcp_transition_refuses_under_a_malformed_principal_8759() {
    let env = AgentEnv::new();
    let conn = fresh();
    let id = alice_claims(&conn, &env);
    handle_lease_release(&conn, &json!({ "action_id": id.clone(), "holder": ALICE }))
        .expect("release");
    let before = stored(&conn, &id);

    env.set(MALFORMED_ENV_ID);
    let expected = crate::identity::resolve_mcp_read_visibility_caller()
        .expect_err("the env identity is malformed")
        .to_string();
    let err = handle_action_transition(
        &conn,
        &json!({ "id": id.clone(), "to": "in_progress", "claimed_by": ALICE }),
    )
    .expect_err("a malformed principal must fail closed");
    assert_eq!(err, expected);
    assert_eq!(stored(&conn, &id), before);
}

/// #8759 — the single-operator posture (no `AI_MEMORY_AGENT_ID`) is
/// unchanged: the one operator may name any worker as `claimed_by`.
#[test]
fn mcp_transition_single_operator_posture_unchanged_8759() {
    let env = AgentEnv::new();
    let conn = fresh();
    env.unset();
    let created = handle_action_create(
        &conn,
        &json!({ "namespace": NS, "kind": "k", "title": "t" }),
    )
    .expect("create ok");
    let id = created[param_names::ID].as_str().expect("id").to_string();
    handle_action_transition(
        &conn,
        &json!({ "id": id.clone(), "to": "claimed", "claimed_by": "ai:worker-1" }),
    )
    .expect("single operator names a worker");
    assert_eq!(
        stored(&conn, &id),
        ("claimed".to_string(), Some("ai:worker-1".to_string()))
    );
}

/// #8759 — the audit's exact reproduction (finding a2-code-04): A creates,
/// leases and claims; B's lease acquire as A is refused (the control); B's
/// `in_progress` and `done` transitions naming A must be refused too, and the
/// action must stay A's `claimed` row.
#[test]
fn audit_repro_bob_cannot_drive_alices_leased_action_8759() {
    let env = AgentEnv::new();
    let conn = fresh();
    let id = alice_claims(&conn, &env);

    env.set(BOB);
    let err = handle_lease_acquire(
        &conn,
        &json!({ "action_id": id.clone(), "holder": ALICE, "ttl_secs": LEASE_TTL_SECS }),
    )
    .expect_err("control: B cannot acquire as A");
    assert_eq!(
        err,
        format!(
            "agent_id mismatch: caller '{BOB}' may only acquire a lease as itself \
             (requested '{ALICE}')"
        ),
        "control refusal"
    );

    for to in ["in_progress", "done"] {
        let err = handle_action_transition(
            &conn,
            &json!({ "id": id.clone(), "to": to, "claimed_by": ALICE }),
        )
        .expect_err("B must not transition A's leased action");
        assert_eq!(err, mismatch(BOB, ALICE), "to {to}");
    }
    assert_eq!(
        stored(&conn, &id),
        ("claimed".to_string(), Some(ALICE.to_string()))
    );
    assert_eq!(
        transition_audit_rows(&conn),
        vec![ALICE.to_string()],
        "only A's own claim is in the audit trail"
    );
}

/// #8791 — BY DESIGN, pinned (conductor ruling: actions are a shared work
/// queue inside what the caller may already read). Actions carry no read
/// visibility gate (`memory_action_get` serves any id to any principal), so a
/// peer taking the lease on a visible, UN-HELD action is the queue working.
/// What stays refused: acquiring AS someone else (#3361), stealing a LIVE
/// lease, and renewing or releasing a lease the principal does not hold.
#[test]
fn lease_acquire_on_a_peers_unheld_visible_action_is_the_shared_queue_8791() {
    let env = AgentEnv::new();
    let conn = fresh();
    env.set(ALICE);
    let created = handle_action_create(
        &conn,
        &json!({ "namespace": NS, "kind": "k", "title": "t", "agent_id": ALICE }),
    )
    .expect("create ok");
    let id = created[param_names::ID].as_str().expect("id").to_string();

    env.set(BOB);
    // The visibility premise: B can already read A's action.
    let seen = handle_action_get(&conn, &json!({ "id": id.clone() })).expect("get ok");
    assert_eq!(seen["action"]["agent_id"].as_str(), Some(ALICE));
    // Acquiring as A is refused (the #3361 bind on the same principal).
    let err = handle_lease_acquire(
        &conn,
        &json!({ "action_id": id.clone(), "holder": ALICE, "ttl_secs": LEASE_TTL_SECS }),
    )
    .expect_err("B may not acquire as A");
    assert_eq!(
        err,
        format!(
            "agent_id mismatch: caller '{BOB}' may only acquire a lease as itself (requested '{ALICE}')"
        )
    );
    // Acquiring as itself on the un-held action succeeds: the queue.
    let got = handle_lease_acquire(
        &conn,
        &json!({ "action_id": id.clone(), "holder": BOB, "ttl_secs": LEASE_TTL_SECS }),
    )
    .expect("a peer may lease a visible un-held action");
    assert_eq!(got["lease"]["holder"].as_str(), Some(BOB));

    // A cannot steal B's LIVE lease, nor renew or release it.
    env.set(ALICE);
    let err = handle_lease_acquire(
        &conn,
        &json!({ "action_id": id.clone(), "holder": ALICE, "ttl_secs": LEASE_TTL_SECS }),
    )
    .expect_err("a live lease is exclusive");
    assert_eq!(err, format!("lease conflict: {id} held by another holder"));
    let err = handle_lease_renew(
        &conn,
        &json!({ "action_id": id.clone(), "holder": BOB, "ttl_secs": LEASE_TTL_SECS }),
    )
    .expect_err("A may not renew as B");
    assert_eq!(
        err,
        format!(
            "agent_id mismatch: caller '{ALICE}' may only renew a lease as itself (requested '{BOB}')"
        )
    );
    let err = handle_lease_release(&conn, &json!({ "action_id": id.clone(), "holder": BOB }))
        .expect_err("A may not release as B");
    assert_eq!(
        err,
        format!(
            "agent_id mismatch: caller '{ALICE}' may only release a lease as itself (requested '{BOB}')"
        )
    );
}

/// The audit sweep's second transition row ("B transitions A's claimed action
/// with claimed_by=B"), BY DESIGN, pinned: with NO live lease the stored claim
/// is not an exclusivity guard (leases are the ownership primitive, #3009 /
/// #3360), so B acting honestly AS ITSELF may move a lease-free claimed action,
/// and the row then records B, never A. Taking A's NAME stays refused.
#[test]
fn lease_free_claim_is_not_exclusive_but_identity_stays_bound_8759() {
    let env = AgentEnv::new();
    let conn = fresh();
    env.set(ALICE);
    let created = handle_action_create(
        &conn,
        &json!({ "namespace": NS, "kind": "k", "title": "t", "agent_id": ALICE }),
    )
    .expect("create ok");
    let id = created[param_names::ID].as_str().expect("id").to_string();
    for to in ["claimed", "in_progress"] {
        handle_action_transition(
            &conn,
            &json!({ "id": id.clone(), "to": to, "claimed_by": ALICE }),
        )
        .expect("A drives its own action");
    }

    env.set(BOB);
    let err = handle_action_transition(
        &conn,
        &json!({ "id": id.clone(), "to": "done", "claimed_by": ALICE }),
    )
    .expect_err("B may not act as A");
    assert_eq!(err, mismatch(BOB, ALICE));
    assert_eq!(
        stored(&conn, &id),
        ("in_progress".to_string(), Some(ALICE.to_string()))
    );
    handle_action_transition(
        &conn,
        &json!({ "id": id.clone(), "to": "done", "claimed_by": BOB }),
    )
    .expect("B as itself on a lease-free action");
    assert_eq!(
        stored(&conn, &id),
        ("done".to_string(), Some(BOB.to_string()))
    );
    assert_eq!(
        transition_audit_rows(&conn).last().map(String::as_str),
        Some(BOB),
        "the audit row names the real actor"
    );
}
