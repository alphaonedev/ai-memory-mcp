// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8759 (SECURITY) — the GA dogfood audit's exact reproduction (finding
//! a2-code-04), driven over two real `ai-memory mcp` stdio children that
//! share one database, each bound to its own `AI_MEMORY_AGENT_ID`.
//!
//! Agent A (`ai:alice-act`) creates an action, takes its lease and claims it.
//! Agent B (`ai:bob-act`) is refused a lease acquire naming A (the control,
//! #3361). Pre-fix B could still drive A's action to `in_progress` and `done`
//! by naming A as `claimed_by`, and the audit row then attributed those
//! transitions to A. Both transitions must be refused with the named
//! `acting_identity_mismatch` error and the action must stay A's `claimed` row.
//!
//! #8773 (same class) — the audit's checkpoint scenario over the same two
//! children: B resolving A's `approval` checkpoint as `resolved_by: A` is
//! refused, the checkpoint stays pending and no resolve audit row is written.

use serde_json::json;

#[path = "common/mcp_wait.rs"]
mod mcp_wait;

#[path = "common/mcp_stdio_child.rs"]
mod mcp_stdio_child;

use mcp_stdio_child::{Fixture, Mcp};

const ALICE: &str = "ai:alice-act";
const BOB: &str = "ai:bob-act";
const NS: &str = "audit-8759";
const LEASE_TTL_SECS: i64 = 600;

fn mismatch(caller: &str, claimed: &str) -> String {
    format!(
        "acting_identity_mismatch: caller '{caller}' may only transition an action as itself \
         (claimed_by '{claimed}')"
    )
}

/// `(state, claimed_by)` straight from the shared database.
fn stored(fixture: &Fixture, id: &str) -> (String, Option<String>) {
    let conn = ai_memory::db::open(&fixture.db).expect("open");
    let action = ai_memory::actions::get(&conn, id)
        .expect("get")
        .expect("action present");
    (action.state.as_str().to_string(), action.claimed_by)
}

fn transition_audit_agents(fixture: &Fixture) -> Vec<String> {
    let conn = ai_memory::db::open(&fixture.db).expect("open");
    let mut stmt = conn
        .prepare("SELECT agent_id FROM signed_events WHERE event_type = ?1 ORDER BY rowid")
        .expect("prepare");
    stmt.query_map([ai_memory::coordination_audit::ACTION_TRANSITION], |r| {
        r.get::<_, String>(0)
    })
    .expect("query")
    .map(|r| r.expect("row"))
    .collect()
}

#[test]
fn audit_repro_bob_cannot_transition_alices_leased_action_over_stdio_8759() {
    let fixture = Fixture::new();

    // A: create, lease, claim.
    let mut alice = Mcp::start(&fixture, Some(ALICE));
    alice.call_ok(
        "memory_action_create",
        &json!({ "namespace": NS, "kind": "k", "title": "audit 8759", "agent_id": ALICE }),
    );
    let id = {
        let conn = ai_memory::db::open(&fixture.db).expect("open");
        let listed = ai_memory::actions::list(&conn, Some(NS), None, 10).expect("list");
        assert_eq!(listed.len(), 1, "exactly one action in {NS}");
        listed[0].id.clone()
    };
    alice.call_ok(
        "memory_lease_acquire",
        &json!({ "action_id": id, "holder": ALICE, "ttl_secs": LEASE_TTL_SECS }),
    );
    alice.call_ok(
        "memory_action_transition",
        &json!({ "id": id, "to": "claimed", "claimed_by": ALICE }),
    );
    assert_eq!(
        stored(&fixture, &id),
        ("claimed".to_string(), Some(ALICE.to_string()))
    );

    // B: the control — B cannot acquire A's lease by naming A.
    let mut bob = Mcp::start(&fixture, Some(BOB));
    let control = bob.call(
        "memory_lease_acquire",
        &json!({ "action_id": id, "holder": ALICE, "ttl_secs": LEASE_TTL_SECS }),
    );
    assert_eq!(control["isError"], true, "control: {control}");
    assert_eq!(
        Mcp::text(&control),
        format!(
            "agent_id mismatch: caller '{BOB}' may only acquire a lease as itself \
             (requested '{ALICE}')"
        )
    );

    // B: the defect — transitions naming A must be refused too.
    for to in ["in_progress", "done"] {
        let result = bob.call(
            "memory_action_transition",
            &json!({ "id": id, "to": to, "claimed_by": ALICE }),
        );
        assert_eq!(
            result["isError"], true,
            "B -> {to} must be refused: {result}"
        );
        assert_eq!(Mcp::text(&result), mismatch(BOB, ALICE), "B -> {to}");
        assert_eq!(
            stored(&fixture, &id),
            ("claimed".to_string(), Some(ALICE.to_string())),
            "B -> {to}: the action must stay A's claimed row"
        );
    }
    assert_eq!(
        transition_audit_agents(&fixture),
        vec![ALICE.to_string()],
        "only A's own claim is in the audit trail"
    );

    // CONTROL: A still drives its own action.
    alice.call_ok(
        "memory_action_transition",
        &json!({ "id": id, "to": "in_progress", "claimed_by": ALICE }),
    );
    assert_eq!(
        stored(&fixture, &id),
        ("in_progress".to_string(), Some(ALICE.to_string()))
    );
}

fn checkpoint_resolve_audit_rows(fixture: &Fixture) -> usize {
    let conn = ai_memory::db::open(&fixture.db).expect("open");
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            [ai_memory::coordination_audit::CHECKPOINT_RESOLVE],
            |r| r.get(0),
        )
        .expect("count");
    usize::try_from(n).expect("non-negative count")
}

#[test]
fn audit_repro_bob_cannot_resolve_alices_checkpoint_over_stdio_8773() {
    const CP_NS: &str = "audit-8773";
    let fixture = Fixture::new();

    let mut alice = Mcp::start(&fixture, Some(ALICE));
    alice.call_ok(
        "memory_checkpoint_create",
        &json!({ "namespace": CP_NS, "title": "approve deploy",
                 "condition_type": "approval", "created_by": ALICE }),
    );
    let id = {
        let conn = ai_memory::db::open(&fixture.db).expect("open");
        let listed = ai_memory::checkpoints::list(&conn, CP_NS, None, 10).expect("list");
        assert_eq!(listed.len(), 1, "exactly one checkpoint in {CP_NS}");
        listed[0].id.clone()
    };
    let pending = |fixture: &Fixture| {
        let conn = ai_memory::db::open(&fixture.db).expect("open");
        let cp = ai_memory::checkpoints::get(&conn, &id)
            .expect("get")
            .expect("checkpoint present");
        (cp.state.as_str().to_string(), cp.resolved_by)
    };

    let mut bob = Mcp::start(&fixture, Some(BOB));
    let result = bob.call(
        "memory_checkpoint_resolve",
        &json!({ "id": id, "state": "resolved", "resolved_by": ALICE }),
    );
    assert_eq!(result["isError"], true, "B as A must be refused: {result}");
    assert_eq!(
        Mcp::text(&result),
        format!(
            "acting_identity_mismatch: caller '{BOB}' may only resolve a checkpoint as itself \
             (resolved_by '{ALICE}')"
        )
    );
    assert_eq!(pending(&fixture), ("pending".to_string(), None));
    assert_eq!(checkpoint_resolve_audit_rows(&fixture), 0);

    // CONTROL: A resolves its own checkpoint as itself.
    alice.call_ok(
        "memory_checkpoint_resolve",
        &json!({ "id": id, "state": "resolved", "resolved_by": ALICE }),
    );
    assert_eq!(
        pending(&fixture),
        ("resolved".to_string(), Some(ALICE.to_string()))
    );
    assert_eq!(checkpoint_resolve_audit_rows(&fixture), 1);
}
