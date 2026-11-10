// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8759 sibling (SECURITY) — `memory_checkpoint_resolve` took its acting
//! identity from the caller-supplied `resolved_by`, so agent B could resolve
//! a checkpoint (an approval gate) as agent A, and the signed audit row
//! attributed the decision to A. The resolver is now bound to the
//! authenticated MCP principal (`AI_MEMORY_AGENT_ID`) unless the resolution is
//! operator-attested by a detached signature against the resolver's enrolled
//! key (the #3007 epoch lane, pinned by
//! `epoch_advance_resolve_with_enrolled_operator_sig_accepts_signed_3007_3368`).
//!
//! #8773 is the same finding filed by the audit lane p1-mcp-b (row
//! `memory_checkpoint_resolve/mcp/adversary`): an `approval` checkpoint created
//! by `agent-a` resolved by `agent-b` naming `resolved_by: "agent-a"`.

use serde_json::{Value, json};

use super::{handle_checkpoint_create, handle_checkpoint_resolve, handle_checkpoint_verify};
use crate::mcp::param_names;

const ALICE: &str = "ai:alice-act";
const BOB: &str = "ai:bob-act";
const MALFORMED_ENV_ID: &str = "bad id with spaces";

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
}

fn fresh() -> rusqlite::Connection {
    crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn resolve_audit_rows(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        rusqlite::params![crate::coordination_audit::CHECKPOINT_RESOLVE],
        |r| r.get(0),
    )
    .expect("count audit rows")
}

/// `(state, resolved_by)` of the stored checkpoint.
fn stored(conn: &rusqlite::Connection, id: &str) -> (String, Option<String>) {
    let got = handle_checkpoint_verify(conn, &json!({ "id": id })).expect("verify");
    (
        got["checkpoint"]["state"]
            .as_str()
            .expect("state")
            .to_string(),
        got["checkpoint"]["resolved_by"]
            .as_str()
            .map(str::to_string),
    )
}

fn alice_creates(conn: &rusqlite::Connection, env: &AgentEnv) -> String {
    env.set(ALICE);
    let created = handle_checkpoint_create(
        conn,
        &json!({ "namespace": "_cp_8759", "title": "approve", "created_by": ALICE }),
    )
    .expect("create ok");
    created[param_names::ID]
        .as_str()
        .expect("id present")
        .to_string()
}

/// B must not resolve a checkpoint AS A: refused with the named error, the
/// checkpoint stays pending and no audit row is written. B resolving as
/// itself is unchanged.
#[test]
fn checkpoint_resolve_binds_resolved_by_to_the_principal_8759() {
    let env = AgentEnv::new();
    let conn = fresh();
    let id = alice_creates(&conn, &env);
    let before = stored(&conn, &id);
    assert_eq!(before, ("pending".to_string(), None));

    env.set(BOB);
    for state in ["resolved", "rejected"] {
        let err = handle_checkpoint_resolve(
            &conn,
            &json!({ "id": id.clone(), "state": state, "resolved_by": ALICE }),
            None,
        )
        .expect_err("B must not resolve as A");
        assert_eq!(
            err,
            format!(
                "acting_identity_mismatch: caller '{BOB}' may only resolve a checkpoint as \
                 itself (resolved_by '{ALICE}')"
            ),
            "state {state}"
        );
        assert_eq!(stored(&conn, &id), before, "state {state}: unchanged");
    }
    assert_eq!(
        resolve_audit_rows(&conn),
        0,
        "a refusal writes no audit row"
    );

    // equal: accepted, attributed to the principal.
    let ok = handle_checkpoint_resolve(
        &conn,
        &json!({ "id": id.clone(), "state": "resolved", "resolved_by": BOB }),
        None,
    )
    .expect("B resolves as itself");
    assert_eq!(ok["checkpoint"]["resolved_by"].as_str(), Some(BOB));
    assert_eq!(resolve_audit_rows(&conn), 1);
}

/// A set-but-malformed principal fails CLOSED (never the single-operator
/// fall-back) and leaves the checkpoint pending.
#[test]
fn checkpoint_resolve_refuses_under_a_malformed_principal_8759() {
    let env = AgentEnv::new();
    let conn = fresh();
    let id = alice_creates(&conn, &env);
    env.set(MALFORMED_ENV_ID);
    let expected = crate::identity::resolve_mcp_read_visibility_caller()
        .expect_err("malformed env identity")
        .to_string();
    let err = handle_checkpoint_resolve(
        &conn,
        &json!({ "id": id.clone(), "state": "resolved", "resolved_by": ALICE }),
        None,
    )
    .expect_err("a malformed principal must fail closed");
    assert_eq!(err, expected);
    assert_eq!(stored(&conn, &id), ("pending".to_string(), None));
    assert_eq!(resolve_audit_rows(&conn), 0);
}

/// #8759 / #8773 — the invariant table over the claimed `resolved_by`
/// (different / equal / absent / malformed) under an authenticated principal,
/// for both terminal states. Every refusal is exact, leaves the checkpoint
/// pending and writes no audit row; only the equal row resolves.
#[test]
fn checkpoint_resolve_claimed_identity_table_8759_8773() {
    let env = AgentEnv::new();
    let conn = fresh();
    for state in ["resolved", "rejected"] {
        let id = alice_creates(&conn, &env);
        let audit_before = resolve_audit_rows(&conn);
        env.set(BOB);
        let malformed_err = format!(
            "invalid agent_id: {}",
            crate::validate::validate_agent_id("bad\nid").expect_err("control char")
        );
        let rows: [(&str, Value, String); 3] = [
            (
                "different",
                json!(ALICE),
                format!(
                    "acting_identity_mismatch: caller '{BOB}' may only resolve a checkpoint \
                     as itself (resolved_by '{ALICE}')"
                ),
            ),
            ("absent", Value::Null, "resolved_by is required".to_string()),
            ("malformed", json!("bad\nid"), malformed_err),
        ];
        for (row, resolved_by, expected) in rows {
            let mut args = json!({ "id": id.clone(), "state": state });
            if !resolved_by.is_null() {
                args["resolved_by"] = resolved_by;
            }
            let err = handle_checkpoint_resolve(&conn, &args, None)
                .expect_err("refused row must not resolve");
            assert_eq!(err, expected, "{state}/{row}");
            assert_eq!(
                stored(&conn, &id),
                ("pending".to_string(), None),
                "{state}/{row}: checkpoint unchanged"
            );
            assert_eq!(
                resolve_audit_rows(&conn),
                audit_before,
                "{state}/{row}: no audit row"
            );
        }
        let ok = handle_checkpoint_resolve(
            &conn,
            &json!({ "id": id.clone(), "state": state, "resolved_by": BOB }),
            None,
        )
        .expect("equal row resolves");
        assert_eq!(ok["checkpoint"]["resolved_by"].as_str(), Some(BOB));
        assert_eq!(
            stored(&conn, &id),
            (state.to_string(), Some(BOB.to_string()))
        );
    }
}

/// #8773 — the audit's exact scenario: `agent-a` creates an `approval`
/// checkpoint; `agent-b` resolving it with `resolved_by: "agent-a"` is refused,
/// the checkpoint stays pending and unattributed.
#[test]
fn audit_repro_agent_b_cannot_resolve_as_agent_a_8773() {
    const AGENT_A: &str = "agent-a";
    const AGENT_B: &str = "agent-b";
    let env = AgentEnv::new();
    let conn = fresh();
    env.set(AGENT_A);
    let created = handle_checkpoint_create(
        &conn,
        &json!({
            "namespace": "_cp_8773",
            "title": "approve deploy",
            "condition_type": "approval",
            "created_by": AGENT_A,
        }),
    )
    .expect("create ok");
    let id = created[param_names::ID]
        .as_str()
        .expect("id present")
        .to_string();

    env.set(AGENT_B);
    let err = handle_checkpoint_resolve(
        &conn,
        &json!({ "id": id.clone(), "resolved_by": AGENT_A, "state": "resolved" }),
        None,
    )
    .expect_err("B must not resolve as A");
    assert_eq!(
        err,
        "acting_identity_mismatch: caller 'agent-b' may only resolve a checkpoint as itself \
         (resolved_by 'agent-a')"
    );
    assert_eq!(stored(&conn, &id), ("pending".to_string(), None));
    assert_eq!(resolve_audit_rows(&conn), 0);
}
