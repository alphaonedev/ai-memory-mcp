// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3365 (#3171 residue) — table-driven fail-open parameter-shape regression
//! suite for the coordination read surfaces.
//!
//! ## The defect class
//!
//! The MCP path has **no runtime JSON-Schema validation**: every handler
//! reaches into the raw `arguments` bag. Six coordination readers still read
//! it with `.and_then(Value::as_str).unwrap_or_default()`, so a value whose
//! JSON type or domain contradicts the advertised schema did not fail — it
//! took the fallback branch and FAILED OPEN in one of two ways:
//!
//! 1. a schema-REQUIRED string degraded to `""`, which matches no row, so the
//!    caller got a plausible EMPTY SUCCESS (`{"action": null}`,
//!    `{"signals": []}`, `verified: false`) instead of a correctable error —
//!    "your id was malformed" is indistinguishable from "no such row", and
//!    `memory_checkpoint_verify {}` reads as "verification FAILED";
//! 2. an optional FILTER (`to_agent`, `namespace`, `state`) that was present
//!    but contradictory was DROPPED, WIDENING the result set — the caller got
//!    strictly more rows than it asked for. `memory_signal_inbox {to_agent:
//!    123}` handed back every OTHER agent's direct signals, a confidentiality
//!    leak; `memory_action_list {state: 5}` handed `done`/`failed` rows to a
//!    worker polling for `pending` work.
//!
//! The control is [`crate::mcp::param_guard`]: required → refuse, present-but-
//! wrong-type → refuse, ABSENT optional → still the documented default. This
//! module drives the WHOLE converted family through one table so a future
//! handler that regresses to `unwrap_or_default()` fails here, and pins the
//! ALLOWED path alongside each denial so the guards cannot be "fixed" by
//! refusing everything.

use super::param_names;
use super::{action, checkpoint, signal};
use serde_json::{Value, json};

/// Every converted handler shares the MCP dispatch signature, which is what
/// lets one table drive the whole family.
type Handler = fn(&rusqlite::Connection, &Value) -> Result<Value, String>;

const NS: &str = "_ps3365";
const ALICE: &str = "ai:alice";
const BOB: &str = "ai:bob";

fn fresh() -> rusqlite::Connection {
    crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

/// Ids of the seeded fixture rows: `(pending action, done action, signal to
/// alice, signal to bob, checkpoint)`.
struct Seeded {
    pending_action: String,
    done_action: String,
    signal_to_alice: String,
    signal_to_bob: String,
    checkpoint: String,
}

fn id_of(v: &Value) -> String {
    v[param_names::ID]
        .as_str()
        .expect("handler returns an id")
        .to_string()
}

/// One namespace holding: two actions (one `pending`, one driven to `done`
/// over the legal `pending -> claimed -> in_progress -> done` edges) joined by
/// an edge, two DIRECT signals to two different agents, and one checkpoint —
/// the minimum corpus in which a DROPPED filter is observable as extra rows.
fn seed(conn: &rusqlite::Connection) -> Seeded {
    let pending = id_of(
        &action::handle_action_create(
            conn,
            &json!({ "namespace": NS, "kind": "k", "title": "pending work" }),
        )
        .expect("create pending action"),
    );
    let done = id_of(
        &action::handle_action_create(
            conn,
            &json!({ "namespace": NS, "kind": "k", "title": "finished work" }),
        )
        .expect("create done action"),
    );
    for to in ["claimed", "in_progress", "done"] {
        action::handle_action_transition(conn, &json!({ "id": done, "to": to }))
            .unwrap_or_else(|e| panic!("transition to {to}: {e}"));
    }
    action::handle_action_add_edge(
        conn,
        &json!({ "from_action": pending, "to_action": done, "edge_type": "requires" }),
    )
    .expect("add edge");

    let to_alice = id_of(
        &signal::handle_signal_send(
            conn,
            &json!({
                "namespace": NS, "from_agent": ALICE, "subject": "for alice",
                "to_agent": ALICE,
            }),
            None,
        )
        .expect("send signal to alice"),
    );
    let to_bob = id_of(
        &signal::handle_signal_send(
            conn,
            &json!({
                "namespace": NS, "from_agent": BOB, "subject": "for bob",
                "to_agent": BOB,
            }),
            None,
        )
        .expect("send signal to bob"),
    );

    let checkpoint = id_of(
        &checkpoint::handle_checkpoint_create(conn, &json!({ "namespace": NS, "title": "gate" }))
            .expect("create checkpoint"),
    );

    Seeded {
        pending_action: pending,
        done_action: done,
        signal_to_alice: to_alice,
        signal_to_bob: to_bob,
        checkpoint,
    }
}

/// THE regression, denied half. Every row FAILS against the pre-#3365
/// handlers: each returned `Ok` with a plausible empty/widened body.
#[test]
fn coordination_readers_refuse_contradictory_param_shapes_3365() {
    let conn = fresh();
    let _seeded = seed(&conn);

    let cases: Vec<(&str, Handler, Value, &str)> = vec![
        // --- class 1: a schema-REQUIRED string, absent / blank / wrong type.
        // Pre-fix each answered `{"action": null}` / `{"signal": null}` /
        // `verified: false` — an empty SUCCESS for a question never asked.
        (
            "memory_action_get",
            action::handle_action_get,
            json!({}),
            "id is required",
        ),
        (
            "memory_action_get",
            action::handle_action_get,
            json!({ "id": "" }),
            "id is required",
        ),
        (
            "memory_action_get",
            action::handle_action_get,
            json!({ "id": 7 }),
            "id is required",
        ),
        (
            "memory_action_edges",
            action::handle_action_edges,
            json!({}),
            "id is required",
        ),
        (
            "memory_action_edges",
            action::handle_action_edges,
            json!({ "id": "   " }),
            "id is required",
        ),
        (
            "memory_signal_read",
            signal::handle_signal_read,
            json!({}),
            "id is required",
        ),
        (
            "memory_signal_read",
            signal::handle_signal_read,
            json!({ "id": false }),
            "id is required",
        ),
        (
            "memory_checkpoint_verify",
            checkpoint::handle_checkpoint_verify,
            json!({}),
            "id is required",
        ),
        (
            "memory_checkpoint_verify",
            checkpoint::handle_checkpoint_verify,
            json!({ "id": "" }),
            "id is required",
        ),
        (
            "memory_signal_inbox",
            signal::handle_signal_inbox,
            json!({}),
            "namespace is required",
        ),
        (
            "memory_signal_inbox",
            signal::handle_signal_inbox,
            json!({ "namespace": 1 }),
            "namespace is required",
        ),
        // --- class 2: an optional FILTER present but contradictory. Pre-fix
        // the filter was DROPPED and the caller got strictly MORE rows.
        (
            "memory_signal_inbox",
            signal::handle_signal_inbox,
            json!({ "namespace": NS, "to_agent": 123 }),
            "invalid to_agent: expected a non-empty string",
        ),
        (
            "memory_signal_inbox",
            signal::handle_signal_inbox,
            json!({ "namespace": NS, "to_agent": "  " }),
            "invalid to_agent: expected a non-empty string",
        ),
        (
            "memory_action_list",
            action::handle_action_list,
            json!({ "namespace": NS, "state": 5 }),
            "invalid state: expected a string",
        ),
        (
            "memory_action_list",
            action::handle_action_list,
            json!({ "namespace": NS, "state": "pendingg" }),
            "invalid state: pendingg",
        ),
        (
            "memory_action_list",
            action::handle_action_list,
            json!({ "namespace": 5 }),
            "invalid namespace: expected a non-empty string",
        ),
    ];

    for (tool, handler, params, expect) in cases {
        match handler(&conn, &params) {
            Ok(v) => panic!(
                "{tool} {params} must be REFUSED (#3365); it returned a plausible success: {v}"
            ),
            Err(e) => assert_eq!(e, expect, "{tool} {params}"),
        }
    }

    // The seed is untouched by every refusal above: a guard that refuses must
    // not also mutate (`memory_signal_read` stamps `read_at` on the way out).
    let inbox = signal::handle_signal_inbox(&conn, &json!({ "namespace": NS }))
        .expect("well-formed inbox still answers");
    assert_eq!(
        inbox["signals"].as_array().expect("signals array").len(),
        2,
        "both seeded signals are still unacked and readable"
    );
}

/// THE regression, ALLOWED half. Refusing everything would also "fix" the
/// denials above, so pin that a well-formed call still answers — and answers
/// with EXACTLY the rows asked for, not the widened set the dropped filter
/// used to return.
#[test]
fn coordination_readers_still_answer_well_formed_calls_3365() {
    let conn = fresh();
    let seeded = seed(&conn);

    // Required-id readers resolve their row.
    let got = action::handle_action_get(&conn, &json!({ "id": seeded.pending_action }))
        .expect("action_get answers");
    assert_eq!(
        got["action"]["id"].as_str(),
        Some(seeded.pending_action.as_str())
    );
    // An id that is well-formed but names no row is still a NULL success —
    // the guard refuses malformed input, it does not turn "absent" into an
    // error (that distinction is the whole point).
    let missing =
        action::handle_action_get(&conn, &json!({ "id": "act-nope" })).expect("absent is Ok");
    assert_eq!(missing["action"], Value::Null);

    let edges = action::handle_action_edges(&conn, &json!({ "id": seeded.pending_action }))
        .expect("action_edges answers");
    assert_eq!(edges["edges"].as_array().expect("edges array").len(), 1);

    let read = signal::handle_signal_read(&conn, &json!({ "id": seeded.signal_to_alice }))
        .expect("signal_read answers");
    assert_eq!(
        read["signal"]["id"].as_str(),
        Some(seeded.signal_to_alice.as_str())
    );

    let verified = checkpoint::handle_checkpoint_verify(&conn, &json!({ "id": seeded.checkpoint }))
        .expect("checkpoint_verify answers");
    assert_eq!(
        verified["checkpoint"]["id"].as_str(),
        Some(seeded.checkpoint.as_str())
    );

    // A well-formed `to_agent` returns ONLY that recipient's direct signals —
    // the confidentiality boundary the dropped filter used to erase.
    let alice_inbox =
        signal::handle_signal_inbox(&conn, &json!({ "namespace": NS, "to_agent": ALICE }))
            .expect("inbox answers");
    let alice_ids: Vec<&str> = alice_inbox["signals"]
        .as_array()
        .expect("signals array")
        .iter()
        .filter_map(|s| s["id"].as_str())
        .collect();
    assert_eq!(alice_ids, vec![seeded.signal_to_alice.as_str()]);
    assert!(
        !alice_ids.contains(&seeded.signal_to_bob.as_str()),
        "alice must never see bob's direct signal"
    );

    // A well-formed `state` narrows; an ABSENT filter still means "all".
    let pending =
        action::handle_action_list(&conn, &json!({ "namespace": NS, "state": "pending" }))
            .expect("list pending");
    let pending_ids: Vec<&str> = pending["actions"]
        .as_array()
        .expect("actions array")
        .iter()
        .filter_map(|a| a["id"].as_str())
        .collect();
    assert_eq!(pending_ids, vec![seeded.pending_action.as_str()]);
    assert!(!pending_ids.contains(&seeded.done_action.as_str()));

    let all = action::handle_action_list(&conn, &json!({ "namespace": NS })).expect("list all");
    assert_eq!(all["actions"].as_array().expect("actions array").len(), 2);
    let unscoped = action::handle_action_list(&conn, &json!({})).expect("list unscoped");
    assert_eq!(
        unscoped["actions"].as_array().expect("actions array").len(),
        2,
        "an absent namespace filter still means every namespace"
    );
}
