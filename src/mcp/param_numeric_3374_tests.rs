// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3374 (#3171 class-3 residue) — table-driven regression suite for the
//! NUMERIC / BOOLEAN parameter shapes that were silently ignored.
//!
//! ## The defect class
//!
//! The MCP path has **no runtime JSON-Schema validation**, so a value whose
//! JSON type contradicts the advertised schema does not fail — it reads as
//! ABSENT through `Value::as_i64()` / `as_u64()` / `as_bool()` and the handler
//! silently substitutes its **server default**. Unlike the #3365 string
//! shapes, nothing here even looks wrong in the response: the call succeeds
//! and returns a well-formed body computed from a value the caller never sent.
//!
//! Each row below is a real, observed fail-open:
//!
//! - `memory_action_create { priority: 7.5 }` stored priority **0** — the
//!   LOWEST rank. `action_frontier` orders `priority DESC`, so the action the
//!   caller marked urgent sorted LAST.
//! - `memory_signal_send { ttl_secs: "3600" }` stored **no `expires_at`**: the
//!   caller asked for an ephemeral signal and got a PERMANENT one the gc
//!   pruner will never reap (a retention-integrity gap).
//! - `memory_lease_acquire { ttl_secs: "600" }` silently took the **60s**
//!   default, so a worker holding what it believed was a 10-minute lease had
//!   it reclaimed under it by the expiry sweep.
//! - `memory_signal_inbox { limit: -5 }` and `memory_inbox { limit: -5 }`
//!   silently became the **50-row** default — MORE rows than asked for.
//! - `memory_inbox { unread_only: "yes" }` read as `false` — the caller asked
//!   for its UNREAD messages and got its ENTIRE inbox.
//! - `memory_rule_list { enabled_only: "true" }` / `{ kind: 123 }` DROPPED the
//!   filter and returned **every governance rule in the substrate** to an
//!   operator who had asked for one kind, or for only the rules the engine
//!   actually enforces.
//!
//! The control is [`crate::mcp::param_guard`]: present-but-wrong-type →
//! refuse; ABSENT → still the documented default. The RANGE stays owned by the
//! domain validator (`validate_ttl_secs`) so its message is not shadowed.

use super::param_names;
use super::{action, notify, rule_list, signal};
use crate::models::field_names;
use serde_json::{Value, json};

/// The converted handlers have three different arities, so the table stores a
/// closure per row rather than a bare fn pointer.
type Adapter = Box<dyn Fn(&rusqlite::Connection, &Value) -> Result<Value, String>>;

const NS: &str = "_pn3374";

fn fresh() -> rusqlite::Connection {
    crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn action_create() -> Adapter {
    Box::new(action::handle_action_create)
}
fn lease_acquire() -> Adapter {
    Box::new(action::handle_lease_acquire)
}
fn lease_renew() -> Adapter {
    Box::new(action::handle_lease_renew)
}
fn signal_send() -> Adapter {
    Box::new(|c, p| signal::handle_signal_send(c, p, None))
}
fn signal_inbox() -> Adapter {
    Box::new(signal::handle_signal_inbox)
}
fn mem_inbox() -> Adapter {
    Box::new(|c, p| notify::handle_inbox(c, p, None, None))
}
fn rule_list_() -> Adapter {
    Box::new(rule_list::handle_rule_list)
}

/// Create one action and take a lease on it, returning the action id — the
/// fixture the `lease_*` rows need so they reach the `ttl_secs` read instead
/// of short-circuiting on "action not found".
fn seed_leased_action(conn: &rusqlite::Connection) -> String {
    let created = action::handle_action_create(
        conn,
        &json!({ "namespace": NS, "kind": "k", "title": "leased work" }),
    )
    .expect("create action");
    let id = created[param_names::ID]
        .as_str()
        .expect("id present")
        .to_string();
    action::handle_lease_acquire(conn, &json!({ "action_id": id, "holder": "ai:worker" }))
        .expect("acquire lease");
    id
}

/// THE regression, DENIED half. Every row FAILS against the pre-#3374
/// handlers: each returned `Ok` with a body computed from the server default.
#[test]
fn numeric_and_boolean_param_shapes_are_refused_3374() {
    let conn = fresh();
    let action_id = seed_leased_action(&conn);

    let cases: Vec<(&str, Adapter, Value, &str)> = vec![
        // --- i64 counts / ranks: a float, a stringy number or a bool read as
        // ABSENT and took the server default.
        (
            "memory_action_create",
            action_create(),
            json!({ "namespace": NS, "kind": "k", "title": "t", "priority": 7.5 }),
            "priority must be an integer",
        ),
        (
            "memory_action_create",
            action_create(),
            json!({ "namespace": NS, "kind": "k", "title": "t", "priority": "9" }),
            "priority must be an integer",
        ),
        (
            "memory_lease_acquire",
            lease_acquire(),
            json!({ "action_id": action_id, "holder": "ai:worker", "ttl_secs": "600" }),
            "ttl_secs must be an integer",
        ),
        (
            "memory_lease_renew",
            lease_renew(),
            json!({ "action_id": action_id, "holder": "ai:worker", "ttl_secs": 600.5 }),
            "ttl_secs must be an integer",
        ),
        (
            "memory_signal_send",
            signal_send(),
            json!({ "namespace": NS, "from_agent": "a", "subject": "s", "ttl_secs": "3600" }),
            "ttl_secs must be an integer",
        ),
        // --- limits: `as_u64()` cannot tell a NEGATIVE from absent, so a
        // bounded page silently became the 50-row default.
        (
            "memory_signal_inbox",
            signal_inbox(),
            json!({ "namespace": NS, "limit": -5 }),
            "limit must be a non-negative integer",
        ),
        (
            "memory_signal_inbox",
            signal_inbox(),
            json!({ "namespace": NS, "limit": "10" }),
            "limit must be a non-negative integer",
        ),
        (
            "memory_inbox",
            mem_inbox(),
            json!({ "limit": -5 }),
            "limit must be a non-negative integer",
        ),
        // --- safety / narrowing booleans: the stringy-truth shape an LLM
        // caller emits most often read as `false` and WIDENED the result.
        (
            "memory_inbox",
            mem_inbox(),
            json!({ "unread_only": "yes" }),
            "unread_only must be a boolean",
        ),
        (
            "memory_rule_list",
            rule_list_(),
            json!({ "enabled_only": "true" }),
            "enabled_only must be a boolean",
        ),
        (
            "memory_rule_list",
            rule_list_(),
            json!({ "enabled_only": 1 }),
            "enabled_only must be a boolean",
        ),
        (
            "memory_rule_list",
            rule_list_(),
            json!({ "kind": 123 }),
            "invalid kind: expected a string",
        ),
    ];

    for (tool, handler, params, expect) in cases {
        match handler(&conn, &params) {
            Ok(v) => panic!(
                "{tool} {params} must be REFUSED (#3374); it silently used a server default and \
                 returned: {v}"
            ),
            Err(e) => assert_eq!(e, expect, "{tool} {params}"),
        }
    }

    // A blank `kind` is refused too; the raw value is echoed so the operator
    // can see what was sent, hence the prefix assertion.
    let blank = rule_list::handle_rule_list(&conn, &json!({ "kind": "   " }))
        .expect_err("blank kind refused");
    assert!(blank.starts_with("invalid kind:"), "got: {blank}");
}

/// THE regression, ALLOWED half. Refusing everything would also satisfy the
/// denials above, so pin that a well-formed value is HONOURED (not silently
/// replaced by the default) and that an ABSENT value still takes the
/// documented default.
#[test]
fn well_formed_numeric_and_boolean_params_are_honoured_3374() {
    let conn = fresh();

    // priority: the supplied rank is stored, and an ABSENT priority still
    // defaults to 0.
    let urgent = action::handle_action_create(
        &conn,
        &json!({ "namespace": NS, "kind": "k", "title": "urgent", "priority": 9 }),
    )
    .expect("create with priority");
    assert_eq!(urgent["action"]["priority"].as_i64(), Some(9));
    let plain = action::handle_action_create(
        &conn,
        &json!({ "namespace": NS, "kind": "k", "title": "plain" }),
    )
    .expect("create without priority");
    assert_eq!(plain["action"]["priority"].as_i64(), Some(0));
    // A NEGATIVE priority still passes the TYPE gate — the guard checks the
    // shape, not the domain.
    let deprioritised = action::handle_action_create(
        &conn,
        &json!({ "namespace": NS, "kind": "k", "title": "later", "priority": -3 }),
    )
    .expect("create with negative priority");
    assert_eq!(deprioritised["action"]["priority"].as_i64(), Some(-3));

    // ttl_secs: the RANGE is still owned by `validate_ttl_secs`, whose message
    // must not be shadowed by the new type check.
    let action_id = urgent[param_names::ID].as_str().expect("id").to_string();
    let ranged = action::handle_lease_acquire(
        &conn,
        &json!({ "action_id": action_id, "holder": "ai:w", "ttl_secs": 0 }),
    )
    .expect_err("ttl_secs 0 is out of range");
    assert!(
        !ranged.contains("must be an integer"),
        "the domain validator must still own the range: {ranged}"
    );
    let leased = action::handle_lease_acquire(
        &conn,
        &json!({ "action_id": action_id, "holder": "ai:w", "ttl_secs": 600 }),
    )
    .expect("well-formed ttl_secs");
    let expires_at = leased["lease"]["expires_at"].as_i64().expect("expires_at");
    let now = chrono::Utc::now().timestamp();
    assert!(
        expires_at > now + 500,
        "the supplied 600s TTL must be honoured, not replaced by the 60s default \
         (expires_at={expires_at}, now={now})"
    );

    // signal ttl_secs: supplied -> an expiry is stamped; ABSENT -> none.
    let ephemeral = signal::handle_signal_send(
        &conn,
        &json!({ "namespace": NS, "from_agent": "a", "subject": "s", "ttl_secs": 3600 }),
        None,
    )
    .expect("send with ttl");
    assert!(ephemeral["signal"]["expires_at"].as_i64().is_some());
    let permanent = signal::handle_signal_send(
        &conn,
        &json!({ "namespace": NS, "from_agent": "a", "subject": "s" }),
        None,
    )
    .expect("send without ttl");
    assert!(permanent["signal"]["expires_at"].is_null());

    // limits: a well-formed limit NARROWS, an absent one defaults, and 0 still
    // honestly means "no rows".
    let one = signal::handle_signal_inbox(&conn, &json!({ "namespace": NS, "limit": 1 }))
        .expect("limit 1");
    assert_eq!(one["signals"].as_array().expect("array").len(), 1);
    let all = signal::handle_signal_inbox(&conn, &json!({ "namespace": NS })).expect("no limit");
    assert_eq!(all["signals"].as_array().expect("array").len(), 2);
    let none = signal::handle_signal_inbox(&conn, &json!({ "namespace": NS, "limit": 0 }))
        .expect("limit 0");
    assert_eq!(none["signals"].as_array().expect("array").len(), 0);

    // memory_inbox: well-formed bool + limit still answer.
    let inbox = notify::handle_inbox(
        &conn,
        &json!({ (field_names::UNREAD_ONLY): true, (param_names::LIMIT): 10 }),
        None,
        None,
    )
    .expect("well-formed inbox");
    assert!(inbox.get("messages").is_some(), "got: {inbox}");
    let defaulted = notify::handle_inbox(&conn, &json!({}), None, None).expect("absent filters");
    assert!(defaulted.get("messages").is_some());

    // rule_list: well-formed filters still answer, and an ABSENT filter still
    // means "every rule".
    let enabled =
        rule_list::handle_rule_list(&conn, &json!({ "enabled_only": true })).expect("enabled_only");
    assert!(enabled.get("count").is_some(), "got: {enabled}");
    let by_kind = rule_list::handle_rule_list(&conn, &json!({ "kind": "filesystem_write" }))
        .expect("kind filter");
    assert!(by_kind.get("count").is_some());
    let unfiltered = rule_list::handle_rule_list(&conn, &json!({})).expect("no filter");
    assert!(unfiltered.get("count").is_some());
}
