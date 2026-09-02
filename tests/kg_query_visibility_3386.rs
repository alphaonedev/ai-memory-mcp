// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3386 — `memory_kg_query`'s `namespace` and `as_agent` params were DEAD on
//! the main (`source_id`) traversal path, and negative bounds were silently
//! coerced.
//!
//! ## The hole
//!
//! Both params were read only INSIDE the `by_source_uri` branch
//! (`src/mcp/tools/kg_query.rs:97,106` pre-fix), so on the main traversal path:
//!
//! - `namespace` — a documented MCP param AND the `ai-memory kg-query
//!   --namespace` CLI flag — was silently ignored: the caller got the whole
//!   reachable set back, not the namespace they asked for. Wrong results, not
//!   fewer.
//! - `as_agent`, documented since #3171 as "#151 scope-visibility agent;
//!   mirrors `memory_search.as_agent`", did NOTHING. `as_agent:"ai:bob"` still
//!   returned alice's `scope=private` node with its title, namespace and graph
//!   position in full. The #1935 post-filter that exists on this path keys ONLY
//!   on the enforced `AI_MEMORY_AGENT_ID` caller, so on the single-operator
//!   default (env unset — the zero-config posture) NO gate ran at all.
//! - `max_depth` / `limit` went through `Value::as_u64`, which returns `None`
//!   for a negative — indistinguishable from "absent" — so `max_depth:-1`
//!   silently became the server default of 1 and `limit:-5` became "no cap".
//!   The same defect class #3171's `param_guard::optional_non_negative_u64`
//!   closed elsewhere, on two params that audit missed.
//!
//! ## The control
//!
//! `namespace`, `as_agent` and `limit` are read ONCE at handler ingress, ahead
//! of the `by_source_uri` branch, so both traversal paths share one gate. That
//! gate is `kg_query::node_visible`, two narrowing steps a node must both pass:
//!
//! 1. the enforced-caller gate — the canonical `visibility::is_visible_to_caller`
//!    (#951) keyed on `AI_MEMORY_AGENT_ID`, unchanged from #1935;
//! 2. the #151 scope-agent gate — `visibility::is_visible_to_scope_agent`, the
//!    in-process twin of the SQL `visibility_clause` that `memory_search` and
//!    `db::list_by_source_uri` bind, so the two really do mirror: the
//!    team/unit/org SUBTREE arms key on `as_agent`, while the owner-keyed
//!    PRIVATE arm keys on the identified caller and FAILS CLOSED when there is
//!    none. Keying private on `as_agent` instead would let a wire value unlock
//!    another principal's private rows on the `by_source_uri` path, whose
//!    baseline is fail-closed — a widening, which is the one thing a read
//!    filter must never do.
//!
//! Each step can only remove rows, so `as_agent` can never widen past the
//! enforced caller. Negative bounds are refused via
//! `param_guard::optional_non_negative_u64`.
//!
//! ## What this pins (MCP `handle_kg_query`, sqlite)
//!
//! DENIED: a supplied `as_agent` with no identified caller (the sweep's exact
//! repro — alice's private node vanishes instead of coming back in full), an
//! enforced non-owner caller, an `as_agent` OUTSIDE a team-scoped row's
//! subtree, a non-matching `namespace`, and both negative bounds — on the main
//! path and on the `by_source_uri` path. ALLOWED: the enforced owner-caller,
//! an `as_agent` INSIDE the subtree, the matching `namespace`, positive
//! bounds, and the zero-config default (no filters, env unset) which must stay
//! byte-unchanged.

use std::sync::Mutex;

use ai_memory::db;
use ai_memory::mcp::handle_kg_query;
use ai_memory::models::{Memory, MemoryKind, Tier};
use rusqlite::Connection;
use serde_json::{Value, json};

mod common;

/// Serialises every test in this binary: they all read / mutate the
/// process-global `AI_MEMORY_AGENT_ID`, mirroring the crate-wide
/// `identity::env_var_lock` discipline (#1772) for the integration-test
/// surface (which cannot reach that `pub(crate)` guard).
static ENV_GUARD: Mutex<()> = Mutex::new(());

const ENV_AGENT_ID: &str = "AI_MEMORY_AGENT_ID";

const ALICE: &str = "ai:alice";
const BOB: &str = "ai:bob";
const PUB_NS: &str = "team/pub";
const PRIV_NS: &str = "team/priv";
const DOC_URI: &str = "doc:3386";

/// RAII fixture: hold `ENV_GUARD` and pin `AI_MEMORY_AGENT_ID` to `caller`
/// (or leave it unset for the single-operator default), restoring the unset
/// state on drop — including on an assertion panic, so a failure cannot leak
/// the var into a sibling test.
struct Posture {
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl Posture {
    /// Single-operator default: `AI_MEMORY_AGENT_ID` unset (trust-all reads).
    fn single_operator() -> Self {
        let lock = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: env mutation is serialised by `ENV_GUARD`, held here.
        unsafe { std::env::remove_var(ENV_AGENT_ID) };
        Self { _lock: lock }
    }

    /// Multi-tenant posture: `AI_MEMORY_AGENT_ID` = `caller`.
    fn enforced(caller: &str) -> Self {
        let lock = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: env mutation is serialised by `ENV_GUARD`, held here.
        unsafe { std::env::set_var(ENV_AGENT_ID, caller) };
        Self { _lock: lock }
    }
}

impl Drop for Posture {
    fn drop(&mut self) {
        // SAFETY: env mutation is serialised by the `ENV_GUARD` guard this
        // struct still holds.
        unsafe { std::env::remove_var(ENV_AGENT_ID) };
    }
}

/// Seed one memory owned by `owner`. A `None` `scope` leaves the key ABSENT,
/// which per the NHI contract IS owner-keyed private — the exact shape the
/// sweep used.
fn seed_scoped(
    conn: &Connection,
    ns: &str,
    title: &str,
    owner: &str,
    scope: Option<&str>,
    source_uri: Option<&str>,
) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body of {title}"),
        priority: 5,
        confidence: 1.0,
        source: "test-3386".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: match scope {
            Some(sc) => json!({ "agent_id": owner, "scope": sc }),
            None => json!({ "agent_id": owner }),
        },
        memory_kind: MemoryKind::Observation,
        source_uri: source_uri.map(str::to_string),
        version: 1,
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("insert memory")
}

/// Owner-keyed private (scope key absent) — the default shape.
fn seed(conn: &Connection, ns: &str, title: &str, owner: &str, source_uri: Option<&str>) -> String {
    seed_scoped(conn, ns, title, owner, None, source_uri)
}

/// `(conn, source_id, private_target_id)` — a public-ish root owned by alice
/// linked to alice's private target in a DIFFERENT namespace, so the namespace
/// filter and the visibility filter are independently observable.
fn fixture() -> (Connection, String, String) {
    let conn = common::fresh_conn();
    let src = seed(&conn, PUB_NS, "kg source", ALICE, None);
    let tgt = seed(&conn, PRIV_NS, "alice secret", ALICE, None);
    db::create_link(&conn, &src, &tgt, "related_to").expect("link");
    (conn, src, tgt)
}

fn titles(env: &Value) -> Vec<String> {
    env["memories"]
        .as_array()
        .expect("memories array")
        .iter()
        .filter_map(|m| m["title"].as_str().map(str::to_string))
        .collect()
}

fn count(env: &Value) -> u64 {
    env["count"].as_u64().expect("count")
}

// ---------------------------------------------------------------------------
// as_agent — the headline leak
// ---------------------------------------------------------------------------

#[test]
fn as_agent_with_no_identified_caller_hides_the_private_node() {
    // DENIED — the sweep's exact repro. Zero-config posture (env unset): the
    // only gate this path had keyed on the enforced caller, so with the env
    // unset NOTHING filtered and `as_agent:"ai:bob"` returned alice's
    // scope=private node with title, namespace and graph position in full.
    // The private arm is now caller-keyed and fails closed, matching what the
    // SQL `visibility_clause` already did for `memory_search`.
    let _p = Posture::single_operator();
    let (conn, src, _tgt) = fixture();

    let out = handle_kg_query(&conn, &json!({"source_id": src, "as_agent": BOB}))
        .expect("query itself succeeds — the node is filtered, not an error");
    assert_eq!(
        count(&out),
        0,
        "an unidentified caller must not read a private node, got {out}"
    );
    assert!(titles(&out).is_empty(), "no titles may leak, got {out}");
    assert!(
        out["paths"].as_array().expect("paths array").is_empty(),
        "the graph POSITION must not leak either, got {out}"
    );

    // Same rule regardless of WHICH agent is named: naming the owner does not
    // unlock the row either, because `as_agent` is self-asserted and the
    // private arm keys on the identified caller.
    let out =
        handle_kg_query(&conn, &json!({"source_id": src, "as_agent": ALICE})).expect("query ok");
    assert_eq!(
        count(&out),
        0,
        "a self-asserted as_agent must not unlock a private row, got {out}"
    );
}

#[test]
fn enforced_owner_caller_still_sees_the_node() {
    // ALLOWED — proves the fix narrows rather than disabling the path. The
    // owner is the ENFORCED caller, with and without a matching `as_agent`.
    let _p = Posture::enforced(ALICE);
    let (conn, src, tgt) = fixture();

    let out = handle_kg_query(&conn, &json!({"source_id": src})).expect("query ok");
    assert_eq!(count(&out), 1, "owner-caller sees its own node, got {out}");
    assert_eq!(titles(&out), vec!["alice secret".to_string()]);
    assert_eq!(out["memories"][0]["target_id"].as_str(), Some(tgt.as_str()));

    let out =
        handle_kg_query(&conn, &json!({"source_id": src, "as_agent": ALICE})).expect("query ok");
    assert_eq!(count(&out), 1, "a matching as_agent is a no-op, got {out}");
}

#[test]
fn enforced_non_owner_caller_is_refused_and_as_agent_cannot_widen() {
    // DENIED — the pre-existing #1935 gate keeps working, AND a wire
    // `as_agent` naming the OWNER cannot widen past the enforced caller. This
    // is the security property that makes honouring a self-asserted value safe
    // on a read filter at all.
    let _p = Posture::enforced(BOB);
    let (conn, src, _tgt) = fixture();

    let out = handle_kg_query(&conn, &json!({"source_id": src})).expect("query ok");
    assert_eq!(count(&out), 0, "the #1935 gate still fires, got {out}");

    let out =
        handle_kg_query(&conn, &json!({"source_id": src, "as_agent": ALICE})).expect("query ok");
    assert_eq!(
        count(&out),
        0,
        "a wire as_agent must not widen past the enforced caller, got {out}"
    );
}

// --- the #151 SUBTREE arm: where `as_agent` actually bites -------------------

const ENG_AGENT: &str = "acme/eng/alice";
const OTHER_AGENT: &str = "other/team/bob";
const ENG_NS: &str = "acme/eng/notes";

/// `(conn, source_id)` — a `scope=team` target in `acme/eng/notes`, i.e. inside
/// `acme/eng/alice`'s team subtree and outside `other/team/bob`'s.
fn team_fixture() -> (Connection, String) {
    let conn = common::fresh_conn();
    let src = seed_scoped(&conn, PUB_NS, "kg source", ENG_AGENT, None, None);
    let tgt = seed_scoped(
        &conn,
        ENG_NS,
        "eng team note",
        ENG_AGENT,
        Some("team"),
        None,
    );
    db::create_link(&conn, &src, &tgt, "related_to").expect("link");
    (conn, src)
}

#[test]
fn as_agent_outside_the_team_subtree_drops_the_node() {
    // DENIED — the positive control that `as_agent` is genuinely honoured on
    // the main path now: the enforced caller CAN see the row (step 1 passes),
    // and it is the `as_agent` step alone that removes it.
    let _p = Posture::enforced(ENG_AGENT);
    let (conn, src) = team_fixture();

    let out = handle_kg_query(&conn, &json!({"source_id": src})).expect("query ok");
    assert_eq!(count(&out), 1, "baseline: the caller can see it, got {out}");

    let out = handle_kg_query(&conn, &json!({"source_id": src, "as_agent": OTHER_AGENT}))
        .expect("query ok");
    assert_eq!(
        count(&out),
        0,
        "a scope-agent outside the team subtree must not see it, got {out}"
    );
}

#[test]
fn as_agent_inside_the_team_subtree_keeps_the_node() {
    // ALLOWED — the same request with a scope agent INSIDE the subtree.
    let _p = Posture::enforced(ENG_AGENT);
    let (conn, src) = team_fixture();

    let out = handle_kg_query(&conn, &json!({"source_id": src, "as_agent": ENG_AGENT}))
        .expect("query ok");
    assert_eq!(count(&out), 1, "in-subtree scope agent sees it, got {out}");
    assert_eq!(titles(&out), vec!["eng team note".to_string()]);
}

// ---------------------------------------------------------------------------
// namespace — dead filter on the main path
// ---------------------------------------------------------------------------

#[test]
fn namespace_filter_drops_a_node_outside_the_requested_namespace() {
    // DENIED. Pre-#3386 this returned the node anyway — a wrong result, not a
    // narrower one.
    let _p = Posture::single_operator();
    let (conn, src, _tgt) = fixture();

    let out = handle_kg_query(&conn, &json!({"source_id": src, "namespace": "team/nope"}))
        .expect("query ok");
    assert_eq!(
        count(&out),
        0,
        "a node in {PRIV_NS} must not answer a team/nope query, got {out}"
    );
}

#[test]
fn namespace_filter_keeps_a_node_inside_the_requested_namespace() {
    // ALLOWED — exact-match semantics, the same `m.namespace = ?` rule
    // `db::list_by_source_uri` already gives the by_source_uri path.
    let _p = Posture::single_operator();
    let (conn, src, _tgt) = fixture();

    let out =
        handle_kg_query(&conn, &json!({"source_id": src, "namespace": PRIV_NS})).expect("query ok");
    assert_eq!(count(&out), 1, "the matching node survives, got {out}");
    assert_eq!(titles(&out), vec!["alice secret".to_string()]);
}

#[test]
fn namespace_is_validated_at_ingress() {
    let _p = Posture::single_operator();
    let (conn, src, _tgt) = fixture();

    let err = handle_kg_query(&conn, &json!({"source_id": src, "namespace": "../../etc"}))
        .expect_err("a path-traversal namespace must refuse");
    assert!(
        err.contains("namespace") || err.contains(".."),
        "got: {err}"
    );
}

// ---------------------------------------------------------------------------
// negative bounds — silently coerced
// ---------------------------------------------------------------------------

#[test]
fn negative_max_depth_is_refused_not_coerced() {
    let _p = Posture::single_operator();
    let (conn, src, _tgt) = fixture();

    let err = handle_kg_query(&conn, &json!({"source_id": src, "max_depth": -1}))
        .expect_err("a negative max_depth must refuse");
    assert!(
        err.contains("max_depth") && err.contains("non-negative"),
        "got: {err}"
    );
}

#[test]
fn negative_limit_is_refused_not_coerced() {
    let _p = Posture::single_operator();
    let (conn, src, _tgt) = fixture();

    let err = handle_kg_query(&conn, &json!({"source_id": src, "limit": -5}))
        .expect_err("a negative limit must refuse");
    assert!(
        err.contains("limit") && err.contains("non-negative"),
        "got: {err}"
    );
}

#[test]
fn positive_bounds_are_still_honoured() {
    // ALLOWED — the guard refuses only the contradictory value.
    let _p = Posture::single_operator();
    let (conn, src, _tgt) = fixture();

    let out = handle_kg_query(
        &conn,
        &json!({"source_id": src, "max_depth": 2, "limit": 10}),
    )
    .expect("positive bounds ok");
    assert_eq!(count(&out), 1, "got {out}");
    assert_eq!(out["max_depth"].as_u64(), Some(2));
}

// ---------------------------------------------------------------------------
// by_source_uri — the other traversal path
// ---------------------------------------------------------------------------

/// `(conn, source_uri)` — two roots sharing a URI: alice's private row in
/// `PRIV_NS` and a second alice row in `PUB_NS`.
fn uri_fixture() -> Connection {
    let conn = common::fresh_conn();
    seed(&conn, PRIV_NS, "alice doc part", ALICE, Some(DOC_URI));
    seed(&conn, PUB_NS, "alice doc intro", ALICE, Some(DOC_URI));
    conn
}

#[test]
fn by_source_uri_hides_roots_from_an_unidentified_caller_with_as_agent() {
    // DENIED on the second traversal path — the pre-existing #1720 A3 rule
    // (`caller = None` ⇒ no private rows) that the main path now matches.
    let _p = Posture::single_operator();
    let conn = uri_fixture();

    let out = handle_kg_query(&conn, &json!({"by_source_uri": DOC_URI, "as_agent": BOB}))
        .expect("query ok");
    assert_eq!(count(&out), 0, "no private roots reach bob, got {out}");
}

#[test]
fn by_source_uri_allows_the_enforced_owner_and_honours_namespace() {
    // ALLOWED + the namespace narrowing on the same path.
    let _p = Posture::enforced(ALICE);
    let conn = uri_fixture();

    let out = handle_kg_query(&conn, &json!({"by_source_uri": DOC_URI})).expect("query ok");
    assert_eq!(
        count(&out),
        2,
        "the owner-caller sees both roots, got {out}"
    );

    let out = handle_kg_query(
        &conn,
        &json!({"by_source_uri": DOC_URI, "namespace": PUB_NS}),
    )
    .expect("query ok");
    assert_eq!(count(&out), 1, "namespace narrows to one root, got {out}");
    assert_eq!(titles(&out), vec!["alice doc intro".to_string()]);
}

#[test]
fn by_source_uri_envelope_carries_the_same_structural_keys() {
    // #3386 — a client had to branch on which request it sent because `paths`
    // (and the per-row `path` / `relation`) existed only on the main envelope.
    // Additive: no pre-existing key was removed or repurposed.
    let _p = Posture::enforced(ALICE);
    let conn = uri_fixture();

    let out = handle_kg_query(&conn, &json!({"by_source_uri": DOC_URI})).expect("query ok");
    assert_eq!(count(&out), 2);
    assert_eq!(out["by_source_uri"].as_str(), Some(DOC_URI));
    let paths = out["paths"].as_array().expect("paths array");
    assert_eq!(paths.len(), 2, "one path per root, got {out}");
    for m in out["memories"].as_array().expect("memories") {
        assert!(m["target_id"].is_string(), "got {m}");
        assert!(m["path"].is_string(), "got {m}");
        assert!(
            m["relation"].is_null(),
            "a root is a node, not an edge: {m}"
        );
        assert_eq!(m["depth"].as_u64(), Some(0), "got {m}");
        assert_eq!(m["source_uri"].as_str(), Some(DOC_URI), "got {m}");
    }
    assert!(
        paths.iter().all(|p| out["memories"]
            .as_array()
            .expect("memories")
            .iter()
            .any(|m| m["target_id"] == *p)),
        "every path must name one of the returned roots, got {out}"
    );
}

#[test]
fn by_source_uri_refuses_a_negative_limit() {
    let _p = Posture::enforced(ALICE);
    let conn = uri_fixture();

    let err = handle_kg_query(&conn, &json!({"by_source_uri": DOC_URI, "limit": -5}))
        .expect_err("a negative limit must refuse on this path too");
    assert!(
        err.contains("limit") && err.contains("non-negative"),
        "got: {err}"
    );
}

// ---------------------------------------------------------------------------
// zero-config default — must stay byte-unchanged
// ---------------------------------------------------------------------------

#[test]
fn single_operator_default_returns_the_full_topology_unchanged() {
    // The whole point of keeping the principal set EMPTY when neither
    // `AI_MEMORY_AGENT_ID` nor `as_agent` is supplied: a zero-config
    // deployment must see exactly what it saw pre-#3386.
    let _p = Posture::single_operator();
    let (conn, src, tgt) = fixture();

    let out = handle_kg_query(&conn, &json!({"source_id": src})).expect("query ok");
    assert_eq!(count(&out), 1, "got {out}");
    assert_eq!(out["memories"][0]["target_id"].as_str(), Some(tgt.as_str()));
    assert_eq!(out["memories"][0]["relation"].as_str(), Some("related_to"));
    assert_eq!(out["source_id"].as_str(), Some(src.as_str()));
    assert_eq!(out["max_depth"].as_u64(), Some(1));
    assert_eq!(out["paths"].as_array().expect("paths").len(), 1);
}
