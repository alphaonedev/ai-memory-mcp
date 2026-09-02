// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3363 — caller-asserted principal residue (the #3171 class) on the eight
//! MCP tools the original tool-contract audit missed.
//!
//! ## The hole
//!
//! `identity::resolve_agent_id(explicit, None)` gives the EXPLICIT (wire)
//! argument precedence over the `AI_MEMORY_AGENT_ID` env identity. That is the
//! right ladder for an operator-as-actor attribution field on a single-operator
//! deployment, and exactly wrong for the durable evidence these eight handlers
//! stamp. With `AI_MEMORY_AGENT_ID=ai:realcaller`:
//!
//! - `memory_skill_retire {agent_id:"ai:forged-2"}` wrote `retired_by =
//!   ai:forged-2` into the skills table;
//! - `memory_skill_delete` wrote the same forged `purged_by` onto a HARD purge;
//! - `memory_skill_get {agent_id:...}` forged the `SKILL_INVOKED` signed-event
//!   principal on the append-only `signed_events` chain;
//! - `memory_agent_register {caller_agent_id:"ai:frank"}` signed the forensic
//!   audit row for minting a NEW principal as frank;
//! - `memory_skill_promote_from_reflection {agent_id:...}` forged the audit
//!   actor for minting a signed capability bundle;
//! - `memory_check_agent_action {agent_id:...}` let a caller pick the principal
//!   its own action is JUDGED as, and never called `validate_agent_id` at all
//!   (`{"agent_id":"../../etc"}` was accepted verbatim);
//! - `memory_action_create {agent_id:"ai:bob"}` / `memory_routine_create
//!   {created_by:"ai:bob"}` attributed the row to — and charged the
//!   per-namespace storage quota of — a principal the caller is not.
//!
//! Worse, five of those sites swallowed a resolution failure with
//! `unwrap_or_else(|_| ANONYMOUS_INVALID)`, so a malformed principal degraded
//! into a sentinel instead of refusing.
//!
//! ## The control (one funnel, not eight patches)
//!
//! Every site now resolves through `identity::resolve_governance_subject`
//! (`src/identity/mod.rs`) — the SAME helper #3171 shipped for the other
//! fourteen tools — reached by the coordination create surfaces through
//! `coordination_guard::resolve_actor`. Its rule:
//!
//! - the wire value, when present, is ALWAYS wire-strict `validate_agent_id`d
//!   (#3363 hardening, so `"../../etc"` and the reserved sentinels are refused
//!   under EVERY posture, not only on the single-operator fallback);
//! - under the multi-tenant posture (`AI_MEMORY_AGENT_ID` set) the subject IS
//!   the caller and a differing wire principal is REFUSED (fail-closed);
//! - under the single-operator default (env unset) the legacy ladder runs, so
//!   zero-config deployments are byte-identical.
//!
//! ## What this pins — per tool, the DENIED and the ALLOWED path
//!
//! Every denied case additionally asserts the durable artefact was NOT written
//! (no skill retired/purged, no agent minted, no action/routine row), proving
//! the refusal precedes the effect rather than merely relabelling it.

use std::sync::Mutex;

use ai_memory::mcp::{
    handle_action_create, handle_agent_register, handle_check_agent_action, handle_routine_create,
    handle_skill_delete, handle_skill_get, handle_skill_promote_from_reflection,
    handle_skill_register, handle_skill_retire,
};
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

/// The enforced multi-tenant caller used throughout.
const CALLER: &str = "ai:realcaller";
/// The principal a wire caller tries to speak as.
const FORGED: &str = "ai:forged-2";

/// SAFETY helper: set `AI_MEMORY_AGENT_ID` (env mutation serialised by the
/// caller holding `ENV_GUARD`).
fn set_agent_id(value: &str) {
    // SAFETY: env mutation is serialised by `ENV_GUARD`, held by the caller.
    unsafe { std::env::set_var(ENV_AGENT_ID, value) };
}

/// SAFETY helper: clear `AI_MEMORY_AGENT_ID` (env mutation serialised by the
/// caller holding `ENV_GUARD`).
fn clear_agent_id() {
    // SAFETY: env mutation is serialised by `ENV_GUARD`, held by the caller.
    unsafe { std::env::remove_var(ENV_AGENT_ID) };
}

/// RAII fixture: hold `ENV_GUARD`, pin `AI_MEMORY_AGENT_ID` to the enforced
/// caller for the test body, and restore the unset default on drop (including
/// on an assertion panic, so a failure cannot leak the var into a sibling).
struct EnforcedCaller {
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnforcedCaller {
    fn new() -> Self {
        let lock = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set_agent_id(CALLER);
        Self { _lock: lock }
    }
}

impl Drop for EnforcedCaller {
    fn drop(&mut self) {
        clear_agent_id();
    }
}

/// The #3171 refusal class every denied path must land on: the wire principal
/// disagreed with the enforced caller, so the operation is refused rather than
/// attributed to the forged id.
fn assert_mismatch_refusal(err: &str, requested: &str) {
    assert!(
        err.contains("agent_id mismatch") && err.contains("may only"),
        "expected the #3171 caller-binding refusal, got: {err}"
    );
    assert!(
        err.contains(CALLER) && err.contains(requested),
        "the refusal must name both the enforced caller and the requested id, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Seeding helpers
// ---------------------------------------------------------------------------

/// Insert a minimal `skills` row directly (same shape the `skill_get` unit
/// tests seed) so the retire / delete / get paths have a real lineage to act
/// on and the denied case can be proven to leave it untouched.
fn seed_skill(conn: &Connection, id: &str, ns: &str, name: &str) {
    use sha2::{Digest as _, Sha256};
    let body = "# seeded skill\n\nbody\n";
    let body_blob = zstd::encode_all(body.as_bytes(), 3).expect("zstd encode");
    let mut h = Sha256::new();
    h.update(body.as_bytes());
    let digest: Vec<u8> = h.finalize().to_vec();
    conn.execute(
        "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, \
         created_at) VALUES (?1, ?2, ?3, 'desc.', '{}', ?4, ?5, 1700000000)",
        rusqlite::params![id, ns, name, body_blob, digest],
    )
    .expect("seed skill row");
}

/// `(retired_at, retired_by)` for a seeded skill — the durable provenance the
/// denied path must leave untouched.
fn skill_retirement(conn: &Connection, id: &str) -> (Option<i64>, Option<String>) {
    conn.query_row(
        "SELECT retired_at, retired_by FROM skills WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .expect("read retirement columns")
}

fn skill_row_count(conn: &Connection, id: &str) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM skills WHERE id = ?1", [id], |r| {
        r.get(0)
    })
    .expect("count skills")
}

/// Seed a depth-1 reflection so `memory_skill_promote_from_reflection` has a
/// promotable source on the allowed path.
fn seed_reflection(conn: &Connection, ns: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: "promotable reflection".to_string(),
        content: "a synthesised insight worth promoting into a skill".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test-3363".to_string(),
        created_at: now.clone(),
        updated_at: now,
        memory_kind: MemoryKind::Reflection,
        reflection_depth: 1,
        version: 1,
        ..Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("insert reflection")
}

/// The most recent `signed_events` actor for a `skill_invoked` row — the
/// principal `memory_skill_get` stamps onto the append-only chain.
fn last_skill_invoked_actor(conn: &Connection) -> Option<String> {
    conn.query_row(
        "SELECT agent_id FROM signed_events WHERE event_type = ?1 \
         ORDER BY sequence DESC LIMIT 1",
        [ai_memory::signed_events::event_types::SKILL_INVOKED],
        |r| r.get(0),
    )
    .ok()
}

fn action_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM actions", [], |r| r.get(0))
        .expect("count actions")
}

fn routine_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM routines", [], |r| r.get(0))
        .expect("count routines")
}

/// Registered principals live in the reserved `_agents` namespace, not a
/// dedicated table — count them through the same reader the tool exposes.
fn agent_count(conn: &Connection) -> usize {
    ai_memory::db::list_agents(conn).expect("list agents").len()
}

// ---------------------------------------------------------------------------
// 1. memory_agent_register — caller_agent_id
// ---------------------------------------------------------------------------

fn agent_register_params(caller_agent_id: Option<&str>) -> Value {
    let mut p = json!({
        "agent_id": "ai:newly-minted",
        "agent_type": "ai:test",
        "capabilities": ["recall"],
    });
    if let Some(c) = caller_agent_id {
        p["caller_agent_id"] = json!(c);
    }
    p
}

#[test]
fn agent_register_refuses_forged_caller_agent_id() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();

    let err = handle_agent_register(&conn, &agent_register_params(Some("ai:frank")))
        .expect_err("a forged caller_agent_id must refuse");
    assert_mismatch_refusal(&err, "ai:frank");
    assert_eq!(
        agent_count(&conn),
        0,
        "the refusal must precede minting the new principal"
    );
}

#[test]
fn agent_register_allows_matching_and_omitted_caller_agent_id() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();

    let out = handle_agent_register(&conn, &agent_register_params(Some(CALLER)))
        .expect("the enforced caller may register as itself");
    assert_eq!(out["registered"], json!(true));
    assert_eq!(out["agent_id"], json!("ai:newly-minted"));

    // ABSENT stays the documented default: the actor resolves to the caller,
    // no wire value required.
    let conn2 = common::fresh_conn();
    handle_agent_register(&conn2, &agent_register_params(None))
        .expect("an omitted caller_agent_id resolves to the ambient caller");
    assert_eq!(agent_count(&conn2), 1);
}

// ---------------------------------------------------------------------------
// 2. memory_skill_retire — agent_id
// ---------------------------------------------------------------------------

#[test]
fn skill_retire_refuses_forged_agent_id() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();
    seed_skill(&conn, "sk-retire-denied", "team/3363", "retire-denied");

    let err = handle_skill_retire(
        &conn,
        &json!({"skill_id": "sk-retire-denied", "agent_id": FORGED}),
        None,
    )
    .expect_err("a forged agent_id must refuse the retire");
    assert_mismatch_refusal(&err, FORGED);

    let (retired_at, retired_by) = skill_retirement(&conn, "sk-retire-denied");
    assert!(
        retired_at.is_none() && retired_by.is_none(),
        "the refusal must precede the retirement write, got ({retired_at:?}, {retired_by:?})"
    );
}

#[test]
fn skill_retire_allows_matching_agent_id_and_stamps_the_caller() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();
    seed_skill(&conn, "sk-retire-ok", "team/3363", "retire-ok");

    let out = handle_skill_retire(
        &conn,
        &json!({"skill_id": "sk-retire-ok", "agent_id": CALLER, "reason": "eol"}),
        None,
    )
    .expect("the enforced caller may retire as itself");
    assert_eq!(out["retired_by"], json!(CALLER));

    let (retired_at, retired_by) = skill_retirement(&conn, "sk-retire-ok");
    assert!(retired_at.is_some(), "the skill must actually be retired");
    assert_eq!(
        retired_by.as_deref(),
        Some(CALLER),
        "retired_by must be the enforced caller, never a wire-asserted id"
    );
}

// ---------------------------------------------------------------------------
// 3. memory_skill_delete — agent_id
// ---------------------------------------------------------------------------

#[test]
fn skill_delete_refuses_forged_agent_id() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();
    seed_skill(&conn, "sk-del-denied", "team/3363", "del-denied");

    let err = handle_skill_delete(
        &conn,
        &json!({"skill_id": "sk-del-denied", "force": true, "agent_id": FORGED}),
        None,
    )
    .expect_err("a forged agent_id must refuse the hard purge");
    assert_mismatch_refusal(&err, FORGED);
    assert_eq!(
        skill_row_count(&conn, "sk-del-denied"),
        1,
        "the refusal must precede the destructive purge"
    );
}

#[test]
fn skill_delete_allows_matching_agent_id() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();
    seed_skill(&conn, "sk-del-ok", "team/3363", "del-ok");

    handle_skill_delete(
        &conn,
        &json!({"skill_id": "sk-del-ok", "force": true, "agent_id": CALLER}),
        None,
    )
    .expect("the enforced caller may purge as itself");
    assert_eq!(
        skill_row_count(&conn, "sk-del-ok"),
        0,
        "the allowed purge must still take effect"
    );
}

// ---------------------------------------------------------------------------
// 4. memory_skill_get — agent_id (SKILL_INVOKED signed-event principal)
// ---------------------------------------------------------------------------

#[test]
fn skill_get_refuses_forged_agent_id() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();
    seed_skill(&conn, "sk-get-denied", "team/3363", "get-denied");

    let err = handle_skill_get(
        &conn,
        &json!({"skill_id": "sk-get-denied", "agent_id": FORGED}),
    )
    .expect_err("a forged agent_id must refuse the activation");
    assert_mismatch_refusal(&err, FORGED);
    assert!(
        last_skill_invoked_actor(&conn).is_none(),
        "the refusal must precede the append-only invocation record"
    );
}

#[test]
fn skill_get_allows_matching_agent_id_and_stamps_the_caller() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();
    seed_skill(&conn, "sk-get-ok", "team/3363", "get-ok");

    let out = handle_skill_get(&conn, &json!({"skill_id": "sk-get-ok", "agent_id": CALLER}))
        .expect("the enforced caller may activate as itself");
    assert!(
        out["invocation_record"]["event_id"].is_string(),
        "the activation must still emit an invocation record, got {out}"
    );
    assert_eq!(
        last_skill_invoked_actor(&conn).as_deref(),
        Some(CALLER),
        "the SKILL_INVOKED actor must be the enforced caller"
    );
}

// ---------------------------------------------------------------------------
// 5. memory_skill_promote_from_reflection — agent_id
// ---------------------------------------------------------------------------

fn promote_params(reflection_id: &str, agent_id: &str, skill_name: &str) -> Value {
    json!({
        "reflection_id": reflection_id,
        "skill_name": skill_name,
        "skill_description": "a skill promoted from a seeded reflection",
        "agent_id": agent_id,
    })
}

#[test]
fn skill_promote_refuses_forged_agent_id() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();
    let reflection_id = seed_reflection(&conn, "team/3363");

    let err = handle_skill_promote_from_reflection(
        &conn,
        &promote_params(&reflection_id, FORGED, "promoted-denied"),
        None,
    )
    .expect_err("a forged agent_id must refuse the promote");
    assert_mismatch_refusal(&err, FORGED);
    assert_eq!(
        skill_row_count_by_name(&conn, "promoted-denied"),
        0,
        "the refusal must precede minting the capability bundle"
    );
}

#[test]
fn skill_promote_allows_matching_agent_id() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();
    let reflection_id = seed_reflection(&conn, "team/3363");

    let out = handle_skill_promote_from_reflection(
        &conn,
        &promote_params(&reflection_id, CALLER, "promoted-ok"),
        None,
    )
    .expect("the enforced caller may promote as itself");
    assert!(
        out["skill_id"].is_string(),
        "the allowed promote must still mint the skill, got {out}"
    );
    assert_eq!(skill_row_count_by_name(&conn, "promoted-ok"), 1);
}

fn skill_row_count_by_name(conn: &Connection, name: &str) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM skills WHERE name = ?1", [name], |r| {
        r.get(0)
    })
    .expect("count skills by name")
}

// ---------------------------------------------------------------------------
// 6. memory_check_agent_action — agent_id (governance SUBJECT, unvalidated)
// ---------------------------------------------------------------------------

#[test]
fn check_agent_action_refuses_forged_agent_id() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();

    let err = handle_check_agent_action(
        &conn,
        &json!({"kind": "bash", "command": "ls", "agent_id": FORGED}),
    )
    .expect_err("a caller may not be judged as another principal");
    assert_mismatch_refusal(&err, FORGED);
}

#[test]
fn check_agent_action_validates_the_wire_agent_id_under_every_posture() {
    let _lock = ENV_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clear_agent_id(); // single-operator default: no enforced caller.
    let conn = common::fresh_conn();

    // Pre-#3363 this path never reached `validate_agent_id` at all.
    let err = handle_check_agent_action(
        &conn,
        &json!({"kind": "bash", "command": "ls", "agent_id": "../../etc"}),
    )
    .expect_err("a path-traversal agent_id must be refused");
    assert!(
        err.contains("agent_id"),
        "expected an agent_id validation refusal, got: {err}"
    );

    // ALLOWED under the same posture: a well-formed wire id is honoured
    // byte-identically to pre-#3363 (zero-config deployments unchanged).
    let out = handle_check_agent_action(
        &conn,
        &json!({"kind": "bash", "command": "ls", "agent_id": "ai:alice"}),
    )
    .expect("a valid wire agent_id is honoured on the single-operator default");
    assert_eq!(out["agent_id"], json!("ai:alice"));
}

#[test]
fn check_agent_action_allows_matching_and_omitted_agent_id() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();

    let out = handle_check_agent_action(
        &conn,
        &json!({"kind": "bash", "command": "ls", "agent_id": CALLER}),
    )
    .expect("the enforced caller may be judged as itself");
    assert_eq!(out["agent_id"], json!(CALLER));

    // ABSENT under the multi-tenant posture resolves to the enforced caller
    // rather than the shared `anonymous:mcp` default, so the decision is
    // judged against the rules that actually apply to this principal.
    let out = handle_check_agent_action(&conn, &json!({"kind": "bash", "command": "ls"}))
        .expect("an omitted agent_id resolves to the enforced caller");
    assert_eq!(out["agent_id"], json!(CALLER));
}

// ---------------------------------------------------------------------------
// 7. memory_action_create — agent_id (attribution + quota key)
// ---------------------------------------------------------------------------

fn action_params(agent_id: Option<&str>) -> Value {
    let mut p = json!({
        "namespace": "team/3363",
        "kind": "task",
        "title": "bound-actor action",
    });
    if let Some(a) = agent_id {
        p["agent_id"] = json!(a);
    }
    p
}

#[test]
fn action_create_refuses_forged_agent_id() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();

    let err = handle_action_create(&conn, &action_params(Some("ai:bob")))
        .expect_err("a forged agent_id must refuse the create");
    assert_mismatch_refusal(&err, "ai:bob");
    assert_eq!(
        action_count(&conn),
        0,
        "the refusal must precede the row insert (and bob's quota charge)"
    );
}

#[test]
fn action_create_allows_matching_agent_id_and_attributes_the_caller() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();

    let out = handle_action_create(&conn, &action_params(Some(CALLER)))
        .expect("the enforced caller may create as itself");
    assert_eq!(out["action"]["agent_id"], json!(CALLER));

    // ABSENT still resolves to the ambient (here: enforced) caller, so the
    // #2998 always-attributed / always-charged property survives.
    let out = handle_action_create(&conn, &action_params(None))
        .expect("an omitted agent_id resolves to the ambient caller");
    assert_eq!(out["action"]["agent_id"], json!(CALLER));
    assert_eq!(action_count(&conn), 2);
}

// ---------------------------------------------------------------------------
// 8. memory_routine_create — created_by
// ---------------------------------------------------------------------------

fn routine_params(created_by: Option<&str>, name: &str) -> Value {
    let mut p = json!({
        "namespace": "team/3363",
        "name": name,
        "template": {"steps": []},
    });
    if let Some(c) = created_by {
        p["created_by"] = json!(c);
    }
    p
}

#[test]
fn routine_create_refuses_forged_created_by() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();

    let err = handle_routine_create(&conn, &routine_params(Some("ai:bob"), "denied"))
        .expect_err("a forged created_by must refuse the create");
    assert_mismatch_refusal(&err, "ai:bob");
    assert_eq!(
        routine_count(&conn),
        0,
        "the refusal must precede the row insert"
    );
}

#[test]
fn routine_create_allows_matching_created_by_and_attributes_the_caller() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();

    let out = handle_routine_create(&conn, &routine_params(Some(CALLER), "allowed"))
        .expect("the enforced caller may create as itself");
    assert_eq!(out["routine"]["created_by"], json!(CALLER));

    let out = handle_routine_create(&conn, &routine_params(None, "ambient"))
        .expect("an omitted created_by resolves to the ambient caller");
    assert_eq!(out["routine"]["created_by"], json!(CALLER));
    assert_eq!(routine_count(&conn), 2);
}

// ---------------------------------------------------------------------------
// In-family residue closed alongside the eight: memory_skill_register's own
// forensic actor took the same wire `agent_id` verbatim (its sibling lifecycle
// tools are four of the eight). `memory_delete`'s pre-refusal forensic actor is
// the matching in-family site and is pinned by
// `src/mcp/tools/delete.rs::forensic_actor_is_bound_to_the_caller_3363`.
// ---------------------------------------------------------------------------

fn minimal_skill_md(name: &str) -> String {
    format!("---\nnamespace: team-3363\nname: {name}\ndescription: A demo skill.\n---\n\nBody.\n")
}

#[test]
fn skill_register_refuses_forged_agent_id() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();

    let err = handle_skill_register(
        &conn,
        &json!({"inline_skill": minimal_skill_md("reg-denied"), "agent_id": FORGED}),
        None,
    )
    .expect_err("a forged agent_id must refuse the register");
    assert_mismatch_refusal(&err, FORGED);
    assert_eq!(
        skill_row_count_by_name(&conn, "reg-denied"),
        0,
        "the refusal must precede minting the capability bundle"
    );
}

#[test]
fn skill_register_allows_matching_agent_id() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();

    let out = handle_skill_register(
        &conn,
        &json!({"inline_skill": minimal_skill_md("reg-ok"), "agent_id": CALLER}),
        None,
    )
    .expect("the enforced caller may register as itself");
    assert_eq!(out["registered"], json!(true));
    assert_eq!(skill_row_count_by_name(&conn, "reg-ok"), 1);
}

// ---------------------------------------------------------------------------
// Cross-cutting: the reserved-sentinel + malformed-principal fail-closed rule
// ---------------------------------------------------------------------------

#[test]
fn malformed_wire_principal_refuses_instead_of_degrading_to_a_sentinel() {
    let _env = EnforcedCaller::new();
    let conn = common::fresh_conn();
    seed_skill(&conn, "sk-malformed", "team/3363", "malformed");

    // Pre-#3363 this landed `retired_by = anonymous:invalid` via the
    // `unwrap_or_else(|_| ANONYMOUS_INVALID)` swallow. It now refuses.
    let err = handle_skill_retire(
        &conn,
        &json!({"skill_id": "sk-malformed", "agent_id": "has spaces;DROP"}),
        None,
    )
    .expect_err("a malformed wire principal must refuse, not degrade");
    assert!(
        err.contains("agent_id"),
        "expected an agent_id refusal, got: {err}"
    );

    let (retired_at, retired_by) = skill_retirement(&conn, "sk-malformed");
    assert!(
        retired_at.is_none() && retired_by.is_none(),
        "no forensic write may land for a refused principal"
    );
}
