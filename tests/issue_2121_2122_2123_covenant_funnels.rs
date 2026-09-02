// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2121 / #2122 / #2123 — TRACT covenant clause-1 enforcement on the
//! REMAINING sqlite write funnels the #2110/#2113 fixes missed.
//!
//! - **#2121 (HIGH)** — `capture_turn_idempotent` / `recover_turn_idempotent`
//!   / `consolidate` stamped `substrate:system-authored` UNCONDITIONALLY, so
//!   a zero-privilege tenant defeated `AI_MEMORY_REQUIRE_WHY_TRACE=1` by
//!   routing verbatim content through those tools (the #2110 kind-forge
//!   bypass re-committed on different funnels). The stamp is now keyed on
//!   the authenticated internal origin (`substrate_authored` ⟸
//!   `CallerContext::bypass_visibility`); a tenant call with no `why_trace`
//!   is REFUSED under enforce.
//! - **#2122 (MEDIUM)** — genuine internal direct-db writers (the
//!   reflection-invalidation cascade + the synthesis provenance row) now
//!   stamp the substrate rationale so enforce mode does not break internal
//!   function, and `memory_notify` / `memory_share` gained a caller
//!   `why_trace` path so the flag is usable on those tools.
//! - **#2123 (LOW)** — the sqlite `merge_inbound` same-`id` path now runs
//!   the never-refuse inbound `why_trace` gate (+ governance + secret screen)
//!   for postgres parity.
//!
//! # Why this lives in its own integration-test process
//!
//! Same rationale as `tests/issue_2059_2060_covenant_write_gates.rs`: the
//! gate reads a bare `AI_MEMORY_REQUIRE_WHY_TRACE` env var with no test
//! override seam, and `cargo test --lib` shares one process across every
//! unit test. Each `tests/*.rs` file compiles to its OWN binary, so env
//! mutation here can never race another test file; a file-local mutex
//! serializes the tests within this binary.

#![allow(clippy::too_many_lines)]

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::storage::{
    self as db, GovernanceRefusal, REQUIRE_WHY_TRACE_ENV, WHY_TRACE_SUBSTRATE_SYSTEM,
};
use serde_json::json;
use std::sync::{Mutex, OnceLock};

fn covenant_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn fresh_conn() -> rusqlite::Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn make_mem(title: &str, ns: &str, why_trace: Option<&str>) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = json!({ "agent_id": "ai:test" });
    if let Some(wt) = why_trace {
        metadata["why_trace"] = json!(wt);
    }
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("content for {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

fn why_trace_of(conn: &rusqlite::Connection, id: &str) -> Option<String> {
    db::get(conn, id).unwrap().and_then(|m| {
        m.metadata
            .get("why_trace")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    })
}

fn capture_write(
    title: &str,
    ns: &str,
    session: &str,
    turn: i64,
    why_trace: Option<&str>,
) -> ai_memory::models::CaptureTurnWrite {
    ai_memory::models::CaptureTurnWrite {
        memory: make_mem(title, ns, why_trace),
        sha256: {
            // Distinct per (session, turn) so the dedup PK never collides.
            let mut h = vec![0u8; 24];
            h.extend_from_slice(&turn.to_le_bytes());
            h.extend_from_slice(&session.as_bytes()[..session.len().min(8)]);
            h.truncate(32);
            h.resize(32, 0);
            h
        },
        host_kind: "claude-code".to_string(),
        host_session_id: session.to_string(),
        host_turn_index: turn,
        recovered_at_ms: chrono::Utc::now().timestamp_millis(),
        signed_event: ai_memory::signed_events::SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: "ai:test".to_string(),
            event_type: "memory_capture_turn".to_string(),
            payload_hash: vec![0u8; 32],
            signature: None,
            attest_level: "self_signed".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            ..ai_memory::signed_events::SignedEvent::default()
        },
    }
}

fn recover_write(
    title: &str,
    ns: &str,
    seed: u8,
    why_trace: Option<&str>,
) -> ai_memory::models::RecoverTurnWrite {
    ai_memory::models::RecoverTurnWrite {
        memory: make_mem(title, ns, why_trace),
        normalized_sha256: vec![seed; 32],
        raw_sha256: vec![seed.wrapping_add(128); 32],
        host_kind: "claude-code".to_string(),
        transcript_path: "/dev/null".to_string(),
        host_session_id: None,
        host_turn_index: None,
        recovered_at_ms: chrono::Utc::now().timestamp_millis(),
    }
}

// ── #2121 — capture_turn_idempotent keys the stamp on authenticated origin ──

#[test]
fn capture_turn_tenant_refused_substrate_exempt_under_enforce_2121() {
    let _g = covenant_env_lock();
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
    let conn = fresh_conn();

    // Default (env unset) — a tenant capture with no why_trace still lands
    // (advisory posture, byte-identical legacy).
    let w0 = capture_write("cap default", "ns/2121-cap", "sess-a", 0, None);
    let r0 = db::capture_turn_idempotent(&conn, &w0, false).expect("advisory capture lands");
    assert!(!r0.dedup_hit);
    // Pre-fix regression guard: the tenant row must NOT carry the substrate
    // stamp (the #2121 bug stamped it unconditionally).
    assert_eq!(why_trace_of(&conn, &r0.memory_id), None);

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // Tenant (substrate_authored=false ⟸ for_agent ctx) + no why_trace →
    // REFUSED at the insert gate; the whole transaction rolls back.
    let w1 = capture_write("cap tenant", "ns/2121-cap", "sess-b", 1, None);
    let err = db::capture_turn_idempotent(&conn, &w1, false)
        .expect_err("tenant capture without why_trace must be refused under enforce");
    assert!(
        err.contains("MEMORY_INSERT_FAILED") && err.contains("why_trace"),
        "refusal must surface the why_trace gate; got: {err}"
    );
    assert!(
        db::get(&conn, &w1.memory.id).unwrap().is_none(),
        "a refused capture must not have written a row"
    );
    let dedup: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM transcript_line_dedup WHERE host_session_id = 'sess-b'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(dedup, 0, "a refused capture must not leave a dedup row");

    // Tenant + caller-supplied why_trace → allowed under enforce.
    let w2 = capture_write(
        "cap tenant wt",
        "ns/2121-cap",
        "sess-c",
        2,
        Some("host volunteered this turn"),
    );
    let r2 = db::capture_turn_idempotent(&conn, &w2, false)
        .expect("caller-supplied why_trace clears the gate");
    assert_eq!(
        why_trace_of(&conn, &r2.memory_id).as_deref(),
        Some("host volunteered this turn")
    );

    // Authenticated internal origin (substrate_authored=true ⟸
    // bypass_visibility) → exempt + stamped.
    let w3 = capture_write("cap system", "ns/2121-cap", "sess-d", 3, None);
    let r3 = db::capture_turn_idempotent(&conn, &w3, true)
        .expect("authenticated internal origin is exempt");
    assert_eq!(
        why_trace_of(&conn, &r3.memory_id).as_deref(),
        Some(WHY_TRACE_SUBSTRATE_SYSTEM)
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

// ── #2121 — recover_turn_idempotent keys the stamp on authenticated origin ──

#[test]
fn recover_turn_tenant_refused_substrate_exempt_under_enforce_2121() {
    let _g = covenant_env_lock();
    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    let conn = fresh_conn();

    // Tenant-context recovery (substrate_authored=false ⟸ for_agent ctx on
    // the SAL surface) + no why_trace → REFUSED, transaction rolled back.
    let w1 = recover_write("rec tenant", "ns/2121-rec", 1, None);
    let err = db::recover_turn_idempotent(&conn, &w1, false)
        .expect_err("tenant recover without why_trace must be refused under enforce");
    assert!(
        err.contains("MEMORY_INSERT_FAILED") && err.contains("why_trace"),
        "refusal must surface the why_trace gate; got: {err}"
    );
    assert!(db::get(&conn, &w1.memory.id).unwrap().is_none());

    // Tenant + caller-supplied why_trace → allowed.
    let w2 = recover_write("rec tenant wt", "ns/2121-rec", 2, Some("rehydrate turn"));
    let r2 = db::recover_turn_idempotent(&conn, &w2, false).expect("why_trace clears the gate");
    assert_eq!(
        why_trace_of(&conn, &r2.memory_id).as_deref(),
        Some("rehydrate turn")
    );

    // Internal L2 walker (substrate_authored=true) → exempt + stamped.
    let w3 = recover_write("rec system", "ns/2121-rec", 3, None);
    let r3 = db::recover_turn_idempotent(&conn, &w3, true)
        .expect("internal L2 recovery is exempt (env #95: never lose a turn)");
    assert_eq!(
        why_trace_of(&conn, &r3.memory_id).as_deref(),
        Some(WHY_TRACE_SUBSTRATE_SYSTEM)
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

// ── #2121 — consolidate keys the stamp on authenticated origin ──────────────

#[test]
fn consolidate_tenant_refused_substrate_exempt_under_enforce_2121() {
    let _g = covenant_env_lock();
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
    let conn = fresh_conn();

    // Seed why_trace-LESS sources while the gate is advisory (the legacy /
    // pre-covenant corpus shape).
    let id_a = db::insert(&conn, &make_mem("cons src a", "ns/2121-cons", None)).unwrap();
    let id_b = db::insert(&conn, &make_mem("cons src b", "ns/2121-cons", None)).unwrap();

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // Tenant consolidate (substrate_authored=false): the merged metadata
    // inherits NO why_trace from the sources → REFUSED under enforce, and
    // the sources survive (transaction rollback).
    let err = db::consolidate(
        &conn,
        &[id_a.clone(), id_b.clone()],
        "tenant merged",
        "verbatim tenant summary",
        "ns/2121-cons",
        &Tier::Long,
        "consolidation",
        "ai:tenant",
        false,
    )
    .expect_err("tenant consolidate without why_trace must be refused under enforce");
    assert!(
        err.downcast_ref::<GovernanceRefusal>().is_some(),
        "refusal must be the shared GovernanceRefusal envelope; got: {err}"
    );
    assert!(
        db::get(&conn, &id_a).unwrap().is_some(),
        "source a survives"
    );
    assert!(
        db::get(&conn, &id_b).unwrap().is_some(),
        "source b survives"
    );

    // Authenticated internal origin (substrate_authored=true ⟸ curator
    // for_admin / autonomy) → exempt + the result carries the stamp.
    let new_id = db::consolidate(
        &conn,
        &[id_a, id_b],
        "curator merged",
        "curator summary",
        "ns/2121-cons",
        &Tier::Long,
        "consolidation",
        "ai:curator",
        true,
    )
    .expect("internal curator consolidate is exempt");
    assert_eq!(
        why_trace_of(&conn, &new_id).as_deref(),
        Some(WHY_TRACE_SUBSTRATE_SYSTEM)
    );

    // Tenant consolidate over a why_trace-BEARING source: the merged
    // metadata inherits the rationale (a consolidation is a derivation over
    // already-gated rows) and clears the gate.
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
    let id_c = db::insert(
        &conn,
        &make_mem(
            "cons src c",
            "ns/2121-cons-inherit",
            Some("caller rationale"),
        ),
    )
    .unwrap();
    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    let inherited_id = db::consolidate(
        &conn,
        &[id_c],
        "tenant merged inherit",
        "summary",
        "ns/2121-cons-inherit",
        &Tier::Long,
        "consolidation",
        "ai:tenant",
        false,
    )
    .expect("inherited why_trace clears the gate for a tenant consolidate");
    assert_eq!(
        why_trace_of(&conn, &inherited_id).as_deref(),
        Some("caller rationale")
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

// ── #2122 — internal writers succeed under enforce ───────────────────────────

#[test]
fn invalidation_cascade_succeeds_under_enforce_2122() {
    let _g = covenant_env_lock();
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
    let conn = fresh_conn();

    // Seed: a reflection R and a dependent D with `D reflects_on R`.
    let r_id = db::insert(&conn, &make_mem("reflection r", "ns/2122-inv", None)).unwrap();
    let d_id = db::insert(&conn, &make_mem("dependent d", "ns/2122-inv", None)).unwrap();
    let invalidating_id =
        db::insert(&conn, &make_mem("reflection r2", "ns/2122-inv", None)).unwrap();
    db::create_link(&conn, &d_id, &r_id, "reflects_on").expect("link");

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // The cascade is a genuine internal writer: it must succeed under
    // enforce (pre-#2122 the notification insert was refused, silently
    // breaking invalidation propagation).
    let notified = ai_memory::notification::invalidation::propagate_reflection_invalidation(
        &conn,
        &r_id,
        &invalidating_id,
        "ai:system",
    )
    .expect("invalidation cascade must succeed under enforce");
    assert_eq!(notified, vec![d_id.clone()]);

    // The notification row exists in `<ns>/_invalidations` and carries the
    // substrate rationale.
    let (notif_id, meta_json): (String, String) = conn
        .query_row(
            "SELECT id, metadata FROM memories WHERE namespace = 'ns/2122-inv/_invalidations'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("notification row exists under enforce");
    assert!(!notif_id.is_empty());
    let meta: serde_json::Value = serde_json::from_str(&meta_json).unwrap();
    assert_eq!(
        meta.get("why_trace").and_then(|v| v.as_str()),
        Some(WHY_TRACE_SUBSTRATE_SYSTEM),
        "internal invalidation writer records the substrate rationale"
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

// ── #2122 — memory_notify why_trace path ────────────────────────────────────

#[test]
fn notify_refused_without_why_trace_param_allowed_with_it_2122() {
    let _g = covenant_env_lock();
    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    let conn = fresh_conn();
    let ttl = ai_memory::config::ResolvedTtl::default();

    // No why_trace → the notify payload is verbatim caller content, the
    // substrate does NOT stamp its own rationale (that would re-open the
    // #2121 bypass class), so the insert gate refuses under enforce.
    let params = json!({
        "target_agent_id": "ai:bob",
        "title": "ping",
        "payload": "verbatim caller payload",
    });
    let err = ai_memory::mcp::handle_notify(&conn, &params, &ttl, Some("ai:alice"))
        .expect_err("notify without why_trace must be refused under enforce");
    assert!(err.contains("why_trace"), "got: {err}");

    // Caller-supplied why_trace param → allowed; the row carries it.
    let params_wt = json!({
        "target_agent_id": "ai:bob",
        "title": "ping 2",
        "payload": "verbatim caller payload",
        "why_trace": "coordinating handoff with bob",
    });
    let resp = ai_memory::mcp::handle_notify(&conn, &params_wt, &ttl, Some("ai:alice"))
        .expect("why_trace param clears the gate");
    let id = resp["id"].as_str().expect("id");
    assert_eq!(
        why_trace_of(&conn, id).as_deref(),
        Some("coordinating handoff with bob")
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

// ── #2122 — memory_share inherits the source's why_trace / param override ───

#[test]
fn share_inherits_source_why_trace_and_param_override_2122() {
    let _g = covenant_env_lock();
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
    let conn = fresh_conn();

    // Gated source (carries why_trace) + legacy source (predates covenant).
    let gated = db::insert(
        &conn,
        &make_mem(
            "share src gated",
            "ns/2122-share",
            Some("original rationale"),
        ),
    )
    .unwrap();
    let legacy = db::insert(&conn, &make_mem("share src legacy", "ns/2122-share", None)).unwrap();

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // Share of a gated source inherits its why_trace → allowed.
    let resp = ai_memory::mcp::share::handle_share(
        &conn,
        &json!({"source_memory_id": gated, "target_agent_id": "ai:bob"}),
        None,
    )
    .expect("share of a why_trace-bearing source inherits and clears the gate");
    let shared_id = resp["shared_memory_id"].as_str().unwrap();
    assert_eq!(
        why_trace_of(&conn, shared_id).as_deref(),
        Some("original rationale")
    );

    // Share of a LEGACY source without an override → refused under enforce.
    let err = ai_memory::mcp::share::handle_share(
        &conn,
        &json!({"source_memory_id": legacy, "target_agent_id": "ai:bob"}),
        None,
    )
    .expect_err("share of a legacy why_trace-less source must be refused under enforce");
    assert!(err.contains("why_trace"), "got: {err}");

    // The caller-supplied override makes the legacy share possible.
    let resp2 = ai_memory::mcp::share::handle_share(
        &conn,
        &json!({
            "source_memory_id": legacy,
            "target_agent_id": "ai:bob",
            "why_trace": "sharing legacy note with bob",
        }),
        None,
    )
    .expect("why_trace override clears the gate for a legacy source");
    let shared2 = resp2["shared_memory_id"].as_str().unwrap();
    assert_eq!(
        why_trace_of(&conn, shared2).as_deref(),
        Some("sharing legacy note with bob")
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

// ── #2123 — sqlite merge_inbound same-id path: inbound gate, never refuses ──

#[test]
fn merge_inbound_same_id_never_refuses_missing_why_trace_under_enforce_2123() {
    let _g = covenant_env_lock();
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
    let conn = fresh_conn();

    // Seed the local row while advisory.
    let local = make_mem("merge target", "ns/2123-merge", None);
    let id = db::insert(&conn, &local).unwrap();

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // A why_trace-less same-`id` inbound merge must NEVER be refused (CRDT
    // convergence is the load-bearing property; the inbound gate is the
    // advisory WARN + forensic-record variant — postgres parity, #2123).
    let mut inbound = local.clone();
    inbound.id = id.clone();
    inbound.content = "remote merged content".to_string();
    inbound.updated_at = (chrono::Utc::now() + chrono::Duration::seconds(2)).to_rfc3339();
    inbound.version = 2;
    let merged_id = db::merge_inbound(&conn, &inbound, false)
        .expect("merge_inbound must accept a why_trace-less inbound write under enforce");
    assert_eq!(merged_id, id);
    let got = db::get(&conn, &id).unwrap().unwrap();
    assert_eq!(
        got.content, "remote merged content",
        "the field-merge applied (remote won the LWW tiebreak)"
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}
