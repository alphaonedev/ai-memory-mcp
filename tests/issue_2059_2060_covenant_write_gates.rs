// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2059 / #2060 — TRACT covenant clauses 1+2 (deferred from #1832 G18,
//! `docs/spec/TRACT-L1-CLAIM-CONTRACT.md` §8.1): the opt-in `why_trace`
//! write-gate + the authorship-immutability enforcement gate at the sqlite
//! store write funnel (`storage::insert` / `storage::update_with_expected_version`
//! / `storage::update_with_archive_on_supersede`).
//!
//! # Why this lives in its own integration-test process
//!
//! Both gates are read via a bare `AI_MEMORY_REQUIRE_WHY_TRACE` /
//! `AI_MEMORY_REQUIRE_IMMUTABLE_AUTHORSHIP` `std::env::var` lookup with no
//! test-only override seam (mirroring every other `AI_MEMORY_REQUIRE_*` K2-
//! style knob in the crate). `cargo test --lib` runs EVERY unit test across
//! the whole crate in ONE multi-threaded process — a local mutex only
//! serializes tests that explicitly acquire it, it does not stop an
//! unrelated concurrently-running unit test (there are hundreds of
//! `storage::insert` / `update_with_expected_version` callers in
//! `src/storage/mod.rs::tests` alone) from observing a mutated global env
//! var mid-flight. Each `tests/*.rs` file compiles to its OWN OS process, so
//! mutating these two vars here can never race any other test file or the
//! `--lib` unit-test binary. Tests WITHIN this file still run on multiple
//! threads by default, so a local mutex guards them against each other.

use ai_memory::models::{ConfidenceSource, EditSource, Memory, MemoryKind, Tier};
use ai_memory::storage::{
    self as db, GovernanceRefusal, REQUIRE_IMMUTABLE_AUTHORSHIP_ENV, REQUIRE_WHY_TRACE_ENV,
    consult_authorship_immutable_gate, consult_why_trace_gate,
    require_immutable_authorship_enabled, require_why_trace_enabled,
};
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

fn make_mem(title: &str, ns: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
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
        metadata: serde_json::json!({}),
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

// ── Clause 1 — why_trace write-gate (#2059) ──────────────────────────────

#[test]
fn require_why_trace_enabled_respects_truthy_grammar() {
    let _g = covenant_env_lock();
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
    assert!(!require_why_trace_enabled(), "unset must be permissive");
    for v in ["1", "true", "TRUE", "yes", "on"] {
        unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, v) };
        assert!(require_why_trace_enabled(), "{v:?} must be truthy");
    }
    for v in ["0", "false", "no", "off", "garbage"] {
        unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, v) };
        assert!(!require_why_trace_enabled(), "{v:?} must be falsy");
    }
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

#[test]
fn consult_why_trace_gate_advisory_by_default_enforce_when_required() {
    let _g = covenant_env_lock();
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
    let mut mem = make_mem("no rationale", "ns/why-trace");
    // Default (unset) — advisory WARN only, write proceeds.
    assert!(
        consult_why_trace_gate(&mem).is_ok(),
        "default posture must be advisory (byte-identical legacy)"
    );
    // Enforce mode — refused while why_trace is absent.
    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    let err = consult_why_trace_gate(&mem).expect_err("must refuse under enforce");
    assert!(
        err.downcast_ref::<GovernanceRefusal>().is_some(),
        "refusal must be the shared GovernanceRefusal envelope"
    );
    // Supplying why_trace clears the refusal even under enforce.
    mem.metadata = serde_json::json!({"why_trace": "operator-approved backfill"});
    assert!(
        consult_why_trace_gate(&mem).is_ok(),
        "a supplied why_trace must satisfy the gate under enforce"
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

#[test]
fn insert_allows_by_default_and_refuses_under_enforce_without_why_trace() {
    let _g = covenant_env_lock();
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
    let conn = fresh_conn();

    // Default: no why_trace, write succeeds (legacy behavior unchanged).
    let mem = make_mem("no rationale insert", "ns/why-trace-insert");
    assert!(
        db::insert(&conn, &mem).is_ok(),
        "default posture must not refuse an insert lacking why_trace"
    );

    // Enforce: a fresh insert lacking why_trace is refused.
    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    let mem2 = make_mem("no rationale insert 2", "ns/why-trace-insert2");
    let err = db::insert(&conn, &mem2).expect_err("enforce must refuse a why_trace-less insert");
    assert!(err.downcast_ref::<GovernanceRefusal>().is_some());
    assert!(
        db::get(&conn, &mem2.id).unwrap().is_none(),
        "a refused insert must not have written a row"
    );

    // Enforce + why_trace present: the insert succeeds.
    let mut mem3 = make_mem("rationale present insert", "ns/why-trace-insert3");
    mem3.metadata = serde_json::json!({"why_trace": "user asked to remember this"});
    assert!(
        db::insert(&conn, &mem3).is_ok(),
        "enforce must allow an insert that carries why_trace"
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

// ── Clause 2 — authorship-immutability gate (#2060) ──────────────────────

#[test]
fn require_immutable_authorship_enabled_respects_truthy_grammar() {
    let _g = covenant_env_lock();
    unsafe { std::env::remove_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV) };
    assert!(
        !require_immutable_authorship_enabled(),
        "unset must be permissive"
    );
    for v in ["1", "true", "TRUE", "yes", "on"] {
        unsafe { std::env::set_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV, v) };
        assert!(
            require_immutable_authorship_enabled(),
            "{v:?} must be truthy"
        );
    }
    for v in ["0", "false", "no", "off", "garbage"] {
        unsafe { std::env::set_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV, v) };
        assert!(
            !require_immutable_authorship_enabled(),
            "{v:?} must be falsy"
        );
    }
    unsafe { std::env::remove_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV) };
}

#[test]
fn consult_authorship_immutable_gate_noop_cases() {
    let _g = covenant_env_lock();
    unsafe { std::env::remove_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV) };
    // No prior authorship claim -> nothing to protect.
    assert!(
        consult_authorship_immutable_gate(None, Some(&serde_json::json!({"agent_id": "mallory"})))
            .is_ok()
    );
    // No incoming metadata at all.
    assert!(consult_authorship_immutable_gate(Some("alice"), None).is_ok());
    // Incoming metadata carries the SAME agent_id.
    assert!(
        consult_authorship_immutable_gate(
            Some("alice"),
            Some(&serde_json::json!({"agent_id": "alice"}))
        )
        .is_ok()
    );
    // Incoming metadata carries no agent_id key at all.
    assert!(
        consult_authorship_immutable_gate(Some("alice"), Some(&serde_json::json!({"foo": 1})))
            .is_ok()
    );
    unsafe { std::env::remove_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV) };
}

#[test]
fn consult_authorship_immutable_gate_advisory_by_default_enforce_when_required() {
    let _g = covenant_env_lock();
    unsafe { std::env::remove_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV) };
    let rewrite = serde_json::json!({"agent_id": "mallory"});
    // Default (unset) — advisory WARN only, the caller-side helper is
    // permitted to proceed (byte-identical legacy: this gate never ran
    // pre-#2060, so an unset env must be a pure no-op).
    assert!(
        consult_authorship_immutable_gate(Some("alice"), Some(&rewrite)).is_ok(),
        "default posture must be advisory"
    );
    // Enforce mode — refused.
    unsafe { std::env::set_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV, "1") };
    let err = consult_authorship_immutable_gate(Some("alice"), Some(&rewrite))
        .expect_err("must refuse an authorship rewrite under enforce");
    assert!(err.downcast_ref::<GovernanceRefusal>().is_some());
    unsafe { std::env::remove_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV) };
}

#[test]
fn update_preserves_authorship_by_default_and_refuses_rewrite_under_enforce() {
    let _g = covenant_env_lock();
    unsafe { std::env::remove_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV) };
    let conn = fresh_conn();
    let mut mem = make_mem("owned by alice", "ns/authorship");
    mem.metadata = serde_json::json!({"agent_id": "alice"});
    let id = db::insert(&conn, &mem).unwrap();

    // #2106 review item 1 — with the gate OFF (default), the sqlite
    // `update_with_expected_version` now PRESERVES the stored agent_id via the
    // json_patch provenance overlay (backend parity with the postgres CASE
    // overlay), so a direct rewrite attempt is silently preserved (existing
    // wins) rather than applied. This closes the backend-divergence hole where
    // sqlite (unlike postgres) let a bypass-the-caller-helper rewrite land.
    let rewrite = serde_json::json!({"agent_id": "mallory"});
    let (found, _) = db::update_with_expected_version(
        &conn,
        &id,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&rewrite),
        None,
        None,
    )
    .unwrap();
    assert!(found);
    let stored = db::get(&conn, &id).unwrap().unwrap();
    assert_eq!(
        stored.metadata.get("agent_id").and_then(|v| v.as_str()),
        Some("alice"),
        "gate-off update must PRESERVE the stored authorship (provenance overlay)"
    );

    // Re-seed a fresh row owned by alice and retry under enforce.
    let mut mem2 = make_mem("owned by alice 2", "ns/authorship2");
    mem2.metadata = serde_json::json!({"agent_id": "alice"});
    let id2 = db::insert(&conn, &mem2).unwrap();
    unsafe { std::env::set_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV, "1") };
    let err = db::update_with_expected_version(
        &conn,
        &id2,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&rewrite),
        None,
        None,
    )
    .expect_err("enforce must refuse an authorship rewrite");
    assert!(err.downcast_ref::<GovernanceRefusal>().is_some());
    let unchanged = db::get(&conn, &id2).unwrap().unwrap();
    assert_eq!(
        unchanged.metadata.get("agent_id").and_then(|v| v.as_str()),
        Some("alice"),
        "a refused rewrite must not mutate the stored authorship"
    );

    // A same-agent update still succeeds under enforce.
    let same = serde_json::json!({"agent_id": "alice", "note": "touch"});
    let (found2, _) = db::update_with_expected_version(
        &conn,
        &id2,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&same),
        None,
        None,
    )
    .unwrap();
    assert!(
        found2,
        "a same-agent_id update must still succeed under enforce"
    );
    unsafe { std::env::remove_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV) };
}

#[test]
fn update_with_archive_on_supersede_refuses_authorship_rewrite_under_enforce() {
    let _g = covenant_env_lock();
    unsafe { std::env::remove_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV) };
    let conn = fresh_conn();
    let mut mem = make_mem("owned by alice supersede", "ns/authorship-supersede");
    mem.metadata = serde_json::json!({"agent_id": "alice", "why_trace": "seed"});
    let id = db::insert(&conn, &mem).unwrap();

    unsafe { std::env::set_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV, "1") };
    let rewrite = serde_json::json!({"agent_id": "mallory", "why_trace": "seed"});
    let err = db::update_with_archive_on_supersede(
        &conn,
        &id,
        Some("new content title"),
        Some("new content body"),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&rewrite),
        None,
        None,
        EditSource::Llm,
    )
    .expect_err("enforce must refuse an authorship rewrite on the supersede path too");
    assert!(err.downcast_ref::<GovernanceRefusal>().is_some());
    // The original row must still be live and unchanged.
    let still_live = db::get(&conn, &id).unwrap().unwrap();
    assert_eq!(
        still_live.metadata.get("agent_id").and_then(|v| v.as_str()),
        Some("alice")
    );
    unsafe { std::env::remove_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV) };
}

// ── New-behavior coverage (#2102 reflection exemption / inbound never-refuse;
//    #2106 item 2 omission-preservation) ───────────────────────────────────

#[test]
fn reflection_kind_is_exempt_from_why_trace_enforce() {
    let _g = covenant_env_lock();
    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    let conn = fresh_conn();
    // #2106 item 4 — a substrate-authored Reflection row with NO why_trace is
    // exempt (the reflection funnel `insert_with_conflict(Error)` is wired to
    // the gate, but the gate never refuses a Reflection/Persona kind), so the
    // curator reflection pass keeps working under enforce.
    let mut refl = make_mem("a reflection", "ns/reflect-exempt");
    refl.memory_kind = MemoryKind::Reflection;
    assert!(
        db::insert_with_conflict(&conn, &refl, db::ConflictMode::Error).is_ok(),
        "enforce must NOT refuse a substrate Reflection write lacking why_trace"
    );
    // A caller-origin Observation still gets refused via the same funnel.
    let obs = make_mem("an observation", "ns/reflect-exempt");
    let err = db::insert_with_conflict(&conn, &obs, db::ConflictMode::Error)
        .expect_err("enforce must refuse a why_trace-less Observation via insert_with_conflict");
    assert!(err.downcast_ref::<GovernanceRefusal>().is_some());
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

#[test]
fn insert_if_newer_never_refuses_missing_why_trace_under_enforce() {
    let _g = covenant_env_lock();
    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    let conn = fresh_conn();
    // Federation-receive funnel: a why_trace-less inbound write must NEVER be
    // refused (CRDT convergence), only WARNed + forensically recorded.
    let inbound = make_mem("inbound no wt", "ns/fed-inbound");
    assert!(
        db::insert_if_newer(&conn, &inbound).is_ok(),
        "insert_if_newer must accept a why_trace-less inbound write under enforce"
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

#[test]
fn update_omitting_agent_id_preserves_authorship() {
    let _g = covenant_env_lock();
    unsafe { std::env::remove_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV) };
    let conn = fresh_conn();
    let mut mem = make_mem("owned by alice omit", "ns/authorship-omit");
    mem.metadata = serde_json::json!({"agent_id": "alice"});
    let id = db::insert(&conn, &mem).unwrap();

    // #2106 item 2 — a full-object metadata patch that OMITS agent_id must NOT
    // erase the stored author (erasure is worse than rewrite). The json_patch
    // provenance overlay preserves it. The authorship gate sees no incoming
    // agent_id → no violation; preservation does the work.
    let omit = serde_json::json!({"note": "no agent_id here"});
    let (found, _) = db::update_with_expected_version(
        &conn,
        &id,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&omit),
        None,
        None,
    )
    .unwrap();
    assert!(found);
    let stored = db::get(&conn, &id).unwrap().unwrap();
    assert_eq!(
        stored.metadata.get("agent_id").and_then(|v| v.as_str()),
        Some("alice"),
        "omitting agent_id on a full-replace update must preserve the stored author"
    );
    assert_eq!(
        stored.metadata.get("note").and_then(|v| v.as_str()),
        Some("no agent_id here"),
        "the caller's non-provenance keys still land"
    );
}
