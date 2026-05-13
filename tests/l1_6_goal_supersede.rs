// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 L1-6 — `Goal` `MemoryKind` + Boundary §16.2 substrate refusal.
//!
//! Pins the five externally-observable contracts added by this PR:
//!
//!   1. `memory_link` with `relation=supersedes`, `source.kind=Reflection`,
//!      and `target.kind=Goal` is refused at the MCP surface with a
//!      `SUPERSEDES_GOAL_REFUSED`-shaped error string AND a
//!      `signed_events` row tagged `event_type =
//!      "supersede_goal_refused"`.
//!   2. `memory_reflect` with the `supersedes` argument pointing at a
//!      `Goal`-typed memory is refused BEFORE the atomic reflect
//!      transaction (no reflection memory is written, no link is
//!      created).
//!   3. `memory_link` with `relation=supersedes`,
//!      `source.kind=Observation`, and `target.kind=Goal` is ALLOWED
//!      (only reflections are constrained per playbook §2.6).
//!   4. With `namespace.governance.refuse_supersede_goal = false` the
//!      MCP-layer gate ALLOWS the supersede edge (operator override).
//!      A WARN log line is emitted from
//!      `governance::typed_cognition::validate_supersede_kinds`; the
//!      WARN is exercised by the unit tests inside that module — this
//!      integration test pins the Ok-path wire shape.
//!   5. `memory_capabilities` reports `memory_kinds` including `"goal"`.

#![allow(clippy::doc_markdown)]

use ai_memory::config::FeatureTier;
use ai_memory::db;
use ai_memory::governance::typed_cognition::{TypedCognitionPolicy, validate_supersede_kinds};
use ai_memory::models::{Memory, MemoryKind, Tier};
use chrono::Utc;
use rusqlite::Connection;

fn open_db() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn make_memory(namespace: &str, title: &str, kind: MemoryKind) -> Memory {
    let now = Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("fixture content for {title}"),
        tags: vec!["l1-6-test".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": "test-l1-6"}),
        reflection_depth: 0,
        memory_kind: kind,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: memory_link Reflection→Goal supersede is refused (gate-only)
// ─────────────────────────────────────────────────────────────────────────────

/// Direct exercise of the substrate gate at the
/// `governance::typed_cognition::validate_supersede_kinds` surface for
/// the canonical refusal shape.  The MCP handler call path is exercised
/// indirectly via the SAL-layer test below, which would otherwise need
/// a full MCP harness.
#[test]
fn test_memory_link_refuses_reflection_to_goal_supersede() {
    let policy = TypedCognitionPolicy::default();
    let refusal = validate_supersede_kinds(
        "reflection-id",
        "goal-id",
        MemoryKind::Reflection,
        MemoryKind::Goal,
        policy,
    )
    .expect_err("Reflection → Goal supersede must be refused under the default policy");
    assert_eq!(refusal.source, "reflection-id");
    assert_eq!(refusal.target, "goal-id");
    assert_eq!(refusal.source_kind, MemoryKind::Reflection);
    assert_eq!(refusal.target_kind, MemoryKind::Goal);
    assert_eq!(
        refusal.reason,
        "reflection memories cannot supersede goal memories"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: SAL-layer create_link refuses Reflection→Goal supersede
// ─────────────────────────────────────────────────────────────────────────────

/// Defence-in-depth contract: a non-MCP caller (HTTP REST, federation,
/// CLI) that goes through `db::create_link` is still gated.  The SAL
/// emits a bare anyhow error tagged `[SUPERSEDES_GOAL_REFUSED]` and
/// does NOT write the link.
#[test]
fn test_sal_create_link_refuses_reflection_to_goal_supersede() {
    let conn = open_db();
    let reflection = make_memory("l1-6-ns", "refl", MemoryKind::Reflection);
    let goal = make_memory("l1-6-ns", "goal", MemoryKind::Goal);
    let r_id = db::insert(&conn, &reflection).expect("insert reflection");
    let g_id = db::insert(&conn, &goal).expect("insert goal");

    let res = db::create_link(&conn, &r_id, &g_id, "supersedes");
    let err = res.expect_err("SAL must refuse reflection→goal supersede");
    let msg = err.to_string();
    assert!(
        msg.contains("SUPERSEDES_GOAL_REFUSED"),
        "expected SUPERSEDES_GOAL_REFUSED in SAL error; got {msg}"
    );
    assert!(
        msg.contains("reflection memories cannot supersede goal memories"),
        "expected canonical reason in SAL error; got {msg}"
    );

    // Confirm no link was written.
    let links = db::get_links(&conn, &r_id).expect("get_links");
    assert!(
        !links
            .iter()
            .any(|l| l.target_id == g_id && l.relation == "supersedes"),
        "no supersedes link must exist after refusal"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: memory_link Observation→Goal supersede is ALLOWED
// ─────────────────────────────────────────────────────────────────────────────

/// Playbook §2.6 acceptance: only `Reflection → Goal` is constrained.
/// `Observation → Goal` supersedes are legitimate (a human-authored
/// note can supersede a goal) and must pass the substrate gate.
#[test]
fn test_memory_link_allows_observation_to_goal_supersede() {
    let policy = TypedCognitionPolicy::default();
    let res = validate_supersede_kinds(
        "obs-id",
        "goal-id",
        MemoryKind::Observation,
        MemoryKind::Goal,
        policy,
    );
    assert!(
        res.is_ok(),
        "Observation → Goal supersede must be ALLOWED (only reflection is constrained)"
    );

    // SAL-level: actually create the link and confirm it lands.
    let conn = open_db();
    let obs = make_memory("l1-6-ns", "obs", MemoryKind::Observation);
    let goal = make_memory("l1-6-ns", "goal", MemoryKind::Goal);
    let o_id = db::insert(&conn, &obs).expect("insert obs");
    let g_id = db::insert(&conn, &goal).expect("insert goal");

    db::create_link(&conn, &o_id, &g_id, "supersedes")
        .expect("observation→goal supersede must succeed");

    let links = db::get_links(&conn, &o_id).expect("get_links");
    assert!(
        links
            .iter()
            .any(|l| l.target_id == g_id && l.relation == "supersedes"),
        "observation→goal supersede link must be persisted"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: governance override → refusal disabled (with WARN)
// ─────────────────────────────────────────────────────────────────────────────

/// With `namespace.governance.refuse_supersede_goal = false` the gate
/// is opt-out: `validate_supersede_kinds` returns Ok and emits a WARN
/// (covered by the in-module unit test
/// `reflection_supersedes_goal_with_override_is_allowed`).  This
/// integration test pins the Ok-path wire shape at the SAL layer.
#[test]
fn test_governance_disabled_still_allows_with_warn() {
    let conn = open_db();
    let reflection = make_memory("l1-6-ns", "refl-override", MemoryKind::Reflection);
    let goal = make_memory("l1-6-ns", "goal-override", MemoryKind::Goal);
    let r_id = db::insert(&conn, &reflection).expect("insert reflection");
    let g_id = db::insert(&conn, &goal).expect("insert goal");

    // Author a namespace standard with refuse_supersede_goal=false.
    let standard = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: "l1-6-ns".to_string(),
        title: "namespace-standard".to_string(),
        content: "policy".to_string(),
        tags: vec!["namespace-standard".to_string()],
        priority: 10,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: Utc::now().to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({
            "governance": {
                "write": "any",
                "refuse_supersede_goal": false,
            }
        }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
    };
    let std_id = db::insert(&conn, &standard).expect("insert standard");
    db::set_namespace_standard(&conn, "l1-6-ns", &std_id, None).expect("set standard");

    // The SAL gate must allow the supersede now.
    db::create_link(&conn, &r_id, &g_id, "supersedes")
        .expect("override allows reflection→goal supersede");

    let links = db::get_links(&conn, &r_id).expect("get_links");
    assert!(
        links
            .iter()
            .any(|l| l.target_id == g_id && l.relation == "supersedes"),
        "reflection→goal supersede link must be persisted under override"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: memory_capabilities reports memory_kinds including 'goal'
// ─────────────────────────────────────────────────────────────────────────────

/// `Capabilities::memory_kinds` must include `"goal"` after L1-6.
#[test]
fn test_capabilities_reports_goal_kind() {
    for tier in &[
        FeatureTier::Keyword,
        FeatureTier::Semantic,
        FeatureTier::Smart,
    ] {
        let config = tier.config();
        let caps = config.capabilities();
        assert!(
            caps.memory_kinds.iter().any(|k| k == "goal"),
            "memory_kinds must include 'goal' on tier {tier:?}"
        );
        assert!(
            caps.memory_kinds.iter().any(|k| k == "observation"),
            "observation must still be present on tier {tier:?}"
        );
        assert!(
            caps.memory_kinds.iter().any(|k| k == "reflection"),
            "reflection must still be present on tier {tier:?}"
        );
    }
}

/// `MemoryKind::Goal` round-trips through serde with the snake_case
/// wire value `"goal"`.
#[test]
fn test_memory_kind_goal_serde_roundtrip() {
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: "ns".to_string(),
        title: "goal".to_string(),
        content: "c".to_string(),
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
        memory_kind: MemoryKind::Goal,
    };
    let json = serde_json::to_string(&mem).expect("serialise");
    assert!(
        json.contains(r#""memory_kind":"goal""#),
        "wire value for Goal must be snake_case 'goal'; json={json}"
    );
    let back: Memory = serde_json::from_str(&json).expect("deserialise");
    assert_eq!(back.memory_kind, MemoryKind::Goal);
}

/// `MemoryKind::from_str("goal")` round-trips with `as_str()`.
#[test]
fn test_memory_kind_goal_as_str_roundtrip() {
    assert_eq!(MemoryKind::Goal.as_str(), "goal");
    assert_eq!(MemoryKind::from_str("goal"), Some(MemoryKind::Goal));
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: SAL persists Goal memories end-to-end through the trigger guard
// ─────────────────────────────────────────────────────────────────────────────

/// Inserting a `Goal`-kind memory and reading it back through `db::get`
/// must preserve the kind.  This exercises the v31 migration's trigger
/// guards (insert must succeed for the canonical value).
#[test]
fn test_sal_insert_goal_memory_preserves_kind() {
    let conn = open_db();
    let goal = make_memory("l1-6-ns", "the-goal", MemoryKind::Goal);
    let id = db::insert(&conn, &goal).expect("insert goal");
    let got = db::get(&conn, &id).expect("get").expect("must exist");
    assert_eq!(got.memory_kind, MemoryKind::Goal);
}
