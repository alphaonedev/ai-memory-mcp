// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 §25.3 S2 (D3-021, #1767) — write-time decorrelation ENFORCE
//! path (the EPIC exit-criterion-8 kill-test evidence) + the OFF
//! inertness pin.
//!
//! This exercises the WIRED enforce path at the sqlite reflect
//! chokepoint (`db::reflect` → `reflect_with_hooks` → the §25.3 S2 gate):
//! an `enforce`-mode reflection into a namespace whose attested corpus is
//! an evidence-backed monoculture (>= `MIN_REFLECTIONS_FLOOR` attested rows,
//! < N distinct attested families) is REFUSED with a signed
//! `reflection.decorrelation_refused` row — and the SAME write is
//! byte-identically ALLOWED with the mode `off` (compiled default).
//!
//! Env is process-local to this integration-test binary, so setting
//! `AI_MEMORY_REFLECT_DECORRELATION_MODE` here cannot leak into other
//! test files (each `tests/*.rs` is its own process).

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::storage::model_attest;
use chrono::Utc;

const MODE_ENV: &str = "AI_MEMORY_REFLECT_DECORRELATION_MODE";
const NS: &str = "team/decorr";

fn base_memory(title: &str, kind: MemoryKind, metadata: serde_json::Value) -> Memory {
    let now = Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("content for {title}"),
        tags: vec!["test".to_string()],
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
        memory_kind: kind,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

/// A reflection-kind memory carrying a loader-ATTESTED `llama` family
/// stamp (the metadata condition of the attested-read predicate).
fn attested_llama_reflection(title: &str) -> Memory {
    base_memory(
        title,
        MemoryKind::Reflection,
        serde_json::json!({
            "agent_id": "curator",
            "model_family": "llama",
            "model_family_attest": "loader_observed",
        }),
    )
}

fn reflect_input(source_ids: Vec<String>, title: &str) -> db::ReflectInput {
    db::ReflectInput {
        source_ids,
        title: title.to_string(),
        content: "a fresh reflection".to_string(),
        namespace: Some(NS.to_string()),
        tier: Tier::Mid,
        tags: vec!["r".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "nhi".to_string(),
        agent_id: "curator".to_string(),
        metadata: serde_json::json!({}),
    }
}

fn refused_event_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = 'reflection.decorrelation_refused'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn enforce_refuses_attested_monoculture_then_off_is_inert() {
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();

    // A base source memory (Observation) for reflections to reflect on.
    let base = base_memory(
        "base-source",
        MemoryKind::Observation,
        serde_json::json!({}),
    );
    let base_id = db::insert(&conn, &base).expect("insert base");

    // Corpus: 3 ATTESTED `llama` reflection-kind memories in the namespace
    // (>= MIN_REFLECTIONS_FLOOR, all one family => an attested monoculture).
    for i in 0..3 {
        let r = attested_llama_reflection(&format!("attested-refl-{i}"));
        db::insert(&conn, &r).expect("insert attested reflection");
    }
    // The backing model_attestations row that makes the family ATTESTED
    // (predicate condition c — without it the stamp reads CLAIMED).
    model_attest::record_loader_observed(&conn, "ollama", "llama3.1:8b", "llama")
        .expect("record loader attestation");

    // ── ENFORCE: the write is REFUSED on attested evidence ──────────
    unsafe { std::env::set_var(MODE_ENV, "enforce") };
    let input = reflect_input(vec![base_id.clone()], "gated-reflection");
    let err = db::reflect(&conn, &input).expect_err("enforce must refuse attested monoculture");
    match err {
        db::ReflectError::DecorrelationRefused {
            distinct_attested_families,
            attested_rows,
            quorum_n,
            namespace,
        } => {
            assert_eq!(
                distinct_attested_families, 1,
                "one distinct attested family"
            );
            assert!(attested_rows >= 3, "at least the floor of attested rows");
            assert_eq!(quorum_n, 3, "default quorum N");
            assert_eq!(namespace, NS);
        }
        other => panic!("expected DecorrelationRefused, got {other}"),
    }
    // The signed refusal row landed exactly once.
    assert_eq!(
        refused_event_count(&conn),
        1,
        "exactly one signed reflection.decorrelation_refused row"
    );
    // The refused reflection was NOT written.
    let gated: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = 'gated-reflection'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(gated, 0, "the refused reflection must not be persisted");

    // ── OFF (compiled default): the SAME write is byte-identically allowed ──
    unsafe { std::env::set_var(MODE_ENV, "off") };
    let outcome = db::reflect(&conn, &input).expect("off mode must allow (inertness pin)");
    assert_eq!(outcome.namespace, NS);
    // No NEW refusal row emitted on the off path.
    assert_eq!(
        refused_event_count(&conn),
        1,
        "off mode emits no decorrelation refusal"
    );
    let written: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = 'gated-reflection'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(written, 1, "off mode persists the reflection");

    unsafe { std::env::remove_var(MODE_ENV) };
}
