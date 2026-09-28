// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! Boids predator plan item 3, part 4 (R5; #3927 / #3266, 5-agent vote
//! `4d3ea1c5`) — the G7 contradiction soft-loser down-weight on the Postgres
//! HYBRID recall lane. PG `search` already honoured the marker; PG
//! `recall_hybrid` did not, so the same row ranked inconsistently across two
//! PG lanes (e.g. a corpus migrated from sqlite, which carries its markers).
//! The penalty is applied to the FUSED score, the sqlite hybrid twin's
//! placement (#2338): an FTS-only SQL penalty would leave the loser fully
//! ranked through the cosine half.
//!
//! Honest scope (R5): nothing on Postgres WRITES the marker today — the only
//! producer is the sqlite curator contradiction pass, and the CRDT merge drops
//! any remote-introduced `contradiction_*` key (node-local, #1824). This pins
//! the CONSUMER, so a marked row is down-weighted on every PG lane it reaches.
#![cfg(feature = "sal-postgres")]

use ai_memory::models::{LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore};
use serde_json::json;

fn mem(ns: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "ai:tester"}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
    }
}

/// The ONE predicate both hybrid lanes use.
#[test]
fn soft_loser_penalty_is_the_factor_only_for_a_true_marker_3927() {
    let f = ai_memory::storage::SOFT_LOSER_SCORE_FACTOR;
    let key = ai_memory::models::field_names::CONTRADICTION_SOFT_LOSER;
    assert!(
        (ai_memory::storage::soft_loser_penalty(&json!({ key: true })) - f).abs() < f64::EPSILON
    );
    for v in [
        json!({}),
        json!({ key: false }),
        json!({ key: "true" }),
        json!({ key: 1 }),
    ] {
        assert!(
            (ai_memory::storage::soft_loser_penalty(&v) - 1.0).abs() < f64::EPSILON,
            "only a JSON boolean true is the marker (the #2436 lesson): {v}"
        );
    }
}

/// A marked row that OUTRANKS its unmarked twin on keywords alone must fall
/// below it on the PG hybrid lane. RED on the parent: no penalty, the marked
/// row stays first.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_recall_hybrid_down_weights_the_soft_loser_3927() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        return;
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ns = format!("softloser-{}", uuid::Uuid::new_v4().simple());
    let ctx = CallerContext::for_agent("ai:tester");
    // A: stronger keyword relevance (the term three times) — would rank first.
    // Distinct titles: (title, namespace) is an upsert key on PG, so identical
    // titles would collapse the two rows into one and make the cell vacuous.
    let a = mem(
        &ns,
        "zebrafish migration notes alpha",
        "zebrafish zebrafish zebrafish migration",
    );
    let b = mem(
        &ns,
        "zebrafish migration notes bravo",
        "zebrafish migration",
    );
    store.store(&ctx, &a).await.expect("seed a");
    store.store(&ctx, &b).await.expect("seed b");
    let mut filter = Filter::default();
    filter.namespace = Some(ns.clone());
    // Explicit limit: `limit == 0` falls back to RECALL_FALLBACK_LIMIT, which
    // would truncate to the top row and hide the ordering this cell measures.
    filter.limit = 10;

    // Control: without the marker, A ranks first (the cell is not vacuous).
    let before = store
        .recall_hybrid(&ctx, "zebrafish", None, &filter)
        .await
        .expect("recall");
    assert_eq!(
        before.len(),
        2,
        "control: BOTH rows recalled (not collapsed)"
    );
    assert_eq!(
        before.first().map(|(m, _)| m.id.as_str()),
        Some(a.id.as_str()),
        "control: A outranks B unmarked"
    );

    // Mark A as the G7 soft loser (JSON boolean true, as conserve_contradiction writes).
    sqlx::query("UPDATE memories SET metadata = jsonb_set(metadata, '{contradiction_soft_loser}', 'true'::jsonb) WHERE id = $1")
        .bind(&a.id)
        .execute(store.pool())
        .await
        .expect("mark a");
    let after = store
        .recall_hybrid(&ctx, "zebrafish", None, &filter)
        .await
        .expect("recall");
    assert_eq!(after.len(), 2, "both rows still recalled after marking");
    assert_eq!(
        after.first().map(|(m, _)| m.id.as_str()),
        Some(b.id.as_str()),
        "the soft loser must fall below its unmarked twin on the PG hybrid lane: {:?}",
        after
            .iter()
            .map(|(m, s)| (&m.content, *s))
            .collect::<Vec<_>>()
    );
}
