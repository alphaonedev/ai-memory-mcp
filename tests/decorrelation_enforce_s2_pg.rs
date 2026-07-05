// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 §25.3 S2 (D3-021, #1767) — POSTGRES parity for the write-time
//! decorrelation ENFORCE path + OFF inertness pin (the kill-test on the
//! postgres reflect chokepoint). Gated on `sal-postgres` + a live
//! `AI_MEMORY_TEST_POSTGRES_URL`; self-skips otherwise. Separate test
//! binary from the sqlite twin so the process-global
//! `AI_MEMORY_REFLECT_DECORRELATION_MODE` env cannot race across them.

#![cfg(feature = "sal-postgres")]

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use chrono::Utc;

const MODE_ENV: &str = "AI_MEMORY_REFLECT_DECORRELATION_MODE";

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

fn mem(ns: &str, title: &str, kind: MemoryKind, metadata: serde_json::Value) -> Memory {
    let now = Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("content for {title}"),
        tags: vec!["test".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "nhi".to_string(),
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

fn attested_reflection(ns: &str, title: &str) -> Memory {
    mem(
        ns,
        title,
        MemoryKind::Reflection,
        serde_json::json!({
            "agent_id": "curator",
            "model_family": "llama",
            "model_family_attest": "loader_observed",
        }),
    )
}

fn reflect_input(ns: &str, source_ids: Vec<String>, title: &str) -> db::ReflectInput {
    db::ReflectInput {
        source_ids,
        title: title.to_string(),
        content: "a fresh reflection".to_string(),
        namespace: Some(ns.to_string()),
        tier: Tier::Mid,
        tags: vec!["r".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "nhi".to_string(),
        agent_id: "curator".to_string(),
        metadata: serde_json::json!({}),
    }
}

#[tokio::test]
async fn pg_enforce_refuses_attested_monoculture_then_off_is_inert() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    let ctx = CallerContext::for_agent("curator".to_string());
    // Unique namespace so re-runs against the same DB stay isolated.
    let ns = format!("team/decorr-pg-{}", uuid::Uuid::new_v4());

    // Base source + 3 ATTESTED `llama` reflection-kind memories.
    let base = mem(
        &ns,
        "base-source",
        MemoryKind::Observation,
        serde_json::json!({"agent_id": "curator"}),
    );
    let base_id = store.store(&ctx, &base).await.expect("store base");
    for i in 0..3 {
        let r = attested_reflection(&ns, &format!("attested-refl-{i}"));
        store
            .store(&ctx, &r)
            .await
            .expect("store attested reflection");
    }

    // Backing model_attestations row (predicate condition c). Idempotent
    // ON CONFLICT DO NOTHING via the UNIQUE constraint.
    let pool = sqlx::postgres::PgPool::connect(&url).await.expect("pool");
    sqlx::query(
        "INSERT INTO model_attestations
             (id, provider, model_ref, model_digest, model_family,
              attest_level, agent_id, signature, created_at)
         VALUES ($1,'ollama','llama3.1:8b',NULL,'llama','loader_observed','',NULL,$2)
         ON CONFLICT DO NOTHING",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(Utc::now().to_rfc3339())
    .execute(&pool)
    .await
    .expect("insert model_attestation");

    // ── ENFORCE: the write is REFUSED on attested evidence ──────────
    unsafe { std::env::set_var(MODE_ENV, "enforce") };
    let input = reflect_input(&ns, vec![base_id.clone()], "gated-reflection-pg");
    let err = store
        .reflect(&ctx, &input)
        .await
        .expect_err("enforce must refuse attested monoculture");
    match err {
        db::ReflectError::DecorrelationRefused {
            distinct_attested_families,
            attested_rows,
            quorum_n,
            namespace,
        } => {
            assert_eq!(distinct_attested_families, 1);
            assert!(attested_rows >= 3);
            assert_eq!(quorum_n, 3);
            assert_eq!(namespace, ns);
        }
        other => {
            unsafe { std::env::remove_var(MODE_ENV) };
            panic!("expected DecorrelationRefused, got {other}");
        }
    }

    // A signed refusal row landed on the postgres audit chain.
    let refused: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = 'reflection.decorrelation_refused'",
    )
    .fetch_one(&pool)
    .await
    .expect("count refused");
    assert!(refused >= 1, "at least one signed decorrelation refusal");

    // ── OFF: the SAME write is byte-identically ALLOWED ─────────────
    unsafe { std::env::set_var(MODE_ENV, "off") };
    let outcome = store
        .reflect(&ctx, &input)
        .await
        .expect("off mode must allow (inertness pin)");
    assert_eq!(outcome.namespace, ns);

    unsafe { std::env::remove_var(MODE_ENV) };

    // Cleanup the namespace rows (best-effort).
    let _ = sqlx::query("DELETE FROM memories WHERE namespace = $1")
        .bind(&ns)
        .execute(&pool)
        .await;
}
