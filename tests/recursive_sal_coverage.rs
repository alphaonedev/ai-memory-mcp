// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
//! #1549 coverage — exercises the recursive-learning `MemoryStore` SAL
//! trait surface (`reflect`, `get_reflection_origin`,
//! `list_recall_observations`) end-to-end on `SqliteStore`, and (gated on
//! `AI_MEMORY_TEST_POSTGRES_URL`) on `PostgresStore`, so the postgres SAL
//! coverage added for the do-1461 recursive-frameworks campaign carries
//! line coverage on BOTH adapters through the trait (not just the inherent
//! native-sqlx entry points).

// The `MemoryStore` SAL trait (`ai_memory::store`) is `#[cfg(feature = "sal")]`,
// so this whole coverage file is sal-only; in a non-sal build it compiles to
// an empty test target.
#![cfg(feature = "sal")]

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::{CallerContext, MemoryStore};
use std::sync::Arc;

const TEST_NS: &str = "_sal_cov";
const TEST_AGENT: &str = "test-agent-sal-cov";

fn base_memory(id: &str, namespace: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("base content for {title}"),
        tags: Vec::new(),
        priority: 5,
        confidence: 1.0,
        source: "nhi".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": TEST_AGENT }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    }
}

fn reflect_input(source_ids: Vec<String>, title: &str) -> ai_memory::db::ReflectInput {
    ai_memory::db::ReflectInput {
        source_ids,
        title: title.to_string(),
        content: format!("synthesised reflection for {title}"),
        namespace: Some(TEST_NS.to_string()),
        tier: Tier::Mid,
        tags: vec!["reflection".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "nhi".to_string(),
        agent_id: TEST_AGENT.to_string(),
        metadata: serde_json::json!({}),
    }
}

/// Drive the three trait methods against an arbitrary `MemoryStore` and
/// assert the recursive-learning contract holds. Backend-agnostic so the
/// sqlite and postgres tests share one body.
async fn exercise_sal_surface(store: &dyn MemoryStore) {
    let ctx = CallerContext::for_admin(TEST_AGENT);

    // Seed a base (depth 0) memory.
    let base = base_memory(
        &format!("sal-base-{}", uuid_like()),
        TEST_NS,
        "sal-coverage-base",
    );
    let base_id = store.store(&ctx, &base).await.expect("store base");

    // reflect() — depth = max(source depths)+1 = 1, one reflects_on edge.
    let r1 = store
        .reflect(
            &ctx,
            &reflect_input(vec![base_id.clone()], "sal-refl-d1"),
            None,
        )
        .await
        .expect("reflect depth 1");
    assert_eq!(r1.reflection_depth, 1, "first reflection lands at depth 1");
    assert_eq!(r1.reflects_on, vec![base_id.clone()]);
    assert_eq!(r1.namespace, TEST_NS);

    // Chain one deeper — depth 2.
    let r2 = store
        .reflect(
            &ctx,
            &reflect_input(vec![r1.id.clone()], "sal-refl-d2"),
            None,
        )
        .await
        .expect("reflect depth 2");
    assert_eq!(r2.reflection_depth, 2, "second reflection lands at depth 2");

    // get_reflection_origin() — the reflection is flagged + carries depth.
    let origin = store
        .get_reflection_origin(&r2.id)
        .await
        .expect("origin lookup ok")
        .expect("origin present for a known reflection");
    assert!(origin.is_reflection, "depth>0 row is a reflection");
    assert_eq!(origin.original_depth, 2);
    assert_eq!(origin.memory_id, r2.id);

    // Unknown id → None (not an error).
    let missing = store
        .get_reflection_origin("does-not-exist-sal-cov")
        .await
        .expect("origin lookup ok for unknown id");
    assert!(missing.is_none(), "unknown id yields None");

    // list_recall_observations() — read path returns Ok (empty ledger on a
    // fresh store; the recall write path populates it elsewhere).
    let obs = store
        .list_recall_observations(None, None, None, None, 50)
        .await
        .expect("list_recall_observations ok");
    assert!(obs.is_empty(), "fresh store has no recall observations");
}

// A tiny unique-id source that does not pull in `Math.random`-equivalent
// nondeterminism concerns — the process pid plus a monotonic counter is
// enough to keep ids distinct within one test binary.
fn uuid_like() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

#[tokio::test]
async fn sqlite_sal_recursive_surface_roundtrips() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(f.path()).expect("open SqliteStore"));
    exercise_sal_surface(store.as_ref()).await;
}

/// Postgres twin — compile-gated on `sal-postgres` (PostgresStore lives
/// behind that feature) and runtime-gated on `AI_MEMORY_TEST_POSTGRES_URL`.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_sal_recursive_surface_roundtrips() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    exercise_sal_surface(&store).await;
}
