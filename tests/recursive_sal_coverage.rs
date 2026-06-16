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

    // list_recall_observations() — read path + recall_id filter. The
    // postgres variant runs against the SHARED CI database, where other
    // suites (e.g. cov_ga2_postgres's recall_observation_insert) write
    // observations, so an UNFILTERED scan is non-deterministic. Query a
    // recall_id this test never writes: the result is deterministically
    // empty regardless of co-resident suites, and the call still
    // exercises the read path AND the recall_id predicate.
    let absent_recall = format!("sal-cov-absent-recall-{}", uuid_like());
    let obs = store
        .list_recall_observations(Some(&absent_recall), None, None, None, 50)
        .await
        .expect("list_recall_observations ok");
    assert!(
        obs.is_empty(),
        "no observations exist for a recall_id this test never wrote"
    );

    // #1705 — record_recall_observation / mark_recall_consumed /
    // recall_observation_gc round-trip through the SAL trait, exercised on
    // BOTH adapters (this is the write-side parity the ledger lacked: pre-
    // #1705 a postgres daemon never populated the ledger). Uses base_id as
    // both the recalled candidate and the consuming memory; rid is unique
    // so the read filter is deterministic on the shared CI database.
    let rid = format!("sal-cov-rec-{}", uuid_like());
    let wrote = store
        .record_recall_observation(
            &rid,
            &[(base_id.clone(), "hybrid".to_string(), 1, 0.9)],
            Some(TEST_AGENT),
            Some(TEST_NS),
        )
        .await
        .expect("record_recall_observation ok");
    assert_eq!(
        wrote, 1,
        "one identity-stamped ledger row written via the SAL trait"
    );
    let listed = store
        .list_recall_observations(Some(&rid), None, None, None, 10)
        .await
        .expect("list after record ok");
    assert_eq!(listed.len(), 1, "the written row is listed");
    assert!(!listed[0].consumed, "fresh row is unconsumed");
    // #1705 cross-agent replay guard: a DIFFERENT agent citing this
    // recall_id (stamped to TEST_AGENT) must NOT flip the row.
    let replay = store
        .mark_recall_consumed(
            &rid,
            &[base_id.clone()],
            &base_id,
            Some("other-agent-sal-cov"),
        )
        .await
        .expect("mark_recall_consumed (wrong agent) ok");
    assert_eq!(
        replay, 0,
        "cross-agent recall_id replay is rejected (0 flipped)"
    );
    // The owning agent's citation flips it.
    let flipped = store
        .mark_recall_consumed(&rid, &[base_id.clone()], &base_id, Some(TEST_AGENT))
        .await
        .expect("mark_recall_consumed ok");
    assert_eq!(flipped, 1, "the owning agent's citation flips the row");
    let consumed = store
        .list_recall_observations(Some(&rid), Some(true), None, None, 10)
        .await
        .expect("list consumed ok");
    assert_eq!(
        consumed.len(),
        1,
        "the consumed row lists under consumed=true"
    );
    // A 10-year TTL prunes nothing recent (and nothing co-resident is that old).
    let pruned = store
        .recall_observation_gc(3650)
        .await
        .expect("recall_observation_gc ok");
    assert_eq!(pruned, 0, "recent row not pruned by a 10-year TTL");

    // #1709 Pillar 1 — action_create / action_get round-trip through the SAL
    // trait, on BOTH adapters (the v59 coordination substrate).
    let aid = format!("sal-cov-act-{}", uuid_like());
    let action = ai_memory::models::Action {
        id: aid.clone(),
        namespace: TEST_NS.to_string(),
        kind: "test.coordinate".to_string(),
        state: ai_memory::models::ActionState::Pending,
        title: "sal-cov action".to_string(),
        payload: serde_json::json!({"k": "v"}),
        priority: 7,
        agent_id: Some(TEST_AGENT.to_string()),
        claimed_by: None,
        vector_clock: serde_json::json!({TEST_AGENT: 1}),
        metadata: serde_json::json!({}),
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
    };
    let created_id = store
        .action_create(&ctx, &action)
        .await
        .expect("action_create ok");
    assert_eq!(created_id, aid);
    let got = store
        .action_get(&ctx, &aid)
        .await
        .expect("action_get ok")
        .expect("action present after create");
    assert_eq!(got.id, aid);
    assert_eq!(got.namespace, TEST_NS);
    assert_eq!(got.kind, "test.coordinate");
    assert_eq!(got.state, ai_memory::models::ActionState::Pending);
    assert_eq!(got.priority, 7);
    assert_eq!(got.agent_id.as_deref(), Some(TEST_AGENT));
    assert_eq!(got.payload, serde_json::json!({"k": "v"}));
    // Unknown id → None (not an error).
    let missing = store
        .action_get(&ctx, "sal-cov-act-does-not-exist")
        .await
        .expect("action_get unknown ok");
    assert!(missing.is_none(), "unknown action id yields None");

    // #1709 — action_transition (state-machine guard) + action_list.
    let claimed = store
        .action_transition(
            &ctx,
            &aid,
            ai_memory::models::ActionState::Claimed,
            Some(TEST_AGENT),
            1_700_000_100,
        )
        .await
        .expect("action_transition pending->claimed ok");
    assert_eq!(claimed.state, ai_memory::models::ActionState::Claimed);
    assert_eq!(claimed.claimed_by.as_deref(), Some(TEST_AGENT));
    assert_eq!(claimed.updated_at, 1_700_000_100);
    // Illegal transition (claimed→done skips in_progress) is rejected.
    let illegal = store
        .action_transition(
            &ctx,
            &aid,
            ai_memory::models::ActionState::Done,
            None,
            1_700_000_200,
        )
        .await;
    assert!(
        illegal.is_err(),
        "illegal transition claimed->done rejected"
    );
    // Transition on a missing action → error (NotFound).
    let absent = store
        .action_transition(
            &ctx,
            "sal-cov-act-missing",
            ai_memory::models::ActionState::Claimed,
            None,
            1_700_000_300,
        )
        .await;
    assert!(absent.is_err(), "transition on a missing action errors");
    // action_list filtered by namespace + state surfaces the claimed action.
    let listed = store
        .action_list(
            &ctx,
            Some(TEST_NS),
            Some(ai_memory::models::ActionState::Claimed),
            50,
        )
        .await
        .expect("action_list ok");
    assert!(
        listed.iter().any(|a| a.id == aid),
        "the claimed action appears in the namespace+state-filtered list"
    );

    // #1709 — action DAG edges: create a second action, add a typed edge,
    // and verify action_edges_for surfaces it (both adapters).
    let aid2 = format!("sal-cov-act2-{}", uuid_like());
    store
        .action_create(
            &ctx,
            &ai_memory::models::Action {
                id: aid2.clone(),
                namespace: TEST_NS.to_string(),
                kind: "test.coordinate".to_string(),
                state: ai_memory::models::ActionState::Pending,
                title: "sal-cov action 2".to_string(),
                payload: serde_json::json!({}),
                priority: 5,
                agent_id: Some(TEST_AGENT.to_string()),
                claimed_by: None,
                vector_clock: serde_json::json!({}),
                metadata: serde_json::json!({}),
                created_at: 1_700_000_000,
                updated_at: 1_700_000_000,
            },
        )
        .await
        .expect("action_create 2 ok");
    store
        .action_add_edge(
            &ctx,
            &aid,
            &aid2,
            ai_memory::models::EdgeType::Requires,
            1_700_000_400,
        )
        .await
        .expect("action_add_edge ok");
    // Idempotent — re-adding the same edge is a no-op (PK dedup).
    store
        .action_add_edge(
            &ctx,
            &aid,
            &aid2,
            ai_memory::models::EdgeType::Requires,
            1_700_000_401,
        )
        .await
        .expect("action_add_edge idempotent ok");
    let edges = store
        .action_edges_for(&ctx, &aid)
        .await
        .expect("action_edges_for ok");
    let mine = edges
        .iter()
        .find(|e| e.from_action == aid && e.to_action == aid2)
        .expect("the requires edge is surfaced for the from-node");
    assert_eq!(mine.edge_type, ai_memory::models::EdgeType::Requires);
    // The same edge is visible from the to-node (inbound union).
    let inbound = store
        .action_edges_for(&ctx, &aid2)
        .await
        .expect("action_edges_for inbound ok");
    assert!(
        inbound
            .iter()
            .any(|e| e.from_action == aid && e.to_action == aid2),
        "edge is visible from the to-node (inbound)"
    );
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

/// Postgres twin — compile-gated on `sal-postgres` (`PostgresStore` lives
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
