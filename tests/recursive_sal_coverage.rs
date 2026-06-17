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

use ai_memory::models::{
    Checkpoint, CheckpointState, ConditionType, ConfidenceSource, Memory, MemoryKind, Routine,
    RoutineRun, RoutineRunState, RoutineState, Signal, SignalType, Tier,
};
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
        lifecycle_state: ai_memory::models::LifecycleState::Open,
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
// One sequential walk of the entire SAL surface (memories, links, recall
// ledger, action substrate, leases); splitting it would obscure the
// single-store contract it pins, so the length lint is allowed here.
#[allow(clippy::too_many_lines)]
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
            std::slice::from_ref(&base_id),
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
        .mark_recall_consumed(
            &rid,
            std::slice::from_ref(&base_id),
            &base_id,
            Some(TEST_AGENT),
        )
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

    // #1709 Pillar-2.5 — size_gc (corpus byte-cap eviction) round-trip
    // through the SAL trait on BOTH adapters. Uses a unique namespace so
    // the corpus arithmetic is deterministic on the shared CI postgres DB
    // regardless of co-resident suites. Inserts three over-cap rows
    // (lowest-value first = lower tier durability then lower priority),
    // size_gc's to a cap that forces two evictions, and asserts (a) the
    // count, (b) the lowest-value rows are gone, (c) the highest-value row
    // survives.
    let sgc_ns = format!("_sal_cov_sgc_{}", uuid_like());
    // ~1000-byte payload rows; tier drives the primary eviction order.
    let sgc_short = {
        let mut m = base_memory(&format!("sgc-short-{}", uuid_like()), &sgc_ns, "sgc-short");
        m.tier = Tier::Short;
        m.priority = 1;
        m.content = "x".repeat(1000);
        m
    };
    let sgc_mid = {
        let mut m = base_memory(&format!("sgc-mid-{}", uuid_like()), &sgc_ns, "sgc-mid");
        m.tier = Tier::Mid;
        m.priority = 5;
        m.content = "x".repeat(1000);
        m
    };
    let sgc_long = {
        let mut m = base_memory(&format!("sgc-long-{}", uuid_like()), &sgc_ns, "sgc-long");
        m.tier = Tier::Long;
        m.priority = 9;
        m.content = "x".repeat(1000);
        m
    };
    let sgc_short_id = store
        .store(&ctx, &sgc_short)
        .await
        .expect("store sgc-short");
    let sgc_mid_id = store.store(&ctx, &sgc_mid).await.expect("store sgc-mid");
    let sgc_long_id = store.store(&ctx, &sgc_long).await.expect("store sgc-long");

    // Under-cap → no-op first (a generous cap evicts nothing).
    let noop = store
        .size_gc(&sgc_ns, 1_000_000, true)
        .await
        .expect("size_gc under-cap ok");
    assert_eq!(noop, 0, "under-cap size_gc is a no-op");

    // Cap forcing two evictions: short-tier then mid-tier go first; the
    // long-tier high-priority row survives.
    let evicted = store
        .size_gc(&sgc_ns, 1500, true)
        .await
        .expect("size_gc over-cap ok");
    assert_eq!(evicted, 2, "two lowest-value rows evicted to reach cap");
    // `get` folds a missing row into a `NotFound` error (the trait does not
    // leak existence via Option), so an evicted row surfaces as `Err`.
    assert!(
        store.get(&ctx, &sgc_short_id).await.is_err(),
        "least-durable (short) row evicted"
    );
    assert!(
        store.get(&ctx, &sgc_mid_id).await.is_err(),
        "mid-tier row evicted next"
    );
    assert!(
        store.get(&ctx, &sgc_long_id).await.is_ok(),
        "highest-value long-tier row survives under cap"
    );

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

    // #1709 — lease lifecycle on the action (both adapters).
    let lease = store
        .lease_acquire(&ctx, &aid, "holder-A", 1_700_001_000, 1_700_001_060)
        .await
        .expect("lease_acquire ok");
    assert_eq!(lease.holder, "holder-A");
    assert_eq!(lease.expires_at, 1_700_001_060);
    // A different holder cannot acquire while the lease is live.
    let conflict = store
        .lease_acquire(&ctx, &aid, "holder-B", 1_700_001_001, 1_700_001_061)
        .await;
    assert!(conflict.is_err(), "a live lease blocks a different holder");
    // The holder renews (extends expiry + bumps heartbeat).
    let renewed = store
        .lease_renew(&ctx, &aid, "holder-A", 1_700_001_030, 1_700_001_090)
        .await
        .expect("lease_renew ok");
    assert_eq!(renewed.expires_at, 1_700_001_090);
    assert_eq!(renewed.heartbeat_at, 1_700_001_030);
    // A non-holder cannot renew.
    assert!(
        store
            .lease_renew(&ctx, &aid, "holder-B", 1_700_001_031, 1_700_001_100)
            .await
            .is_err(),
        "a non-holder renew is rejected"
    );
    // get reflects the renewed lease.
    let got = store
        .lease_get(&ctx, &aid)
        .await
        .expect("lease_get ok")
        .expect("lease present");
    assert_eq!(got.holder, "holder-A");
    assert_eq!(got.expires_at, 1_700_001_090);
    // Release by the holder; then the lease is gone.
    assert!(
        store
            .lease_release(&ctx, &aid, "holder-A")
            .await
            .expect("lease_release ok"),
        "the held lease is released"
    );
    assert!(
        store
            .lease_get(&ctx, &aid)
            .await
            .expect("lease_get after release ok")
            .is_none(),
        "no lease after release"
    );
    // After release, a different holder can acquire.
    let reacquire = store
        .lease_acquire(&ctx, &aid, "holder-B", 1_700_001_200, 1_700_001_260)
        .await
        .expect("re-acquire after release ok");
    assert_eq!(reacquire.holder, "holder-B");

    // #1709 Pillar 1 — the background lease-sweeper reclaims expired leases.
    // Acquire a lease whose deadline is already in the past, then sweep at a
    // `now` after it: at least the one expired lease is reclaimed and gone.
    store
        .lease_acquire(&ctx, &aid, "holder-C", 1_700_002_000, 1_700_002_000 - 1)
        .await
        .expect("acquire expired-deadline lease ok");
    let reclaimed = store
        .lease_sweep_expired(1_700_002_000)
        .await
        .expect("lease_sweep_expired ok");
    assert!(reclaimed >= 1, "the expired lease is reclaimed");
    assert!(
        store
            .lease_get(&ctx, &aid)
            .await
            .expect("lease_get after sweep ok")
            .is_none(),
        "no lease after sweep"
    );

    // #1709 §11.4 Pillar-1 FRONTIER — a fresh pending action with no blocking
    // edges is UNBLOCKED, so it appears in action_frontier and action_next
    // returns it (both adapters).
    let fid = format!("sal-cov-frontier-{}", uuid_like());
    store
        .action_create(
            &ctx,
            &ai_memory::models::Action {
                id: fid.clone(),
                namespace: TEST_NS.to_string(),
                kind: "test.coordinate".to_string(),
                state: ai_memory::models::ActionState::Pending,
                title: "sal-cov frontier action".to_string(),
                payload: serde_json::json!({}),
                priority: 7,
                agent_id: None,
                claimed_by: None,
                vector_clock: serde_json::json!({}),
                metadata: serde_json::json!({}),
                created_at: 1_700_004_000,
                updated_at: 1_700_004_000,
            },
        )
        .await
        .expect("action_create frontier ok");
    let frontier = store
        .action_frontier(&ctx, TEST_NS, 50)
        .await
        .expect("action_frontier ok");
    assert!(
        frontier.iter().any(|a| a.id == fid),
        "the unblocked pending action appears in the frontier"
    );
    let next = store
        .action_next(&ctx, TEST_NS, None)
        .await
        .expect("action_next ok")
        .expect("action_next returns a row when the frontier is non-empty");
    assert_eq!(
        next.namespace, TEST_NS,
        "action_next returns an action in the requested namespace"
    );
    // The unowned action is reachable for an arbitrary caller too.
    let next_owned = store
        .action_next(&ctx, TEST_NS, Some("sal-cov-some-agent"))
        .await
        .expect("action_next owned ok");
    assert!(
        next_owned.is_some(),
        "the unowned action is visible to any caller"
    );

    // #1709 Pillar 1 — signal_send / signal_get / signal_inbox / signal_ack
    // round-trip through the SAL surface on BOTH adapters. The SIGNED path is
    // exercised here: a test keypair signs the signal on send, and the row
    // read back via signal_get is asserted to verify (Ed25519 over canonical
    // signal content).
    let sid = format!("sal-cov-sig-{}", uuid_like());
    let signal = Signal {
        id: sid.clone(),
        namespace: TEST_NS.to_string(),
        from_agent: TEST_AGENT.to_string(),
        to_agent: Some(TEST_AGENT.to_string()),
        subject: "sal-cov-subject".to_string(),
        body: serde_json::json!({}),
        signal_type: SignalType::Notify,
        in_reply_to: None,
        correlation_id: None,
        reference_ids: serde_json::json!([]),
        created_at: 1_700_003_000,
        expires_at: None,
        delivered_at: None,
        read_at: None,
        acknowledged_at: None,
        signature: vec![],
        sender_pubkey: vec![],
    };
    let kp = ai_memory::identity::keypair::generate(TEST_AGENT).expect("generate keypair");
    let attest = store
        .signal_send(&ctx, &signal, Some(&kp))
        .await
        .expect("signal_send ok");
    assert_eq!(attest, "self_signed", "signed send reports self_signed");

    let got_sig = store
        .signal_get(&ctx, &sid)
        .await
        .expect("signal_get ok")
        .expect("signal present");
    assert_eq!(got_sig.namespace, TEST_NS);
    assert_eq!(got_sig.from_agent, TEST_AGENT);
    assert_eq!(got_sig.to_agent.as_deref(), Some(TEST_AGENT));
    assert_eq!(got_sig.signal_type, SignalType::Notify);
    assert!(got_sig.acknowledged_at.is_none());
    // The signed row read back from the store verifies its Ed25519 signature.
    assert!(
        ai_memory::signals::verify(&got_sig),
        "the signed signal row must verify after a store round-trip"
    );

    let inbox = store
        .signal_inbox(&ctx, TEST_NS, Some(TEST_AGENT), 10)
        .await
        .expect("signal_inbox ok");
    assert!(
        inbox.iter().any(|s| s.id == sid),
        "the sent signal is in the inbox"
    );

    // First ack flips acknowledged_at; a second ack is a no-op.
    assert!(
        store
            .signal_ack(&ctx, &sid, 1_700_003_100)
            .await
            .expect("signal_ack ok"),
        "first ack stamps acknowledged_at"
    );
    assert!(
        !store
            .signal_ack(&ctx, &sid, 1_700_003_200)
            .await
            .expect("signal_ack second ok"),
        "second ack is a no-op"
    );
    assert_eq!(
        store
            .signal_get(&ctx, &sid)
            .await
            .expect("signal_get after ack ok")
            .expect("signal present")
            .acknowledged_at,
        Some(1_700_003_100)
    );

    // #1709 Pillar 1 — checkpoint_create / checkpoint_get / checkpoint_list /
    // checkpoint_resolve round-trip through the SAL surface on BOTH adapters
    // (the v61 attested-checkpoints substrate). The SIGNED resolution path is
    // exercised: the test keypair attests the resolution on resolve, and the
    // returned row is asserted to verify (Ed25519 over the canonical
    // RESOLUTION).
    let cid = format!("sal-cov-cp-{}", uuid_like());
    let checkpoint = Checkpoint {
        id: cid.clone(),
        namespace: TEST_NS.to_string(),
        title: "sal-cov checkpoint".to_string(),
        condition_type: ConditionType::Approval,
        condition: serde_json::json!({}),
        state: CheckpointState::Pending,
        created_by: TEST_AGENT.to_string(),
        resolved_by: None,
        resolution: None,
        resolution_note: None,
        signature: vec![],
        resolver_pubkey: vec![],
        created_at: 1_700_004_000,
        deadline_at: None,
        resolved_at: None,
        metadata: serde_json::json!({}),
    };
    let created_cp = store
        .checkpoint_create(&ctx, &checkpoint)
        .await
        .expect("checkpoint_create ok");
    assert_eq!(created_cp, cid);

    let got_cp = store
        .checkpoint_get(&ctx, &cid)
        .await
        .expect("checkpoint_get ok")
        .expect("checkpoint present");
    assert_eq!(got_cp.namespace, TEST_NS);
    assert_eq!(got_cp.title, "sal-cov checkpoint");
    assert_eq!(got_cp.condition_type, ConditionType::Approval);
    assert_eq!(got_cp.state, CheckpointState::Pending);
    assert_eq!(got_cp.created_by, TEST_AGENT);
    assert!(got_cp.resolved_at.is_none());

    let cp_list = store
        .checkpoint_list(&ctx, TEST_NS, Some(CheckpointState::Pending), 10)
        .await
        .expect("checkpoint_list ok");
    assert!(
        cp_list.iter().any(|c| c.id == cid),
        "the pending checkpoint is in the namespace+state-filtered list"
    );

    let resolved_cp = store
        .checkpoint_resolve(
            &ctx,
            &cid,
            CheckpointState::Resolved,
            TEST_AGENT,
            Some("approved"),
            None,
            1_700_004_100,
            Some(&kp),
        )
        .await
        .expect("checkpoint_resolve ok")
        .expect("resolve returns the updated row");
    assert_eq!(resolved_cp.state, CheckpointState::Resolved);
    assert_eq!(resolved_cp.resolved_by.as_deref(), Some(TEST_AGENT));
    assert_eq!(resolved_cp.resolution.as_deref(), Some("approved"));
    assert_eq!(resolved_cp.resolved_at, Some(1_700_004_100));
    // The signed resolution row verifies (Ed25519 over the canonical RESOLUTION).
    assert!(
        ai_memory::checkpoints::verify(&resolved_cp),
        "the attested checkpoint resolution must verify after a store round-trip"
    );

    // #1709 Pillar 1 — routine_create / routine_get / routine_list /
    // routine_freeze + routine_run_create / routine_run_get /
    // routine_run_set_state round-trip through the SAL surface on BOTH
    // adapters (the v62 routines substrate).
    let rid = format!("sal-cov-rt-{}", uuid_like());
    let routine = Routine {
        id: rid.clone(),
        namespace: TEST_NS.to_string(),
        name: "r1".to_string(),
        template: serde_json::json!({ "actions": [] }),
        parameters: serde_json::json!([]),
        state: RoutineState::Draft,
        created_by: TEST_AGENT.to_string(),
        created_at: 1_700_005_000,
        frozen_at: None,
        signature: vec![],
        signer_pubkey: vec![],
        metadata: serde_json::json!({}),
    };
    let created_rt = store
        .routine_create(&ctx, &routine)
        .await
        .expect("routine_create ok");
    assert_eq!(created_rt, rid);

    let got_rt = store
        .routine_get(&ctx, &rid)
        .await
        .expect("routine_get ok")
        .expect("routine present");
    assert_eq!(got_rt.namespace, TEST_NS);
    assert_eq!(got_rt.name, "r1");
    assert_eq!(got_rt.state, RoutineState::Draft);
    assert_eq!(got_rt.created_by, TEST_AGENT);

    let rt_list = store
        .routine_list(&ctx, TEST_NS, Some(RoutineState::Draft), 10)
        .await
        .expect("routine_list ok");
    assert!(
        rt_list.iter().any(|r| r.id == rid),
        "the draft routine is in the namespace+state-filtered list"
    );

    let frozen_rt = store
        .routine_freeze(&ctx, &rid, 1_700_005_100, Some(&kp))
        .await
        .expect("routine_freeze ok")
        .expect("freeze returns the updated row");
    assert_eq!(frozen_rt.state, RoutineState::Frozen);
    assert_eq!(frozen_rt.frozen_at, Some(1_700_005_100));
    // The signed freeze row verifies (Ed25519 FREEZE-ATTESTATION over the
    // canonical frozen template).
    assert!(
        ai_memory::routines::verify(&frozen_rt),
        "the attested routine freeze must verify after a store round-trip"
    );

    let run_id = format!("sal-cov-run-{}", uuid_like());
    let run = RoutineRun {
        id: run_id.clone(),
        routine_id: rid.clone(),
        namespace: TEST_NS.to_string(),
        arguments: serde_json::json!({}),
        state: RoutineRunState::Pending,
        created_action_ids: serde_json::json!([]),
        started_at: 1_700_005_000,
        finished_at: None,
        error: None,
        metadata: serde_json::json!({}),
    };
    let created_run = store
        .routine_run_create(&ctx, &run)
        .await
        .expect("routine_run_create ok");
    assert_eq!(created_run, run_id);

    let got_run = store
        .routine_run_get(&ctx, &run_id)
        .await
        .expect("routine_run_get ok")
        .expect("run present");
    assert_eq!(got_run.routine_id, rid);
    assert_eq!(got_run.state, RoutineRunState::Pending);

    let completed_run = store
        .routine_run_set_state(
            &ctx,
            &run_id,
            RoutineRunState::Completed,
            Some(1_700_005_200),
            Some(&serde_json::json!(["a1"])),
            None,
        )
        .await
        .expect("routine_run_set_state ok")
        .expect("set_state returns the updated row");
    assert_eq!(completed_run.state, RoutineRunState::Completed);
    assert_eq!(completed_run.finished_at, Some(1_700_005_200));
    assert_eq!(completed_run.created_action_ids, serde_json::json!(["a1"]));

    // #1709 Pillar-3 (#224) — merge_inbound field-merges a divergent
    // same-`id` inbound row through the SAL trait on BOTH adapters. The
    // merge_memory reconciler is the SAME shared Rust fn on each adapter
    // (only the read/write SQL differs), so this asserts the wired #224
    // CRDT-lite behaviour end-to-end: insert id X (tags=[a], prio=3),
    // then merge_inbound id X (tags=[b], prio=5, NEWER) → tags union
    // {a,b}, priority max=5.
    let mi_id = format!("sal-cov-merge-{}", uuid_like());
    let mut mi_local = base_memory(&mi_id, TEST_NS, "sal-cov-merge");
    mi_local.tags = vec!["a".to_string()];
    mi_local.priority = 3;
    mi_local.updated_at = "2026-06-16T00:00:00+00:00".to_string();
    let stored_id = store
        .merge_inbound(&ctx, &mi_local)
        .await
        .expect("merge_inbound fresh-insert ok");
    assert_eq!(stored_id, mi_id, "fresh merge_inbound returns the row id");

    let mut mi_inbound = mi_local.clone();
    mi_inbound.tags = vec!["b".to_string()];
    mi_inbound.priority = 5;
    mi_inbound.updated_at = "2026-06-16T09:00:00+00:00".to_string();
    let merged_id = store
        .merge_inbound(&ctx, &mi_inbound)
        .await
        .expect("merge_inbound divergent same-id ok");
    assert_eq!(merged_id, mi_id, "merge returns the existing row id");

    let merged = store.get(&ctx, &mi_id).await.expect("get merged row ok");
    let mut merged_tags = merged.tags.clone();
    merged_tags.sort();
    assert_eq!(merged_tags, vec!["a", "b"], "tags union (both survive)");
    assert_eq!(merged.priority, 5, "priority is max(3, 5)");
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
