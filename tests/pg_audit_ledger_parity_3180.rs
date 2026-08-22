// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3180 — the three audit/signal writes the postgres adapter lost.
//!
//! 1. **`pending_action.denied`** — a governance DENY must be provable. Before
//!    #3180, `grep -rn 'pending_action.denied' src/` matched `storage/mod.rs`
//!    only: on pg the deny left nothing in the signed chain, so the refusal
//!    was unprovable once the (mutable) `pending_actions` row moved on.
//! 2. **the recall access ledger** — `recall_hybrid` appended NOTHING on pg,
//!    so every pg-backed fleet produced zero `recall_observations` and the
//!    memory lifecycle (TTL extension, mid→long promotion, priority decay),
//!    which folds from exactly those rows, was frozen.
//! 3. **`reclassify` `cause_hash`** — the pg twin bound `None`, so an auditor
//!    could not tie a reclassification to the caller and inputs that caused
//!    it. The test recomputes the hash with the SQLITE formula and requires
//!    the stored pg value to equal it byte-for-byte.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL` (skips cleanly when unset).

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::uninlined_format_args
)]

use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

#[tokio::test]
async fn pg_pending_deny_appends_a_signed_denied_event_3180() {
    let Some(url) = postgres_url() else {
        return; // no live PG — skip cleanly
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ctx = CallerContext::for_admin("ai:3180");
    let pending_id = format!("pa-3180-{}", uuid::Uuid::new_v4());
    let ns = format!("deny-3180-{}", uuid::Uuid::new_v4());

    sqlx::query(
        "INSERT INTO pending_actions (id, action_type, namespace, payload, requested_by, status) \
         VALUES ($1, 'delete', $2, '{}'::jsonb, 'ai:requester', 'pending')",
    )
    .bind(&pending_id)
    .bind(&ns)
    .execute(store.pool())
    .await
    .expect("seed pending action");

    let before: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM signed_events WHERE event_type = $1")
            .bind("pending_action.denied")
            .fetch_one(store.pool())
            .await
            .expect("count denied events");

    let decided = store
        .pending_decide(&ctx, &pending_id, false, "ai:approver-3180")
        .await
        .expect("pending_decide deny");
    assert!(decided, "the deny transition must land");

    let after: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM signed_events WHERE event_type = $1")
            .bind("pending_action.denied")
            .fetch_one(store.pool())
            .await
            .expect("count denied events");
    assert_eq!(
        after,
        before + 1,
        "#3180: a landed DENY must append exactly one pending_action.denied \
         row to the signed chain on postgres"
    );

    // The audited row is the POST-update snapshot: the decision actor is the
    // approver, matching the sqlite twin's `get_pending_action`-after-UPDATE.
    let actor: String = sqlx::query_scalar(
        "SELECT agent_id FROM signed_events WHERE event_type = $1 \
         ORDER BY COALESCE(sequence, 0) DESC LIMIT 1",
    )
    .bind("pending_action.denied")
    .fetch_one(store.pool())
    .await
    .expect("read denied event actor");
    assert_eq!(
        actor, "ai:approver-3180",
        "#3180: the audit row's agent_id is the decision actor"
    );

    // A second deny of the same (now `rejected`) row is a no-op and must NOT
    // append a second audit row — the emit is bound to a LANDED transition.
    let again = store
        .pending_decide(&ctx, &pending_id, false, "ai:approver-3180")
        .await
        .expect("second deny");
    assert!(!again, "a decided row does not re-transition");
    let after2: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM signed_events WHERE event_type = $1")
            .bind("pending_action.denied")
            .fetch_one(store.pool())
            .await
            .expect("count denied events");
    assert_eq!(after2, after, "#3180: no audit row without a transition");

    sqlx::query("DELETE FROM pending_actions WHERE id = $1")
        .bind(&pending_id)
        .execute(store.pool())
        .await
        .ok();
}

#[tokio::test]
async fn pg_recall_hybrid_appends_the_access_ledger_3180() {
    let Some(url) = postgres_url() else {
        return; // no live PG — skip cleanly
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ns = format!("ledger-3180-{}", uuid::Uuid::new_v4());
    let ctx = CallerContext::for_agent("ai:3180-recaller");
    let token = format!("zqxjv{}", uuid::Uuid::new_v4().simple());

    let now = chrono::Utc::now().to_rfc3339();
    let mut ids: Vec<String> = Vec::new();
    for i in 0..3 {
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: ns.clone(),
            title: format!("ledger probe {i}"),
            content: format!("{token} candidate number {i}"),
            source: "test".to_string(),
            priority: i,
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: serde_json::json!({ "agent_id": "ai:3180-recaller" }),
            ..Default::default()
        };
        ids.push(store.store(&ctx, &mem).await.expect("store probe row"));
    }

    let filter = ai_memory::store::Filter {
        namespace: Some(ns.clone()),
        limit: 10,
        ..Default::default()
    };
    let results = store
        .recall_hybrid(&ctx, &token, None, &filter)
        .await
        .expect("recall_hybrid");
    assert!(
        !results.is_empty(),
        "the probe token must match the seeded rows"
    );

    // One ledger row per RETURNED candidate, ranked from 1 in returned order.
    let rows: Vec<(String, i64, String)> = sqlx::query_as(
        "SELECT memory_id, rank, retriever FROM recall_observations \
         WHERE namespace = $1 ORDER BY rank ASC",
    )
    .bind(&ns)
    .fetch_all(store.pool())
    .await
    .expect("read recall_observations");
    assert_eq!(
        rows.len(),
        results.len(),
        "#3180: SAL recall on postgres must append one access observation per \
         returned candidate — pre-fix it appended NONE and the whole memory \
         lifecycle (TTL extension / promotion / decay) was frozen"
    );
    for (i, (memory_id, rank, retriever)) in rows.iter().enumerate() {
        assert_eq!(
            memory_id, &results[i].0.id,
            "#3180: ledger rows must follow the RETURNED ranking order"
        );
        assert_eq!(
            *rank,
            i64::try_from(i + 1).unwrap_or(-1),
            "#3180: ranks are 1-based over the returned set"
        );
        assert_eq!(
            retriever, "keyword",
            "#3180: with no query embedding the retriever is `keyword` (the \
             sqlite `query_embedding.is_some()` test)"
        );
    }

    sqlx::query("DELETE FROM recall_observations WHERE namespace = $1")
        .bind(&ns)
        .execute(store.pool())
        .await
        .ok();
    for id in &ids {
        sqlx::query("DELETE FROM memories WHERE id = $1")
            .bind(id)
            .execute(store.pool())
            .await
            .ok();
    }
}

#[tokio::test]
async fn pg_reclassify_binds_the_sqlite_cause_hash_3180() {
    let Some(url) = postgres_url() else {
        return; // no live PG — skip cleanly
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ns = format!("reclass-3180-{}", uuid::Uuid::new_v4());
    let caller = "ai:3180-reclassifier";
    let ctx = CallerContext::for_agent(caller);
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.clone(),
        title: "reclassify probe".to_string(),
        content: "body".to_string(),
        source: "test".to_string(),
        memory_kind: MemoryKind::Observation,
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({ "agent_id": caller }),
        ..Default::default()
    };
    let id = store.store(&ctx, &mem).await.expect("store probe row");

    let changed = store
        .reclassify_memory_kind(&ctx, &id, MemoryKind::Claim)
        .await
        .expect("reclassify");
    assert!(changed, "the reclassification must land");

    let stored: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT cause_hash FROM signed_events \
         WHERE event_type = 'memory.reclassified' AND agent_id = $1 \
         ORDER BY COALESCE(sequence, 0) DESC LIMIT 1",
    )
    .bind(caller)
    .fetch_one(store.pool())
    .await
    .expect("read reclassify event cause_hash");
    let stored = stored.expect(
        "#3180: the postgres reclassify twin must bind a cause_hash — pre-fix \
         it passed None while sqlite bound one, so the pg chain lost causal \
         linkage",
    );

    // The SQLITE formula, recomputed here: caller + action + id + the
    // identity-only input args. Byte equality is the parity proof.
    let expected = ai_memory::signed_events::compute_cause_hash(
        caller,
        "memory.reclassified",
        &id,
        &format!(
            "{id}|{}|{}",
            MemoryKind::Observation.as_str(),
            MemoryKind::Claim.as_str()
        ),
    );
    assert_eq!(
        stored, expected,
        "#3180: the postgres cause_hash must be byte-identical to the value \
         the sqlite twin computes for the same reclassification"
    );

    sqlx::query("DELETE FROM memories WHERE id = $1")
        .bind(&id)
        .execute(store.pool())
        .await
        .ok();
}
