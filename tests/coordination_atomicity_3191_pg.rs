// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3191 — coordination-plane atomicity (postgres twins).
//!
//! Postgres-lane regressions for the F-1 (`checkpoint_resolve`) and F-2
//! (`action_transition`) coordination-plane atomicity fixes. Gated on
//! `AI_MEMORY_TEST_POSTGRES_URL` (skips cleanly when unset), like the other
//! `*_pg` suites.

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::too_many_lines,
    clippy::similar_names
)]

use ai_memory::checkpoints;
use ai_memory::identity::keypair;
use ai_memory::models::{Action, ActionState, Checkpoint, CheckpointState, ConditionType};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use std::sync::Arc;

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

fn pending_checkpoint(id: &str) -> Checkpoint {
    let now = chrono::Utc::now().timestamp();
    Checkpoint {
        id: id.to_string(),
        namespace: "_cp_3191_pg".to_string(),
        title: "needs approval".to_string(),
        condition_type: ConditionType::Approval,
        condition: serde_json::Value::Null,
        state: CheckpointState::Pending,
        created_by: "agent-creator".to_string(),
        resolved_by: None,
        resolution: None,
        resolution_note: None,
        signature: Vec::new(),
        resolver_pubkey: Vec::new(),
        created_at: now,
        deadline_at: None,
        resolved_at: None,
        metadata: serde_json::Value::Null,
    }
}

fn pending_action(id: &str) -> Action {
    let now = chrono::Utc::now().timestamp();
    Action {
        id: id.to_string(),
        namespace: "_act_3191_pg".to_string(),
        kind: "test.kind".to_string(),
        state: ActionState::Pending,
        title: "t".to_string(),
        payload: serde_json::json!({}),
        priority: 5,
        agent_id: Some("agent-x".to_string()),
        claimed_by: None,
        vector_clock: serde_json::json!({}),
        metadata: serde_json::json!({}),
        created_at: now,
        updated_at: now,
    }
}

/// F-1 (postgres twin) — the signature-persist UPDATE is forced to fail (a
/// row-scoped BEFORE-UPDATE trigger). Pre-fix the CAS state-flip had already
/// committed on the pool, stranding the anchor `state=resolved` with an EMPTY
/// signature. Post-fix the CAS + signature write share ONE transaction, so the
/// abort rolls the state-flip back — the checkpoint stays PENDING.
#[tokio::test]
async fn pg_resolve_signature_persist_failure_rolls_back_stays_pending_3191() {
    let Some(url) = postgres_url() else {
        return; // no live PG — skip cleanly
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ctx = CallerContext::for_agent("resolver-a");
    let kp = keypair::generate("resolver-a").expect("keypair");

    let uniq = uuid::Uuid::new_v4().simple().to_string();
    let id = format!("cp-3191-pg-{uniq}");
    let trg = format!("cp3191_fs_trg_{uniq}");
    let func = format!("cp3191_fs_fn_{uniq}");

    store
        .checkpoint_create(&ctx, &pending_checkpoint(&id))
        .await
        .expect("create pending checkpoint");

    // Inject a failure into the signature-persist UPDATE for THIS row only.
    sqlx::query(&format!(
        "CREATE FUNCTION {func}() RETURNS trigger AS $$ BEGIN \
         RAISE EXCEPTION 'injected signature-persist failure #3191'; END; $$ LANGUAGE plpgsql"
    ))
    .execute(store.pool())
    .await
    .expect("create trigger fn");
    sqlx::query(&format!(
        "CREATE TRIGGER {trg} BEFORE UPDATE OF signature ON checkpoints FOR EACH ROW \
         WHEN (NEW.id = '{id}' AND octet_length(NEW.signature) > 0) EXECUTE FUNCTION {func}()"
    ))
    .execute(store.pool())
    .await
    .expect("create trigger");

    let now = chrono::Utc::now().timestamp();
    let err = store
        .checkpoint_resolve(
            &ctx,
            &id,
            CheckpointState::Resolved,
            "resolver-a",
            Some("approved"),
            None,
            now,
            Some(&kp),
        )
        .await
        .expect_err("signature-persist failure must surface as an Err");
    let _ = err;

    let row = store
        .checkpoint_get(&ctx, &id)
        .await
        .expect("get")
        .expect("row present");
    assert_eq!(
        row.state,
        CheckpointState::Pending,
        "a signing-side failure MUST roll the resolve back — the checkpoint stays PENDING"
    );
    assert!(
        row.signature.is_empty(),
        "the checkpoint must never persist a resolved state with an empty signature"
    );

    // Cleanup the injected objects, then prove a retry can resolve (the anchor
    // was never permanently stranded answering Conflict).
    sqlx::query(&format!("DROP TRIGGER IF EXISTS {trg} ON checkpoints"))
        .execute(store.pool())
        .await
        .expect("drop trigger");
    sqlx::query(&format!("DROP FUNCTION IF EXISTS {func}()"))
        .execute(store.pool())
        .await
        .expect("drop fn");

    let outcome = store
        .checkpoint_resolve(
            &ctx,
            &id,
            CheckpointState::Resolved,
            "resolver-a",
            Some("approved"),
            None,
            chrono::Utc::now().timestamp(),
            Some(&kp),
        )
        .await
        .expect("retry after the transient failure resolves");
    assert!(matches!(outcome, checkpoints::ResolveOutcome::Resolved(_)));
    let row = store
        .checkpoint_get(&ctx, &id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(row.state, CheckpointState::Resolved);
    assert!(!row.signature.is_empty(), "retry persisted the attestation");
    assert!(checkpoints::verify(&row), "the resolved anchor verifies");
}

/// F-2 (postgres twin) — concurrent `action_transition` of ONE pending action
/// yields EXACTLY ONE winner. The `SELECT ... FOR UPDATE` row lock plus the
/// `AND state = $5` guard make the second racer re-read `claimed` (a
/// `claimed -> claimed` no-op is illegal) rather than double-applying.
#[tokio::test]
async fn pg_concurrent_action_transition_single_winner_3191() {
    let Some(url) = postgres_url() else {
        return; // no live PG — skip cleanly
    };
    let store = Arc::new(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    );
    let ctx = CallerContext::for_agent("agent-x");

    let uniq = uuid::Uuid::new_v4().simple().to_string();
    let id = format!("act-3191-pg-{uniq}");
    store
        .action_create(&ctx, &pending_action(&id))
        .await
        .expect("create pending action");

    let now = chrono::Utc::now().timestamp();
    let mut tasks = Vec::new();
    for i in 0..8u32 {
        let store = Arc::clone(&store);
        let ctx = ctx.clone();
        let id = id.clone();
        tasks.push(tokio::spawn(async move {
            let claimant = format!("claimant-{i}");
            store
                .action_transition(&ctx, &id, ActionState::Claimed, Some(&claimant), now)
                .await
                .is_ok()
        }));
    }
    let mut wins = 0;
    for t in tasks {
        if t.await.expect("task panicked") {
            wins += 1;
        }
    }
    assert_eq!(
        wins, 1,
        "exactly one concurrent action_transition may win pending -> claimed"
    );

    let row = store
        .action_get(&ctx, &id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(row.state, ActionState::Claimed);
}
