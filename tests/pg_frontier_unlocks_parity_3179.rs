// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3179 — the FRONTIER `unlocks` gate must hold on BOTH backends.
//!
//! `a --unlocks--> b` documents "`from` unlocks `to` on completion", so while
//! `a` is not `done`, `b` is NOT dispatchable. #3008 added that third
//! `NOT EXISTS` clause to the sqlite predicate; the postgres adapter carried a
//! HAND-COPIED twin that was never updated, so on a pg-backed coordination
//! plane `action_frontier` / `action_next` served `b` to agents while sqlite
//! held it back — out-of-order execution — under a doc comment claiming the
//! two were "byte-for-byte the same predicate".
//!
//! The fix formats both backends from one fragment
//! (`crate::actions::frontier_where_tail_with`). These tests pin the BEHAVIOUR
//! on both lanes so a future `EdgeType` cannot regress one of them; the
//! sqlite lane always runs, the pg lane skips cleanly without
//! `AI_MEMORY_TEST_POSTGRES_URL`.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::uninlined_format_args
)]

use ai_memory::models::{Action, ActionState, EdgeType};
use ai_memory::store::{CallerContext, MemoryStore};

fn action(id: &str, ns: &str, title: &str) -> Action {
    let now = chrono::Utc::now().timestamp();
    Action {
        id: id.to_string(),
        namespace: ns.to_string(),
        kind: "task".to_string(),
        state: ActionState::Pending,
        title: title.to_string(),
        payload: serde_json::Value::Null,
        priority: 5,
        agent_id: None,
        claimed_by: None,
        vector_clock: serde_json::json!({}),
        metadata: serde_json::json!({}),
        created_at: now,
        updated_at: now,
    }
}

/// Drive the shared scenario against any `MemoryStore`:
/// `a --unlocks--> b`, `a` pending ⇒ `b` is NOT on the frontier and is never
/// what `action_next` hands out; `a → done` ⇒ `b` appears.
async fn assert_unlocks_gates_frontier(store: &dyn MemoryStore, lane: &str) {
    let ctx = CallerContext::for_agent("ai:3179");
    let ns = format!("frontier-3179-{}", uuid::Uuid::new_v4());
    let a_id = format!("a-{}", uuid::Uuid::new_v4());
    let b_id = format!("b-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().timestamp();

    store
        .action_create(&ctx, &action(&a_id, &ns, "unlocker"))
        .await
        .unwrap_or_else(|e| panic!("{lane}: create a: {e}"));
    store
        .action_create(&ctx, &action(&b_id, &ns, "unlocked"))
        .await
        .unwrap_or_else(|e| panic!("{lane}: create b: {e}"));
    store
        .action_add_edge(&ctx, &a_id, &b_id, EdgeType::Unlocks, now)
        .await
        .unwrap_or_else(|e| panic!("{lane}: add unlocks edge: {e}"));

    // --- a is pending ⇒ b is BLOCKED. ---
    let frontier = store
        .action_frontier(&ctx, &ns, 50)
        .await
        .unwrap_or_else(|e| panic!("{lane}: frontier: {e}"));
    let ids: Vec<&str> = frontier.iter().map(|x| x.id.as_str()).collect();
    assert!(
        !ids.contains(&b_id.as_str()),
        "#3179 ({lane}): an action whose ONLY dependency is an inbound \
         `unlocks` edge from a still-pending action must NOT be on the \
         frontier — got {ids:?}"
    );
    assert!(
        ids.contains(&a_id.as_str()),
        "#3179 ({lane}): the unlocker itself is unblocked and must be on the \
         frontier — got {ids:?}"
    );
    // `action_next` runs the SAME predicate; it must never hand out b.
    let next = store
        .action_next(&ctx, &ns, None)
        .await
        .unwrap_or_else(|e| panic!("{lane}: next: {e}"));
    assert_ne!(
        next.as_ref().map(|x| x.id.as_str()),
        Some(b_id.as_str()),
        "#3179 ({lane}): action_next must not dispatch an unlocks-gated action"
    );

    // --- a → done ⇒ b becomes dispatchable. ---
    for to in [
        ActionState::Claimed,
        ActionState::InProgress,
        ActionState::Done,
    ] {
        store
            .action_transition(&ctx, &a_id, to, Some("ai:3179"), now)
            .await
            .unwrap_or_else(|e| panic!("{lane}: transition a to {to:?}: {e}"));
    }
    let frontier = store
        .action_frontier(&ctx, &ns, 50)
        .await
        .unwrap_or_else(|e| panic!("{lane}: frontier after done: {e}"));
    let ids: Vec<&str> = frontier.iter().map(|x| x.id.as_str()).collect();
    assert!(
        ids.contains(&b_id.as_str()),
        "#3179 ({lane}): once the unlocker is `done` the unlocked action must \
         appear on the frontier — got {ids:?}"
    );
}

#[tokio::test]
async fn sqlite_unlocks_gates_the_frontier_3179() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("frontier-3179.db");
    let store = ai_memory::store::sqlite::SqliteStore::open(&db).expect("open SqliteStore");
    assert_unlocks_gates_frontier(&store, "sqlite").await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn pg_unlocks_gates_the_frontier_3179() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        return; // no live PG — skip cleanly
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    assert_unlocks_gates_frontier(&store, "postgres").await;
}
