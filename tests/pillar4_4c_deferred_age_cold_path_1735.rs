// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Pillar-4 4.C (#1735) — staggered AGE cold-path integration tests.
//!
//! Postgres+AGE only. Like the sibling `g3`/`g4` postgres tests these are
//! gated on `AI_MEMORY_TEST_POSTGRES_URL` (fallback `AI_MEMORY_TEST_AGE_URL`)
//! and print a skip line + return cleanly when it is unset, so the default
//! `cargo test` (and SQLite-only contributors) are unaffected. They run in
//! CI's Postgres-gate + Per-Module-Coverage jobs (which set the URL) and
//! cover the deferred-mode code added by 4.C on `src/store/postgres.rs`:
//! the `link_internal` outbox-enqueue branch, `drain_kg_projection_outbox`,
//! and the `find_paths` CTE-route under deferred mode.
//!
//! This file is its own test binary, so flipping the process-wide
//! `AgeProjectionMode` global to `Deferred` here cannot leak into the
//! sync-mode postgres tests (separate processes); it is also restored to
//! `Sync` at the end of each test for in-file hygiene.

use ai_memory::config::{AgeProjectionMode, set_age_projection_mode};
use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::CallerContext;
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_AGE_URL")
        .ok()
        .or_else(|| std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok())
}

fn mk_memory(namespace: &str, title: &str, now: &str) -> Memory {
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "x".to_string(),
        created_at: now.to_string(),
        updated_at: now.to_string(),
        ..Memory::default()
    }
}

/// Deferred mode: a link enqueues to `kg_projection_outbox` instead of the
/// inline AGE MERGE; `find_paths` stays read-your-own-write correct via the
/// relational CTE before the cold drain; the drainer then projects the
/// pending row (and a second drain is a no-op once `projected_at` is set).
#[tokio::test(flavor = "multi_thread")]
async fn deferred_link_enqueues_drains_and_find_paths_via_cte_1735() {
    let Some(url) = pg_url() else {
        eprintln!(
            "skipping deferred_link_enqueues_drains_and_find_paths_via_cte_1735: \
             AI_MEMORY_TEST_POSTGRES_URL / AI_MEMORY_TEST_AGE_URL not set"
        );
        return;
    };

    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres adapter");
    let ctx = CallerContext::for_agent("t-4c-1735".to_string());
    // Unique namespace per run — the CI test DB persists across runs, so a
    // fresh namespace keeps repeated runs independent.
    let ns = format!("t4c-1735-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();

    // Seed the two endpoint memories (memory writes are unaffected by the
    // projection mode; only link writes branch on it).
    let a = mk_memory(&ns, "a", &now);
    let b = mk_memory(&ns, "b", &now);
    let a_id = store.store(&ctx, &a).await.expect("store memory a");
    let b_id = store.store(&ctx, &b).await.expect("store memory b");

    // Flip to deferred for the link write.
    set_age_projection_mode(AgeProjectionMode::Deferred);

    let link = MemoryLink {
        source_id: a_id.clone(),
        target_id: b_id.clone(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: now.clone(),
        valid_from: None,
        valid_until: None,
        observed_by: None,
        signature: None,
        attest_level: None,
    };
    store
        .link(&ctx, &link)
        .await
        .expect("deferred link must commit (enqueues kg_projection_outbox row)");

    // Read-your-own-write under deferred: `find_paths` routes through the
    // always-current relational recursive-CTE, so the edge is visible BEFORE
    // the cold drain projects it into AGE.
    let pre = store
        .find_paths(&a_id, &b_id, Some(4), Some(10))
        .await
        .expect("find_paths pre-drain");
    assert!(
        !pre.is_empty(),
        "deferred find_paths must see the freshly-linked edge via the CTE \
         before the cold drain (read-your-own-write)"
    );

    // The cold drainer projects the pending outbox row into AGE.
    let projected = store
        .drain_kg_projection_outbox(64)
        .await
        .expect("drain kg_projection_outbox");
    assert!(
        projected >= 1,
        "drain must project at least the one pending row, got {projected}"
    );

    // Idempotent: an already-projected row (projected_at set) is excluded
    // from the take-query, so a second drain projects nothing new.
    let again = store
        .drain_kg_projection_outbox(64)
        .await
        .expect("second drain");
    assert_eq!(
        again, 0,
        "already-projected rows must not be re-drained, got {again}"
    );

    // find_paths still returns the edge after projection.
    let post = store
        .find_paths(&a_id, &b_id, Some(4), Some(10))
        .await
        .expect("find_paths post-drain");
    assert!(
        !post.is_empty(),
        "edge must remain reachable after projection"
    );

    // In-file hygiene: restore the process default.
    set_age_projection_mode(AgeProjectionMode::Sync);
}
