// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal-postgres")]
#![allow(clippy::needless_update)]

//! Postgres+AGE deferred-projection-mode correctness cluster (roadmap-3x7
//! findings #7/#8/#9, DAG node 6de44ebb):
//!
//! * **#2375 (FIX #7)** — `kg_invalidate` must NOT be a silent no-op under
//!   `AI_MEMORY_AGE_PROJECTION_MODE=deferred`: a freshly-written link exists
//!   relationally + in `kg_projection_outbox` but not yet in AGE, so the
//!   Cypher MATCH misses; the fix falls through to the relational
//!   `UPDATE ... RETURNING` so the invalidation is never lost.
//! * **#2376 (FIX #8)** — `delete_link` must unproject a DRAINED AGE edge even
//!   under `deferred` mode (`kg_query`/`kg_timeline` stay cypher-served), so a
//!   deleted edge is not served by cypher forever.
//! * **#2377 (FIX #9)** — an AGE-projected edge must carry the relational row's
//!   `valid_until`, so a link BORN already-invalidated (or invalidated before
//!   the drain) is excluded by the current-view Cypher filter exactly as the
//!   relational reads exclude it.
//!
//! Postgres+AGE only. Gated on `AI_MEMORY_TEST_POSTGRES_URL` (fallback
//! `AI_MEMORY_TEST_AGE_URL`); prints a skip line + returns cleanly when unset
//! or when the backend is not AGE, so default `cargo test` (and SQLite-only
//! contributors) are unaffected. Runs in CI's Postgres-gate job. Its own test
//! binary, so flipping the process-wide `AgeProjectionMode` to `Deferred`
//! cannot leak into the sync-mode postgres tests; each test restores `Sync`.

use ai_memory::config::{AgeProjectionMode, set_age_projection_mode};
use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, KgBackend, MemoryStore};

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

/// Connect + require AGE; returns `None` (with a skip line) when the env is
/// unset or the backend resolved to `Cte` (plain postgres, no graph to defer).
async fn age_store_or_skip(test: &str) -> Option<PostgresStore> {
    let url = pg_url()?;
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres adapter");
    if store.kg_backend() != KgBackend::Age {
        eprintln!("skipping {test}: postgres backend is not AGE (no graph projection to defer)");
        return None;
    }
    Some(store)
}

/// #2375 (FIX #7) — under deferred mode, invalidating a link that has been
/// written relationally but not yet drained into AGE must still take effect
/// (found=true) rather than silently returning found=false, and the
/// invalidation must survive the eventual drain (the drainer re-reads
/// `valid_until` from `memory_links`, #2377), so a subsequent current-view
/// `kg_query` excludes the edge.
#[tokio::test(flavor = "multi_thread")]
async fn deferred_invalidate_before_drain_takes_effect_2375() {
    let test = "deferred_invalidate_before_drain_takes_effect_2375";
    let Some(store) = age_store_or_skip(test).await else {
        return;
    };

    let ctx = CallerContext::for_agent("t-2375".to_string());
    let ns = format!("t2375-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();
    let a_id = store
        .store(&ctx, &mk_memory(&ns, "a", &now))
        .await
        .expect("store a");
    let b_id = store
        .store(&ctx, &mk_memory(&ns, "b", &now))
        .await
        .expect("store b");

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
        source_cid: None,
        target_cid: None,
    };
    store
        .link(&ctx, &link)
        .await
        .expect("deferred link commit (enqueues outbox, NOT yet in AGE)");

    // The link is in `memory_links` + `kg_projection_outbox` but NOT AGE, so
    // the Cypher MATCH misses. Pre-fix this returned found=false and never ran
    // the relational UPDATE; the fix falls through to `kg_invalidate_cte`.
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let res = store
        .kg_invalidate(
            &a_id,
            &b_id,
            MemoryLinkRelation::RelatedTo.as_str(),
            Some(&past),
        )
        .await
        .expect("kg_invalidate under deferred mode");
    assert!(
        res.found,
        "#2375: deferred-mode invalidate of a relationally-present (un-drained) \
         edge must report found=true, not silently no-op"
    );

    // Drain now projects the edge into AGE ALREADY-invalidated (drainer
    // re-reads valid_until from memory_links, #2377).
    store
        .drain_kg_projection_outbox(64)
        .await
        .expect("drain outbox");

    let rows = store
        .kg_query(&a_id, 4)
        .await
        .expect("kg_query current view");
    assert!(
        rows.iter().all(|r| r.target_id != b_id),
        "#2375/#2377: an edge invalidated before the drain must be excluded from \
         the current-view AGE kg_query after projection, got {rows:?}"
    );

    // Control: the historical view (CTE) still shows the (now-invalidated) edge.
    let hist = store
        .kg_query_with_history(&a_id, 4, true)
        .await
        .expect("kg_query historical");
    assert!(
        hist.iter().any(|r| r.target_id == b_id),
        "#2375: the invalidated edge must remain visible in the historical view"
    );

    set_age_projection_mode(AgeProjectionMode::Sync);
}

/// #2376 (FIX #8) — under deferred mode, deleting an edge that was already
/// drained into AGE must unproject it, so a cypher-served `kg_query` no longer
/// returns it. Pre-fix the unprojection was gated on Sync mode, so the drained
/// edge was served by cypher forever.
#[tokio::test(flavor = "multi_thread")]
async fn deferred_delete_after_drain_removes_edge_from_kg_query_2376() {
    let test = "deferred_delete_after_drain_removes_edge_from_kg_query_2376";
    let Some(store) = age_store_or_skip(test).await else {
        return;
    };

    let ctx = CallerContext::for_agent("t-2376".to_string());
    let ns = format!("t2376-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();
    let a_id = store
        .store(&ctx, &mk_memory(&ns, "a", &now))
        .await
        .expect("store a");
    let b_id = store
        .store(&ctx, &mk_memory(&ns, "b", &now))
        .await
        .expect("store b");

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
        source_cid: None,
        target_cid: None,
    };
    store.link(&ctx, &link).await.expect("deferred link commit");

    // Drain projects the edge into AGE, so it is now cypher-served.
    store
        .drain_kg_projection_outbox(64)
        .await
        .expect("drain outbox");
    let before = store
        .kg_query(&a_id, 4)
        .await
        .expect("kg_query before delete");
    assert!(
        before.iter().any(|r| r.target_id == b_id),
        "#2376: precondition — the drained edge must be cypher-served before delete"
    );

    // Delete the relational edge. Under deferred mode this must STILL unproject
    // the drained AGE edge (the fix drops the Sync-mode gate).
    let removed = store
        .delete_link(&ctx, &a_id, &b_id)
        .await
        .expect("delete_link");
    assert!(removed, "#2376: delete_link must report the edge removed");

    let after = store
        .kg_query(&a_id, 4)
        .await
        .expect("kg_query after delete");
    assert!(
        after.iter().all(|r| r.target_id != b_id),
        "#2376: after deleting a drained edge under deferred mode the AGE \
         kg_query must NOT return it (phantom edge), got {after:?}"
    );

    set_age_projection_mode(AgeProjectionMode::Sync);
}

/// #2377 (FIX #9) — a link BORN with `valid_until` already in the past must be
/// excluded from the current-view AGE `kg_query` after projection, exactly as
/// the relational reads exclude it. Pre-fix the projection `MERGEd` a bare
/// `{relation}` edge, so cypher served the born-invalid edge as VALID forever.
#[tokio::test(flavor = "multi_thread")]
async fn deferred_born_invalid_link_excluded_from_kg_query_2377() {
    let test = "deferred_born_invalid_link_excluded_from_kg_query_2377";
    let Some(store) = age_store_or_skip(test).await else {
        return;
    };

    let ctx = CallerContext::for_agent("t-2377".to_string());
    let ns = format!("t2377-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();
    let a_id = store
        .store(&ctx, &mk_memory(&ns, "a", &now))
        .await
        .expect("store a");
    let b_id = store
        .store(&ctx, &mk_memory(&ns, "b", &now))
        .await
        .expect("store b");

    set_age_projection_mode(AgeProjectionMode::Deferred);

    // Born already-invalidated: valid_until one hour in the PAST.
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let link = MemoryLink {
        source_id: a_id.clone(),
        target_id: b_id.clone(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: now.clone(),
        valid_from: None,
        valid_until: Some(past),
        observed_by: None,
        signature: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    };
    store
        .link(&ctx, &link)
        .await
        .expect("deferred born-invalid link commit");

    store
        .drain_kg_projection_outbox(64)
        .await
        .expect("drain outbox (projects with valid_until, #2377)");

    let current = store
        .kg_query(&a_id, 4)
        .await
        .expect("kg_query current view");
    assert!(
        current.iter().all(|r| r.target_id != b_id),
        "#2377: a link born with a past valid_until must be excluded from the \
         current-view AGE kg_query, got {current:?}"
    );

    // Control: the edge exists — the historical view returns it.
    let hist = store
        .kg_query_with_history(&a_id, 4, true)
        .await
        .expect("kg_query historical");
    assert!(
        hist.iter().any(|r| r.target_id == b_id),
        "#2377: the born-invalid edge must exist (historical view returns it), \
         proving the current-view exclusion is temporal, not a missing edge"
    );

    set_age_projection_mode(AgeProjectionMode::Sync);
}
