// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
//! #2513 — lease-acquire SAL-trait reachability pin.
//!
//! At v1.0.0 the lease acquire/renew/release/get operations are surfaced on a
//! single production path — the MCP stdio handlers, which hold a bare
//! `rusqlite::Connection` and call the `crate::actions::lease_*` free-functions
//! directly (MCP stdio is structurally sqlite-only, #1675). There is no HTTP
//! lease route (leases are node-local single-holder; they do not federate), so
//! a POSTGRES-backed daemon has no lease-acquire caller — the `PostgresStore`
//! lease methods are correct + live-PG-tested (#2310) forward-scaffolding.
//!
//! This test pins the invariant the #2513 fix documents: the lease-acquire
//! operation REACHES THE SAL TRAIT and round-trips end-to-end through a
//! `&dyn MemoryStore` object. Because both `SqliteStore` and `PostgresStore`
//! implement the trait, this proves that a FUTURE pg-reachable lease surface
//! that dispatches through `app.store.lease_acquire(...)` (the mandated
//! SAL-routing discipline, NOT a direct `crate::actions::*` call) will be served
//! on postgres exactly as it is on sqlite. If the trait surface ever regressed
//! to `UnsupportedCapability` (the default), this test fails.

// The `MemoryStore` SAL trait (`ai_memory::store`) is `#[cfg(feature = "sal")]`,
// so this whole file is sal-only; in a non-sal build it compiles to an empty
// test target.
#![cfg(feature = "sal")]

use ai_memory::models::{Action, ActionState};
use ai_memory::store::{CallerContext, MemoryStore};

const TEST_NS: &str = "_lease_reach_2513";
const TEST_AGENT: &str = "lease-reach-2513-agent";

/// A per-invocation unique action id. `SqliteStore` runs against a fresh
/// tempfile so a fixed id would suffice there, but the live-pg twin shares the
/// CI database across runs, so a colliding fixed id would make a second run's
/// `action_create` fail. Uniqueness keeps both paths re-runnable.
fn unique_action_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("lease-reach-2513-action-{nanos}")
}

fn action(id: &str) -> Action {
    Action {
        id: id.to_string(),
        namespace: TEST_NS.to_string(),
        kind: "test.coordinate".to_string(),
        state: ActionState::Pending,
        title: "lease reachability action".to_string(),
        payload: serde_json::json!({}),
        priority: 5,
        agent_id: Some(TEST_AGENT.to_string()),
        claimed_by: None,
        vector_clock: serde_json::json!({ TEST_AGENT: 1 }),
        metadata: serde_json::json!({}),
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
    }
}

/// Drives the full lease lifecycle through the SAL trait object and asserts each
/// operation is genuinely served (never the default `UnsupportedCapability`).
/// Backend-agnostic: exercised against `SqliteStore` always, and against
/// `PostgresStore` under the live-pg twin below.
async fn exercise_lease_sal_surface(store: &dyn MemoryStore) {
    let ctx = CallerContext::for_admin(TEST_AGENT);
    let action_id = unique_action_id();

    // The `leases.action_id` FK requires an existing action.
    store
        .action_create(&ctx, &action(&action_id))
        .await
        .expect("action_create ok");

    // acquire — the #2513 subject: it MUST reach the SAL trait, not the default.
    let lease = store
        .lease_acquire(&ctx, &action_id, "holder-A", 1_700_001_000, 1_700_001_060)
        .await
        .expect("lease_acquire reaches the SAL trait (not UnsupportedCapability)");
    assert_eq!(
        lease.holder, "holder-A",
        "acquired by the requesting holder"
    );
    assert_eq!(lease.expires_at, 1_700_001_060, "caller-computed deadline");

    // A live lease blocks a different holder (single-holder invariant).
    assert!(
        store
            .lease_acquire(&ctx, &action_id, "holder-B", 1_700_001_001, 1_700_001_061)
            .await
            .is_err(),
        "a live lease blocks a different holder"
    );

    // renew — extend the deadline for the holder.
    let renewed = store
        .lease_renew(&ctx, &action_id, "holder-A", 1_700_001_030, 1_700_001_090)
        .await
        .expect("lease_renew reaches the SAL trait");
    assert_eq!(
        renewed.expires_at, 1_700_001_090,
        "renewed deadline extended"
    );

    // get — reflects the renewed lease.
    let got = store
        .lease_get(&ctx, &action_id)
        .await
        .expect("lease_get reaches the SAL trait")
        .expect("a lease is present");
    assert_eq!(got.holder, "holder-A");
    assert_eq!(got.expires_at, 1_700_001_090);

    // release — the held lease is removed.
    assert!(
        store
            .lease_release(&ctx, &action_id, "holder-A")
            .await
            .expect("lease_release reaches the SAL trait"),
        "the held lease is released"
    );
    assert!(
        store
            .lease_get(&ctx, &action_id)
            .await
            .expect("lease_get after release ok")
            .is_none(),
        "no lease remains after release"
    );
}

/// `SqliteStore` — always runs. Proves the sqlite SAL adapter serves the lease
/// surface through the trait (the sqlite adapter delegates to the same
/// `crate::actions::*` free-functions the MCP stdio handler calls).
#[tokio::test]
async fn lease_acquire_reaches_sal_trait_sqlite_2513() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let store = ai_memory::store::sqlite::SqliteStore::open(f.path()).expect("open SqliteStore");
    exercise_lease_sal_surface(&store).await;
}

/// `PostgresStore` — the live-pg twin. Compile-gated on `sal-postgres`
/// (`PostgresStore` lives behind that feature) and RUN-gated on
/// `AI_MEMORY_TEST_POSTGRES_URL`; `#[ignore]` so a default `cargo test` never
/// requires a live database. Proves the postgres SAL adapter is READY to serve
/// a future pg-reachable lease wire surface routed through `app.store` — the
/// forward-scaffolding #2513 documents as dormant-but-correct.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires a live postgres at AI_MEMORY_TEST_POSTGRES_URL"]
async fn lease_acquire_reaches_sal_trait_postgres_2513() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("AI_MEMORY_TEST_POSTGRES_URL unset — skipping live-pg lease reachability twin");
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect PostgresStore");
    exercise_lease_sal_surface(&store).await;
}
