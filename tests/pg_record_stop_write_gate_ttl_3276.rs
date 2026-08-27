// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// #1986: crate-level `//!` docs are still linted when `#![cfg(feature =
// "sal-postgres")]` is false (the allow below that cfg is configured out).
#![allow(clippy::doc_markdown)]

//! v1.0.0 #3276 — the record-stop is a DURABLE, fleet-wide "freeze all
//! writes" control (persisted in the `signed_events` chain). A stop engaged
//! by ANY daemon must freeze EVERY daemon's WRITE gate, not only the pool
//! that issued it.
//!
//! Pre-#3276 the postgres WRITE gate (`gate_record_stop`) read ONLY the
//! process-local cache seeded once at `connect`, so a stop engaged by
//! another pool did NOT stop this pool's HTTP/MCP writes until it
//! reconnected — a fail-OPEN kill switch. The fix adds a TTL-bounded,
//! single-flight durable re-check to the write gate.
//!
//! This binary holds a SINGLE `#[tokio::test]` because engaging the record
//! plane is a cluster-wide state on the shared test database; concurrent
//! tests in one binary would stomp each other's engage/release on the shared
//! chain. Every phase releases the stop before it asserts, so a failure can
//! never leave the shared cluster frozen.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL` (skips cleanly when unset).

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::uninlined_format_args
)]

use std::time::Duration;

use ai_memory::models::Memory;
use ai_memory::store::postgres::{PostgresStore, RECORD_STOP_REFRESH_TTL_MS};
use ai_memory::store::{CallerContext, MemoryStore, StoreError};

/// A slack margin added to the TTL so timing jitter never flakes the test.
const TTL_SLACK_MS: u64 = 400;

fn past_ttl() -> Duration {
    Duration::from_millis(RECORD_STOP_REFRESH_TTL_MS + TTL_SLACK_MS)
}

fn mem(namespace: &str, id: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: "3276".to_string(),
        content: "body".to_string(),
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        ..Default::default()
    }
}

async fn row_exists(store: &PostgresStore, id: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM memories WHERE id = $1)")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .expect("row-exists probe")
}

async fn purge(store: &PostgresStore, id: &str) {
    let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
        .bind(id)
        .execute(store.pool())
        .await;
}

#[tokio::test]
async fn pg_write_gate_honors_cross_pool_stop_within_ttl_3276() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        return; // no live PG — skip cleanly
    };

    // Two pools against ONE cluster — the production multi-daemon topology.
    // `store_a` connects while the plane is RUNNING, so its cache is seeded
    // RUNNING and ONLY a durable re-check can correct it (no reconnect, no
    // `record_stop_status` call, in this test).
    let store_a = PostgresStore::connect(&url).await.expect("connect store_a");
    let store_b = PostgresStore::connect(&url).await.expect("connect store_b");
    let ctx = CallerContext::for_admin("ai:3276");

    let early_id = uuid::Uuid::new_v4().to_string();
    let late_id = uuid::Uuid::new_v4().to_string();
    let fc_id = uuid::Uuid::new_v4().to_string();

    // ============================================================
    // PHASE A — the durable re-check + the bounded fast-path window.
    // ============================================================
    store_b
        .record_stop(&ctx, true, "ai:3276", "record-plane")
        .await
        .expect("engage record-stop from store_b");

    // (2) STEADY-STATE FAST PATH: within the TTL window, `store_a`'s write
    //     gate rides its (still-RUNNING) process-local cache and does NOT do
    //     a per-write DB read — so it does not yet observe the cross-pool
    //     stop and the write LANDS. This is the deliberate, bounded fail-open
    //     window (≤ RECORD_STOP_REFRESH_TTL_MS) that is the accepted cost of
    //     NOT paying a DB round-trip on every write; a per-write read is what
    //     #3276 explicitly must avoid. Same-process stops remain instant (the
    //     shared cache flips synchronously) — this window is cross-pool only.
    let early = store_a.store(&ctx, &mem("ns-3276-early", &early_id)).await;
    // The precise steady-state claim: the gate did NOT refuse (it rode the
    // cache and did not re-read the chain). A per-write DB read would have
    // surfaced the just-engaged cross-pool stop as `Stopped` here.
    let early_not_gated = !matches!(early, Err(StoreError::Stopped { .. }));
    let early_landed = row_exists(&store_b, &early_id).await;

    // Let the shared re-check clock go stale.
    tokio::time::sleep(past_ttl()).await;

    // (1) DURABLE RE-CHECK: after the TTL, `store_a`'s write gate re-derives
    //     the durable state from the `signed_events` chain, reconciles its
    //     cache to STOPPED, and REFUSES — WITHOUT any reconnect and WITHOUT a
    //     `record_stop_status` call. A NONEXISTENT id also proves the gate
    //     runs BEFORE the row work (an ungated body would not surface Stopped).
    let late = store_a.store(&ctx, &mem("ns-3276-late", &late_id)).await;
    let late_stopped = matches!(late, Err(StoreError::Stopped { .. }));
    let late_landed = row_exists(&store_b, &late_id).await;

    // Release BEFORE asserting so a failure cannot leave the cluster stopped.
    store_b
        .record_stop(&ctx, false, "ai:3276", "record-plane")
        .await
        .expect("release record-stop (phase A)");

    // ============================================================
    // PHASE B — fail-CLOSED: a durable-read error must NOT downgrade STOPPED.
    // ============================================================
    store_b
        .record_stop(&ctx, true, "ai:3276", "record-plane")
        .await
        .expect("engage record-stop from store_b (phase B)");

    // Reconcile `store_a`'s cache to STOPPED through the chain-derived status
    // read, then BREAK `store_a`'s durable read path by closing its pool.
    let fc_status = store_a
        .record_stop_status(&ctx)
        .await
        .expect("record_stop_status (phase B)");
    store_a.pool().close().await;

    // Force the write gate's re-check to fire (stale clock). The chain read
    // now ERRORS (pool closed); the fail-closed contract is that the error
    // leaves the cache UNTOUCHED (STOPPED), so the gate still refuses with
    // `Stopped` — never a silent downgrade to RUNNING (which would surface as
    // Ok or a non-Stopped backend error).
    tokio::time::sleep(past_ttl()).await;
    let fc = store_a.store(&ctx, &mem("ns-3276-fc", &fc_id)).await;
    let fc_stopped = matches!(fc, Err(StoreError::Stopped { .. }));

    // Release through the still-live `store_b` pool and clean up landed rows.
    store_b
        .record_stop(&ctx, false, "ai:3276", "record-plane")
        .await
        .expect("release record-stop (phase B)");
    purge(&store_b, &early_id).await;
    purge(&store_b, &late_id).await;
    purge(&store_b, &fc_id).await;

    // -------------------- assertions --------------------
    assert!(
        early_not_gated,
        "#3276: within the TTL window the write gate must ride the local cache \
         (no per-write DB read), so a just-engaged cross-pool stop is not yet \
         seen and the gate does NOT refuse; got {early:?}, landed={early_landed}"
    );
    assert!(
        late_stopped && !late_landed,
        "#3276: after the TTL the write gate must re-derive the durable stop \
         from the chain and REFUSE with Stopped WITHOUT a reconnect; \
         got {late:?}, landed={late_landed}"
    );
    assert!(
        fc_status.stopped,
        "#3276 setup: store_a's cache must be reconciled to STOPPED before the \
         read path is broken"
    );
    assert!(
        fc_stopped,
        "#3276 fail-closed: a durable-read error (pool closed) must NOT \
         downgrade a cached STOPPED to RUNNING — the gate must still refuse \
         with Stopped; got {fc:?}"
    );
}
