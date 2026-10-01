// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4359 — PostgreSQL twin: the notify daily quota is a per-SENDER bound, not
//! only per (sender, recipient inbox). One sender notifying 1,500 DISTINCT
//! recipients is refused at the sender ceiling; a single-recipient flood is
//! still refused at 1,001; `quota_status_ns(sender, "_notify")` reports the
//! aggregate counter and the namespace-omitted rollup does not double-count.
//! FAILS (not skips) when `AI_MEMORY_TEST_POSTGRES_URL` is set but the
//! database is unreachable; skips only when the variable is unset.

#![cfg(feature = "sal-postgres")]

use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};

const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";
const SENTINEL: &str = ai_memory::quotas::NOTIFY_AGGREGATE_NAMESPACE;

async fn connect() -> Option<PostgresStore> {
    let Ok(url) = std::env::var(PG_URL_ENV) else {
        eprintln!("SKIP notify_sender_quota_4359_pg: {PG_URL_ENV} unset");
        return None;
    };
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("AI_MEMORY_TEST_POSTGRES_URL is set but postgres is unreachable"),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn pg_distinct_recipient_flood_is_refused_at_the_sender_ceiling_4359() {
    let Some(store) = connect().await else { return };
    let sender = format!("ai:flood-{}", uuid::Uuid::new_v4().simple());
    let ctx = CallerContext::for_agent(&sender);
    let (mut ok, mut first_refusal) = (0_usize, None);
    for index in 0..1_500_usize {
        let target = format!("ai:distinct-{}-{index}", uuid::Uuid::new_v4().simple());
        match store
            .notify(&ctx, &target, "flood", "p", None, None, None)
            .await
        {
            Ok(_) => ok += 1,
            Err(StoreError::QuotaExceeded { namespace, .. }) => {
                assert_eq!(namespace, SENTINEL);
                first_refusal.get_or_insert(index);
            }
            Err(e) => panic!("unexpected error at {index}: {e:?}"),
        }
    }
    assert_eq!(first_refusal, Some(1_000));
    assert_eq!(ok, 1_000);
    let agg = store
        .quota_status_ns(&sender, SENTINEL)
        .await
        .expect("aggregate");
    assert_eq!(agg.current_memories_today, 1_000);
    assert_eq!(agg.max_memories_per_day, 1_000);
    let rollup = store.quota_status(&sender).await.expect("rollup");
    assert_eq!(rollup.current_memories_today, 1_000, "no double count");
}

#[tokio::test(flavor = "multi_thread")]
async fn pg_single_recipient_flood_still_refused_at_1001_4359() {
    let Some(store) = connect().await else { return };
    let sender = format!("ai:one-{}", uuid::Uuid::new_v4().simple());
    let target = format!("ai:same-{}", uuid::Uuid::new_v4().simple());
    let ctx = CallerContext::for_agent(&sender);
    let mut refused_at = None;
    for index in 0..1_002_usize {
        if let Err(e) = store
            .notify(&ctx, &target, "f", "p", None, None, None)
            .await
        {
            assert!(matches!(e, StoreError::QuotaExceeded { .. }), "{e:?}");
            refused_at.get_or_insert(index);
        }
    }
    assert_eq!(refused_at, Some(1_000));
    let ns = store
        .quota_status_ns(&sender, &ai_memory::inbox_namespace(&target))
        .await
        .expect("ns status");
    assert_eq!(ns.current_memories_today, 1_000);
}
