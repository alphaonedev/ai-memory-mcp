// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4359 (N2) — backend parity of the REFUSAL NAME. When one sender has
//! exhausted BOTH the per-recipient inbox row and the per-sender `_notify`
//! aggregate row, the next notify is refused on sqlite and on postgres with a
//! `QuotaExceeded` that names the SAME row: the aggregate (`_notify`), because
//! both backends charge the aggregate first. Allow/refuse behaviour is
//! unchanged; only the named row was backend-dependent.
//! The postgres cell FAILS (not skips) when `AI_MEMORY_TEST_POSTGRES_URL` is
//! set but the database is unreachable; it skips only when the variable is unset.

#![cfg(feature = "sal")]

use ai_memory::store::{CallerContext, MemoryStore, StoreError};

const SENTINEL: &str = ai_memory::quotas::NOTIFY_AGGREGATE_NAMESPACE;
/// Default notify ceiling per (sender, row) per day.
const CEILING: usize = 1_000;

/// Exhaust both rows (one recipient, `CEILING` notifies), then notify once
/// more and return the namespace named by the refusal.
async fn refusal_namespace_when_both_rows_exhausted<S: MemoryStore>(
    store: &S,
    sender: &str,
    target: &str,
) -> String {
    let ctx = CallerContext::for_agent(sender);
    for index in 0..CEILING {
        store
            .notify(&ctx, target, "t", "p", None, None, None)
            .await
            .unwrap_or_else(|e| panic!("notify {index} under the ceiling failed: {e:?}"));
    }
    match store.notify(&ctx, target, "t", "p", None, None, None).await {
        Err(StoreError::QuotaExceeded { namespace, .. }) => namespace,
        other => panic!("expected QuotaExceeded on the over-ceiling notify, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_refusal_names_the_aggregate_row_when_both_exhausted_4359() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ai_memory::store::sqlite::SqliteStore::open(dir.path().join("p.db"))
        .expect("open SqliteStore");
    let name = refusal_namespace_when_both_rows_exhausted(&store, "ai:par-sqlite", "ai:rcpt").await;
    assert_eq!(name, SENTINEL);
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn pg_refusal_names_the_aggregate_row_when_both_exhausted_4359() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("SKIP notify_refusal_name_parity_4359: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("AI_MEMORY_TEST_POSTGRES_URL is set but postgres is unreachable");
    let sender = format!("ai:par-pg-{}", uuid::Uuid::new_v4().simple());
    let target = format!("ai:rcpt-{}", uuid::Uuid::new_v4().simple());
    let name = refusal_namespace_when_both_rows_exhausted(&store, &sender, &target).await;
    assert_eq!(name, SENTINEL);
}
