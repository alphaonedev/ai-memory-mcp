// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8487 — PostgreSQL twin of `notify_idempotency_key_8487.rs`: the same
//! `(sender, target, key)` resolves to the original inbox row, a changed body
//! is a typed conflict carrying the original id, invalid keys are refused
//! before any write, an absent key is today's behaviour, and a concurrent
//! retry race leaves one row. Runs only with a live database
//! (`AI_MEMORY_TEST_POSTGRES_URL`); SKIP line otherwise. Every cell uses
//! unique sender and recipient ids, so it is safe on a shared clone.
//!
//! Decision shape: 3-agent vote (6def5ab6).

#![cfg(feature = "sal-postgres")]

use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore, NotifyOutcome, StoreError};
use std::sync::Arc;

const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";
const KEY: &str = "retry-key_1.a:b";

async fn connect() -> Option<PostgresStore> {
    let Ok(url) = std::env::var(PG_URL_ENV) else {
        eprintln!("SKIP notify_idempotency_key_8487_pg: {PG_URL_ENV} unset");
        return None;
    };
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

async fn deliver(
    store: &PostgresStore,
    sender: &str,
    target: &str,
    payload: &str,
    key: Option<&str>,
) -> Result<NotifyOutcome, StoreError> {
    store
        .notify_outcome(
            &CallerContext::for_agent(sender),
            target,
            "deploy approval",
            payload,
            Some(5),
            None,
            None,
            key,
        )
        .await
}

async fn rows(store: &PostgresStore, target: &str) -> usize {
    let bob = CallerContext::for_agent(target);
    let mut filter = Filter::default();
    filter.namespace = Some(ai_memory::inbox_namespace(target));
    filter.limit = 50;
    store.list(&bob, &filter).await.expect("list inbox").len()
}

#[tokio::test(flavor = "multi_thread")]
async fn pg_same_key_twice_returns_original_id_and_one_row_8487() {
    let Some(store) = connect().await else { return };
    let (alice, bob) = (uid("ai:alice"), uid("ai:bob"));
    let a = deliver(&store, &alice, &bob, "body", Some(KEY))
        .await
        .unwrap();
    let b = deliver(&store, &alice, &bob, "body", Some(KEY))
        .await
        .unwrap();
    assert!(!a.dedup_hit);
    assert!(b.dedup_hit);
    assert_eq!(a.id, b.id);
    assert_eq!(rows(&store, &bob).await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn pg_target_and_sender_scope_the_key_8487() {
    let Some(store) = connect().await else { return };
    let (alice, mallory, bob, carol) = (
        uid("ai:alice"),
        uid("ai:mallory"),
        uid("ai:bob"),
        uid("ai:carol"),
    );
    let a = deliver(&store, &alice, &bob, "body", Some(KEY))
        .await
        .unwrap();
    let other_target = deliver(&store, &alice, &carol, "body", Some(KEY))
        .await
        .unwrap();
    let other_sender = deliver(&store, &mallory, &bob, "body", Some(KEY))
        .await
        .unwrap();
    assert_ne!(a.id, other_target.id);
    assert_ne!(a.id, other_sender.id);
    assert!(!other_target.dedup_hit && !other_sender.dedup_hit);
    assert_eq!(rows(&store, &bob).await, 2);
    assert_eq!(rows(&store, &carol).await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn pg_mismatched_payload_conflicts_with_original_id_8487() {
    let Some(store) = connect().await else { return };
    let (alice, bob) = (uid("ai:alice"), uid("ai:bob"));
    let a = deliver(&store, &alice, &bob, "body", Some(KEY))
        .await
        .unwrap();
    let err = deliver(&store, &alice, &bob, "DIFFERENT", Some(KEY))
        .await
        .expect_err("conflict");
    match err {
        StoreError::Conflict { id } => assert_eq!(id, a.id),
        other => panic!("expected Conflict, got {other:?}"),
    }
    assert_eq!(rows(&store, &bob).await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn pg_invalid_keys_refused_before_any_write_8487() {
    let Some(store) = connect().await else { return };
    let (alice, bob) = (uid("ai:alice"), uid("ai:bob"));
    let too_long = "k".repeat(129);
    for bad in ["", "has space", too_long.as_str()] {
        let err = deliver(&store, &alice, &bob, "body", Some(bad))
            .await
            .expect_err("invalid key refused");
        assert!(matches!(err, StoreError::InvalidInput { .. }), "{err:?}");
    }
    assert_eq!(rows(&store, &bob).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn pg_absent_key_is_todays_behaviour_8487() {
    let Some(store) = connect().await else { return };
    let (alice, bob) = (uid("ai:alice"), uid("ai:bob"));
    let a = deliver(&store, &alice, &bob, "body", None).await.unwrap();
    let b = deliver(&store, &alice, &bob, "body", None).await.unwrap();
    assert_ne!(a.id, b.id);
    assert!(!a.dedup_hit && !b.dedup_hit);
    assert_eq!(rows(&store, &bob).await, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_concurrent_retry_race_yields_one_row_and_one_id_8487() {
    let Some(store) = connect().await else { return };
    let store = Arc::new(store);
    let (alice, bob) = (uid("ai:alice"), uid("ai:bob"));
    let mut joins = Vec::new();
    for _ in 0..8 {
        let (s, a, b) = (Arc::clone(&store), alice.clone(), bob.clone());
        joins.push(tokio::spawn(async move {
            deliver(&s, &a, &b, "body", Some(KEY)).await
        }));
    }
    let mut ids = Vec::new();
    let mut fresh = 0;
    for j in joins {
        let o = j.await.unwrap().expect("every racer succeeds");
        if !o.dedup_hit {
            fresh += 1;
        }
        ids.push(o.id);
    }
    assert_eq!(fresh, 1, "exactly one racer inserts");
    assert!(ids.iter().all(|i| *i == ids[0]));
    assert_eq!(rows(&store, &bob).await, 1);
}
