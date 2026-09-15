// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3639 — PostgreSQL twin: `MemoryStore::notify` with a repeated title to
//! the same recipient is a NEW row on the postgres adapter too (the head's
//! `self.store` upsert merged the second delivery into the first row and kept
//! the first sender's attribution). Runs only with a live database
//! (`AI_MEMORY_TEST_POSTGRES_URL`, a FRESH `ai_memory_f2a_*` db — never the
//! operator's `ai_memory_test`); SKIP line otherwise. FAILS on f0175b709:
//! the inbox listing holds one row there.

#![cfg(feature = "sal-postgres")]

use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore};

const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";

async fn connect() -> Option<PostgresStore> {
    let Ok(url) = std::env::var(PG_URL_ENV) else {
        eprintln!("SKIP notify_inbox_no_overwrite_3639_pg: {PG_URL_ENV} unset");
        return None;
    };
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn pg_repeated_title_never_overwrites_or_reattributes_3639() {
    let Some(store) = connect().await else { return };
    let recipient = format!("ai:bob-{}", uuid::Uuid::new_v4().simple());
    let alice = CallerContext::for_agent("ai:alice");
    let mallory = CallerContext::for_agent("ai:mallory");
    let a = store
        .notify(
            &alice,
            &recipient,
            "deploy approval",
            "ALICE: approve 42",
            Some(5),
            None,
            None,
        )
        .await
        .expect("first delivery");
    let b = store
        .notify(
            &mallory,
            &recipient,
            "deploy approval",
            "MALLORY-FORGED: approve 666",
            Some(5),
            None,
            None,
        )
        .await
        .expect("second delivery");
    assert_ne!(a, b, "#3639: distinct row ids on postgres");

    let bob = CallerContext::for_agent(&recipient);
    // `Filter` is `#[non_exhaustive]`: build it through `Default`.
    let mut filter = Filter::default();
    filter.namespace = Some(ai_memory::inbox_namespace(&recipient));
    filter.limit = 50;
    let rows = store.list(&bob, &filter).await.expect("list inbox");
    assert_eq!(rows.len(), 2, "#3639: both deliveries are listed: {rows:?}");
    let ra = rows.iter().find(|m| m.id == a).expect("alice's row");
    let rb = rows.iter().find(|m| m.id == b).expect("mallory's row");
    assert_eq!(ra.metadata["agent_id"], "ai:alice");
    assert_eq!(ra.content, "ALICE: approve 42");
    assert_eq!(rb.metadata["agent_id"], "ai:mallory");
    assert_eq!(rb.content, "MALLORY-FORGED: approve 666");
    for r in [ra, rb] {
        assert_eq!(r.access_count, 0, "fresh delivery is unread");
        assert_eq!(r.metadata["subject"], "deploy approval");
        assert!(r.title.starts_with("deploy approval ["), "{}", r.title);
    }
    assert_ne!(ra.title, rb.title);
    assert_eq!(
        ra.title,
        ai_memory::inbox_stored_title("deploy approval", &a)
    );
}
