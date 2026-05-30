// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::needless_update)]

//! v0.7.0 #1423 — regression pin for the postgres-PUT silent-drop of
//! `body.expires_at`.
//!
//! Pre-fix `crate::store::UpdatePatch` had no `expires_at` field; the
//! HTTP postgres-branch handler at `src/handlers/memories.rs:228-294`
//! built an `UpdatePatch` from `body` but couldn't include
//! `body.expires_at` because the field didn't exist on the patch.
//! `PostgresStore::update`'s SQL UPDATE never touched the
//! `expires_at` column. A caller PUT-ing
//! `{ "expires_at": "2030-01-01T..." }` against a postgres-backed
//! daemon got 200 OK + stale expires_at on re-fetch.
//!
//! Sqlite branch was OK pre-fix — the sqlite HTTP path bypasses
//! `app.store.update` (UpdatePatch) entirely and calls
//! `db::update_with_expected_version` directly with `body.expires_at`
//! threaded positionally. The fix lives on the postgres path only.
//!
//! Test self-skips when `AI_MEMORY_TEST_POSTGRES_URL` is unset
//! (postgres-only fix; sqlite parity is structural).

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, UpdatePatch};

async fn maybe_open() -> Option<PostgresStore> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!(
            "test skipped: AI_MEMORY_TEST_POSTGRES_URL not set - \
             postgres-only #1423 expires_at pin requires a live instance"
        );
        return None;
    };
    match PostgresStore::connect(&url).await {
        Ok(store) => Some(store),
        Err(e) => {
            eprintln!("test skipped: PostgresStore::connect failed: {e}");
            None
        }
    }
}

fn seed_mem(owner: &str, namespace: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "body".to_string(),
        tags: vec!["1423-pin".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test-1423".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": owner }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

#[tokio::test]
async fn postgres_update_threads_expires_at_through_sal_patch() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let owner = "ai:1423-expires-at-roundtrip";
    let ctx = CallerContext::for_agent(owner);
    let mem = seed_mem(owner, "ns-1423-set", "expires-at-set");
    let inserted_id = store.store(&ctx, &mem).await.expect("seed insert");

    // Round-trip 1 — verify the seed row landed with expires_at = NULL.
    let pre = store.get(&ctx, &inserted_id).await.expect("get post-seed");
    assert!(
        pre.expires_at.is_none(),
        "seed row has no expires_at; got: {:?}",
        pre.expires_at
    );

    // PUT-equivalent: SAL update with expires_at set to a future
    // RFC3339 timestamp. Pre-#1423 the patch had no expires_at field
    // so this was structurally impossible to express.
    let future = "2030-01-01T00:00:00+00:00";
    let patch = UpdatePatch {
        expires_at: Some(future.to_string()),
        ..Default::default()
    };
    store
        .update(&ctx, &inserted_id, patch)
        .await
        .expect("expires_at patch must succeed");

    let post = store
        .get(&ctx, &inserted_id)
        .await
        .expect("get post-update");
    let stamped = post
        .expires_at
        .as_deref()
        .expect("post-update row carries the patched expires_at (pre-#1423 this was None)");
    // RFC3339 round-trips with potential format normalization through
    // postgres (e.g. timezone may render as `+00:00` or `Z`). Compare
    // as parsed timestamps to be tolerant.
    let want = chrono::DateTime::parse_from_rfc3339(future).expect("parse future");
    let got = chrono::DateTime::parse_from_rfc3339(stamped).expect("parse stamped");
    assert_eq!(
        want.timestamp(),
        got.timestamp(),
        "expires_at round-trips to the same instant"
    );
}

#[tokio::test]
async fn postgres_update_without_expires_at_patch_leaves_stored_value_untouched() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let owner = "ai:1423-expires-at-coalesce";
    let ctx = CallerContext::for_agent(owner);
    let mut mem = seed_mem(owner, "ns-1423-coalesce", "expires-at-coalesce");
    // Seed with a pre-existing expires_at so we can prove the no-touch
    // semantics of the COALESCE behaviour.
    let pre_existing = "2029-06-01T12:00:00+00:00";
    mem.expires_at = Some(pre_existing.to_string());
    let inserted_id = store.store(&ctx, &mem).await.expect("seed insert");

    // Patch with title only; expires_at left at None (Unchanged).
    let patch = UpdatePatch {
        title: Some("renamed-1423".to_string()),
        ..Default::default()
    };
    store
        .update(&ctx, &inserted_id, patch)
        .await
        .expect("partial patch must succeed");

    let post = store
        .get(&ctx, &inserted_id)
        .await
        .expect("get post-update");
    assert_eq!(post.title, "renamed-1423", "title patch applied");
    let stamped = post
        .expires_at
        .as_deref()
        .expect("expires_at left untouched - still Some(pre_existing)");
    let want = chrono::DateTime::parse_from_rfc3339(pre_existing).expect("parse pre");
    let got = chrono::DateTime::parse_from_rfc3339(stamped).expect("parse got");
    assert_eq!(
        want.timestamp(),
        got.timestamp(),
        "absent expires_at on patch -> stored value unchanged (COALESCE semantics)"
    );
}
