// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Fix-round 3 — postgres SAL parity regressions (#1626 / #1630 / #1642).
//!
//! Live-postgres gated tests following the skip-if-env-unset pattern of
//! `live_store_with_embedding_persists_full_provenance_1608` and
//! `tests/store_parity_gaps.rs`: every test self-skips with an eprintln
//! when `AI_MEMORY_TEST_POSTGRES_URL` is unset so a plain `cargo test`
//! stays green on nodes without postgres routing, and RUNS the real
//! assertions when the env var points at a live schema.
//!
//! ## How to run
//!
//! ```sh
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://user:pwd@host:5432/db \
//!   cargo test --features sal,sal-postgres --test pg_fix3_parity_tests
//! ```

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, UpdatePatch};

async fn live_pg() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            None
        }
    }
}

/// Memory builder stamped with `metadata.agent_id = owner` so the SAL
/// #1412 caller-owns write gates pass for a `CallerContext::for_agent`
/// built from the same owner.
fn sample_memory(id: &str, namespace: &str, tier: Tier, owner: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier,
        namespace: namespace.to_string(),
        title: format!("title-{id}"),
        content: "fix3 parity test content".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": owner }),
        version: 1,
        ..Memory::default()
    }
}

fn parse_ts(s: &str) -> chrono::DateTime<chrono::FixedOffset> {
    chrono::DateTime::parse_from_rfc3339(s).expect("rfc3339 timestamp")
}

/// #1626 — pg promote (trait `update` with `tier: Some(Long)`) must
/// clear `expires_at`, mirroring the sqlite promote handler's explicit
/// `UPDATE memories SET expires_at = NULL`. Pre-fix the trait update's
/// `expires_at = COALESCE($11, expires_at)` left the old mid-tier
/// deadline in place and GC reaped the promoted "long" row.
#[tokio::test]
async fn live_promote_clears_expiry_pg() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let unique = uuid::Uuid::new_v4();
    let owner = format!("ai:fix3-1626-{unique}");
    let ctx = CallerContext::for_agent(owner.clone());
    let ns = format!("fix3-1626-{unique}");

    // 1) store mid → tier-default expiry is backfilled (non-NULL).
    let mem = sample_memory(&format!("fix3-1626-a-{unique}"), &ns, Tier::Mid, &owner);
    let id = store.store(&ctx, &mem).await.expect("store mid memory");
    let before = store.get(&ctx, &id).await.expect("get pre-promote");
    assert_eq!(before.tier, Tier::Mid);
    assert!(
        before.expires_at.is_some(),
        "mid-tier store must carry the tier-default expiry backfill (#1466)"
    );

    // 2) promote (the handler's promote patch shape) → expiry cleared.
    let promote_patch = UpdatePatch {
        tier: Some(Tier::Long),
        ..UpdatePatch::default()
    };
    store
        .update(&ctx, &id, promote_patch)
        .await
        .expect("promote update");
    let after = store.get(&ctx, &id).await.expect("get post-promote");
    assert_eq!(after.tier, Tier::Long, "tier must land long");
    assert!(
        after.expires_at.is_none(),
        "#1626: promoting to long must clear expires_at on postgres \
         (got {:?})",
        after.expires_at
    );

    // 3) rule: an explicitly-supplied patch.expires_at still wins when
    //    the patch tier is NOT long.
    let mem_b = sample_memory(&format!("fix3-1626-b-{unique}"), &ns, Tier::Mid, &owner);
    let id_b = store.store(&ctx, &mem_b).await.expect("store mid memory b");
    let explicit = (chrono::Utc::now() + chrono::Duration::days(3)).to_rfc3339();
    let expiry_patch = UpdatePatch {
        expires_at: Some(explicit.clone()),
        ..UpdatePatch::default()
    };
    store
        .update(&ctx, &id_b, expiry_patch)
        .await
        .expect("explicit expires_at update");
    let got_b = store.get(&ctx, &id_b).await.expect("get b");
    let got_expiry = got_b
        .expires_at
        .as_deref()
        .expect("explicit expires_at must persist when tier is not long");
    assert_eq!(
        parse_ts(got_expiry).timestamp(),
        parse_ts(&explicit).timestamp(),
        "explicit patch.expires_at must win when tier is not long"
    );

    // 4) rule: when the patch tier IS long, the clear wins even when an
    //    explicit expires_at rides the same patch (sqlite upsert
    //    semantics: expiry is only cleared / never set on long).
    let long_with_expiry = UpdatePatch {
        tier: Some(Tier::Long),
        expires_at: Some(explicit),
        ..UpdatePatch::default()
    };
    store
        .update(&ctx, &id_b, long_with_expiry)
        .await
        .expect("promote-with-expiry update");
    let got_b2 = store.get(&ctx, &id_b).await.expect("get b post-promote");
    assert!(
        got_b2.expires_at.is_none(),
        "#1626: the tier→long clear must win over an explicit \
         patch.expires_at (got {:?})",
        got_b2.expires_at
    );

    // Cleanup (best-effort).
    let _ = store.delete(&ctx, &id).await;
    let _ = store.delete(&ctx, &id_b).await;
}
