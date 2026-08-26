// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::too_many_lines, clippy::needless_update)]

//! #3193 / #3194 — SAL-layer caller-owns gates on postgres
//! `archive_by_ids` and `link` / `link_signed`.
//!
//! Template: [`postgres_owner_gate_1412.rs`]. Skip when
//! `AI_MEMORY_TEST_POSTGRES_URL` is unset (stderr WARN). The PR
//! lane MUST run these with the scratch URL so they do not skip.

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{
    ConfidenceSource, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier,
};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};

async fn maybe_open() -> Option<PostgresStore> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!(
            "test skipped: AI_MEMORY_TEST_POSTGRES_URL not set — \
             postgres-only #3193/#3194 owner-gate pin requires a live instance"
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

fn seed_mem_owned_by(owner: &str, namespace: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "body".to_string(),
        tags: vec!["3193-pin".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test-3193".to_string(),
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

fn related_link(source_id: &str, target_id: &str) -> MemoryLink {
    MemoryLink {
        source_id: source_id.to_string(),
        target_id: target_id.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: None,
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

struct RestoreK9Rules;
impl Drop for RestoreK9Rules {
    fn drop(&mut self) {
        ai_memory::permissions::clear_active_permission_rules_for_test();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// #3193 — PostgresStore::archive_by_ids owner gate
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn postgres_archive_by_ids_owner_match_succeeds_3193() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:3193-alice-archive-match";
    let ctx = CallerContext::for_agent(alice);
    let mem = seed_mem_owned_by(alice, "ns-3193-am", "owner-match-archive");
    let id = store.store(&ctx, &mem).await.expect("seed insert");
    let n = store
        .archive_by_ids(&ctx, std::slice::from_ref(&id), Some("test-3193"))
        .await
        .expect("owner-match archive must succeed");
    assert_eq!(n, 1, "exactly one live row archived");
    let err = store
        .get(&ctx, &id)
        .await
        .expect_err("archived row must leave the live table");
    match err {
        StoreError::NotFound { id: gone } => assert_eq!(gone, id),
        other => panic!("expected NotFound after archive, got: {other:?}"),
    }
}

#[tokio::test]
async fn postgres_archive_by_ids_owner_mismatch_returns_permission_denied_3193() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:3193-alice-archive-mismatch";
    let bob = "ai:3193-bob-archive-hijack";
    let mem = seed_mem_owned_by(alice, "ns-3193-amm", "owner-mismatch-archive");
    let id = store
        .store(&CallerContext::for_agent(alice), &mem)
        .await
        .expect("seed insert");
    let err = store
        .archive_by_ids(
            &CallerContext::for_agent(bob),
            std::slice::from_ref(&id),
            Some("hijack"),
        )
        .await
        .expect_err("owner-mismatch archive must error");
    match err {
        StoreError::PermissionDenied {
            action,
            target,
            reason,
        } => {
            assert_eq!(action, "archive", "action carries op name; got: {action:?}");
            assert_eq!(target, id, "target is the row id");
            assert!(
                reason.contains(bob),
                "reason names the rejected caller, got: {reason:?}"
            );
            assert!(
                reason.contains(alice),
                "reason names the rightful owner, got: {reason:?}"
            );
        }
        other => panic!("expected PermissionDenied, got: {other:?}"),
    }
    store
        .get(&CallerContext::for_agent(alice), &id)
        .await
        .expect("refusal must leave alice's row LIVE (no data loss)");
}

#[tokio::test]
async fn postgres_archive_by_ids_admin_bypass_skips_owner_gate_3193() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:3193-alice-admin-bypass-archive";
    let mem = seed_mem_owned_by(alice, "ns-3193-aab", "admin-bypass-archive");
    let id = store
        .store(&CallerContext::for_agent(alice), &mem)
        .await
        .expect("seed insert");
    let admin = CallerContext::for_admin("operator:archive-gc");
    let n = store
        .archive_by_ids(&admin, std::slice::from_ref(&id), Some("admin-3193"))
        .await
        .expect("admin bypass must skip the owner gate");
    assert_eq!(n, 1);
}

#[tokio::test]
async fn postgres_archive_by_ids_unstamped_row_refused_3193() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:3193-alice-unstamped-archive";
    let ctx = CallerContext::for_agent(alice);
    let mem = seed_mem_owned_by(alice, "ns-3193-unst", "unstamped-archive");
    let id = store.store(&ctx, &mem).await.expect("seed insert");
    // Strip the agent_id stamp so the pg #3124 unstamped-row policy
    // fires (REFUSE — leaves the row live). `metadata->>'agent_id'`
    // returns SQL NULL on an empty object.
    sqlx::query("UPDATE memories SET metadata = '{}'::jsonb WHERE id = $1")
        .bind(&id)
        .execute(store.pool())
        .await
        .expect("strip agent_id stamp");
    let err = store
        .archive_by_ids(&ctx, std::slice::from_ref(&id), Some("unstamped"))
        .await
        .expect_err("unstamped tenant archive must error (pg #3124)");
    match err {
        StoreError::PermissionDenied {
            action,
            target,
            reason,
        } => {
            assert_eq!(action, "archive");
            assert_eq!(target, id);
            assert!(
                reason.contains("no agent_id stamp"),
                "unstamped reason, got: {reason:?}"
            );
            assert!(
                reason.contains("archives refused"),
                "archive-verb sibling of the write/delete reasons, got: {reason:?}"
            );
        }
        other => panic!("expected PermissionDenied, got: {other:?}"),
    }
    store
        .get(&CallerContext::for_admin("operator:unstamped-read"), &id)
        .await
        .expect("unstamped refusal must leave the row LIVE");
}

#[tokio::test]
async fn postgres_archive_by_ids_unknown_id_is_silent_zero_3193() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:3193-unknown");
    let bogus = uuid::Uuid::new_v4().to_string();
    let n = store
        .archive_by_ids(&ctx, std::slice::from_ref(&bogus), None)
        .await
        .expect("missing id is a silent continue, not PermissionDenied (no existence oracle)");
    assert_eq!(n, 0);
}

#[tokio::test]
async fn postgres_archive_by_ids_inbox_target_carve_out_3193() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:3193-alice-inbox-src";
    let bob = "ai:3193-bob-inbox-target";
    let mut mem = seed_mem_owned_by(alice, "ns-3193-inb", "inbox-archive");
    mem.metadata = serde_json::json!({
        "agent_id": alice,
        "target_agent_id": bob,
    });
    let id = store
        .store(&CallerContext::for_agent(alice), &mem)
        .await
        .expect("seed inbox row");
    let n = store
        .archive_by_ids(
            &CallerContext::for_agent(bob),
            std::slice::from_ref(&id),
            Some("inbox-3193"),
        )
        .await
        .expect("inbox-target carve-out: bob may archive a row addressed to him");
    assert_eq!(n, 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// #3194 — PostgresStore::link / link_signed caller-owns + inbox carve-out
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn postgres_link_owner_match_succeeds_3194() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:3194-alice-link-match";
    let ctx = CallerContext::for_agent(alice);
    let src = seed_mem_owned_by(alice, "ns-3194-lm", "link-src-match");
    let dst = seed_mem_owned_by(alice, "ns-3194-lm", "link-dst-match");
    let src_id = store.store(&ctx, &src).await.expect("seed src");
    let dst_id = store.store(&ctx, &dst).await.expect("seed dst");
    store
        .link(&ctx, &related_link(&src_id, &dst_id))
        .await
        .expect("owner-match link must succeed");
}

#[tokio::test]
async fn postgres_link_owner_mismatch_returns_permission_denied_3194() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:3194-alice-link-mismatch";
    let bob = "ai:3194-bob-link-hijack";
    let src = seed_mem_owned_by(alice, "ns-3194-lmm", "link-src-mismatch");
    let dst = seed_mem_owned_by(bob, "ns-3194-lmm", "link-dst-mismatch");
    let src_id = store
        .store(&CallerContext::for_agent(alice), &src)
        .await
        .expect("seed src");
    let dst_id = store
        .store(&CallerContext::for_agent(bob), &dst)
        .await
        .expect("seed dst");
    let err = store
        .link(
            &CallerContext::for_agent(bob),
            &related_link(&src_id, &dst_id),
        )
        .await
        .expect_err("bob must not root a link at alice's source");
    match err {
        StoreError::PermissionDenied {
            action,
            target,
            reason,
        } => {
            assert_eq!(action, "memory_link");
            assert_eq!(target, src_id);
            assert!(
                reason.contains(ai_memory::errors::msg::CALLER_NOT_SOURCE_MEMORY_OWNER),
                "sqlite #941 wire body, got: {reason:?}"
            );
        }
        other => panic!("expected PermissionDenied, got: {other:?}"),
    }
}

#[tokio::test]
async fn postgres_link_signed_also_gates_on_ctx_3194() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:3194-alice-link-signed";
    let bob = "ai:3194-bob-link-signed";
    let src = seed_mem_owned_by(alice, "ns-3194-ls", "link-signed-src");
    let dst = seed_mem_owned_by(bob, "ns-3194-ls", "link-signed-dst");
    let src_id = store
        .store(&CallerContext::for_agent(alice), &src)
        .await
        .expect("seed src");
    let dst_id = store
        .store(&CallerContext::for_agent(bob), &dst)
        .await
        .expect("seed dst");
    // Pre-fix `link_signed` discarded `_ctx` and evaluated K9 as the
    // daemon keypair. Passing `None` keypair used to make the write
    // succeed for ANY caller; now the ctx principal is the gate.
    let err = store
        .link_signed(
            &CallerContext::for_agent(bob),
            &related_link(&src_id, &dst_id),
            None,
        )
        .await
        .expect_err("link_signed must honour ctx, not the (absent) keypair");
    match err {
        StoreError::PermissionDenied { action, .. } => assert_eq!(action, "memory_link"),
        other => panic!("expected PermissionDenied, got: {other:?}"),
    }
}

#[tokio::test]
async fn postgres_link_inbox_target_carve_out_holds_3194() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:3194-alice-inbox-src";
    let bob = "ai:3194-bob-inbox-target";
    let mut src = seed_mem_owned_by(alice, "ns-3194-inb", "inbox-src");
    src.metadata = serde_json::json!({
        "agent_id": alice,
        "target_agent_id": bob,
    });
    let dst = seed_mem_owned_by(bob, "ns-3194-inb", "inbox-dst");
    let src_id = store
        .store(&CallerContext::for_agent(alice), &src)
        .await
        .expect("seed inbox src");
    let dst_id = store
        .store(&CallerContext::for_agent(bob), &dst)
        .await
        .expect("seed dst");
    store
        .link(
            &CallerContext::for_agent(bob),
            &related_link(&src_id, &dst_id),
        )
        .await
        .expect("inbox-target carve-out: bob may link from a source addressed to him");
}

#[tokio::test]
async fn postgres_link_missing_source_is_not_an_existence_oracle_3194() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let bob = "ai:3194-bob-missing-src";
    let ctx = CallerContext::for_agent(bob);
    let dst = seed_mem_owned_by(bob, "ns-3194-ms", "missing-src-dst");
    let dst_id = store.store(&ctx, &dst).await.expect("seed dst");
    let bogus = uuid::Uuid::new_v4().to_string();
    let err = store
        .link(&ctx, &related_link(&bogus, &dst_id))
        .await
        .expect_err("missing source must error");
    match err {
        StoreError::InvalidInput { detail } => {
            assert!(
                detail.contains("source memory not found"),
                "FK pre-flight names the missing memory, not a 403 oracle; got: {detail:?}"
            );
        }
        StoreError::PermissionDenied { .. } => {
            panic!("owner-gate 403 on a missing id would be an existence oracle")
        }
        other => panic!("expected InvalidInput, got: {other:?}"),
    }
}

#[tokio::test]
async fn postgres_link_admin_bypass_skips_owner_gate_3194() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:3194-alice-admin-link";
    let src = seed_mem_owned_by(alice, "ns-3194-al", "admin-link-src");
    let dst = seed_mem_owned_by(alice, "ns-3194-al", "admin-link-dst");
    let src_id = store
        .store(&CallerContext::for_agent(alice), &src)
        .await
        .expect("seed src");
    let dst_id = store
        .store(&CallerContext::for_agent(alice), &dst)
        .await
        .expect("seed dst");
    store
        .link(
            &CallerContext::for_admin("operator:relink"),
            &related_link(&src_id, &dst_id),
        )
        .await
        .expect("admin bypass must skip the source-owner gate");
}

#[tokio::test]
async fn postgres_link_k9_denies_based_on_the_caller_3194() {
    // #3194 acceptance: "Deny on the namespace refuses based on the CALLER"
    // (not the daemon keypair). Pre-fix K9 evaluated as keypair-or-"system".
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:3194-k9-caller-pin";
    let ns = "ns-3194-k9-caller";
    ai_memory::config::set_active_permissions_mode(ai_memory::config::PermissionsMode::Enforce);
    ai_memory::permissions::set_active_permission_rules(vec![
        ai_memory::permissions::PermissionRule {
            namespace_pattern: ns.to_string(),
            op: "memory_link".to_string(),
            agent_pattern: alice.to_string(),
            decision: ai_memory::permissions::RuleDecision::Deny,
            reason: Some("k9 caller pin 3194".to_string()),
        },
    ]);
    let _restore = RestoreK9Rules;
    let ctx = CallerContext::for_agent(alice);
    let src = seed_mem_owned_by(alice, ns, "k9-src");
    let dst = seed_mem_owned_by(alice, ns, "k9-dst");
    let src_id = store.store(&ctx, &src).await.expect("seed src");
    let dst_id = store.store(&ctx, &dst).await.expect("seed dst");
    let err = store
        .link(&ctx, &related_link(&src_id, &dst_id))
        .await
        .expect_err("owner-match link must still refuse when K9 denies the CALLER");
    match err {
        StoreError::PermissionDenied { action, reason, .. } => {
            assert_eq!(action, "memory_link");
            assert!(
                reason.contains(ai_memory::storage::LINK_PERMISSION_DENIED_ERR_PREFIX)
                    || reason.contains("k9 caller pin 3194"),
                "K9 deny must surface the permission-rule envelope, got: {reason:?}"
            );
        }
        other => panic!("expected PermissionDenied from K9, got: {other:?}"),
    }
}
