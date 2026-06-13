// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::too_many_lines, clippy::needless_update)]

//! v0.7.0 #1412 (CRITICAL, 2026-05-30) — SAL-layer caller-owns gate on
//! `PostgresStore::update` + `::delete`. Pre-fix the postgres adapter
//! discarded its `_ctx: &CallerContext` and let any authenticated
//! caller rewrite or delete any tenant's memory row by id; sqlite
//! enforced the gate at the HTTP handler layer via
//! `require_caller_owns_memory` but postgres' HTTP branch routed
//! through `app.store.update` / `app.store.delete` which bypassed it
//! entirely.
//!
//! Discovered by the 6-agent code+security review of `release/v0.7.0`
//! HEAD `4488d25ca` (reviewer 2 wire-truthfulness finding F2.6, also
//! flagged at reviewer 3 C2-clean dimension exception, memories
//! `51ee1c71` + `cd28329a`).
//!
//! ## Threat model
//!
//! Multi-tenant postgres-backed daemons: any authenticated caller
//! hijacks any row. Bob can `PUT /memories/{alice-row-id}` against a
//! postgres-backed daemon → 200 OK; against sqlite → 403. The
//! `metadata.agent_id` preservation invariant (Blocker #295) means
//! the rewrite is silent to anyone auditing on agent_id alone.
//!
//! ## What this test pins
//!
//! Two test arms (`update`, `delete`) × four scenarios:
//!
//! 1. **owner matches** — the row's `metadata.agent_id` equals the
//!    caller; operation succeeds (returns Ok).
//! 2. **owner mismatch** — the row's `metadata.agent_id` differs from
//!    the caller; operation returns `StoreError::PermissionDenied`.
//! 3. **row missing** — operation returns `StoreError::NotFound`.
//! 4. **admin bypass** — `CallerContext::for_admin` (bypass_visibility)
//!    skips the gate even when the agent_id doesn't match the row.
//!
//! ## Skip semantics
//!
//! Postgres backend tests require `AI_MEMORY_TEST_POSTGRES_URL` to
//! point at a live instance. When absent, every test in this binary
//! self-skips with a stderr WARN — matching the existing
//! `postgres_*_parity.rs` pattern.

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};

/// Returns `Some(PostgresStore)` when `AI_MEMORY_TEST_POSTGRES_URL`
/// is set, else `None` and emits a stderr WARN so the skip is
/// audit-visible without failing the binary.
async fn maybe_open() -> Option<PostgresStore> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!(
            "test skipped: AI_MEMORY_TEST_POSTGRES_URL not set — \
             postgres-only #1412 owner-gate pin requires a live instance"
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
        tags: vec!["1412-pin".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test-1412".to_string(),
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

// ─────────────────────────────────────────────────────────────────────────────
// PostgresStore::update — owner gate
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn postgres_update_owner_match_succeeds() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:1412-alice-update-match";
    let ctx = CallerContext::for_agent(alice);
    let mem = seed_mem_owned_by(alice, "ns-1412-um", "owner-match-update");
    let inserted_id = store.store(&ctx, &mem).await.expect("seed insert");

    let patch = UpdatePatch {
        content: Some("rewritten by owner".to_string()),
        ..Default::default()
    };
    store
        .update(&ctx, &inserted_id, patch)
        .await
        .expect("owner-match update must succeed");
}

#[tokio::test]
async fn postgres_update_owner_mismatch_returns_permission_denied() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:1412-alice-update-mismatch";
    let bob = "ai:1412-bob-update-hijack";
    let mem = seed_mem_owned_by(alice, "ns-1412-umm", "owner-mismatch-update");
    let inserted_id = store
        .store(&CallerContext::for_agent(alice), &mem)
        .await
        .expect("seed insert");

    let patch = UpdatePatch {
        content: Some("hijacked content".to_string()),
        ..Default::default()
    };
    let err = store
        .update(&CallerContext::for_agent(bob), &inserted_id, patch)
        .await
        .expect_err("owner-mismatch update must error");
    match err {
        StoreError::PermissionDenied {
            action,
            target,
            reason,
        } => {
            assert_eq!(action, "update", "action carries op name; got: {action:?}");
            assert_eq!(target, inserted_id, "target is the row id");
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
}

#[tokio::test]
async fn postgres_update_missing_row_returns_not_found() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:1412-update-notfound");
    let bogus_id = uuid::Uuid::new_v4().to_string();
    let patch = UpdatePatch::default();
    let err = store
        .update(&ctx, &bogus_id, patch)
        .await
        .expect_err("missing row must error");
    match err {
        StoreError::NotFound { id } => assert_eq!(id, bogus_id),
        other => panic!("expected NotFound, got: {other:?}"),
    }
}

#[tokio::test]
async fn postgres_update_admin_bypass_skips_owner_gate() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:1412-alice-admin-bypass";
    let mem = seed_mem_owned_by(alice, "ns-1412-uab", "admin-bypass-update");
    let inserted_id = store
        .store(&CallerContext::for_agent(alice), &mem)
        .await
        .expect("seed insert");

    // Admin context (bypass_visibility = true) — agent_id != alice
    // but the gate is short-circuited.
    let admin = CallerContext::for_admin("operator:migrate");
    let patch = UpdatePatch {
        content: Some("admin rewrite".to_string()),
        ..Default::default()
    };
    store
        .update(&admin, &inserted_id, patch)
        .await
        .expect("admin bypass must skip the owner gate");
}

// ─────────────────────────────────────────────────────────────────────────────
// PostgresStore::delete — owner gate
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn postgres_delete_owner_match_succeeds() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:1412-alice-delete-match";
    let ctx = CallerContext::for_agent(alice);
    let mem = seed_mem_owned_by(alice, "ns-1412-dm", "owner-match-delete");
    let inserted_id = store.store(&ctx, &mem).await.expect("seed insert");
    store
        .delete(&ctx, &inserted_id)
        .await
        .expect("owner-match delete must succeed");
}

#[tokio::test]
async fn postgres_delete_owner_mismatch_returns_permission_denied() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:1412-alice-delete-mismatch";
    let bob = "ai:1412-bob-delete-hijack";
    let mem = seed_mem_owned_by(alice, "ns-1412-dmm", "owner-mismatch-delete");
    let inserted_id = store
        .store(&CallerContext::for_agent(alice), &mem)
        .await
        .expect("seed insert");
    let err = store
        .delete(&CallerContext::for_agent(bob), &inserted_id)
        .await
        .expect_err("owner-mismatch delete must error");
    match err {
        StoreError::PermissionDenied {
            action,
            target,
            reason,
        } => {
            assert_eq!(action, "delete");
            assert_eq!(target, inserted_id);
            assert!(reason.contains(bob) && reason.contains(alice), "{reason}");
        }
        other => panic!("expected PermissionDenied, got: {other:?}"),
    }
}

#[tokio::test]
async fn postgres_delete_missing_row_returns_not_found() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:1412-delete-notfound");
    let bogus_id = uuid::Uuid::new_v4().to_string();
    let err = store
        .delete(&ctx, &bogus_id)
        .await
        .expect_err("missing row must error");
    match err {
        StoreError::NotFound { id } => assert_eq!(id, bogus_id),
        other => panic!("expected NotFound, got: {other:?}"),
    }
}

#[tokio::test]
async fn postgres_delete_admin_bypass_skips_owner_gate() {
    let Some(store) = maybe_open().await else {
        return;
    };
    let alice = "ai:1412-alice-admin-bypass-delete";
    let mem = seed_mem_owned_by(alice, "ns-1412-dab", "admin-bypass-delete");
    let inserted_id = store
        .store(&CallerContext::for_agent(alice), &mem)
        .await
        .expect("seed insert");
    let admin = CallerContext::for_admin("operator:gc-sweep");
    store
        .delete(&admin, &inserted_id)
        .await
        .expect("admin bypass must skip the owner gate");
}
