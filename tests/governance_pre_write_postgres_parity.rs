// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! ARCH-1 (CRITICAL) regression — `GOVERNANCE_PRE_WRITE` pre-write
//! hook parity between the `SQLite` and Postgres SAL adapters.
//!
//! Pre-fix: the substrate pre-write hook
//! ([`ai_memory::storage::GOVERNANCE_PRE_WRITE`]) was consulted ONLY
//! by the legacy `crate::storage::insert*` free-functions (the `SQLite`
//! path). The sqlx-native [`PostgresStore::store`],
//! [`PostgresStore::store_with_embedding`], and
//! [`PostgresStore::apply_remote_memory`] paths bypassed the hook
//! entirely — multi-tenant cloud + postgres-backed daemons would
//! silently accept memories that the operator's signed governance
//! rules refuse on the `SQLite` path. A substrate-level bypass.
//!
//! Post-fix: each of the three postgres write paths consults the same
//! hook via the `consult_governance_pre_write_pg` adapter helper that
//! maps a refusal to [`StoreError::PermissionDenied`] (the closest
//! typed variant — surfaces as `403 FORBIDDEN` via
//! `store_err_to_response`).
//!
//! ## Test architecture
//!
//! Each `#[tokio::test]` here lives in this dedicated integration-
//! test binary so it gets its own process, its own `OnceLock` slot
//! for `GOVERNANCE_PRE_WRITE`, and can install a fresh hook without
//! coordinating with `governance_storage_insert_hook.rs` (which holds
//! the `SQLite`-path mirror tests). The hook closure records every
//! dispatch in a process-wide `AtomicU64` so the test can assert
//! the hook fired exactly once per write path.
//!
//! ## Gating
//!
//! `#[ignore]` on `AI_MEMORY_TEST_POSTGRES_URL` per the project
//! convention for postgres-store tests — Track C blocker, issue #79.
//! Operators with a reachable test postgres flip the env var and
//! run `cargo test --features sal-postgres --test
//! governance_pre_write_postgres_parity -- --ignored`.

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::needless_update,
    clippy::doc_markdown
)]

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::storage::GOVERNANCE_PRE_WRITE;
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, StoreError};
use serde_json::json;

// ---------------------------------------------------------------------------
// Process-wide hook dispatcher (OnceLock workaround — same pattern as
// `tests/governance_storage_insert_hook.rs`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum HookVerdict {
    Allow,
    Refuse(String),
}

static HOOK_VERDICT: OnceLock<std::sync::Mutex<HookVerdict>> = OnceLock::new();
static HOOK_FIRE_COUNT: OnceLock<AtomicU64> = OnceLock::new();

fn verdict_slot() -> &'static std::sync::Mutex<HookVerdict> {
    HOOK_VERDICT.get_or_init(|| std::sync::Mutex::new(HookVerdict::Allow))
}

fn fire_count() -> &'static AtomicU64 {
    HOOK_FIRE_COUNT.get_or_init(|| AtomicU64::new(0))
}

/// Serialise the in-process tests so the shared verdict slot is not
/// raced across the parallel tokio test executor. Each test grabs the
/// guard at entry and holds it for the duration of its scenario.
/// Uses [`tokio::sync::Mutex`] (NOT `std::sync::Mutex`) because the
/// guard must be held across `.await` points — postgres calls run
/// inside the tokio executor and a `std::sync::Mutex` guard held
/// across `await` deadlocks the runtime and trips
/// `clippy::await_holding_lock`.
fn test_serial() -> &'static tokio::sync::Mutex<()> {
    static M: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    M.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Install the dispatcher hook exactly once. Idempotent — subsequent
/// calls observe the OnceLock-already-set state and proceed; the
/// dispatcher closure picks up the per-test verdict via
/// `verdict_slot()`.
fn ensure_hook_installed() {
    let _ = GOVERNANCE_PRE_WRITE.set(Box::new(|_mem: &Memory| {
        fire_count().fetch_add(1, Ordering::SeqCst);
        let guard = verdict_slot().lock().expect("verdict mutex poisoned");
        match &*guard {
            HookVerdict::Allow => Ok(()),
            HookVerdict::Refuse(reason) => Err(reason.clone()),
        }
    }));
}

fn set_verdict(v: HookVerdict) {
    *verdict_slot().lock().expect("verdict mutex poisoned") = v;
}

fn reset_fire_count() -> u64 {
    fire_count().swap(0, Ordering::SeqCst)
}

async fn live_pg() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!(
                "skipping postgres pre-write parity verify: PostgresStore::connect failed: {e}\n\
                 (test-infra blocker per issue #79 — 192.168.50.100 ↔ 192.168.1.50 routing)"
            );
            None
        }
    }
}

fn sample_memory(id: &str, namespace: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("title-{id}"),
        content: "ARCH-1 postgres pre-write parity body".to_string(),
        tags: vec!["arch-1".to_string()],
        priority: 5,
        confidence: 0.7,
        source: "arch-1-test".to_string(),
        access_count: 0,
        created_at: "2026-05-26T10:00:00Z".to_string(),
        updated_at: "2026-05-26T10:00:00Z".to_string(),
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "ai:arch-1-test"}),
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
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// ARCH-1 pin: `PostgresStore::store` fires the
/// `GOVERNANCE_PRE_WRITE` hook with the memory payload AND the row
/// lands on the Allow verdict.
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
async fn postgres_store_fires_governance_pre_write_hook_on_allow() {
    let _g = test_serial().lock().await;
    let Some(pg) = live_pg().await else {
        return;
    };
    ensure_hook_installed();
    set_verdict(HookVerdict::Allow);
    let _ = reset_fire_count();

    let ctx = CallerContext::for_admin("arch-1-postgres-store-allow");
    let mem = sample_memory("arch-1-pg-store-allow", "arch-1-pg-store");
    let id = pg
        .store(&ctx, &mem)
        .await
        .expect("Allow verdict must let PostgresStore::store succeed");
    assert_eq!(id, mem.id, "store returns the inserted id");

    let fires = fire_count().load(Ordering::SeqCst);
    assert!(
        fires >= 1,
        "GOVERNANCE_PRE_WRITE hook MUST fire on PostgresStore::store \
         (ARCH-1 substrate parity); observed {fires} dispatches"
    );

    let _ = MemoryStore::delete(&pg, &ctx, &mem.id).await;
}

/// ARCH-1 pin: `PostgresStore::store` consults the hook and a Refuse
/// verdict short-circuits the write — the row MUST NOT land.
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
async fn postgres_store_refusal_blocks_insert() {
    let _g = test_serial().lock().await;
    let Some(pg) = live_pg().await else {
        return;
    };
    ensure_hook_installed();
    set_verdict(HookVerdict::Refuse("ARCH-1 deny-all".to_string()));
    let _ = reset_fire_count();

    let ctx = CallerContext::for_admin("arch-1-postgres-store-refuse");
    let mem = sample_memory("arch-1-pg-store-refuse", "arch-1-pg-store-refuse-ns");

    let err = pg
        .store(&ctx, &mem)
        .await
        .expect_err("Refuse verdict MUST surface as a typed error");

    // The refusal MUST map to PermissionDenied (403 via store_err_to_response).
    match &err {
        StoreError::PermissionDenied { reason, .. } => {
            assert!(
                reason.contains("ARCH-1 deny-all"),
                "operator-authored reason must propagate verbatim; got {reason:?}"
            );
        }
        other => panic!(
            "expected StoreError::PermissionDenied carrying the operator-authored \
             reason; got {other:?}"
        ),
    }

    let fires = fire_count().load(Ordering::SeqCst);
    assert!(
        fires >= 1,
        "GOVERNANCE_PRE_WRITE hook MUST fire even on the refusal path; \
         observed {fires} dispatches"
    );

    // Verify no row landed.
    match MemoryStore::get(&pg, &ctx, &mem.id).await {
        Err(StoreError::NotFound { .. }) => { /* expected — refused write left no row */ }
        Ok(_) => panic!(
            "ARCH-1 BYPASS DETECTED: PostgresStore::store wrote a row \
             despite the GOVERNANCE_PRE_WRITE hook refusing"
        ),
        Err(other) => panic!("unexpected error reading back refused row: {other:?}"),
    }

    // Reset verdict so any subsequent test in the same process starts clean.
    set_verdict(HookVerdict::Allow);
}

/// ARCH-1 pin: `PostgresStore::store_with_embedding` (semantic-recall
/// write path) also consults the hook. Without this, an operator-
/// signed refuse rule could be bypassed by routing through the
/// embedded-vector path.
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
async fn postgres_store_with_embedding_fires_hook_and_refuses() {
    let _g = test_serial().lock().await;
    let Some(pg) = live_pg().await else {
        return;
    };
    ensure_hook_installed();
    set_verdict(HookVerdict::Refuse("ARCH-1 embed deny".to_string()));
    let _ = reset_fire_count();

    let ctx = CallerContext::for_admin("arch-1-postgres-embed-refuse");
    let mem = sample_memory("arch-1-pg-embed-refuse", "arch-1-pg-embed-ns");
    let embedding: Vec<f32> = vec![0.1; 384];

    let err = pg
        .store_with_embedding(&ctx, &mem, Some(&embedding))
        .await
        .expect_err("Refuse verdict MUST surface on the embed write path");

    match &err {
        StoreError::PermissionDenied { reason, .. } => {
            assert!(
                reason.contains("ARCH-1 embed deny"),
                "reason must carry the operator-authored refusal text; got {reason:?}"
            );
        }
        other => panic!("expected PermissionDenied; got {other:?}"),
    }

    let fires = fire_count().load(Ordering::SeqCst);
    assert!(
        fires >= 1,
        "hook MUST fire on store_with_embedding; observed {fires}"
    );

    // No row landed.
    match MemoryStore::get(&pg, &ctx, &mem.id).await {
        Err(StoreError::NotFound { .. }) => { /* expected */ }
        Ok(_) => panic!("ARCH-1 BYPASS: store_with_embedding wrote a row despite refusal"),
        Err(other) => panic!("unexpected error: {other:?}"),
    }

    set_verdict(HookVerdict::Allow);
}

/// ARCH-1 pin: `PostgresStore::apply_remote_memory` (federation
/// receive path) consults the hook. Federation-pushed memories must
/// clear the same pre-write hook as locally-authored writes;
/// otherwise a peer could push rows that the local operator's signed
/// governance rules refuse on the local path.
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
async fn postgres_apply_remote_memory_fires_hook_and_refuses() {
    let _g = test_serial().lock().await;
    let Some(pg) = live_pg().await else {
        return;
    };
    ensure_hook_installed();
    set_verdict(HookVerdict::Refuse("ARCH-1 federation deny".to_string()));
    let _ = reset_fire_count();

    let ctx = CallerContext::for_admin("arch-1-postgres-federation-refuse");
    let mem = sample_memory("arch-1-pg-fed-refuse", "arch-1-pg-fed-ns");

    let err = pg
        .apply_remote_memory(&ctx, &mem)
        .await
        .expect_err("Refuse verdict MUST surface on the federation receive path");

    match &err {
        StoreError::PermissionDenied { reason, .. } => {
            assert!(
                reason.contains("ARCH-1 federation deny"),
                "reason must carry the refusal text; got {reason:?}"
            );
        }
        other => panic!("expected PermissionDenied; got {other:?}"),
    }

    let fires = fire_count().load(Ordering::SeqCst);
    assert!(
        fires >= 1,
        "hook MUST fire on apply_remote_memory; observed {fires}"
    );

    match MemoryStore::get(&pg, &ctx, &mem.id).await {
        Err(StoreError::NotFound { .. }) => { /* expected */ }
        Ok(_) => panic!("ARCH-1 BYPASS: apply_remote_memory wrote a row despite refusal"),
        Err(other) => panic!("unexpected error: {other:?}"),
    }

    set_verdict(HookVerdict::Allow);
}
