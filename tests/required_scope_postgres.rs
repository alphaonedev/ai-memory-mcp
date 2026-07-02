// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1720 Workstream C — postgres twin of the sqlite `required_scope`
//! (refuse-only) governance-gate tests.
//!
//! Mirrors `src/mcp/tools/store/tests.rs::required_scope_*` against the
//! `PostgresStore::enforce_governance_action` Store path. A namespace
//! standard pins `metadata.governance.required_scope`; a `Store` whose
//! effective `metadata.scope` (absent ⇒ private) does not match is
//! REFUSED at the gate (the gate never mutates the write). Matching and
//! absent-scope writes are allowed.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset.
//! Forces `PermissionsMode::Enforce` (the gate is Advisory-allow by
//! default).
//!
//! ## How to run
//!
//! ```sh
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://…@<host>:5432/aimemory_test \
//!   AI_MEMORY_NO_CONFIG=1 \
//!   cargo test --features sal,sal-postgres --test required_scope_postgres
//! ```

#![cfg(feature = "sal-postgres")]

use ai_memory::models::GovernanceDecision;
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{GovernedAction, MemoryStore};
use sqlx::PgPool;

mod common;
use common::postgres_url;

fn unique_suffix() -> String {
    uuid::Uuid::new_v4().to_string()[..8].to_string()
}

/// Seed a namespace standard whose `metadata.governance` carries the
/// supplied policy blob + register it in `namespace_meta`.
async fn seed_standard(pool: &PgPool, namespace: &str, owner: &str, policy: serde_json::Value) {
    let standard_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let metadata = serde_json::json!({
        "agent_id": owner,
        "governance": policy,
    });
    sqlx::query(
        "INSERT INTO memories (
            id, tier, namespace, title, content, tags, priority, confidence,
            source, access_count, created_at, updated_at, metadata
        ) VALUES ($1, 'long', $2, $3, 'standard', '[]'::jsonb, 5, 1.0,
                  'test', 0, $4, $4, $5)",
    )
    .bind(&standard_id)
    .bind(namespace)
    .bind(format!("standard:{namespace}"))
    .bind(now)
    .bind(&metadata)
    .execute(pool)
    .await
    .expect("seed standard memory");

    sqlx::query(
        "INSERT INTO namespace_meta (namespace, standard_id, parent_namespace) \
         VALUES ($1, $2, NULL) \
         ON CONFLICT (namespace) DO UPDATE SET standard_id = EXCLUDED.standard_id",
    )
    .bind(namespace)
    .bind(&standard_id)
    .execute(pool)
    .await
    .expect("seed namespace_meta");
}

async fn cleanup(pool: &PgPool, prefix: &str) {
    let _ = sqlx::query("DELETE FROM namespace_meta WHERE namespace LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM memories WHERE namespace LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(pool)
        .await;
}

/// A `required_scope: private` policy with `write: any`, so the
/// write-level decision is `Allow` and the scope mismatch is the sole
/// refusal trigger — the postgres twin of the sqlite test's policy.
fn private_scope_policy() -> serde_json::Value {
    serde_json::json!({
        "write": "any",
        "promote": "any",
        "delete": "any",
        "required_scope": "private",
    })
}

#[tokio::test]
async fn required_scope_refuses_mismatched_store_pg() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    let store = PostgresStore::connect(&url).await.expect("connect");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("test-side pool");

    let suffix = unique_suffix();
    let ns_prefix = format!("reqscope-mismatch-{suffix}");
    let ns = ns_prefix.clone();
    let owner = format!("ai:reqscope-owner-{suffix}");

    seed_standard(&pool, &ns, &owner, private_scope_policy()).await;

    // Write declares scope=collective into a private-required namespace.
    let payload = serde_json::json!({ "metadata": { "scope": "collective" } });
    let decision = store
        .enforce_governance_action(
            GovernedAction::Store,
            &ns,
            &owner,
            None,
            None,
            &payload,
            None,
        )
        .await
        .expect("enforce_governance_action");
    match decision {
        GovernanceDecision::Deny(refusal) => {
            assert!(
                refusal.reason.contains("requires scope 'private'")
                    && refusal.reason.contains("collective"),
                "unexpected refusal reason: {}",
                refusal.reason
            );
        }
        other => panic!("expected Deny for scope mismatch; got {other:?}"),
    }

    cleanup(&pool, &ns_prefix).await;
}

#[tokio::test]
async fn required_scope_allows_matching_and_absent_store_pg() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    let store = PostgresStore::connect(&url).await.expect("connect");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("test-side pool");

    let suffix = unique_suffix();
    let ns_prefix = format!("reqscope-allow-{suffix}");
    let ns = ns_prefix.clone();
    let owner = format!("ai:reqscope-owner-{suffix}");

    seed_standard(&pool, &ns, &owner, private_scope_policy()).await;

    // Matching scope=private ⇒ allowed.
    let matching = serde_json::json!({ "metadata": { "scope": "private" } });
    let decision = store
        .enforce_governance_action(
            GovernedAction::Store,
            &ns,
            &owner,
            None,
            None,
            &matching,
            None,
        )
        .await
        .expect("enforce_governance_action (matching)");
    assert!(
        matches!(decision, GovernanceDecision::Allow),
        "matching scope must be allowed; got {decision:?}"
    );

    // Absent scope ⇒ defaults to private ⇒ matches ⇒ allowed.
    let absent = serde_json::json!({ "metadata": {} });
    let decision = store
        .enforce_governance_action(
            GovernedAction::Store,
            &ns,
            &owner,
            None,
            None,
            &absent,
            None,
        )
        .await
        .expect("enforce_governance_action (absent)");
    assert!(
        matches!(decision, GovernanceDecision::Allow),
        "absent scope must default to private and be allowed; got {decision:?}"
    );

    cleanup(&pool, &ns_prefix).await;
}
