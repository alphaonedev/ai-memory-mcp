// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal")]
// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

//! v1.0.0 #3418 — the STORE-BACKED half: a per-agent api-key enrolled through
//! the SAL reaches the live registry on BOTH backends, with no daemon restart.
//!
//! # What this pins that the in-memory suite cannot
//!
//! `agent_key_hot_enroll_3418.rs` pins the registry and the refresh funnel in
//! isolation. This binary closes the loop the issue is actually about: the
//! operator runs `agents bind-api-key` against the CONFIGURED data tier, and
//! the daemon's refresh observes it. Concretely, per backend:
//!
//! * ALLOWED — bind, `list_agent_api_keys`, feed the rows through
//!   [`apply_agent_key_refresh`], and the caller resolves to
//!   `KeyAuthenticated`; the daemon was never restarted and `AppState` was
//!   never rebuilt;
//! * DENIED — revoke, refresh again, and the SAME token stops authenticating.
//!   This is the security half: pre-#3418 a revoked key kept working until the
//!   next restart.
//!
//! Sqlite always runs. Postgres runs when `AI_MEMORY_TEST_POSTGRES_URL` is set
//! (falling back to `AI_MEMORY_TEST_PG_URL`) — that is the certified tier
//! #3418 reports as unreachable, so leaving it silently unexercised would
//! reproduce the defect in the test suite.

use std::sync::Arc;

use ai_memory::handlers::identity_binding::{
    AgentKeyRefresh, AuthLevel, EnrolledAgentKeys, api_key_sha256_hex, apply_agent_key_refresh,
    resolve_auth_level,
};
use ai_memory::store::{CallerContext, MemoryStore};
use axum::http::HeaderMap;

fn headers_with_key(token: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("x-api-key", token.parse().expect("header value"));
    h
}

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .or_else(|| std::env::var("AI_MEMORY_TEST_PG_URL").ok())
        .filter(|u| !u.trim().is_empty())
}

/// The whole enroll → refresh → revoke → refresh cycle, backend-agnostic.
///
/// Written once and driven with each adapter so the two backends cannot drift:
/// a parity claim proved by two hand-written tests is a parity claim that
/// survives only until someone edits one of them.
async fn enroll_and_revoke_reach_the_live_registry(store: &Arc<dyn MemoryStore>, agent: &str) {
    let token = format!("{agent}-hot-enroll-token");
    let digest = api_key_sha256_hex(&token);
    let headers = headers_with_key(&token);
    let ctx = CallerContext::for_admin(ai_memory::identity::sentinels::DAEMON_PRINCIPAL);

    // Start from the posture a daemon boots with when nothing is enrolled.
    let registry = EnrolledAgentKeys::empty();
    assert_eq!(
        resolve_auth_level(&registry, &headers, agent),
        AuthLevel::Claimed,
        "an empty registry leaves every caller merely claimed"
    );

    // --- ALLOWED: enroll, then let the refresh observe it. ----------------
    store
        .bind_agent_api_key(&ctx, agent, &digest)
        .await
        .expect("bind_agent_api_key");
    let rows = store.list_agent_api_keys().await.map_err(|e| e.to_string());
    let outcome = apply_agent_key_refresh(&registry, rows);
    assert!(
        matches!(outcome, AgentKeyRefresh::Installed(n) if n >= 1),
        "the refresh must install the freshly enrolled key, got {outcome:?}"
    );
    assert_eq!(
        resolve_auth_level(&registry, &headers, agent),
        AuthLevel::KeyAuthenticated,
        "the key enrolled a moment ago must authenticate with NO daemon restart"
    );

    // --- DENIED: revoke, then let the refresh observe THAT. ---------------
    let removed = store
        .revoke_agent_api_key(&ctx, agent)
        .await
        .expect("revoke_agent_api_key");
    assert!(removed >= 1, "the binding we just wrote must be removed");
    let rows = store.list_agent_api_keys().await.map_err(|e| e.to_string());
    let outcome = apply_agent_key_refresh(&registry, rows);
    assert!(
        matches!(outcome, AgentKeyRefresh::Installed(_)),
        "a revocation is a change the refresh must install, got {outcome:?}"
    );
    assert_eq!(
        resolve_auth_level(&registry, &headers, agent),
        AuthLevel::Claimed,
        "a REVOKED key must stop authenticating without a restart — a revocation \
         that waits for one is a credential the operator has been told is dead"
    );
}

#[tokio::test]
async fn sqlite_enrollment_and_revocation_reach_the_live_registry_3418() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("hot-enroll.db");
    let _ = ai_memory::db::open(&db_path).expect("db::open (migrations)");
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    enroll_and_revoke_reach_the_live_registry(&store, "alice-3418-lt").await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_enrollment_and_revocation_reach_the_live_registry_3418() {
    let Some(url) = postgres_url() else {
        eprintln!(
            "skip postgres_enrollment_and_revocation_reach_the_live_registry_3418: \
             AI_MEMORY_TEST_POSTGRES_URL / AI_MEMORY_TEST_PG_URL unset"
        );
        return;
    };
    let store = match ai_memory::store::postgres::PostgresStore::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            return;
        }
    };
    let store: Arc<dyn MemoryStore> = Arc::new(store);
    // A distinct agent id per backend keeps concurrent suite runs against the
    // shared test cluster from revoking each other's binding.
    enroll_and_revoke_reach_the_live_registry(&store, "alice-3418-pg").await;
}

/// Keep `postgres_url` referenced on a `sal`-only build so the helper cannot
/// silently rot out of the postgres leg.
#[test]
fn postgres_url_helper_is_reachable_3418() {
    let _ = postgres_url();
}
