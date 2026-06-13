// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Coverage agent cov4 — live-Postgres integration coverage for the
//! `PostgresStore` SAL adapter governance / agent-registry / quota /
//! namespace-standard / lifecycle surfaces (`src/store/postgres.rs`).
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset.
//! Per-run uuid ids keep the suite rerunnable against a persistent DB.

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::uninlined_format_args
)]

use ai_memory::models::{AgentRegistration, ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, Filter, GovernedAction, MemoryStore};

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

async fn connect() -> Option<PostgresStore> {
    let url = postgres_url()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

fn mem(id: &str, ns: &str, title: &str, content: &str, owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["covtest".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "cov4-gov".to_string(),
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
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    }
}

// ───────────────────────────────────────────────────────────────────
// register_agent / is_registered_agent / list_agents /
// bind_agent_pubkey / agent_pubkey / revoke_agent_pubkey
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_registry_full_lifecycle() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let agent_id = uid("ai:cov4-agent");
    let reg = AgentRegistration {
        agent_id: agent_id.clone(),
        agent_type: "nhi".to_string(),
        capabilities: vec!["read".to_string(), "write".to_string()],
        registered_at: chrono::Utc::now().to_rfc3339(),
        last_seen_at: chrono::Utc::now().to_rfc3339(),
    };
    store.register_agent(&ctx, &reg).await.expect("register");
    assert!(
        store.is_registered_agent(&agent_id).await.expect("is_reg"),
        "agent must be registered"
    );
    let agents = store.list_agents().await.expect("list_agents");
    assert!(agents.iter().any(|a| a.agent_id == agent_id));

    // No key bound yet → agent_pubkey returns None.
    assert!(
        store
            .agent_pubkey(&agent_id)
            .await
            .expect("pubkey")
            .is_none(),
        "no key bound yet"
    );

    // Bind a key, read it back, then revoke.
    let pubkey_b64 = base64_pub();
    store
        .bind_agent_pubkey(&ctx, &agent_id, &pubkey_b64)
        .await
        .expect("bind_agent_pubkey");
    let got = store
        .agent_pubkey(&agent_id)
        .await
        .expect("pubkey after bind");
    assert_eq!(got.as_deref(), Some(pubkey_b64.as_str()));

    store
        .revoke_agent_pubkey(&ctx, &agent_id)
        .await
        .expect("revoke_agent_pubkey");
    assert!(
        store
            .agent_pubkey(&agent_id)
            .await
            .expect("pubkey after revoke")
            .is_none(),
        "key cleared after revoke"
    );
}

fn base64_pub() -> String {
    use base64::Engine;
    // 32-byte all-zero ed25519 pubkey is structurally a valid b64 blob;
    // the bind path stores it verbatim, the verify path is exercised
    // elsewhere. Use a deterministic 32-byte vector.
    let bytes = [7u8; 32];
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ───────────────────────────────────────────────────────────────────
// quota_status / quota_status_ns / quota_status_list /
// quota_status_list_ns
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn quota_status_surfaces_aggregate_and_per_ns() {
    let Some(store) = connect().await else {
        return;
    };
    let agent = uid("ai:cov4-quota");
    let ctx = CallerContext::for_agent(&agent);
    let ns = uid("cov-quota");
    // A store write increments the agent's quota counters (#1156 path).
    store
        .store(&ctx, &mem(&uid("q"), &ns, "quota mem", "body", &agent))
        .await
        .expect("store");

    let agg = store.quota_status(&agent).await.expect("quota_status");
    assert_eq!(agg.agent_id, agent);

    let per_ns = store
        .quota_status_ns(&agent, &ns)
        .await
        .expect("quota_status_ns");
    assert_eq!(per_ns.agent_id, agent);

    let list = store.quota_status_list().await.expect("quota_status_list");
    assert!(list.iter().any(|q| q.agent_id == agent));

    let list_ns = store
        .quota_status_list_ns(&ns)
        .await
        .expect("quota_status_list_ns");
    assert!(list_ns.iter().any(|q| q.agent_id == agent));
}

// ───────────────────────────────────────────────────────────────────
// namespace standards: set / get / clear + build_namespace_chain +
// resolve_governance_policy
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn namespace_standard_set_get_clear_and_chain() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_admin("ai:cov4");
    let ns = uid("cov-nsstd");
    // The standard must reference an existing memory.
    let std_id = uid("std");
    store
        .store(
            &ctx,
            &mem(&std_id, &ns, "standard memory", "policy body", "ai:cov4"),
        )
        .await
        .expect("store standard memory");

    store
        .set_namespace_standard(&ctx, &ns, &std_id, None)
        .await
        .expect("set_namespace_standard");

    let got = store
        .get_namespace_standard(&ctx, &ns)
        .await
        .expect("get_namespace_standard");
    assert_eq!(got.map(|(s, _)| s), Some(std_id.clone()));

    // build_namespace_chain always starts at the global "*".
    let chain = store
        .build_namespace_chain(&ns)
        .await
        .expect("build_namespace_chain");
    assert!(chain.iter().any(|c| c == "*"));

    // resolve_governance_policy walks the chain (may be None if the
    // standard carries no governance block, which is fine — the call
    // path is what we exercise).
    let _ = store
        .resolve_governance_policy(&ns)
        .await
        .expect("resolve_governance_policy");

    let cleared = store
        .clear_namespace_standard(&ctx, &ns)
        .await
        .expect("clear_namespace_standard");
    assert!(cleared, "existing standard row must be cleared");

    let cleared_again = store
        .clear_namespace_standard(&ctx, &ns)
        .await
        .expect("clear again");
    assert!(!cleared_again, "no row to clear the second time");
}

// ───────────────────────────────────────────────────────────────────
// enforce_governance_action — Allow default (ungated namespace)
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn enforce_governance_action_allows_ungated_namespace() {
    let Some(store) = connect().await else {
        return;
    };
    let ns = uid("cov-ungated");
    let agent = "ai:cov4";
    let payload = serde_json::json!({"title": "free write"});
    let decision = store
        .enforce_governance_action(GovernedAction::Store, &ns, agent, None, None, &payload)
        .await
        .expect("enforce_governance_action");
    assert!(matches!(
        decision,
        ai_memory::models::GovernanceDecision::Allow
    ));
}

// ───────────────────────────────────────────────────────────────────
// forget / consolidate / run_gc / archive_by_ids / list_archived /
// archive_restore / archive_purge
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn forget_deletes_matching_rows() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-forget");
    for i in 0..3 {
        store
            .store(
                &ctx,
                &mem(&uid("f"), &ns, &format!("forget {i}"), "body", "ai:cov4"),
            )
            .await
            .unwrap();
    }
    let deleted = store
        .forget(&ctx, Some(&ns), None, None, true)
        .await
        .expect("forget");
    assert_eq!(deleted, 3, "all rows in namespace forgotten");
}

#[tokio::test]
async fn consolidate_merges_sources() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-consol");
    let a = uid("ca");
    let b = uid("cb");
    store
        .store(&ctx, &mem(&a, &ns, "source a", "abody", "ai:cov4"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&b, &ns, "source b", "bbody", "ai:cov4"))
        .await
        .unwrap();
    let new_id = store
        .consolidate(
            &ctx,
            &[a.clone(), b.clone()],
            "consolidated",
            "merged summary of a and b",
            &ns,
            &Tier::Long,
            "cov4-consol",
            "ai:cov4",
        )
        .await
        .expect("consolidate");
    let got = store.get(&ctx, &new_id).await.expect("get consolidated");
    assert_eq!(got.title, "consolidated");
}

#[tokio::test]
async fn archive_by_ids_list_archived_and_restore() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-arch");
    let id = uid("arc");
    store
        .store(&ctx, &mem(&id, &ns, "archive me", "body", "ai:cov4"))
        .await
        .unwrap();
    let moved = store
        .archive_by_ids(&ctx, std::slice::from_ref(&id), Some("covtest"))
        .await
        .expect("archive_by_ids");
    assert_eq!(moved, 1);

    let archived = store
        .list_archived(Some(&ns), 50, 0)
        .await
        .expect("list_archived");
    assert!(!archived.is_empty(), "archived row must surface");

    let restored = store
        .archive_restore(&ctx, &id)
        .await
        .expect("archive_restore");
    assert!(restored, "row restored from archive");
    let got = store.get(&ctx, &id).await.expect("get restored");
    assert_eq!(got.title, "archive me");
}

#[tokio::test]
async fn run_gc_and_archive_purge_execute() {
    let Some(store) = connect().await else {
        return;
    };
    // run_gc + archive_purge issue store-wide DELETEs. Against a shared
    // persistent DB with other suites inserting concurrently, Postgres
    // can surface a transient `deadlock detected` (40P01) — a true
    // serialization transient, not a substrate defect (production GC
    // runs on its own schedule). Retry a few times so the SQL path is
    // exercised deterministically.
    retry_transient(|| store.run_gc(true))
        .await
        .expect("run_gc");
    let ctx = CallerContext::for_admin("ai:cov4");
    // archive_purge with a generous retention window is a safe no-op-ish
    // call that still exercises the SQL path.
    retry_transient(|| store.archive_purge(&ctx, Some(36500)))
        .await
        .expect("archive_purge");
}

/// Retry a store call up to 5 times on a transient backend error
/// (deadlock / serialization) that only manifests when a shared
/// persistent DB sees concurrent writers from sibling test binaries.
async fn retry_transient<T, Fut, F>(mut op: F) -> Result<T, ai_memory::store::StoreError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, ai_memory::store::StoreError>>,
{
    let mut last = op().await;
    for _ in 0..4 {
        match &last {
            Err(ai_memory::store::StoreError::BackendUnavailable { detail, .. })
                if detail.contains("deadlock") || detail.contains("serializ") =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                last = op().await;
            }
            _ => break,
        }
    }
    last
}

// ───────────────────────────────────────────────────────────────────
// list_namespaces / get_taxonomy / stats / health_check
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn read_surfaces_namespaces_taxonomy_stats_health() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-read");
    store
        .store(&ctx, &mem(&uid("r"), &ns, "read mem", "body", "ai:cov4"))
        .await
        .unwrap();

    assert!(store.health_check().await.expect("health_check"));
    let _ = store.stats().await.expect("stats");
    let nss = store.list_namespaces().await.expect("list_namespaces");
    assert!(nss.iter().any(|n| n.namespace == ns));
    let _ = store
        .get_taxonomy(Some(&ns), 5, 100)
        .await
        .expect("get_taxonomy");

    let filter = Filter {
        namespace: Some(ns.clone()),
        limit: 5,
        ..Filter::default()
    };
    let listed = store.list(&ctx, &filter).await.expect("list");
    assert_eq!(listed.len(), 1);
}

// ───────────────────────────────────────────────────────────────────
// find_by_title_namespace / next_versioned_title /
// find_contradictions
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn title_helpers_and_contradictions() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-title");
    let id = uid("t");
    let title = "distinctive title cov4";
    store
        .store(&ctx, &mem(&id, &ns, title, "body", "ai:cov4"))
        .await
        .unwrap();

    let found = store
        .find_by_title_namespace(title, &ns)
        .await
        .expect("find_by_title_namespace");
    assert_eq!(found.as_deref(), Some(id.as_str()));

    let missing = store
        .find_by_title_namespace("no such title", &ns)
        .await
        .expect("find missing");
    assert!(missing.is_none());

    // next_versioned_title appends a suffix on collision.
    let versioned = store
        .next_versioned_title(title, &ns)
        .await
        .expect("next_versioned_title");
    assert_ne!(versioned, title, "collision must produce a suffix");

    // A fresh title returns unchanged.
    let fresh = "unclaimed title cov4 unique";
    let same = store
        .next_versioned_title(fresh, &ns)
        .await
        .expect("next_versioned_title fresh");
    assert_eq!(same, fresh);

    let _ = store
        .find_contradictions(title, &ns)
        .await
        .expect("find_contradictions");
}
