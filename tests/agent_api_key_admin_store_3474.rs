// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal")]
// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

//! v1.0.0 #3474 — the STORE-BACKED half of the admin api-key enrolment
//! surface: BOTH backends must behave identically, because the certified tier
//! is postgres and #3418's own report was that enrolment there was
//! unreachable.
//!
//! `agent_api_key_admin_route_3474.rs` drives the HTTP surface on sqlite.
//! This binary drives the SAL seam that surface sits on, once per adapter,
//! from ONE backend-agnostic body — a parity claim proved by two hand-written
//! tests survives only until someone edits one of them.
//!
//! What it pins, per backend:
//!
//! * ALLOWED — `queue_pending_action` parks a row the approval flow can find
//!   (`get_pending` returns it `pending`, with OUR payload intact), and a
//!   DIFFERENT registered approver transitions it to `approved`;
//! * DENIED — the REQUESTER cannot approve their own row (the two-person
//!   rule), and an UNREGISTERED approver cannot either;
//! * ALLOWED/DENIED — bind then revoke round-trips digest-keyed, and the raw
//!   token never reaches the store.
//!
//! Sqlite always runs. Postgres runs when `AI_MEMORY_TEST_POSTGRES_URL` is set
//! (falling back to `AI_MEMORY_TEST_PG_URL`).

use std::sync::Arc;

use ai_memory::handlers::agent_api_key::{
    IDENTITY_NAMESPACE, OP_REVOKE, PENDING_PAYLOAD_KIND, key_fingerprint,
};
use ai_memory::handlers::identity_binding::api_key_sha256_hex;
use ai_memory::models::AgentRegistration;
use ai_memory::store::{ApproveOutcome, CallerContext, GovernedAction, MemoryStore};
use serde_json::json;

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .or_else(|| std::env::var("AI_MEMORY_TEST_PG_URL").ok())
        .filter(|u| !u.trim().is_empty())
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

async fn register(store: &Arc<dyn MemoryStore>, agent_id: &str) {
    let ctx = CallerContext::for_admin(ai_memory::identity::sentinels::DAEMON_PRINCIPAL);
    store
        .register_agent(
            &ctx,
            &AgentRegistration {
                agent_id: agent_id.to_string(),
                agent_type: "human".to_string(),
                capabilities: Vec::new(),
                registered_at: now_rfc3339(),
                last_seen_at: now_rfc3339(),
            },
        )
        .await
        .expect("register_agent");
}

/// The whole enrolment + approval seam, backend-agnostic.
///
/// `suffix` keeps concurrent runs against the SHARED postgres test cluster
/// from colliding on agent ids or revoking each other's bindings.
async fn admin_api_key_seam_parity(store: &Arc<dyn MemoryStore>, suffix: &str) {
    let requester = format!("ai:k3474-requester-{suffix}");
    let approver = format!("ai:k3474-approver-{suffix}");
    let stranger = format!("ai:k3474-stranger-{suffix}");
    let target = format!("ai:k3474-target-{suffix}");
    let ctx = CallerContext::for_agent(requester.clone());

    register(store, &requester).await;
    register(store, &approver).await;

    // --- bind / resolve / revoke, digest-keyed ---------------------------
    let token = format!("minted-token-{suffix}");
    let digest = api_key_sha256_hex(&token);
    store
        .bind_agent_api_key(&ctx, &target, &digest)
        .await
        .expect("bind_agent_api_key");
    assert_eq!(
        store
            .agent_id_for_api_key(&digest)
            .await
            .expect("resolve by digest"),
        Some(target.clone()),
        "the binding must resolve by the SAME digest the mint stored"
    );
    assert!(
        store
            .agent_id_for_api_key(&api_key_sha256_hex("some-other-token"))
            .await
            .expect("resolve unknown")
            .is_none()
    );
    let listed = store
        .list_agent_api_keys()
        .await
        .expect("list_agent_api_keys");
    assert!(
        listed.iter().any(|(d, a)| d == &digest && a == &target),
        "the enrolled pair must appear in the registry seed"
    );
    assert!(
        listed.iter().all(|(d, _)| d != &token),
        "the RAW token must never be a stored key"
    );

    // --- queue a revoke approval ------------------------------------------
    let payload = json!({
        "kind": PENDING_PAYLOAD_KIND,
        "op": OP_REVOKE,
        "target_agent_id": target,
        "reason": "another_principal",
        "key_fingerprint": key_fingerprint(&digest),
    });
    let pending_id = store
        .queue_pending_action(
            &ctx,
            GovernedAction::Delete,
            IDENTITY_NAMESPACE,
            None,
            &requester,
            &payload,
        )
        .await
        .expect("queue_pending_action");
    let row = store
        .get_pending(&ctx, &pending_id)
        .await
        .expect("get_pending")
        .expect("the queued row must be readable");
    assert_eq!(row.status, "pending");
    assert_eq!(row.requested_by, requester);
    assert_eq!(row.namespace, IDENTITY_NAMESPACE);
    assert_eq!(row.memory_id, None, "an identity action names no memory");
    assert_eq!(row.payload["kind"], PENDING_PAYLOAD_KIND);
    assert_eq!(row.payload["op"], OP_REVOKE);
    assert_eq!(row.payload["target_agent_id"], target.as_str());
    assert!(
        !row.payload.to_string().contains(&token),
        "a queued approval must carry the DIGEST, never the token"
    );

    // --- DENIED: the requester cannot approve their own action ------------
    match store
        .governance_approve_with_consensus(&ctx, &pending_id, &requester)
        .await
        .expect("self-approval call")
    {
        ApproveOutcome::Rejected(reason) => {
            assert!(!reason.is_empty(), "a refusal must say why: {reason}");
        }
        other => panic!("self-approval must be refused, got {other:?}"),
    }
    assert_eq!(
        store
            .get_pending(&ctx, &pending_id)
            .await
            .expect("get_pending")
            .expect("row")
            .status,
        "pending",
        "a refused approval must leave the row untouched"
    );

    // --- DENIED: an UNREGISTERED approver cannot approve either -----------
    match store
        .governance_approve_with_consensus(&ctx, &pending_id, &stranger)
        .await
        .expect("stranger approval call")
    {
        ApproveOutcome::Rejected(_) => {}
        other => panic!("an unregistered approver must be refused, got {other:?}"),
    }
    assert_eq!(
        store
            .get_pending(&ctx, &pending_id)
            .await
            .expect("get_pending")
            .expect("row")
            .status,
        "pending"
    );

    // --- ALLOWED: a DIFFERENT registered approver transitions it ----------
    match store
        .governance_approve_with_consensus(&ctx, &pending_id, &approver)
        .await
        .expect("approver call")
    {
        ApproveOutcome::Approved => {}
        other => panic!("a registered second approver must approve, got {other:?}"),
    }
    let decided = store
        .get_pending(&ctx, &pending_id)
        .await
        .expect("get_pending")
        .expect("row");
    assert_eq!(decided.status, "approved");
    assert_eq!(decided.decided_by.as_deref(), Some(approver.as_str()));

    // --- the revoke the approval authorises actually revokes --------------
    let removed = store
        .revoke_agent_api_key(&ctx, &target)
        .await
        .expect("revoke_agent_api_key");
    assert!(removed >= 1);
    assert!(
        store
            .agent_id_for_api_key(&digest)
            .await
            .expect("resolve after revoke")
            .is_none(),
        "a revoked binding must not resolve"
    );
}

#[tokio::test]
async fn sqlite_admin_api_key_seam_parity_3474() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("api-key-seam.db");
    let _ = ai_memory::db::open(&db_path).expect("db::open (migrations)");
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    admin_api_key_seam_parity(&store, "lt").await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_admin_api_key_seam_parity_3474() {
    let Some(url) = postgres_url() else {
        eprintln!(
            "skip postgres_admin_api_key_seam_parity_3474: \
             AI_MEMORY_TEST_POSTGRES_URL / AI_MEMORY_TEST_PG_URL unset"
        );
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("PostgresStore::connect (the certified tier must be exercised, not skipped)");
    let store: Arc<dyn MemoryStore> = Arc::new(store);
    let suffix = format!("pg{}", uuid::Uuid::new_v4().simple());
    admin_api_key_seam_parity(&store, &suffix).await;
}

/// Keep `postgres_url` referenced on a `sal`-only build so the helper cannot
/// silently rot out of the postgres leg.
#[test]
fn postgres_url_helper_is_reachable_3474() {
    let _ = postgres_url();
}
