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
use ai_memory::storage::BindApiKeyOutcome;
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
    assert_eq!(
        store
            .bind_agent_api_key(&ctx, &target, &digest)
            .await
            .expect("bind_agent_api_key"),
        BindApiKeyOutcome::Bound
    );
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

// ---------------------------------------------------------------------------
// v1.0.0 #3529 (#3474 advisory A1) — the last-key rule is enforced by the
// STORE, atomically, on both backends.
// ---------------------------------------------------------------------------

/// Empty the enrolled-key registry so the registry-GLOBAL "would this be the
/// last key" rule can be exercised at all.
///
/// The rule is deployment-wide by construction — an empty registry makes the
/// identity gate inert in EVERY mode (#1985), which is why it is gated — so
/// there is no per-agent scope to isolate on. This is safe here because the
/// only database these tests ever reach is a throwaway sqlite file or the
/// dedicated `AI_MEMORY_TEST_POSTGRES_URL` test tier, and the rows are
/// ephemeral digests of test tokens that nothing can recover or needs to.
async fn clear_all_enrolled(store: &Arc<dyn MemoryStore>) {
    let ctx = CallerContext::for_agent("ai:k3529-cleaner".to_string());
    let enrolled = store
        .list_agent_api_keys()
        .await
        .expect("list_agent_api_keys");
    let mut agents: Vec<String> = enrolled.into_iter().map(|(_, agent)| agent).collect();
    agents.sort_unstable();
    agents.dedup();
    for agent in agents {
        store
            .revoke_agent_api_key(&ctx, &agent)
            .await
            .expect("clear enrolled key");
    }
    assert!(
        store
            .list_agent_api_keys()
            .await
            .expect("list after clear")
            .is_empty(),
        "the registry must be empty before the last-key rule can be exercised"
    );
}

/// The #3474 A1 interleaving, PROVOKED rather than raced.
///
/// The handler's decision is a pure function of the enrolled snapshot
/// (`revoke_requires_approval`), so the schedule where two concurrent
/// self-revokes both slip through is exactly: compute BOTH decisions from the
/// same snapshot — in which each holder can see the other's key — and then run
/// both applies. That is what this does, with no sleeps and no timing bet.
///
/// Before #3529 both applies succeeded and the registry ended EMPTY. Now the
/// store counts and deletes in one transaction, so the second one is refused
/// with nothing removed.
async fn revoke_unless_last_atomicity_parity(store: &Arc<dyn MemoryStore>, suffix: &str) {
    use ai_memory::handlers::agent_api_key::{
        revoke_requires_approval, revoke_would_empty_registry,
    };
    use ai_memory::storage::RevokeUnlessLastOutcome;

    clear_all_enrolled(store).await;

    let a = format!("ai:k3529-holder-a-{suffix}");
    let b = format!("ai:k3529-holder-b-{suffix}");
    let c = format!("ai:k3529-holder-c-{suffix}");
    let ctx_a = CallerContext::for_agent(a.clone());
    let ctx_b = CallerContext::for_agent(b.clone());
    let ctx_c = CallerContext::for_agent(c.clone());

    let digest_a = api_key_sha256_hex(&format!("token-a-{suffix}"));
    let digest_b = api_key_sha256_hex(&format!("token-b-{suffix}"));
    assert_eq!(
        store
            .bind_agent_api_key(&ctx_a, &a, &digest_a)
            .await
            .expect("bind a"),
        BindApiKeyOutcome::Bound
    );
    assert_eq!(
        store
            .bind_agent_api_key(&ctx_b, &b, &digest_b)
            .await
            .expect("bind b"),
        BindApiKeyOutcome::Bound
    );

    // The ONE snapshot both in-flight requests observe. Each holder sees the
    // other's key, so each pre-check says "apply immediately" — the exact
    // state in which the pre-#3529 code emptied the registry.
    let snapshot = store
        .list_agent_api_keys()
        .await
        .expect("list_agent_api_keys");
    assert_eq!(snapshot.len(), 2, "the last TWO key-holders: {snapshot:?}");
    let count_of = |agent: &str| {
        snapshot
            .iter()
            .filter(|(_, id)| id.as_str() == agent)
            .count()
    };
    assert_eq!(
        revoke_requires_approval(&a, &a, snapshot.len(), count_of(&a), false),
        None,
        "A's pre-check must legitimately conclude it is not the last key"
    );
    assert_eq!(
        revoke_requires_approval(&b, &b, snapshot.len(), count_of(&b), false),
        None,
        "B's pre-check must legitimately conclude it is not the last key"
    );
    assert!(!revoke_would_empty_registry(snapshot.len(), count_of(&a)));

    // Both applies now run. The FIRST wins…
    match store
        .revoke_agent_api_key_unless_last(&ctx_a, &a)
        .await
        .expect("A revoke")
    {
        RevokeUnlessLastOutcome::Revoked { bindings_removed } => {
            assert_eq!(bindings_removed, 1, "A held exactly one key");
        }
        other @ RevokeUnlessLastOutcome::WouldEmptyRegistry => {
            panic!("the first self-revoke must apply, got {other:?}")
        }
    }
    // …and the SECOND is refused by the atomic re-check, even though its
    // pre-check had already passed.
    match store
        .revoke_agent_api_key_unless_last(&ctx_b, &b)
        .await
        .expect("B revoke")
    {
        RevokeUnlessLastOutcome::WouldEmptyRegistry => {}
        other @ RevokeUnlessLastOutcome::Revoked { .. } => {
            panic!("the second self-revoke must be refused, got {other:?}")
        }
    }

    // The load-bearing assertion: exactly ONE key survives, and it is B's.
    let after = store
        .list_agent_api_keys()
        .await
        .expect("list after the race");
    assert_eq!(
        after.len(),
        1,
        "the registry must never be emptied by two concurrent self-revokes: {after:?}"
    );
    assert_eq!(
        store
            .agent_id_for_api_key(&digest_b)
            .await
            .expect("resolve B"),
        Some(b.clone()),
        "the refused revoke must leave B's key live"
    );
    assert_eq!(
        store
            .agent_id_for_api_key(&digest_a)
            .await
            .expect("resolve A"),
        None,
        "the applied revoke must have removed A's key"
    );

    // ALLOWED — with another holder present the same call revokes, so the
    // refusal above is the control and not a broken seam.
    let digest_c = api_key_sha256_hex(&format!("token-c-{suffix}"));
    assert_eq!(
        store
            .bind_agent_api_key(&ctx_c, &c, &digest_c)
            .await
            .expect("bind c"),
        BindApiKeyOutcome::Bound
    );
    match store
        .revoke_agent_api_key_unless_last(&ctx_b, &b)
        .await
        .expect("B revoke with C enrolled")
    {
        RevokeUnlessLastOutcome::Revoked { bindings_removed } => {
            assert_eq!(bindings_removed, 1);
        }
        other @ RevokeUnlessLastOutcome::WouldEmptyRegistry => {
            panic!("a revoke that leaves C enrolled must apply, got {other:?}")
        }
    }

    // An agent with NO keys is an idempotent no-op, NOT a refusal — the two
    // zero-row cases must never be conflated, because answering "revoked" for
    // a credential that is still live is a wrong answer.
    match store
        .revoke_agent_api_key_unless_last(&ctx_a, &a)
        .await
        .expect("A revoke with no keys")
    {
        RevokeUnlessLastOutcome::Revoked { bindings_removed } => {
            assert_eq!(bindings_removed, 0, "no rows to remove");
        }
        other @ RevokeUnlessLastOutcome::WouldEmptyRegistry => {
            panic!("a no-op revoke must not be a refusal, got {other:?}")
        }
    }

    // C now holds every enrolled key: refused, and nothing is removed.
    match store
        .revoke_agent_api_key_unless_last(&ctx_c, &c)
        .await
        .expect("C revoke")
    {
        RevokeUnlessLastOutcome::WouldEmptyRegistry => {}
        other @ RevokeUnlessLastOutcome::Revoked { .. } => {
            panic!("the last holder's revoke must be refused, got {other:?}")
        }
    }
    assert_eq!(
        store
            .agent_id_for_api_key(&digest_c)
            .await
            .expect("resolve C"),
        Some(c.clone()),
        "a refused revoke removes nothing"
    );

    // The UNGUARDED seam still exists and still empties the registry — that is
    // what an approval which DISCLOSED `empties_registry` authorises, and
    // keeping it separate is why the guarded one can refuse.
    assert_eq!(
        store
            .revoke_agent_api_key(&ctx_c, &c)
            .await
            .expect("unguarded revoke"),
        1
    );
    assert!(
        store
            .list_agent_api_keys()
            .await
            .expect("list after the approved emptying")
            .is_empty()
    );
}

#[tokio::test]
async fn sqlite_revoke_unless_last_atomicity_3529() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("revoke-unless-last.db");
    let _ = ai_memory::db::open(&db_path).expect("db::open (migrations)");
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    revoke_unless_last_atomicity_parity(&store, "lt").await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_revoke_unless_last_atomicity_3529() {
    let Some(url) = postgres_url() else {
        eprintln!(
            "skip postgres_revoke_unless_last_atomicity_3529: \
             AI_MEMORY_TEST_POSTGRES_URL / AI_MEMORY_TEST_PG_URL unset"
        );
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("PostgresStore::connect (the certified tier must be exercised, not skipped)");
    let store: Arc<dyn MemoryStore> = Arc::new(store);
    let suffix = format!("pg{}", uuid::Uuid::new_v4().simple());
    revoke_unless_last_atomicity_parity(&store, &suffix).await;
}

