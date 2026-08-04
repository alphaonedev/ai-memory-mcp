// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2711 (CWE-284, CB-7) — POSTGRES twin namespace-scope confinement for the
//! three `/sync/push` subcollections the postgres receive funnel
//! (`sync_push_via_store`) applied WITHOUT any namespace gate while the sqlite
//! twin gated them: `links[]` (#2489), `signals[]` (#2489), and
//! `action_transitions[]` (#2649).
//!
//! Each lane's confinement subject mirrors the sqlite twin exactly:
//!   * links  — BOTH endpoints' STORED namespaces (a claimed-only gate would let
//!     a `public/*`-scoped peer relate a `secure/ops` row by id).
//!   * signals — the signal's own claimed namespace.
//!   * `action_transitions` — the STORED action's namespace (never wire-claimed).
//!
//! These assert ROW STATE (the #2528 precedent), not just response counters: an
//! out-of-scope link/signal/transition must leave the store UNCHANGED, while the
//! in-scope control must land. A posture guard proves zero-config replication is
//! byte-identical to pre-#2711.
//!
//! Gated on `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL`; without
//! the env var every test prints a skip line and returns (the house pattern —
//! see `tests/federation_write_ns_scope_2447_pg.rs`). Every namespace / id /
//! peer-id is uuid-randomised so concurrent runs against the shared scratch DB
//! never collide, and no test asserts global-table emptiness.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

/// Serialises every test in this binary — they all mutate the process-global
/// federation env vars, and cargo runs `#[tokio::test]`s concurrently.
static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

async fn pg_router(url: &str) -> (axum::Router, Arc<dyn MemoryStore>) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(PostgresStore::connect(url).await.expect("connect postgres"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Postgres,
        store: store.clone(),
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), store)
}

/// Enrol `peer` scoped to `<public_ns_root>/*` ONLY — the issue's scenario.
/// `extra` lets a lane loosen a per-lane signature default (signals /
/// transitions) so the ns-scope gate is what's under test, not the sig gate.
fn set_scoped_posture(peer: &str, public_ns_root: &str, extra: &[(&str, &str)]) {
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            format!(
                r#"{{"{peer}":{{"allowed_namespaces":["{public_ns_root}/*"],"allowed_sender_agent_ids":["{peer}"]}}}}"#
            ),
        );
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
        for (k, v) in extra {
            std::env::set_var(k, v);
        }
    }
}

fn clear_posture() {
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
        std::env::remove_var(REQUIRE_ATTEST_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_SIGNAL_SIG_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_TRANSITION_SIG_ENV);
    }
}

async fn push(router: &axum::Router, peer: &str, body: &Value) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            peer,
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let _ = axum::body::to_bytes(resp.into_body(), 64 * 1024).await;
    status
}

/// Admin ctx — the TEST's own read/seed, so it observes/creates the true stored
/// state regardless of the #910 visibility filter.
fn admin_ctx() -> ai_memory::store::CallerContext {
    let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-2711-pg");
    ctx.bypass_visibility = true;
    ctx
}

/// Seed a memory row directly into the store (bypassing the receive gate) so a
/// link between two rows in an out-of-scope namespace has real endpoints.
async fn seed_memory(store: &Arc<dyn MemoryStore>, id: &str, namespace: &str) {
    let m = ai_memory::models::Memory {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: uniq("anchor"),
        content: "anchor row".to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-02T00:00:00+00:00".to_string(),
        metadata: json!({"agent_id": "ai:anchor-owner-2711"}),
        ..Default::default()
    };
    store
        .store(&admin_ctx(), &m)
        .await
        .expect("seed anchor row");
}

async fn seed_pending_action(store: &Arc<dyn MemoryStore>, id: &str, namespace: &str) {
    let action = ai_memory::models::Action {
        id: id.to_string(),
        namespace: namespace.to_string(),
        kind: "test".to_string(),
        state: ai_memory::models::ActionState::Pending,
        title: "tx".to_string(),
        payload: json!({}),
        priority: 5,
        agent_id: Some("ai:action-owner-2711".to_string()),
        claimed_by: None,
        vector_clock: json!({}),
        metadata: json!({}),
        created_at: 1_700_009_000,
        updated_at: 1_700_009_000,
    };
    store
        .action_create(&admin_ctx(), &action)
        .await
        .expect("seed pending action");
}

fn wire_link(src: &str, tgt: &str) -> Value {
    json!({
        "source_id": src,
        "target_id": tgt,
        "relation": "related_to",
        "created_at": chrono::Utc::now().to_rfc3339(),
        "signature": null,
        "observed_by": null,
        "valid_from": null,
        "valid_until": null,
        "attest_level": null,
    })
}

fn wire_signal(id: &str, namespace: &str, from_agent: &str) -> Value {
    let sig = ai_memory::models::Signal {
        id: id.to_string(),
        namespace: namespace.to_string(),
        from_agent: from_agent.to_string(),
        to_agent: None,
        subject: "confine-2711".to_string(),
        body: json!({"k": "v"}),
        signal_type: ai_memory::models::SignalType::Notify,
        in_reply_to: None,
        correlation_id: None,
        reference_ids: json!([]),
        created_at: 1_700_006_000,
        expires_at: None,
        delivered_at: None,
        read_at: None,
        acknowledged_at: None,
        signature: vec![],
        sender_pubkey: vec![],
    };
    serde_json::to_value(&sig).unwrap()
}

fn wire_unsigned_transition(action_id: &str, claimed_by: &str) -> Value {
    let op = ai_memory::federation::sync::ActionTransitionOp {
        action_id: action_id.to_string(),
        from_state: ai_memory::models::ActionState::Pending,
        to_state: ai_memory::models::ActionState::Claimed,
        claimed_by: Some(claimed_by.to_string()),
        vector_clock: json!({}),
        updated_at: 1_700_009_100,
        signature: vec![],
        signer_pubkey: vec![],
        nonce: vec![],
    };
    serde_json::to_value(&op).unwrap()
}

// ---------------------------------------------------------------------
// links[] — BOTH endpoints' STORED namespaces are the subject.
// ---------------------------------------------------------------------

#[tokio::test]
async fn federated_link_outside_peer_scope_refused_2711_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP federated_link_outside_peer_scope_refused_2711_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let peer = uniq("ai:evil");
    let public_root = uniq("public");
    let victim_ns = uniq("secure/ops");
    set_scoped_posture(&peer, &public_root, &[]);
    let (router, store) = pg_router(&url).await;

    // EXPLOIT: two anchors in a namespace OUTSIDE the peer's scope, then a link
    // between them. A claimed-only gate would let the `public/*` peer relate the
    // two `secure/ops` rows by id.
    let evil_src = uuid::Uuid::new_v4().to_string();
    let evil_tgt = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &evil_src, &victim_ns).await;
    seed_memory(&store, &evil_tgt, &victim_ns).await;
    let status = push(
        &router,
        &peer,
        &json!({
            "sender_agent_id": peer,
            "sender_clock": {"entries": {}},
            "memories": [],
            "links": [wire_link(&evil_src, &evil_tgt)],
            "dry_run": false,
        }),
    )
    .await;
    assert!(status.is_success(), "sync_push must not hard-error");
    let evil_links = store
        .get_links_for_anchor(&evil_src)
        .await
        .expect("get_links_for_anchor");
    assert!(
        evil_links.is_empty(),
        "#2711 (pg): a peer scoped to {public_root}/* must NOT link two {victim_ns} rows"
    );

    // CONTROL: two anchors INSIDE scope, link between them still lands.
    let ok_ns = format!("{public_root}/ok");
    let ok_src = uuid::Uuid::new_v4().to_string();
    let ok_tgt = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &ok_src, &ok_ns).await;
    seed_memory(&store, &ok_tgt, &ok_ns).await;
    let ok_status = push(
        &router,
        &peer,
        &json!({
            "sender_agent_id": peer,
            "sender_clock": {"entries": {}},
            "memories": [],
            "links": [wire_link(&ok_src, &ok_tgt)],
            "dry_run": false,
        }),
    )
    .await;
    assert!(ok_status.is_success());
    let ok_links = store
        .get_links_for_anchor(&ok_src)
        .await
        .expect("get_links_for_anchor");
    assert!(
        !ok_links.is_empty(),
        "#2711 (pg): an in-scope link must still be applied"
    );

    clear_posture();
}

// ---------------------------------------------------------------------
// signals[] — the signal's own claimed namespace is the subject.
// ---------------------------------------------------------------------

#[tokio::test]
async fn federated_signal_outside_peer_scope_refused_2711_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP federated_signal_outside_peer_scope_refused_2711_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let peer = uniq("ai:evil");
    let public_root = uniq("public");
    let victim_ns = uniq("secure/ops");
    // REQUIRE_SIGNAL_SIG=0 → unsigned self-relay applies (accept-and-flag), so
    // the ONLY thing that can refuse the exploit is the namespace-scope gate.
    set_scoped_posture(
        &peer,
        &public_root,
        &[(
            ai_memory::federation::receive_auth::REQUIRE_SIGNAL_SIG_ENV,
            "0",
        )],
    );
    let (router, store) = pg_router(&url).await;

    // EXPLOIT: a signal in a namespace OUTSIDE the peer's scope.
    let evil_id = uniq("sig-evil");
    let status = push(
        &router,
        &peer,
        &json!({
            "sender_agent_id": peer,
            "sender_clock": {"entries": {}},
            "memories": [],
            "signals": [wire_signal(&evil_id, &victim_ns, &peer)],
            "dry_run": false,
        }),
    )
    .await;
    assert!(status.is_success());
    assert!(
        store
            .signal_get(&admin_ctx(), &evil_id)
            .await
            .expect("signal_get")
            .is_none(),
        "#2711 (pg): a peer scoped to {public_root}/* must NOT write a signal in {victim_ns}"
    );

    // CONTROL: a signal INSIDE scope still lands.
    let ok_ns = format!("{public_root}/ok");
    let ok_id = uniq("sig-ok");
    let ok_status = push(
        &router,
        &peer,
        &json!({
            "sender_agent_id": peer,
            "sender_clock": {"entries": {}},
            "memories": [],
            "signals": [wire_signal(&ok_id, &ok_ns, &peer)],
            "dry_run": false,
        }),
    )
    .await;
    assert!(ok_status.is_success());
    assert!(
        store
            .signal_get(&admin_ctx(), &ok_id)
            .await
            .expect("signal_get")
            .is_some(),
        "#2711 (pg): an in-scope signal must still be applied"
    );

    clear_posture();
}

// ---------------------------------------------------------------------
// action_transitions[] — the STORED action's namespace is the subject.
// ---------------------------------------------------------------------

#[tokio::test]
async fn federated_action_transition_outside_peer_scope_refused_2711_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP federated_action_transition_outside_peer_scope_refused_2711_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let peer = uniq("ai:evil");
    let public_root = uniq("public");
    let victim_ns = uniq("secure/ops");
    // REQUIRE_TRANSITION_SIG=0 → an unsigned transition applies under the
    // heterogeneous-rollout posture, so the ONLY refusal source for the exploit
    // is the namespace-scope gate (not the authority-lane signature gate).
    set_scoped_posture(
        &peer,
        &public_root,
        &[(
            ai_memory::federation::receive_auth::REQUIRE_TRANSITION_SIG_ENV,
            "0",
        )],
    );
    let (router, store) = pg_router(&url).await;

    // EXPLOIT: transition a STORED action whose namespace is out of scope.
    let evil_action = uniq("act-evil");
    seed_pending_action(&store, &evil_action, &victim_ns).await;
    let status = push(
        &router,
        &peer,
        &json!({
            "sender_agent_id": peer,
            "sender_clock": {"entries": {}},
            "memories": [],
            "action_transitions": [wire_unsigned_transition(&evil_action, &peer)],
            "dry_run": false,
        }),
    )
    .await;
    assert!(status.is_success());
    let evil_got = store
        .action_get(&admin_ctx(), &evil_action)
        .await
        .expect("action_get")
        .expect("action present");
    assert_eq!(
        evil_got.state,
        ai_memory::models::ActionState::Pending,
        "#2711 (pg): a peer scoped to {public_root}/* must NOT transition a {victim_ns} action"
    );

    // CONTROL: an in-scope action transitions.
    let ok_ns = format!("{public_root}/ok");
    let ok_action = uniq("act-ok");
    seed_pending_action(&store, &ok_action, &ok_ns).await;
    let ok_status = push(
        &router,
        &peer,
        &json!({
            "sender_agent_id": peer,
            "sender_clock": {"entries": {}},
            "memories": [],
            "action_transitions": [wire_unsigned_transition(&ok_action, &peer)],
            "dry_run": false,
        }),
    )
    .await;
    assert!(ok_status.is_success());
    let ok_got = store
        .action_get(&admin_ctx(), &ok_action)
        .await
        .expect("action_get")
        .expect("action present");
    assert_eq!(
        ok_got.state,
        ai_memory::models::ActionState::Claimed,
        "#2711 (pg): an in-scope action transition must still be applied"
    );

    clear_posture();
}

// ---------------------------------------------------------------------
// Posture guard — zero-config replication must be unchanged on pg too.
// ---------------------------------------------------------------------

#[tokio::test]
async fn zero_config_confinement_lanes_still_apply_2711_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP zero_config_confinement_lanes_still_apply_2711_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let peer = uniq("ai:zeroconf");
    let ns = uniq("secure/ops");
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::set_var(
            ai_memory::federation::receive_auth::REQUIRE_SIGNAL_SIG_ENV,
            "0",
        );
        std::env::set_var(
            ai_memory::federation::receive_auth::REQUIRE_TRANSITION_SIG_ENV,
            "0",
        );
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
    let (router, store) = pg_router(&url).await;

    // link between two rows in secure/ops
    let src = uuid::Uuid::new_v4().to_string();
    let tgt = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &src, &ns).await;
    seed_memory(&store, &tgt, &ns).await;
    // action in secure/ops
    let action = uniq("act-zc");
    seed_pending_action(&store, &action, &ns).await;
    // signal in secure/ops
    let sig_id = uniq("sig-zc");

    let status = push(
        &router,
        &peer,
        &json!({
            "sender_agent_id": peer,
            "sender_clock": {"entries": {}},
            "memories": [],
            "links": [wire_link(&src, &tgt)],
            "signals": [wire_signal(&sig_id, &ns, &peer)],
            "action_transitions": [wire_unsigned_transition(&action, &peer)],
            "dry_run": false,
        }),
    )
    .await;
    assert!(status.is_success());

    assert!(
        !store
            .get_links_for_anchor(&src)
            .await
            .expect("get_links_for_anchor")
            .is_empty(),
        "#2711 (pg): zero-config link replication must be byte-identical to pre-fix"
    );
    assert!(
        store
            .signal_get(&admin_ctx(), &sig_id)
            .await
            .expect("signal_get")
            .is_some(),
        "#2711 (pg): zero-config signal replication must be byte-identical to pre-fix"
    );
    assert_eq!(
        store
            .action_get(&admin_ctx(), &action)
            .await
            .expect("action_get")
            .expect("action present")
            .state,
        ai_memory::models::ActionState::Claimed,
        "#2711 (pg): zero-config transition replication must be byte-identical to pre-fix"
    );

    clear_posture();
}
