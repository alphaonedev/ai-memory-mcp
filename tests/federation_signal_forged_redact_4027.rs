// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4027 — the federation `/sync/push` `signals[]` lane must refuse a
//! present-but-INVALID (forged) wire signature BEFORE the #3049 receive-side
//! secret screen runs, on BOTH backends.
//!
//! The screen clears `signature` / `sender_pubkey` whenever it redacts a
//! signed field (`subject` / `body`), because the redacted bytes no longer
//! match the attestation. Pre-fix, the postgres funnel only checked the wire
//! signature AFTER that screen (inside `MemoryStore::apply_remote_signal`),
//! and that check only fires on a NON-empty signature — so with the
//! staged-rollout opt-out `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG=0` a forged signal
//! whose signed field tripped the screen was laundered into an accepted
//! "unsigned" one. The sqlite funnel refused it (forged check first). This
//! suite pins the shared contract: forged ⇒ refused and nothing stored;
//! genuinely unsigned ⇒ accepted under the opt-out; validly signed ⇒ accepted
//! (redacted, attestation dropped).
//!
//! Dedicated binary: `secret_screen::SCREEN_MODE` is a process-wide
//! `OnceLock`; this file is its only setter. The postgres cells are gated on
//! `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL` (skip line
//! otherwise — the house pattern).

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::receive_auth::{
    REQUIRE_PUSH_NAMESPACE_SCOPE_ENV, REQUIRE_SIGNAL_SIG_ENV,
};
use ai_memory::federation::signing::REQUIRE_SIG_ENV;
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{Signal, SignalType};
use ai_memory::secret_screen::{REDACTION_PLACEHOLDER, SecretScreenMode, set_screen_mode};

/// Canonical AWS access-key fixture the detector is pinned on.
const AWS_AKIA_FIXTURE: &str = "AKIAIOSFODNN7EXAMPLE";
const PEER: &str = "ai:peer-4027";

/// Serialises the cells: they mutate process-global federation env vars.
static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

fn seed_screen_mode() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| set_screen_mode(SecretScreenMode::Refuse));
}

/// The #4027 posture: the per-signal signature requirement is OFF (the
/// documented staged-rollout opt-out), everything orthogonal is relaxed so the
/// forged-signature disposition is the only gate under test.
fn set_posture() {
    unsafe {
        std::env::set_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV, "0");
        std::env::set_var(REQUIRE_SIG_ENV, "0");
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
        std::env::set_var(REQUIRE_SIGNAL_SIG_ENV, "0");
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
}

fn clear_posture() {
    unsafe {
        std::env::remove_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
        std::env::remove_var(REQUIRE_SIG_ENV);
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        std::env::remove_var(REQUIRE_SIGNAL_SIG_ENV);
    }
}

fn app_state(
    db: Db,
    backend: StorageBackend,
    store: Arc<dyn ai_memory::store::MemoryStore>,
) -> AppState {
    AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

fn router_for(state: AppState) -> axum::Router {
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, state)
}

fn sqlite_router() -> (axum::Router, Arc<dyn ai_memory::store::MemoryStore>) {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    std::mem::forget(db_tmp);
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    (
        router_for(app_state(db, StorageBackend::Sqlite, store.clone())),
        store,
    )
}

#[cfg(feature = "sal-postgres")]
async fn pg_router(url: &str) -> (axum::Router, Arc<dyn ai_memory::store::MemoryStore>) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(url)
            .await
            .expect("connect postgres"),
    );
    (
        router_for(app_state(db, StorageBackend::Postgres, store.clone())),
        store,
    )
}

fn admin_ctx() -> ai_memory::store::CallerContext {
    let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-4027");
    ctx.bypass_visibility = true;
    ctx
}

fn make_signal(namespace: &str, subject: &str) -> Signal {
    Signal {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: namespace.to_string(),
        from_agent: PEER.to_string(),
        to_agent: None,
        subject: subject.to_string(),
        body: json!({"note": "4027"}),
        signal_type: SignalType::Notify,
        in_reply_to: None,
        correlation_id: None,
        reference_ids: json!([]),
        created_at: 1_700_000_000,
        expires_at: None,
        delivered_at: None,
        read_at: None,
        acknowledged_at: None,
        signature: Vec::new(),
        sender_pubkey: Vec::new(),
    }
}

async fn push(router: &axum::Router, signals: &[Signal]) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": PEER,
        "sender_clock": {"entries": {}},
        "memories": [],
        "signals": signals,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            PEER,
        )
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The shared cell body — identical assertions on both backends.
async fn run_cell(
    backend: &str,
    router: &axum::Router,
    store: &Arc<dyn ai_memory::store::MemoryStore>,
) {
    let ns = format!("ns-4027-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let secret_subject = format!("deploy key {AWS_AKIA_FIXTURE}");
    let kp = ai_memory::identity::keypair::generate(PEER).expect("keypair");

    // FORGED: a present-but-invalid signature over a signed field the screen
    // will redact.
    let mut forged = make_signal(&ns, &secret_subject);
    forged.signature = vec![0u8; 64];
    forged.sender_pubkey = kp.public.to_bytes().to_vec();
    // FORGED (no key): a signature with an empty `sender_pubkey` never verifies
    // and is refused as forged on the sqlite twin too.
    let mut forged_nokey = make_signal(&ns, &secret_subject);
    forged_nokey.signature = vec![7u8; 64];
    // CONTROL: genuinely unsigned (accepted under the opt-out, redacted).
    let unsigned = make_signal(&ns, &secret_subject);
    // CONTROL: validly signed, then redacted (attestation dropped).
    let mut signed = make_signal(&ns, &secret_subject);
    ai_memory::signals::sign_into(&mut signed, &kp).expect("sign");
    assert!(ai_memory::signals::verify(&signed), "control must verify");

    let (status, _) = push(
        router,
        &[
            forged.clone(),
            forged_nokey.clone(),
            unsigned.clone(),
            signed.clone(),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{backend}: push status");

    let ctx = admin_ctx();
    for (label, sig) in [("forged", &forged), ("forged-nokey", &forged_nokey)] {
        let got = store.signal_get(&ctx, &sig.id).await.expect("signal_get");
        assert!(
            got.is_none(),
            "#4027 ({backend}): a {label} signal whose signed field was redacted \
             must be REFUSED, not laundered into an accepted unsigned signal; stored: {got:?}"
        );
    }
    for (label, sig) in [("unsigned", &unsigned), ("signed", &signed)] {
        let got = store
            .signal_get(&ctx, &sig.id)
            .await
            .expect("signal_get")
            .unwrap_or_else(|| panic!("#4027 ({backend}): {label} control must be applied"));
        assert!(
            got.subject.contains(REDACTION_PLACEHOLDER) && !got.subject.contains(AWS_AKIA_FIXTURE),
            "#4027 ({backend}): {label} control must be stored REDACTED: {:?}",
            got.subject
        );
        assert!(
            got.signature.is_empty(),
            "#4027 ({backend}): {label} control carries no stale attestation"
        );
    }
}

#[tokio::test]
async fn forged_signal_refused_before_screen_sqlite_4027() {
    let _g = FED_ENV_LOCK.lock().await;
    seed_screen_mode();
    set_posture();
    let (router, store) = sqlite_router();
    run_cell("sqlite", &router, &store).await;
    clear_posture();
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn forged_signal_refused_before_screen_pg_4027() {
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!(
            "SKIP forged_signal_refused_before_screen_pg_4027: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    seed_screen_mode();
    set_posture();
    let (router, store) = pg_router(&url).await;
    run_cell("postgres", &router, &store).await;
    clear_posture();
}
