// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! Campaign P: exercise the production router, not a copy of its middleware.
//! Opt in with `cargo test --release --test overload_bounds -- --ignored`.

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tower::ServiceExt as _;

const CAP: usize = 4;
const CLIENTS: usize = 64;
const TIMEOUT: Duration = Duration::from_secs(5);
const WATCHDOG: Duration = Duration::from_secs(30);
const AGENT: &str = "ai:campaign-p-7028";

/// A body that signals actual handler entry, then waits for the router timeout.
struct SlowBody(Option<Arc<Semaphore>>);

impl futures_core::Stream for SlowBody {
    type Item = Result<axum::body::Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(entered) = self.0.take() {
            entered.add_permits(1);
        }
        Poll::Pending
    }
}

fn request(body: Body) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/recall")
        .header("content-type", "application/json")
        .header("x-agent-id", AGENT)
        .body(body)
        .expect("request")
}

#[tokio::test]
#[ignore = "explicit campaign P release-build gate"]
async fn bounded_admission_timeout_body_and_permit_recovery_7028() {
    tokio::time::timeout(WATCHDOG, exercise())
        .await
        .expect("campaign watchdog");
}

async fn exercise() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/overload");
    std::fs::create_dir_all(&root).expect("scratch root");
    let dir = tempfile::Builder::new()
        .prefix("bounds-")
        .tempdir_in(&root)
        .expect("scratch db");
    let app = sqlite_app_state(&dir.path().join("bounds.db"));
    // Production boot resolves AI_MEMORY_MAX_INFLIGHT_REQUESTS into this setter.
    // No process environment mutation in an async test (CONCURRENCY-20).
    ai_memory::set_max_inflight_requests(CAP);
    let router = ai_memory::build_router_with_timeout(ApiKeyState::default(), app, TIMEOUT);
    let entered = Arc::new(Semaphore::new(0));
    let before = ai_memory::metrics::registry().admission_shed_total.get();
    let mut admitted = tokio::task::JoinSet::new();
    for _ in 0..CAP {
        let app = router.clone();
        let body = Body::from_stream(SlowBody(Some(Arc::clone(&entered))));
        admitted.spawn(async move { app.oneshot(request(body)).await.expect("slow response") });
    }
    entered
        .acquire_many(u32::try_from(CAP).expect("small cap"))
        .await
        .expect("all four bodies entered")
        .forget();
    let mut excess = tokio::task::JoinSet::new();
    for _ in CAP..CLIENTS {
        let app = router.clone();
        excess.spawn(async move {
            app.oneshot(request(Body::from("{}")))
                .await
                .expect("excess")
        });
    }
    while let Some(response) = excess.join_next().await {
        let response = response.expect("join excess");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()["retry-after"], "1");
        let bytes = axum::body::to_bytes(response.into_body(), ai_memory::HTTP_BODY_LIMIT_BYTES)
            .await
            .expect("bounded refusal");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("refusal JSON");
        assert_eq!(body["code"], "OVERLOADED");
        assert_eq!(body["max_inflight"], CAP);
    }
    while let Some(response) = admitted.join_next().await {
        assert_eq!(
            response.expect("join admitted").status(),
            StatusCode::GATEWAY_TIMEOUT
        );
    }
    let after = ai_memory::metrics::registry().admission_shed_total.get();
    assert_eq!(
        after - before,
        u64::try_from(CLIENTS - CAP).expect("small count")
    );
    let probe = router
        .clone()
        .oneshot(request(Body::from(r#"{"context":"campaign probe"}"#)))
        .await
        .expect("post-burst probe");
    assert_eq!(
        probe.status(),
        StatusCode::OK,
        "non-exempt route recovers after timeouts"
    );
    let body = Body::from(" ".repeat(ai_memory::HTTP_BODY_LIMIT_BYTES + 1));
    let response = router
        .oneshot(request(body))
        .await
        .expect("body limit response");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        ai_memory::metrics::registry().admission_shed_total.get(),
        after
    );
}

#[cfg_attr(
    not(feature = "sal"),
    expect(
        clippy::needless_pass_by_value,
        reason = "`SalStore` is a ZST without `sal`, but under `sal` its inner \
                  `Arc<dyn MemoryStore>` is MOVED into the struct literal below; \
                  one signature keeps both feature legs building identically."
    )
)]
fn app_state_with(db: Db, backend: StorageBackend, store: SalStore) -> AppState {
    let _ = &store;
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
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
        #[cfg(feature = "sal")]
        store: store.0,
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

/// The SAL handle, present only under `feature = "sal"`. Wrapping it in a
/// newtype keeps `app_state_with`'s signature identical across feature legs
/// (the default-feature build has no `MemoryStore` trait at all).
#[cfg(feature = "sal")]
struct SalStore(Arc<dyn ai_memory::store::MemoryStore>);
#[cfg(not(feature = "sal"))]
struct SalStore(());

/// Build a sqlite-backed `AppState` over a real on-disk DB. Under `sal` the
/// `SqliteStore` is opened against the SAME file as `app.db`, so both views
/// see the same rows (exactly what `bootstrap_serve` does).
fn sqlite_app_state(path: &std::path::Path) -> AppState {
    let conn = ai_memory::db::open(path).expect("open sqlite fixture db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store = SalStore(Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.to_path_buf()).expect("open SqliteStore"),
    ));
    #[cfg(not(feature = "sal"))]
    let store = SalStore(());
    app_state_with(db, StorageBackend::Sqlite, store)
}
