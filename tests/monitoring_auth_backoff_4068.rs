// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4068 — the authenticated monitoring routes must share the #2502
//! per-source auth-failure backoff.
//!
//! `handlers::monitoring::access` (the outermost HTTP gate) authenticates
//! `/api/v1/monitoring/{status,metrics}` itself, and the transport gate
//! `api_key_auth` exempts those paths, so before the fix a monitoring
//! credential failure was never counted and a source already in backoff on
//! ordinary routes was still admitted on monitoring. The same gate also
//! answers `401 unresolved_transport_principal` for an uncredentialed request
//! to an ordinary route once health-only scopes are configured, and that
//! failure was not counted either.
//!
//! Every cell drives the PRODUCTION router (`ai_memory::build_router`) with
//! TLS-enabled monitoring and a `ConnectInfo<SocketAddr>` peer in the request
//! extensions, exactly where the listener puts it. The backoff window is the
//! policy's 1 s base step, so consecutive requests land inside it.

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::auth_backoff::{AUTH_BACKOFF_ERROR, FREE_FAILURES};
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::monitoring::{METRICS_PATH, MonitoringConfig, STATUS_PATH};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

/// Health-only enrolled monitoring principal.
const MONITOR: &str = "ai:monitor-4068";
/// Obviously fake placeholder credentials.
const MONITOR_TOKEN: &str = "pw-placeholder-monitor-4068";
const SHARED_KEY: &str = "pw-placeholder-shared-4068";
const WRONG_KEY: &str = "pw-placeholder-wrong-4068";

fn sqlite_app_state(path: &std::path::Path) -> AppState {
    let conn = ai_memory::db::open(path).expect("open sqlite fixture db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
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
        storage_backend: StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store: Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(path.to_path_buf())
                .expect("open SqliteStore"),
        ),
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
        enrolled_agent_keys: Arc::new(EnrolledAgentKeys::empty()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

/// The production router: TLS-enabled monitoring, one health-only enrolled
/// principal, and (when `shared`) a distinct shared transport key.
fn router(dir: &tempfile::TempDir, shared: bool) -> axum::Router {
    let mut app = sqlite_app_state(&dir.path().join("monitoring-4068.db"));
    let registry = Arc::new(
        EnrolledAgentKeys::from_map(
            [(api_key_sha256_hex(MONITOR_TOKEN), MONITOR.to_owned())]
                .into_iter()
                .collect(),
        )
        .with_monitoring(
            MonitoringConfig {
                agent_ids: vec![MONITOR.to_owned()],
                peer_ids: Vec::new(),
            },
            true,
        ),
    );
    app.enrolled_agent_keys = Arc::clone(&registry);
    let auth = ApiKeyState {
        key: shared.then(|| SHARED_KEY.to_owned()),
        mtls_enforced: false,
        enrolled_agent_keys: registry,
        identity_mode: ai_memory::config::HttpIdentityMode::Off,
        ..Default::default()
    };
    ai_memory::build_router(auth, app)
}

struct Outcome {
    status: StatusCode,
    retry_after: Option<String>,
    body: String,
}

async fn send(router: &axum::Router, ip: IpAddr, path: &str, key: Option<&str>) -> Outcome {
    let mut builder = Request::builder()
        .uri(path)
        .method("GET")
        .header("x-forwarded-proto", "https");
    if let Some(k) = key {
        builder = builder.header(ai_memory::HEADER_API_KEY, k);
    }
    let mut req = builder.body(Body::empty()).expect("request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip, 40_068)));
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("body");
    Outcome {
        status,
        retry_after,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn ip(n: u8) -> IpAddr {
    IpAddr::from([10, 40, 68, n])
}

fn assert_backoff(out: &Outcome, what: &str) {
    assert_eq!(
        out.status,
        StatusCode::TOO_MANY_REQUESTS,
        "#4068: {what} must be refused with 429 while the source is in backoff; body={}",
        out.body
    );
    assert!(
        out.retry_after.is_some(),
        "#4068: {what}: a 429 must carry Retry-After"
    );
    assert!(
        out.body.contains(AUTH_BACKOFF_ERROR),
        "#4068: {what}: the 429 body must be the shared closed vocabulary; body={}",
        out.body
    );
}

/// Failed monitoring credentials are counted on BOTH monitoring routes: after
/// `FREE_FAILURES` wrong keys the next attempt is 429, and a correct
/// credential inside the window is refused too (not a key oracle). Covered
/// for the shared key and the enrolled per-agent key.
#[tokio::test]
async fn monitoring_failures_earn_backoff_on_both_routes_4068() {
    let dir = tempfile::tempdir().expect("tempdir");
    let router = router(&dir, true);
    for (n, path, good) in [
        (1, STATUS_PATH, SHARED_KEY),
        (2, METRICS_PATH, SHARED_KEY),
        (3, STATUS_PATH, MONITOR_TOKEN),
        (4, METRICS_PATH, MONITOR_TOKEN),
    ] {
        let source = ip(n);
        for i in 0..FREE_FAILURES {
            let out = send(&router, source, path, Some(WRONG_KEY)).await;
            assert_eq!(
                out.status,
                StatusCode::UNAUTHORIZED,
                "failure {i} on {path} stays 401; body={}",
                out.body
            );
        }
        let out = send(&router, source, path, Some(WRONG_KEY)).await;
        assert_backoff(&out, &format!("wrong key #{} on {path}", FREE_FAILURES + 1));
        let out = send(&router, source, path, Some(good)).await;
        assert_backoff(&out, &format!("a CORRECT key on {path} during backoff"));
    }
}

/// Backoff earned on an ordinary authenticated route carries over to the
/// monitoring routes (one table, one predicate).
#[tokio::test]
async fn backoff_from_an_ordinary_route_is_honoured_on_monitoring_4068() {
    let dir = tempfile::tempdir().expect("tempdir");
    let router = router(&dir, true);
    let source = ip(5);
    for _ in 0..=FREE_FAILURES {
        send(
            &router,
            source,
            ai_memory::handlers::routes::MEMORIES,
            Some(WRONG_KEY),
        )
        .await;
    }
    for path in [STATUS_PATH, METRICS_PATH] {
        let out = send(&router, source, path, Some(SHARED_KEY)).await;
        assert_backoff(
            &out,
            &format!("monitoring {path} after ordinary-route backoff"),
        );
    }
}

/// With health-only scopes configured and NO shared key, the monitoring gate
/// itself answers `401 unresolved_transport_principal` for an ordinary route;
/// those failures count too, and the earned backoff covers monitoring.
#[tokio::test]
async fn unresolved_principal_failures_are_counted_4068() {
    let dir = tempfile::tempdir().expect("tempdir");
    let router = router(&dir, false);
    let source = ip(6);
    for _ in 0..FREE_FAILURES {
        let out = send(
            &router,
            source,
            ai_memory::handlers::routes::MEMORIES,
            Some(WRONG_KEY),
        )
        .await;
        assert_eq!(out.status, StatusCode::UNAUTHORIZED, "body={}", out.body);
    }
    let out = send(
        &router,
        source,
        ai_memory::handlers::routes::MEMORIES,
        Some(WRONG_KEY),
    )
    .await;
    assert_backoff(&out, "unresolved-principal failure past the budget");
    let out = send(&router, source, STATUS_PATH, Some(MONITOR_TOKEN)).await;
    assert_backoff(
        &out,
        "a correct monitoring key after unresolved-principal backoff",
    );
}

/// Controls: a success resets the source's budget, other sources are not
/// affected, and the public `/api/v1/health` liveness probe stays exempt for
/// a backed-off source.
#[tokio::test]
async fn success_resets_and_liveness_stays_exempt_4068() {
    let dir = tempfile::tempdir().expect("tempdir");
    let router = router(&dir, true);
    let source = ip(7);
    for _ in 0..FREE_FAILURES - 1 {
        send(&router, source, STATUS_PATH, Some(WRONG_KEY)).await;
    }
    let out = send(&router, source, STATUS_PATH, Some(MONITOR_TOKEN)).await;
    assert_eq!(out.status, StatusCode::OK, "body={}", out.body);
    for i in 0..FREE_FAILURES {
        let out = send(&router, source, STATUS_PATH, Some(WRONG_KEY)).await;
        assert_eq!(
            out.status,
            StatusCode::UNAUTHORIZED,
            "a success must restart the budget (failure {i} after reset); body={}",
            out.body
        );
    }
    let out = send(&router, source, STATUS_PATH, Some(WRONG_KEY)).await;
    assert_backoff(&out, "the budget after reset is exhausted");

    let other = send(&router, ip(8), STATUS_PATH, Some(MONITOR_TOKEN)).await;
    assert_eq!(other.status, StatusCode::OK, "another source is unaffected");

    let live = send(&router, source, ai_memory::handlers::routes::HEALTH, None).await;
    assert_eq!(
        live.status,
        StatusCode::OK,
        "the public liveness probe stays exempt for a backed-off source; body={}",
        live.body
    );
}
