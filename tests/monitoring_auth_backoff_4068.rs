// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4068 — the authenticated monitoring routes are metered by the SAME
//! per-source auth-failure backoff as every other authenticated route.
//!
//! `monitoring::access` (the outermost gate) authenticates
//! `/api/v1/monitoring/{status,metrics}` itself, and `api_key_auth` exempts
//! those paths. Before #4068 that second credential check neither consulted
//! nor updated `AuthFailurePolicy`: failed monitoring credentials were never
//! counted, and a source already backed off on ordinary routes was not
//! refused on monitoring — contradicting the shipped "one chokepoint, every
//! auth-failure site" contract. The same gate's `unresolved_transport_principal`
//! refusal (health-only scopes configured) was unmetered too.
//!
//! Driven through the PRODUCTION router with TLS-enabled monitoring and a
//! synthetic `ConnectInfo` peer, exactly where `axum::serve` puts it. Every
//! refusal pin has an allowed-path control.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::auth_backoff::{AUTH_BACKOFF_ERROR, FREE_FAILURES};
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::monitoring::{METRICS_PATH, MonitoringConfig, STATUS_PATH};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

const SHARED_KEY: &str = "4068-shared-transport-key";
const AGENT_TOKEN: &str = "4068-enrolled-agent-token";
const AGENT_ID: &str = "ai:agent-4068";
const MONITOR_TOKEN: &str = "4068-health-only-monitor-token";
const MONITOR_ID: &str = "ai:monitor-4068";
const WRONG_KEY: &str = "4068-wrong-key";
const ORDINARY: &str = "/api/v1/capabilities";

fn app_state(path: &std::path::Path, registry: Arc<EnrolledAgentKeys>) -> AppState {
    let conn = ai_memory::db::open(path).expect("open sqlite fixture db");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
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
        enrolled_agent_keys: registry,
        http_identity_mode: ai_memory::config::HttpIdentityMode::Off,
    }
}

struct Fixture {
    router: axum::Router,
    _dir: tempfile::TempDir,
}

/// Production router, TLS-enabled monitoring. `scoped` additionally assigns a
/// health-only monitor identity, which makes the outer gate require a
/// resolved transport principal on every non-probe route.
fn fixture(scoped: bool) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut keys = HashMap::new();
    keys.insert(api_key_sha256_hex(AGENT_TOKEN), AGENT_ID.to_string());
    keys.insert(api_key_sha256_hex(MONITOR_TOKEN), MONITOR_ID.to_string());
    let monitoring = if scoped {
        MonitoringConfig {
            agent_ids: vec![MONITOR_ID.to_string()],
            peer_ids: Vec::new(),
        }
    } else {
        MonitoringConfig::default()
    };
    let registry = Arc::new(EnrolledAgentKeys::from_map(keys).with_monitoring(monitoring, true));
    let app = app_state(&dir.path().join("m.db"), Arc::clone(&registry));
    let auth = ApiKeyState {
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: registry,
        identity_mode: ai_memory::config::HttpIdentityMode::Off,
        ..Default::default()
    };
    Fixture {
        router: ai_memory::build_router(auth, app),
        _dir: dir,
    }
}

struct Outcome {
    status: StatusCode,
    retry_after: Option<String>,
    body: String,
}

async fn attempt(router: &axum::Router, ip: IpAddr, path: &str, key: Option<&str>) -> Outcome {
    let mut builder = Request::builder()
        .method("GET")
        .uri(path)
        .header("x-forwarded-proto", "https");
    if let Some(k) = key {
        builder = builder.header(ai_memory::HEADER_API_KEY, k);
    }
    let mut req = builder.body(Body::empty()).expect("request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip, 45_068)));
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
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
        "{what}: {}",
        out.body
    );
    assert!(
        out.retry_after.is_some(),
        "{what}: 429 must carry Retry-After"
    );
    assert!(
        out.body.contains(AUTH_BACKOFF_ERROR),
        "{what}: closed-vocabulary backoff body, got {}",
        out.body
    );
}

/// Burn the free budget with wrong keys on `path`, pinning each to `401`.
async fn exhaust(router: &axum::Router, source: IpAddr, path: &str) {
    for i in 0..FREE_FAILURES {
        let out = attempt(router, source, path, Some(WRONG_KEY)).await;
        assert_eq!(
            out.status,
            StatusCode::UNAUTHORIZED,
            "failure {i} on {path} stays 401: {}",
            out.body
        );
    }
}

/// Both monitoring routes: wrong credentials are COUNTED, the next attempt is
/// `429` + `Retry-After`, and a CORRECT credential (shared or enrolled) in the
/// window is refused too — the refusal is not a key oracle.
#[tokio::test]
async fn monitoring_failures_are_counted_and_refused_4068() {
    for (n, path, good) in [
        (1, STATUS_PATH, SHARED_KEY),
        (2, METRICS_PATH, SHARED_KEY),
        (3, STATUS_PATH, AGENT_TOKEN),
        (4, METRICS_PATH, AGENT_TOKEN),
    ] {
        let fx = fixture(false);
        let source = ip(n);
        // Control first: the credential under test works from this source.
        let ok = attempt(&fx.router, source, path, Some(good)).await;
        assert_eq!(
            ok.status,
            StatusCode::OK,
            "{path} with a valid key: {}",
            ok.body
        );

        exhaust(&fx.router, source, path).await;
        let refused = attempt(&fx.router, source, path, Some(WRONG_KEY)).await;
        assert_backoff(&refused, &format!("{path}: attempt past the free budget"));
        let correct = attempt(&fx.router, source, path, Some(good)).await;
        assert_backoff(&correct, &format!("{path}: a CORRECT key during backoff"));

        // Control: another source is unaffected.
        let other = attempt(&fx.router, ip(n + 100), path, Some(good)).await;
        assert_eq!(
            other.status,
            StatusCode::OK,
            "another source: {}",
            other.body
        );
    }
}

/// Backoff earned on an ORDINARY route is honoured on both monitoring routes.
#[tokio::test]
async fn ordinary_route_backoff_carries_over_to_monitoring_4068() {
    let fx = fixture(false);
    let source = ip(20);
    exhaust(&fx.router, source, ORDINARY).await;
    let refused = attempt(&fx.router, source, ORDINARY, Some(WRONG_KEY)).await;
    assert_backoff(&refused, "ordinary route past the budget");
    for path in [STATUS_PATH, METRICS_PATH] {
        for good in [SHARED_KEY, AGENT_TOKEN] {
            let out = attempt(&fx.router, source, path, Some(good)).await;
            assert_backoff(&out, &format!("{path} for a source backed off elsewhere"));
        }
    }
}

/// Failures on monitoring count against the SAME budget ordinary routes use.
#[tokio::test]
async fn monitoring_failures_carry_over_to_ordinary_routes_4068() {
    let fx = fixture(false);
    let source = ip(30);
    exhaust(&fx.router, source, STATUS_PATH).await;
    let crossing = attempt(&fx.router, source, METRICS_PATH, Some(WRONG_KEY)).await;
    assert_backoff(&crossing, "monitoring attempt past the free budget");
    let out = attempt(&fx.router, source, ORDINARY, Some(SHARED_KEY)).await;
    assert_backoff(&out, "ordinary route after monitoring failures");
}

/// A key-based success resets the source, as on ordinary routes: the free
/// budget restarts rather than one old failure lingering forever.
#[tokio::test]
async fn a_monitoring_success_resets_the_budget_4068() {
    let fx = fixture(false);
    let source = ip(40);
    exhaust(&fx.router, source, STATUS_PATH).await;
    let ok = attempt(&fx.router, source, STATUS_PATH, Some(SHARED_KEY)).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
    // Budget restarted: FREE_FAILURES more wrong keys are plain 401s again.
    exhaust(&fx.router, source, METRICS_PATH).await;
}

/// The intentionally public legacy liveness probe stays reachable for a
/// backed-off source, with or without a key.
#[tokio::test]
async fn legacy_health_probe_stays_public_during_backoff_4068() {
    let fx = fixture(true);
    let source = ip(50);
    exhaust(&fx.router, source, STATUS_PATH).await;
    let crossing = attempt(&fx.router, source, STATUS_PATH, Some(WRONG_KEY)).await;
    assert_backoff(&crossing, "monitoring attempt past the free budget");
    let refused = attempt(&fx.router, source, STATUS_PATH, Some(SHARED_KEY)).await;
    assert_backoff(&refused, "monitoring during backoff");
    for key in [None, Some(WRONG_KEY), Some(MONITOR_TOKEN)] {
        let out = attempt(&fx.router, source, ai_memory::handlers::routes::HEALTH, key).await;
        assert_ne!(
            out.status,
            StatusCode::TOO_MANY_REQUESTS,
            "legacy /health must not be backed off (key={key:?}): {}",
            out.body
        );
        assert_ne!(
            out.status,
            StatusCode::FORBIDDEN,
            "a backed-off source's key is not consulted on /health (key={key:?})"
        );
    }
}

/// With health-only scopes configured the outer gate requires a resolved
/// principal on every non-probe route; those `401`s are counted too.
#[tokio::test]
async fn unresolved_principal_refusals_are_counted_4068() {
    let fx = fixture(true);
    let source = ip(60);
    for i in 0..FREE_FAILURES {
        let out = attempt(&fx.router, source, ORDINARY, Some(WRONG_KEY)).await;
        assert_eq!(
            out.status,
            StatusCode::UNAUTHORIZED,
            "failure {i}: {}",
            out.body
        );
    }
    let refused = attempt(&fx.router, source, ORDINARY, Some(WRONG_KEY)).await;
    assert_backoff(&refused, "unresolved principal past the budget");
    let correct = attempt(&fx.router, source, ORDINARY, Some(SHARED_KEY)).await;
    assert_backoff(&correct, "a correct key during backoff");
    // Control: the monitor's health-only scope is still enforced for a source
    // in good standing.
    let scoped = attempt(&fx.router, ip(61), ORDINARY, Some(MONITOR_TOKEN)).await;
    assert_eq!(scoped.status, StatusCode::FORBIDDEN, "{}", scoped.body);
    let health = attempt(&fx.router, ip(61), STATUS_PATH, Some(MONITOR_TOKEN)).await;
    assert_eq!(health.status, StatusCode::OK, "{}", health.body);
}
