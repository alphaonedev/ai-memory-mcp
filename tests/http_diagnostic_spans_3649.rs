// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3649: diagnostic sinks must never record request URI secrets.

use std::sync::{Arc, Mutex};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt as _;
use tracing::instrument::WithSubscriber as _;

/// Build the production router over a fresh SQLite file. The file lives in a
/// `TempDir` (derived from `TMPDIR`) so SQLite's `-wal` / `-shm` siblings are
/// owned and removed with it; the guard is returned to keep it alive.
fn build_router() -> (axum::Router, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("ai-memory.db");
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let app_state = AppState {
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
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: Some("fixture-key-3649".to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, dir)
}

#[derive(Clone, Default)]
struct LogSink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("sink lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Drive four requests carrying sentinel secrets (query, path segment,
/// headers) through the production router with the HTTP span enabled by
/// `filter`, and assert the rendered diagnostics carry the route template and
/// method but none of the sentinels.
async fn check_diagnostics(json: bool, filter: &str) {
    let (router, _db_dir) = build_router();
    for (uri, route, status) in [
        (
            "/api/v1/recall?query=PRIVATE_QUERY_3649&api_key=PRIVATE_TOKEN_3649",
            "/api/v1/recall",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/api/v1/health?token=PRIVATE_TOKEN_3649",
            "/api/v1/health",
            StatusCode::OK,
        ),
        (
            "/api/v1/memories/PRIVATE_PATH_3649?token=PRIVATE_TOKEN_3649",
            "/api/v1/memories/{id}",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/PRIVATE_UNMATCHED_3649?query=PRIVATE_QUERY_3649",
            ai_memory::HTTP_SPAN_UNMATCHED_ROUTE,
            StatusCode::NOT_FOUND,
        ),
    ] {
        let sink = LogSink::default();
        let writer = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .without_time()
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NEW)
            .with_writer(move || writer.clone());
        let dispatch = if json {
            tracing::Dispatch::new(subscriber.json().finish())
        } else {
            tracing::Dispatch::new(subscriber.finish())
        };
        // Authenticate the unmatched request so it reaches the 404 fallback;
        // the matched private routes deliberately exercise auth rejection.
        let api_key = if status == StatusCode::NOT_FOUND {
            "fixture-key-3649"
        } else {
            "PRIVATE_API_KEY_3649"
        };
        let request = Request::builder()
            .uri(uri)
            .header(ai_memory::HEADER_API_KEY, api_key)
            .header("authorization", "Bearer PRIVATE_HEADER_3649")
            .header("x-private-header", "PRIVATE_HEADER_3649")
            .body(Body::empty())
            .expect("request");
        let response = router
            .clone()
            .oneshot(request)
            .with_subscriber(dispatch)
            .await
            .expect("response");
        assert_eq!(response.status(), status);
        let logs =
            String::from_utf8(sink.0.lock().expect("sink lock").clone()).expect("UTF-8 logs");
        assert!(
            logs.contains("request"),
            "diagnostics must be enabled: {logs}"
        );
        assert!(!logs.contains("PRIVATE_"), "request secrets leaked: {logs}");
        assert!(logs.contains(route), "matched template missing: {logs}");
        assert!(logs.contains("GET"), "method missing: {logs}");
        if json {
            let events: Vec<serde_json::Value> = logs
                .lines()
                .map(|line| serde_json::from_str(line).expect("JSON event"))
                .collect();
            // The span-creation event (`FmtSpan::NEW`) is the one whose own
            // metadata is the span's, so its `target` is the span target.
            let created = events
                .iter()
                .find(|event| event["fields"]["message"] == "new")
                .expect("span-creation event");
            assert_eq!(created["target"], ai_memory::HTTP_SPAN_TARGET);
            let span = &created["span"];
            assert_eq!(span["name"], "request");
            assert_eq!(span["route"], route);
            assert_eq!(span["method"], "GET");
            assert_eq!(span["version"], "HTTP/1.1");
            assert!(span.get("uri").is_none(), "URI field must be absent");
            assert!(span.get("path").is_none(), "path field must be absent");
            assert!(span.get("headers").is_none(), "headers must be absent");
        }
    }
}

#[tokio::test]
async fn issue_3649_plain_diagnostics_exclude_uri_secrets() {
    check_diagnostics(false, "off,tower_http=debug").await;
}

#[tokio::test]
async fn issue_3649_json_diagnostics_exclude_uri_secrets() {
    check_diagnostics(true, "off,tower_http=debug").await;
}

/// The span keeps tower-http's own target, so the most specific directive an
/// operator could already have in a runbook still enables it.
#[tokio::test]
async fn issue_3649_span_keeps_tower_http_make_span_target() {
    check_diagnostics(true, "off,tower_http::trace::make_span=debug").await;
}
