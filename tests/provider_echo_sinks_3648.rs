// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::manual_let_else, clippy::map_unwrap_or)]
//! #3648 — the HTTP chat SINK end to end: `POST /api/v1/expand_query` against a
//! mock provider that echoes a secret in a non-2xx body and in a malformed
//! 2xx body. The 502 `error` field a caller sees and the operator log line
//! must both be free of the provider body AND carry the bounded diagnostic
//! (provider identity + classification) — the presence control that keeps
//! the absence assertion honest. The embedder sink's twin is
//! `tests/round2_f10_embed_status.rs::http_provider_echo_is_redacted_3648`;
//! the MCP chat sinks are pinned in `src/mcp/provider_echo_sinks_3648_tests.rs`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::llm::OllamaClient;

const SECRET: &str = "provider-echo-credential-3648-http";

fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for
    // the process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

#[derive(Clone, Default)]
struct CapturedLog(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn build_router_with_llm(llm: OllamaClient) -> (axum::Router, NamedTempFile) {
    permissive_attestation_for_tests();
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
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
        vector_index: Arc::new(Mutex::new(None)),
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
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(Some(llm))),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),

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
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

async fn expand(router: &axum::Router, query: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/expand_query")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"query": query})).unwrap(),
        ))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

#[tokio::test(flavor = "multi_thread")]
async fn http_expand_query_sink_never_carries_the_provider_body_3648() {
    let logs = CapturedLog::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    for ollama in [false, true] {
        for (status, malformed) in [(401u16, false), (200u16, true)] {
            let server = MockServer::start().await;
            let body = if malformed {
                format!("{{{SECRET}")
            } else {
                json!({"error": SECRET}).to_string()
            };
            Mock::given(method("POST"))
                .and(path(if ollama {
                    "/api/chat"
                } else {
                    "/chat/completions"
                }))
                .respond_with(ResponseTemplate::new(status).set_body_string(body))
                .mount(&server)
                .await;
            let client = if ollama {
                OllamaClient::new_with_url_no_health_check(&server.uri(), "test").unwrap()
            } else {
                OllamaClient::new_openai_compatible(&server.uri(), "test", "test-key").unwrap()
            };
            let (router, _db) = build_router_with_llm(client);
            let (code, payload) = expand(&router, "ordinary query").await;
            assert_eq!(code, StatusCode::BAD_GATEWAY, "{payload}");
            let error = payload["error"].as_str().unwrap_or_default();
            assert!(!error.contains(SECRET), "provider echo leaked: {error}");
            assert!(error.len() < 512, "error must be bounded: {error}");
            let provider = if ollama {
                "ollama"
            } else {
                "openai_compatible"
            };
            let marker = if malformed {
                "invalid_response"
            } else {
                "http_status=401"
            };
            assert!(
                error.contains(provider) && error.contains(marker),
                "the bounded diagnostic must reach the caller (presence control): {error}"
            );
            assert!(!server.received_requests().await.unwrap().is_empty());
        }
    }
    let rendered = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        rendered.contains("expand_query LLM call failed")
            && rendered.contains("http_status=401")
            && rendered.contains("invalid_response"),
        "the operator log must carry the diagnostic (presence control): {rendered}"
    );
    assert!(
        !rendered.contains(SECRET),
        "provider echo leaked to the operator log: {rendered}"
    );
}
