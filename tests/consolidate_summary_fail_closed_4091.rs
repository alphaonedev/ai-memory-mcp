// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4091 — HTTP consolidate must FAIL CLOSED when no real summary
//! exists, instead of replacing the sources with a content-free placeholder.
//!
//! `POST /api/v1/consolidate` with no caller-supplied `summary` asked the LLM
//! and, when none was wired, the call timed out, or it errored / returned
//! nothing, fabricated a titles-only or fixed-string "summary" and went on to
//! consolidate — tombstoning the sources by default, HARD-DELETING them with
//! tombstoning off. A transient model failure thereby replaced the memories'
//! meaning with a placeholder.
//!
//! Pinned per backend (sqlite always; postgres when
//! `AI_MEMORY_TEST_POSTGRES_URL` is set), through the production router:
//!
//! * LLM absent, LLM timeout, LLM error, LLM empty/whitespace completion —
//!   each answers `503` with the `summary_unavailable` code, BOTH sources are
//!   still live with their original content, and no consolidated row exists;
//! * control: a real model summary still consolidates (`201`), so the gate
//!   is not simply refusing everything.

#![allow(
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::missing_panics_doc
)]
#![cfg(feature = "sal")]

use std::sync::Arc;
use std::time::Duration;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::llm::OllamaClient;
use ai_memory::store::MemoryStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CALLER: &str = "ai:consolidator-4091";
/// Short enough that the timeout case is fast, long enough that a healthy
/// mock never trips it.
const LLM_TIMEOUT: Duration = Duration::from_secs(2);

/// Pin the explicit permissive agent-attestation opt-out, as every suite
/// that seeds unsigned rows through the store path does (#1751).
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for
    // the process lifetime, set before any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

#[derive(Clone, Copy, Debug)]
enum Llm {
    Absent,
    Timeout,
    Error,
    Empty,
    Healthy,
}

async fn mock_llm(kind: Llm) -> Option<MockServer> {
    let chat = match kind {
        Llm::Absent => return None,
        Llm::Timeout => ResponseTemplate::new(200)
            .set_body_json(json!({"message": {"content": "too late"}, "done": true}))
            .set_delay(LLM_TIMEOUT * 3),
        Llm::Error => ResponseTemplate::new(500).set_body_string("upstream boom"),
        Llm::Empty => ResponseTemplate::new(200)
            .set_body_json(json!({"message": {"content": "   \n  "}, "done": true})),
        Llm::Healthy => ResponseTemplate::new(200).set_body_json(json!({
            "message": {"content": "A real synthesis of both source memories for #4091."},
            "done": true
        })),
    };
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(chat)
        .mount(&server)
        .await;
    Some(server)
}

fn app_state(
    db: Db,
    backend: StorageBackend,
    store: Arc<dyn MemoryStore>,
    llm: Option<&MockServer>,
) -> AppState {
    let llm = Arc::new(ai_memory::reload::SwappableLlm::new(llm.map(|s| {
        OllamaClient::new_with_url_no_health_check(&s.uri(), "test-model").expect("llm client")
    })));
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
        storage_backend: backend,
        store,
        llm,
        auto_tag_model: Arc::new(None),
        llm_call_timeout: LLM_TIMEOUT,
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

fn router(app: AppState) -> axum::Router {
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, app)
}

async fn call(
    router: &axum::Router,
    m: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = Request::builder()
        .method(m)
        .uri(uri)
        .header(ai_memory::HEADER_AGENT_ID, CALLER);
    let body = match body {
        Some(v) => {
            b = b.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&v).expect("serialise"))
        }
        None => Body::empty(),
    };
    let resp = router
        .clone()
        .oneshot(b.body(body).expect("request"))
        .await
        .expect("route");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 << 20)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn seed(router: &axum::Router, ns: &str, title: &str, content: &str) -> String {
    let (status, v) = call(
        router,
        "POST",
        "/api/v1/memories",
        Some(json!({
            "tier": "long",
            "namespace": ns,
            "title": title,
            "content": content,
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "metadata": {},
        })),
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "seed: {status} {v}"
    );
    v["id"].as_str().expect("seeded id").to_string()
}

/// Every live row in `ns`, as `(id, title, content)`.
async fn live_rows(router: &axum::Router, ns: &str) -> Vec<(String, String, String)> {
    let (status, v) = call(
        router,
        "GET",
        &format!("/api/v1/memories?namespace={ns}&limit=50"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list: {v}");
    let mut rows: Vec<(String, String, String)> = v["memories"]
        .as_array()
        .expect("memories array")
        .iter()
        .map(|m| {
            (
                m["id"].as_str().unwrap_or_default().to_string(),
                m["title"].as_str().unwrap_or_default().to_string(),
                m["content"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    rows.sort();
    rows
}

/// One case: seed two sources, consolidate WITHOUT a summary, check the
/// outcome and the sources.
async fn case(router: &axum::Router, kind: Llm) {
    let ns = format!("c4091-{}", uuid::Uuid::new_v4().simple());
    let a = seed(router, &ns, "source alpha", "alpha: the durable truth one").await;
    let b = seed(router, &ns, "source beta", "beta: the durable truth two").await;
    let before = live_rows(router, &ns).await;
    assert_eq!(before.len(), 2, "{before:?}");

    let (status, v) = call(
        router,
        "POST",
        "/api/v1/consolidate",
        Some(json!({
            "ids": [a, b],
            "title": "merged 4091",
            "namespace": ns,
            "use_llm": true,
        })),
    )
    .await;
    let after = live_rows(router, &ns).await;

    if matches!(kind, Llm::Healthy) {
        assert_eq!(status, StatusCode::CREATED, "control must consolidate: {v}");
        assert!(
            v["summary"]
                .as_str()
                .is_some_and(|s| s.contains("real synthesis")),
            "{v}"
        );
        return;
    }
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{kind:?}: no valid summary must refuse, got {v}"
    );
    assert_eq!(
        v["code"],
        json!(ai_memory::handlers::SUMMARY_UNAVAILABLE),
        "{kind:?}: typed error code: {v}"
    );
    assert_eq!(
        after, before,
        "{kind:?}: both sources must be untouched and no consolidated row created"
    );
}

async fn all_cases(build: impl AsyncFn(Option<&MockServer>) -> axum::Router) {
    for kind in [
        Llm::Absent,
        Llm::Timeout,
        Llm::Error,
        Llm::Empty,
        Llm::Healthy,
    ] {
        let server = mock_llm(kind).await;
        let router = build(server.as_ref()).await;
        case(&router, kind).await;
    }
}

#[tokio::test]
async fn sqlite_consolidate_without_a_real_summary_fails_closed_4091() {
    permissive_attestation_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("m.db");
    all_cases(async |llm| {
        let conn = ai_memory::db::open(&db_path).expect("db::open");
        let db: Db = Arc::new(tokio::sync::Mutex::new((
            conn,
            db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        let store: Arc<dyn MemoryStore> =
            Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
        router(app_state(db, StorageBackend::Sqlite, store, llm))
    })
    .await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_consolidate_without_a_real_summary_fails_closed_4091() {
    permissive_attestation_for_tests();
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
    else {
        eprintln!("skip postgres_consolidate_without_a_real_summary_fails_closed_4091: no PG url");
        return;
    };
    let pg: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("PostgresStore::connect"),
    );
    all_cases(async |llm| {
        // `app.db` is a deliberately EMPTY scratch sqlite: a postgres handler
        // that read it instead of `app.store` would fail the test loudly.
        let scratch = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch");
        let db: Db = Arc::new(tokio::sync::Mutex::new((
            scratch,
            std::path::PathBuf::from(":memory:"),
            ResolvedTtl::default(),
            true,
        )));
        router(app_state(
            db,
            StorageBackend::Postgres,
            Arc::clone(&pg),
            llm,
        ))
    })
    .await;
}
