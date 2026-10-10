// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4286 — HTTP `POST /api/v1/consolidate` with an LLM-generated summary
//! must not consume a source that changed while the summary was being
//! generated (the #4045 lost-update class, CWE-367, on the tenant surface).
//!
//! The handler reads the sources, awaits the model with no store lock held,
//! then consumes the sources. A wiremock LLM stub commits a v2 edit to one
//! source from a second connection DURING the summarise call. The handler
//! must answer 409, leave the v2 text live, and write no summary row. A
//! no-race control proves the auto-summary path still succeeds.
//!
//! The sqlite cells run everywhere. The postgres twin is gated on
//! `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL` (skips when
//! the URL is unset) and runs on the host.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::llm::OllamaClient;

const CALLER: &str = "ai:cas-4286";
const NS: &str = "cas-4286";
const EDITED: &str = "v2 text committed while the summary was being generated";
const MERGED_TITLE: &str = "Merged 4286 note";

/// #1751 — permissive attestation for this binary's unsigned fixtures.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for
    // the process lifetime, set before any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn chat_ok() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "message": {"content": "A consolidated synthesis of the source memories."},
        "done": true,
    }))
}

/// LLM stub whose first `/api/chat` call runs `edit` before answering, so
/// the edit commits inside the handler's summarise window.
struct EditDuringSummary {
    edit: Box<dyn Fn() + Send + Sync>,
    fired: AtomicBool,
}

impl Respond for EditDuringSummary {
    fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
        if !self.fired.swap(true, Ordering::SeqCst) {
            (self.edit)();
        }
        chat_ok()
    }
}

async fn mount_llm(edit: Option<Box<dyn Fn() + Send + Sync>>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    match edit {
        Some(edit) => {
            Mock::given(method("POST"))
                .and(path("/api/chat"))
                .respond_with(EditDuringSummary {
                    edit,
                    fired: AtomicBool::new(false),
                })
                .mount(&server)
                .await;
        }
        None => {
            Mock::given(method("POST"))
                .and(path("/api/chat"))
                .respond_with(chat_ok())
                .mount(&server)
                .await;
        }
    }
    server
}

fn app_state(
    db: Db,
    store: Arc<dyn ai_memory::store::MemoryStore>,
    backend: StorageBackend,
    llm_url: &str,
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
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(Some(
            OllamaClient::new_with_url_no_health_check(llm_url, "test-model").expect("llm"),
        ))),
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
        admin_agent_ids: Arc::new(vec![CALLER.to_string()]),
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

fn router(state: AppState) -> axum::Router {
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

fn sqlite_db(path: &std::path::Path) -> Db {
    let conn = ai_memory::db::open(path).expect("db::open");
    Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )))
}

async fn post(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", CALLER)
        .body(Body::from(serde_json::to_vec(&body).expect("json")))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn seed(router: &axum::Router, title: &str) -> String {
    let (status, v) = post(
        router,
        "/api/v1/memories",
        json!({
            "tier": "long",
            "namespace": NS,
            "title": title,
            "content": format!("original body for {title}, long enough to summarise"),
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "metadata": {},
        }),
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "seed: {status} {v}"
    );
    v["id"].as_str().expect("seeded id").to_string()
}

fn consolidate_body(ids: &[String]) -> Value {
    json!({"ids": ids, "title": MERGED_TITLE, "namespace": NS})
}

/// #4286 review F2 — the common minimal 409 body BOTH backends emit on a
/// stale source: `status`, the conflicting source `id`, and an `error`
/// string. sqlite additionally carries the expected/current version pair.
fn assert_conflict_shape(v: &Value, conflicting_id: &str) {
    assert_eq!(v["status"], "conflict", "409 body names the conflict: {v}");
    assert_eq!(
        v["id"], conflicting_id,
        "409 body names the source that changed: {v}"
    );
    assert!(
        v["error"].as_str().is_some_and(|s| !s.is_empty()),
        "409 body carries an error string: {v}"
    );
}

/// Build a sqlite router whose LLM edits `target` (once) mid-summary.
/// Returns the router, the keep-alive temp file, and the id cell the edit
/// reads (filled after seeding).
async fn sqlite_race_router(
    race: bool,
) -> (
    axum::Router,
    NamedTempFile,
    Arc<std::sync::Mutex<String>>,
    MockServer,
) {
    permissive_attestation_for_tests();
    let f = NamedTempFile::new().expect("tempfile");
    let db_path: PathBuf = f.path().to_path_buf();
    let target = Arc::new(std::sync::Mutex::new(String::new()));
    let edit: Option<Box<dyn Fn() + Send + Sync>> = if race {
        let target = Arc::clone(&target);
        let edit_path = db_path.clone();
        Some(Box::new(move || {
            let id = target.lock().expect("target").clone();
            let conn = ai_memory::db::open(&edit_path).expect("second connection");
            ai_memory::db::update(
                &conn,
                &id,
                None,
                Some(EDITED),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .expect("concurrent edit commits");
        }))
    } else {
        None
    };
    let server = mount_llm(edit).await;
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let state = app_state(
        sqlite_db(&db_path),
        store,
        StorageBackend::Sqlite,
        &server.uri(),
    );
    (router(state), f, target, server)
}

#[tokio::test]
async fn http_consolidate_llm_summary_refuses_source_edited_mid_summary_4286() {
    let (router, f, target, _server) = sqlite_race_router(true).await;
    let a = seed(&router, "source a").await;
    let b = seed(&router, "source b").await;
    *target.lock().expect("target") = b.clone();

    let (status, v) = post(
        &router,
        "/api/v1/consolidate",
        consolidate_body(&[a.clone(), b.clone()]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a source edited during summarisation must not be consumed: {v}"
    );
    assert_conflict_shape(&v, &b);

    let conn = ai_memory::db::open(f.path()).expect("db::open");
    let edited = ai_memory::db::get(&conn, &b)
        .expect("get")
        .expect("edited source still present");
    assert_eq!(edited.content, EDITED, "the v2 text is still live");
    assert!(
        ai_memory::db::get(&conn, &a).expect("get").is_some(),
        "the untouched source is not consumed either"
    );
    let rows = ai_memory::db::list(
        &conn,
        Some(NS),
        None,
        50,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("list");
    assert!(
        rows.iter().all(|m| m.title != MERGED_TITLE),
        "no summary row may be written on a conflict"
    );
}

#[tokio::test]
async fn http_consolidate_llm_summary_no_race_control_succeeds_4286() {
    let (router, f, _target, _server) = sqlite_race_router(false).await;
    let a = seed(&router, "source a").await;
    let b = seed(&router, "source b").await;

    let (status, v) = post(&router, "/api/v1/consolidate", consolidate_body(&[a, b])).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    let rows = ai_memory::db::list(
        &conn,
        Some(NS),
        None,
        50,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("list");
    assert!(
        rows.iter().any(|m| m.title == MERGED_TITLE),
        "the summary row lands"
    );
}

/// Postgres twin. Runs on the host (`AI_MEMORY_TEST_POSTGRES_URL` set);
/// skips with a message otherwise.
#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_consolidate_llm_summary_refuses_source_edited_mid_summary_pg_4286() {
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore, UpdatePatch};

    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("SKIP http_consolidate_..._pg_4286: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    permissive_attestation_for_tests();
    let target = Arc::new(std::sync::Mutex::new(String::new()));
    let edit_target = Arc::clone(&target);
    let edit_url = url.clone();
    let edit: Box<dyn Fn() + Send + Sync> = Box::new(move || {
        let id = edit_target.lock().expect("target").clone();
        let url = edit_url.clone();
        // A separate thread + runtime: the responder is sync and runs on the
        // mock server's runtime, so the async store write is driven here.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            rt.block_on(async {
                let store = PostgresStore::connect(&url).await.expect("connect");
                store
                    .update(
                        &CallerContext::for_agent(CALLER),
                        &id,
                        UpdatePatch {
                            content: Some(EDITED.to_string()),
                            ..Default::default()
                        },
                    )
                    .await
                    .expect("concurrent edit commits");
            });
        })
        .join()
        .expect("edit thread");
    });
    let server = mount_llm(Some(edit)).await;
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    );
    let router = router(app_state(
        db,
        Arc::clone(&store),
        StorageBackend::Postgres,
        &server.uri(),
    ));
    let suffix = uuid::Uuid::new_v4().to_string();
    let a = seed(&router, &format!("pg source a {suffix}")).await;
    let b = seed(&router, &format!("pg source b {suffix}")).await;
    *target.lock().expect("target") = b.clone();

    let (status, v) = post(
        &router,
        "/api/v1/consolidate",
        consolidate_body(&[a.clone(), b.clone()]),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{v}");
    assert_conflict_shape(&v, &b);
    let ctx = CallerContext::for_agent(CALLER);
    let edited = store.get(&ctx, &b).await.expect("edited source still live");
    assert_eq!(edited.content, EDITED);
    assert!(store.get(&ctx, &a).await.is_ok(), "untouched source live");
}
