// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2587 — the async `auto_tag` write path.
//!
//! **R-203.** These tests FAIL at the parent commit. At parent,
//! `maybe_auto_tag` (the pre-#2587 HTTP `create_memory` helper) awaits the
//! LLM `auto_tag_async` call INLINE, before the response is built: an
//! `AI_MEMORY_AUTONOMOUS_HOOKS=1` daemon with an LLM configured pays the
//! full LLM round-trip (or `llm_call_timeout`, default 30s, on a
//! never-answering endpoint) on every untagged `POST /api/v1/memories`.
//! Measured in production: 4.9-11.1s per write (issue #2587).
//!
//! The North-Star invariant under test: the DURABLE WRITE (title +
//! content, the source of truth) must never be blocked or lost by the
//! tagging concern (derived, regenerable data) — regardless of whether
//! the LLM is slow, unreachable, or absent.
//!
//! Harness mirrors `tests/cov_handlers_llm_wired_1660.rs`'s
//! `build_llm_router` (a `wiremock` `/api/chat` endpoint feeding a real
//! `AppState`), extended to wire the bounded `auto_tag_queue` +
//! `crate::background::auto_tag_worker` the way `bootstrap_serve` does
//! (see `src/daemon_runtime.rs`'s "spawn the bounded async `auto_tag`
//! worker unconditionally" comment for the production twin of this
//! chicken-and-egg construction order).
//!
//! `AppState.store` (the SAL trait-object handle) is only present under
//! `--features sal` — mirrors `tests/cov_handlers_llm_wired_1660.rs`.
#![cfg(feature = "sal")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::llm::OllamaClient;

/// #1751 — permissive attestation opt-out, the same pin
/// `tests/cov_handlers_llm_wired_1660.rs` carries (unsigned store
/// fixtures would otherwise 403 under the v0.9 store-path default).
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for
    // the process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

/// Build a Smart-tier sqlite router whose `app.llm` points at `llm_url`
/// and whose `auto_tag_queue` is wired to a LIVE
/// `crate::background::auto_tag_worker` — the same construction order
/// `bootstrap_serve` uses (spawn the worker with a clone whose OWN
/// `auto_tag_queue` is a `None` placeholder, then assign the returned
/// `Sender` onto the real `AppState` before it is handed to the router).
fn build_autotag_router(
    llm_url: &str,
    autonomous_hooks: bool,
) -> (axum::Router, NamedTempFile, Db) {
    permissive_attestation_for_tests();
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let llm = Arc::new(ai_memory::reload::SwappableLlm::new(Some(
        OllamaClient::new_with_url_no_health_check(llm_url, "test-model").expect("llm"),
    )));
    let mut app_state = AppState {
        db: db.clone(),
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        // Smart tier so `tier_config.llm_model.is_some()` — one of the
        // `auto_tag_eligible` gates.
        tier_config: Arc::new(FeatureTier::Smart.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        store,
        llm,
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks,
        // Placeholder — the real `Sender` is assigned below, mirroring
        // `bootstrap_serve`'s construction order exactly (see #2587).
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec!["*".to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let (tx, _worker_handle) = ai_memory::background::auto_tag_worker::spawn(app_state.clone());
    app_state.auto_tag_queue = Some(tx);

    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f, db)
}

async fn post_json(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", "autotag-2587-tester")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn get_json(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", "autotag-2587-tester")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Long-enough, untagged, public-namespace create-memory body — every
/// `auto_tag_eligible` gate except `autonomous_hooks` passes for this
/// payload.
fn eligible_create_body(title: &str) -> Value {
    json!({
        "tier": "long",
        "namespace": "autotag-2587",
        "title": title,
        "content": "content long enough to clear AUTO_TAG_MIN_CONTENT_LEN (50 \
                     chars) so every auto_tag_eligible gate except \
                     autonomous_hooks passes for this payload — #2587.",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "user",
        "metadata": {},
    })
}

/// A `wiremock` `/api/chat` endpoint that answers after `delay` — a
/// deterministic stand-in for "the LLM is up but slow", the same class
/// of hazard `tests/recall_embed_budget_2577.rs` injects via a
/// never-responding TCP listener for the read path. `/api/tags` (the
/// `OllamaClient` health-probe route) answers instantly so ONLY the
/// `auto_tag` call itself is slow.
async fn start_delayed_chat_mock(delay: Duration, tags_body: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": {"content": tags_body}, "done": true}))
                .set_delay(delay),
        )
        .mount(&server)
        .await;
    server
}

/// The write returns FAST even though the mock LLM takes multiple
/// seconds to answer — proving the durable insert no longer waits on
/// the `auto_tag` LLM call. The mock delay (6s) comfortably exceeds the
/// #2587 measured production range (4.9-11.1s); the assertion ceiling
/// (1.5s) is comfortably below it and generous against CI jitter, so
/// this cannot pass by accident.
///
/// **Fails at parent**: pre-#2587 `maybe_auto_tag` awaits the LLM
/// inline, so the whole request takes >= the mock's 6s delay.
#[tokio::test(flavor = "multi_thread")]
async fn slow_llm_does_not_block_the_durable_write_2587() {
    let mock = start_delayed_chat_mock(Duration::from_secs(6), "rust\nmemory\nasync").await;
    let (router, _f, db) = build_autotag_router(&mock.uri(), true);

    let started = Instant::now();
    let (status, body) = post_json(
        &router,
        "/api/v1/memories",
        eligible_create_body("slow-llm-fast-write"),
    )
    .await;
    let elapsed = started.elapsed();

    assert_eq!(status, StatusCode::CREATED, "write must succeed: {body}");
    assert!(
        elapsed < Duration::from_millis(1500),
        "the durable write took {elapsed:?} — it must not wait on the 6s-delayed LLM call (#2587)"
    );
    assert_eq!(
        body.get("auto_tagging").and_then(Value::as_str),
        Some("queued"),
        "eligible write must report auto_tagging=queued, got {body}"
    );

    // The row must ALREADY be durable — read it back through the SAME
    // connection the write used, well before the mock's 6s delay elapses.
    let id = body["id"].as_str().expect("id in response").to_string();
    let lock = db.lock().await;
    let stored = ai_memory::db::get(&lock.0, &id)
        .expect("db read")
        .expect("row must be durably persisted immediately after the 201");
    assert_eq!(stored.title, "slow-llm-fast-write");
    assert!(
        stored.tags.is_empty(),
        "tags must NOT be populated synchronously — auto_tag is deferred (#2587), got {:?}",
        stored.tags
    );
}

/// The write returns fast and durably persists even when the LLM never
/// answers at all (a silent-accept loopback listener — the same "up but
/// not answering" shape `tests/recall_embed_budget_2577.rs` injects for
/// the read path). Pre-#2587 this would hang the request for the full
/// `llm_call_timeout` (30s in this harness).
#[tokio::test(flavor = "multi_thread")]
async fn unreachable_llm_does_not_block_or_fail_the_write_2587() {
    // A loopback listener that accepts the TCP connection and then never
    // writes a byte — "up but not answering", not merely "refused".
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            match stream {
                Ok(s) => held.push(s),
                Err(_) => break,
            }
        }
    });
    let llm_url = format!("http://{addr}");
    let (router, _f, db) = build_autotag_router(&llm_url, true);

    let started = Instant::now();
    let (status, body) = post_json(
        &router,
        "/api/v1/memories",
        eligible_create_body("unreachable-llm-still-succeeds"),
    )
    .await;
    let elapsed = started.elapsed();

    assert_eq!(status, StatusCode::CREATED, "write must succeed: {body}");
    assert!(
        elapsed < Duration::from_millis(1500),
        "the durable write took {elapsed:?} against an LLM endpoint that never answers at all"
    );

    let id = body["id"].as_str().expect("id in response").to_string();
    let lock = db.lock().await;
    let stored = ai_memory::db::get(&lock.0, &id)
        .expect("db read")
        .expect("row must be durably persisted even though the LLM is unreachable");
    assert_eq!(stored.title, "unreachable-llm-still-succeeds");
}

/// Regression pin (the issue's own suggestion): with
/// `AI_MEMORY_AUTONOMOUS_HOOKS` effectively off (`autonomous_hooks:
/// false`) and an LLM wired, `create_memory` must issue ZERO LLM calls —
/// `#[allow(dead_code)]`'s sibling `maybe_detect_conflicts` already
/// respected this gate; pre-#2587 `maybe_auto_tag` did not.
#[tokio::test(flavor = "multi_thread")]
async fn autonomous_hooks_disabled_fires_zero_llm_calls_2587() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    // No `/api/chat` mount at all — any POST to it 404s, and `expect(0)`
    // below hard-fails the test if `auto_tag_async` is ever invoked.
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": {"content": "should-never-fire"}})),
        )
        .expect(0)
        .mount(&server)
        .await;

    let (router, _f, _db) = build_autotag_router(&server.uri(), false);
    let (status, body) = post_json(
        &router,
        "/api/v1/memories",
        eligible_create_body("autonomous-hooks-off"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "write must succeed: {body}");
    assert!(
        body.get("auto_tagging").is_none(),
        "autonomous_hooks=false must never surface auto_tagging, got {body}"
    );

    // Give the (non-existent) background job a moment to have fired if it
    // was wrongly enqueued, then let wiremock's `expect(0)` verify on
    // drop that `/api/chat` was never hit.
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// Eventual correctness: a FAST-responding mock still lets the
/// background worker land tags on the row after the response has
/// already returned — proving deferral is "later, not never".
#[tokio::test(flavor = "multi_thread")]
async fn tags_eventually_applied_by_background_worker_2587() {
    let mock = start_delayed_chat_mock(Duration::from_millis(50), "rust\nmemory\nasync").await;
    let (router, _f, _db) = build_autotag_router(&mock.uri(), true);

    let (status, body) = post_json(
        &router,
        "/api/v1/memories",
        eligible_create_body("eventually-tagged"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "write must succeed: {body}");
    let id = body["id"].as_str().expect("id in response").to_string();

    // Bounded poll — deterministic upper bound, not a fixed sleep-and-hope.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_tags: Vec<String> = Vec::new();
    while Instant::now() < deadline {
        let (_status, got) = get_json(&router, &format!("/api/v1/memories/{id}")).await;
        let tags: Vec<String> = got
            .get("memory")
            .and_then(|m| m.get("tags"))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if !tags.is_empty() {
            last_tags = tags;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        !last_tags.is_empty(),
        "the background worker must eventually apply auto_tag's tags to the row (#2587)"
    );
    assert!(
        last_tags.contains(&"rust".to_string()),
        "expected the mock's tags to land, got {last_tags:?}"
    );
}
