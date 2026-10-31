// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8444: shared harness and scenarios for the `Agent2Agent` (A2A 1.0) standard
//! binding. The SQLite and PostgreSQL test binaries build their own
//! `AppState` and then run the SAME scenarios through [`run_suite`].

#![allow(
    dead_code,
    reason = "shared harness: each test binary uses a subset of the helpers"
)]

pub mod conformance;

use ai_memory::a2a::{A2A_RPC_PATH, AGENT_CARD_PATH, state};
use ai_memory::config::{FeatureTier, ResolvedScoring};
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::storage::a2a_tasks::{A2aTaskRow, A2aTaskUpdate};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

pub const ALICE: &str = "ai:alice-8444";
pub const BOB: &str = "ai:bob-8444";
pub const ALICE_KEY: &str = "alice-key-8444-0123456789abcdef";
pub const BOB_KEY: &str = "bob-key-8444-0123456789abcdef";
/// A header-asserted identity that differs from the credential.
pub const SPOOFED: &str = "ai:spoofed-8444";

/// The SAL handle, present only under `feature = "sal"`.
#[cfg(feature = "sal")]
pub struct SalStore(pub Arc<dyn ai_memory::store::MemoryStore>);
#[cfg(not(feature = "sal"))]
pub struct SalStore(pub ());

#[cfg_attr(
    not(feature = "sal"),
    expect(
        clippy::needless_pass_by_value,
        reason = "`SalStore` is a ZST without `sal`; one signature keeps both feature legs identical."
    )
)]
pub fn app_state_with(db: Db, backend: StorageBackend, store: SalStore) -> AppState {
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
        enrolled_agent_keys: Arc::new(EnrolledAgentKeys::empty()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

/// Router with a shared global key plus two enrolled per-agent keys.
pub fn router(mut app: AppState) -> (axum::Router, String) {
    let global = uuid::Uuid::new_v4().to_string();
    let enrolled = Arc::new(EnrolledAgentKeys::from_map(
        [
            (api_key_sha256_hex(ALICE_KEY), ALICE.to_owned()),
            (api_key_sha256_hex(BOB_KEY), BOB.to_owned()),
        ]
        .into_iter()
        .collect(),
    ));
    app.enrolled_agent_keys = Arc::clone(&enrolled);
    app.http_identity_mode = ai_memory::config::HttpIdentityMode::Enforce;
    let router = ai_memory::build_router(
        ApiKeyState {
            key: Some(global.clone()),
            mtls_enforced: false,
            enrolled_agent_keys: enrolled,
            identity_mode: ai_memory::config::HttpIdentityMode::Enforce,
            ..Default::default()
        },
        app,
    );
    (router, global)
}

pub struct Reply {
    pub status: StatusCode,
    pub version: Option<String>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("JSON response body")
    }
}

pub async fn send(
    router: &axum::Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Reply {
    let mut request = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        request = request.header(*k, *v);
    }
    let response = router
        .clone()
        .oneshot(request.body(Body::from(body)).expect("request"))
        .await
        .expect("route");
    let status = response.status();
    let version = response
        .headers()
        .get("a2a-version")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("response bytes");
    Reply {
        status,
        version,
        body: bytes.to_vec(),
    }
}

/// POST one JSON-RPC call as `key`, optionally with extra headers.
pub async fn rpc_with(
    router: &axum::Router,
    key: &str,
    extra: &[(&str, &str)],
    method: &str,
    params: &Value,
) -> Reply {
    let body = json!({"jsonrpc":"2.0","id":7,"method":method,"params":params});
    let mut headers = vec![
        ("content-type", "application/json"),
        (ai_memory::HEADER_API_KEY, key),
    ];
    headers.extend_from_slice(extra);
    send(
        router,
        "POST",
        A2A_RPC_PATH,
        &headers,
        serde_json::to_vec(&body).expect("body"),
    )
    .await
}

pub async fn rpc(router: &axum::Router, key: &str, method: &str, params: &Value) -> Reply {
    rpc_with(router, key, &[], method, params).await
}

fn message(text: &str, role: &str) -> Value {
    json!({
        "messageId": uuid::Uuid::new_v4().to_string(),
        "role": role,
        "parts": [{"text": text}],
    })
}

fn error_code(reply: &Reply) -> i64 {
    reply.json()["error"]["code"].as_i64().expect("error.code")
}

async fn send_ok(router: &axum::Router, key: &str, text: &str, role: &str) -> Value {
    let reply = rpc(
        router,
        key,
        "SendMessage",
        &json!({"message": message(text, role)}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.json());
    reply.json()["result"]["task"].clone()
}

/// Read the stored inbox memory back through the actual backend.
async fn stored_memory(app: &AppState, owner: &str, id: &str) -> ai_memory::models::Memory {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return app
            .store
            .get(&ai_memory::store::CallerContext::for_agent(owner), id)
            .await
            .expect("read inbox memory from PostgreSQL");
    }
    let _ = owner;
    ai_memory::db::get(&app.db.lock().await.0, id)
        .expect("SQLite read")
        .expect("persisted inbox memory")
}

/// Seed a WORKING task through the storage layer (not the HTTP surface).
async fn seed_working_task(app: &AppState, agent: &str, id: &str) {
    seed_task(
        app,
        &SeedTask::new(agent, id, "ctx-seed-8444", state::WORKING),
    )
    .await;
}

/// One storage-layer task fixture.
pub struct SeedTask<'a> {
    pub agent: &'a str,
    pub id: &'a str,
    pub context_id: &'a str,
    pub state: &'a str,
    pub timestamp: String,
    pub history: Value,
}

impl<'a> SeedTask<'a> {
    pub fn new(agent: &'a str, id: &'a str, context_id: &'a str, state: &'a str) -> Self {
        Self {
            agent,
            id,
            context_id,
            state,
            timestamp: "2026-10-31T12:00:00.000Z".to_string(),
            history: json!([]),
        }
    }
}

/// Insert a task row through the backend's storage layer (not HTTP).
pub async fn seed_task(app: &AppState, seed: &SeedTask<'_>) {
    let now = seed.timestamp.clone();
    let row = A2aTaskRow {
        id: seed.id.to_string(),
        context_id: seed.context_id.to_string(),
        agent_id: seed.agent.to_string(),
        state: seed.state.to_string(),
        status_timestamp: now.clone(),
        history: seed.history.clone(),
        artifacts: json!([]),
        metadata: json!({}),
        created_at: now.clone(),
        updated_at: now,
    };
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        app.store.a2a_task_insert(&row).await.expect("seed pg task");
        return;
    }
    ai_memory::storage::a2a_tasks::a2a_task_insert(&app.db.lock().await.0, &row)
        .expect("seed sqlite task");
}

/// Storage-layer probe of one agent's tasks: (total rows, whether `first` still
/// exists, whether `active` still exists).
pub async fn storage_probe(
    app: &AppState,
    agent: &str,
    first: &str,
    active: &str,
) -> (usize, bool, bool) {
    use ai_memory::storage::a2a_tasks::A2aTaskFilter;
    let filter = A2aTaskFilter {
        limit: 1,
        ..A2aTaskFilter::default()
    };
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let total = app
            .store
            .a2a_task_list(agent, &filter)
            .await
            .expect("pg list")
            .total;
        let first_present = app
            .store
            .a2a_task_get(agent, first)
            .await
            .expect("pg get")
            .is_some();
        let active_present = app
            .store
            .a2a_task_get(agent, active)
            .await
            .expect("pg get")
            .is_some();
        return (total, first_present, active_present);
    }
    let guard = app.db.lock().await;
    let conn = &guard.0;
    let total = ai_memory::storage::a2a_tasks::a2a_task_list(conn, agent, &filter)
        .expect("list")
        .total;
    let first_present = ai_memory::storage::a2a_tasks::a2a_task_get(conn, agent, first)
        .expect("get")
        .is_some();
    let active_present = ai_memory::storage::a2a_tasks::a2a_task_get(conn, agent, active)
        .expect("get")
        .is_some();
    (total, first_present, active_present)
}

/// A fresh SQLite-backed `AppState` at `path`.
pub fn sqlite_app_state(path: &std::path::Path) -> AppState {
    let conn = ai_memory::db::open(path).expect("open sqlite fixture db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ai_memory::config::ResolvedTtl::default(),
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

/// Direct compare-and-set completion, bypassing HTTP.
async fn complete_directly(app: &AppState, agent: &str, id: &str) -> bool {
    let update = A2aTaskUpdate {
        status_timestamp: "2026-10-31T12:00:01.000Z".to_string(),
        history: None,
        artifacts: Some(json!([])),
    };
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return app
            .store
            .a2a_task_transition(agent, id, &[state::WORKING], state::COMPLETED, &update)
            .await
            .expect("pg transition");
    }
    ai_memory::storage::a2a_tasks::a2a_task_transition(
        &app.db.lock().await.0,
        agent,
        id,
        &[state::WORKING],
        state::COMPLETED,
        &update,
    )
    .expect("sqlite transition")
}

fn assert_no_leak(card: &Value, forbidden: &[&str]) {
    let text = card.to_string();
    for needle in forbidden {
        assert!(!text.contains(needle), "card leaks {needle}");
    }
}

/// Run every #8444 scenario against `app` (a fresh, empty backend).
pub async fn run_suite(app: AppState) {
    let probe = app.clone();
    let (router, global) = router(app);

    card_is_authenticated_only(&router, &global).await;
    send_message_stamps_authenticated_principal(&router, &probe).await;
    task_access_is_caller_scoped(&router).await;
    unsupported_and_error_codes(&router).await;
    cancel_races_completion_once(&router, &probe).await;
    conformance::run_all(&router, &probe, &global).await;
}

async fn card_is_authenticated_only(router: &axum::Router, _global: &str) {
    let anon = send(router, "GET", AGENT_CARD_PATH, &[], Vec::new()).await;
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED);
    assert!(
        !String::from_utf8_lossy(&anon.body).contains("supportedInterfaces"),
        "an unauthenticated GET must not leak the card"
    );

    let ok = send(
        router,
        "GET",
        AGENT_CARD_PATH,
        &[
            (ai_memory::HEADER_API_KEY, ALICE_KEY),
            ("host", "node.example:9077"),
        ],
        Vec::new(),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(ok.version.as_deref(), Some("1.0"));
    let card = ok.json();
    for field in [
        "name",
        "description",
        "version",
        "supportedInterfaces",
        "capabilities",
        "defaultInputModes",
        "defaultOutputModes",
        "skills",
        "securitySchemes",
        "securityRequirements",
    ] {
        assert!(card.get(field).is_some(), "card missing {field}");
    }
    assert!(
        card.get("signatures").is_none(),
        "signatures must be absent"
    );
    assert_eq!(card["capabilities"]["streaming"], json!(false));
    assert_eq!(card["capabilities"]["pushNotifications"], json!(false));
    assert_eq!(card["capabilities"]["extendedAgentCard"], json!(false));
    let iface = &card["supportedInterfaces"][0];
    assert_eq!(iface["protocolBinding"], json!("JSONRPC"));
    assert_eq!(iface["protocolVersion"], json!("1.0"));
    assert!(
        iface["url"]
            .as_str()
            .is_some_and(|u| u.ends_with("/api/v1/a2a")),
        "interface url"
    );
    assert_eq!(card["skills"][0]["id"], json!("memory-inbox"));
    assert!(card["securitySchemes"].to_string().contains("x-api-key"));
    assert_no_leak(&card, &[ALICE, BOB, "ai:", "_inbox", "namespace"]);
}

async fn send_message_stamps_authenticated_principal(router: &axum::Router, app: &AppState) {
    // The header claims another identity and the body claims a third: only
    // the credential counts.
    let body_claim = json!({
        "message": {
            "messageId": "m-stamp-8444",
            "role": "ROLE_USER",
            "parts": [{"text": "hello from the standard binding"}, {"data": {"k": 1}}],
            "metadata": {"content_principal": "ai:body-claim-8444", "agent_id": "ai:body-claim-8444"}
        },
        "metadata": {"agent_id": "ai:body-claim-8444"}
    });
    // A header naming a different agent than the per-agent key is refused by
    // the existing identity-binding layer before the handler runs.
    let spoofed = rpc_with(
        router,
        ALICE_KEY,
        &[(ai_memory::HEADER_AGENT_ID, SPOOFED)],
        "SendMessage",
        &body_claim,
    )
    .await;
    assert_eq!(
        spoofed.status,
        StatusCode::FORBIDDEN,
        "{}",
        String::from_utf8_lossy(&spoofed.body)
    );
    let reply = rpc(router, ALICE_KEY, "SendMessage", &body_claim).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.json());
    assert_eq!(reply.version.as_deref(), Some("1.0"));
    let task = reply.json()["result"]["task"].clone();
    assert_eq!(task["status"]["state"], json!(state::COMPLETED));
    assert_eq!(task["history"].as_array().map(Vec::len), Some(1));
    assert_eq!(task["artifacts"].as_array().map(Vec::len), Some(1));
    assert!(task["id"].as_str().is_some() && task["contextId"].as_str().is_some());

    let artifact_id = task["artifacts"][0]["artifactId"]
        .as_str()
        .expect("artifact id");
    let memory_id = artifact_id
        .strip_prefix("receipt-")
        .expect("receipt prefix");
    let mem = stored_memory(app, ALICE, memory_id).await;
    assert_eq!(mem.namespace, ai_memory::inbox_namespace(ALICE));
    assert!(mem.content.contains("hello from the standard binding"));
    assert!(mem.content.contains("\"k\":1"));
    assert_eq!(mem.metadata["content_principal"], json!(ALICE));
    assert_eq!(mem.metadata["a2a_role"], json!("ROLE_USER"));
    assert_ne!(mem.metadata["content_principal"], json!(SPOOFED));
    assert_ne!(
        mem.metadata["content_principal"],
        json!("ai:body-claim-8444")
    );

    // A caller-chosen contextId is honoured.
    let reply = rpc(
        router,
        ALICE_KEY,
        "SendMessage",
        &json!({"message": {"messageId":"m-ctx","role":"ROLE_AGENT","contextId":"ctx-given-8444","parts":[{"text":"x"}]}}),
    )
    .await;
    assert_eq!(
        reply.json()["result"]["task"]["contextId"],
        json!("ctx-given-8444")
    );

    // A shared-key (no credential-bound agent) caller is refused on RPC.
    let no_agent = rpc(router, "not-an-enrolled-key", "SendMessage", &json!({})).await;
    assert_eq!(no_agent.status, StatusCode::UNAUTHORIZED);
}

async fn task_access_is_caller_scoped(router: &axum::Router) {
    let task = send_ok(router, ALICE_KEY, "alice private", "ROLE_USER").await;
    let id = task["id"].as_str().expect("task id").to_string();

    let own = rpc(router, ALICE_KEY, "GetTask", &json!({"id": id})).await;
    assert_eq!(own.status, StatusCode::OK);
    assert_eq!(own.json()["result"]["id"], json!(id));

    let other = rpc(router, BOB_KEY, "GetTask", &json!({"id": id})).await;
    assert_eq!(other.status, StatusCode::NOT_FOUND);
    assert_eq!(error_code(&other), -32001);
    let cancel_other = rpc(router, BOB_KEY, "CancelTask", &json!({"id": id})).await;
    assert_eq!(cancel_other.status, StatusCode::NOT_FOUND);
    assert_eq!(error_code(&cancel_other), -32001);

    let bob_task = send_ok(router, BOB_KEY, "bob private", "ROLE_USER").await;
    let bob_list = rpc(router, BOB_KEY, "ListTasks", &json!({})).await;
    let tasks = bob_list.json()["result"]["tasks"].clone();
    let ids: Vec<&str> = tasks
        .as_array()
        .expect("tasks")
        .iter()
        .filter_map(|t| t["id"].as_str())
        .collect();
    assert!(ids.contains(&bob_task["id"].as_str().expect("id")));
    assert!(
        !ids.contains(&id.as_str()),
        "ListTasks must be scoped to the caller"
    );
    assert_eq!(bob_list.json()["result"]["totalSize"], json!(ids.len()));

    // Page size: below 1 is invalid, above the cap is clamped (not rejected).
    let bad = rpc(router, ALICE_KEY, "ListTasks", &json!({"pageSize": 0})).await;
    assert_eq!(error_code(&bad), -32602);
    let clamped = rpc(router, ALICE_KEY, "ListTasks", &json!({"pageSize": 101})).await;
    assert_eq!(clamped.json()["result"]["pageSize"], json!(100));

    // Terminal task cannot be cancelled.
    let done = rpc(router, ALICE_KEY, "CancelTask", &json!({"id": id})).await;
    assert_eq!(done.status, StatusCode::BAD_REQUEST);
    assert_eq!(error_code(&done), -32002);

    // A taskId on a message must be the caller's and non-terminal.
    let cont = rpc(
        router,
        ALICE_KEY,
        "SendMessage",
        &json!({"message": {"messageId":"m-c","role":"ROLE_USER","taskId": id,"parts":[{"text":"again"}]}}),
    )
    .await;
    assert_eq!(error_code(&cont), -32001);
}

async fn unsupported_and_error_codes(router: &axum::Router) {
    for m in [
        "SendStreamingMessage",
        "SubscribeToTask",
        "GetExtendedAgentCard",
    ] {
        let r = rpc(router, ALICE_KEY, m, &json!({})).await;
        assert_eq!(error_code(&r), -32004, "{m}");
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{m}");
        assert_eq!(r.version.as_deref(), Some("1.0"));
    }
    for m in [
        "CreateTaskPushNotificationConfig",
        "GetTaskPushNotificationConfig",
        "ListTaskPushNotificationConfigs",
        "DeleteTaskPushNotificationConfig",
    ] {
        let r = rpc(router, ALICE_KEY, m, &json!({})).await;
        assert_eq!(error_code(&r), -32003, "{m}");
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{m}");
    }
    let file_part = rpc(
        router,
        ALICE_KEY,
        "SendMessage",
        &json!({"message": {"messageId":"m-f","role":"ROLE_USER","parts":[{"raw":"AAAA","mediaType":"image/png"}]}}),
    )
    .await;
    assert_eq!(error_code(&file_part), -32005);
    assert_eq!(file_part.status, StatusCode::BAD_REQUEST);

    let v03 = rpc_with(
        router,
        ALICE_KEY,
        &[("a2a-version", "0.3")],
        "ListTasks",
        &json!({}),
    )
    .await;
    assert_eq!(error_code(&v03), -32009);
    assert_eq!(v03.status, StatusCode::BAD_REQUEST);
    let empty = rpc_with(
        router,
        ALICE_KEY,
        &[("a2a-version", "")],
        "ListTasks",
        &json!({}),
    )
    .await;
    assert_eq!(error_code(&empty), -32009);
    let v10 = rpc_with(
        router,
        ALICE_KEY,
        &[("a2a-version", "1.0")],
        "ListTasks",
        &json!({}),
    )
    .await;
    assert_eq!(v10.status, StatusCode::OK);

    let unknown = rpc(router, ALICE_KEY, "NoSuchMethod", &json!({})).await;
    assert_eq!(error_code(&unknown), -32601);
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);

    let malformed = send(
        router,
        "POST",
        A2A_RPC_PATH,
        &[
            ("content-type", "application/json"),
            (ai_memory::HEADER_API_KEY, ALICE_KEY),
        ],
        b"{not json".to_vec(),
    )
    .await;
    assert_eq!(error_code(&malformed), -32700);
    assert_eq!(malformed.status, StatusCode::OK);
    assert_eq!(malformed.version.as_deref(), Some("1.0"));

    let anon = send(
        router,
        "POST",
        A2A_RPC_PATH,
        &[("content-type", "application/json")],
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED);
}

/// `CancelTask` racing a direct completion on the same WORKING task leaves
/// exactly one terminal state, and exactly one side wins the compare-and-set.
async fn cancel_races_completion_once(router: &axum::Router, app: &AppState) {
    for round in 0..8 {
        let id = format!("race-8444-{round}-{}", uuid::Uuid::new_v4());
        seed_working_task(app, ALICE, &id).await;
        let cancel_params = json!({"id": id});
        let (cancel, completed) = tokio::join!(
            rpc(router, ALICE_KEY, "CancelTask", &cancel_params),
            complete_directly(app, ALICE, &id),
        );
        let cancel_won = cancel.status == StatusCode::OK;
        assert_ne!(
            cancel_won, completed,
            "exactly one of cancel and completion may win (round {round})"
        );
        let got = rpc(router, ALICE_KEY, "GetTask", &json!({"id": id})).await;
        let final_state = got.json()["result"]["status"]["state"]
            .as_str()
            .expect("state")
            .to_string();
        let expected = if cancel_won {
            state::CANCELED
        } else {
            state::COMPLETED
        };
        assert_eq!(final_state, expected);
        if !cancel_won {
            assert_eq!(error_code(&cancel), -32002);
        }
    }
}
