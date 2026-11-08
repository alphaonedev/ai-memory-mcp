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
use ai_memory::storage::a2a_tasks::{A2aHistoryEntry, A2aTaskRow, A2aTaskUpdate};
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
            timestamp: ai_memory::a2a::now_timestamp(),
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
        status_timestamp: ai_memory::a2a::now_timestamp(),
        artifact_append: Some(
            json!({"artifactId": "direct", "parts": [{"text": "direct completion"}]}),
        ),
        ..A2aTaskUpdate::default()
    };
    transition_direct(app, agent, id, &[state::WORKING], state::COMPLETED, &update).await
}

// --- round 2 (#8444 r2) scenarios --------------------------------------------

/// The memory id inside a Task's `receipt-<memory id>` artifact.
pub fn receipt_memory_id(task: &Value) -> String {
    task["artifacts"][0]["artifactId"]
        .as_str()
        .expect("artifact id")
        .strip_prefix("receipt-")
        .expect("receipt prefix")
        .to_string()
}

/// One compare-and-set through the backend's storage layer (not HTTP).
async fn transition_direct(
    app: &AppState,
    agent: &str,
    id: &str,
    from_states: &[&str],
    to_state: &str,
    update: &A2aTaskUpdate,
) -> bool {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return app
            .store
            .a2a_task_transition(agent, id, from_states, to_state, update)
            .await
            .expect("pg transition");
    }
    ai_memory::storage::a2a_tasks::a2a_task_transition(
        &app.db.lock().await.0,
        agent,
        id,
        from_states,
        to_state,
        update,
    )
    .expect("sqlite transition")
}

/// Append content-free history entries (and their memory links) to a seeded
/// WORKING task, one atomic compare-and-set each.
pub async fn link_history(app: &AppState, agent: &str, task_id: &str, entries: &[A2aHistoryEntry]) {
    for entry in entries {
        let update = A2aTaskUpdate {
            status_timestamp: ai_memory::a2a::now_timestamp(),
            history_append: Some(entry.clone()),
            ..A2aTaskUpdate::default()
        };
        assert!(
            transition_direct(
                app,
                agent,
                task_id,
                &[state::WORKING],
                state::WORKING,
                &update
            )
            .await,
            "link history entry {}",
            entry.message_id
        );
    }
}

/// The stored row exactly as the backend returns it (history is the
/// content-free `history_json` column, filtered to still-linked memories).
async fn stored_task(app: &AppState, agent: &str, id: &str) -> Option<A2aTaskRow> {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return app.store.a2a_task_get(agent, id).await.expect("pg get");
    }
    ai_memory::storage::a2a_tasks::a2a_task_get(&app.db.lock().await.0, agent, id).expect("get")
}

/// Every stored task row, through the export read of the backend.
async fn export_tasks(app: &AppState) -> Vec<A2aTaskRow> {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return app.store.a2a_task_export().await.expect("pg export");
    }
    ai_memory::storage::a2a_tasks::a2a_task_export(&app.db.lock().await.0).expect("export")
}

/// Hard-delete one inbox memory through the backend (the erase / delete / GC
/// paths all end in the same `memories` row removal).
async fn erase_memory(app: &AppState, owner: &str, id: &str) {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        app.store
            .delete(&ai_memory::store::CallerContext::for_agent(owner), id)
            .await
            .expect("pg delete");
        return;
    }
    let _ = owner;
    assert!(
        ai_memory::db::delete(&app.db.lock().await.0, id).expect("sqlite delete"),
        "the inbox memory existed"
    );
}

fn history_of(reply: &Reply) -> Vec<Value> {
    reply.json()["result"]
        .get("history")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Sec MEDIUM-1 / LOW-2: the task history holds ids only, `GetTask` renders the
/// text from the inbox memory, and erasing that memory removes the content from
/// every task view.
async fn history_is_content_free_and_follows_erasure(router: &axum::Router, app: &AppState) {
    use ai_memory::storage::a2a_tasks::A2A_HISTORY_ENTRY_MAX_BYTES;
    let marker = "erase-me-8444-marker";
    let task = send_ok(router, ALICE_KEY, marker, "ROLE_USER").await;
    let id = task["id"].as_str().expect("task id").to_string();
    let context_id = task["contextId"].as_str().expect("ctx").to_string();
    let memory_id = receipt_memory_id(&task);
    assert_eq!(task["history"][0]["parts"][0]["text"], json!(marker));

    let row = stored_task(app, ALICE, &id).await.expect("stored row");
    let entries = row.history.as_array().expect("history array").clone();
    assert_eq!(entries.len(), 1);
    assert!(
        !row.history.to_string().contains(marker),
        "history_json must hold no message content: {}",
        row.history
    );
    for entry in &entries {
        assert!(entry.to_string().len() <= A2A_HISTORY_ENTRY_MAX_BYTES);
        assert_eq!(entry["memoryId"], json!(memory_id));
        assert_eq!(entry["taskId"], json!(id));
    }

    erase_memory(app, ALICE, &memory_id).await;
    let get = rpc(router, ALICE_KEY, "GetTask", &json!({"id": id})).await;
    assert_eq!(get.status, StatusCode::OK);
    assert!(
        history_of(&get).is_empty(),
        "erased content is not rendered"
    );
    assert!(!String::from_utf8_lossy(&get.body).contains(marker));
    let list = rpc(
        router,
        ALICE_KEY,
        "ListTasks",
        &json!({"contextId": context_id}),
    )
    .await;
    assert!(!String::from_utf8_lossy(&list.body).contains(marker));
    let after = stored_task(app, ALICE, &id).await.expect("stored row");
    assert_eq!(
        after.history,
        json!([]),
        "the link left with the memory in the same transaction"
    );

    // A secret-shaped value never reaches history_json, whatever the screen
    // does to the memory itself.
    // Assembled at runtime so no secret-shaped literal sits in the source.
    let secret = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
    let secret = secret.as_str();
    let reply = rpc(
        router,
        ALICE_KEY,
        "SendMessage",
        &json!({"message": message(&format!("key {secret} end"), "ROLE_USER")}),
    )
    .await;
    // Sec INFO-1 (r3): the suite seeds the screen mode (`Off`, see
    // `run_suite`), so the message is accepted and the block always runs.
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.json());
    let secret_task = reply.json()["result"]["task"].clone();
    let sid = secret_task["id"].as_str().expect("id").to_string();
    let row = stored_task(app, ALICE, &sid).await.expect("row");
    assert!(!row.history.to_string().contains(secret));
    assert!(!row.artifacts.to_string().contains(secret));
    // GetTask renders exactly the stored memory content, nothing else.
    let mem = stored_memory(app, ALICE, &receipt_memory_id(&secret_task)).await;
    let got = rpc(router, ALICE_KEY, "GetTask", &json!({"id": sid})).await;
    assert_eq!(got.status, StatusCode::OK);
    let rendered = history_of(&got);
    assert_eq!(rendered.len(), 1);
    assert_eq!(rendered[0]["parts"][0]["text"], json!(mem.content));
}

/// Code LOW-2 / LOW-5: concurrent continuations never lose a history entry or
/// a receipt (the lost-update class), and every completion adds both.
async fn concurrent_continuations_keep_every_history_entry(router: &axum::Router, app: &AppState) {
    let id = format!("cont-8444-{}", uuid::Uuid::new_v4());
    seed_working_task(app, ALICE, &id).await; // context "ctx-seed-8444"
    let cont = |i: usize| {
        let mut m = message(&format!("cont-text-{i}"), "ROLE_USER");
        m["taskId"] = json!(id);
        m["contextId"] = json!("ctx-seed-8444");
        let sent = m["messageId"].as_str().expect("message id").to_string();
        async move {
            let r = rpc(router, ALICE_KEY, "SendMessage", &json!({"message": m})).await;
            (sent, r)
        }
    };
    let (a, b, c, d) = tokio::join!(cont(0), cont(1), cont(2), cont(3));
    let sent = [a, b, c, d];
    // A continuation either lands or finds the task already terminal (-32004).
    for (_, r) in &sent {
        if r.status != StatusCode::OK {
            assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.json());
            assert_eq!(error_code(r), -32004, "{}", r.json());
        }
    }
    assert!(
        sent.iter().any(|(_, r)| r.status == StatusCode::OK),
        "at least one continuation lands"
    );
    let got = rpc(router, ALICE_KEY, "GetTask", &json!({"id": id})).await;
    let task = got.json()["result"].clone();
    let history = history_of(&got);
    let artifacts = task["artifacts"].as_array().cloned().unwrap_or_default();
    assert_ne!(history, [] as [serde_json::Value; 0]);
    assert_eq!(
        history.len(),
        artifacts.len(),
        "each completion appends its entry and its receipt together"
    );
    let ids: Vec<&str> = history
        .iter()
        .filter_map(|h| h["messageId"].as_str())
        .collect();
    let unique_ids: std::collections::HashSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique_ids.len(), ids.len(), "no entry is duplicated");
    for entry_id in &ids {
        assert!(sent.iter().any(|(m, _)| m == entry_id));
    }
    // Code MEDIUM-2 (r3): EVERY 200 reply acknowledged its message, so its
    // entry is in the final task, whatever state the reply reported.
    for (message_id, r) in &sent {
        if r.status == StatusCode::OK {
            assert!(
                ids.contains(&message_id.as_str()),
                "{message_id} was acknowledged but is missing from the history"
            );
        }
    }
}

/// Code MEDIUM-2 (r3), deterministic interleaving: continuation A is WORKING
/// when continuation B re-opens the task (WORKING -> SUBMITTED). A's
/// completion still appends its entry and receipt (it never answers success
/// without them), B then completes, and the final task holds both. A
/// completion that finds the task ended is `-32004`, never a success.
async fn completion_survives_a_reopen_while_working(router: &axum::Router, app: &AppState) {
    let first = send_ok(router, ALICE_KEY, "interleave-a-8444", "ROLE_USER").await;
    let memory_a = receipt_memory_id(&first);
    let id = format!("interleave-8444-{}", uuid::Uuid::new_v4());
    seed_working_task(app, ALICE, &id).await; // A holds the task WORKING
    let reopen = A2aTaskUpdate {
        status_timestamp: ai_memory::a2a::now_timestamp(),
        ..A2aTaskUpdate::default()
    };
    assert!(
        transition_direct(
            app,
            ALICE,
            &id,
            &state::NON_TERMINAL,
            state::SUBMITTED,
            &reopen
        )
        .await,
        "B re-opens the task while A is WORKING"
    );
    let a_message = uuid::Uuid::new_v4().to_string();
    let entry = A2aHistoryEntry {
        message_id: a_message.clone(),
        role: "ROLE_USER".to_string(),
        context_id: "ctx-seed-8444".to_string(),
        task_id: id.clone(),
        memory_id: memory_a.clone(),
    };
    ai_memory::handlers::a2a_complete_message(app, ALICE, &id, entry)
        .await
        .expect("A's completion lands while B holds the task");
    let row = stored_task(app, ALICE, &id).await.expect("row");
    assert!(
        row.history.to_string().contains(&a_message),
        "A's acknowledged entry is in the task: {}",
        row.history
    );
    assert_eq!(row.state, state::SUBMITTED, "B's re-open is left in place");

    let mut m = message("interleave-b-8444", "ROLE_USER");
    m["taskId"] = json!(id);
    let b_message = m["messageId"].as_str().expect("message id").to_string();
    let b = rpc(router, ALICE_KEY, "SendMessage", &json!({"message": m})).await;
    assert_eq!(b.status, StatusCode::OK, "{}", b.json());
    let got = rpc(router, ALICE_KEY, "GetTask", &json!({"id": id})).await;
    let task = got.json()["result"].clone();
    assert_eq!(task["status"]["state"], json!(state::COMPLETED));
    let ids: Vec<String> = history_of(&got)
        .iter()
        .filter_map(|h| h["messageId"].as_str().map(str::to_string))
        .collect();
    assert_eq!(ids, vec![a_message, b_message], "both entries, in order");
    assert_eq!(
        task["artifacts"].as_array().map(Vec::len),
        Some(2),
        "both receipts"
    );

    // A completion whose task a concurrent continuation already COMPLETED
    // still appends (the COMPLETED source of the final compare-and-set).
    let c_message = uuid::Uuid::new_v4().to_string();
    let entry = A2aHistoryEntry {
        message_id: c_message.clone(),
        role: "ROLE_USER".to_string(),
        context_id: "ctx-seed-8444".to_string(),
        task_id: id.clone(),
        memory_id: memory_a.clone(),
    };
    ai_memory::handlers::a2a_complete_message(app, ALICE, &id, entry)
        .await
        .expect("a completion after a concurrent COMPLETED lands");
    let row = stored_task(app, ALICE, &id).await.expect("row");
    assert_eq!(row.state, state::COMPLETED);
    assert!(
        row.history.to_string().contains(&c_message),
        "the late completion's entry is in the task: {}",
        row.history
    );

    // A completion that finds the task CANCELED refuses (-32004 naming the
    // state) and leaves the task untouched.
    let ended = format!("interleave-ended-8444-{}", uuid::Uuid::new_v4());
    seed_working_task(app, ALICE, &ended).await;
    assert!(
        transition_direct(
            app,
            ALICE,
            &ended,
            &state::NON_TERMINAL,
            state::CANCELED,
            &reopen
        )
        .await
    );
    let entry = A2aHistoryEntry {
        message_id: uuid::Uuid::new_v4().to_string(),
        role: "ROLE_USER".to_string(),
        context_id: "ctx-seed-8444".to_string(),
        task_id: ended.clone(),
        memory_id: memory_a,
    };
    let err = ai_memory::handlers::a2a_complete_message(app, ALICE, &ended, entry)
        .await
        .expect_err("a completion on a CANCELED task is refused");
    assert_eq!(err.code, -32004, "{err:?}");
    assert!(err.message.contains(state::CANCELED), "{err:?}");
    let row = stored_task(app, ALICE, &ended).await.expect("row");
    assert_eq!(row.history, json!([]));
    assert_eq!(row.state, state::CANCELED);

    // Code LOW-1 (r4): a task in a wire state this server never writes
    // (non-terminal, outside both compare-and-set source sets) exhausts the
    // bounded loop. The exhaustion is the fail-closed catch-all: `-32004`
    // "modified concurrently" without "retry", and nothing is appended.
    let stuck = format!("interleave-stuck-8444-{}", uuid::Uuid::new_v4());
    seed_task(
        app,
        &SeedTask::new(ALICE, &stuck, "ctx-seed-8444", "TASK_STATE_INPUT_REQUIRED"),
    )
    .await;
    let entry = A2aHistoryEntry {
        message_id: uuid::Uuid::new_v4().to_string(),
        role: "ROLE_USER".to_string(),
        context_id: "ctx-seed-8444".to_string(),
        task_id: stuck.clone(),
        memory_id: receipt_memory_id(&first),
    };
    let err = ai_memory::handlers::a2a_complete_message(app, ALICE, &stuck, entry)
        .await
        .expect_err("an exhausted completion is refused, never a success");
    assert_eq!(err.code, -32004, "{err:?}");
    assert!(err.message.contains("modified concurrently"), "{err:?}");
    assert!(!err.message.contains("retry"), "{err:?}");
    let row = stored_task(app, ALICE, &stuck).await.expect("row");
    assert!(
        row.history.as_array().is_some_and(Vec::is_empty),
        "no entry: {}",
        row.history
    );
    assert!(
        row.artifacts.as_array().is_some_and(Vec::is_empty),
        "no receipt: {}",
        row.artifacts
    );
    assert_eq!(row.state, "TASK_STATE_INPUT_REQUIRED");
}

/// Moves one memory out of the caller's read scope through the backend's own
/// storage (a raw write no API caller can reach). Each test binary supplies
/// its backend's twin.
pub type ScopeMover =
    Box<dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>>;

/// The agent a moved memory is reassigned to.
pub const MALLORY: &str = "ai:mallory-8444";

/// The SQLite scope mover: the memory's owner and inbox target become
/// [`MALLORY`], so the caller-scoped read no longer returns it to `ALICE`.
pub fn sqlite_scope_mover(app: &AppState) -> ScopeMover {
    let db = Arc::clone(&app.db);
    Box::new(move |id: String| {
        let db = Arc::clone(&db);
        Box::pin(async move {
            let changed = db
                .lock()
                .await
                .0
                .execute(
                    "UPDATE memories SET metadata = json_set(metadata, '$.agent_id', ?1, \
                     '$.target_agent_id', ?1) WHERE id = ?2",
                    rusqlite::params![MALLORY, id],
                )
                .expect("move the memory out of scope");
            assert_eq!(changed, 1, "the memory row exists");
        })
    })
}

/// Code INFO-1 (r3): `GetTask` renders each linked memory through the
/// caller-scoped read on BOTH backends, so a linked memory moved out of the
/// caller's scope is omitted the same way on SQLite and PostgreSQL.
async fn history_render_is_caller_scoped(
    router: &axum::Router,
    app: &AppState,
    mover: &ScopeMover,
) {
    let kept = send_ok(router, ALICE_KEY, "scope-kept-8444", "ROLE_USER").await;
    let out_of_scope = send_ok(router, ALICE_KEY, "scope-moved-8444", "ROLE_USER").await;
    let id = format!("scope-8444-{}", uuid::Uuid::new_v4());
    seed_working_task(app, ALICE, &id).await;
    let entry = |memory_id: String| A2aHistoryEntry {
        message_id: uuid::Uuid::new_v4().to_string(),
        role: "ROLE_USER".to_string(),
        context_id: "ctx-seed-8444".to_string(),
        task_id: id.clone(),
        memory_id,
    };
    link_history(
        app,
        ALICE,
        &id,
        &[
            entry(receipt_memory_id(&kept)),
            entry(receipt_memory_id(&out_of_scope)),
        ],
    )
    .await;
    mover(receipt_memory_id(&out_of_scope)).await;
    let got = rpc(router, ALICE_KEY, "GetTask", &json!({"id": id})).await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.json());
    let texts: Vec<Value> = history_of(&got)
        .iter()
        .map(|h| h["parts"][0]["text"].clone())
        .collect();
    assert_eq!(texts, vec![json!("scope-kept-8444")]);
    assert!(!String::from_utf8_lossy(&got.body).contains("scope-moved-8444"));
    let own = rpc(
        router,
        ALICE_KEY,
        "GetTask",
        &json!({"id": out_of_scope["id"]}),
    )
    .await;
    assert_eq!(own.status, StatusCode::OK);
    assert!(history_of(&own).is_empty(), "{}", own.json());
}

/// A loopback federation peer that answers every push with `500`.
async fn spawn_failing_peer() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind failing peer");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 8192];
                let _ = socket.read(&mut buf).await;
                let body = "{}";
                let response = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    format!("http://{addr}/api/v1/sync/push")
}

/// Code INFO-2 (r3): a `SendMessage` whose federation fan-out misses quorum is
/// still durable locally, keeps its entry, is counted, and tells the caller
/// in the task status message (never a bare success).
async fn replication_pending_is_surfaced(app: &AppState) {
    let peer = ai_memory::federation::PeerEndpoint {
        id: "peer-failing-8444".to_string(),
        sync_push_url: spawn_failing_peer().await,
    };
    let config = ai_memory::federation::FederationConfig {
        policy: ai_memory::replication::QuorumPolicy::new(
            2,
            2,
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(30),
        )
        .expect("W=2 of 2 policy"),
        peers: vec![peer],
        client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("client"),
        sender_agent_id: "ai:a2a-8444-origin".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    };
    let mut fed_app = app.clone();
    fed_app.federation = Arc::new(Some(config));
    let (fed_router, _) = router(fed_app);
    let before = ai_memory::a2a::replication_pending_total();
    let task = send_ok(&fed_router, ALICE_KEY, "replication-8444", "ROLE_USER").await;
    assert_eq!(task["status"]["state"], json!(state::COMPLETED));
    assert_eq!(
        task["status"]["message"]["parts"][0]["text"],
        json!(ai_memory::a2a::REPLICATION_PENDING_TEXT),
        "{task}"
    );
    assert_eq!(task["status"]["message"]["role"], json!("ROLE_AGENT"));
    assert_eq!(
        task["history"][0]["parts"][0]["text"],
        json!("replication-8444")
    );
    assert!(ai_memory::a2a::replication_pending_total() > before);
    // Without a federation the status carries no such message.
    let (plain_router, _) = router(app.clone());
    let plain = send_ok(&plain_router, ALICE_KEY, "no-federation-8444", "ROLE_USER").await;
    assert!(plain["status"].get("message").is_none(), "{plain}");
}

/// Code MEDIUM-1 / sec MEDIUM-2 (lost compare-and-set): a continuation racing a
/// `CancelTask` is either accepted or answered `-32004` / HTTP 400, never `-32001`.
async fn continuation_racing_cancel_is_unsupported_operation(
    router: &axum::Router,
    app: &AppState,
) {
    for round in 0..8 {
        let id = format!("race-cont-8444-{round}-{}", uuid::Uuid::new_v4());
        seed_working_task(app, ALICE, &id).await;
        let mut m = message("racing", "ROLE_USER");
        m["taskId"] = json!(id);
        let params = json!({"message": m});
        let cancel_params = json!({"id": id});
        let (cont, cancel) = tokio::join!(
            rpc(router, ALICE_KEY, "SendMessage", &params),
            rpc(router, ALICE_KEY, "CancelTask", &cancel_params),
        );
        if cont.status != StatusCode::OK {
            assert_eq!(error_code(&cont), -32004, "round {round}: {}", cont.json());
            assert_eq!(cont.status, StatusCode::BAD_REQUEST);
            assert!(
                cont.json()["error"]["message"]
                    .as_str()
                    .is_some_and(|t| t.contains("TASK_STATE_") || t.contains("concurrently")),
                "{}",
                cont.json()
            );
        }
        assert!(
            cancel.status == StatusCode::OK || error_code(&cancel) == -32002,
            "round {round}: {}",
            cancel.json()
        );
    }
}

/// Code LOW-3 / LOW-9 / sec LOW-1: an unreadable stored task is a refused read
/// (`-32603`, HTTP 500, no substrate text), never a silently defaulted value.
async fn corrupt_stored_task_answers_internal_error(router: &axum::Router, app: &AppState) {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // The PostgreSQL decode path is pinned by the unit test
        // `corrupt_json_column_is_an_error_not_a_default`.
        return;
    }
    let id = format!("corrupt-8444-{}", uuid::Uuid::new_v4());
    seed_working_task(app, ALICE, &id).await;
    {
        let guard = app.db.lock().await;
        guard
            .0
            .execute(
                "UPDATE a2a_tasks SET history_json = ?1 WHERE id = ?2",
                rusqlite::params!["{not json: secret-substrate-text", id],
            )
            .expect("corrupt the column");
    }
    let got = rpc(router, ALICE_KEY, "GetTask", &json!({"id": id})).await;
    assert_eq!(got.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error_code(&got), -32603);
    let body = String::from_utf8_lossy(&got.body).to_string();
    for leak in [
        "secret-substrate-text",
        "history_json",
        "not json",
        "expected",
    ] {
        assert!(!body.contains(leak), "internal error leaks {leak}: {body}");
    }
    // The corrupt row is never overwritten by a continuation.
    let mut m = message("after corruption", "ROLE_USER");
    m["taskId"] = json!(id);
    let cont = rpc(router, ALICE_KEY, "SendMessage", &json!({"message": m})).await;
    assert_eq!(cont.status, StatusCode::INTERNAL_SERVER_ERROR);
    // Remove the corrupt fixture so later scenarios can read every row.
    app.db
        .lock()
        .await
        .0
        .execute("DELETE FROM a2a_tasks WHERE id = ?1", rusqlite::params![id])
        .expect("remove the corrupt fixture");
}

/// Code LOW-5: an active task older than the bound is retired to FAILED by the
/// same agent's next insert, so a non-terminal row cannot live forever.
async fn abandoned_active_tasks_are_retired(app: &AppState) {
    let agent = format!("ai:stale-8444-{}", uuid::Uuid::new_v4());
    let stale = format!("stale-8444-{}", uuid::Uuid::new_v4());
    let mut seed = SeedTask::new(&agent, &stale, "ctx-stale", state::WORKING);
    seed.timestamp = "2026-01-01T00:00:00.000Z".to_string();
    // The insert's own transaction retires an abandoned row (it is older than
    // the bound), so the row is FAILED as soon as it exists.
    seed_task(app, &seed).await;
    let fresh = format!("fresh-8444-{}", uuid::Uuid::new_v4());
    seed_task(
        app,
        &SeedTask::new(&agent, &fresh, "ctx-stale", state::WORKING),
    )
    .await;
    assert_eq!(
        stored_task(app, &agent, &stale).await.expect("row").state,
        state::FAILED,
        "the abandoned task was retired"
    );
    assert_eq!(
        stored_task(app, &agent, &fresh).await.expect("row").state,
        state::WORKING,
        "a recent active task is untouched"
    );
}

/// Code MEDIUM-3 / LOW-7: the card URL is configuration, not the request.
async fn card_url_ignores_request_headers(router: &axum::Router) {
    let plain = send(
        router,
        "GET",
        AGENT_CARD_PATH,
        &[(ai_memory::HEADER_API_KEY, ALICE_KEY)],
        Vec::new(),
    )
    .await;
    let hostile = send(
        router,
        "GET",
        AGENT_CARD_PATH,
        &[
            (ai_memory::HEADER_API_KEY, ALICE_KEY),
            ("host", "evil.example:6666"),
            ("x-forwarded-proto", "https"),
        ],
        Vec::new(),
    )
    .await;
    assert_eq!(plain.status, StatusCode::OK);
    assert_eq!(
        plain.body, hostile.body,
        "request headers never change the card"
    );
    assert!(!String::from_utf8_lossy(&hostile.body).contains("evil.example"));
    // A TLS daemon advertises https; a configured public URL wins.
    assert_eq!(
        ai_memory::a2a::resolve_card_base_url(None, true, "127.0.0.1:9077"),
        "https://127.0.0.1:9077"
    );
    assert_eq!(
        ai_memory::a2a::resolve_card_base_url(Some("https://mem.example.org"), false, "x:1"),
        "https://mem.example.org"
    );
}

/// Sec LOW-2: export carries the content-free task rows.
async fn export_carries_content_free_task_rows(router: &axum::Router, app: &AppState) {
    let marker = "export-marker-8444";
    let task = send_ok(router, ALICE_KEY, marker, "ROLE_USER").await;
    let id = task["id"].as_str().expect("id").to_string();
    let rows = export_tasks(app).await;
    let row = rows.iter().find(|r| r.id == id).expect("task is exported");
    assert_eq!(row.agent_id, ALICE);
    assert_eq!(row.history.as_array().map(Vec::len), Some(1));
    assert!(
        !serde_json::to_string(row)
            .expect("serialise")
            .contains(marker)
    );
}

/// Info 5: a content principal supplied in the request never survives.
async fn body_supplied_content_principal_never_survives(router: &axum::Router, app: &AppState) {
    let mut m = message("principal probe", "ROLE_USER");
    m["metadata"] = json!({"content_principal": "ai:body-claim-8444", "a2a_role": "ROLE_ADMIN"});
    let reply = rpc(
        router,
        ALICE_KEY,
        "SendMessage",
        &json!({"message": m, "metadata": {"content_principal": "ai:body-claim-8444"}}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.json());
    let task = reply.json()["result"]["task"].clone();
    let mem = stored_memory(app, ALICE, &receipt_memory_id(&task)).await;
    assert_eq!(mem.metadata["content_principal"], json!(ALICE));
    assert_eq!(mem.metadata["a2a_role"], json!("ROLE_USER"));
}

fn assert_no_leak(card: &Value, forbidden: &[&str]) {
    let text = card.to_string();
    for needle in forbidden {
        assert!(!text.contains(needle), "card leaks {needle}");
    }
}

/// Run every #8444 scenario against `app` (a fresh, empty backend);
/// `mover` is the backend's [`ScopeMover`].
pub async fn run_suite(app: AppState, mover: ScopeMover) {
    // Sec INFO-1 (r3): the screen mode is seeded explicitly, never inherited.
    ai_memory::secret_screen::set_screen_mode(ai_memory::secret_screen::SecretScreenMode::Off);
    assert_eq!(
        ai_memory::secret_screen::screen_mode(),
        ai_memory::secret_screen::SecretScreenMode::Off
    );
    let probe = app.clone();
    let (router, global) = router(app);

    card_is_authenticated_only(&router, &global).await;
    send_message_stamps_authenticated_principal(&router, &probe).await;
    task_access_is_caller_scoped(&router).await;
    unsupported_and_error_codes(&router).await;
    cancel_races_completion_once(&router, &probe).await;
    history_is_content_free_and_follows_erasure(&router, &probe).await;
    concurrent_continuations_keep_every_history_entry(&router, &probe).await;
    completion_survives_a_reopen_while_working(&router, &probe).await;
    history_render_is_caller_scoped(&router, &probe, &mover).await;
    continuation_racing_cancel_is_unsupported_operation(&router, &probe).await;
    corrupt_stored_task_answers_internal_error(&router, &probe).await;
    abandoned_active_tasks_are_retired(&probe).await;
    card_url_ignores_request_headers(&router).await;
    export_carries_content_free_task_rows(&router, &probe).await;
    body_supplied_content_principal_never_survives(&router, &probe).await;
    conformance::run_all(&router, &probe, &global).await;
    replication_pending_is_surfaced(&probe).await;
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
    // The caller owns the task, so it is a state error (-32004), not "not found".
    assert_eq!(cont.status, StatusCode::BAD_REQUEST);
    assert_eq!(error_code(&cont), -32004);
    assert!(
        cont.json()["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("TASK_STATE_COMPLETED")),
        "{}",
        cont.json()
    );
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
            .unwrap_or_else(|| panic!("GetTask answered no state: {}", got.json()))
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
