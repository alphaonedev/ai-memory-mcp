// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3555: real write receipts on both HTTP storage backends.
use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::http::Request;
use serde_json::{Value, json};
#[cfg(feature = "sal-postgres")]
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;
mod common;
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

/// Build a postgres-backed `AppState`. `app.db` is a throwaway in-memory
/// sqlite — deliberately EMPTY, so any handler that reads it instead of
/// `app.store` returns nothing and the test fails loudly.
#[cfg(feature = "sal-postgres")]
async fn postgres_app_state(url: &str) -> AppState {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store = SalStore(Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(url)
            .await
            .expect("connect postgres adapter"),
    ));
    app_state_with(db, StorageBackend::Postgres, store)
}

fn router(app: AppState) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    ai_memory::build_router(
        ApiKeyState {
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
        },
        app,
    )
}

async fn request(router: &axum::Router, method: &str, path: &str, body: Value) -> Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .header("x-agent-id", "receipt-agent-3555")
                .header("x-peer-id", "receipt-agent-3555")
                .body(Body::from(
                    serde_json::to_vec(&body).expect("encode request"),
                ))
                .expect("request"),
        )
        .await
        .expect("route");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let receipt: Value = serde_json::from_slice(&bytes).expect("receipt JSON");
    assert!(status.is_success(), "{method} {path}: {status} {receipt}");
    receipt
}

async fn exercise_local(app: AppState, fsync: &str) {
    let router = router(app);
    let nonce = uuid::Uuid::new_v4().to_string();
    let memory = |title: String| json!({"title": title, "content": "Durability receipt contract observation.", "namespace": "receipt3555"});
    let created = request(
        &router,
        "POST",
        "/api/v1/memories",
        memory(format!("create-{nonce}")),
    )
    .await;
    let id = created["id"].as_str().expect("created id");
    let updated = request(
        &router,
        "PUT",
        &format!("/api/v1/memories/{id}"),
        json!({"content": "Updated durability receipt observation."}),
    )
    .await;
    let bulk = request(
        &router,
        "POST",
        "/api/v1/memories/bulk",
        json!([memory(format!("bulk-{nonce}"))]),
    )
    .await;
    let capture_body = json!({"host_session_id": nonce, "host_turn_index": 0, "role": "user", "content": "Captured durability receipt observation."});
    let capture = request(
        &router,
        "POST",
        "/api/v1/capture_turn",
        capture_body.clone(),
    )
    .await;
    let replay = request(&router, "POST", "/api/v1/capture_turn", capture_body).await;
    assert_eq!(replay["dedup_hit"], true);
    let now = chrono::Utc::now().to_rfc3339();
    let replicated = json!({
        "id": uuid::Uuid::new_v4().to_string(), "tier": "long",
        "namespace": "receipt3555", "title": format!("sync-{nonce}"),
        "content": "Federated durability receipt observation.",
        "tags": [], "priority": 5, "confidence": 1.0, "source": "api",
        "access_count": 0, "created_at": now, "updated_at": now,
        "metadata": {"agent_id": "receipt-agent-3555"},
        "reflection_depth": 0, "memory_kind": "observation"
    });
    let synced = request(
        &router,
        "POST",
        "/api/v1/sync/push",
        json!({
            "sender_agent_id": "receipt-agent-3555", "sender_clock": {"entries": {}},
            "memories": [replicated], "dry_run": false
        }),
    )
    .await;
    assert_eq!(
        synced["applied"], 1,
        "sync must actually persist a row: {synced}"
    );
    for (funnel, receipt) in [
        ("create", created),
        ("update", updated),
        ("bulk", bulk),
        ("capture", capture),
        ("replay", replay),
        ("sync", synced),
    ] {
        assert_eq!(
            receipt["durability_class"], "local-only",
            "{funnel}: {receipt}"
        );
        assert_eq!(receipt["fsync"], fsync, "{funnel}: {receipt}");
    }
}

#[test]
fn sqlite_http_write_receipts_3555() {
    let root = std::env::var("CARGO_TARGET_DIR").expect("lane target directory");
    let scratch = tempfile::tempdir_in(root).expect("scratch");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    for (sync, fsync) in [("NORMAL", "per-checkpoint"), ("FULL", "per-commit")] {
        let _env = common::MultiEnvVarGuard::apply(&[
            ("AI_MEMORY_NO_CONFIG", Some("1")),
            ("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", Some("0")),
            ("AI_MEMORY_FED_REQUIRE_SIG", Some("0")),
            ("AI_MEMORY_FED_REQUIRE_WRITE_SIG", Some("0")),
            ("AI_MEMORY_FED_REQUIRE_POLICY_CURRENT", Some("0")),
            ("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", Some("0")),
            (
                "AI_MEMORY_FED_PEER_ATTESTATION",
                Some(
                    r#"{"receipt-agent-3555":{"allowed_namespaces":["receipt3555"],"allowed_sender_agent_ids":["receipt-agent-3555"]}}"#,
                ),
            ),
            ("AI_MEMORY_DB_SYNCHRONOUS", Some(sync)),
        ]);
        runtime.block_on(exercise_local(
            sqlite_app_state(&scratch.path().join(format!("{sync}.db"))),
            fsync,
        ));
    }
}

#[cfg(feature = "sal-postgres")]
#[test]
fn postgres_http_write_receipts_3555() {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("fresh ai_memory_codex_3555 URL required");
    assert!(
        url.split('?')
            .next()
            .is_some_and(|url| url.ends_with("/ai_memory_codex_3555")),
        "only the lane database is allowed"
    );
    let _env = common::MultiEnvVarGuard::apply(&[
        ("AI_MEMORY_NO_CONFIG", Some("1")),
        ("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", Some("0")),
        ("AI_MEMORY_FED_REQUIRE_SIG", Some("0")),
        ("AI_MEMORY_FED_REQUIRE_WRITE_SIG", Some("0")),
        ("AI_MEMORY_FED_REQUIRE_POLICY_CURRENT", Some("0")),
        ("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", Some("0")),
        (
            "AI_MEMORY_FED_PEER_ATTESTATION",
            Some(
                r#"{"receipt-agent-3555":{"allowed_namespaces":["receipt3555"],"allowed_sender_agent_ids":["receipt-agent-3555"]}}"#,
            ),
        ),
    ]);
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        exercise_local(postgres_app_state(&url).await, "per-commit").await;
        let separator = if url.contains('?') { '&' } else { '?' };
        let asynchronous = format!("{url}{separator}options=-c%20synchronous_commit%3Doff");
        exercise_local(
            postgres_app_state(&asynchronous).await,
            "asynchronous WAL flush",
        )
        .await;
    });
}

async fn exercise_quorum(mut app: AppState) {
    use ai_memory::federation::{FederationConfig, PeerEndpoint};
    use ai_memory::replication::QuorumPolicy;
    use std::time::Duration;
    fn acknowledge(
        axum::Json(payload): axum::Json<Value>,
    ) -> std::future::Ready<axum::Json<Value>> {
        std::future::ready(axum::Json(
            json!({"applied": 1, "noop": 0, "skipped": 0, "ids": [payload["memories"][0]["id"]]}),
        ))
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind peer");
    let address = listener.local_addr().expect("peer address");
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            axum::Router::new().route("/sync", axum::routing::post(acknowledge)),
        )
        .await
        .expect("peer serve");
    });
    app.federation = Arc::new(Some(FederationConfig {
        policy: QuorumPolicy::new(2, 2, Duration::from_secs(5), Duration::from_secs(30))
            .expect("policy"),
        peers: vec![PeerEndpoint {
            id: "receipt-peer-3555".to_owned(),
            sync_push_url: format!("http://{address}/sync"),
        }],
        client: reqwest::Client::new(),
        sender_agent_id: "receipt-agent-3555".to_owned(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }));
    let router = router(app);
    let captured = request(
        &router,
        "POST",
        "/api/v1/capture_turn",
        json!({
            "host_session_id": uuid::Uuid::new_v4().to_string(), "host_turn_index": 0,
            "role": "user", "content": "Configured mesh alone is not acknowledgement evidence."
        }),
    )
    .await;
    assert_eq!(captured["durability_class"], "local-only", "{captured}");
    let receipt = request(&router, "POST", "/api/v1/memories", json!({"title": uuid::Uuid::new_v4().to_string(), "content": "Quorum receipt evidence observation.", "namespace": "receipt3555"})).await;
    let backed_up =
        std::env::var("AI_MEMORY_BACKUP_POSTURE_ATTESTATION").is_ok_and(|v| v == "attested");
    assert_eq!(
        receipt["durability_class"],
        if backed_up {
            "replicated+backup"
        } else {
            "quorum 2-of-2"
        },
        "{receipt}"
    );
    assert_eq!(receipt["quorum_acks"], 2, "{receipt}");
    assert_eq!(receipt["quorum_n"], 2, "{receipt}");
    server.abort();
    let _ = server.await;
}

#[test]
fn sqlite_http_quorum_and_backup_receipts_3555() {
    let root = std::env::var("CARGO_TARGET_DIR").expect("lane target directory");
    let scratch = tempfile::tempdir_in(root).expect("scratch");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let _ = ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_| Ok(())));
    for backup in [None, Some("attested")] {
        let _env = common::MultiEnvVarGuard::apply(&[
            ("AI_MEMORY_NO_CONFIG", Some("1")),
            ("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", Some("0")),
            ("AI_MEMORY_FED_REQUIRE_SIG", Some("0")),
            ("AI_MEMORY_FED_REQUIRE_WRITE_SIG", Some("0")),
            ("AI_MEMORY_FED_REQUIRE_POLICY_CURRENT", Some("0")),
            ("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", Some("0")),
            (
                "AI_MEMORY_FED_PEER_ATTESTATION",
                Some(
                    r#"{"receipt-agent-3555":{"allowed_namespaces":["receipt3555"],"allowed_sender_agent_ids":["receipt-agent-3555"]}}"#,
                ),
            ),
            ("AI_MEMORY_BACKUP_POSTURE_ATTESTATION", backup),
        ]);
        runtime.block_on(exercise_quorum(sqlite_app_state(
            &scratch.path().join(format!("{}.db", uuid::Uuid::new_v4())),
        )));
    }
}

#[cfg(feature = "sal-postgres")]
#[test]
fn postgres_http_quorum_and_backup_receipts_3555() {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("fresh ai_memory_codex_3555 URL required");
    assert!(
        url.split('?')
            .next()
            .is_some_and(|url| url.ends_with("/ai_memory_codex_3555")),
        "only the lane database is allowed"
    );
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let _ = ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_| Ok(())));
    for backup in [None, Some("attested")] {
        let _env = common::MultiEnvVarGuard::apply(&[
            ("AI_MEMORY_NO_CONFIG", Some("1")),
            ("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", Some("0")),
            ("AI_MEMORY_FED_REQUIRE_SIG", Some("0")),
            ("AI_MEMORY_FED_REQUIRE_WRITE_SIG", Some("0")),
            ("AI_MEMORY_FED_REQUIRE_POLICY_CURRENT", Some("0")),
            ("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", Some("0")),
            (
                "AI_MEMORY_FED_PEER_ATTESTATION",
                Some(
                    r#"{"receipt-agent-3555":{"allowed_namespaces":["receipt3555"],"allowed_sender_agent_ids":["receipt-agent-3555"]}}"#,
                ),
            ),
            ("AI_MEMORY_BACKUP_POSTURE_ATTESTATION", backup),
        ]);
        runtime.block_on(async {
            exercise_quorum(postgres_app_state(&url).await).await;
        });
    }
}
