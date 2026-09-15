// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3646 actual-router scope sweep and metadata non-disclosure, both backends.
use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::monitoring::{METRICS_PATH, MonitoringConfig, STATUS_PATH};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::Value;
#[cfg(feature = "sal-postgres")]
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;
const MONITOR: &str = "ai:monitor-3646";
const TOKEN: &str = "SECRET_KEY_MATERIAL_3646";
const CONTENT: &str = "TENANT_CONTENT_CANARY_3646";
const POLICY: &str = "PRIVATE_POLICY_CANARY_3646";
const DSN: &str = "postgres://user:DSN_PASSWORD_CANARY_3646@invalid/db";
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

fn router(mut app: AppState, tls: bool, shared: bool) -> (axum::Router, Arc<EnrolledAgentKeys>) {
    let registry = Arc::new(
        EnrolledAgentKeys::from_map(
            [(api_key_sha256_hex(TOKEN), MONITOR.to_owned())]
                .into_iter()
                .collect(),
        )
        .with_monitoring(
            MonitoringConfig {
                agent_ids: vec![MONITOR.to_owned()],
                peer_ids: vec![MONITOR.to_owned()],
            },
            tls,
        ),
    );
    app.enrolled_agent_keys = Arc::clone(&registry);
    let auth = ApiKeyState {
        // Deliberate global/enrolled collision: restrictive scope must win.
        key: shared.then(|| TOKEN.to_owned()),
        mtls_enforced: true,
        enrolled_agent_keys: Arc::clone(&registry),
        identity_mode: ai_memory::config::HttpIdentityMode::Off,
    };
    (ai_memory::build_router(auth, app), registry)
}

async fn request(
    router: &axum::Router,
    path: &str,
    method: &str,
    key: bool,
    cert: bool,
) -> (StatusCode, String) {
    let mut req = Request::builder()
        .uri(path)
        .method(method)
        .header(ai_memory::HEADER_AGENT_ID, "ai:spoofed-admin")
        .header("x-forwarded-proto", "https");
    if key {
        req = req.header(ai_memory::HEADER_API_KEY, TOKEN);
    }
    let mut req = req.body(Body::from("{}")).unwrap();
    if cert {
        req.extensions_mut()
            .insert(ai_memory::tls::ClientCertPeerId(Some(MONITOR.to_owned())));
    }
    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    if path == METRICS_PATH && status == StatusCode::OK {
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            ai_memory::handlers::monitoring::PROMETHEUS_CONTENT_TYPE
        );
    }
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

/// Axum exposes its actual path tree in `Debug` (including merged/fallback routes).
/// Walk those quoted paths; do not maintain a second route inventory. A changed
/// Debug contract fails closed through the count/membership assertions below.
fn actual_paths(router: &axum::Router) -> std::collections::BTreeSet<String> {
    format!("{router:?}")
        .split('"')
        .filter(|s| s.starts_with('/'))
        .map(str::to_owned)
        .collect()
}

async fn sweep(app: AppState) {
    let (router, _) = router(app, true, true);
    let paths = actual_paths(&router);
    // Axum installs both `/` and its private catch-all in the fallback router.
    // They remain in the sweep below; the count includes both fallback paths.
    assert_eq!(
        paths.len(),
        ai_memory::EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT + 2,
        "actual router traversal must cover every registration and fallback",
    );
    assert!(paths.contains(STATUS_PATH));
    assert!(paths.contains(ai_memory::handlers::routes::MEMORIES));
    let mut refused = 0;
    for path in paths {
        let concrete = path
            .split('/')
            .map(|s| if s.starts_with('{') { "canary" } else { s })
            .collect::<Vec<_>>()
            .join("/");
        for method in [
            "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT",
        ] {
            if ai_memory::handlers::monitoring::is_health_path(&path)
                && matches!(method, "GET" | "HEAD")
            {
                continue;
            }
            for (key, cert) in [(true, false), (false, true), (true, true)] {
                let (status, _) = request(&router, &concrete, method, key, cert).await;
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{method} {path} key={key} cert={cert}"
                );
                refused += 1;
            }
        }
    }
    // Also prove fallback protection, independent of the router's registrations.
    assert_eq!(
        request(&router, "/future-route-3646", "POST", true, false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    eprintln!("#3646 actual router sweep: {refused} monitoring requests refused");
}

#[tokio::test]
async fn issue_3646_sqlite_every_actual_route_refuses_monitoring() {
    let dir = tempfile::tempdir().unwrap();
    sweep(sqlite_app_state(&dir.path().join("test.db"))).await;
}

#[tokio::test]
async fn issue_3646_tls_auth_revocation_and_health_contract() {
    let dir = tempfile::tempdir().unwrap();
    let app = sqlite_app_state(&dir.path().join("test.db"));
    let (plain, _) = router(app.clone(), false, false);
    assert_eq!(
        request(&plain, STATUS_PATH, "GET", true, false).await.0,
        StatusCode::FORBIDDEN
    );
    let (secure, keys) = router(app, true, false);
    assert_eq!(
        request(&secure, STATUS_PATH, "GET", false, false).await.0,
        StatusCode::UNAUTHORIZED
    );
    for (key, cert) in [(true, false), (false, true)] {
        let (code, body) = request(&secure, STATUS_PATH, "GET", key, cert).await;
        assert_eq!(code, StatusCode::OK, "{body}");
        let value: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["schema_version"], 1);
        for field in [
            "software_version",
            "observed_at_seconds",
            "status",
            "reasons",
            "backend",
            "database_schema_version",
            "posture",
            "singleton",
            "federation",
            "wake",
            "logging_delivery",
            "webhook_audit_delivery",
            "read_audit_delivery",
            "restore_evidence",
        ] {
            assert!(value.get(field).is_some(), "missing v1 field {field}");
        }
        assert_eq!(value["status"], "degraded");
        assert_eq!(value["wake"]["fallback_state"]["issue"], 3657);
        assert!(value["database_schema_version"].as_i64().unwrap() > 0);
        let (code, body) = request(&secure, METRICS_PATH, "GET", key, cert).await;
        assert_eq!(code, StatusCode::OK);
        assert!(
            body.contains("# TYPE ai_memory_admission_shed_total counter"),
            "{body}"
        );
    }
    keys.install(std::collections::HashMap::new());
    assert_eq!(
        request(&secure, STATUS_PATH, "GET", true, false).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &secure,
            ai_memory::handlers::routes::MEMORIES,
            "POST",
            true,
            false
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}

async fn assert_no_disclosure(mut app: AppState) {
    app.federation = Arc::new(Some(ai_memory::federation::FederationConfig {
        policy: ai_memory::replication::QuorumPolicy::new(
            2,
            1,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        )
        .unwrap(),
        peers: vec![ai_memory::federation::PeerEndpoint {
            id: DSN.to_owned(),
            sync_push_url: DSN.to_owned(),
        }],
        client: reqwest::Client::new(),
        sender_agent_id: DSN.to_owned(),
        api_key: Some(TOKEN.to_owned()),
        signing_key: None,
        dlq_sink: None,
    }));
    // Pollute a label-bearing global collector: health must not forward it.
    ai_memory::metrics::registry()
        .store_total
        .with_label_values(&[CONTENT, POLICY])
        .inc();
    let (router, _) = router(app, true, false);
    for path in [STATUS_PATH, METRICS_PATH] {
        let (code, body) = request(&router, path, "GET", true, false).await;
        assert_eq!(code, StatusCode::OK, "{body}");
        if path == STATUS_PATH {
            let value: Value = serde_json::from_str(&body).unwrap();
            let peer = &value["federation"]["peers"][0];
            assert_eq!(peer["last_successful_push_age_seconds"]["issue"], 3654);
            assert_eq!(peer["reachability"]["state"], "unavailable");
            assert_eq!(peer["identity_ref"], api_key_sha256_hex(DSN));
        }
        for canary in [CONTENT, POLICY, TOKEN, DSN, "DSN_PASSWORD_CANARY_3646"] {
            assert!(!body.contains(canary), "{path} leaked {canary}");
        }
    }
}

#[tokio::test]
async fn issue_3646_sqlite_seeded_payloads_are_metadata_only() {
    let dir = tempfile::tempdir().unwrap();
    let app = sqlite_app_state(&dir.path().join("test.db"));
    {
        let db = app.db.lock().await;
        db.0.execute("INSERT INTO memories (id,tier,namespace,title,content,tags,priority,confidence,source,access_count,created_at,updated_at,metadata) VALUES ('3646','long','private',?1,?1,'[]',5,1.0,'api',0,datetime('now'),datetime('now'),?2)", rusqlite::params![CONTENT, serde_json::json!({"policy": POLICY, "dsn": DSN, "key": TOKEN}).to_string()]).unwrap();
        db.0.execute("INSERT INTO namespace_meta (namespace, standard_id, updated_at) VALUES ('private','3646',datetime('now'))", []).unwrap();
        db.0.execute("INSERT INTO memories (id,tier,namespace,title,content,tags,priority,confidence,source,access_count,created_at,updated_at,metadata) SELECT 'inbox3646',tier,'_inbox/ai:private',title,?1,tags,priority,confidence,source,access_count,created_at,updated_at,metadata FROM memories WHERE id='3646'", [POLICY]).unwrap();
        assert_eq!(
            db.0.query_row("SELECT content FROM memories WHERE id='3646'", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap(),
            CONTENT
        );
    }
    assert_no_disclosure(app).await;
}

#[tokio::test]
async fn issue_3646_store_failure_is_failing_without_error_content() {
    let dir = tempfile::tempdir().unwrap();
    let app = sqlite_app_state(&dir.path().join("test.db"));
    app.db
        .lock()
        .await
        .0
        .execute_batch("DROP TABLE memories_fts")
        .unwrap();
    let (router, _) = router(app, true, false);
    let (code, body) = request(&router, STATUS_PATH, "GET", true, false).await;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["status"],
        "failing"
    );
    assert!(!body.contains("no such table"));
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn issue_3646_postgres_routes_and_seeded_non_disclosure() {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("dedicated #3646 postgres database required");
    assert!(
        url.ends_with("/ai_memory_codex_3646"),
        "never use an operator database"
    );
    let app = postgres_app_state(&url).await;
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    sqlx::query("INSERT INTO memories (id,tier,namespace,title,content,tags,priority,confidence,source,access_count,created_at,updated_at,metadata) VALUES ('3646','long','private',$1,$1,'[]',5,1.0,'api',0,NOW(),NOW(),$2) ON CONFLICT (id) DO NOTHING")
        .bind(CONTENT).bind(serde_json::json!({"policy": POLICY, "dsn": DSN, "key": TOKEN})).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO namespace_meta (namespace, standard_id, updated_at) VALUES ('private','3646',NOW()) ON CONFLICT (namespace) DO NOTHING").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO memories (id,tier,namespace,title,content,source) VALUES ('inbox3646','long','_inbox/ai:private',$1,$1,'api') ON CONFLICT (id) DO NOTHING").bind(POLICY).execute(&pool).await.unwrap();
    let content: String = sqlx::query_scalar("SELECT content FROM memories WHERE id='3646'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(content, CONTENT);
    sweep(app.clone()).await;
    assert_no_disclosure(app).await;
    pool.close().await;
}

#[tokio::test]
async fn issue_3646_real_mtls_monitor_cannot_write() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let app = sqlite_app_state(&dir.path().join("test.db"));
    let (router, _) = router(app, true, false);
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
    let allowlist = dir.path().join("allowlist");
    let fingerprint = std::fs::read_to_string(fixtures.join("valid_cert_sha256.txt")).unwrap();
    std::fs::write(&allowlist, &fingerprint).unwrap();
    let tls = ai_memory::tls::load_mtls_rustls_config(
        &fixtures.join("valid_cert.pem"),
        &fixtures.join("valid_key_pkcs8.pem"),
        &allowlist,
    )
    .await
    .unwrap();
    let fingerprints = ai_memory::tls::load_fingerprint_allowlist(&allowlist)
        .await
        .unwrap();
    let bindings = fingerprints
        .into_iter()
        .map(|fp| (fp, MONITOR.to_owned()))
        .collect();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    let server = tokio::spawn(async move {
        axum_server::from_tcp(listener)
            .unwrap()
            .acceptor(ai_memory::tls::serve_rustls_acceptor_with_peer_binding(
                &tls, bindings,
            ))
            .handle(server_handle)
            .serve(router.into_make_service())
            .await
            .unwrap();
    });
    let mut pem = std::fs::read(fixtures.join("valid_cert.pem")).unwrap();
    pem.extend(std::fs::read(fixtures.join("valid_key_pkcs8.pem")).unwrap());
    let client = reqwest::Client::builder()
        // Committed self-signed fixture; the server still enforces its allowlist.
        .danger_accept_invalid_certs(true)
        .identity(reqwest::Identity::from_pem(&pem).unwrap())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let response = client
        .get(format!("https://{addr}{STATUS_PATH}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.json::<Value>().await.unwrap()["schema_version"], 1);
    let response = client
        .post(format!(
            "https://{addr}{}",
            ai_memory::handlers::routes::MEMORIES
        ))
        .json(&serde_json::json!({"content": CONTENT}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let anonymous = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    assert!(
        anonymous
            .get(format!("https://{addr}{STATUS_PATH}"))
            .send()
            .await
            .is_err()
    );
    handle.shutdown();
    server.await.unwrap();
}
