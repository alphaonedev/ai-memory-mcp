// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3578: hub credentials confer no memory-write authority. HTTP exercises
//! the real router, API-key binding, and both adapters. MCP exercises its
//! production handler via the existing test entry, locally and forwarded to
//! a real loopback HTTP listener. This is not stdio framing or OS isolation.
//! TEST-02: every denial compares all memory rows before/after; legitimate
//! root signatures and independently enrolled API keys are positive controls.

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::{
    hub_delegation::{self, A2A_HUB_SCOPE, DelegationWire},
    keypair::{self, AgentKeypair},
    test_agent_id::AgentIdOverride,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
#[cfg(feature = "sal-postgres")]
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

mod common;
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
const CALLER: &str = "ai:write-owner-3578";
const FORGED: &str = "ai:write-forged-3578";
const TARGET: &str = "ai:write-recipient-3578";
// Test-only credentials generated per fixture; no operator material is read.

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

fn router(mut app: AppState, token: Option<&str>) -> axum::Router {
    use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
    let enrolled = Arc::new(EnrolledAgentKeys::from_map(
        token
            .map(|t| (api_key_sha256_hex(t), CALLER.to_owned()))
            .into_iter()
            .collect(),
    ));
    app.enrolled_agent_keys = Arc::clone(&enrolled);
    app.http_identity_mode = ai_memory::config::HttpIdentityMode::Enforce;
    ai_memory::build_router(
        ApiKeyState {
            key: token.map(|_| uuid::Uuid::new_v4().to_string()),
            mtls_enforced: false,
            enrolled_agent_keys: enrolled,
            identity_mode: ai_memory::config::HttpIdentityMode::Enforce,
        },
        app,
    )
}

struct Fixture {
    app: AppState,
    root: AgentKeypair,
    delegate: SigningKey,
    wire: DelegationWire,
    token: String,
    #[cfg(feature = "sal-postgres")]
    pool: Option<sqlx::PgPool>,
}

impl Fixture {
    fn new(app: AppState) -> Self {
        let root = keypair::generate(CALLER).expect("fixture root");
        let delegate = SigningKey::from_bytes(&[79; 32]);
        let now = chrono::Utc::now();
        let mut wire = DelegationWire {
            principal: CALLER.to_owned(),
            scope: A2A_HUB_SCOPE.to_owned(),
            delegate_key_id: delegate.verifying_key().to_bytes(),
            hub_id: "hub3578".into(),
            not_before: (now - chrono::Duration::seconds(1))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            not_after: (now + chrono::Duration::minutes(30))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            signature: [0; 64],
        };
        wire.signature = hub_delegation::sign_hub_delegation(
            root.private.as_ref().expect("root private"),
            &wire.as_delegation(),
        )
        .expect("sign hub delegation");
        let encoded = wire.encode().expect("encode delegation");
        let decoded = DelegationWire::decode(&encoded).expect("decode delegation");
        hub_delegation::verify_hub_delegation(
            &root.public,
            &decoded.as_delegation(),
            &decoded.signature,
        )
        .expect("VALID hub-domain signature");
        hub_delegation::check_ttl(&decoded.as_delegation()).expect("bounded TTL");
        hub_delegation::check_validity(&decoded.as_delegation(), &now.to_rfc3339())
            .expect("currently valid");
        Self {
            app,
            root,
            delegate,
            wire,
            token: uuid::Uuid::new_v4().to_string(),
            #[cfg(feature = "sal-postgres")]
            pool: None,
        }
    }

    fn prove_hub_admission(
        &mut self,
        entry: ai_memory::wake_hub::delegation_verifier::AllowlistEntry,
    ) {
        use ai_memory::wake_hub::delegation_verifier::{AllowlistCache, ScopedDelegationVerifier};
        use ai_memory::wake_hub::identity::{
            HelloRequest, HelloVerifier as _, PeerCred, hello_transcript, topics_hash,
        };
        // Mint AFTER the real possession binding; check the exported bound_at
        // and authority with the production verifier, including #3540 ordering.
        self.wire.not_before =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        self.wire.signature = hub_delegation::sign_hub_delegation(
            self.root.private.as_ref().expect("root"),
            &self.wire.as_delegation(),
        )
        .expect("mint after binding");
        let dir = tempfile::tempdir().expect("public snapshot directory");
        let path = dir.path().join("public.json");
        ai_memory::identity::hub_cache::publish(
            &path,
            &ai_memory::wake_hub::delegation_verifier::AllowlistFile {
                version: ai_memory::wake_hub::delegation_verifier::ALLOWLIST_FILE_VERSION,
                refreshed_at: Some(chrono::Utc::now().to_rfc3339()),
                agents: vec![entry],
            },
        )
        .expect("publish fixture public snapshot");
        let cache =
            AllowlistCache::load_from_file(&path).expect("load backend-derived public snapshot");
        let verifier = ScopedDelegationVerifier::new(cache);
        let nonce = [3; 32];
        let topics = vec![format!("#_inbox/{CALLER}")];
        let signature = self
            .delegate
            .sign(&hello_transcript(
                &self.wire.hub_id,
                &nonce,
                CALLER,
                &topics_hash(&topics),
            ))
            .to_bytes();
        let wire = self.wire.encode().expect("valid delegation wire");
        let admitted = verifier
            .verify(&HelloRequest {
                hub_id: &self.wire.hub_id,
                nonce: &nonce,
                claimed_agent_id: CALLER,
                pubkey: &self.wire.delegate_key_id,
                signature: &signature,
                delegation: &wire,
                topics: &topics,
                peer: PeerCred {
                    uid: 1000,
                    gid: 1000,
                    pid: Some(42),
                },
            })
            .expect("same credential ADMITTED by production hub verifier");
        assert_eq!(admitted.agent_id, CALLER);
        assert_eq!(admitted.pubkey, self.delegate.verifying_key().to_bytes());
    }

    fn delegation(&self) -> String {
        STANDARD.encode(self.wire.encode().expect("wire"))
    }

    fn memory(&self) -> Value {
        let created = ai_memory::identity::attest::now_attestable_rfc3339();
        let mut body = json!({"title": uuid::Uuid::new_v4().to_string(),
            "content":"A concrete observation for the wake authority boundary regression.",
            "namespace":"wake-authority-3578", "tier":"mid", "kind":"observation",
            "agent_id":CALLER, "created_at":created, "why_trace":"#3578 allowed control",
            "metadata":{"why_trace":"#3578 allowed control"}});
        body["signature"] = json!(sign_body(
            &body,
            self.root.private.as_ref().expect("root private")
        ));
        body
    }

    async fn snapshot(&self) -> Value {
        #[cfg(feature = "sal-postgres")]
        if let Some(pool) = &self.pool {
            let rows: Vec<Value> =
                sqlx::query_scalar("SELECT to_jsonb(m) FROM memories m ORDER BY id")
                    .fetch_all(pool)
                    .await
                    .expect("snapshot LIVE postgres memory rows");
            // A mistaken dispatch into the SQLite shadow must also fail this pin.
            return json!({"pg":rows, "shadow":sqlite_snapshot(&self.app.db.lock().await.0)});
        }
        sqlite_snapshot(&self.app.db.lock().await.0)
    }

    async fn row(&self, id: &str) -> Value {
        #[cfg(feature = "sal-postgres")]
        if let Some(pool) = &self.pool {
            return sqlx::query_scalar("SELECT to_jsonb(m) FROM memories m WHERE id=$1")
                .bind(id)
                .fetch_one(pool)
                .await
                .expect("LIVE persisted row");
        }
        serde_json::to_value(
            ai_memory::db::get(&self.app.db.lock().await.0, id)
                .expect("read row")
                .expect("persisted row"),
        )
        .expect("serialize memory")
    }
}

fn sqlite_snapshot(conn: &rusqlite::Connection) -> Value {
    let mut stmt = conn
        .prepare("SELECT * FROM memories ORDER BY id")
        .expect("snapshot query");
    let columns = stmt.column_count();
    let rows = stmt
        .query_map([], |r| {
            (0..columns)
                .map(|i| {
                    r.get::<_, rusqlite::types::Value>(i)
                        .map(|v| format!("{v:?}"))
                })
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .expect("snapshot rows")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("all memory columns");
    json!(rows)
}

async fn post(
    router: &axum::Router,
    path: &str,
    token: Option<&str>,
    caller: Option<&str>,
    body: &Value,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header(ai_memory::HEADER_API_KEY, token);
    }
    if let Some(caller) = caller {
        request = request.header(ai_memory::HEADER_AGENT_ID, caller);
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(Body::from(serde_json::to_vec(body).expect("body")))
                .expect("request"),
        )
        .await
        .expect("route");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("response");
    (
        status,
        serde_json::from_slice(&bytes).expect("JSON response"),
    )
}

fn forged_fields(f: &Fixture) -> Value {
    json!({"principal":FORGED,"sender":FORGED,"from":FORGED,
        "namespace":"_inbox/ai:write-forged-3578", "scope":A2A_HUB_SCOPE,
        "delegation":f.delegation(), "inbox_row_id":"forged-row", "seq":99})
}

async fn exercise_http(f: &Fixture) {
    let router = router(f.app.clone(), Some(&f.token));
    let before = f.snapshot().await;
    let hints = forged_fields(f);
    let mut notify = json!({"target_agent_id":TARGET,"title":"wake-3578-notify",
        "payload":"A legitimate content-plane notification.","why_trace":"#3578 boundary test"});
    notify
        .as_object_mut()
        .expect("object")
        .extend(hints.as_object().expect("hints").clone());
    // A signature that is valid for hub admission, its full wire envelope,
    // and its delegated public key are not enrolled API credentials.
    let credential_forms = [
        f.delegation(),
        STANDARD.encode(f.wire.signature),
        STANDARD.encode(f.wire.delegate_key_id),
    ];
    for token in std::iter::once(None).chain(credential_forms.iter().map(|t| Some(t.as_str()))) {
        for (path, body) in [
            (ai_memory::handlers::routes::NOTIFY, notify.clone()),
            ("/api/v1/memories", f.memory()),
        ] {
            let (status, result) = post(&router, path, token, Some(CALLER), &body).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{result}");
            assert_eq!(result["error"], "missing or invalid API key");
            assert_eq!(
                f.snapshot().await,
                before,
                "API credential refusal must not mutate memory rows"
            );
        }
    }
    for claim in [FORGED, A2A_HUB_SCOPE, "a2a-hub/join/v1"] {
        let (status, result) = post(
            &router,
            ai_memory::handlers::routes::NOTIFY,
            Some(&f.token),
            Some(claim),
            &notify,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{result}");
        assert_eq!(result["error"], "identity_binding_mismatch");
        let mut body = notify.clone();
        body["agent_id"] = json!(claim);
        let (status, result) = post(
            &router,
            ai_memory::handlers::routes::NOTIFY,
            Some(&f.token),
            None,
            &body,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{result}");
        assert_eq!(
            f.snapshot().await,
            before,
            "header/body claims must not create a row"
        );
    }
    let before = f.snapshot().await;
    for mut body in denied_writes(f) {
        body.as_object_mut()
            .expect("object")
            .insert("delegation".into(), json!(f.delegation()));
        let (status, result) = post(&router, "/api/v1/memories", Some(&f.token), None, &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{result}");
        assert_eq!(result["code"], "ATTESTATION_FAILED");
        assert_eq!(
            f.snapshot().await,
            before,
            "write attestation refusal must not mutate rows"
        );
    }
    let body = f.memory();
    let (status, result) = post(&router, "/api/v1/memories", Some(&f.token), None, &body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    let row = f.row(result["id"].as_str().expect("memory id")).await;
    assert_eq!(row["metadata"]["agent_id"], CALLER);
    assert_eq!(row["metadata"]["attest_level"], "agent_attested");
    assert_eq!(row["content"], body["content"]);
    // Actual API credential resolves CALLER even without a claimed header.
    // Hostile hint fields may be ignored; acceptance must never imply that
    // those fields authenticated the request or selected its write namespace.
    let (status, result) = post(
        &router,
        ai_memory::handlers::routes::NOTIFY,
        Some(&f.token),
        None,
        &notify,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    let row = f.row(result["id"].as_str().expect("notify id")).await;
    assert_eq!(row["metadata"]["agent_id"], CALLER);
    assert_eq!(row["namespace"], ai_memory::inbox_namespace(TARGET));
    assert_eq!(row["content"], notify["payload"]);
}

fn denied_writes(f: &Fixture) -> Vec<Value> {
    let mut domain = f.memory();
    domain["signature"] = json!(STANDARD.encode(f.wire.signature));
    let mut delegated = f.memory();
    delegated["signature"] = json!(sign_body(&delegated, &f.delegate));
    vec![domain, delegated]
}

fn mcp_store(
    conn: &rusqlite::Connection,
    body: &Value,
    forward: Option<&str>,
) -> Result<Value, String> {
    ai_memory::mcp::tools::handle_store_for_tests(
        conn,
        std::path::Path::new(":memory:"),
        body,
        None,
        None,
        None,
        &ResolvedTtl::default(),
        false,
        None,
        forward,
    )
}

fn exercise_mcp(
    f: &Fixture,
    conn: &rusqlite::Connection,
    forward: Option<&str>,
    rt: &tokio::runtime::Runtime,
) {
    let _caller = AgentIdOverride::set(CALLER);
    let before = rt.block_on(f.snapshot());
    for mut body in denied_writes(f) {
        body["delegation"] = json!(f.delegation());
        let err = mcp_store(conn, &body, forward)
            .expect_err("hub/delegate signature has no write authority");
        assert!(
            err.contains("attestation") || err.contains("signature"),
            "{err}"
        );
        assert_eq!(rt.block_on(f.snapshot()), before);
    }
    for claim in [FORGED, A2A_HUB_SCOPE, "a2a-hub/join/v1"] {
        let mut body = f.memory();
        body["agent_id"] = json!(claim);
        body["delegation"] = json!(f.delegation());
        let err = mcp_store(conn, &body, forward).expect_err("forged principal refused");
        assert!(
            err.contains("agent_id mismatch") || err.contains("reserved for internal use"),
            "{err}"
        );
        assert_eq!(rt.block_on(f.snapshot()), before);
    }
    let mut body = f.memory();
    for field in ["principal", "sender", "from"] {
        body[field] = json!(FORGED);
    }
    body["delegation"] = json!(f.delegation());
    let result = mcp_store(conn, &body, forward).expect("independently signed caller control");
    let row = rt.block_on(f.row(result["id"].as_str().expect("MCP memory id")));
    assert_eq!(row["metadata"]["agent_id"], CALLER);
    assert_eq!(row["metadata"]["attest_level"], "agent_attested");
    assert_eq!(row["namespace"], body["namespace"]);
}

fn sign_body(body: &Value, key: &SigningKey) -> String {
    let hash =
        ai_memory::identity::attest::content_sha256(body["content"].as_str().expect("content"));
    let write = ai_memory::identity::sign::SignableWrite {
        agent_id: CALLER,
        namespace: body["namespace"].as_str().expect("namespace"),
        title: body["title"].as_str().expect("title"),
        kind: "observation",
        created_at: body["created_at"].as_str().expect("timestamp"),
        content_sha256: &hash,
    };
    STANDARD.encode(
        key.sign(
            &ai_memory::identity::sign::canonical_cbor_write(&write).expect("canonical write"),
        )
        .to_bytes(),
    )
}

#[test]
fn sqlite_mcp_http_hub_credential_and_write_authority_3578() {
    let _serial = TEST_LOCK.lock().expect("serialize fixture environment");
    let _caller = AgentIdOverride::unset();
    let _env = common::MultiEnvVarGuard::apply(&[
        ("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", Some("1")),
        ("AI_MEMORY_NO_CONFIG", Some("1")),
    ]);
    let dir = tempfile::tempdir().expect("fixture dir");
    let path = dir.path().join("authority.db");
    let mut f = Fixture::new(sqlite_app_state(&path));
    let conn = ai_memory::db::open(&path).expect("fixture connection");
    ai_memory::db::register_agent(&conn, CALLER, "nhi", &[]).expect("register root");
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, CALLER, &f.root)
        .expect("possession bind root");
    let mut snapshot = ai_memory::identity::hub_cache::derive_sqlite(&conn, &[CALLER.to_owned()])
        .expect("derived SQLite hub snapshot");
    assert_eq!(snapshot.agents.len(), 1);
    f.prove_hub_admission(snapshot.agents.remove(0));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    exercise_mcp(&f, &conn, None, &rt);
    rt.block_on(exercise_http(&f));
}

#[cfg(feature = "sal-postgres")]
#[test]
fn live_postgres_http_and_forwarded_mcp_write_authority_3578() {
    use ai_memory::identity::pubkey_bind::{PossessionProof, sign_bind_challenge};
    use ai_memory::store::CallerContext;
    let _serial = TEST_LOCK.lock().expect("serialize fixture environment");
    let _caller = AgentIdOverride::unset();
    let _env = common::MultiEnvVarGuard::apply(&[
        ("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", Some("1")),
        ("AI_MEMORY_NO_CONFIG", Some("1")),
    ]);
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("own LIVE postgres required; never skip");
    let parsed = reqwest::Url::parse(&url).expect("postgres URL");
    // Refuse the LIVE operator database (the certified twin on :5445 on both
    // hosts). CI's ephemeral service database is also named `ai_memory_test`
    // but listens on :5432, so key the guard on name AND port.
    assert!(
        !(parsed.path() == "/ai_memory_test" && parsed.port() == Some(5445)),
        "never the live operator DB on :5445"
    );
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let mut f = Fixture::new(rt.block_on(postgres_app_state(&url)));
    f.pool = Some(
        rt.block_on(sqlx::PgPool::connect(&url))
            .expect("live snapshot pool"),
    );
    let ctx = CallerContext::for_admin("test:3578");
    rt.block_on(async {
        f.app
            .store
            .register_agent(
                &ctx,
                &ai_memory::models::AgentRegistration {
                    agent_id: CALLER.into(),
                    agent_type: "nhi".into(),
                    capabilities: vec![],
                    registered_at: chrono::Utc::now().to_rfc3339(),
                    last_seen_at: chrono::Utc::now().to_rfc3339(),
                },
            )
            .await
            .expect("register live pg");
        let public = f.root.public_base64();
        let issued = f
            .app
            .store
            .issue_pubkey_bind_challenge(&ctx, CALLER, &public, "test:3578")
            .await
            .expect("challenge");
        let sig = sign_bind_challenge(f.root.private.as_ref().expect("root"), &issued);
        let taken = f
            .app
            .store
            .consume_pubkey_bind_challenge(&ctx, CALLER, &issued.nonce_b64)
            .await
            .expect("consume")
            .expect("unspent");
        let proof = PossessionProof::verify_challenge_response(taken, CALLER, &public, &sig)
            .expect("proof");
        f.app
            .store
            .bind_agent_pubkey(&ctx, CALLER, &public, proof)
            .await
            .expect("bind live pg");
        let history = f
            .app
            .store
            .agent_pubkey_versions(CALLER)
            .await
            .expect("actual PG root history");
        let entry = ai_memory::identity::hub_cache::entry(
            CALLER,
            &history,
            vec![],
            vec![],
            &chrono::Utc::now().to_rfc3339(),
        )
        .expect("derived PG hub entry");
        f.prove_hub_admission(entry);
        exercise_http(&f).await;
    });
    // The MCP forwarder sends X-Agent-Id, not an API key. This loopback-only
    // fixture separately requires the root's write signature. API-key refusal
    // is covered above; this tests the production forwarding/PG write twin.
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("loopback listener");
    let forward = format!("http://{}", listener.local_addr().expect("address"));
    let router = router(f.app.clone(), None);
    let server = rt.spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("fixture HTTP server");
    });
    let scratch = ai_memory::db::open(std::path::Path::new(":memory:")).expect("MCP local shadow");
    exercise_mcp(&f, &scratch, Some(&forward), &rt);
    assert_eq!(
        sqlite_snapshot(&scratch),
        json!([]),
        "forwarder must not write its local shadow"
    );
    server.abort();
    assert!(
        rt.block_on(server)
            .expect_err("aborted fixture server")
            .is_cancelled()
    );
    rt.block_on(f.pool.as_ref().expect("pool").close());
}
