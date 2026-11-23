// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10037 / #10039 — the outbound scope on the PULL path (`GET /sync/since`).
//!
//! The reviewer's reproduction, as named tests on SQLite and PostgreSQL:
//! a peer attested for `public/*` whose outbound scope names only
//! `public/alpha` pulls a window holding one row in `public/alpha` and one
//! in `public/beta`. It must get exactly the `public/alpha` row: zero
//! out-of-scope rows, the in-scope rows exactly. The trust bypass, an
//! unmapped identity, an unset scope and an unsigned header spoof are the
//! sibling rows. The metric row pins the `/sync/since` series label to the
//! push lane's peer id (#10039).
//!
//! Every test here mutates process env, so each holds [`SERVE_ENV_LOCK`].

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::FederationConfig;
use ai_memory::federation::outbound_scope::{OUTBOUND_SCOPE_ENV, filtered_series};
use ai_memory::federation::outbound_scope_serve::SCOPE_STATUS_OUTBOUND_DENY;
use ai_memory::federation::peer_attestation::{
    PEER_ATTESTATION_ENV, PEER_ID_HEADER, SYNC_TRUST_PEER_ENV,
};
use ai_memory::federation::signing::{
    NONCE_HEADER, REQUIRE_NONCE_ENV, REQUIRE_SIG_ENV, SIGNATURE_HEADER, sign_body_with_nonce_header,
};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::keypair as kp_mod;
use ai_memory::models::Memory;
use ai_memory::store::{CallerContext, MemoryStore};

static SERVE_ENV_LOCK: Mutex<()> = Mutex::const_new(());

const KEY_DIR_ENV: &str = "AI_MEMORY_KEY_DIR";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const SYNC_SINCE_PATH: &str = "/api/v1/sync/since";
/// The pulling peer's push-lane URL (the outbound scope key).
const PEER_URL: &str = "https://peer-b.serve-10037.invalid:9077";
/// The pulling peer's agent id (its enrolled key and `peer_ids` entry).
const PEER_AGENT: &str = "ai:peer-b-serve-10037";
const OTHER_AGENT: &str = "ai:peer-c-serve-10037";
const SEED_AGENT: &str = "ai:seed-serve-10037";
const SCOPE_STATUS_SCOPED: &str = "scoped";
const SCOPE_STATUS_LEGACY: &str = "legacy_bypass";

/// One storage backend under test.
enum Backend {
    Sqlite,
    #[cfg(feature = "sal-postgres")]
    Postgres(String),
}

struct Host {
    router: axum::Router,
    store: Arc<dyn MemoryStore>,
    peer: kp_mod::AgentKeypair,
    _db_tmp: Option<tempfile::NamedTempFile>,
    _key_tmp: tempfile::TempDir,
}

fn app_state(db: Db, store: Arc<dyn MemoryStore>, backend: StorageBackend) -> AppState {
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
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
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

async fn host(backend: &Backend) -> Host {
    let key_tmp = tempfile::TempDir::new().expect("key tempdir");
    // The key-dir guard (#3198) refuses a group-writable directory; pin
    // 0700 so the fixture does not depend on the runner's umask.
    std::fs::set_permissions(
        key_tmp.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("chmod 0700 the key dir");
    // SAFETY: env mutation under SERVE_ENV_LOCK, held by every caller.
    unsafe { std::env::set_var(KEY_DIR_ENV, key_tmp.path()) };
    let peer = kp_mod::generate(PEER_AGENT).expect("generate peer keypair");
    let public_only = kp_mod::AgentKeypair {
        agent_id: peer.agent_id.clone(),
        public: peer.public,
        private: None,
    };
    kp_mod::save_public_only(&public_only, key_tmp.path()).expect("enrol the peer key");

    let (db, store, kind, db_tmp): (Db, Arc<dyn MemoryStore>, StorageBackend, _) = match backend {
        Backend::Sqlite => {
            let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
            let path = db_tmp.path().to_path_buf();
            let conn = ai_memory::db::open(&path).expect("db::open");
            let store: Arc<dyn MemoryStore> = Arc::new(
                ai_memory::store::sqlite::SqliteStore::open(&path).expect("open SqliteStore"),
            );
            let db: Db = Arc::new(Mutex::new((conn, path, ResolvedTtl::default(), true)));
            (db, store, StorageBackend::Sqlite, Some(db_tmp))
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(url) => {
            let conn =
                ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
            let db: Db = Arc::new(Mutex::new((
                conn,
                std::path::PathBuf::from(":memory:"),
                ResolvedTtl::default(),
                true,
            )));
            let store: Arc<dyn MemoryStore> = Arc::new(
                ai_memory::store::postgres::PostgresStore::connect(url)
                    .await
                    .expect("AI_MEMORY_TEST_POSTGRES_URL is set, so the store must connect"),
            );
            (db, store, StorageBackend::Postgres, None)
        }
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    let router = ai_memory::build_router(api_key_state, app_state(db, store.clone(), kind));
    Host {
        router,
        store,
        peer,
        _db_tmp: db_tmp,
        _key_tmp: key_tmp,
    }
}

/// The posture of one row of the table.
#[derive(Clone, Copy, Debug)]
enum Posture {
    /// Attested for `public/*`; outbound scope names only the alpha
    /// namespace and maps the signing peer (the reviewer's probe).
    WideAttestationNarrowOutbound,
    /// No attestation, `AI_MEMORY_FED_SYNC_TRUST_PEER=1`; the same narrow
    /// outbound scope.
    TrustBypassNarrowOutbound,
    /// Attested for `public/*`; the outbound entry maps another peer id.
    UnmappedIdentity,
    /// Attested for `public/*`; no outbound scope configured at all.
    OutboundUnset,
    /// Signatures off: the `X-Peer-Id` header names the mapped peer, but
    /// nothing proves it.
    UnsignedHeaderSpoof,
}

struct Window {
    since: String,
    alpha_ns: String,
    beta_ns: String,
    alpha_id: String,
    beta_id: String,
}

fn row(id: &str, ns: &str, at: &str) -> Memory {
    Memory {
        id: id.to_string(),
        namespace: ns.to_string(),
        title: format!("serve-10037 {id}"),
        content: "pull-path outbound scope row".to_string(),
        created_at: at.to_string(),
        updated_at: at.to_string(),
        metadata: json!({"federation_share": true, "agent_id": SEED_AGENT}),
        ..Default::default()
    }
}

async fn seed_window(store: &Arc<dyn MemoryStore>) -> Window {
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let now = chrono::Utc::now();
    let since =
        (now - chrono::Duration::seconds(5)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let w = Window {
        since,
        alpha_ns: format!("public/alpha-{tag}"),
        beta_ns: format!("public/beta-{tag}"),
        alpha_id: format!("alpha-{tag}"),
        beta_id: format!("beta-{tag}"),
    };
    let mut ctx = CallerContext::for_agent(SEED_AGENT);
    ctx.bypass_visibility = true;
    for m in [
        row(&w.alpha_id, &w.alpha_ns, &at),
        row(&w.beta_id, &w.beta_ns, &at),
    ] {
        store.store(&ctx, &m).await.expect("seed a window row");
    }
    w
}

fn outbound_config(alpha_ns: &str, peer_id: &str) -> String {
    format!(r#"{{"{PEER_URL}":{{"allowed_namespaces":["{alpha_ns}"],"peer_ids":["{peer_id}"]}}}}"#)
}

fn apply(posture: Posture, w: &Window) {
    let attested = format!(r#"{{"{PEER_AGENT}":{{"allowed_namespaces":["public/*"]}}}}"#);
    // SAFETY: env mutation under SERVE_ENV_LOCK.
    unsafe {
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "1");
        std::env::set_var(REQUIRE_SIG_ENV, "1");
        std::env::set_var(REQUIRE_NONCE_ENV, "1");
        std::env::remove_var(SYNC_TRUST_PEER_ENV);
        std::env::set_var(PEER_ATTESTATION_ENV, &attested);
        std::env::set_var(OUTBOUND_SCOPE_ENV, outbound_config(&w.alpha_ns, PEER_AGENT));
        match posture {
            Posture::WideAttestationNarrowOutbound => {}
            Posture::TrustBypassNarrowOutbound => {
                std::env::remove_var(PEER_ATTESTATION_ENV);
                std::env::set_var(SYNC_TRUST_PEER_ENV, "1");
            }
            Posture::UnmappedIdentity => {
                std::env::set_var(
                    OUTBOUND_SCOPE_ENV,
                    outbound_config(&w.alpha_ns, OTHER_AGENT),
                );
            }
            Posture::OutboundUnset => std::env::remove_var(OUTBOUND_SCOPE_ENV),
            Posture::UnsignedHeaderSpoof => {
                std::env::set_var(REQUIRE_SIG_ENV, "0");
                std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
            }
        }
    }
}

fn clear_env() {
    // SAFETY: env mutation under SERVE_ENV_LOCK.
    unsafe {
        for k in [
            REQUIRE_ENROLLMENT_ENV,
            REQUIRE_SIG_ENV,
            REQUIRE_NONCE_ENV,
            SYNC_TRUST_PEER_ENV,
            PEER_ATTESTATION_ENV,
            OUTBOUND_SCOPE_ENV,
            KEY_DIR_ENV,
        ] {
            std::env::remove_var(k);
        }
    }
}

/// One pull as the peer: signed unless the posture is the spoof row.
async fn pull(h: &Host, posture: Posture, since: &str) -> (StatusCode, Value) {
    let query = format!("limit=50&since={since}");
    let mut req = Request::builder()
        .method("GET")
        .uri(format!("{SYNC_SINCE_PATH}?{query}"))
        .header(PEER_ID_HEADER, PEER_AGENT);
    if !matches!(posture, Posture::UnsignedHeaderSpoof) {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"GET\n");
        canonical.extend_from_slice(SYNC_SINCE_PATH.as_bytes());
        canonical.push(b'\n');
        canonical.extend_from_slice(query.as_bytes());
        let nonce = uuid::Uuid::new_v4().to_string();
        let key = h
            .peer
            .private
            .as_ref()
            .expect("the peer has its private key");
        req = req
            .header(
                SIGNATURE_HEADER,
                sign_body_with_nonce_header(key, &canonical, &nonce),
            )
            .header(NONCE_HEADER, nonce);
    }
    let resp = h
        .router
        .clone()
        .oneshot(req.body(Body::empty()).expect("request"))
        .await
        .expect("router");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn ids(body: &Value) -> Vec<String> {
    body["memories"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| m["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// What one posture must serve: the alpha row only, or nothing.
async fn cell(backend: Backend, posture: Posture) {
    let _g = SERVE_ENV_LOCK.lock().await;
    let h = host(&backend).await;
    let w = seed_window(&h.store).await;
    apply(posture, &w);
    let (status, body) = pull(&h, posture, &w.since).await;
    clear_env();
    assert_eq!(status, StatusCode::OK, "{posture:?}: body={body}");
    let served = ids(&body);
    assert!(
        !served.contains(&w.beta_id),
        "{posture:?}: zero out-of-scope rows; served {served:?}"
    );
    match posture {
        Posture::WideAttestationNarrowOutbound | Posture::TrustBypassNarrowOutbound => {
            assert_eq!(
                served,
                vec![w.alpha_id.clone()],
                "{posture:?}: the in-scope rows exactly"
            );
            assert_eq!(body["count"], 1, "{posture:?}");
            let status_word = if matches!(posture, Posture::TrustBypassNarrowOutbound) {
                SCOPE_STATUS_LEGACY
            } else {
                SCOPE_STATUS_SCOPED
            };
            assert_eq!(body["scope_status"], status_word, "{posture:?}");
        }
        Posture::UnmappedIdentity | Posture::OutboundUnset | Posture::UnsignedHeaderSpoof => {
            assert_eq!(
                served,
                Vec::<String>::new(),
                "{posture:?}: nothing is served"
            );
            assert_eq!(body["count"], 0, "{posture:?}");
            assert_eq!(
                body["scope_status"], SCOPE_STATUS_OUTBOUND_DENY,
                "{posture:?}"
            );
            assert_eq!(
                body["next_since"],
                Value::Null,
                "{posture:?}: no cursor leaks"
            );
        }
    }
}

/// #10039: the pull path counts each row it leaves out under the SAME
/// stable peer id the push lanes use for that peer.
async fn metric_cell(backend: Backend) {
    let _g = SERVE_ENV_LOCK.lock().await;
    let h = host(&backend).await;
    let w = seed_window(&h.store).await;
    let push_lane_id = FederationConfig::build(
        1,
        &[PEER_URL.to_string()],
        Duration::from_secs(1),
        None,
        None,
        None,
        SEED_AGENT.to_string(),
        None,
    )
    .expect("build the push-lane config")
    .expect("one peer configured")
    .peers[0]
        .id
        .clone();
    apply(Posture::WideAttestationNarrowOutbound, &w);
    let (status, body) = pull(&h, Posture::WideAttestationNarrowOutbound, &w.since).await;
    clear_env();
    assert_eq!(status, StatusCode::OK, "body={body}");
    let series: Vec<_> = filtered_series()
        .into_iter()
        .filter(|s| s.namespace == w.beta_ns)
        .collect();
    assert_eq!(
        series.len(),
        1,
        "one series for the left-out namespace: {series:?}"
    );
    assert_eq!(
        series[0].peer_id, push_lane_id,
        "the push lane's peer id labels the pull series"
    );
    assert_eq!(series[0].count, 1);
}

#[tokio::test]
async fn sync_since_narrow_outbound_wide_attestation_serves_only_in_scope_sqlite_10037() {
    cell(Backend::Sqlite, Posture::WideAttestationNarrowOutbound).await;
}

#[tokio::test]
async fn sync_since_trust_bypass_never_widens_the_outbound_scope_sqlite_10037() {
    cell(Backend::Sqlite, Posture::TrustBypassNarrowOutbound).await;
}

#[tokio::test]
async fn sync_since_unmapped_identity_is_denied_sqlite_10037() {
    cell(Backend::Sqlite, Posture::UnmappedIdentity).await;
}

#[tokio::test]
async fn sync_since_unset_outbound_scope_is_denied_sqlite_10037() {
    cell(Backend::Sqlite, Posture::OutboundUnset).await;
}

#[tokio::test]
async fn sync_since_unsigned_peer_header_selects_no_scope_sqlite_10037() {
    cell(Backend::Sqlite, Posture::UnsignedHeaderSpoof).await;
}

#[tokio::test]
async fn sync_since_filtered_series_uses_the_push_lane_peer_id_sqlite_10039() {
    metric_cell(Backend::Sqlite).await;
}

#[cfg(feature = "sal-postgres")]
fn pg_backend() -> Option<Backend> {
    match std::env::var("AI_MEMORY_TEST_POSTGRES_URL") {
        Ok(url) if !url.is_empty() => Some(Backend::Postgres(url)),
        _ => {
            eprintln!("test skipped: AI_MEMORY_TEST_POSTGRES_URL not set");
            None
        }
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn sync_since_narrow_outbound_wide_attestation_serves_only_in_scope_postgres_9996() {
    let Some(b) = pg_backend() else { return };
    cell(b, Posture::WideAttestationNarrowOutbound).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn sync_since_trust_bypass_never_widens_the_outbound_scope_postgres_9996() {
    let Some(b) = pg_backend() else { return };
    cell(b, Posture::TrustBypassNarrowOutbound).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn sync_since_unmapped_identity_is_denied_postgres_9996() {
    let Some(b) = pg_backend() else { return };
    cell(b, Posture::UnmappedIdentity).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn sync_since_unset_outbound_scope_is_denied_postgres_9996() {
    let Some(b) = pg_backend() else { return };
    cell(b, Posture::OutboundUnset).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn sync_since_unsigned_peer_header_selects_no_scope_postgres_9996() {
    let Some(b) = pg_backend() else { return };
    cell(b, Posture::UnsignedHeaderSpoof).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn sync_since_filtered_series_uses_the_push_lane_peer_id_postgres_9996() {
    let Some(b) = pg_backend() else { return };
    metric_cell(b).await;
}
