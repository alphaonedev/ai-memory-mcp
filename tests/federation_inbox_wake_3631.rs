// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3631 — an inbox row applied by FEDERATION wakes the recipient on
//! the receiving node.
//!
//! A `memory_notify` written on node-1 reaches node-2 through the federation
//! receive path — the signed `/sync/push` fan-out or the catch-up pull — and
//! never through `MemoryStore::notify`. Before #3631 neither path published to
//! the inbox wake bus, so a recipient on node-2 heard about the message only on
//! its `<=60 s` backstop poll.
//!
//! Every cell drives the REAL receive entry point (the router's `/sync/push`,
//! or the production catch-up loop against a peer serving `/sync/since`), then
//! proves the wake end to end: the bus frame is forwarded by the #3469
//! in-process sink to a REAL hub, and a REAL `wake-listen` session admitted by
//! the SHIPPED delegation verifier receives it, naming the applied row and
//! carrying a digest, never the body. The negative halves pin that a replayed
//! row, an invalid row and a non-notify row wake nobody.
//!
//! The postgres cells (`sal-postgres`) run the same scenarios against the
//! postgres receive funnel and the SAL catch-up; they soft-skip when
//! `AI_MEMORY_TEST_POSTGRES_URL` is unset and are deliberately not `#[ignore]`.

// The CLIPPY LEG TRAP (#3465 pool rule): these `#![allow]`s sit BEFORE any
// `cfg`, so they still apply on a leg where the module docs above are linted.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::similar_names
)]

mod wake_hub_harness;

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ai_memory::federation::{FederationConfig, PeerEndpoint};
use ai_memory::identity::hub_delegation::{A2A_HUB_SCOPE, DelegationWire, sign_hub_delegation};
use ai_memory::identity::keypair;
use ai_memory::inbox_wake::{InboxEvent, InboxWakeSink as _, subscribe};
use ai_memory::models::{Memory, Tier};
use ai_memory::replication::QuorumPolicy;
use ai_memory::wake_client::{
    HubJoinBundle, SessionConfig, WakeClientConfig, WakeReason, WakeSignal, WakeStream,
};
use ai_memory::wake_hub::delegation_verifier::{
    AllowlistCache, EnrolledRoot, RootBindAuthority, ScopedDelegationVerifier,
};
use ai_memory::wake_hub::identity::SameUidAuthorizer;
use ai_memory::wake_sink::in_process::InProcessWakeSink;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;
use tower::ServiceExt as _;
use wake_hub_harness::Harness;

/// Serialises every cell: they all set process-global federation posture.
static FED_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The pushing peer, and the peer id the catch-up loop presents.
const PEER_ID: &str = "ai:peer-3631";
const CATCHUP_PEER_ID: &str = "peer-0";
/// The notifying agent on the far node. Allow-listed for the pushing peer so
/// the receive path honours the authorship the row claims.
const AUTHOR: &str = "ai:alice-3631";
const SECRET_BODY: &str = "SUPER-SECRET-FEDERATED-NOTIFY-BODY-3631";
const SUBJECT: &str = "SUBJECT-LINE-3631";

const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const REQUIRE_WRITE_SIG_ENV: &str = "AI_MEMORY_FED_REQUIRE_WRITE_SIG";
const SYNC_TRUST_PEER_ENV: &str = "AI_MEMORY_FED_SYNC_TRUST_PEER";
const TRUST_BODY_AGENT_ID_ENV: &str = "AI_MEMORY_FED_TRUST_BODY_AGENT_ID";

/// Restores the federation posture when a cell ends, pass or fail.
struct PostureGuard;

impl Drop for PostureGuard {
    fn drop(&mut self) {
        // SAFETY: every caller holds FED_ENV_LOCK for the guard's lifetime.
        unsafe {
            std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
            std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
            std::env::remove_var(REQUIRE_WRITE_SIG_ENV);
        }
    }
}

/// Both peers are scoped to the inbox tree only, and the pushing peer may
/// relay `AUTHOR`'s writes. Peer-key enrollment and the per-write signature
/// are relaxed because this suite is about the wake, not the attestation
/// gates (which have their own suites); the namespace scope gate stays ON.
fn set_posture() -> PostureGuard {
    // SAFETY: every caller holds FED_ENV_LOCK for the returned guard's lifetime.
    unsafe {
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::set_var(REQUIRE_WRITE_SIG_ENV, "0");
        std::env::remove_var(SYNC_TRUST_PEER_ENV);
        std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            format!(
                r#"{{"{PEER_ID}":{{"allowed_namespaces":["_inbox/**"],"allowed_sender_agent_ids":["{PEER_ID}","{AUTHOR}"]}},"{CATCHUP_PEER_ID}":{{"allowed_namespaces":["_inbox/**"]}}}}"#
            ),
        );
    }
    PostureGuard
}

fn uid(prefix: &str) -> String {
    format!("ai:{prefix}-{}", uuid::Uuid::new_v4())
}

/// The inbox row `memory_notify` writes on the far node, as it travels.
fn notify_row(recipient: &str, source: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ai_memory::inbox_namespace(recipient),
        title: format!("{SUBJECT}-{}", uuid::Uuid::new_v4()),
        content: SECRET_BODY.to_string(),
        tags: vec!["notify".to_string()],
        priority: 5,
        confidence: 1.0,
        source: source.to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({
            "agent_id": AUTHOR,
            "target_agent_id": recipient,
            "notify": true,
        }),
        ..Default::default()
    }
}

fn push_body(memories: &[Value]) -> Value {
    json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": memories,
        "dry_run": false,
    })
}

async fn push(router: &axum::Router, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            PEER_ID,
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

// ---------------------------------------------------------------------------
// The receiving node's wake-listen session (the #3470 pattern)
// ---------------------------------------------------------------------------

/// The artefacts `ai-memory identity delegate --scope a2a-hub` leaves behind.
struct StagedIdentity {
    dir: tempfile::TempDir,
    agent_id: String,
    enrolled_public: ed25519_dalek::VerifyingKey,
}

impl StagedIdentity {
    fn stage(agent_id: &str, hub_id: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700");
        let enrolled = keypair::generate(agent_id).expect("generate enrolled");
        keypair::save(&enrolled, dir.path()).expect("save enrolled");
        let root = enrolled.private.clone().expect("private half");
        let delegate = keypair::generate(agent_id).expect("generate delegate");
        let delegate_private = delegate.private.clone().expect("private half");
        let now = chrono::Utc::now();
        let mut wire = DelegationWire {
            principal: agent_id.to_owned(),
            scope: A2A_HUB_SCOPE.to_owned(),
            delegate_key_id: delegate.public.to_bytes(),
            hub_id: hub_id.to_owned(),
            not_before: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            not_after: (now + chrono::Duration::seconds(3_600))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            signature: [0u8; 64],
        };
        wire.signature = sign_hub_delegation(&root, &wire.as_delegation()).expect("sign");
        let bundle = json!({
            "version": 1,
            "agent_id": agent_id,
            "hub_id": hub_id,
            "delegation_b64": URL_SAFE_NO_PAD.encode(wire.encode().expect("encode")),
            "delegate_private_b64": URL_SAFE_NO_PAD.encode(delegate_private.to_bytes()),
            "not_before": wire.not_before,
            "not_after": wire.not_after,
        });
        let path = HubJoinBundle::default_path(dir.path(), agent_id);
        std::fs::write(&path, serde_json::to_vec_pretty(&bundle).expect("json")).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        Self {
            dir,
            agent_id: agent_id.to_owned(),
            enrolled_public: enrolled.public,
        }
    }

    fn key_dir(&self) -> &Path {
        self.dir.path()
    }

    fn bundle_path(&self) -> PathBuf {
        HubJoinBundle::default_path(self.dir.path(), &self.agent_id)
    }
}

/// A real hub admitting `recipient` through the SHIPPED verifier, with a
/// welcomed `wake-listen` session attached and the #3469 in-process sink the
/// daemon would forward bus frames through.
struct Listener {
    harness: Harness,
    stream: WakeStream,
    sink: InProcessWakeSink,
    _staged: StagedIdentity,
}

impl Listener {
    async fn start(recipient: &str, hub_id: &str) -> Self {
        let staged = StagedIdentity::stage(recipient, hub_id);
        let mut cache = AllowlistCache::new();
        cache.insert(
            &staged.agent_id,
            EnrolledRoot {
                pubkey: staged.enrolled_public,
                authority: RootBindAuthority::PossessionProof,
            },
        );
        let hub_id_owned = hub_id.to_owned();
        let harness = Harness::start(
            move |cfg| cfg.hub_id = hub_id_owned,
            Arc::new(ScopedDelegationVerifier::new(cache)),
            Arc::new(SameUidAuthorizer::for_current_process()),
        );
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let bundle = HubJoinBundle::load(
            &staged.bundle_path(),
            &harness.hub_id,
            staged.key_dir(),
            &now,
        )
        .expect("the bundle `identity delegate` writes must load");
        let mut stream = WakeStream::start(
            WakeClientConfig {
                poll_interval: Duration::from_secs(5),
                ..WakeClientConfig::default()
            },
            Some((
                SessionConfig::new(harness.socket.clone(), harness.hub_id.clone()),
                Arc::new(bundle),
            )),
        )
        .expect("start");
        assert_eq!(
            next_hub_signal(&mut stream).await.reason,
            WakeReason::Welcome,
            "an admitted session is welcomed"
        );
        stream.note_read();
        let sink = InProcessWakeSink::for_router(harness.router());
        Self {
            harness,
            stream,
            sink,
            _staged: staged,
        }
    }

    /// Forward one bus frame the way `serve` does, and prove the listener
    /// receives it as a hub wake naming `row_id` — a digest, never the body.
    async fn expect_wake(&mut self, event: &InboxEvent, row_id: &str, recipient: &str) {
        self.sink.on_wake(event);
        let wake = next_hub_signal(&mut self.stream).await;
        assert_eq!(wake.reason, WakeReason::Wake);
        let meta = wake.meta.as_ref().expect("a wake carries its hint");
        assert_eq!(meta.inbox_row_id, row_id, "the hint names the applied row");
        assert_eq!(meta.namespace, ai_memory::inbox_namespace(recipient));
        assert_eq!(meta.digest.len(), 32, "a digest, never a body");
        let rendered = format!("{meta:?}");
        assert!(
            !rendered.contains(SECRET_BODY) && !rendered.contains(SUBJECT),
            "no body and no title may reach a listener (#3578): {rendered}"
        );
        self.stream.note_read();
    }

    async fn stop(self) {
        drop(self.stream);
        self.harness.stop().await;
    }
}

async fn next_hub_signal(stream: &mut WakeStream) -> WakeSignal {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no hub-driven signal arrived"
        );
        let signal = tokio::time::timeout(Duration::from_secs(15), stream.next())
            .await
            .expect("timed out waiting for a wake signal")
            .expect("the listener's producers must not stop");
        if signal.reason.is_hub_driven() {
            return signal;
        }
        stream.note_read();
    }
}

/// The next bus frame for `recipient` within `wait`, if any.
async fn wake_for(
    rx: &mut Receiver<InboxEvent>,
    recipient: &str,
    wait: Duration,
) -> Option<InboxEvent> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(ev)) if ev.recipient_agent_id() == recipient => return Some(ev),
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) | Err(_) => return None,
        }
    }
}

/// The fields of an `agent_notified` frame the assertions look at.
fn frame_fields(ev: &InboxEvent) -> (&str, &str, &str) {
    let InboxEvent::AgentNotified {
        inbox_row_id,
        sender_agent_id,
        content_digest,
        ..
    } = ev;
    (inbox_row_id, sender_agent_id, content_digest)
}

/// Assert the bus frame names `row_id`, attributes it to `AUTHOR`, and
/// carries a digest rather than the body.
fn assert_frame(ev: &InboxEvent, row_id: &str) {
    let (id, sender, digest) = frame_fields(ev);
    assert_eq!(id, row_id, "the frame names the applied row");
    assert_eq!(sender, AUTHOR, "the sender rides in the frame metadata");
    assert!(digest.starts_with("sha256:"), "a digest: {digest}");
    assert!(!format!("{ev:?}").contains(SECRET_BODY), "never the body");
}

// ---------------------------------------------------------------------------
// The peer the catch-up loop pulls from
// ---------------------------------------------------------------------------

/// Serve `/sync/since` returning `memories` once, then nothing.
async fn spawn_since_peer(memories: Vec<Value>) -> String {
    use axum::routing::get;
    let served = Arc::new(tokio::sync::Mutex::new(Some(memories)));
    let app = axum::Router::new().route(
        "/api/v1/sync/since",
        get(move || {
            let served = Arc::clone(&served);
            async move {
                let rows = served.lock().await.take().unwrap_or_default();
                axum::Json(json!({ "memories": rows }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

fn catchup_config(peer_url: &str) -> FederationConfig {
    let _ =
        ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
    FederationConfig {
        policy: QuorumPolicy::new(2, 1, Duration::from_secs(2), Duration::from_secs(30)).unwrap(),
        peers: vec![PeerEndpoint {
            id: CATCHUP_PEER_ID.to_string(),
            sync_push_url: format!("{peer_url}/api/v1/sync/push"),
        }],
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client"),
        sender_agent_id: "ai:catchup-3631".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

/// The catch-up loop sleeps 5 s before its first pull; give it room.
const CATCHUP_WAKE_WAIT: Duration = Duration::from_secs(30);
const NO_WAKE_WAIT: Duration = Duration::from_secs(2);
/// Long enough that only the first catch-up pass runs inside a cell.
const CATCHUP_INTERVAL: Duration = Duration::from_secs(3_600);

fn scratch_db() -> ai_memory::handlers::Db {
    let conn = ai_memory::db::open(Path::new(":memory:")).expect("open sqlite");
    Arc::new(tokio::sync::Mutex::new((
        conn,
        PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )))
}

// ---------------------------------------------------------------------------
// sqlite receiver
// ---------------------------------------------------------------------------

fn app_state(
    db: ai_memory::handlers::Db,
    backend: ai_memory::handlers::StorageBackend,
    #[cfg(feature = "sal")] store: Arc<dyn ai_memory::store::MemoryStore>,
) -> ai_memory::handlers::AppState {
    ai_memory::handlers::AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
        #[cfg(feature = "sal")]
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

fn router(state: ai_memory::handlers::AppState) -> axum::Router {
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, state)
}

fn sqlite_router() -> axum::Router {
    // `#[cfg]` is not allowed on a call argument, so the two builds build
    // the state in separate statements.
    #[cfg(feature = "sal")]
    let state = {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
        let path = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        let store: Arc<dyn ai_memory::store::MemoryStore> =
            Arc::new(ai_memory::store::sqlite::SqliteStore::open(&path).expect("open store"));
        app_state(
            scratch_db(),
            ai_memory::handlers::StorageBackend::Sqlite,
            store,
        )
    };
    #[cfg(not(feature = "sal"))]
    let state = app_state(scratch_db(), ai_memory::handlers::StorageBackend::Sqlite);
    router(state)
}

/// The shared `/sync/push` scenario: a delivered notify wakes a real
/// listener; the same row replayed, an invalid row and a non-notify row in the
/// inbox wake nobody.
async fn sync_push_scenario(router: &axum::Router, hub_id: &str) {
    let recipient = uid("fed-push");
    let mut listener = Listener::start(&recipient, hub_id).await;
    let mut rx = subscribe();

    let row = notify_row(&recipient, "notify");
    let wire = serde_json::to_value(&row).expect("row json");
    let (status, report) = push(router, &push_body(std::slice::from_ref(&wire))).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(report["applied"].as_u64(), Some(1), "{report}");
    let event = wake_for(&mut rx, &recipient, NO_WAKE_WAIT * 5)
        .await
        .expect("#3631: a federation-applied inbox row must wake its recipient");
    assert_frame(&event, &row.id);
    listener.expect_wake(&event, &row.id, &recipient).await;

    // Replay: the row is already held with the same updated_at.
    let (status, report) = push(router, &push_body(&[wire])).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert!(
        wake_for(&mut rx, &recipient, NO_WAKE_WAIT).await.is_none(),
        "a replayed row must not wake its recipient again: {report}"
    );

    // An invalid row (a source outside the allow-list) is skipped by the
    // receive path and wakes nobody.
    let invalid_recipient = uid("fed-push-invalid");
    let invalid = notify_row(&invalid_recipient, "not-in-allowlist");
    // A valid row in the inbox that is not a notify wakes nobody either.
    let plain_recipient = uid("fed-push-plain");
    let plain = notify_row(&plain_recipient, "api");
    let (status, report) = push(
        router,
        &push_body(&[
            serde_json::to_value(&invalid).unwrap(),
            serde_json::to_value(&plain).unwrap(),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(report["skipped"].as_u64(), Some(1), "{report}");
    assert!(
        wake_for(&mut rx, &invalid_recipient, NO_WAKE_WAIT)
            .await
            .is_none()
    );
    assert!(
        wake_for(&mut rx, &plain_recipient, NO_WAKE_WAIT)
            .await
            .is_none()
    );

    listener.stop().await;
}

/// ALLOWED + DENIED, sqlite `/sync/push`.
#[tokio::test]
async fn sqlite_sync_push_applied_inbox_row_wakes_a_real_listener_3631() {
    let _lock = FED_ENV_LOCK.lock().await;
    let _posture = set_posture();
    sync_push_scenario(&sqlite_router(), "hub-3631-push").await;
}

/// The catch-up scenario against whatever apply path `spawn` drives: the
/// delivered notify wakes a real listener, the invalid row alongside it wakes
/// nobody.
async fn catchup_scenario(
    hub_id: &str,
    spawn: impl FnOnce(FederationConfig) -> tokio::task::JoinHandle<()>,
) {
    let recipient = uid("fed-catchup");
    let mut listener = Listener::start(&recipient, hub_id).await;
    let mut rx = subscribe();

    let row = notify_row(&recipient, "notify");
    let invalid_recipient = uid("fed-catchup-invalid");
    let invalid = notify_row(&invalid_recipient, "not-in-allowlist");
    let peer = spawn_since_peer(vec![
        serde_json::to_value(&row).unwrap(),
        serde_json::to_value(&invalid).unwrap(),
    ])
    .await;
    let handle = spawn(catchup_config(&peer));

    let event = wake_for(&mut rx, &recipient, CATCHUP_WAKE_WAIT)
        .await
        .expect("#3631: a catch-up-applied inbox row must wake its recipient");
    assert_frame(&event, &row.id);
    listener.expect_wake(&event, &row.id, &recipient).await;
    assert!(
        wake_for(&mut rx, &invalid_recipient, NO_WAKE_WAIT)
            .await
            .is_none()
    );

    handle.abort();
    listener.stop().await;
}

/// ALLOWED + DENIED, the sqlite catch-up loop (`catchup_once_legacy` on the
/// default build, the store-less SAL branch under `sal`).
#[tokio::test]
async fn sqlite_catchup_applied_inbox_row_wakes_a_real_listener_3631() {
    let _lock = FED_ENV_LOCK.lock().await;
    let _posture = set_posture();
    let db = scratch_db();
    catchup_scenario("hub-3631-catchup", |cfg| {
        ai_memory::federation::spawn_catchup_loop(cfg, db, CATCHUP_INTERVAL)
    })
    .await;
}

/// ALLOWED + DENIED, the SAL catch-up branch over a `SqliteStore`.
#[cfg(feature = "sal")]
#[tokio::test]
async fn sqlite_store_catchup_applied_inbox_row_wakes_a_real_listener_3631() {
    let _lock = FED_ENV_LOCK.lock().await;
    let _posture = set_posture();
    let dir = tempfile::tempdir().expect("tempdir");
    let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(dir.path().join("store.db"))
            .expect("open SqliteStore"),
    );
    catchup_scenario("hub-3631-catchup-store", |cfg| {
        ai_memory::federation::spawn_catchup_loop_with_store(
            cfg,
            scratch_db(),
            Some(store),
            CATCHUP_INTERVAL,
        )
    })
    .await;
    drop(dir);
}

// ---------------------------------------------------------------------------
// postgres receiver
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
async fn postgres_store() -> Option<Arc<dyn ai_memory::store::MemoryStore>> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())?;
    Some(Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    ))
}

/// ALLOWED + DENIED, the postgres `/sync/push` funnel.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_sync_push_applied_inbox_row_wakes_a_real_listener_3631() {
    let Some(store) = postgres_store().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let _lock = FED_ENV_LOCK.lock().await;
    let _posture = set_posture();
    let router = router(app_state(
        scratch_db(),
        ai_memory::handlers::StorageBackend::Postgres,
        store,
    ));
    sync_push_scenario(&router, "hub-3631-push-pg").await;
}

/// ALLOWED + DENIED, the SAL catch-up branch over a `PostgresStore`.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_catchup_applied_inbox_row_wakes_a_real_listener_3631() {
    let Some(store) = postgres_store().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let _lock = FED_ENV_LOCK.lock().await;
    let _posture = set_posture();
    catchup_scenario("hub-3631-catchup-pg", |cfg| {
        ai_memory::federation::spawn_catchup_loop_with_store(
            cfg,
            scratch_db(),
            Some(store),
            CATCHUP_INTERVAL,
        )
    })
    .await;
}
