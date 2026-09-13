// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3663 — one operation joined across the storage, federation and wake
//! boundaries using emitted telemetry ALONE.
//!
//! The test installs a JSON tracing subscriber that captures every event,
//! then drives real code on each hop:
//!
//! 1. Node A: an operation span with a known `op_id` runs a signed-event
//!    append through the HTTP daemon's blocking DB helper (`db_op`) and a
//!    federation fan-out (`broadcast_store_quorum`) to node B.
//! 2. Node B: a real sqlite router served over TCP receives the signed push
//!    under its own request span.
//! 3. Wake: a notify on node B and the recipient's inbox read.
//!
//! Every assertion reads the captured telemetry only: the op id reaches the
//! signed-event row written on a blocking worker thread and the fan-out
//! dispatch logged in a spawned task; the receiver logs the same `push_ref`
//! under a DIFFERENT op id; and the recipient's read names the inbox row id
//! the notify published.
//!
//! Gated on `sal` like its precedent `cov_fupb_fed_signing.rs`: the HTTP
//! `AppState` carries the SAL store only under that feature.

#![cfg(feature = "sal")]

use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ai_memory::correlation::{OP_ID_FIELD, TARGET, mint_op_id};
use ai_memory::federation::{FederationConfig, PeerEndpoint};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::keypair::AgentKeypair;
use ai_memory::models::Memory;
use ai_memory::replication::QuorumPolicy;
use ai_memory::signed_events::SignedEvent;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use tracing::Instrument;

const NODE_A: &str = "ai:node-a-3663";
const SENDER: &str = "ai:alice-3663";
const RECIPIENT: &str = "ai:bob-3663";

static CAPTURED: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Process-global JSON subscriber: the blocking DB worker and the spawned
/// fan-out tasks run on other threads, so a thread-local default would miss
/// exactly the events under test.
fn install_capture() -> Arc<Mutex<Vec<u8>>> {
    Arc::clone(CAPTURED.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let sink = Capture(Arc::clone(&buf));
        tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || sink.clone())
            .init();
        buf
    }))
}

/// Every captured correlation event, parsed.
fn correlation_events(buf: &Arc<Mutex<Vec<u8>>>) -> Vec<Value> {
    let bytes = buf
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["target"] == TARGET)
        .collect()
}

fn find<'a>(events: &'a [Value], message: &str, pred: impl Fn(&Value) -> bool) -> &'a Value {
    events
        .iter()
        .find(|e| e["fields"]["message"] == message && pred(e))
        .unwrap_or_else(|| panic!("no `{message}` correlation event; captured: {events:#?}"))
}

/// The operation ids of every span enclosing an event.
fn op_ids(event: &Value) -> Vec<String> {
    event["spans"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s[OP_ID_FIELD].as_str().map(str::to_string))
        .collect()
}

fn fresh_db(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    ai_memory::db::open(&path).expect("db::open runs the migration ladder");
    path
}

fn router_for(db_path: &std::path::Path) -> axum::Router {
    let conn = ai_memory::db::open(db_path).expect("reopen");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.to_path_buf(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("SqliteStore"));
    let app_state = AppState {
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
        storage_backend: StorageBackend::Sqlite,
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
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

/// Enrol node A's public key on node B (the receiver verifies the signed
/// push against it) in an owner-only key directory.
fn enrol_node_a(dir: &std::path::Path, signer: &SigningKey) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .expect("tighten the key dir to 0700");
    }
    let kp = AgentKeypair {
        agent_id: NODE_A.to_string(),
        public: signer.verifying_key(),
        private: None,
    };
    ai_memory::identity::keypair::save_public_only(&kp, dir).expect("save node A pubkey");
}

fn replicated_memory() -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: "corr/3663".to_string(),
        title: "operation correlation 3663".to_string(),
        content: "a replicated row whose push must join across nodes".to_string(),
        tags: Vec::new(),
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({ "agent_id": NODE_A }),
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: ai_memory::models::LifecycleState::Open,
        cid: None,
        valid_from: None,
        valid_until: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_operation_joins_across_signed_write_two_nodes_and_a_wake_recipient() {
    let buf = install_capture();
    let scratch = tempfile::tempdir().expect("scratch dir");
    let key_dir = scratch.path().join("keys");
    std::fs::create_dir(&key_dir).expect("key dir");
    let signer = SigningKey::from_bytes(&[36u8; 32]);
    enrol_node_a(&key_dir, &signer);
    // SAFETY: this binary holds exactly one test, so nothing reads the
    // environment concurrently. Node B verifies node A's signature against
    // the enrolled key; the namespace-scope requirement is lifted because
    // this test declares no peer attestation map (#3582).
    unsafe {
        std::env::set_var("AI_MEMORY_KEY_DIR", &key_dir);
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE", "0");
    }

    // Node B: a real router served over loopback TCP.
    let b_path = fresh_db(scratch.path(), "node-b.db");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind node B");
    let b_url = format!("http://{}", listener.local_addr().expect("node B addr"));
    let router_b = router_for(&b_path);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router_b.into_make_service()).await;
    });

    // Node A: the operation under test.
    let a_path = fresh_db(scratch.path(), "node-a.db");
    let a_conn = ai_memory::db::open(&a_path).expect("node A conn");
    let a_db: Db = Arc::new(tokio::sync::Mutex::new((
        a_conn,
        a_path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let cfg = FederationConfig {
        policy: QuorumPolicy::new(2, 2, Duration::from_secs(5), Duration::from_secs(30))
            .expect("quorum policy"),
        peers: vec![PeerEndpoint {
            id: "node-b".to_string(),
            sync_push_url: format!("{b_url}/api/v1/sync/push"),
        }],
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client"),
        sender_agent_id: NODE_A.to_string(),
        api_key: None,
        signing_key: Some(Arc::new(signer.clone())),
        dlq_sink: None,
    };
    let op_a = mint_op_id();
    let event_id = uuid::Uuid::new_v4().to_string();
    let row = SignedEvent {
        id: event_id.clone(),
        agent_id: NODE_A.to_string(),
        event_type: "memory_link.created".to_string(),
        payload_hash: vec![7u8; 32],
        signature: None,
        attest_level: "unsigned".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    let mem = replicated_memory();
    let fanout = async {
        ai_memory::handlers::db_op(Arc::clone(&a_db), move |g| {
            ai_memory::signed_events::append_signed_event(&g.0, &row)
        })
        .await
        .expect("db_op dispatch")
        .expect("signed event append");
        ai_memory::federation::sync::broadcast_store_quorum(&cfg, &mem).await
    }
    .instrument(tracing::info_span!("node_a_op", op_id = %op_a))
    .await;
    assert!(
        fanout.is_ok(),
        "node B must ack the signed push, got {:?}",
        fanout.err()
    );

    // Wake: notify on node B, then the recipient reads its inbox.
    let http = reqwest::Client::new();
    let notify = http
        .post(format!("{b_url}/api/v1/notify"))
        .header("x-agent-id", SENDER)
        .json(&json!({
            "target_agent_id": RECIPIENT,
            "title": "correlation 3663",
            "payload": "the wake half of the joined operation",
        }))
        .send()
        .await
        .expect("notify");
    assert_eq!(notify.status(), reqwest::StatusCode::CREATED);
    let inbox: Value = http
        .get(format!("{b_url}/api/v1/inbox"))
        .header("x-agent-id", RECIPIENT)
        .send()
        .await
        .expect("inbox")
        .json()
        .await
        .expect("inbox json");
    assert_eq!(inbox["count"], json!(1), "inbox: {inbox}");

    // SAFETY: as above.
    unsafe {
        std::env::remove_var("AI_MEMORY_KEY_DIR");
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE");
    }

    let events = correlation_events(&buf);

    // Hop 1 — the signed write, emitted on the blocking DB worker thread.
    let written = find(&events, "signed event written", |e| {
        e["fields"]["event_id"] == event_id.as_str()
    });
    assert_eq!(
        op_ids(written),
        vec![op_a.clone()],
        "signed write: {written}"
    );

    // Hop 2 — node A's dispatch, emitted inside a spawned fan-out task.
    let dispatched = find(&events, "federation push dispatched", |e| {
        op_ids(e).contains(&op_a)
    });
    let reference = dispatched["fields"]["push_ref"]
        .as_str()
        .expect("push_ref is a string");
    assert_eq!(reference.len(), ai_memory::correlation::PUSH_REF_HEX_LEN);

    // Hop 3 — node B's receipt of the SAME push under its OWN operation.
    let received = find(&events, "federation push received", |e| {
        e["fields"]["push_ref"] == reference
    });
    assert_eq!(received["fields"]["verified"], json!(true), "{received}");
    assert_eq!(received["fields"]["peer_id"], json!(NODE_A), "{received}");
    let op_b = op_ids(received);
    assert_eq!(op_b.len(), 1, "one request span on node B: {received}");
    assert_ne!(op_b[0], op_a, "node B runs its own operation");

    // Hops 4 + 5 — the notify and the recipient's read join on the row id.
    let row_id = inbox["messages"][0]["id"]
        .as_str()
        .expect("inbox message id")
        .to_string();
    let published = find(&events, "inbox notify published", |e| {
        e["fields"]["inbox_row_id"] == row_id.as_str()
    });
    let read = find(&events, "inbox read", |e| {
        e["fields"]["inbox_row_ids"]
            .as_str()
            .is_some_and(|ids| ids.split(',').any(|id| id == row_id))
    });
    let (op_notify, op_read) = (op_ids(published), op_ids(read));
    assert_eq!(op_notify.len(), 1, "{published}");
    assert_eq!(op_read.len(), 1, "{read}");
    assert_ne!(
        op_notify, op_read,
        "the recipient read is its own operation"
    );
    assert_eq!(read["fields"]["recipient"], json!(RECIPIENT), "{read}");

    // Privacy: no correlation event carries a message body or title.
    for e in &events {
        let text = e.to_string();
        assert!(!text.contains("the wake half"), "body leaked: {text}");
        assert!(!text.contains("a replicated row"), "body leaked: {text}");
    }
}
