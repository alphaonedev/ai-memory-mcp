// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8443 (arXiv 2610.38209) - handler-level role-grounding cells.
//!
//! - HTTP import (`POST /api/v1/import`) on the sqlite arm AND on the Postgres
//!   arm (a `storage_backend = Postgres` state over the SAL store, the same
//!   fake-Postgres pairing `cov_ga2_handlers_a` uses): the server re-derived
//!   `content_principal` survives the SAL ingress strip, and a claim naming the
//!   importer is replaced by the publisher.
//! - Federation receive (`POST /api/v1/sync/push`): the receive loop passes the
//!   authenticated peer to `sanitize_inbound_principal`, so a claim naming the
//!   peer (the only author an attested row can name) falls back to `unknown`,
//!   and an `owner` claim is dropped.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};

const IMPORTER: &str = "admin-caller";
const ATTACKER: &str = "ai:attacker";
const KEY: &str = "content_principal";
const PEER: &str = "ai:evil";

/// Process-global lock: the federation cells set process-wide env knobs.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

fn build_router(backend: StorageBackend) -> (axum::Router, NamedTempFile, Db) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let f = NamedTempFile::new().expect("db tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let app_state = AppState {
        db: db.clone(),
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
        admin_agent_ids: Arc::new(vec![IMPORTER.to_string()]),
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
    let router = ai_memory::build_router(
        ApiKeyState {
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
            ..Default::default()
        },
        app_state,
    );
    (router, f, db)
}

fn wire_row(id: &str, title: &str, metadata: Value) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = ai_memory::models::Memory {
        id: id.to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: "public/ok".to_string(),
        title: title.to_string(),
        content: format!("{title} body"),
        source: "import".into(),
        confidence: 1.0,
        priority: 5,
        created_at: now.clone(),
        updated_at: now,
        metadata,
        ..ai_memory::models::Memory::default()
    };
    serde_json::to_value(&mem).expect("serialize Memory")
}

async fn stored_principal(db: &Db, id: &str) -> Option<String> {
    let guard = db.lock().await;
    let mem = ai_memory::db::get(&guard.0, id)
        .expect("get")
        .expect("row stored");
    mem.metadata
        .get(KEY)
        .and_then(Value::as_str)
        .map(str::to_string)
}

async fn import(router: &axum::Router, rows: &[Value]) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/import")
        .header("content-type", "application/json")
        .header("x-agent-id", IMPORTER)
        .body(Body::from(json!({"memories": rows}).to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Both import arms: an `unknown` marker under the importer's own agent_id
/// survives (it is a server-derived demotion), and a claim naming the importer
/// is replaced by the publisher the bundle names.
async fn import_cells(backend: StorageBackend, label: &str) {
    let _g = ENV_LOCK.lock().await;
    let (router, _f, db) = build_router(backend);
    let unknown_id = uuid::Uuid::new_v4().to_string();
    let promote_id = uuid::Uuid::new_v4().to_string();
    let rows = [
        wire_row(
            &unknown_id,
            "unattributed export",
            json!({"agent_id": IMPORTER, KEY: "unknown"}),
        ),
        wire_row(
            &promote_id,
            "promoted claim",
            json!({"agent_id": ATTACKER, KEY: IMPORTER}),
        ),
    ];
    let (status, body) = import(&router, &rows).await;
    assert_eq!(status, StatusCode::OK, "{label}: {body}");
    assert_eq!(
        stored_principal(&db, &unknown_id).await.as_deref(),
        Some("unknown"),
        "{label}: the server-stamped `unknown` must survive the import"
    );
    assert_eq!(
        stored_principal(&db, &promote_id).await.as_deref(),
        Some(ATTACKER),
        "{label}: a claim naming the importer is replaced by the publisher"
    );
}

#[tokio::test]
async fn http_import_keeps_the_server_stamped_principal_on_sqlite_8443() {
    import_cells(StorageBackend::Sqlite, "sqlite").await;
}

#[tokio::test]
async fn http_import_keeps_the_server_stamped_principal_on_the_postgres_arm_8443() {
    import_cells(StorageBackend::Postgres, "postgres-arm").await;
}

// ---------------------------------------------------------------------------
// Federation receive (handler level)
// ---------------------------------------------------------------------------

const ALLOWLIST: &str = r#"{"ai:evil":{"allowed_namespaces":["public/*"],"allowed_sender_agent_ids":["ai:evil","ai:victim","ai:origin"]}}"#;

async fn push(router: &axum::Router, memories: &[Value]) -> (StatusCode, String) {
    let body = json!({
        "sender_agent_id": PEER,
        "sender_clock": {"entries": {}},
        "memories": memories,
        "dry_run": false,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            PEER,
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn federation_receive_passes_the_peer_to_the_principal_sanitiser_8443() {
    let _g = ENV_LOCK.lock().await;
    unsafe {
        std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
        // The relayed rows name an origin author with no enrolled key; the
        // explicit write-signature opt-out lets them reach the sanitiser.
        std::env::set_var("AI_MEMORY_FED_REQUIRE_WRITE_SIG", "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            ALLOWLIST,
        );
    }
    let (router, _f, db) = build_router(StorageBackend::Sqlite);
    let vouch_id = uuid::Uuid::new_v4().to_string();
    let owner_id = uuid::Uuid::new_v4().to_string();
    let third_id = uuid::Uuid::new_v4().to_string();
    let relay_id = uuid::Uuid::new_v4().to_string();
    let relay_case_id = uuid::Uuid::new_v4().to_string();
    let rows = [
        // The row names the peer as author AND as principal: a peer cannot
        // vouch for itself, so the claim falls back to `unknown`.
        wire_row(
            &vouch_id,
            "self vouching",
            json!({"agent_id": PEER, KEY: PEER}),
        ),
        // An `owner` claim is a promotion and is dropped.
        wire_row(
            &owner_id,
            "owner claim",
            json!({"agent_id": PEER, KEY: "owner"}),
        ),
        // A third party the peer vouches for survives (demotion).
        wire_row(
            &third_id,
            "third party",
            json!({"agent_id": PEER, KEY: "ai:third"}),
        ),
        // Code L4: a relayed row authored by `ai:origin` whose claim names
        // `ai:origin` is the row's own author naming itself; the authenticated
        // peer takes the claim, never the origin.
        wire_row(
            &relay_id,
            "relayed self claim",
            json!({"agent_id": "ai:origin", KEY: "ai:origin"}),
        ),
        // Sec LOW-4: the same imitation differing only in letter case.
        wire_row(
            &relay_case_id,
            "relayed self claim, case variant",
            json!({"agent_id": "ai:origin", KEY: "AI:Origin"}),
        ),
    ];
    let (status, resp_body) = push(&router, &rows).await;
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_WRITE_SIG");
        std::env::remove_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION");
    }
    assert!(
        status.is_success(),
        "push must succeed: {status} {resp_body}"
    );
    eprintln!("push response: {resp_body}");
    assert_eq!(
        stored_principal(&db, &vouch_id).await.as_deref(),
        Some("unknown"),
        "a claim naming the row's own author and the peer is never kept"
    );
    assert_eq!(
        stored_principal(&db, &owner_id).await,
        None,
        "an owner claim is dropped"
    );
    assert_eq!(
        stored_principal(&db, &third_id).await.as_deref(),
        Some("ai:third"),
        "a third-party claim survives"
    );
    assert_eq!(
        stored_principal(&db, &relay_id).await.as_deref(),
        Some(PEER),
        "a relayed row whose claim names its own origin stores the peer"
    );
    assert_eq!(
        stored_principal(&db, &relay_case_id).await.as_deref(),
        Some(PEER),
        "a case variant of the row's own author is the same imitation"
    );
}
