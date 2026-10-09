// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4043 — SQLITE federation-receive side of "an unreadable namespace policy
//! must fail closed" (twin of `governance_policy_read_fault_4043_pg.rs`).
//!
//! The bound namespace standard's `encrypted_envelope` is replaced by bytes
//! that cannot be opened (selective key loss / corrupted ciphertext). The
//! sqlite resolver used to fold that read fault into "no policy", and
//! `sync_push` stamped the compiled default reflection cap and applied the
//! row. The row must now be refused (reject-before-apply) while a control
//! row into a namespace with a READABLE policy still lands.

#![allow(clippy::too_many_lines)]

#[path = "common/sqlite_tempfile.rs"]
mod sqlite_tempfile;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const PEER_ID: &str = "ai:peer4043";
const ALLOWLIST: &str = r#"{"ai:peer4043":{"allowed_namespaces":["gov4043fed/*"],"allowed_sender_agent_ids":["ai:peer4043"]}}"#;

fn build_router_with_db() -> (axum::Router, ai_memory::handlers::Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    let path = std::path::PathBuf::from(":memory:");
    let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        path,
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = {
        let tmp = crate::sqlite_tempfile::SqliteTempFile::new().expect("tempfile for SqliteStore");
        let p = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        std::sync::Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open store"))
    };
    let app_state = ai_memory::handlers::AppState {
        db: db.clone(),
        embedder: std::sync::Arc::new(None),
        vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        federation: std::sync::Arc::new(None),
        tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: std::sync::Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: std::sync::Arc::new(None),
        active_keypair: std::sync::Arc::new(None),
        family_embeddings: std::sync::Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: std::sync::Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: std::sync::Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: std::sync::Arc::new(None),
        deferred_audit_queue: std::sync::Arc::new(None),
        admin_agent_ids: std::sync::Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    (ai_memory::build_router(api_key_state, app_state), db)
}

fn set_posture() {
    // SAFETY: serialised by `ENV_LOCK`; no other thread reads these vars.
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            ALLOWLIST,
        );
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
}

fn clear_posture() {
    // SAFETY: serialised by `ENV_LOCK`; no other thread reads these vars.
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
        std::env::remove_var(REQUIRE_ATTEST_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
}

fn wire_memory(id: &str, namespace: &str) -> Value {
    json!({
        "id": id,
        "tier": "long",
        "namespace": namespace,
        "title": format!("fed-4043-{id}"),
        "content": "federated payload",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "access_count": 0,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-07-01T00:00:00+00:00",
        "metadata": {"agent_id": PEER_ID},
        "reflection_depth": 0,
        "memory_kind": "observation",
    })
}

async fn push(router: &axum::Router, memories: Vec<Value>) -> StatusCode {
    let body = json!({
        "sender_agent_id": PEER_ID,
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
            PEER_ID,
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let _ = axum::body::to_bytes(resp.into_body(), 64 * 1024).await;
    status
}

/// Bind a permissive standard (write: Any, depth cap 1) to `ns`; return its id.
fn bind_standard(conn: &rusqlite::Connection, ns: &str) -> String {
    let policy = ai_memory::models::GovernancePolicy {
        core: ai_memory::models::CorePolicy {
            max_reflection_depth: Some(1),
            ..ai_memory::models::CorePolicy::default()
        },
        ..ai_memory::models::GovernancePolicy::default()
    };
    let now = chrono::Utc::now().to_rfc3339();
    let standard = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: format!("_standards-{ns}"),
        title: format!("standard-4043-{ns}"),
        content: "policy".to_string(),
        priority: 9,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({
            "agent_id": "ai:owner-4043",
            "governance": serde_json::to_value(policy).unwrap(),
        }),
        ..ai_memory::models::Memory::default()
    };
    let id = ai_memory::db::insert(conn, &standard).expect("seed standard");
    ai_memory::db::set_namespace_standard(conn, ns, &id, None).expect("bind standard");
    id
}

fn row_exists(conn: &rusqlite::Connection, id: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get::<_, i64>(0),
    )
    .expect("count")
        > 0
}

#[tokio::test]
async fn sqlite_sync_push_refuses_row_when_policy_unreadable_4043() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let (router, db) = build_router_with_db();
    let (readable_ns, broken_ns) = ("gov4043fed/readable", "gov4043fed/broken");
    {
        let lock = db.lock().await;
        bind_standard(&lock.0, readable_ns);
        let broken = bind_standard(&lock.0, broken_ns);
        let changed = lock
            .0
            .execute(
                "UPDATE memories SET encrypted_envelope = x'00ff00ff' WHERE id = ?1",
                rusqlite::params![broken],
            )
            .expect("corrupt standard envelope");
        assert_eq!(changed, 1);
    }

    // CONTROL: a readable policy — the row lands.
    let ok_id = uuid::Uuid::new_v4().to_string();
    let status = push(&router, vec![wire_memory(&ok_id, readable_ns)]).await;
    assert!(
        status.is_success(),
        "sync_push must not hard-error, got {status}"
    );
    assert!(
        row_exists(&db.lock().await.0, &ok_id),
        "control: a row into a namespace with a READABLE policy must land"
    );

    // #4043: the policy cannot be read — the row must be refused.
    let refused_id = uuid::Uuid::new_v4().to_string();
    let status = push(&router, vec![wire_memory(&refused_id, broken_ns)]).await;
    assert!(
        status.is_success(),
        "sync_push must not hard-error, got {status}"
    );
    assert!(
        !row_exists(&db.lock().await.0, &refused_id),
        "#4043: a row into a namespace whose policy cannot be read must NOT be applied"
    );
    clear_posture();
}
