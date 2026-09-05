// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioural
// impact on the regression we pin.
#![allow(clippy::redundant_closure_for_method_calls, clippy::too_many_lines)]

//! #2863 (federation data-integrity) — fed-consolidate-source-attest-parity.
//!
//! End-to-end `/sync/push` pin for the #2860 re-broadcast divergence: a
//! consolidation SOURCE row that landed `agent_attested` on the peer (fresh
//! push, self-relayed by its author) must STAY `agent_attested` when the same
//! row is RE-BROADCAST under the daemon federation identity (a newer
//! `updated_at`, as the tombstone disposition emits). Pre-fix the re-broadcast
//! MERGED over the existing row and `db::merge_inbound`'s `sanitize` + LWW-newer
//! demoted the receiver's own just-verified level to `claimed` — a divergence
//! from the origin's `agent_attested`.
//!
//! This drives the REAL `/sync/push` receive loop (not `db::merge_inbound`
//! alone), so it pins the receive-loop WIRING: that the loop passes
//! `row_is_agent_attested(&to_insert)` into `merge_inbound` so the atomic
//! `reassert_verified_attestation` restores the verified level. Zero-config
//! posture (the DO-mesh shape); the enrolled-unauthorized honor branch (fix #1
//! in `resolve_inbound_attribution`) is unit-covered in
//! `handlers::federation_receive::tests::rebroadcast_source_honors_crypto_attested_claim_2863`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

/// Process-global async lock — these tests mutate federation env vars.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
        let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
        let p = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        std::sync::Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&p).expect("open SqliteStore"),
        )
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
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, db)
}

/// Relax the ENVELOPE-level federation gates so the per-write attestation lane
/// under test is reached, and clear the allowlist (zero-config posture).
fn reset_env_zero_config() {
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
        std::env::set_var("AI_MEMORY_FED_REQUIRE_SIG", "0");
        std::env::set_var("AI_MEMORY_FED_REQUIRE_NONCE", "0");
        // Strict per-write sig stays at its v1.0.0 default (unset) — the signed
        // source verifies, so strict never bricks it.
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_WRITE_SIG");
        std::env::remove_var("AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED");
    }
}

#[allow(clippy::too_many_arguments)]
fn memory_json(
    id: &str,
    ns: &str,
    title: &str,
    content: &str,
    created_at: &str,
    updated_at: &str,
    author: &str,
    write_sig_b64: &str,
) -> Value {
    json!({
        "id": id,
        "tier": "long",
        "namespace": ns,
        "title": title,
        "content": content,
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "user",
        "access_count": 0,
        "created_at": created_at,
        "updated_at": updated_at,
        "metadata": { "agent_id": author, "write_signature": write_sig_b64 },
        "reflection_depth": 0,
        "memory_kind": "observation",
    })
}

async fn post_sync_push(router: &axum::Router, sender: &str, memory: Value) -> StatusCode {
    let body = json!({
        "sender_agent_id": sender,
        "sender_clock": {"entries": {}},
        "memories": [memory],
        "dry_run": false,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            sender,
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    router.clone().oneshot(req).await.unwrap().status()
}

async fn row_attest(db: &ai_memory::handlers::Db, id: &str) -> (String, String) {
    let lock = db.lock().await;
    lock.0
        .query_row(
            "SELECT json_extract(metadata,'$.attest_level'), json_extract(metadata,'$.agent_id') \
             FROM memories WHERE id = ?1",
            rusqlite::params![id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .unwrap()
}

#[tokio::test]
async fn rebroadcast_tombstoned_source_stays_agent_attested_2863() {
    let _g = ENV_LOCK.lock().await;
    reset_env_zero_config();

    let (router, db) = build_router_with_db();
    let author = "ai:hive-author";
    let daemon = "ai:hive-memory-1"; // #2860 re-broadcast sender (fed identity)

    // Enroll the origin author's key at this receiver so the write_signature
    // verifies (both DO nodes had it enrolled).
    // #3464 — the bind proves possession from the keypair itself, so the
    // separately-encoded public key this used to pass is no longer needed
    // (`base64` is still used below for the write signature).
    let kp = ai_memory::identity::keypair::generate(author).unwrap();
    {
        let lock = db.lock().await;
        ai_memory::db::register_agent(&lock.0, author, "nhi", &[]).unwrap();
        ai_memory::db::bind_agent_pubkey_with_keypair(&lock.0, author, &kp).unwrap();
    }

    let id = uuid::Uuid::new_v4().to_string();
    let ns = "team/alpha";
    let title = "kubernetes deployment guide";
    let content = "scale the deployment to three replicas";
    let created = "2026-08-10T12:00:00+00:00";

    // Sign the 6-field SignableWrite exactly as the AUTHORING node would.
    let to_sign = ai_memory::models::Memory {
        id: id.clone(),
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        created_at: created.to_string(),
        metadata: json!({ "agent_id": author }),
        ..ai_memory::models::Memory::default()
    };
    let sig = ai_memory::identity::attest::sign_memory_write(&kp, &to_sign, author).unwrap();
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);

    // POST 1 — fresh push, SELF-RELAYED by the author → lands agent_attested.
    let status1 = post_sync_push(
        &router,
        author,
        memory_json(&id, ns, title, content, created, created, author, &sig_b64),
    )
    .await;
    assert_eq!(status1, StatusCode::OK, "fresh signed self-relay push");
    let (lvl1, owner1) = row_attest(&db, &id).await;
    assert_eq!(
        lvl1, "agent_attested",
        "fresh signed source lands agent_attested"
    );
    assert_eq!(owner1, author);

    // POST 2 — the #2860 RE-BROADCAST: same source (same id + write_signature),
    // NEWER updated_at (the tombstone disposition), relayed under the DAEMON
    // federation identity (a third-party relay from the receiver's view).
    let newer = "2026-08-10T19:14:31+00:00";
    let status2 = post_sync_push(
        &router,
        daemon,
        memory_json(&id, ns, title, content, created, newer, author, &sig_b64),
    )
    .await;
    assert_eq!(status2, StatusCode::OK, "re-broadcast push accepted");

    let (lvl2, owner2) = row_attest(&db, &id).await;
    assert_eq!(
        lvl2, "agent_attested",
        "#2863: the re-broadcast merge-over-existing must NOT demote the \
         receiver-verified level to `claimed` (origin stays agent_attested)"
    );
    assert_eq!(owner2, author, "authorship preserved as the true author");
}
