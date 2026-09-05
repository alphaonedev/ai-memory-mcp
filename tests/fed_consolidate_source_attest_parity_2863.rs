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

fn build_app() -> ai_memory::handlers::AppState {
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
    ai_memory::handlers::AppState {
        db,
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
    }
}

fn router_for(app_state: ai_memory::handlers::AppState) -> axum::Router {
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

fn build_router_with_db() -> (axum::Router, ai_memory::handlers::Db) {
    let app = build_app();
    let db = std::sync::Arc::clone(&app.db);
    (router_for(app), db)
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
    // #3502: bind before signing; receiver history is authoritative at created_at.
    let created = ai_memory::identity::attest::now_attestable_rfc3339();

    // Sign the 6-field SignableWrite exactly as the AUTHORING node would.
    let to_sign = ai_memory::models::Memory {
        id: id.clone(),
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        created_at: created.clone(),
        metadata: json!({ "agent_id": author }),
        ..ai_memory::models::Memory::default()
    };
    let sig = ai_memory::identity::attest::sign_memory_write(&kp, &to_sign, author).unwrap();
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);

    // POST 1 — fresh push, SELF-RELAYED by the author → lands agent_attested.
    let status1 = post_sync_push(
        &router,
        author,
        memory_json(
            &id, ns, title, content, &created, &created, author, &sig_b64,
        ),
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
    let newer = ai_memory::identity::attest::now_attestable_rfc3339();
    let status2 = post_sync_push(
        &router,
        daemon,
        memory_json(&id, ns, title, content, &created, &newer, author, &sig_b64),
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

#[derive(Clone, Default)]
struct CapturedLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// v1.0.0 #3502 — ONE mixed batch that pins the whole decision on either
/// backend: an eligible signed write still replicates, an INELIGIBLE one (a
/// valid signature over a `created_at` that PREDATES the author's key binding)
/// and a forged one are both refused, and BOTH refusals are visible to the
/// pushing peer in the 200 response as well as in the receiver's WARN stream.
///
/// The decision this pins (issue #3502 question 2): the v97 timestamp-eligible
/// resolver is CORRECT — a key bound after a memory's signed `created_at`
/// legitimately cannot verify it, because letting it would hand every freshly
/// bound key retroactive authority over arbitrarily old envelopes, which is the
/// exact hole #3464 closed (and `bind_pubkey_possession_3464`'s
/// `sqlite_skew_boundary_reverification_cryptographically_selects_one_key_3464`
/// already pins the empty candidate set outside the skew-expanded window). The
/// fix is therefore on the OTHER side of the 200: the refusal is no longer
/// silent.
async fn push_timestamp_matrix(
    router: axum::Router,
    author: &str,
    kp: &ai_memory::identity::keypair::AgentKeypair,
) -> (String, String, String) {
    use tracing::instrument::WithSubscriber as _;

    let old_id = uuid::Uuid::new_v4().to_string();
    let forged_id = uuid::Uuid::new_v4().to_string();
    let good_id = uuid::Uuid::new_v4().to_string();
    let now = ai_memory::identity::attest::now_attestable_rfc3339();
    let old = ai_memory::identity::attest::canonicalize_attested_created_at(
        &(chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339(),
    )
    .expect("canonical old timestamp");
    let memories: Vec<Value> = [(&old_id, &old), (&forged_id, &now), (&good_id, &now)]
        .into_iter()
        .map(|(id, created)| {
            let mut value = memory_json(
                id,
                "team/alpha",
                id,
                "replicated content",
                created,
                &now,
                author,
                "",
            );
            let memory: ai_memory::models::Memory =
                serde_json::from_value(value.clone()).expect("memory");
            let mut signature =
                ai_memory::identity::attest::sign_memory_write(kp, &memory, author).expect("sign");
            if id == &forged_id {
                signature[0] ^= 1;
            }
            value["metadata"]["write_signature"] =
                json!(base64::engine::general_purpose::STANDARD.encode(signature));
            value
        })
        .collect();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            author,
        )
        .body(Body::from(
            json!({
                "sender_agent_id": author, "sender_clock": {"entries": {}},
                "memories": memories, "dry_run": false,
            })
            .to_string(),
        ))
        .expect("push request");
    let logs = CapturedLog::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || writer.clone())
        .finish();
    let response = router
        .oneshot(request)
        .with_subscriber(subscriber)
        .await
        .expect("push response");
    assert_eq!(response.status(), StatusCode::OK, "partial batch response");
    let bytes = axum::body::to_bytes(response.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("response body");
    let body: Value = serde_json::from_slice(&bytes).expect("response JSON");
    assert_eq!(body["applied"], 1, "eligible key still replicates: {body}");
    assert_eq!(
        body["skipped"], 2,
        "ineligible and forged writes refused: {body}"
    );
    assert_eq!(
        body["attestation_rejections"],
        json!([
            {
                "memory_id": old_id,
                "cause": ai_memory::federation::receive_auth::CAUSE_NO_ELIGIBLE_KEY_AT_CREATED_AT,
            },
            {
                "memory_id": forged_id,
                "cause": ai_memory::federation::receive_auth::CAUSE_FORGED_OR_MALFORMED,
            },
        ]),
        "HTTP 200 must expose every attestation refusal"
    );
    let log = String::from_utf8(logs.0.lock().expect("log buffer").clone()).expect("UTF-8 log");
    for (id, cause) in [
        (
            &old_id,
            ai_memory::federation::receive_auth::CAUSE_NO_ELIGIBLE_KEY_AT_CREATED_AT,
        ),
        (
            &forged_id,
            ai_memory::federation::receive_auth::CAUSE_FORGED_OR_MALFORMED,
        ),
    ] {
        assert!(
            log.lines()
                .any(|line| line.contains("WARN") && line.contains(id) && line.contains(cause)),
            "each refused item must emit its cause at WARN: {log}"
        );
    }
    assert!(
        log.contains(&old),
        "rejection log must identify the signed timestamp: {log}"
    );
    (old_id, forged_id, good_id)
}

/// SQLite arm of the #3502 decision (see [`push_timestamp_matrix`]): the two
/// refused rows must not persist, and the eligible one must still land
/// `agent_attested`. DEGRADE, never corrupt — a refusal costs one row, never a
/// wrong attestation.
#[tokio::test]
async fn sqlite_prebinding_signature_rejected_visibly_3502() {
    let _guard = ENV_LOCK.lock().await;
    reset_env_zero_config();
    let (router, db) = build_router_with_db();
    let author = "ai:timestamp-sqlite";
    let kp = ai_memory::identity::keypair::generate(author).expect("keypair");
    {
        let lock = db.lock().await;
        ai_memory::db::register_agent(&lock.0, author, "nhi", &[]).expect("register");
        ai_memory::db::bind_agent_pubkey_with_keypair(&lock.0, author, &kp).expect("bind");
    }
    let (old, forged, good) = push_timestamp_matrix(router, author, &kp).await;
    let lock = db.lock().await;
    for id in [old, forged] {
        assert!(
            ai_memory::db::get(&lock.0, &id)
                .expect("read refused row")
                .is_none(),
            "refused row must not persist"
        );
    }
    let memory = ai_memory::db::get(&lock.0, &good)
        .expect("read accepted row")
        .expect("accepted row persists");
    assert_eq!(memory.metadata["attest_level"], "agent_attested");
}

/// PostgreSQL twin of [`sqlite_prebinding_signature_rejected_visibly_3502`].
/// Both backends must reach the same verdict, the same cause tokens and the
/// same response shape; a backend-specific answer to "is this write attested"
/// is a data-integrity divergence, not a feature gap.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_prebinding_signature_rejected_visibly_3502() {
    let _guard = ENV_LOCK.lock().await;
    reset_env_zero_config();
    let url =
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("own PG URL required; no soft skip");
    let mut app = build_app();
    app.store = std::sync::Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("own PG database"),
    );
    app.storage_backend = ai_memory::handlers::StorageBackend::Postgres;
    let author = "ai:timestamp-postgres";
    let kp = ai_memory::identity::keypair::generate(author).expect("keypair");
    let ctx = ai_memory::store::CallerContext::for_agent(author);
    let now = ai_memory::identity::attest::now_attestable_rfc3339();
    app.store
        .register_agent(
            &ctx,
            &ai_memory::models::AgentRegistration {
                agent_id: author.to_string(),
                agent_type: "nhi".to_string(),
                capabilities: Vec::new(),
                registered_at: now.clone(),
                last_seen_at: now,
            },
        )
        .await
        .expect("register");
    let proof = ai_memory::store::prove_possession_via_store(
        app.store.as_ref(),
        &ctx,
        author,
        kp.private.as_ref().expect("private key"),
    )
    .await
    .expect("prove possession");
    app.store
        .bind_agent_pubkey(&ctx, author, &kp.public_base64(), proof)
        .await
        .expect("bind");
    let (old, forged, good) = push_timestamp_matrix(router_for(app), author, &kp).await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("PG inspection");
    for id in [old, forged] {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("read refused row");
        assert_eq!(count, 0, "refused row must not persist");
    }
    let level: String =
        sqlx::query_scalar("SELECT metadata->>'attest_level' FROM memories WHERE id = $1")
            .bind(good)
            .fetch_one(&pool)
            .await
            .expect("accepted row persists");
    assert_eq!(level, "agent_attested");
    pool.close().await;
}
