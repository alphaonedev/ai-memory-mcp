// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal")]
#![allow(clippy::doc_markdown)]

//! #2000 (v1.0.x) — HTTP signed-bulk **write-signature EMIT** integration.
//!
//! PR #1999 (#1801→#1954) wired the store-time write-signature sender-EMIT
//! into the `POST /api/v1/memories/bulk` path (commit `fdaa1abe`, both
//! backends: `src/handlers/memories_query.rs::bulk_create`, the postgres
//! branch ~L899 and the sqlite branch ~L1159). That fix was validated only
//! by clippy + the `persist_write_signature` UNIT tests — CI had **no HTTP
//! integration test that drives a signed bulk POST end-to-end and asserts
//! the author's `metadata.write_signature` is EMITTED / persisted**. This
//! binary closes that gap.
//!
//! Each test drives `bulk_create` over HTTP with one validly-signed row
//! (an Ed25519 signature over the #626 `SignableWrite` envelope
//! `agent_id + namespace + title + kind + created_at + sha256(content)`),
//! then re-opens the DB and asserts the persisted memory carries a
//! `metadata.write_signature` that (a) round-trips the presented base64 and
//! (b) decodes to the exact signature bytes the author signed — plus
//! `attest_level = "agent_attested"` so the row is provably the same one the
//! gate verified.
//!
//! **Both backend branches, deterministically.** The sqlite test runs a real
//! `StorageBackend::Sqlite`; the postgres test uses the established "fake-PG"
//! pattern (`handler_postgres_branches_fake_pg.rs` /
//! `agent_attestation_postgres.rs`) — claim `StorageBackend::Postgres` while
//! wiring an `SqliteStore` as the `dyn MemoryStore`, so the postgres
//! `bulk_create` branch (with its `store_batch` persistence) fires against
//! the sqlite adapter. No live postgres, no network, no model dependency.
//!
//! **Regression guard.** A future bulk refactor that drops the
//! `persist_write_signature` EMIT call — the exact regression class the
//! PR #1999 adversarial audit found — makes the `write_signature`-present
//! assertions here fail CI.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::field_names::WRITE_SIGNATURE;

/// Build a router over a fresh sqlite DB file, advertising `backend`. Passing
/// `StorageBackend::Postgres` while backing it with an `SqliteStore` exercises
/// the postgres `bulk_create` branch (the "fake-PG" pattern) deterministically.
fn build_router(backend: StorageBackend) -> (axum::Router, NamedTempFile, std::path::PathBuf) {
    let f = NamedTempFile::new().expect("tempfile");
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
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
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
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f, db_path)
}

/// Register `agent_id` and bind `pubkey_b64` through a fresh connection on the
/// daemon's db file so the gate's bound-key lookup resolves it.
fn provision_agent(db_path: &std::path::Path, agent_id: &str, pubkey_b64: &str) {
    let conn = ai_memory::db::open(db_path).expect("reopen for provision");
    ai_memory::storage::register_agent(&conn, agent_id, "nhi", &[]).expect("register");
    ai_memory::storage::bind_agent_pubkey(&conn, agent_id, pubkey_b64).expect("bind");
}

/// Standard-base64 Ed25519 signature over the canonical store envelope.
fn sign_envelope(
    kp: &ai_memory::identity::keypair::AgentKeypair,
    agent_id: &str,
    namespace: &str,
    title: &str,
    content: &str,
    created_at: &str,
) -> String {
    let content_hash = ai_memory::identity::attest::content_sha256(content);
    let write = ai_memory::identity::sign::SignableWrite {
        agent_id,
        namespace,
        title,
        kind: ai_memory::models::MemoryKind::Observation.as_str(),
        created_at,
        content_sha256: &content_hash,
    };
    let sig = ai_memory::identity::sign::sign_write(kp, &write).expect("sign");
    base64::engine::general_purpose::STANDARD.encode(sig)
}

/// POST a bare JSON array (the bulk_create wire shape) as `agent_id`.
async fn post_bulk(router: &axum::Router, agent_id: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories/bulk")
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

/// Drive one validly-signed bulk row end-to-end and assert the author's
/// write-signature is EMITTED into the persisted `metadata.write_signature`.
/// Shared by the sqlite + fake-PG cases so both `bulk_create` branches are
/// pinned by identical assertions.
async fn assert_signed_bulk_row_emits_write_signature(backend: StorageBackend, namespace: &str) {
    let (router, _f, db_path) = build_router(backend);
    let agent = "ai:alice";
    let kp = ai_memory::identity::keypair::generate(agent).expect("keypair");
    provision_agent(&db_path, agent, &kp.public_base64());

    let title = "bulk-2000-signed";
    let content = "This is the body of bulk-2000-signed, long enough to be meaningful prose.";
    // #3422 — the attestation funnel accepts ONLY the canonical
    // storage-stable rendering (UTC, `+00:00`, microsecond-truncated):
    // it is the one form both backends return byte-for-byte, so the
    // signature stays re-derivable from the persisted row.
    let created_at = ai_memory::identity::attest::now_attestable_rfc3339();
    let sig_b64 = sign_envelope(&kp, agent, namespace, title, content, &created_at);

    // bulk_create accepts a bare JSON array (Vec<CreateMemory>); the per-row
    // `signature` + `created_at` carry the author's write attestation.
    let body = json!([
        {
            "title": title,
            "content": content,
            "namespace": namespace,
            "tier": "mid",
            "signature": sig_b64,
            "created_at": created_at,
        }
    ]);

    let (status, resp) = post_bulk(&router, agent, &body).await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "signed bulk POST must succeed; got {status}: {resp}"
    );
    assert_eq!(
        resp["created"].as_u64(),
        Some(1),
        "the one signed row must land; got: {resp}"
    );
    assert_eq!(
        resp["errors"].as_array().map(Vec::len),
        Some(0),
        "no per-row errors expected; got: {resp}"
    );

    // Re-open the DB and read the persisted row back (bulk responses carry no
    // per-row id, so cross-reference by namespace).
    let conn = ai_memory::db::open(&db_path).expect("reopen for read");
    let rows = ai_memory::db::list(
        &conn,
        Some(namespace),
        None,
        50,
        0,
        None,
        None,
        None,
        None,
        None,
        None, // #1834 valid_at
    )
    .expect("db::list");
    assert_eq!(rows.len(), 1, "exactly one persisted row; got: {rows:?}");
    let stored = &rows[0];

    // The gate verified the signature — proof the EMITted signature belongs to
    // the same row the gate accepted (not a stray/forged value).
    assert_eq!(
        stored.metadata["attest_level"].as_str(),
        Some("agent_attested"),
        "the signed bulk row must verify to agent_attested; metadata: {}",
        stored.metadata
    );

    // THE #2000 ASSERTION — the author's write-signature was EMITTED/persisted.
    let emitted = stored.metadata[WRITE_SIGNATURE]
        .as_str()
        .unwrap_or_else(|| {
            panic!(
                "metadata.write_signature MUST be emitted on the signed bulk path \
                 (#1801→#1954 EMIT); metadata: {}",
                stored.metadata
            )
        });
    // (a) round-trips the presented base64 verbatim, and
    assert_eq!(
        emitted, sig_b64,
        "emitted write_signature must round-trip the presented base64"
    );
    // (b) decodes to the exact detached signature bytes the author signed.
    let presented_bytes = base64::engine::general_purpose::STANDARD
        .decode(&sig_b64)
        .expect("presented sig decodes");
    let emitted_bytes = base64::engine::general_purpose::STANDARD
        .decode(emitted)
        .expect("emitted sig decodes (standard base64)");
    assert_eq!(
        emitted_bytes, presented_bytes,
        "emitted write_signature must decode to the author's signature bytes"
    );
}

#[tokio::test]
async fn http_bulk_signed_row_emits_write_signature_sqlite() {
    // Real sqlite backend → the sqlite `bulk_create` branch (~L1159).
    assert_signed_bulk_row_emits_write_signature(StorageBackend::Sqlite, "bulk-2000-sqlite").await;
}

#[tokio::test]
async fn http_bulk_signed_row_emits_write_signature_fake_pg() {
    // Fake-PG (Postgres backend advertised, SqliteStore under it) → the
    // postgres `bulk_create` branch (~L899), deterministically, no live PG.
    assert_signed_bulk_row_emits_write_signature(StorageBackend::Postgres, "bulk-2000-pg").await;
}
