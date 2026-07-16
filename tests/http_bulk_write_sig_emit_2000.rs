// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2000 (v1.0.x) — HTTP signed-bulk write-signature EMIT integration coverage.
//!
//! PR #1999 (#1801→#1954) wired the store-time write-signature sender-EMIT into
//! single-create, MCP store, CLI `--sign`, and — after an adversarial audit
//! caught the gap — the `/api/v1/memories/bulk` path (`bulk_create`, both
//! backends). The bulk EMIT is pattern-identical to the fully-tested
//! single-create path, but no HTTP integration test exercised bulk EMIT
//! end-to-end (a signed bulk POST → stored `metadata.write_signature` that
//! round-trips + verifies against the author's key). The gap survived initial
//! review precisely because CI had no bulk-emit coverage — #2000 tracks that
//! residual.
//!
//! This test drives the real `bulk_create` HTTP handler in-process (via the
//! axum router + `tower::ServiceExt::oneshot`, the same harness the #238 /
//! F-53 attestation suites use) with a validly-signed row and asserts the
//! persisted memory carries the emitted `metadata.write_signature`, verified
//! against the author's enrolled key.
//!
//! It doubles as the **refactor guard** #2000's acceptance asks for: a future
//! `bulk_create` change that drops the `persist_write_signature` EMIT call (the
//! exact regression class the #1999 audit found) makes
//! `signed_bulk_row_emits_write_signature_2000` fail — the persisted row would
//! carry no `write_signature`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

/// Minimal sqlite-backed router + Db, mirroring the canonical in-process HTTP
/// harness in `tests/g_issue_238_sender_attestation.rs`. The `bulk_create`
/// sqlite branch (`memories_query.rs`) verifies + emits against `app.db`'s
/// connection, which is where the author key is enrolled below.
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
        llm: std::sync::Arc::new(None),
        auto_tag_model: std::sync::Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: std::sync::Arc::new(None),
        deferred_audit_queue: std::sync::Arc::new(None),
        admin_agent_ids: std::sync::Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, db)
}

/// Enroll `author`'s Ed25519 verifying key on `app.db`'s connection so the
/// bulk gate can verify a presented per-write signature against it.
async fn enroll_author(
    db: &ai_memory::handlers::Db,
    author: &str,
) -> ai_memory::identity::keypair::AgentKeypair {
    let kp = ai_memory::identity::keypair::generate(author).expect("keypair");
    let lock = db.lock().await;
    ai_memory::storage::register_agent(&lock.0, author, "nhi", &[]).expect("register");
    ai_memory::storage::bind_agent_pubkey(&lock.0, author, &kp.public_base64()).expect("bind");
    kp
}

/// Mint the standard-base64 #626 `SignableWrite` signature the bulk gate
/// rebuilds and verifies: `agent_id + namespace + title + kind + created_at +
/// sha256(content)`. `agent_id` is the resolved caller (the `X-Agent-Id`
/// header), NOT a body-metadata field.
fn sign_row(
    kp: &ai_memory::identity::keypair::AgentKeypair,
    author: &str,
    namespace: &str,
    title: &str,
    kind: &str,
    created_at: &str,
    content: &str,
) -> String {
    let content_hash = ai_memory::identity::attest::content_sha256(content);
    let write = ai_memory::identity::sign::SignableWrite {
        agent_id: author,
        namespace,
        title,
        kind,
        created_at,
        content_sha256: &content_hash,
    };
    base64::engine::general_purpose::STANDARD
        .encode(ai_memory::identity::sign::sign_write(kp, &write).expect("sign write"))
}

async fn post_bulk(router: &axum::Router, rows: &Value, author: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories/bulk")
        .header("content-type", "application/json")
        .header(ai_memory::HEADER_AGENT_ID, author)
        .body(Body::from(rows.to_string()))
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

/// Fetch the persisted row's `(metadata.write_signature, attest_level)` by id.
async fn stored_write_sig_and_level(
    db: &ai_memory::handlers::Db,
    ns: &str,
    title: &str,
) -> (Option<String>, Option<String>) {
    let lock = db.lock().await;
    lock.0
        .query_row(
            "SELECT json_extract(metadata, '$.write_signature'), \
             json_extract(metadata, '$.attest_level') \
             FROM memories WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![ns, title],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .unwrap_or((None, None))
}

#[tokio::test]
async fn signed_bulk_row_emits_write_signature_2000() {
    let (router, db) = build_router_with_db();

    let author = "ai:bulk-emit-author";
    let kp = enroll_author(&db, author).await;

    let ns = "bulk-emit-2000";
    let title = "signed bulk row";
    let content = "A signed bulk-authored body, long enough to be meaningful prose.";
    let kind = ai_memory::models::MemoryKind::Observation.as_str();
    let created_at = chrono::Utc::now().to_rfc3339();

    let sig_b64 = sign_row(&kp, author, ns, title, kind, &created_at, content);

    // A bulk POST of ONE validly-signed row.
    let rows = json!([{
        "tier": "long",
        "namespace": ns,
        "title": title,
        "content": content,
        "tags": [],
        "priority": 5,
        "source": "user",
        "kind": "observation",
        "created_at": created_at,
        "signature": sig_b64,
        "metadata": {},
    }]);

    let (status, body) = post_bulk(&router, &rows, author).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "signed bulk row must be accepted; body={body}"
    );
    assert_eq!(
        body["created"].as_i64(),
        Some(1),
        "exactly one signed row should have landed; body={body}"
    );

    // EMIT: the persisted row carries the author's write_signature verbatim,
    // and the row is stamped agent_attested (a verified per-write signature).
    let (stored_sig, level) = stored_write_sig_and_level(&db, ns, title).await;
    assert_eq!(
        stored_sig.as_deref(),
        Some(sig_b64.as_str()),
        "bulk_create must EMIT the presented write_signature into metadata (the #2000 gap)"
    );
    assert_eq!(
        level.as_deref(),
        Some("agent_attested"),
        "a verified per-write signature stamps agent_attested on the bulk path"
    );

    // ROUND-TRIP: the emitted signature verifies against the author's key over
    // the same SignableWrite the receiver rebuilds — proving it is a usable,
    // propagatable attestation, not an opaque blob.
    let stored_sig = stored_sig.unwrap();
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&stored_sig)
        .expect("emitted signature is standard base64");
    let content_hash = ai_memory::identity::attest::content_sha256(content);
    let write = ai_memory::identity::sign::SignableWrite {
        agent_id: author,
        namespace: ns,
        title,
        kind,
        created_at: &created_at,
        content_sha256: &content_hash,
    };
    ai_memory::identity::verify::verify_write(&kp.public, &write, &sig_bytes)
        .expect("the EMITTED bulk write_signature must verify against the author's key");
}

/// Negative guard: an UNSIGNED bulk row never gains a `write_signature` — the
/// EMIT is bound to a presented+verified signature, not fabricated by the
/// server. (Uses the permissive-attestation surface via an explicit body so
/// the row lands rather than being batch-rejected by the #1751 require gate.)
#[tokio::test]
async fn unsigned_bulk_row_has_no_write_signature_2000() {
    // SAFETY: single-threaded within this isolated test binary; the surface
    // default only matters for whether the unsigned row lands at all.
    unsafe {
        std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
    }
    let (router, db) = build_router_with_db();
    let author = "ai:bulk-unsigned-author";
    let _kp = enroll_author(&db, author).await;

    let ns = "bulk-emit-2000-unsigned";
    let title = "unsigned bulk row";
    let rows = json!([{
        "tier": "long",
        "namespace": ns,
        "title": title,
        "content": "An unsigned bulk-authored body — a bare claim, no signature.",
        "tags": [],
        "priority": 5,
        "source": "user",
        "kind": "observation",
        "metadata": {},
    }]);

    let (status, body) = post_bulk(&router, &rows, author).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unsigned row lands under permissive attestation; body={body}"
    );
    assert_eq!(
        body["created"].as_i64(),
        Some(1),
        "one unsigned row lands; body={body}"
    );

    let (stored_sig, _level) = stored_write_sig_and_level(&db, ns, title).await;
    assert_eq!(
        stored_sig, None,
        "an unsigned bulk row must carry NO write_signature (EMIT is not server-fabricated)"
    );
    unsafe {
        std::env::remove_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION");
    }
}
