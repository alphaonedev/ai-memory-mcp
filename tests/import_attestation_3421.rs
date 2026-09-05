// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3421 (security-high, v1.0.0) — `POST /api/v1/import` must never land a
//! wire-asserted attestation it cannot verify.
//!
//! Pre-fix the handler re-owned every imported row to the importing admin
//! (`restamp_agent_id` rewrites `metadata.agent_id`) but carried the body's
//! `metadata.attest_level` and `metadata.write_signature` through VERBATIM.
//! The stored row therefore asserted `agent_attested` while carrying a
//! signature minted over a DIFFERENT `agent_id` / `namespace` / `title` — an
//! attestation no principal ever signed, which every downstream trust surface
//! (`row_is_agent_attested`, federation relay, the attestation census) then
//! believed. The CLI L1 route (#2264) and the portability v2 route both
//! already re-derived the attestation from what the DESTINATION can verify;
//! HTTP was the one surface that did neither.
//!
//! The control is `identity::attest::reconcile_imported_attestation` — ONE
//! funnel, called by both import branches of `handlers::admin::import_memories`
//! (and by `portability::import::apply_import_attestation`), so a future
//! import surface cannot re-introduce the forge primitive.
//!
//! Coverage, DENIED and ALLOWED, on BOTH backend lanes:
//!
//! * sqlite lane — `StorageBackend::Sqlite` (the `db::insert` branch).
//! * postgres lane — `StorageBackend::Postgres` driving the SAL
//!   `app.store.agent_pubkey` / `app.store.store` branch, wired over an
//!   `SqliteStore` handle (the `handler_postgres_branches_fake_pg` harness
//!   pattern; the branch under test is handler-side, and the attestation
//!   funnel itself is backend-agnostic).

#![cfg(feature = "sal")]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::verify::AttestLevel;
use ai_memory::models::field_names;
use ai_memory::models::{Memory, Tier};

const ADMIN: &str = "ops:admin";
const OUTSIDER: &str = "ai:victim@elsewhere";

/// #1751 — pin this binary to the permissive store-path attestation posture;
/// the fixtures below store through the import funnel, not the signed create
/// funnel, and must not be rejected by the HTTP-direct default.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before any gated store is issued.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

/// Build an admin-gated router on `backend`. Returns the router plus the
/// tempfile that owns the sqlite database (kept alive by the caller) and its
/// path, so a test can read the DURABLE row back and assert on what actually
/// landed — not merely on the wire envelope.
fn build_router(backend: StorageBackend) -> (axum::Router, NamedTempFile, std::path::PathBuf) {
    permissive_attestation_for_tests();
    // #1570 — model an AUTHENTICATED deployment (api_key configured at boot).
    // `require_admin` honours an `X-Agent-Id` role claim only when the daemon
    // has request authn configured or the operator opted into the legacy
    // trust-the-header posture; without this the admin allowlist alone yields
    // 403 by secure default. The #1570 default itself is pinned by
    // `tests/admin_header_trust_1570.rs` in its own process; this suite is
    // about attestation, not the admin gate. Same fixture line as
    // `tests/import_memories_admin_gate_956.rs`.
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
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
        admin_agent_ids: Arc::new(vec![ADMIN.to_string()]),
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
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f, db_path)
}

async fn import_as_admin(router: &axum::Router, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/import")
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn fixture(id: &str, title: &str, author: &str) -> Memory {
    // #3464: the signed write must fall inside its newly enrolled key window.
    let stamp = ai_memory::identity::attest::now_attestable_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: "imp".to_string(),
        title: title.to_string(),
        content: "the durable body of the imported memory".to_string(),
        created_at: stamp.clone(),
        updated_at: stamp,
        metadata: json!({ "agent_id": author }),
        ..Memory::default()
    }
}

/// Read the DURABLE row back from the sqlite file the daemon wrote.
fn stored(db_path: &std::path::Path, id: &str) -> Memory {
    let conn = ai_memory::db::open(db_path).expect("reopen for readback");
    ai_memory::db::get(&conn, id)
        .expect("db::get")
        .expect("row present")
}

fn attest_level_of(mem: &Memory) -> Option<&str> {
    mem.metadata
        .get(field_names::ATTEST_LEVEL)
        .and_then(Value::as_str)
}

/// Register `agent_id` and bind its Ed25519 public key in the destination, so
/// the funnel's `agent_pubkey` lookup resolves a key to verify against. The
/// bind REQUIRES an existing registration row (`bind_agent_pubkey` refuses
/// otherwise), which is why both steps run — the `provision_agent` pattern from
/// `tests/agent_attestation_integrity.rs`.
fn enroll(db_path: &std::path::Path, agent_id: &str) -> ai_memory::identity::keypair::AgentKeypair {
    let kp = ai_memory::identity::keypair::generate(agent_id).expect("generate keypair");
    let conn = ai_memory::db::open(db_path).expect("reopen for enroll");
    ai_memory::storage::register_agent(&conn, agent_id, "nhi", &[]).expect("register agent");
    ai_memory::storage::bind_agent_pubkey_with_keypair(&conn, agent_id, &kp).expect("bind pubkey");
    kp
}

fn sign_b64(
    kp: &ai_memory::identity::keypair::AgentKeypair,
    mem: &Memory,
    agent_id: &str,
) -> String {
    use base64::Engine as _;
    let sig = ai_memory::identity::attest::sign_memory_write(kp, mem, agent_id).expect("sign");
    base64::engine::general_purpose::STANDARD.encode(sig)
}

// ---------------------------------------------------------------------------
// DENIED — a re-owned row can never keep the original author's attestation
// ---------------------------------------------------------------------------

async fn reowned_row_lands_claimed(backend: StorageBackend) {
    let (router, _f, db_path) = build_router(backend);
    // The victim genuinely signed this row under THEIR OWN id — the strongest
    // form of the attack: every byte of the signature is real, it simply does
    // not belong to the row once the import re-owns it to the admin.
    let victim_kp = enroll(&db_path, OUTSIDER);
    let id = uuid::Uuid::new_v4().to_string();
    let mut mem = fixture(&id, "re-owned row", OUTSIDER);
    let sig_b64 = sign_b64(&victim_kp, &mem, OUTSIDER);
    mem.metadata = json!({
        "agent_id": OUTSIDER,
        (field_names::ATTEST_LEVEL): AttestLevel::AgentAttested.as_str(),
        (field_names::WRITE_SIGNATURE): sig_b64,
        (field_names::AGENT_PUBKEY): victim_kp.public_base64(),
    });

    let (status, body) = import_as_admin(
        &router,
        json!({ "memories": [serde_json::to_value(&mem).unwrap()] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["imported"], json!(1), "body: {body}");

    let row = stored(&db_path, &id);
    assert_eq!(
        attest_level_of(&row),
        Some(AttestLevel::Claimed.as_str()),
        "a re-owned row must land claimed, never agent_attested: {}",
        row.metadata
    );
    assert!(
        row.metadata.get(field_names::WRITE_SIGNATURE).is_none(),
        "the stale signature must be dropped, never retained beside a new owner: {}",
        row.metadata
    );
    assert!(
        row.metadata.get(field_names::AGENT_PUBKEY).is_none(),
        "an unauthenticated wire identity-key claim must never seed the enrolled-key surface: {}",
        row.metadata
    );
    // The original claim is still recorded — provenance is preserved, only the
    // unverifiable ATTESTATION is dropped (degrade, never corrupt).
    assert_eq!(
        row.metadata
            .get(field_names::IMPORTED_FROM_AGENT_ID)
            .and_then(Value::as_str),
        Some(OUTSIDER),
        "{}",
        row.metadata
    );
}

#[tokio::test]
async fn sqlite_import_reowned_row_lands_claimed_3421() {
    reowned_row_lands_claimed(StorageBackend::Sqlite).await;
}

#[tokio::test]
async fn postgres_import_reowned_row_lands_claimed_3421() {
    reowned_row_lands_claimed(StorageBackend::Postgres).await;
}

// ---------------------------------------------------------------------------
// DENIED — a presented-but-FORGED signature skips the row entirely
// ---------------------------------------------------------------------------

async fn forged_signature_skips_the_row(backend: StorageBackend) {
    let (router, _f, db_path) = build_router(backend);
    // The admin IS enrolled, and the row is already attributed to the admin —
    // so the re-attribution rule does not fire and the signature is actually
    // verified. It was minted by a DIFFERENT key, so it is forged.
    let _admin_kp = enroll(&db_path, ADMIN);
    let attacker_kp = ai_memory::identity::keypair::generate(ADMIN).expect("attacker keypair");
    let id = uuid::Uuid::new_v4().to_string();
    let mut mem = fixture(&id, "forged row", ADMIN);
    let forged = sign_b64(&attacker_kp, &mem, ADMIN);
    mem.metadata = json!({
        "agent_id": ADMIN,
        (field_names::ATTEST_LEVEL): AttestLevel::AgentAttested.as_str(),
        (field_names::WRITE_SIGNATURE): forged,
    });

    let (status, body) = import_as_admin(
        &router,
        json!({ "memories": [serde_json::to_value(&mem).unwrap()] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["imported"],
        json!(0),
        "a forged signature must never land a row: {body}"
    );
    assert!(
        body["errors"].as_array().is_some_and(|e| e
            .iter()
            .any(|m| m.as_str().is_some_and(|s| s.contains("forged")))),
        "the refusal must name the cause: {body}"
    );
    let conn = ai_memory::db::open(&db_path).expect("reopen for readback");
    assert!(
        ai_memory::db::get(&conn, &id).expect("db::get").is_none(),
        "a forged-signature row must not exist at all — never downgraded into storage"
    );
}

#[tokio::test]
async fn sqlite_import_forged_signature_skips_row_3421() {
    forged_signature_skips_the_row(StorageBackend::Sqlite).await;
}

#[tokio::test]
async fn postgres_import_forged_signature_skips_row_3421() {
    forged_signature_skips_the_row(StorageBackend::Postgres).await;
}

// ---------------------------------------------------------------------------
// ALLOWED — a genuine self-authored, destination-verifiable attestation survives
// ---------------------------------------------------------------------------

async fn genuine_self_signed_row_stays_attested(backend: StorageBackend) {
    let (router, _f, db_path) = build_router(backend);
    let admin_kp = enroll(&db_path, ADMIN);
    let id = uuid::Uuid::new_v4().to_string();
    let mut mem = fixture(&id, "genuine self-signed row", ADMIN);
    let sig_b64 = sign_b64(&admin_kp, &mem, ADMIN);
    mem.metadata = json!({
        "agent_id": ADMIN,
        (field_names::ATTEST_LEVEL): AttestLevel::AgentAttested.as_str(),
        (field_names::WRITE_SIGNATURE): sig_b64.clone(),
    });

    let (status, body) = import_as_admin(
        &router,
        json!({ "memories": [serde_json::to_value(&mem).unwrap()] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["imported"], json!(1), "body: {body}");

    let row = stored(&db_path, &id);
    assert_eq!(
        attest_level_of(&row),
        Some(AttestLevel::AgentAttested.as_str()),
        "a signature the destination CAN verify must keep its attestation: {}",
        row.metadata
    );
    assert_eq!(
        row.metadata
            .get(field_names::WRITE_SIGNATURE)
            .and_then(Value::as_str),
        Some(sig_b64.as_str()),
        "the verified signature must be preserved verbatim: {}",
        row.metadata
    );
}

#[tokio::test]
async fn sqlite_import_genuine_self_signed_stays_attested_3421() {
    genuine_self_signed_row_stays_attested(StorageBackend::Sqlite).await;
}

#[tokio::test]
async fn postgres_import_genuine_self_signed_stays_attested_3421() {
    genuine_self_signed_row_stays_attested(StorageBackend::Postgres).await;
}

// ---------------------------------------------------------------------------
// ALLOWED — an ordinary unattested row is imported byte-for-byte as before
// ---------------------------------------------------------------------------

async fn plain_row_is_unchanged(backend: StorageBackend) {
    let (router, _f, db_path) = build_router(backend);
    let id = uuid::Uuid::new_v4().to_string();
    let mem = fixture(&id, "plain row", OUTSIDER);

    let (status, body) = import_as_admin(
        &router,
        json!({ "memories": [serde_json::to_value(&mem).unwrap()] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["imported"], json!(1), "body: {body}");

    let row = stored(&db_path, &id);
    assert!(
        attest_level_of(&row).is_none(),
        "a row that asserted nothing must not acquire an attest_level: {}",
        row.metadata
    );
    assert!(
        row.metadata.get(field_names::WRITE_SIGNATURE).is_none(),
        "{}",
        row.metadata
    );
    assert_eq!(row.title, "plain row");
    assert_eq!(row.content, "the durable body of the imported memory");
}

#[tokio::test]
async fn sqlite_import_plain_row_unchanged_3421() {
    plain_row_is_unchanged(StorageBackend::Sqlite).await;
}

#[tokio::test]
async fn postgres_import_plain_row_unchanged_3421() {
    plain_row_is_unchanged(StorageBackend::Postgres).await;
}
