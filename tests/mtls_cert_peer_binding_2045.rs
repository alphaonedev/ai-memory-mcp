// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2045 L6 — mTLS client-cert ↔ `X-Peer-Id` cross-check regression tests.
//!
//! Under `AI_MEMORY_FED_REQUIRE_SIG=0` the mTLS `/sync/*` path trusted a
//! verbatim `X-Peer-Id` header: any holder of ANY allowlisted client cert
//! could assert any peer identity (#2032 finding L6). The fix binds the
//! presenting client cert (by operator-declared SHA-256 fingerprint) to the
//! ONE peer-id it may assert, injects that binding into request extensions
//! via the peer-binding mTLS acceptor (`tls::PeerBindingAcceptor`), and
//! cross-checks it against `X-Peer-Id` on `/sync/push` + `/sync/since`.
//!
//! Posture `AI_MEMORY_FED_CERT_PEER_BINDING = off|warn|enforce` (default
//! `warn`); legacy certs with no binding always degrade to WARN (never
//! brick). These tests drive the real handler code path in-process via
//! `tower::ServiceExt::oneshot`, injecting the `ClientCertPeerId` extension
//! the acceptor would have set on a live mTLS connection.

#![allow(clippy::too_many_lines)]
#![allow(clippy::await_holding_lock)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::tls::{CertPeerBindingMode, ClientCertPeerId, FED_CERT_PEER_BINDING_ENV};

/// Serialize the process-global env mutations these tests perform.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn setup_router() -> axum::Router {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    std::mem::forget(db_tmp);
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
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
        storage_backend: StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store: Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"),
        ),
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
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

/// POST `/api/v1/sync/push` with an optional `X-Peer-Id` header and an
/// optional injected `ClientCertPeerId` extension (simulating what the
/// peer-binding acceptor would have set on a live mTLS connection).
///
/// `cert_binding` deliberately distinguishes all THREE mTLS states the
/// handler treats differently: `None` (no extension — plain HTTP / no
/// binding map), `Some(None)` (mTLS cert with no operator binding — the
/// never-brick legacy path), and `Some(Some(id))` (cert bound to `id`).
#[allow(clippy::option_option)]
async fn post_sync_push(
    router: &axum::Router,
    peer_id: Option<&str>,
    cert_binding: Option<Option<&str>>,
) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": "peer-a",
        "sender_clock": {"entries": {}},
        "memories": [],
        "dry_run": false,
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json");
    if let Some(p) = peer_id {
        builder = builder.header(ai_memory::federation::peer_attestation::PEER_ID_HEADER, p);
    }
    let mut req = builder.body(Body::from(body_bytes)).unwrap();
    if let Some(binding) = cert_binding {
        req.extensions_mut()
            .insert(ClientCertPeerId(binding.map(str::to_string)));
    }
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Neutralise every OTHER `/sync/push` gate so we isolate the #2045 check:
/// no signature requirement, no peer allowlist (TOFU no-op), body agent-id
/// trusted (#238 no-op).
fn relax_other_gates() {
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
}

fn clear_env() {
    unsafe {
        std::env::remove_var(FED_CERT_PEER_BINDING_ENV);
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn mismatched_peer_id_refused_under_enforce() {
    let _g = env_lock();
    relax_other_gates();
    unsafe {
        std::env::set_var(FED_CERT_PEER_BINDING_ENV, "enforce");
    }
    let router = setup_router();
    // Cert is operator-bound to "peer-a"; the request asserts "peer-b".
    let (status, body) = post_sync_push(&router, Some("peer-b"), Some(Some("peer-a"))).await;
    clear_env();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "#2045: a cert bound to peer-a asserting X-Peer-Id peer-b MUST be refused under enforce; \
         body={body}"
    );
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "peer_id_cert_mismatch",
        "#2045: refusal MUST carry the canonical cross-check tag; body={body}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn matching_peer_id_accepted_under_enforce() {
    let _g = env_lock();
    relax_other_gates();
    unsafe {
        std::env::set_var(FED_CERT_PEER_BINDING_ENV, "enforce");
    }
    let router = setup_router();
    // Cert bound to "peer-a", request asserts "peer-a" — passes the gate.
    let (status, body) = post_sync_push(&router, Some("peer-a"), Some(Some("peer-a"))).await;
    clear_env();
    assert_eq!(
        status,
        StatusCode::OK,
        "#2045: a matching cert↔X-Peer-Id MUST pass the cross-check; body={body}"
    );
    assert_ne!(
        body["error"].as_str().unwrap_or(""),
        "peer_id_cert_mismatch"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn mismatched_peer_id_allowed_under_warn() {
    let _g = env_lock();
    relax_other_gates();
    unsafe {
        std::env::set_var(FED_CERT_PEER_BINDING_ENV, "warn");
    }
    let router = setup_router();
    let (status, body) = post_sync_push(&router, Some("peer-b"), Some(Some("peer-a"))).await;
    clear_env();
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "#2045: under warn a mismatch is logged, NOT refused; body={body}"
    );
    assert_ne!(
        body["error"].as_str().unwrap_or(""),
        "peer_id_cert_mismatch"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_cert_without_binding_never_bricks_under_enforce() {
    let _g = env_lock();
    relax_other_gates();
    unsafe {
        std::env::set_var(FED_CERT_PEER_BINDING_ENV, "enforce");
    }
    let router = setup_router();
    // The presenting cert's fingerprint carries NO binding — degrade to a
    // WARN even under enforce, so an unmapped legacy peer is not bricked.
    let (status, body) = post_sync_push(&router, Some("peer-b"), Some(None)).await;
    clear_env();
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "#2045: a cert with no operator binding MUST degrade to WARN, never brick; body={body}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn no_cert_extension_skips_check_under_enforce() {
    let _g = env_lock();
    relax_other_gates();
    unsafe {
        std::env::set_var(FED_CERT_PEER_BINDING_ENV, "enforce");
    }
    let router = setup_router();
    // No `ClientCertPeerId` extension at all (plain-HTTP / no binding map):
    // the cross-check is skipped — cannot bind what did not arrive over the
    // peer-binding acceptor.
    let (status, _body) = post_sync_push(&router, Some("peer-b"), None).await;
    clear_env();
    assert_ne!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "current_thread")]
async fn mismatch_ignored_when_posture_off() {
    let _g = env_lock();
    relax_other_gates();
    unsafe {
        std::env::set_var(FED_CERT_PEER_BINDING_ENV, "off");
    }
    let router = setup_router();
    let (status, body) = post_sync_push(&router, Some("peer-b"), Some(Some("peer-a"))).await;
    clear_env();
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "#2045: posture=off is the pre-#2045 verbatim-X-Peer-Id behaviour; body={body}"
    );
}

// ---------------------------------------------------------------------------
// Pure parser / posture-resolver coverage.
// ---------------------------------------------------------------------------

#[test]
fn binding_map_parses_and_supports_rotation() {
    let fp_a = "a".repeat(64);
    let fp_b = "b".repeat(64);
    let body = format!(
        "# operator cert-peer bindings\n\
         {fp_a} peer-one   # node one\n\
         sha256:{fp_b} peer-one\n\
         \n"
    );
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), body).unwrap();
    let map = ai_memory::tls::load_cert_peer_binding_map(tmp.path()).unwrap();
    // Two distinct fingerprints, both bound to the same peer-id (rotation).
    assert_eq!(map.get(&[0xaa; 32]).map(String::as_str), Some("peer-one"));
    assert_eq!(map.get(&[0xbb; 32]).map(String::as_str), Some("peer-one"));
}

#[test]
fn binding_map_rejects_conflicting_peer_id_for_one_fingerprint() {
    let fp = "c".repeat(64);
    let body = format!("{fp} peer-one\n{fp} peer-two\n");
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), body).unwrap();
    let err = ai_memory::tls::load_cert_peer_binding_map(tmp.path()).unwrap_err();
    assert!(
        err.to_string().contains("already bound"),
        "conflicting binding must be a fail-closed parse error; got: {err}"
    );
}

#[test]
fn binding_map_rejects_missing_peer_id_field() {
    let fp = "d".repeat(64);
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), format!("{fp}\n")).unwrap();
    let err = ai_memory::tls::load_cert_peer_binding_map(tmp.path()).unwrap_err();
    assert!(err.to_string().contains("expected"), "got: {err}");
}

#[test]
fn binding_map_rejects_malformed_peer_id() {
    let fp = "e".repeat(64);
    let tmp = tempfile::NamedTempFile::new().unwrap();
    // A space-free but control-char-bearing peer-id fails the agent-id shape.
    std::fs::write(tmp.path(), format!("{fp} bad$peer\n")).unwrap();
    let err = ai_memory::tls::load_cert_peer_binding_map(tmp.path()).unwrap_err();
    assert!(err.to_string().contains("valid peer-id"), "got: {err}");
}

#[test]
fn posture_parse_defaults_to_warn() {
    assert_eq!(CertPeerBindingMode::parse("off"), CertPeerBindingMode::Off);
    assert_eq!(
        CertPeerBindingMode::parse("ENFORCE"),
        CertPeerBindingMode::Enforce
    );
    assert_eq!(
        CertPeerBindingMode::parse("warn"),
        CertPeerBindingMode::Warn
    );
    // Unrecognised / typo falls through to the secure-but-non-bricking default.
    assert_eq!(
        CertPeerBindingMode::parse("banana"),
        CertPeerBindingMode::Warn
    );
}
