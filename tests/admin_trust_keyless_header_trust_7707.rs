// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7707 r3 (L5) - the keyless-daemon shape of the generic admin refusal.
//!
//! A daemon started with no `api_key` marks request authn as NOT configured
//! (`mark_request_authn_configured(false)`, `daemon_runtime.rs` bootstrap), so
//! the `AI_MEMORY_ADMIN_HEADER_TRUST` disjunct of the admin predicate is the
//! one that can decide. With per-agent keys enrolled and no credential on the
//! wire, an unknown id and the allowlisted-but-unattested admin id must get the
//! SAME generic 403 (status, full header map, 31 B body) whether header trust
//! is on (`1`) or off (`0`), in every identity mode.
//!
//! This binary holds exactly ONE test: the process-global authn marker and the
//! header-trust variable are mutated sequentially from that single test, with
//! no sibling test thread that could read the environment concurrently
//! (precedent: `tests/admin_visibility_bypass_gate_1582.rs:100-140`, one
//! sequential test per binary). The variable is removed by an RAII guard, also
//! on panic.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::admin_role::{ENV_ADMIN_HEADER_TRUST, mark_request_authn_configured};
use ai_memory::handlers::identity_binding::api_key_sha256_hex;
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

const ADMIN_KEY: &str = "admin-per-agent-key";
const BOB_KEY: &str = "bob-per-agent-key";
const ADMIN_ID: &str = "root-admin";
const BOB_ID: &str = "bob";
const UNKNOWN_ADMIN_CLAIM: &str = "mallory";
/// The ONE generic wire body for every `require_admin` refusal (31 bytes).
const GENERIC_ADMIN_REFUSAL: &str = r#"{"error":"admin role required"}"#;

type Wire = (StatusCode, HeaderMap, Vec<u8>);

/// Removes `AI_MEMORY_ADMIN_HEADER_TRUST` on drop, also when an assertion panics.
struct HeaderTrustGuard;

impl HeaderTrustGuard {
    fn set(value: &str) -> Self {
        // SAFETY: this binary has a single test, so no other thread of this
        // process reads or writes the environment while it runs (UNSAFE-04).
        unsafe { std::env::set_var(ENV_ADMIN_HEADER_TRUST, value) };
        Self
    }
}

impl Drop for HeaderTrustGuard {
    fn drop(&mut self) {
        // SAFETY: same single-test invariant as `set`.
        unsafe { std::env::remove_var(ENV_ADMIN_HEADER_TRUST) };
    }
}

fn fresh_dir() -> TempDir {
    let root = PathBuf::from(".local-runs").join("issue-7707-keyless-header-trust");
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

/// Keyless-daemon router: per-agent keys enrolled, NO shared transport key,
/// request authn marked NOT configured (the daemon bootstrap shape).
fn build_keyless(mode: HttpIdentityMode) -> (axum::Router, NamedTempFile) {
    mark_request_authn_configured(false);
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));

    let mut map = HashMap::new();
    map.insert(api_key_sha256_hex(ADMIN_KEY), ADMIN_ID.to_string());
    map.insert(api_key_sha256_hex(BOB_KEY), BOB_ID.to_string());
    let enrolled =
        Arc::new(ai_memory::handlers::identity_binding::EnrolledAgentKeys::from_map(map));

    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
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
        admin_agent_ids: Arc::new(vec![ADMIN_ID.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: enrolled.clone(),
        http_identity_mode: mode,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: enrolled,
        identity_mode: mode,
        ..Default::default()
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

/// Credential-less `POST /api/v1/gc` claiming `agent_id`: status, EVERY header,
/// body bytes.
async fn post_gc_claim(router: axum::Router, agent_id: &str) -> Wire {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/gc")
        .header("x-agent-id", agent_id)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, headers, bytes.to_vec())
}

fn assert_generic(label: &str, w: &Wire) {
    assert_eq!(w.0, StatusCode::FORBIDDEN, "{label}: status");
    assert_eq!(w.2.len(), 31, "{label}: body length");
    assert_eq!(
        String::from_utf8_lossy(&w.2),
        GENERIC_ADMIN_REFUSAL,
        "{label}: body is not the generic refusal"
    );
}

#[tokio::test]
async fn keyless_daemon_header_trust_on_and_off_refuse_identically_7707() {
    let _dir = fresh_dir();
    let mut reference: Option<Wire> = None;
    for trust in ["1", "0"] {
        let _guard = HeaderTrustGuard::set(trust);
        for mode in [
            HttpIdentityMode::Off,
            HttpIdentityMode::Advisory,
            HttpIdentityMode::Enforce,
        ] {
            let label = format!("keyless daemon, header-trust {trust}, {mode:?}");
            let (r1, _f1) = build_keyless(mode);
            let unknown = post_gc_claim(r1, UNKNOWN_ADMIN_CLAIM).await;
            let (r2, _f2) = build_keyless(mode);
            let admin = post_gc_claim(r2, ADMIN_ID).await;
            assert_generic(&format!("{label}, unknown id"), &unknown);
            assert_generic(&format!("{label}, allowlisted admin"), &admin);
            assert_eq!(admin.0, unknown.0, "{label}: status differs");
            assert_eq!(admin.1, unknown.1, "{label}: header map differs");
            assert_eq!(admin.2, unknown.2, "{label}: body bytes differ");
            match &reference {
                None => reference = Some(unknown),
                Some(r) => {
                    assert_eq!(r.0, unknown.0, "{label}: status differs across cells");
                    assert_eq!(r.1, unknown.1, "{label}: headers differ across cells");
                    assert_eq!(r.2, unknown.2, "{label}: body differs across cells");
                }
            }
        }
    }
}
