// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7707 (HIGH, authorization) — admin elevation requires a key-attested
//! identity once per-agent keys are enrolled, in EVERY identity mode.
//!
//! Before the fix `admin_role::is_admin_caller_trusted` and
//! `admin_role::require_admin` consumed `identity_binding::enforce_for_request`,
//! which under the default `advisory` mode WARNs and then ADMITS a `Claimed`
//! (shared transport key, self-asserted `X-Agent-Id`) caller, and under `off` is a
//! no-op. So a deployment that enrolled per-agent keys but kept the default
//! posture still served the full admin surface to anyone holding the shared key
//! who typed an allowlisted admin id into the header.
//!
//! Decision A (3-agent vote 6def5ab6, memory 2b48c6f1): fail-closed admin
//! elevation once the enrolled map is non-empty, in every mode, with no new knob.
//! `advisory` keeps its WARN-only behaviour for ordinary (non-admin) identity
//! decisions; a keyless single-operator daemon (empty map) is unchanged.
//!
//! One `require_admin` site (`POST /api/v1/gc`) and one
//! `is_admin_caller_trusted` site (the predicate itself, plus the
//! `DELETE /api/v1/archive` owner-scope it feeds) are driven per cell.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::admin_role::is_admin_caller_trusted;
use ai_memory::handlers::identity_binding::api_key_sha256_hex;
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

const SHARED_KEY: &str = "shared-transport-key";
const ADMIN_KEY: &str = "admin-per-agent-key";
const BOB_KEY: &str = "bob-per-agent-key";
const ADMIN_ID: &str = "root-admin";
const BOB_ID: &str = "bob";
const CLAIMED_NON_ADMIN: &str = "carol";
const REFUSAL_ERROR: &str = "attested_identity_required";

fn fresh_dir() -> TempDir {
    let root = PathBuf::from(".local-runs").join("issue-7707-admin-trust");
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

/// Build a router + state in `mode`. `enroll_keys` selects whether the two
/// per-agent keys (the admin's and `bob`'s) are enrolled; `false` is the keyless
/// single-operator daemon. `root-admin` is always on the admin allowlist.
fn build(mode: HttpIdentityMode, enroll_keys: bool) -> (axum::Router, AppState, NamedTempFile) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
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
    if enroll_keys {
        map.insert(api_key_sha256_hex(ADMIN_KEY), ADMIN_ID.to_string());
        map.insert(api_key_sha256_hex(BOB_KEY), BOB_ID.to_string());
    }
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
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled,
        identity_mode: mode,
        ..Default::default()
    };
    let router = ai_memory::build_router(api_key_state, app_state.clone());
    (router, app_state, f)
}

fn headers_with_key(api_key: &str, agent_id: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("x-api-key", api_key.parse().unwrap());
    h.insert("x-agent-id", agent_id.parse().unwrap());
    h
}

/// `POST /api/v1/gc` — a `require_admin` site. `agent_id` is `None` to let the
/// per-agent key's middleware binding supply the header.
async fn post_gc(
    router: axum::Router,
    api_key: &str,
    agent_id: Option<&str>,
) -> (StatusCode, String) {
    let mut b = Request::builder()
        .method("POST")
        .uri("/api/v1/gc")
        .header("x-api-key", api_key);
    if let Some(id) = agent_id {
        b = b.header("x-agent-id", id);
    }
    let resp = router
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// `DELETE /api/v1/archive` — feeds `is_admin_caller_trusted` into the purge
/// owner-scope (`admin` vs `caller`).
async fn purge_scope(
    router: axum::Router,
    api_key: &str,
    agent_id: Option<&str>,
) -> (StatusCode, String) {
    let mut b = Request::builder()
        .method("DELETE")
        .uri("/api/v1/archive?older_than_days=3650")
        .header("x-api-key", api_key);
    if let Some(id) = agent_id {
        b = b.header("x-agent-id", id);
    }
    let resp = router
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn list_memories(router: axum::Router, api_key: &str, agent_id: &str) -> StatusCode {
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/memories")
        .header("x-api-key", api_key)
        .header("x-agent-id", agent_id)
        .body(Body::empty())
        .unwrap();
    router.oneshot(req).await.unwrap().status()
}

// ---------------------------------------------------------------------------
// (a) Advisory + enrolled keys + shared key + forged admin id -> no elevation.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_trust_7707_a_advisory_shared_key_forged_admin_require_admin_is_403() {
    let _dir = fresh_dir();
    let (router, _app, _f) = build(HttpIdentityMode::Advisory, true);
    let (status, body) = post_gc(router, SHARED_KEY, Some(ADMIN_ID)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#7707: advisory + enrolled per-agent keys must refuse a shared-key caller \
         forging an allowlisted admin X-Agent-Id on a require_admin surface"
    );
    assert!(
        body.contains(REFUSAL_ERROR),
        "the refusal reuses the closed-vocabulary error, body was {body}"
    );
}

#[tokio::test]
async fn admin_trust_7707_a_advisory_shared_key_forged_admin_predicate_is_untrusted() {
    let _dir = fresh_dir();
    let (router, app, _f) = build(HttpIdentityMode::Advisory, true);
    let shared = headers_with_key(SHARED_KEY, ADMIN_ID);
    assert!(
        !is_admin_caller_trusted(&app, &shared, ADMIN_ID),
        "#7707: advisory + enrolled keys must not treat a Claimed admin as trusted"
    );
    // The same predicate feeds the purge owner scope: no cross-tenant admin scope.
    let (status, body) = purge_scope(router, SHARED_KEY, Some(ADMIN_ID)).await;
    // Advisory WARNs for the IDOR gate and proceeds; the owner scope must be the
    // caller's, never admin.
    assert_eq!(status, StatusCode::OK, "purge body: {body}");
    assert!(
        !body.contains("\"owner_scope\":\"admin\""),
        "#7707: a Claimed admin must not get the admin purge scope, body was {body}"
    );
}

#[tokio::test]
async fn admin_trust_7707_a_advisory_non_admin_claimed_caller_still_admitted_with_warn() {
    let _dir = fresh_dir();
    let (router, _app, _f) = build(HttpIdentityMode::Advisory, true);
    // Advisory keeps its WARN-only behaviour for ordinary identity decisions:
    // a Claimed non-admin caller on an IDOR-gated read is served, not refused.
    assert_eq!(
        list_memories(router, SHARED_KEY, CLAIMED_NON_ADMIN).await,
        StatusCode::OK,
        "#7707: advisory must keep admitting a Claimed NON-admin caller (WARN only)"
    );
}

// ---------------------------------------------------------------------------
// (b) Enforce: the same request is refused (unchanged).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_trust_7707_b_enforce_shared_key_forged_admin_is_403() {
    let _dir = fresh_dir();
    let (router, app, _f) = build(HttpIdentityMode::Enforce, true);
    let shared = headers_with_key(SHARED_KEY, ADMIN_ID);
    assert!(!is_admin_caller_trusted(&app, &shared, ADMIN_ID));
    let (status, body) = post_gc(router, SHARED_KEY, Some(ADMIN_ID)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert!(body.contains(REFUSAL_ERROR), "body was {body}");
}

// ---------------------------------------------------------------------------
// (c) Advisory + the admin's own per-agent key -> elevation granted.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_trust_7707_c_advisory_admin_per_agent_key_is_admitted() {
    let _dir = fresh_dir();
    let (router, app, _f) = build(HttpIdentityMode::Advisory, true);
    let keyed = headers_with_key(ADMIN_KEY, ADMIN_ID);
    assert!(
        is_admin_caller_trusted(&app, &keyed, ADMIN_ID),
        "#7707: the admin's enrolled per-agent key must be trusted under advisory"
    );
    let (status, body) = post_gc(router, ADMIN_KEY, None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn admin_trust_7707_c_advisory_other_agents_key_cannot_elevate_admin_id() {
    let _dir = fresh_dir();
    let (router, app, _f) = build(HttpIdentityMode::Advisory, true);
    // bob presents HIS enrolled key but asserts the admin id: not attested as admin.
    let mixed = headers_with_key(BOB_KEY, ADMIN_ID);
    assert!(!is_admin_caller_trusted(&app, &mixed, ADMIN_ID));
    // The middleware rebinds X-Agent-Id to the key-derived principal (bob), who is
    // not on the allowlist: still refused.
    let (status, _body) = post_gc(router, BOB_KEY, Some(ADMIN_ID)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// (d) Keyless single-operator daemon: unchanged (#1570 rules).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_trust_7707_d_keyless_daemon_allowlisted_admin_header_unchanged() {
    for mode in [
        HttpIdentityMode::Advisory,
        HttpIdentityMode::Enforce,
        HttpIdentityMode::Off,
    ] {
        let _dir = fresh_dir();
        let (router, app, _f) = build(mode, false);
        let shared = headers_with_key(SHARED_KEY, ADMIN_ID);
        assert!(
            is_admin_caller_trusted(&app, &shared, ADMIN_ID),
            "#7707: with NO enrolled keys the predicate is unchanged ({mode:?})"
        );
        let (status, body) = post_gc(router, SHARED_KEY, Some(ADMIN_ID)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "#7707: keyless daemon + allowlisted admin header stays 200 ({mode:?}), body: {body}"
        );
    }
}

// ---------------------------------------------------------------------------
// (e) Off + enrolled keys + forged admin header -> no elevation.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_trust_7707_e_off_shared_key_forged_admin_is_403() {
    let _dir = fresh_dir();
    let (router, app, _f) = build(HttpIdentityMode::Off, true);
    let shared = headers_with_key(SHARED_KEY, ADMIN_ID);
    assert!(
        !is_admin_caller_trusted(&app, &shared, ADMIN_ID),
        "#7707: off + enrolled keys must not trust a Claimed admin"
    );
    let (status, body) = post_gc(router, SHARED_KEY, Some(ADMIN_ID)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#7707: off + enrolled keys must refuse a forged admin header, body: {body}"
    );
}

#[tokio::test]
async fn admin_trust_7707_e_off_admin_per_agent_key_still_admitted() {
    let _dir = fresh_dir();
    let (router, _app, _f) = build(HttpIdentityMode::Off, true);
    // Off mode does not rebind the header from the key, so the admin names itself.
    let (status, body) = post_gc(router, ADMIN_KEY, Some(ADMIN_ID)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

// ---------------------------------------------------------------------------
// (g) Boot signal: which allowlisted admin ids have no enrolled per-agent key.
// ---------------------------------------------------------------------------

fn enrolled_for(ids: &[&str]) -> HashMap<String, String> {
    ids.iter()
        .map(|id| (api_key_sha256_hex(&format!("{id}-key")), (*id).to_string()))
        .collect()
}

#[test]
fn admin_trust_7707_g_boot_reason_names_unkeyed_admin_under_advisory_and_off() {
    use ai_memory::handlers::admin_role::unattested_admin_boot_reason;
    let admins = vec![ADMIN_ID.to_string(), "keyed-admin".to_string()];
    let enrolled = enrolled_for(&[BOB_ID, "keyed-admin"]);
    for mode in [HttpIdentityMode::Advisory, HttpIdentityMode::Off] {
        let reason = unattested_admin_boot_reason(mode, &enrolled, &admins)
            .expect("an unkeyed allowlisted admin must be reported");
        assert!(reason.contains(ADMIN_ID), "{reason}");
        assert!(!reason.contains("keyed-admin"), "{reason}");
        assert!(reason.contains("agents bind-api-key"), "{reason}");
    }
}

#[test]
fn admin_trust_7707_g_boot_reason_is_silent_when_inert_enforced_or_keyed() {
    use ai_memory::handlers::admin_role::unattested_admin_boot_reason;
    let admins = vec![ADMIN_ID.to_string()];
    // Keyless daemon: inert.
    assert!(
        unattested_admin_boot_reason(HttpIdentityMode::Advisory, &HashMap::new(), &admins)
            .is_none()
    );
    // Enforce already refused these admins: no new signal.
    assert!(
        unattested_admin_boot_reason(HttpIdentityMode::Enforce, &enrolled_for(&[BOB_ID]), &admins)
            .is_none()
    );
    // Every admin keyed: nothing to say.
    assert!(
        unattested_admin_boot_reason(
            HttpIdentityMode::Advisory,
            &enrolled_for(&[ADMIN_ID, BOB_ID]),
            &admins
        )
        .is_none()
    );
}
