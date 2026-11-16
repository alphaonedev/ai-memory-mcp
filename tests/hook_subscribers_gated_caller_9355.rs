// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9355 (found by the #8947 round 1 security review, H2) — the namespace
//! standard GET routes must sit behind the same identity gate as their siblings
//! in `src/handlers/hook_subscribers.rs` (set, clear, inbox, `session_start`).
//!
//! Defect class: a handler that builds its visibility caller from the request
//! (`X-Agent-Id`) with no identity gate at all. Pre-fix, a shared-transport-key
//! caller under Enforce could name any agent in `X-Agent-Id` and read that
//! agent's private namespace standard (title, content, governance) through the
//! path form, the query form and the query form with `inherit=true`.
//!
//! Invariant pinned here: for every form, under Enforce, a principal the key
//! does not prove is refused before any store read (403
//! `attested_identity_required`, exactly as the set / clear / inbox siblings),
//! the key-bound owner still reads its own standard, and the shipped default
//! mode answers every row as it did before the gate.
//!
//! Cells: `h9355_*` on SQLite always; on PostgreSQL when
//! `AI_MEMORY_TEST_POSTGRES_URL` is set, on an isolated scratch database.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::collections::HashMap;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::Memory;
use ai_memory::store::MemoryStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const AGENT_A: &str = "agent-a-9355";
const AGENT_B: &str = "agent-b-9355";
const KEY_A: &str = "key-a-9355-per-agent";
const KEY_B: &str = "key-b-9355-per-agent";
const SHARED_KEY: &str = "shared-transport-key-9355";
const STD_NAMESPACE: &str = "ns-9355-std";
const MARKER_B_STD: &str = "marker-9355-b-private-standard";
const ERR_ATTESTED_REQUIRED: &str = "attested_identity_required";
const ERR_BINDING_MISMATCH: &str = "identity_binding_mismatch";
const BODY_LIMIT_BYTES: usize = 512 * 1024;

/// The three GET forms of the namespace standard read.
const FORM_PATH: &str = "/api/v1/namespaces/ns-9355-std/standard";
const FORM_QS: &str = "/api/v1/namespaces?namespace=ns-9355-std";
const FORM_INHERIT: &str = "/api/v1/namespaces?namespace=ns-9355-std&inherit=true";
const FORMS: [&str; 3] = [FORM_PATH, FORM_QS, FORM_INHERIT];

const NONE: Option<&str> = None;
const HDR_A: Option<&str> = Some(AGENT_A);
const HDR_B: Option<&str> = Some(AGENT_B);

/// B's private memory, bound as the namespace standard.
fn b_standard() -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: STD_NAMESPACE.to_string(),
        title: "b-private-standard-9355".to_string(),
        content: MARKER_B_STD.to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test-9355".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": AGENT_B }),
        version: 1,
        ..Memory::default()
    }
}

fn build_router_in_mode(
    db: Db,
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    mode: HttpIdentityMode,
) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let mut enrolled = HashMap::new();
    enrolled.insert(api_key_sha256_hex(KEY_A), AGENT_A.to_string());
    enrolled.insert(api_key_sha256_hex(KEY_B), AGENT_B.to_string());
    let enrolled = Arc::new(EnrolledAgentKeys::from_map(enrolled));
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
        admin_agent_ids: Arc::new(Vec::new()),
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
    ai_memory::build_router(api_key_state, app_state)
}

fn scratch_dir() -> tempfile::TempDir {
    let root = std::path::PathBuf::from(".local-runs").join("issue-9355");
    std::fs::create_dir_all(&root).expect("create .local-runs/issue-9355");
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

fn sqlite_router_in_mode(dir: &tempfile::TempDir, mode: HttpIdentityMode) -> axum::Router {
    let db_path = dir.path().join("std-get-9355.db");
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let standard = b_standard();
    ai_memory::db::insert(&conn, &standard).expect("db::insert");
    ai_memory::db::set_namespace_standard(&conn, STD_NAMESPACE, &standard.id, None)
        .expect("set standard");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    build_router_in_mode(db, store, StorageBackend::Sqlite, mode)
}

async fn get(
    router: &axum::Router,
    uri: &str,
    key: &str,
    x_agent: Option<&str>,
) -> (StatusCode, Value, String) {
    let mut req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-api-key", key);
    if let Some(h) = x_agent {
        req = req.header("x-agent-id", h);
    }
    let resp = router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), BODY_LIMIT_BYTES)
        .await
        .unwrap();
    let raw = String::from_utf8_lossy(&bytes).into_owned();
    let parsed = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed, raw)
}

/// (key, header, expected status, expected error code, whether B's private
/// standard appears).
type Row = (
    &'static str,
    Option<&'static str>,
    StatusCode,
    Option<&'static str>,
    bool,
);

/// Under Enforce: a shared key proves no agent, so naming B is refused like the
/// siblings; A's key naming B is the transport's binding mismatch; A's key
/// naming A and the anonymous shared caller get 200 with B's standard withheld;
/// B's own key reads it.
const ENFORCE_ROWS: [Row; 5] = [
    (
        SHARED_KEY,
        HDR_B,
        StatusCode::FORBIDDEN,
        Some(ERR_ATTESTED_REQUIRED),
        false,
    ),
    (
        KEY_A,
        HDR_B,
        StatusCode::FORBIDDEN,
        Some(ERR_BINDING_MISMATCH),
        false,
    ),
    (KEY_A, HDR_A, StatusCode::OK, None, false),
    (SHARED_KEY, NONE, StatusCode::OK, None, false),
    (KEY_B, HDR_B, StatusCode::OK, None, true),
];

/// The shipped default mode, unchanged by the gate: the shared key + claimed
/// id row is the pre-existing Advisory behaviour tracked as #9352 (a warning,
/// not a refusal); A's key naming B is corrected to A.
const DEFAULT_ROWS: [Row; 5] = [
    (SHARED_KEY, HDR_B, StatusCode::OK, None, true),
    (KEY_A, HDR_B, StatusCode::OK, None, false),
    (KEY_A, HDR_A, StatusCode::OK, None, false),
    (SHARED_KEY, NONE, StatusCode::OK, None, false),
    (KEY_B, HDR_B, StatusCode::OK, None, true),
];

async fn cell_h9355_matrix(router: &axum::Router, mode: HttpIdentityMode) {
    let rows: &[Row] = if mode == HttpIdentityMode::Enforce {
        &ENFORCE_ROWS
    } else {
        &DEFAULT_ROWS
    };
    let mut mismatches: Vec<String> = Vec::new();
    for form in FORMS {
        for &(key, header, want_status, want_err, want_b) in rows {
            let (status, parsed, raw) = get(router, form, key, header).await;
            let err = parsed["error"].as_str();
            let err_ok = match want_err {
                Some(code) => err == Some(code),
                None => parsed["error"].is_null(),
            };
            let sees_b = raw.contains(MARKER_B_STD);
            if status != want_status || !err_ok || sees_b != want_b {
                mismatches.push(format!(
                    "h9355 {} {form} key={key} header={header:?}: want status={} err={want_err:?} \
                     b={want_b}; got status={} err={err:?} b={sees_b}",
                    mode.as_str(),
                    want_status.as_u16(),
                    status.as_u16(),
                ));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} cells differ:\n{}",
        mismatches.len(),
        FORMS.len() * rows.len(),
        mismatches.join("\n")
    );
}

#[tokio::test]
async fn h9355_sqlite_std_get_gate_enforce() {
    let dir = scratch_dir();
    let mode = HttpIdentityMode::Enforce;
    cell_h9355_matrix(&sqlite_router_in_mode(&dir, mode), mode).await;
}

#[tokio::test]
async fn h9355_sqlite_std_get_default_mode_unchanged() {
    let dir = scratch_dir();
    let mode = HttpIdentityMode::default();
    cell_h9355_matrix(&sqlite_router_in_mode(&dir, mode), mode).await;
}

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

#[cfg(feature = "sal-postgres")]
mod postgres_cells {
    use super::{
        AGENT_B, Arc, Db, HttpIdentityMode, MemoryStore, ResolvedTtl, STD_NAMESPACE,
        StorageBackend, b_standard, build_router_in_mode, cell_h9355_matrix, pg_barrier,
    };
    use ai_memory::store::CallerContext;
    use ai_memory::store::postgres::PostgresStore;

    const SCRATCH_PREFIX: &str = "ai_memory_9355sg";

    /// #1751 — the v0.9 store-path default demands signed attestation; this
    /// suite's unsigned seed row uses the explicit permissive opt-out, set once.
    fn permissive_attestation_for_tests() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        // SAFETY: `Once`-gated process-global env write, one stable value.
        ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
    }

    async fn pg_router_in_mode(
        mode: HttpIdentityMode,
    ) -> Option<(pg_barrier::ScratchDb, axum::Router)> {
        permissive_attestation_for_tests();
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL not set");
            return None;
        };
        let scratch = pg_barrier::ScratchDb::create(&url, SCRATCH_PREFIX)
            .await
            .expect("create scratch database");
        let pg = PostgresStore::connect(&scratch.url())
            .await
            .expect("connect scratch database");
        let standard = b_standard();
        let ctx = CallerContext::for_agent(AGENT_B);
        pg.store(&ctx, &standard).await.expect("seed standard row");
        pg.set_namespace_standard(&ctx, STD_NAMESPACE, &standard.id, None)
            .await
            .expect("bind standard");
        let store: Arc<dyn MemoryStore> = Arc::new(pg);
        let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
        let db: Db = Arc::new(tokio::sync::Mutex::new((
            conn,
            std::path::PathBuf::from(":memory:"),
            ResolvedTtl::default(),
            true,
        )));
        let router = build_router_in_mode(db, store, StorageBackend::Postgres, mode);
        Some((scratch, router))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn h9355_pg_std_get_gate_enforce() {
        let mode = HttpIdentityMode::Enforce;
        let Some((_scratch, router)) = pg_router_in_mode(mode).await else {
            return;
        };
        cell_h9355_matrix(&router, mode).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn h9355_pg_std_get_default_mode_unchanged() {
        let mode = HttpIdentityMode::default();
        let Some((_scratch, router)) = pg_router_in_mode(mode).await else {
            return;
        };
        cell_h9355_matrix(&router, mode).await;
    }
}
