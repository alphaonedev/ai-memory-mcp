// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3696 / #3690 — the refusal a caller gets for a `(title, namespace)` slot
//! whose occupant they CANNOT SEE (another agent's `scope=private` row) is
//! BYTE-IDENTICAL to the refusal for an occupant that is NOT FOUND IN THEIR
//! VIEW (a lifecycle-hidden row — quarantined; a TOMBSTONED occupant is the
//! #3690 ADMISSION case, the slot is free, so it is a control here). Pinned as
//! WHOLE-BODY comparisons, not as two prose strings asserted separately: a
//! reader of this file learns that the two axes are indistinguishable to the
//! caller, which is the non-disclosure property, and a future change that
//! makes one axis chattier than the other (an extra field, a different
//! message, an id that leaks on one path) fails here even if each axis still
//! satisfies its own prose pin.
//!
//! Three seams, each with a VISIBLE control that must differ (it names the
//! occupant's id), so an equality cannot pass because the whole refusal went
//! blank:
//! - the storage funnel (`db::insert_no_overwrite_as`), `Display` of the typed
//!   `ConflictError` plus its fields;
//! - `POST /api/v1/memories` on sqlite — the 409 JSON body;
//! - `POST /api/v1/memories` on postgres — the same, and every hidden body
//!   equals the sqlite hidden body once the fixture-specific title is
//!   normalised.

#![allow(clippy::too_many_lines)]

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::storage::ConflictError;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
#[cfg(feature = "sal-postgres")]
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

mod common;

const ALICE: &str = "ai:alice-3696";
const BOB: &str = "ai:bob-3696";
const API_KEY: &str = "hidden-occupant-3696";
const NS: &str = "team/ops-3696";

// ---------------------------------------------------------------------------
// Seam 1 — the storage funnel
// ---------------------------------------------------------------------------

fn private_row_of(owner: &str, id: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("{owner}'s text"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test-3696".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({ "agent_id": owner, "scope": "private" }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
    }
}

fn set_state(conn: &rusqlite::Connection, id: &str, state: &str) {
    conn.execute(
        "UPDATE memories SET lifecycle_state = ?2 WHERE id = ?1",
        rusqlite::params![id, state],
    )
    .expect("set lifecycle_state");
}

fn conflict(err: &anyhow::Error) -> &ConflictError {
    err.downcast_ref::<ConflictError>()
        .unwrap_or_else(|| panic!("expected a typed ConflictError, got: {err:#}"))
}

/// The three ways a slot's occupant can be hidden from the caller, driven
/// through ONE funnel on ONE slot, must render ONE refusal.
#[test]
fn storage_hidden_by_scope_equals_hidden_by_lifecycle_3696() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = ai_memory::db::open(&dir.path().join("m.db")).expect("open");
    ai_memory::db::insert(&conn, &private_row_of(ALICE, "id-a", "slot")).expect("seed");

    let attempt = |viewer: &str, id: &str| {
        ai_memory::db::insert_no_overwrite_as(
            &conn,
            &private_row_of(viewer, id, "slot"),
            Some(viewer),
        )
        .expect_err("the slot is taken either way")
    };

    // Axis 1: the viewer cannot SEE the live occupant (another agent's
    // private row).
    let by_scope = attempt(BOB, "id-b");
    // Axis 2: the occupant is not found in the OWNER's view (quarantined).
    set_state(&conn, "id-a", "quarantined");
    let by_quarantine = attempt(ALICE, "id-c");

    // WHOLE refusal: the rendered text AND the typed fields.
    assert_eq!(
        by_scope.to_string(),
        by_quarantine.to_string(),
        "scope-hidden and quarantine-hidden refusals must be byte-identical"
    );
    let fields = |e: &anyhow::Error| {
        let c = conflict(e);
        (c.title.clone(), c.namespace.clone(), c.existing_id.clone())
    };
    assert_eq!(fields(&by_scope), fields(&by_quarantine));
    assert!(
        !by_scope.to_string().contains("id-a"),
        "the hidden occupant's id must not appear: {by_scope}"
    );

    // CONTROL 1: a VISIBLE occupant renders a DIFFERENT refusal — it names the
    // id — so the equality above is not the whole refusal going blank.
    set_state(&conn, "id-a", "open");
    let visible = attempt(ALICE, "id-e");
    assert_ne!(visible.to_string(), by_scope.to_string());
    assert!(
        visible.to_string().contains("id-a"),
        "a visible occupant is named to its owner: {visible}"
    );
    // CONTROL 2: a TOMBSTONED occupant is the #3690 ADMISSION case — the slot
    // is free and the store LANDS (no refusal at all), which is what keeps
    // "hidden" from collapsing into "any non-open state".
    set_state(&conn, "id-a", "tombstoned");
    let landed = ai_memory::db::insert_no_overwrite_as(
        &conn,
        &private_row_of(ALICE, "id-f", "slot"),
        Some(ALICE),
    )
    .expect("a tombstoned occupant frees the slot (#3690 admission)");
    assert_eq!(landed, "id-f");
}

// ---------------------------------------------------------------------------
// Seams 2 + 3 — the HTTP 409 body, sqlite and postgres
// ---------------------------------------------------------------------------

#[cfg_attr(
    not(feature = "sal"),
    expect(
        clippy::needless_pass_by_value,
        reason = "`SalStore` is a ZST without `sal`, but under `sal` its inner \
                  `Arc<dyn MemoryStore>` is MOVED into the struct literal below; \
                  one signature keeps both feature legs building identically."
    )
)]
fn app_state_with(db: Db, backend: StorageBackend, store: SalStore) -> AppState {
    let _ = &store;
    AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
        #[cfg(feature = "sal")]
        store: store.0,
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
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

#[cfg(feature = "sal")]
struct SalStore(Arc<dyn ai_memory::store::MemoryStore>);
#[cfg(not(feature = "sal"))]
struct SalStore(());

fn sqlite_app_state(path: &std::path::Path) -> AppState {
    let conn = ai_memory::db::open(path).expect("open sqlite fixture db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store = SalStore(Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.to_path_buf()).expect("open SqliteStore"),
    ));
    #[cfg(not(feature = "sal"))]
    let store = SalStore(());
    app_state_with(db, StorageBackend::Sqlite, store)
}

#[cfg(feature = "sal-postgres")]
async fn postgres_app_state(url: &str) -> AppState {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store = SalStore(Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(url)
            .await
            .expect("connect postgres adapter"),
    ));
    app_state_with(db, StorageBackend::Postgres, store)
}

fn router(app: AppState) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    ai_memory::build_router(
        ApiKeyState {
            key: Some(API_KEY.into()),
            mtls_enforced: false,
            enrolled_agent_keys: Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
        },
        app,
    )
}

async fn post_memory(router: &axum::Router, caller: &str, title: &str) -> (StatusCode, Value) {
    let body = json!({
        "namespace": NS,
        "title": title,
        "content": format!("{caller}'s text"),
        "tier": "long",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "metadata": {"scope": "private"},
        "on_conflict": "error",
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("x-api-key", API_KEY)
        .header("x-agent-id", caller)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// How a test hides the occupant on the lifecycle axis, per backend.
enum Lifecycle {
    Sqlite(Db),
    #[cfg(feature = "sal-postgres")]
    Postgres(String),
}

impl Lifecycle {
    async fn set(&self, id: &str, state: &str) {
        match self {
            Self::Sqlite(db) => {
                let lock = db.lock().await;
                set_state(&lock.0, id, state);
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres(url) => {
                let pool = sqlx::PgPool::connect(url).await.expect("pg pool");
                sqlx::query("UPDATE memories SET lifecycle_state = $2 WHERE id = $1")
                    .bind(id)
                    .bind(state)
                    .execute(&pool)
                    .await
                    .expect("set lifecycle_state");
                pool.close().await;
            }
        }
    }
}

/// Returns the hidden-occupant 409 body with the title normalised, after
/// asserting the scope-hidden and quarantine-hidden bodies are equal and both
/// controls hold (a visible occupant differs; a tombstoned one admits).
async fn check_http(app: AppState, lifecycle: Lifecycle) -> Value {
    let router = router(app);
    let title = format!("slot-{}", uuid::Uuid::new_v4().simple());
    let (status, created) = post_memory(&router, ALICE, &title).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().expect("id").to_owned();

    // Axis 1: bob cannot see alice's private occupant.
    let (s1, by_scope) = post_memory(&router, BOB, &title).await;
    assert_eq!(s1, StatusCode::CONFLICT, "{by_scope}");
    // Axis 2: the occupant is not found in ALICE's own view (quarantined).
    lifecycle.set(&id, "quarantined").await;
    let (s2, by_quarantine) = post_memory(&router, ALICE, &title).await;
    assert_eq!(s2, StatusCode::CONFLICT, "{by_quarantine}");

    assert_eq!(
        by_scope, by_quarantine,
        "scope-hidden and quarantine-hidden 409 bodies must be identical"
    );
    assert!(
        !by_scope.to_string().contains(&id),
        "the hidden occupant's id must not appear: {by_scope}"
    );

    // CONTROL 1: the visible occupant is named to its owner.
    lifecycle.set(&id, "open").await;
    let (s3, visible) = post_memory(&router, ALICE, &title).await;
    assert_eq!(s3, StatusCode::CONFLICT, "{visible}");
    assert_ne!(
        visible, by_scope,
        "a visible occupant renders a different body"
    );
    assert_eq!(visible["existing_id"], id, "{visible}");
    // CONTROL 2: a TOMBSTONED occupant is the #3690 ADMISSION case — the
    // store LANDS (201), so "hidden" here means quarantined or unseeable,
    // never "any non-open state".
    lifecycle.set(&id, "tombstoned").await;
    let (s4, landed) = post_memory(&router, ALICE, &title).await;
    assert_eq!(s4, StatusCode::CREATED, "{landed}");
    assert_ne!(landed["id"], id, "{landed}");

    let mut normalised = by_scope;
    if let Some(err) = normalised["error"].as_str() {
        normalised["error"] = json!(err.replace(&title, "<title>"));
    }
    normalised
}

#[tokio::test]
async fn http_sqlite_hidden_occupant_refusals_are_one_body_3696() {
    common::permissive_attestation_for_tests();
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    let app = sqlite_app_state(&dir.path().join("memories.db"));
    let lifecycle = Lifecycle::Sqlite(Arc::clone(&app.db));
    check_http(app, lifecycle).await;
}

/// The postgres twin, plus cross-backend identity: every hidden body on
/// postgres equals the hidden body on sqlite.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn http_postgres_hidden_occupant_refusals_are_one_body_3696() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    common::permissive_attestation_for_tests();
    let pg = check_http(postgres_app_state(&url).await, Lifecycle::Postgres(url)).await;
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    let app = sqlite_app_state(&dir.path().join("memories.db"));
    let lifecycle = Lifecycle::Sqlite(Arc::clone(&app.db));
    let sq = check_http(app, lifecycle).await;
    assert_eq!(
        serde_json::to_string(&pg).unwrap(),
        serde_json::to_string(&sq).unwrap(),
        "the hidden-occupant 409 body must be byte-identical across backends"
    );
}
