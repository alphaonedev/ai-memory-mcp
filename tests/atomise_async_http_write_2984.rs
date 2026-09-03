// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]
//! v1.0.0 #2984 — Batman auto-atomisation on the HTTP create funnel.
//!
//! **R-203.** These tests FAIL at the parent commit. At parent the ONLY
//! production caller of the auto-atomise hook was the MCP stdio store
//! path (`src/mcp/tools/store/mod.rs`); NO call site existed anywhere in
//! `src/handlers/`. Since MCP stdio is structurally sqlite-only
//! (#1675/n24), every postgres-backed and mTLS-fronted deployment —
//! including the certified enterprise-federation hive — serves every
//! agent write through `POST /api/v1/memories`, where atomisation could
//! never fire. A live over-threshold attested write to the hive
//! (2026-08-16, Batman standard bound on `*`) landed whole: zero atoms,
//! zero links, and no field in the response saying so.
//!
//! What is pinned here: the honest response fields on the create
//! envelope, and the atoms actually landing after the bounded worker
//! drains — with a MOCK curator, no live LLM.
//!
//! Harness mirrors `tests/autotag_async_write_2587.rs`'s
//! `build_autotag_router` (a real `AppState` + `build_router`), extended
//! to wire the bounded `atomise_queue` the way `bootstrap_serve` does.
//!
//! `AppState.store` (the SAL trait-object handle) is only present under
//! `--features sal`.
#![cfg(feature = "sal")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::atomisation::curator::{Atom, Curator, CuratorError};
use ai_memory::atomisation::{Atomiser, AtomiserConfig};
use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::hooks::pre_store::auto_atomise::{OUTCOME_QUEUED, OUTCOME_SKIPPED_NO_CURATOR};
use ai_memory::llm::OllamaClient;
use ai_memory::models::{
    ApproverType, AtomisationPolicy, AutoAtomiseMode, CorePolicy, GovernanceLevel,
    GovernancePolicy, Memory, Tier,
};
use ai_memory::storage as db;

/// #1751 — permissive attestation opt-out, the same pin
/// `tests/autotag_async_write_2587.rs` carries.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for
    // the process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn local_runs_db(tag: &str) -> std::path::PathBuf {
    // Project HARD RULE: agent-created scratch never lands on a tmpfs.
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("atomise-http-2984");
    std::fs::create_dir_all(&root).expect("create .local-runs scratch dir");
    root.join(format!("{tag}-{}.db", uuid::Uuid::new_v4()))
}

// ---------------------------------------------------------------------------
// Mock curator — the whole point is that NO live LLM is needed.
// ---------------------------------------------------------------------------

struct TwoAtomCurator {
    calls: Arc<Mutex<usize>>,
}

impl Curator for TwoAtomCurator {
    fn decompose(
        &self,
        _body: &str,
        _max_atom_tokens: u32,
        _max_retries: u32,
    ) -> Result<Vec<Atom>, CuratorError> {
        *self.calls.lock().unwrap() += 1;
        Ok(vec![
            Atom {
                text: "Canary instance health checks must pass before traffic shifts.".into(),
            },
            Atom {
                text: "A failed readiness probe rolls the deployment back.".into(),
            },
        ])
    }
}

/// Build a Smart-tier sqlite router whose `atomise_queue` is wired to a
/// LIVE `crate::background::atomise_worker` driving a MOCK curator — the
/// same construction order `bootstrap_serve` uses (spawn the worker, then
/// assign the returned handle onto the real `AppState`).
///
/// `wire_llm` controls the #2985 curator-presence gate. The client is
/// constructed WITHOUT a health check and is never actually called: the
/// worker's provider closure returns the mock atomiser, so the test is
/// hermetic.
fn build_atomise_router(
    wire_llm: bool,
    wire_worker: bool,
    calls: &Arc<Mutex<usize>>,
) -> (axum::Router, std::path::PathBuf) {
    permissive_attestation_for_tests();
    let db_path = local_runs_db("http-create");
    let conn = db::open(&db_path).expect("db::open");
    let db: Db = Arc::new(AsyncMutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
    let llm = Arc::new(ai_memory::reload::SwappableLlm::new(if wire_llm {
        Some(
            OllamaClient::new_with_url_no_health_check("http://127.0.0.1:1", "mock-curator-model")
                .expect("llm"),
        )
    } else {
        None
    }));
    let mut app_state = AppState {
        db: db.clone(),
        embedder: Arc::new(None),
        vector_index: Arc::new(AsyncMutex::new(None)),
        federation: Arc::new(None),
        // Smart tier so `tier_config.llm_model.is_some()` — the other
        // half of the #2985 curator-presence gate.
        tier_config: Arc::new(FeatureTier::Smart.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        store,
        llm,
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
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
        admin_agent_ids: Arc::new(vec!["*".to_string()]),
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
    if wire_worker {
        let calls = Arc::clone(calls);
        app_state.atomise_queue =
            ai_memory::background::atomise_worker::spawn(Arc::new(move || {
                Some(Arc::new(Atomiser::new(
                    Box::new(TwoAtomCurator {
                        calls: Arc::clone(&calls),
                    }),
                    None,
                    AtomiserConfig::default(),
                    FeatureTier::Smart,
                )))
            }));
    }

    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, db_path)
}

fn seed_policy(db_path: &std::path::Path, ns: &str, mode: AutoAtomiseMode) {
    let conn = db::open(db_path).expect("open for seed");
    let policy = GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Any,
            promote: GovernanceLevel::Any,
            delete: GovernanceLevel::Owner,
            approver: ApproverType::Human,
            inherit: true,
            max_reflection_depth: None,
            required_scope: None,
        },
        atomisation: AtomisationPolicy {
            auto_atomise: Some(true),
            auto_atomise_threshold_cl100k: Some(20),
            auto_atomise_max_atom_tokens: Some(50),
            auto_atomise_max_retries: None,
            auto_atomise_mode: Some(mode),
        },
        ..Default::default()
    };
    let now = chrono::Utc::now().to_rfc3339();
    let std_mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: format!("__standard_{ns}"),
        content: "standard".into(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({
            "agent_id": "ai:test",
            "governance": serde_json::to_value(&policy).unwrap(),
        }),
        ..Default::default()
    };
    let id = db::insert(&conn, &std_mem).expect("seed standard");
    db::set_namespace_standard(&conn, ns, &id, None).expect("set standard");
}

async fn post_json(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", "atomise-2984-tester")
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

fn over_threshold_body(ns: &str, title: &str) -> Value {
    json!({
        "tier": "long",
        "namespace": ns,
        "title": title,
        "content": "The kubernetes rolling deploy strategy required canary instance health \
                    checks. The pod readiness probe must pass before traffic shifts. Failures \
                    roll back the deployment within 30 seconds. Observability tail logs feed \
                    the cluster ingress dashboard so an operator can see the canary window.",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "user",
        "metadata": {},
    })
}

fn count_atoms(db_path: &std::path::Path, source_id: &str) -> i64 {
    let conn = db::open(db_path).expect("reopen");
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE atom_of = ?1",
        [source_id],
        |r| r.get(0),
    )
    .unwrap_or(0)
}

// ===========================================================================
// (iii) The HTTP create funnel enqueues, says so honestly, and the atoms land.
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn http_create_enqueues_atomisation_and_the_worker_lands_the_atoms_2984() {
    let calls = Arc::new(Mutex::new(0usize));
    let (router, db_path) = build_atomise_router(true, true, &calls);
    let ns = "atomise-2984-deferred";
    seed_policy(&db_path, ns, AutoAtomiseMode::Deferred);

    let (status, body) = post_json(
        &router,
        "/api/v1/memories",
        over_threshold_body(ns, "http-deferred-1"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "durable write must succeed");

    // The honest envelope fields. Pre-#2984 NONE of these existed on the
    // HTTP response — the write landed whole and said nothing.
    assert_eq!(body["atomise_mode"].as_str(), Some("deferred"));
    assert_eq!(body["atomise_outcome"].as_str(), Some(OUTCOME_QUEUED));
    assert!(
        body.get("atomise_mode_configured").is_none(),
        "deferred-configured + deferred-ran must report NO divergence"
    );

    let source_id = body["id"].as_str().expect("id").to_string();
    // Deferred means deferred: the response did not wait on the curator.
    assert_eq!(
        count_atoms(&db_path, &source_id),
        0,
        "the create response must not have blocked on the curator"
    );

    // …and the bounded single-consumer worker drains it out-of-band.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut atoms = 0;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        atoms = count_atoms(&db_path, &source_id);
        if atoms >= 2 {
            break;
        }
    }
    assert_eq!(
        atoms, 2,
        "the worker must land the mock curator's two atoms"
    );
    assert_eq!(*calls.lock().unwrap(), 1, "exactly one curator call");
}

// ===========================================================================
// (iii, divergence) A `synchronous`-configured namespace over HTTP runs
// DEFERRED and reports the divergence — never silently honoured, never
// silently dropped.
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn synchronous_namespace_over_http_runs_deferred_and_says_so_2987() {
    let calls = Arc::new(Mutex::new(0usize));
    let (router, db_path) = build_atomise_router(true, true, &calls);
    let ns = "atomise-2984-sync";
    seed_policy(&db_path, ns, AutoAtomiseMode::Synchronous);

    let (status, body) = post_json(
        &router,
        "/api/v1/memories",
        over_threshold_body(ns, "http-sync-1"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        body["atomise_mode"].as_str(),
        Some("deferred"),
        "the mode label must be the mode that RAN"
    );
    assert_eq!(
        body["atomise_mode_configured"].as_str(),
        Some("synchronous"),
        "the CONFIGURED mode must survive into the envelope"
    );
    assert_eq!(
        body["atomise_mode_reason"].as_str(),
        Some("deferred_on_http"),
        "and the reason must name WHY it diverged"
    );
    assert_eq!(body["atomise_outcome"].as_str(), Some(OUTCOME_QUEUED));
}

// ===========================================================================
// (iii, #2985) An opted-in namespace on a curator-less daemon says so.
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn http_create_without_a_curator_reports_skipped_no_curator_2985() {
    let calls = Arc::new(Mutex::new(0usize));
    let (router, db_path) = build_atomise_router(false, false, &calls);
    let ns = "atomise-2984-nocurator";
    seed_policy(&db_path, ns, AutoAtomiseMode::Deferred);

    let (status, body) = post_json(
        &router,
        "/api/v1/memories",
        over_threshold_body(ns, "http-nocurator-1"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a missing curator must NEVER fail the durable write"
    );
    assert_eq!(
        body["atomise_outcome"].as_str(),
        Some(OUTCOME_SKIPPED_NO_CURATOR)
    );
    assert_eq!(body["atomise_mode"].as_str(), Some("off"));
    assert_eq!(body["atomise_mode_reason"].as_str(), Some("no_curator"));
    assert_eq!(*calls.lock().unwrap(), 0);
}

// ===========================================================================
// (iii, silence) A namespace that never opted in gets NO atomise fields —
// byte-identical to the pre-#2984 envelope.
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn http_create_on_an_opted_out_namespace_emits_no_atomise_fields_2987() {
    let calls = Arc::new(Mutex::new(0usize));
    let (router, _db_path) = build_atomise_router(true, true, &calls);

    let (status, body) = post_json(
        &router,
        "/api/v1/memories",
        over_threshold_body("atomise-2984-plain", "http-plain-1"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    for field in [
        "atomise_mode",
        "atomise_outcome",
        "atomise_mode_configured",
        "atomise_mode_reason",
    ] {
        assert!(
            body.get(field).is_none(),
            "a knob nobody set must not start narrating itself on every write: {field} present \
             in {body}"
        );
    }
    assert_eq!(*calls.lock().unwrap(), 0);
}
