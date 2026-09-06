// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3507 — `memory_calibrate_confidence` caller gate, POSTGRES half.
//!
//! The sqlite twin is `tests/calibrate_confidence_caller_gate_3507.rs`. This
//! file proves the SAME gate on the postgres adapter, because the whole
//! point of #3507 is that the two backends close the hole TOGETHER — a fix
//! landed on one adapter only would reintroduce exactly the cross-backend
//! divergence the SAL method's doc-comment exists to prevent.
//!
//! Two layers are asserted:
//!
//! 1. the SAL method `MemoryStore::calibrate_confidence_report` under a
//!    scoped / foreign / admin / unresolvable `CallerContext`;
//! 2. the live HTTP route on a postgres-backed daemon, which is the arm
//!    (`route_1111::calibrate_confidence_http_via_store`) an operator
//!    actually reaches.
//!
//! Gated on `feature = "sal-postgres"` + a live `AI_MEMORY_TEST_POSTGRES_URL`
//! and skipped cleanly otherwise — the `tests/pg_parity_3064.rs` pattern.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::doc_markdown, clippy::too_many_lines)]

use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::confidence::calibrate::CalibrationReport;
use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::{CallerContext, MemoryStore};
use serde_json::{Value, json};
use tokio::sync::{Mutex, Notify, RwLock};

mod common;
use common::{DAEMON_READY_TIMEOUT, free_port, pg_test_client, postgres_url, wait_for_http_ready};

/// The tenant principals. Both carry a `/` so the #1921 subtree arms have an
/// ancestor to resolve.
const ALICE: &str = "team/alice-3507";
const BOB: &str = "team/bob-3507";
/// The ONLY principal on the fixture's admin allow-list.
const ADMIN: &str = "ai:calibrate-admin-3507";
const SOURCE: &str = "nhi";

/// Per-run namespace suffix so concurrent / repeated runs against the shared
/// `ai_memory_test` corpus never collide.
fn run_tag() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

// ---------------------------------------------------------------------------
// Seeding (direct sqlx — the daemon's own write path is not under test here)
// ---------------------------------------------------------------------------

struct Seeded {
    alice: String,
    bob: String,
    team: String,
    substrate: String,
}

async fn seed(pool: &sqlx::PgPool, tag: &str) -> Seeded {
    let seeded = Seeded {
        alice: format!("team/alice-3507/{tag}"),
        bob: format!("team/bob-3507/{tag}"),
        team: format!("team/shared-3507/{tag}"),
        substrate: format!("_curator/reports-3507-{tag}"),
    };
    let rows: [(&str, &str, &str, Option<&str>); 4] = [
        ("m-alice", seeded.alice.as_str(), ALICE, None),
        ("m-bob", seeded.bob.as_str(), BOB, None),
        ("m-team", seeded.team.as_str(), BOB, Some("team")),
        ("m-substrate", seeded.substrate.as_str(), ALICE, None),
    ];
    let now = chrono::Utc::now().to_rfc3339();
    for (stem, namespace, owner, scope) in rows {
        let id = format!("{stem}-{tag}");
        let metadata = scope.map_or_else(
            || json!({ "agent_id": owner }),
            |scope| json!({ "agent_id": owner, "scope": scope }),
        );
        sqlx::query(
            "INSERT INTO memories (id, tier, namespace, title, content, source, metadata)
             VALUES ($1, 'mid', $2, $1, 'body', $3, $4::jsonb)",
        )
        .bind(&id)
        .bind(namespace)
        .bind(SOURCE)
        .bind(metadata.to_string())
        .execute(pool)
        .await
        .expect("seed memory");

        sqlx::query(
            "INSERT INTO confidence_shadow_observations
                 (memory_id, namespace, source, caller_confidence, derived_confidence,
                  signals, observed_at)
             VALUES ($1, $2, $3, 0.9, 0.5, '{}', $4)",
        )
        .bind(&id)
        .bind(namespace)
        .bind(SOURCE)
        .bind(&now)
        .execute(pool)
        .await
        .expect("seed observation");
    }
    seeded
}

async fn cleanup(pool: &sqlx::PgPool, tag: &str) {
    let like = format!("%-{tag}");
    let _ = sqlx::query("DELETE FROM confidence_shadow_observations WHERE memory_id LIKE $1")
        .bind(&like)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM memories WHERE id LIKE $1")
        .bind(&like)
        .execute(pool)
        .await;
}

/// `(namespace, count)` pairs for the namespaces this run seeded, sorted.
/// Scoped to the run tag so a shared corpus cannot make the assertion flaky.
fn tagged_groups(report: &CalibrationReport, tag: &str) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = report
        .baselines
        .iter()
        .filter(|b| b.namespace.ends_with(tag))
        .map(|b| (b.namespace.clone(), b.count))
        .collect();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Layer 1 — the SAL method
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sal_calibrate_is_caller_scoped_on_postgres_3507() {
    let Some(url) = postgres_url() else {
        eprintln!("skipping sal_calibrate_is_caller_scoped_on_postgres_3507");
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect postgres adapter");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("seed pool");
    let tag = run_tag();
    let seeded = seed(&pool, &tag).await;

    let now = chrono::Utc::now();

    // ALLOWED — alice sees her own private row plus the team-scoped row in
    // her subtree, and NOTHING else.
    let alice = store
        .calibrate_confidence_report(&CallerContext::for_agent(ALICE), 30, now)
        .await
        .expect("scoped calibrate");
    assert_eq!(
        tagged_groups(&alice, &tag),
        vec![(seeded.alice.clone(), 1), (seeded.team.clone(), 1)],
        "#3507(pg): alice's aggregate must exclude bob's namespace AND the \
         substrate namespace she owns: {alice:?}"
    );

    // DENIED — bob's aggregate is a DIFFERENT set. Asserting both halves is
    // what proves the gate discriminates rather than merely narrows.
    let bob = store
        .calibrate_confidence_report(&CallerContext::for_agent(BOB), 30, now)
        .await
        .expect("scoped calibrate");
    assert_eq!(
        tagged_groups(&bob, &tag),
        vec![(seeded.bob.clone(), 1), (seeded.team.clone(), 1)],
        "#3507(pg): bob's aggregate must be HIS rows: {bob:?}"
    );
    assert_ne!(
        tagged_groups(&alice, &tag),
        tagged_groups(&bob, &tag),
        "#3507(pg): two tenants must not receive the same aggregate"
    );

    // ADMIN — the global sweep, including the substrate namespace.
    let admin = store
        .calibrate_confidence_report(&CallerContext::for_admin_checked(ADMIN, true), 30, now)
        .await
        .expect("admin calibrate");
    // Already in sorted order: `_curator/…` < `team/alice…` < `team/bob…`
    // < `team/shared…`.
    assert_eq!(
        tagged_groups(&admin, &tag),
        vec![
            (seeded.substrate.clone(), 1),
            (seeded.alice.clone(), 1),
            (seeded.bob.clone(), 1),
            (seeded.team.clone(), 1),
        ],
        "#3507(pg): an admin context keeps the pre-fix GLOBAL sweep: {admin:?}"
    );

    // FAIL-CLOSED — an unresolvable principal is refused, never widened.
    let refusal = store
        .calibrate_confidence_report(&CallerContext::for_agent("anonymous:req-deadbeef"), 30, now)
        .await
        .expect_err("#3507(pg): a synthetic anonymous principal must be refused");
    assert!(
        refusal.to_string().contains("caller-scoped aggregate"),
        "#3507(pg): the refusal must name the posture: {refusal}"
    );

    cleanup(&pool, &tag).await;
    pool.close().await;
}

// ---------------------------------------------------------------------------
// Layer 2 — the live HTTP route on a postgres-backed daemon
// ---------------------------------------------------------------------------

/// `app.db` is a throwaway in-memory sqlite — deliberately EMPTY, so a
/// handler that read it instead of `app.store` would report an all-zero
/// calibration and the assertions below would fail loudly.
async fn postgres_app_state(url: &str) -> AppState {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(url)
            .await
            .expect("connect postgres adapter"),
    );
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
        storage_backend: StorageBackend::Postgres,
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
        // ONLY the admin principal — alice and bob are ordinary tenants, so
        // the scoped arm is the one they exercise.
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
    }
}

async fn spawn(
    app_state: AppState,
) -> (
    String,
    Arc<Notify>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let shutdown = Arc::new(Notify::new());
    let shutdown_for_daemon = shutdown.clone();
    let addr_for_daemon = addr.clone();
    let handle = tokio::spawn(async move {
        ai_memory::daemon_runtime::serve_http_with_shutdown(
            &addr_for_daemon,
            api_key_state,
            app_state,
            shutdown_for_daemon,
        )
        .await
    });
    wait_for_http_ready(&addr, DAEMON_READY_TIMEOUT)
        .await
        .expect("daemon ready");
    (format!("http://{addr}"), shutdown, handle)
}

async fn call(client: &reqwest::Client, base: &str) -> (u16, Value) {
    let resp = client
        .post(format!("{base}/api/v1/memory_calibrate_confidence"))
        .json(&json!({"days": 30}))
        .send()
        .await
        .expect("calibrate POST");
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.expect("calibrate body");
    (status, body)
}

fn http_groups(body: &Value, tag: &str) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = body["report"]["baselines"]
        .as_array()
        .expect("baselines array")
        .iter()
        .filter_map(|b| {
            let ns = b["namespace"].as_str()?;
            ns.ends_with(tag)
                .then(|| (ns.to_string(), b["count"].as_u64().unwrap_or_default()))
        })
        .collect();
    out.sort();
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn http_route_is_caller_scoped_on_postgres_3507() {
    let Some(url) = postgres_url() else {
        eprintln!("skipping http_route_is_caller_scoped_on_postgres_3507");
        return;
    };
    // Build the app state FIRST: `PostgresStore::connect` is what bootstraps
    // the schema, so seeding before it would target a database whose
    // `memories` relation does not exist yet on a fresh lane database.
    let state = postgres_app_state(&url).await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("seed pool");
    let tag = run_tag();
    let seeded = seed(&pool, &tag).await;

    let (base, shutdown, handle) = spawn(state).await;

    // ALLOWED — an ordinary tenant gets the SCOPED aggregate through the
    // real route, proving `calibrate_confidence_http_via_store` honours the
    // gate rather than the SAL default.
    let (status, body) = call(&pg_test_client(ALICE), &base).await;
    assert_eq!(status, 200, "scoped calibrate body={body}");
    assert_eq!(
        http_groups(&body, &tag),
        vec![(seeded.alice.clone(), 1), (seeded.team.clone(), 1)],
        "#3507(pg-http): a tenant must not receive another tenant's \
         namespaces: {body}"
    );

    // ADMIN — the allow-listed principal still gets the global sweep.
    let (status, body) = call(&pg_test_client(ADMIN), &base).await;
    assert_eq!(status, 200, "admin calibrate body={body}");
    let admin_groups = http_groups(&body, &tag);
    assert_eq!(
        admin_groups.len(),
        4,
        "#3507(pg-http): the admin sweep spans every seeded namespace: {body}"
    );
    assert!(
        admin_groups
            .iter()
            .any(|(ns, _)| ns == &seeded.substrate),
        "#3507(pg-http): only the admin sweep reaches a substrate namespace: {body}"
    );
    assert!(
        admin_groups.iter().any(|(ns, _)| ns == &seeded.bob),
        "#3507(pg-http): the admin sweep spans both tenants: {body}"
    );

    // DENIED — no caller header at all is refused, never served the global
    // aggregate.
    let anon = reqwest::Client::builder()
        .build()
        .expect("anonymous client");
    let resp = anon
        .post(format!("{base}/api/v1/memory_calibrate_confidence"))
        .json(&json!({"days": 30}))
        .send()
        .await
        .expect("anonymous POST");
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.expect("anonymous body");
    assert_eq!(
        status, 403,
        "#3507(pg-http): a caller-less request must be refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("caller-scoped aggregate"),
        "#3507(pg-http): the refusal must name the posture: {body}"
    );

    shutdown.notify_one();
    let _ = handle.await;
    cleanup(&pool, &tag).await;
    pool.close().await;
}
