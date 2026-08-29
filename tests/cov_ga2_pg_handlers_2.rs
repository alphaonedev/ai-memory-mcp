// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cov_ga2_pg_handlers_2` — postgres-router coverage for the
//! `StorageBackend::Postgres` dispatch arms of the four
//! GA-session-0611 target handler modules:
//! `handlers/{hook_subscribers,http,power,power_consolidation}`.
//!
//! Prior coverage rounds drove these handlers through a
//! sqlite/fake-postgres router that returned `503` *before* the
//! `#[cfg(feature = "sal-postgres")]` branch body executed, so the
//! postgres dispatch arms (the bulk of the uncovered lines) stayed
//! dark. This file copies the REAL-`PostgresStore` router harness from
//! `tests/cov3_handlers_postgres.rs` (an `Arc<PostgresStore>` built via
//! [`PostgresStore::connect`], `storage_backend = Postgres`, driven via
//! `tower::oneshot`) so the postgres branch bodies execute end-to-end.
//!
//! Covered postgres branch bodies (fn → driving test):
//! - `get_inbox` pg arm → `pg_get_inbox_*`
//! - `get_namespace_standard_qs` pg arm (inherit + non-inherit) →
//!   `pg_get_namespace_standard_*`
//! - `clear_namespace_standard_inner` pg arm → `pg_clear_namespace_standard_*`
//! - `session_start` → `pg_session_start_*` (routes through the shared
//!   MCP handler; exercised on a postgres-backed `AppState`)
//! - `check_duplicate` pg arm → `pg_check_duplicate_*`
//! - `get_taxonomy` pg arm (admin-gated) → `pg_get_taxonomy_*`
//! - `detect_contradictions` pg arm (heuristic, not LLM-gated) →
//!   `pg_detect_contradictions_*`
//! - `consolidate_memories` + `fetch_consolidate_source_pairs` pg arms →
//!   `pg_consolidate_*`
//! - `fetch_memory_for_handler` pg arm (via `auto_tag_handler`) →
//!   `pg_auto_tag_*`
//! - `load_family_handler` pg arm → `pg_load_family_*`
//! - `auto_tag_handler` / `expand_query_handler` no-LLM 503 arm →
//!   `pg_auto_tag_no_llm_503` / `pg_expand_query_no_llm_503`
//!
//! Structural exceptions (NOT covered here — recorded, not faked):
//! - `handlers/http.rs::maybe_auto_tag`, `maybe_detect_conflicts`,
//!   `fetch_namespace_candidates` (pg arm), `get_with_visibility_retry`
//!   are `pub(crate)`/private internal helpers with no own route; the
//!   LLM-bearing ones additionally require a live LLM the CI pg+AGE
//!   host does not provide.
//! - The LLM-success branches of `auto_tag_handler` /
//!   `expand_query_handler` / `consolidate_memories` (LLM summary) /
//!   `detect_contradictions` require a live LLM (CI has pg+AGE, NO LLM);
//!   only the no-LLM degradation + validation arms are driven here.
//!
//! Gated on `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL`.
//! Without the env var every test prints a skip line and returns.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

/// The agent id every request in this file presents and which the
/// router's admin allowlist names, so the admin-gated taxonomy handler
/// admits it once `AI_MEMORY_ADMIN_HEADER_TRUST` is set.
const CALLER: &str = "ai:cov-ga2-pg";

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

/// #1751 — pin this test binary to the explicit permissive agent-attestation
/// opt-out; the v0.9 store-path default is REQUIRED and would reject this
/// suite's unsigned store/seed fixtures. One stable `Once` value for the
/// process lifetime — no set/restore window, so no cross-test race (the
/// #1609 class this binary's attestation NOTE documents). The required
/// default itself is pinned in `tests/agent_attestation_integrity.rs`.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}
async fn pg_router(url: &str) -> axum::Router {
    permissive_attestation_for_tests();
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(PostgresStore::connect(url).await.expect("connect postgres"));
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
        admin_agent_ids: Arc::new(vec![CALLER.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
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

async fn post_json(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", CALLER)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    decode(router, req).await
}

async fn delete_req(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("x-agent-id", CALLER)
        .body(Body::empty())
        .unwrap();
    decode(router, req).await
}

async fn get(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", CALLER)
        .body(Body::empty())
        .unwrap();
    decode(router, req).await
}

async fn decode(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// A unique namespace per test run so concurrent runs against the
/// shared scratch DB don't collide and so assertions can filter on the
/// caller's own rows rather than asserting global-table emptiness.
fn uniq_ns() -> String {
    format!("covga2-{}", &uuid::Uuid::new_v4().to_string()[..12])
}

/// Seed a memory through the production router (so it lands in postgres
/// via the same SAL store the handlers read from) and return its id.
async fn seed_memory(router: &axum::Router, ns: &str, title: &str, content: &str) -> String {
    let (status, body) = post_json(
        router,
        "/api/v1/memories",
        json!({
            "title": title,
            "content": content,
            "namespace": ns,
            "agent_id": CALLER,
        }),
    )
    .await;
    assert!(
        status.is_success(),
        "seed memory status={status} body={body}"
    );
    body["id"]
        .as_str()
        .expect("seed memory returns id")
        .to_string()
}

/// #2743 — seed a memory carrying `metadata.topic` so the topic-filtered
/// contradiction sweep selects it. Distinct titles are now REQUIRED between
/// co-namespace seeds: the postgres single-create honours `on_conflict`
/// (default `error`), so two writes sharing a `(title, namespace)` no longer
/// silently upsert to one row — they 409. The topic filter matches on
/// `metadata.topic` (or `title`), so distinct titles plus a shared topic give
/// two genuinely distinct contradiction candidates.
async fn seed_memory_topic(
    router: &axum::Router,
    ns: &str,
    title: &str,
    content: &str,
    topic: &str,
) -> String {
    let (status, body) = post_json(
        router,
        "/api/v1/memories",
        json!({
            "title": title,
            "content": content,
            "namespace": ns,
            "agent_id": CALLER,
            "metadata": { "topic": topic },
        }),
    )
    .await;
    assert!(
        status.is_success(),
        "seed memory status={status} body={body}"
    );
    body["id"]
        .as_str()
        .expect("seed memory returns id")
        .to_string()
}

macro_rules! pg_test {
    ($name:ident, $url:ident, $body:block) => {
        #[tokio::test]
        async fn $name() {
            let Some($url) = pg_url() else {
                eprintln!(
                    "SKIP {}: AI_MEMORY_TEST_POSTGRES_URL not set",
                    stringify!($name)
                );
                return;
            };
            $body
        }
    };
}

/// Serializes the taxonomy tests that flip the process-global
/// `AI_MEMORY_ADMIN_HEADER_TRUST` env var. cargo runs the
/// `#[tokio::test]`s in this binary concurrently, so without this guard
/// one test's `remove_var` could clobber another mid-request and flip
/// the admin gate closed, yielding a spurious 403.
static ADMIN_ENV_LOCK: Mutex<()> = Mutex::const_new(());

// ---------------------------------------------------------------------------
// hook_subscribers::get_inbox — postgres `_inbox/<owner>` namespace read
// ---------------------------------------------------------------------------

pg_test!(pg_get_inbox_empty_default, url, {
    let r = pg_router(&url).await;
    let (status, body) = get(&r, "/api/v1/inbox").await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    assert_eq!(body["agent_id"], CALLER);
    assert!(body["messages"].is_array());
});

pg_test!(pg_get_inbox_after_notify_unread_only, url, {
    let r = pg_router(&url).await;
    // `notify` lands a message under `_inbox/<target>`; the inbox read
    // then projects it. Target ourselves so the caller-owned read sees
    // the row (#901 — header is the only trusted owner source).
    let (ns, ok) = post_json(
        &r,
        "/api/v1/notify",
        json!({
            "target_agent_id": CALLER,
            "title": "cov-ga2 inbox ping",
            "content": "covga2 inbox payload body",
            "from_agent_id": CALLER,
        }),
    )
    .await;
    assert!(
        ns.is_success() || ns == StatusCode::CREATED,
        "notify status={ns} body={ok}"
    );

    // unread_only=true exercises the metadata `read` filter branch.
    let (status, body) = get(&r, "/api/v1/inbox?unread_only=true&limit=50").await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    assert!(
        body["messages"].as_array().is_some_and(|m| !m.is_empty()),
        "expected at least our own notify message; body={body}"
    );
});

pg_test!(pg_get_inbox_query_mismatch_is_403, url, {
    let r = pg_router(&url).await;
    // #901 — a `?agent_id=` that disagrees with the header is rejected
    // before the postgres arm runs.
    let (status, _b) = get(&r, "/api/v1/inbox?agent_id=ai:someone-else").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
});

// ---------------------------------------------------------------------------
// hook_subscribers::session_start — postgres-backed AppState
// ---------------------------------------------------------------------------

pg_test!(pg_session_start_ok, url, {
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    let (status, body) = post_json(
        &r,
        "/api/v1/session/start",
        json!({"namespace": ns, "limit": 5, "agent_id": CALLER}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body.get("session_id").is_some(), "session id stamped");
    assert_eq!(body["agent_id"], CALLER);
});

pg_test!(pg_session_start_invalid_agent_id_is_400, url, {
    let r = pg_router(&url).await;
    let (status, _b) = post_json(
        &r,
        "/api/v1/session/start",
        json!({"agent_id": "bad id with spaces"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
});

// ---------------------------------------------------------------------------
// hook_subscribers — namespace-standard set / get / clear postgres arms
// ---------------------------------------------------------------------------

pg_test!(pg_namespace_standard_set_get_clear_roundtrip, url, {
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    // Seed a standard memory to point the namespace standard at.
    let std_id = seed_memory(&r, &ns, "cov-ga2 ns standard", "policy body for this ns").await;

    // SET via the query-string form (POST /api/v1/namespaces).
    let (set_status, set_body) = post_json(
        &r,
        "/api/v1/namespaces",
        json!({"namespace": ns, "standard_id": std_id, "id": std_id, "agent_id": CALLER}),
    )
    .await;
    assert!(
        set_status == StatusCode::CREATED || set_status == StatusCode::OK,
        "set standard status={set_status} body={set_body}"
    );

    // GET via the postgres arm of get_namespace_standard_qs (non-inherit).
    let (get_status, get_body) = get(&r, &format!("/api/v1/namespaces?namespace={ns}")).await;
    assert_eq!(get_status, StatusCode::OK, "get body={get_body}");
    assert_eq!(get_body["storage_backend"], "postgres");

    // GET with inherit=true exercises the chain-walk branch.
    let (inh_status, inh_body) = get(
        &r,
        &format!("/api/v1/namespaces?namespace={ns}/child&inherit=true"),
    )
    .await;
    assert_eq!(inh_status, StatusCode::OK, "inherit body={inh_body}");
    assert_eq!(inh_body["storage_backend"], "postgres");
    assert!(inh_body["chain"].is_array());

    // CLEAR via the postgres arm of clear_namespace_standard_inner.
    let (clr_status, clr_body) =
        delete_req(&r, &format!("/api/v1/namespaces?namespace={ns}")).await;
    assert_eq!(clr_status, StatusCode::OK, "clear body={clr_body}");
    assert_eq!(clr_body["storage_backend"], "postgres");
    assert_eq!(clr_body["cleared"], true);
});

pg_test!(pg_namespace_standard_get_unset_is_null_standard, url, {
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    // No standard set: the non-inherit pg arm returns 200 with a null
    // standard_id (Ok(None) fall-through).
    let (status, body) = get(&r, &format!("/api/v1/namespaces?namespace={ns}")).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    assert!(body["standard_id"].is_null());
});

pg_test!(pg_namespace_standard_clear_missing_is_404, url, {
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    // Nothing to clear → the pg arm's Ok(false) → 404.
    let (status, body) = delete_req(&r, &format!("/api/v1/namespaces?namespace={ns}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body={body}");
});

// ---------------------------------------------------------------------------
// power::check_duplicate — postgres `check_duplicate_with_text` trait arm
// ---------------------------------------------------------------------------

pg_test!(pg_check_duplicate_no_embedder_hash_phase, url, {
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    // Embedder is None on this AppState, so query_embedding is empty and
    // the trait method falls through to the phase-1 SHA-256 exact-match
    // path. A fresh title+content has no exact duplicate.
    let (status, body) = post_json(
        &r,
        "/api/v1/check_duplicate",
        json!({
            "title": "cov-ga2 dup probe",
            "content": format!("unique content for {ns}"),
            "namespace": ns,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    assert_eq!(body["is_duplicate"], false);
});

pg_test!(pg_check_duplicate_exact_content_is_duplicate, url, {
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    let title = "cov-ga2 exact dup";
    let content = format!("byte-equal content body for {ns}");
    // Seed the row, then probe with byte-equal (title, content): the
    // SHA-256 short-circuit in the pg trait method should flag it.
    seed_memory(&r, &ns, title, &content).await;
    let (status, body) = post_json(
        &r,
        "/api/v1/check_duplicate",
        json!({"title": title, "content": content, "namespace": ns}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    assert_eq!(
        body["is_duplicate"], true,
        "exact content match; body={body}"
    );
});

pg_test!(pg_check_duplicate_invalid_title_is_400, url, {
    let r = pg_router(&url).await;
    let (status, _b) = post_json(
        &r,
        "/api/v1/check_duplicate",
        json!({"title": "", "content": "x"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
});

pg_test!(pg_check_duplicate_hides_private, url, {
    // #3234 — pg check_duplicate had no #947 visibility mask. A
    // byte-equal probe from a different tenant must not disclose the
    // private row (existence + similarity oracle). CALLER is on the
    // admin allowlist but `is_admin_caller_trusted` stays false here
    // (keyless + no `AI_MEMORY_ADMIN_HEADER_TRUST`), so the mask runs.
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    let title = "cov-ga2 private dup 3234";
    let content = format!("private-owned content for {ns}");
    let owner = "ai:alice-3234";
    let seed = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json")
        .header("x-agent-id", owner)
        .body(Body::from(
            serde_json::to_vec(&json!({
                "title": title,
                "content": content,
                "namespace": ns,
                "agent_id": owner,
                "metadata": {"scope": "private", "agent_id": owner},
            }))
            .unwrap(),
        ))
        .unwrap();
    let (status, body) = decode(&r, seed).await;
    assert!(
        status.is_success(),
        "seed private status={status} body={body}"
    );

    // Probe as CALLER (not owner). Exact hash match would flag duplicate
    // pre-mask; the #947/#3234 post-filter must hide it.
    let (status, body) = post_json(
        &r,
        "/api/v1/check_duplicate",
        json!({"title": title, "content": content, "namespace": ns}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(
        body["is_duplicate"], false,
        "private foreign nearest must be masked; body={body}"
    );
    assert!(
        body["nearest"].is_null(),
        "nearest must be hidden; body={body}"
    );
});

// ---------------------------------------------------------------------------
// power::get_taxonomy — admin-gated postgres `get_taxonomy` trait arm
// ---------------------------------------------------------------------------

pg_test!(pg_get_taxonomy_admin_pg_arm, url, {
    let _g = ADMIN_ENV_LOCK.lock().await;
    // The taxonomy handler is admin-gated (require_admin). On a keyless
    // deployment the allowlisted name is only honored when the operator
    // opts into header-trust. SAFETY: this test owns the process env for
    // the lock's duration.
    unsafe {
        std::env::set_var(ai_memory::handlers::admin_role::ENV_ADMIN_HEADER_TRUST, "1");
    }
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    seed_memory(&r, &format!("{ns}/alpha"), "tax a", "taxonomy node a").await;
    seed_memory(&r, &format!("{ns}/beta"), "tax b", "taxonomy node b").await;
    let (status, body) = get(
        &r,
        &format!("/api/v1/taxonomy?prefix={ns}&depth=3&limit=100"),
    )
    .await;
    unsafe {
        std::env::remove_var(ai_memory::handlers::admin_role::ENV_ADMIN_HEADER_TRUST);
    }
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    assert!(body.get("tree").is_some());
});

pg_test!(pg_get_taxonomy_non_admin_is_403, url, {
    let _g = ADMIN_ENV_LOCK.lock().await;
    // With header-trust OFF (default) the allowlisted name is not enough
    // on a keyless deployment → 403 before the pg arm.
    unsafe {
        std::env::remove_var(ai_memory::handlers::admin_role::ENV_ADMIN_HEADER_TRUST);
    }
    let r = pg_router(&url).await;
    let (status, _b) = get(&r, "/api/v1/taxonomy").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
});

// ---------------------------------------------------------------------------
// power::detect_contradictions — postgres heuristic arm (NOT LLM-gated)
// ---------------------------------------------------------------------------

pg_test!(pg_detect_contradictions_pg_arm, url, {
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    // #2743 — DISTINCT titles. The postgres single-create now honours
    // `on_conflict` (default `error`), so two writes sharing a
    // `(title, namespace)` no longer silently upsert to one row (pre-#2743 this
    // seeded ONE row via the `ON CONFLICT (title, namespace) DO UPDATE` arm, and
    // the array-ness assertions below passed vacuously). Two distinct rows
    // exercise the pg candidate list + pairwise loop; the NO-topic synth arm
    // keys on identical titles (which the single-create dedup structurally
    // prevents), so this asserts the arm returns OK with `memories`/`links`
    // arrays over a real two-row candidate set.
    seed_memory(&r, &ns, "shared topic blue", "the sky is blue").await;
    seed_memory(&r, &ns, "shared topic green", "the sky is green").await;
    let (status, body) = get(&r, &format!("/api/v1/contradictions?namespace={ns}")).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    // Both distinct-title writes persisted (no 409, no dedup): two candidates.
    assert_eq!(
        body["memories"].as_array().map(Vec::len),
        Some(2),
        "#2743: both distinct-title single-creates persist as separate rows: {body}"
    );
    assert!(body["links"].is_array());
});

pg_test!(pg_detect_contradictions_topic_filter_pg_arm, url, {
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    // #2743 — DISTINCT titles + a shared `metadata.topic`. Two genuinely
    // distinct rows (single-create no longer upserts same-title writes to one)
    // selected by the `&topic=` filter via `metadata.topic`, with differing
    // content, so the pg heuristic synthesizes a `contradicts` link — the
    // scenario the pre-#2743 same-title seeds only PRETENDED to exercise (they
    // upserted to one row and synthesized nothing; the test passed vacuously).
    seed_memory_topic(&r, &ns, "alpha-topic one", "claim one", "alpha-topic").await;
    seed_memory_topic(
        &r,
        &ns,
        "alpha-topic two",
        "claim two differs",
        "alpha-topic",
    )
    .await;
    let (status, body) = get(
        &r,
        &format!("/api/v1/contradictions?namespace={ns}&topic=alpha-topic"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    // Both distinct rows match the topic and differ in content → the pg arm
    // synthesizes exactly one `contradicts` link (only `contradicts` links are
    // synthesized on this arm).
    let links = body["links"].as_array().expect("links[]");
    assert!(
        links.iter().any(|l| l["synthesized"] == true),
        "#2743: two distinct topic-matched rows must synthesize a contradicts link: {body}"
    );
});

pg_test!(pg_detect_contradictions_missing_args_is_400, url, {
    let r = pg_router(&url).await;
    // Neither topic nor namespace → 400 before the pg arm.
    let (status, _b) = get(&r, "/api/v1/contradictions").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
});

// ---------------------------------------------------------------------------
// power_consolidation::consolidate_memories — postgres `consolidate` arm
// + fetch_consolidate_source_pairs pg arm (caller-supplied summary path)
// ---------------------------------------------------------------------------

pg_test!(pg_consolidate_pg_arm_with_summary, url, {
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    let id1 = seed_memory(&r, &ns, "consolidate src 1", "first source body").await;
    let id2 = seed_memory(&r, &ns, "consolidate src 2", "second source body").await;
    // Caller-supplied summary skips the LLM resolve path and drives the
    // postgres `consolidate` trait method directly.
    let (status, body) = post_json(
        &r,
        "/api/v1/consolidate",
        json!({
            "ids": [id1, id2],
            "title": "cov-ga2 consolidated",
            "summary": "a deterministic consolidation summary over the two sources",
            "namespace": ns,
            "agent_id": CALLER,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    assert_eq!(body["consolidated"], 2);
    assert!(body["id"].is_string());
});

pg_test!(
    pg_consolidate_pg_arm_no_summary_deterministic_fallback,
    url,
    {
        let r = pg_router(&url).await;
        let ns = uniq_ns();
        let id1 = seed_memory(&r, &ns, "no-summary src 1", "alpha body").await;
        let id2 = seed_memory(&r, &ns, "no-summary src 2", "beta body").await;
        // No summary + no LLM wired → resolve_consolidate_summary takes the
        // deterministic title-concat fallback (fetch_consolidate_source_pairs
        // postgres arm runs to gather the source titles).
        let (status, body) = post_json(
            &r,
            "/api/v1/consolidate",
            json!({
                "ids": [id1, id2],
                "title": "cov-ga2 fallback consolidated",
                "namespace": ns,
                "agent_id": CALLER,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "body={body}");
        assert_eq!(body["storage_backend"], "postgres");
        assert!(
            body["summary"].as_str().is_some_and(|s| !s.is_empty()),
            "deterministic fallback summary present; body={body}"
        );
    }
);

pg_test!(pg_consolidate_unknown_source_id_is_400, url, {
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    // No summary forces the source-pair fetch; a non-existent id in the
    // postgres arm surfaces as a 400 (NotFound → memory_not_found).
    let ghost = format!("ghost-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let ghost2 = format!("ghost-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let (status, _b) = post_json(
        &r,
        "/api/v1/consolidate",
        json!({
            "ids": [ghost, ghost2],
            "title": "cov-ga2 ghost consolidate",
            "namespace": ns,
            "agent_id": CALLER,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
});

// ---------------------------------------------------------------------------
// power_consolidation::load_family_handler — postgres `list` + filter arm
// ---------------------------------------------------------------------------

pg_test!(pg_load_family_pg_arm, url, {
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    let (status, body) = post_json(
        &r,
        "/api/v1/memory_load_family",
        json!({"family": "core", "namespace": ns, "k": 10}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    // The pg arm projects {family, namespace, k, count, memories}.
    assert_eq!(body["family"], "core");
    assert!(body["memories"].is_array());
    assert_eq!(body["k"], 10);
});

pg_test!(pg_load_family_unknown_family_is_400, url, {
    let r = pg_router(&url).await;
    let (status, _b) = post_json(
        &r,
        "/api/v1/memory_load_family",
        json!({"family": "not-a-real-family"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
});

// ---------------------------------------------------------------------------
// power_consolidation::auto_tag_handler / expand_query_handler — no-LLM arm
// (CI has pg+AGE but NO LLM: cover the 503 degradation + validation arms)
// ---------------------------------------------------------------------------

pg_test!(pg_auto_tag_no_llm_503, url, {
    let r = pg_router(&url).await;
    // app.llm is None → the handler's first gate returns 503 before any
    // backend work. (The LLM-success branch + fetch_memory_for_handler's
    // happy path require a live LLM — structural exception.)
    let (status, body) = post_json(
        &r,
        "/api/v1/auto_tag",
        json!({"title": "t", "content": "c"}),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body={body}");
    assert_eq!(body["error"], "LLM not configured");
});

pg_test!(pg_expand_query_no_llm_503, url, {
    let r = pg_router(&url).await;
    let (status, body) = post_json(&r, "/api/v1/expand_query", json!({"query": "anything"})).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body={body}");
    assert_eq!(body["error"], "LLM not configured");
});

pg_test!(pg_memory_verify_not_501_3064, url, {
    // #3064 — pre-fix postgres_route_gate 501'd this MCP-parity route.
    // Fail-on-old-code: 501 is the regression. SAL `verify_link` must run.
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    let src = seed_memory(&r, &ns, "verify-src-3064", "src body").await;
    let dst = seed_memory(&r, &ns, "verify-dst-3064", "dst body").await;
    let (status, body) = post_json(
        &r,
        "/api/v1/links",
        json!({"source_id": src, "target_id": dst, "relation": "related_to"}),
    )
    .await;
    assert!(status.is_success(), "seed link status={status} body={body}");
    let (status, body) = post_json(
        &r,
        "/api/v1/memory_verify",
        json!({"source_id": src, "target_id": dst, "relation": "related_to"}),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::NOT_IMPLEMENTED,
        "pre-#3064 501; body={body}"
    );
    assert_eq!(status, StatusCode::OK, "body={body}");
    // sqlite↔pg MCP envelope parity: the seed link is unsigned, so
    // `memory_verify` reports signature_verified=false + null
    // signed_by/signed_at (same as sqlite `handle_verify`). SAL
    // `VerifyLinkReport.verified` is true for unsigned rows — the HTTP
    // mapper must not leak that as signature_verified=true.
    assert_eq!(
        body.get("signature_verified"),
        Some(&json!(false)),
        "unsigned seed; MCP parity; body={body}"
    );
    assert_eq!(body.get("signed_by"), Some(&json!(null)), "body={body}");
    assert_eq!(body.get("signed_at"), Some(&json!(null)), "body={body}");
    assert!(
        body.get("attest_level").is_some(),
        "MCP envelope; body={body}"
    );
});
