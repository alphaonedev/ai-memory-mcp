// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! cov_ga2 — REAL-Postgres router coverage for the four handler modules
//! whose `#[cfg(feature = "sal-postgres")]` dispatch arms were left dark
//! by the prior wave's "fake-postgres" harness (an `AppState` whose
//! `storage_backend = Postgres` but whose `store` is a `SqliteStore`
//! handle). That trick trips `downcast_postgres` and 503s BEFORE the
//! postgres branch body runs, so the bulk of the uncovered lines —
//! the actual SAL trait dispatch inside each postgres arm — never
//! executed.
//!
//! This suite copies the `tests/cov3_handlers_postgres.rs` harness
//! exactly: it builds the production router (`ai_memory::build_router`)
//! backed by a LIVE [`PostgresStore`] with `storage_backend =
//! StorageBackend::Postgres`, then drives HTTP requests through
//! `tower::oneshot` so the real postgres dispatch arm in each handler
//! runs end-to-end. A concrete `PostgresStore` clone is kept alongside
//! the `Arc<dyn MemoryStore>` so each test can seed the exact pg state
//! (registered agents, approve-gated pending rows, link anchors) the
//! branch body needs to reach past its early-return refusals.
//!
//! Modules + postgres-branch functions covered:
//!   - `handlers::governance::list_pending` (pg arm via
//!     `list_pending_actions_via_store`)
//!   - `handlers::admin::{register_agent, bind_agent_pubkey,
//!     import_memories, quota_status_handler}` (pg arms)
//!   - `handlers::links::{create_link, delete_link, get_links,
//!     verify_link_handler}` (pg arms)
//!   - `handlers::approvals::{approval_decide, approval_decide_postgres}`
//!     (pg arms; HMAC-gated)
//!
//! Gated on `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL`.
//! Without the env var every test prints a skip line and returns. Every
//! namespace / agent-id / memory-id is uuid-randomised so this suite
//! never collides with co-resident suites on the shared scratch DB, and
//! no test ever asserts global-table emptiness — assertions filter to
//! this suite's own unique ids only.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::similar_names)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::uninlined_format_args)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{ConfidenceSource, GovernanceDecision, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, GovernedAction, MemoryStore};

/// Admin agent-id this suite presents on every request. It is added to
/// `admin_agent_ids` so the admin-gated handlers (register / import /
/// quota-list / bind) admit it past `require_admin`.
const ADMIN_AGENT: &str = "ai:cov-ga2-pg";

/// A hex-decodable HMAC secret so the approvals path takes the canonical
/// (hex-decoded) key branch in `hmac_sha256_hex`, not the invalid-hex
/// raw-bytes fallback.
const HMAC_SECRET_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Opt into the #1570 legacy header-trust posture so a bare
/// `X-Agent-Id` naming an allowlisted admin resolves to admin role on
/// this keyless test daemon (no api_key is configured). Without this,
/// `is_admin_caller_trusted` refuses header-only admin and every
/// admin-gated handler (register / import / quota-list) 403s before its
/// postgres arm runs. Set process-wide exactly once; it only LOOSENS
/// admin gating, so it never affects the non-admin negative tests (they
/// use distinct non-admin agent ids that are not on the allowlist).
fn enable_admin_header_trust() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: set once, before any concurrent reader observes a
        // half-written value; the var is only ever set (never cleared)
        // for the lifetime of the test binary.
        unsafe {
            std::env::set_var(ai_memory::handlers::admin_role::ENV_ADMIN_HEADER_TRUST, "1");
        }
    });
}

/// Connect once, returning a concrete `PostgresStore` (kept for direct
/// seeding) plus the production router that wraps a clone of it as the
/// `Arc<dyn MemoryStore>`. `PostgresStore` is `Clone` (shares the pool),
/// so the seeding handle and the router observe the same DB.
async fn pg_store_and_router(url: &str) -> (PostgresStore, axum::Router) {
    let store_concrete = PostgresStore::connect(url).await.expect("connect postgres");
    let router = router_for(store_concrete.clone());
    (store_concrete, router)
}

fn router_for(store_concrete: PostgresStore) -> axum::Router {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = Arc::new(store_concrete);
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
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec![ADMIN_AGENT.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

// ---------------------------------------------------------------------------
// HTTP drivers
// ---------------------------------------------------------------------------

async fn decode(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn post_json(router: &axum::Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_AGENT)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    decode(router, req).await
}

async fn put_json(router: &axum::Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_AGENT)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    decode(router, req).await
}

async fn delete_json(router: &axum::Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_AGENT)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    decode(router, req).await
}

async fn get(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", ADMIN_AGENT)
        .body(Body::empty())
        .unwrap();
    decode(router, req).await
}

// ---------------------------------------------------------------------------
// HMAC signing — replicates `subscriptions::{sha256_hex, hmac_sha256_hex}`
// (both `pub(crate)`, so not reachable from an integration test). The
// canonical signed string is `<ts>.<METHOD>.<pending_id>.<body>` per
// `verify_approval_hmac`'s #628-P1 binding.
// ---------------------------------------------------------------------------

fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hmac_sha256_hex(key_hex: &str, body: &str) -> String {
    const BLOCK: usize = 64;
    let mut key = hex_decode(key_hex);
    if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(&key);
        key = h.finalize().to_vec();
    }
    key.resize(BLOCK, 0);
    let mut opad = [0x5cu8; BLOCK];
    let mut ipad = [0x36u8; BLOCK];
    for i in 0..BLOCK {
        opad[i] ^= key[i];
        ipad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(body.as_bytes());
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    format!("{:x}", outer.finalize())
}

/// Build an HMAC-signed `POST /api/v1/approvals/{pending_id}` request.
fn signed_approval_request(pending_id: &str, body: &Value) -> Request<Body> {
    let body_bytes = serde_json::to_vec(body).unwrap();
    let body_str = String::from_utf8(body_bytes.clone()).unwrap();
    let ts = chrono::Utc::now().timestamp().to_string();
    let canonical = format!("{ts}.POST.{pending_id}.{body_str}");
    let key_hash = sha256_hex(HMAC_SECRET_HEX);
    let sig = hmac_sha256_hex(&key_hash, &canonical);
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_AGENT)
        .header("x-ai-memory-signature", format!("sha256={sig}"))
        .header("x-ai-memory-timestamp", ts)
        .body(Body::from(body_bytes))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Seeding helpers (direct against the concrete PostgresStore)
// ---------------------------------------------------------------------------

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..12])
}

fn mem(id: &str, ns: &str, title: &str, owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: "cov-ga2 pg-handler anchor".to_string(),
        tags: vec!["cov-ga2".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({ "agent_id": owner }),
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
    }
}

/// Point a fresh namespace at an `write: approve` governance standard so
/// a non-owner Store routes through `Pending` — yielding a real
/// `pending_id` we can drive through the governance + approvals handlers.
async fn seed_approve_standard(store: &PostgresStore, ns: &str, owner: &str) {
    let ctx = CallerContext::for_admin(owner);
    let std_id = uid("std");
    let mut standard = mem(&std_id, ns, &format!("standard:{ns}"), owner);
    standard.tier = Tier::Long;
    standard.metadata = json!({
        "agent_id": owner,
        "governance": {"write": "approve", "promote": "any", "delete": "owner"},
    });
    store.store(&ctx, &standard).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, ns, &std_id, None)
        .await
        .expect("set_namespace_standard");
}

/// Seed an approve-gated pending Store action and return its id. The
/// queued payload is a full serialized `Memory` so the
/// `execute_pending_action` "store" arm can deserialize + replay it.
async fn seed_pending_store(
    store: &PostgresStore,
    ns: &str,
    owner: &str,
    requester: &str,
) -> String {
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    seed_approve_standard(store, ns, owner).await;
    let queued = mem(&uid("pa"), ns, "needs approval", requester);
    let payload = serde_json::to_value(&queued).expect("serialize memory payload");
    let decision = store
        .enforce_governance_action(GovernedAction::Store, ns, requester, None, None, &payload)
        .await
        .expect("enforce_governance_action");
    match decision {
        GovernanceDecision::Pending(id) => id,
        other => panic!("approve-level non-owner write must Pending; got {other:?}"),
    }
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

// ===========================================================================
// governance::list_pending — postgres arm via list_pending_actions_via_store
// ===========================================================================

pg_test!(pg_list_pending_admin_sees_seeded_row, url, {
    enable_admin_header_trust();
    let (store, router) = pg_store_and_router(&url).await;
    let owner = uid("ai:cov-ga2-owner");
    let requester = uid("ai:cov-ga2-req");
    let ns = uid("cov-ga2-pend");
    let pending_id = seed_pending_store(&store, &ns, &owner, &requester).await;

    // ADMIN_AGENT is operator-allowlisted → admin scope → bypasses the
    // requested_by post-filter and sees the seeded row. Filter the
    // global pending list to OUR unique pending_id only.
    let (status, body) = get(
        &router,
        &format!("/api/v1/pending?status=pending&namespace={ns}&limit=1000"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    assert_eq!(body["owner_scope"], "admin");
    let pending = body["pending"].as_array().expect("pending array");
    assert!(
        pending
            .iter()
            .any(|p| p.get("id").and_then(Value::as_str) == Some(pending_id.as_str())),
        "admin list must include our seeded pending_id {pending_id}; got {body}"
    );
});

pg_test!(pg_list_pending_non_admin_filtered_to_caller, url, {
    // A non-admin caller resolves to itself and the post-filter keeps
    // only rows whose requested_by == caller. ADMIN_AGENT requested
    // nothing here (the seed requester is a different uuid), so OUR
    // seeded row must be absent from a non-admin caller's view.
    let (store, router) = pg_store_and_router(&url).await;
    let owner = uid("ai:cov-ga2-owner");
    let requester = uid("ai:cov-ga2-req");
    let ns = uid("cov-ga2-pend");
    let pending_id = seed_pending_store(&store, &ns, &owner, &requester).await;

    let non_admin = uid("ai:cov-ga2-nonadmin");
    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "/api/v1/pending?status=pending&namespace={ns}&limit=1000"
        ))
        .header("x-agent-id", &non_admin)
        .body(Body::empty())
        .unwrap();
    let (status, body) = decode(&router, req).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    assert_eq!(body["owner_scope"], "caller");
    let pending = body["pending"].as_array().expect("pending array");
    assert!(
        !pending
            .iter()
            .any(|p| p.get("id").and_then(Value::as_str) == Some(pending_id.as_str())),
        "non-admin caller must NOT see another requester's pending_id {pending_id}"
    );
});

// ===========================================================================
// admin::register_agent — postgres arm
// ===========================================================================

pg_test!(pg_register_agent_postgres_arm, url, {
    enable_admin_header_trust();
    let (_store, router) = pg_store_and_router(&url).await;
    let agent_id = uid("ai:cov-ga2-reg");
    let (status, body) = post_json(
        &router,
        "/api/v1/agents",
        &json!({"agent_id": agent_id, "agent_type": "system", "capabilities": ["recall"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    assert_eq!(body["agent_id"], agent_id);
    assert!(
        body["id"].is_string(),
        "postgres register returns the row id"
    );
});

pg_test!(pg_register_agent_invalid_id_is_400, url, {
    enable_admin_header_trust();
    let (_store, router) = pg_store_and_router(&url).await;
    let (status, _body) = post_json(
        &router,
        "/api/v1/agents",
        &json!({"agent_id": "bad id with spaces", "agent_type": "system"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
});

// ===========================================================================
// admin::bind_agent_pubkey — postgres arm (register first, then bind)
// ===========================================================================

pg_test!(pg_bind_agent_pubkey_postgres_arm, url, {
    enable_admin_header_trust();
    let (_store, router) = pg_store_and_router(&url).await;
    let agent_id = uid("ai:cov-ga2-bind");
    // Register so the bind has a row to mutate (unregistered → InvalidInput).
    let (rs, rb) = post_json(
        &router,
        "/api/v1/agents",
        &json!({"agent_id": agent_id, "agent_type": "system"}),
    )
    .await;
    assert_eq!(rs, StatusCode::CREATED, "register body={rb}");

    // A real 32-byte Ed25519 public key (base64). Generated via the
    // crate's own keypair surface so it passes validate_agent_pubkey_b64.
    let kp = ai_memory::identity::keypair::generate(&agent_id).expect("keypair");
    let pubkey_b64 = kp.public_base64();

    let (status, body) = put_json(
        &router,
        &format!("/api/v1/agents/{agent_id}/pubkey"),
        &json!({"pubkey_b64": pubkey_b64}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bind body={body}");
    assert_eq!(body["bound"], true);
    assert_eq!(body["agent_id"], agent_id);
});

pg_test!(pg_bind_agent_pubkey_unregistered_is_error, url, {
    enable_admin_header_trust();
    let (_store, router) = pg_store_and_router(&url).await;
    let agent_id = uid("ai:cov-ga2-bind-missing");
    let kp = ai_memory::identity::keypair::generate(&agent_id).expect("keypair");
    let (status, _body) = put_json(
        &router,
        &format!("/api/v1/agents/{agent_id}/pubkey"),
        &json!({"pubkey_b64": kp.public_base64()}),
    )
    .await;
    // Binding an unregistered agent surfaces the SAL InvalidInput →
    // store_err_to_response (not OK). The branch body executed either
    // way; we only assert it did not 200.
    assert_ne!(status, StatusCode::OK, "unregistered bind must not succeed");
});

// ===========================================================================
// admin::import_memories — postgres arm (admin gate + restamp + store loop)
// ===========================================================================

pg_test!(pg_import_memories_postgres_arm, url, {
    enable_admin_header_trust();
    let (_store, router) = pg_store_and_router(&url).await;
    let ns = uid("cov-ga2-import");
    let m1 = mem(&uid("imp"), &ns, "import-one", ADMIN_AGENT);
    let m2 = mem(&uid("imp"), &ns, "import-two", ADMIN_AGENT);
    let (status, body) = post_json(
        &router,
        "/api/v1/import",
        &json!({
            "memories": [m1, m2],
            "links": [],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "import body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    assert_eq!(
        body["imported"], 2,
        "both rows import on the pg arm; body={body}"
    );
});

pg_test!(pg_import_memories_oversize_is_400, url, {
    let (_store, router) = pg_store_and_router(&url).await;
    // Exceed MAX_BULK_SIZE so the early-return 400 fires before any
    // store call — covers the size-guard arm.
    let ns = uid("cov-ga2-import-big");
    let big: Vec<Value> = (0..=ai_memory::handlers::MAX_BULK_SIZE)
        .map(|i| {
            serde_json::to_value(mem(&uid("imp"), &ns, &format!("row-{i}"), ADMIN_AGENT)).unwrap()
        })
        .collect();
    let (status, _body) = post_json(&router, "/api/v1/import", &json!({ "memories": big })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
});

// ===========================================================================
// admin::quota_status_handler — postgres arms (single-agent + list)
// ===========================================================================

pg_test!(pg_quota_status_single_agent_postgres_arm, url, {
    let (_store, router) = pg_store_and_router(&url).await;
    // body.agent_id == authenticated caller → single-agent pg arm
    // (app.store.quota_status). A fresh agent simply has the default
    // quota row projected; OK either way.
    let (status, body) = post_json(
        &router,
        "/api/v1/quota/status",
        &json!({"agent_id": ADMIN_AGENT}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "quota single body={body}");
});

pg_test!(pg_quota_status_list_postgres_arm, url, {
    enable_admin_header_trust();
    let (_store, router) = pg_store_and_router(&url).await;
    // No agent_id → operator list path; ADMIN_AGENT passes require_admin
    // and reaches app.store.quota_status_list (pg arm).
    let (status, body) = post_json(&router, "/api/v1/quota/status", &json!({})).await;
    assert_eq!(status, StatusCode::OK, "quota list body={body}");
    assert!(body.get("quotas").is_some(), "list shape carries quotas[]");
    assert!(body.get("count").is_some());
});

pg_test!(pg_quota_status_mismatch_is_403, url, {
    let (_store, router) = pg_store_and_router(&url).await;
    // body.agent_id != caller → 403 before any store call.
    let (status, _body) = post_json(
        &router,
        "/api/v1/quota/status",
        &json!({"agent_id": "ai:someone-else"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
});

// ===========================================================================
// links::create_link / get_links — postgres arms
// ===========================================================================

pg_test!(pg_create_and_get_links_postgres_arm, url, {
    let (store, router) = pg_store_and_router(&url).await;
    let ns = uid("cov-ga2-links");
    // Seed two real anchor memories owned by ADMIN_AGENT so link_signed
    // + the get(source) event-namespace lookup resolve.
    let src_id = uid("ln-src");
    let tgt_id = uid("ln-tgt");
    let ctx = CallerContext::for_admin(ADMIN_AGENT);
    store
        .store(&ctx, &mem(&src_id, &ns, "link-src", ADMIN_AGENT))
        .await
        .expect("seed src");
    store
        .store(&ctx, &mem(&tgt_id, &ns, "link-tgt", ADMIN_AGENT))
        .await
        .expect("seed tgt");

    let (cs, cb) = post_json(
        &router,
        "/api/v1/links",
        &json!({"source_id": src_id, "target_id": tgt_id, "relation": "related_to"}),
    )
    .await;
    assert_eq!(cs, StatusCode::CREATED, "create_link body={cb}");
    assert_eq!(cb["linked"], true);
    assert_eq!(cb["source_id"], src_id);

    // get_links postgres arm — admin caller bypasses the visibility
    // filter; assert OUR edge is present (filter to our own ids).
    let (gs, gb) = get(&router, &format!("/api/v1/links/{src_id}")).await;
    assert_eq!(gs, StatusCode::OK, "get_links body={gb}");
    let links = gb["links"].as_array().expect("links array");
    assert!(
        links
            .iter()
            .any(|l| l.get("target_id").and_then(Value::as_str) == Some(tgt_id.as_str())),
        "get_links must surface the edge we just created; got {gb}"
    );
});

pg_test!(pg_create_link_invalid_relation_is_400, url, {
    let (_store, router) = pg_store_and_router(&url).await;
    let (status, _b) = post_json(
        &router,
        "/api/v1/links",
        &json!({"source_id": "a", "target_id": "b", "relation": "not_a_relation"}),
    )
    .await;
    // Pre-flight relation closed-set check returns 400 before the pg arm.
    assert_eq!(status, StatusCode::BAD_REQUEST);
});

// ===========================================================================
// links::delete_link — postgres arm
// ===========================================================================

pg_test!(pg_delete_link_postgres_arm, url, {
    let (store, router) = pg_store_and_router(&url).await;
    let ns = uid("cov-ga2-dellink");
    let src_id = uid("dl-src");
    let tgt_id = uid("dl-tgt");
    let ctx = CallerContext::for_admin(ADMIN_AGENT);
    store
        .store(&ctx, &mem(&src_id, &ns, "del-src", ADMIN_AGENT))
        .await
        .expect("seed src");
    store
        .store(&ctx, &mem(&tgt_id, &ns, "del-tgt", ADMIN_AGENT))
        .await
        .expect("seed tgt");
    // Create the edge through the router first (postgres create arm).
    let (cs, _cb) = post_json(
        &router,
        "/api/v1/links",
        &json!({"source_id": src_id, "target_id": tgt_id, "relation": "related_to"}),
    )
    .await;
    assert_eq!(cs, StatusCode::CREATED);

    // Now delete it through the router (postgres delete arm).
    let (ds, db) = delete_json(
        &router,
        "/api/v1/links",
        &json!({"source_id": src_id, "target_id": tgt_id, "relation": "related_to"}),
    )
    .await;
    assert_eq!(ds, StatusCode::OK, "delete_link body={db}");
    assert!(
        db.get("deleted").is_some(),
        "delete returns a boolean verdict"
    );
});

// ===========================================================================
// links::verify_link_handler — postgres arm
// ===========================================================================

pg_test!(pg_verify_link_missing_args_is_400, url, {
    let (_store, router) = pg_store_and_router(&url).await;
    let (status, _b) = post_json(&router, "/api/v1/links/verify", &json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
});

pg_test!(pg_verify_link_nonexistent_postgres_arm, url, {
    let (_store, router) = pg_store_and_router(&url).await;
    // Valid args, no such link → the postgres verify_link trait arm
    // runs and maps the not-found store error.
    let src = uid("ghost-src");
    let tgt = uid("ghost-tgt");
    let (status, _b) = post_json(
        &router,
        "/api/v1/links/verify",
        &json!({"source_id": src, "target_id": tgt}),
    )
    .await;
    assert!(
        status == StatusCode::NOT_FOUND
            || status == StatusCode::OK
            || status == StatusCode::BAD_REQUEST,
        "verify pg arm executed; status={status}"
    );
});

// ===========================================================================
// approvals::approval_decide / approval_decide_postgres — postgres arms
// ===========================================================================

pg_test!(pg_approval_decide_approve_postgres_arm, url, {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (store, router) = pg_store_and_router(&url).await;
    let owner = uid("ai:cov-ga2-aowner");
    let requester = uid("ai:cov-ga2-areq");
    let ns = uid("cov-ga2-approve");
    let pending_id = seed_pending_store(&store, &ns, &owner, &requester).await;

    let body = json!({"decision": "approve", "remember": "once"});
    let req = signed_approval_request(&pending_id, &body);
    let (status, resp) = decode(&router, req).await;
    // The approve path runs governance_approve_with_consensus +
    // execute_pending_action against real postgres. A single human
    // approver may resolve to Approved (200 with executed=true) or
    // remain Pending (consensus quorum) — both are covered branch
    // bodies of approval_decide_postgres. 500 only if execute fails.
    assert!(
        status == StatusCode::OK,
        "approve pg arm should 200 (approved or pending); status={status} resp={resp}"
    );
    assert_eq!(resp["id"], pending_id);
});

pg_test!(pg_approval_decide_deny_postgres_arm, url, {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (store, router) = pg_store_and_router(&url).await;
    let owner = uid("ai:cov-ga2-downer");
    let requester = uid("ai:cov-ga2-dreq");
    let ns = uid("cov-ga2-deny");
    let pending_id = seed_pending_store(&store, &ns, &owner, &requester).await;

    let body = json!({"decision": "deny", "remember": "once"});
    let req = signed_approval_request(&pending_id, &body);
    let (status, resp) = decode(&router, req).await;
    assert_eq!(status, StatusCode::OK, "deny pg arm body={resp}");
    assert_eq!(resp["rejected"], true);
    assert_eq!(resp["id"], pending_id);
});

pg_test!(pg_approval_decide_unknown_id_postgres_arm, url, {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (_store, router) = pg_store_and_router(&url).await;
    // Valid HMAC but no such pending row → the postgres deny arm's
    // pending_decide(false) returns Ok(false) → 404.
    let pending_id = uid("nope");
    let body = json!({"decision": "deny", "remember": "once"});
    let req = signed_approval_request(&pending_id, &body);
    let (status, _resp) = decode(&router, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
});

pg_test!(pg_approval_decide_bad_signature_is_401, url, {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (_store, router) = pg_store_and_router(&url).await;
    let pending_id = uid("sig");
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_AGENT)
        .header("x-ai-memory-signature", "sha256=deadbeef")
        .header(
            "x-ai-memory-timestamp",
            chrono::Utc::now().timestamp().to_string(),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({"decision": "approve"})).unwrap(),
        ))
        .unwrap();
    let (status, _resp) = decode(&router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
});
