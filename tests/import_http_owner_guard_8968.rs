// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #8968 — `POST /api/v1/import` must never replace or merge another
//! owner's row. A row whose id, or whose `(title, namespace)` slot, is held
//! by a row of another owner is NOT written: the destination row is kept
//! byte-for-byte, the receipt counts it in `cross_owner_kept`, and the
//! `errors` array names the incoming id (the #3151 disposition). The same
//! owner re-importing its own row still merges.

#![allow(clippy::needless_pass_by_value)]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::models::field_names::CROSS_OWNER_KEPT;
use ai_memory::portability::owner_guard::FOREIGN_OWNER_KEPT_MSG;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// The owner of the seeded private row.
const OWNER_A: &str = "ops:owner-a-8968";
/// The importing caller, a different owner.
const OWNER_B: &str = "ops:owner-b-8968";
/// Namespace shared by every row of this suite.
const NAMESPACE: &str = "import-8968/owner-guard";
/// The seeded row's id and title.
const SEED_ID: &str = "89680000-0000-4000-8000-000000000001";
const SEED_TITLE: &str = "private-row-8968";
/// The seeded row's content, which must survive every foreign import.
const SEED_CONTENT: &str = "owner-a private content 8968";
/// The content a foreign import tries to write.
const FOREIGN_CONTENT: &str = "owner-b overwrite attempt 8968";
/// A second id that collides with the seed only on `(title, namespace)`.
const SLOT_ONLY_ID: &str = "89680000-0000-4000-8000-000000000002";

#[allow(clippy::too_many_lines)]
fn build_router_fixture_with_admin(
    db_path: &std::path::Path,
    admin_ids: Vec<String>,
) -> axum::Router {
    // #1570 — these tests model an AUTHENTICATED deployment (api_key
    // configured at boot), the pre-#1570 implicit posture, so the admin
    // header role-claims they assert keep working. The #1570 secure
    // default (bare X-Agent-Id on an UNAUTHENTICATED deployment -> 403)
    // is pinned by tests/admin_header_trust_1570.rs in its own process.
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let conn = ai_memory::db::open(db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("open SqliteStore"));
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
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(admin_ids),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, app_state)
}

fn body_memory(id: &str, title: &str, content: &str, owner: &str) -> Value {
    json!({
        "id": id, "tier": "long", "namespace": NAMESPACE,
        "title": title, "content": content,
        "tags": [], "priority": 5, "confidence": 1.0, "source": "import",
        "access_count": 0,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "last_accessed_at": null, "expires_at": null,
        "metadata": {"agent_id": owner, "scope": "private"},
        "reflection_depth": 0,
        "memory_kind": "observation",
    })
}

async fn import_as(router: &axum::Router, caller: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/import")
        .header("content-type", "application/json")
        .header("x-agent-id", caller)
        .body(Body::from(serde_json::to_vec(&body).expect("encode body")))
        .expect("build request");
    let resp = router.clone().oneshot(req).await.expect("route");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .expect("read body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// `(content, agent_id)` of the seeded row as stored.
fn seed_row(db_path: &std::path::Path) -> (String, String) {
    let conn = ai_memory::db::open(db_path).expect("open db");
    let mem = ai_memory::db::get(&conn, SEED_ID)
        .expect("read seed")
        .expect("seed row present");
    let owner = mem.metadata["agent_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    (mem.content, owner)
}

fn count_rows(db_path: &std::path::Path) -> i64 {
    let conn = ai_memory::db::open(db_path).expect("open db");
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
        [NAMESPACE],
        |r| r.get(0),
    )
    .expect("count rows")
}

/// One collision case: the incoming row's id and the receipt it must yield.
struct Case {
    name: &'static str,
    incoming_id: &'static str,
}

const FOREIGN_CASES: [Case; 2] = [
    Case {
        name: "same id",
        incoming_id: SEED_ID,
    },
    Case {
        name: "same (title, namespace), new id",
        incoming_id: SLOT_ONLY_ID,
    },
];

#[tokio::test]
async fn issue_8968_http_import_keeps_foreign_owner_private_row() {
    for case in &FOREIGN_CASES {
        let f = NamedTempFile::new().expect("tempfile under TMPDIR");
        let db_path = f.path();
        let router = build_router_fixture_with_admin(db_path, vec![OWNER_A.into(), OWNER_B.into()]);
        let seed = json!({"memories": [body_memory(SEED_ID, SEED_TITLE, SEED_CONTENT, OWNER_A)]});
        let (status, payload) = import_as(&router, OWNER_A, seed).await;
        assert_eq!(status, StatusCode::OK, "{}: seed body={payload}", case.name);
        assert_eq!(payload["imported"], 1, "{}: seed body={payload}", case.name);

        let attack = json!({"memories": [body_memory(case.incoming_id, SEED_TITLE, FOREIGN_CONTENT, OWNER_B)]});
        let (status, payload) = import_as(&router, OWNER_B, attack).await;
        assert_eq!(status, StatusCode::OK, "{}: body={payload}", case.name);
        assert_eq!(payload["imported"], 0, "{}: body={payload}", case.name);
        assert_eq!(
            payload[CROSS_OWNER_KEPT], 1,
            "{}: body={payload}",
            case.name
        );
        assert_eq!(
            payload["errors"],
            json!([format!("{}: {FOREIGN_OWNER_KEPT_MSG}", case.incoming_id)]),
            "{}: body={payload}",
            case.name
        );
        assert_eq!(
            seed_row(db_path),
            (SEED_CONTENT.to_string(), OWNER_A.to_string()),
            "{}: the foreign owner's row must be kept byte-for-byte",
            case.name
        );
        assert_eq!(
            count_rows(db_path),
            1,
            "{}: no second row lands in the slot",
            case.name
        );
    }
}

#[tokio::test]
async fn issue_8968_http_import_same_owner_still_merges() {
    let f = NamedTempFile::new().expect("tempfile under TMPDIR");
    let db_path = f.path();
    let router = build_router_fixture_with_admin(db_path, vec![OWNER_A.into()]);
    for content in [SEED_CONTENT, FOREIGN_CONTENT] {
        let body = json!({"memories": [body_memory(SEED_ID, SEED_TITLE, content, OWNER_A)]});
        let (status, payload) = import_as(&router, OWNER_A, body).await;
        assert_eq!(status, StatusCode::OK, "body={payload}");
        assert_eq!(payload["imported"], 1, "body={payload}");
        assert_eq!(payload[CROSS_OWNER_KEPT], 0, "body={payload}");
    }
    assert_eq!(
        seed_row(db_path),
        (FOREIGN_CONTENT.to_string(), OWNER_A.to_string()),
        "the owner's own re-import merges"
    );
}
