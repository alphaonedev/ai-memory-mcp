// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #958 — `list_pending` caller-vs-requester gate regression
//! (security-medium, v0.7.0 SHIP-blocker).
//!
//! Pre-#958 the `GET /api/v1/pending` handler took NO `headers:
//! HeaderMap`, accepted no caller-identity input, and dispatched
//! directly to:
//!
//! - Postgres: `crate::store::postgres::list_pending_actions_via_store`
//! - Sqlite: `db::list_pending_actions`
//!
//! Both functions take NO `caller: &str`. Any HTTP caller could
//! enumerate every pending governance action across every owner +
//! every namespace — leaking the proposed memory body, the
//! requester's `agent_id`, and the target-namespace topology. The
//! K10 SSE handler (`approvals_sse`) already applies the per-#628
//! tenant filter via `sse_event_visible_to`, but the polling-style
//! HTTP list path was the legacy gap that same issue closed for
//! the SSE channel only.
//!
//! The fix (companion to #957's admin-gate posture):
//!
//! 1. Handler signature gains `headers: HeaderMap`.
//! 2. Resolve caller from `X-Agent-Id` via
//!    `identity::resolve_http_agent_id`.
//! 3. Check admin status via
//!    `handlers::admin_role::is_admin_caller`.
//! 4. Post-filter the pending list to rows whose
//!    `PendingAction.requested_by` matches the caller. Admin
//!    callers (operator queue-view) bypass the filter.
//!
//! These tests pin the contract on the sqlite path:
//!
//! 1. `non_admin_caller_sees_only_own_pending_958` — alice queues
//!    one pending, bob queues two; alice's list returns only her
//!    one row, bob's list returns only his two rows; cross-tenant
//!    rows are silently dropped from the count.
//! 2. `admin_caller_sees_every_pending_958` — admin (in
//!    `admin_agent_ids`) sees both alice's + bob's pending rows
//!    (the legitimate operator queue-view surface).
//! 3. `missing_agent_id_header_sees_no_pending_958` — request
//!    with no `X-Agent-Id` synthesizes `anonymous:req-…` which
//!    matches no `requested_by` row → empty list (no leak).
//! 4. `owner_scope_field_present_958` — the response envelope
//!    carries `owner_scope` ("caller" vs "admin") so callers can
//!    distinguish their own queue view from an operator's
//!    cross-tenant view.
//! 5. `count_matches_filtered_payload_958` — the `count` field
//!    reflects the POST-filter list length, not the underlying
//!    table row count, so a non-admin caller cannot probe the
//!    queue depth of other tenants.

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use rusqlite::params;
use serde_json::Value;
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// Insert a `pending_actions` row directly via SQL. The handler
/// list path reads back only the `requested_by` column for the gate,
/// so this minimal fixture is sufficient to exercise the filter.
/// Routes through `ai_memory::db::open` so the schema migrations
/// run before the raw insert (the `pending_actions` table is
/// created on the first `db::open` against a fresh path).
fn seed_pending(db_path: &std::path::Path, id: &str, requested_by: &str, namespace: &str) {
    // Drop the migrated handle before opening a raw rusqlite
    // connection so WAL state is committed and the raw connection
    // sees the freshly-created tables. `db::open` itself returns a
    // `rusqlite::Connection`, so we use it directly for the insert.
    let conn = ai_memory::db::open(db_path).expect("db::open (initialises schema)");
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO pending_actions (id, action_type, namespace, payload, requested_by,
                                       requested_at, status)
         VALUES (?1, 'store', ?2, '{}', ?3, ?4, 'pending')",
        params![id, namespace, requested_by, now],
    )
    .expect("insert pending row");
}

#[allow(clippy::too_many_lines)]
fn build_router_fixture_with_admin(
    db_path: &std::path::Path,
    admin_ids: Vec<String>,
) -> axum::Router {
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
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(admin_ids),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn list_pending_as(router: &axum::Router, caller: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("GET").uri("/api/v1/pending");
    if let Some(c) = caller {
        builder = builder.header("x-agent-id", c);
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Helper — collect the `requested_by` strings from a pending-list
/// payload's `pending` array.
fn requested_by_set(body: &Value) -> Vec<String> {
    body.get("pending")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|row| {
            row.get("requested_by")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

#[tokio::test]
async fn non_admin_caller_sees_only_own_pending_958() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    seed_pending(db_path, "p-alice-1", "alice", "ns-a");
    seed_pending(db_path, "p-bob-1", "bob", "ns-b");
    seed_pending(db_path, "p-bob-2", "bob", "ns-b");

    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);

    // Alice should see her ONE row, NOT bob's two.
    let (status, body) = list_pending_as(&router, Some("alice")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#958: list MUST return 200 for authenticated non-admin caller; body={body}"
    );
    assert_eq!(
        body["count"].as_u64(),
        Some(1),
        "#958: alice MUST see exactly 1 pending row; body={body}"
    );
    let seen = requested_by_set(&body);
    assert_eq!(
        seen,
        vec!["alice".to_string()],
        "#958: alice's list MUST contain only her own requested_by; body={body}"
    );

    // Bob should see his TWO rows, NOT alice's.
    let (status, body) = list_pending_as(&router, Some("bob")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["count"].as_u64(),
        Some(2),
        "#958: bob MUST see exactly 2 pending rows; body={body}"
    );
    let seen = requested_by_set(&body);
    assert!(
        seen.iter().all(|rb| rb == "bob"),
        "#958: bob's list MUST contain only his own requested_by; got={seen:?} body={body}"
    );
}

#[tokio::test]
async fn admin_caller_sees_every_pending_958() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    seed_pending(db_path, "p-alice-1", "alice", "ns-a");
    seed_pending(db_path, "p-bob-1", "bob", "ns-b");
    seed_pending(db_path, "p-carol-1", "carol", "ns-c");

    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);

    // Admin (in allowlist) MUST see every pending row — the
    // legitimate operator queue-view surface.
    let (status, body) = list_pending_as(&router, Some("ops:admin")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["count"].as_u64(),
        Some(3),
        "#958: admin MUST see every pending row; body={body}"
    );
    let mut seen = requested_by_set(&body);
    seen.sort();
    assert_eq!(
        seen,
        vec!["alice".to_string(), "bob".to_string(), "carol".to_string()],
        "#958: admin's list MUST cover every requester; got={seen:?} body={body}"
    );
    // Owner scope indicator: operators get the admin marker so
    // downstream UIs can label the view appropriately.
    assert_eq!(
        body["owner_scope"].as_str(),
        Some("admin"),
        "#958: admin response MUST carry owner_scope=admin; body={body}"
    );
}

#[tokio::test]
async fn missing_agent_id_header_sees_no_pending_958() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    seed_pending(db_path, "p-alice-1", "alice", "ns-a");
    seed_pending(db_path, "p-bob-1", "bob", "ns-b");

    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);

    // No X-Agent-Id header → synthesizes `anonymous:req-…` which
    // cannot match any seeded `requested_by` value. The list MUST
    // be empty; the count MUST be 0 (no leakage of underlying row
    // count).
    let (status, body) = list_pending_as(&router, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["count"].as_u64(),
        Some(0),
        "#958: anonymous caller MUST see 0 pending rows; body={body}"
    );
    let seen = requested_by_set(&body);
    assert!(
        seen.is_empty(),
        "#958: anonymous caller MUST get empty pending list; got={seen:?} body={body}"
    );
}

#[tokio::test]
async fn owner_scope_field_present_958() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    seed_pending(db_path, "p-alice-1", "alice", "ns-a");

    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);

    // Non-admin caller: owner_scope=caller
    let (_status, body) = list_pending_as(&router, Some("alice")).await;
    assert_eq!(
        body["owner_scope"].as_str(),
        Some("caller"),
        "#958: non-admin response MUST carry owner_scope=caller; body={body}"
    );

    // Admin caller: owner_scope=admin
    let (_status, body) = list_pending_as(&router, Some("ops:admin")).await;
    assert_eq!(
        body["owner_scope"].as_str(),
        Some("admin"),
        "#958: admin response MUST carry owner_scope=admin; body={body}"
    );
}

#[tokio::test]
async fn count_matches_filtered_payload_958() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    // Seed 1 row for alice + 5 rows for bob.
    seed_pending(db_path, "p-alice-1", "alice", "ns-a");
    for i in 0..5 {
        seed_pending(db_path, &format!("p-bob-{i}"), "bob", "ns-b");
    }

    let router = build_router_fixture_with_admin(db_path, vec![]);

    // Alice's count MUST be 1, NOT 6 — the count field MUST
    // reflect the post-filter list length, so a non-admin caller
    // cannot use the count as an enumeration side-channel against
    // the queue depth of other tenants.
    let (status, body) = list_pending_as(&router, Some("alice")).await;
    assert_eq!(status, StatusCode::OK);
    let count = body["count"].as_u64().unwrap_or(0);
    let pending_len = body
        .get("pending")
        .and_then(Value::as_array)
        .map_or(0, Vec::len) as u64;
    assert_eq!(
        count, 1,
        "#958: count MUST reflect post-filter length (1, not 6); body={body}"
    );
    assert_eq!(
        count, pending_len,
        "#958: count MUST equal pending.len() after filter; got count={count} len={pending_len}"
    );

    // Empty allowlist → bob also sees only his own rows, NOT
    // alice's. Re-validates the safe-by-default posture: an empty
    // `[admin].agent_ids` does NOT inadvertently admit anyone to
    // the operator queue-view; every caller is constrained to
    // their own pending rows.
    let (_status, body) = list_pending_as(&router, Some("bob")).await;
    assert_eq!(
        body["count"].as_u64(),
        Some(5),
        "#958: bob sees only his 5 rows; body={body}"
    );
    assert_eq!(
        body["owner_scope"].as_str(),
        Some("caller"),
        "#958: empty allowlist MUST still mark non-admin callers as caller-scope; body={body}"
    );
    // The total payload MUST NOT contain alice's id.
    let payload_str = serde_json::to_string(&body).unwrap();
    assert!(
        !payload_str.contains("p-alice-1"),
        "#958: bob's payload MUST NOT contain alice's pending id; body={body}"
    );
    assert!(
        !payload_str.contains("\"alice\""),
        "#958: bob's payload MUST NOT contain alice as a requested_by; body={body}"
    );

    // Critical: the JSON envelope MUST carry the same shape on the
    // empty-allowlist + non-admin path as on a populated-allowlist
    // path so wire-shape regressions surface here.
    assert!(
        body["pending"].is_array(),
        "#958: response MUST carry the `pending` array; body={body}"
    );
}

// ── Sanity test: pre-#958 wire-shape preservation ───────────────
//
// The handler now emits an additional `owner_scope` field on the
// success envelope, but the `count` + `pending` shape is preserved
// so existing operator dashboards / CLI consumers do not break.
// This test pins the legacy fields' presence + types.

#[tokio::test]
async fn legacy_response_shape_preserved_958() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    seed_pending(db_path, "p-alice-1", "alice", "ns-a");

    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);
    let (status, body) = list_pending_as(&router, Some("ops:admin")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("count").is_some_and(Value::is_number),
        "#958: response MUST preserve numeric `count` field; body={body}"
    );
    assert!(
        body.get("pending").is_some_and(Value::is_array),
        "#958: response MUST preserve `pending` array field; body={body}"
    );
    let row = &body["pending"][0];
    assert_eq!(
        row["id"].as_str(),
        Some("p-alice-1"),
        "#958: row MUST preserve `id` field; row={row}"
    );
    assert_eq!(
        row["requested_by"].as_str(),
        Some("alice"),
        "#958: row MUST preserve `requested_by` field; row={row}"
    );
    assert_eq!(
        row["namespace"].as_str(),
        Some("ns-a"),
        "#958: row MUST preserve `namespace` field; row={row}"
    );
    assert_eq!(
        row["status"].as_str(),
        Some("pending"),
        "#958: row MUST preserve `status` field; row={row}"
    );
}
