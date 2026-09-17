// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Issue #3426 (folding #3339 and the memory-route half of #3407) —
//! authorization refusals must not disclose the OWNING agent id, and the
//! sqlite and postgres branches must refuse a cross-owner memory mutation
//! with the SAME status.
//!
//! ## The defect
//!
//! Two independent disclosures, both reachable by any authenticated
//! caller who knows (or guesses) a row id:
//!
//! 1. **Body disclosure.** The sqlite HTTP owner gate
//!    (`handlers::parity::require_caller_owns_memory`, shared by
//!    `PUT /api/v1/memories/{id}`, `DELETE`, and `promote`) answered
//!    `403` with `{"error": ..., "owner": "<owning agent id>", ...}`.
//!    The same `"owner"` field was echoed by `GET /api/v1/kg/timeline`,
//!    `POST /api/v1/kg/invalidate`, and `POST /api/v1/links`, and
//!    `DELETE /api/v1/links` echoed BOTH endpoint owners as
//!    `source_owner` / `target_owner`. On the postgres side both SAL
//!    twins of `assert_caller_owns_for_mutation` interpolated the owner
//!    into `StoreError::PermissionDenied.reason`, which
//!    `handlers::postgres_gate::store_err_to_response` renders straight
//!    into the 403 body (its sanitizer redacts URLs and filesystem paths,
//!    never principals). Either way a refused caller learned WHO holds a
//!    row it is not entitled to — a cross-tenant identity oracle on the
//!    certified tier.
//!
//! 2. **Status divergence / existence oracle.** For a row the caller
//!    cannot READ (another agent's `private` row — the default, since a
//!    row with no `metadata.scope` key is private), sqlite answered
//!    `403` while `GET` answered `404`, so the write path confirmed the
//!    id EXISTS. The postgres handlers already masked these: they read
//!    through a visibility-scoped `store.get`, which yields
//!    `StoreError::NotFound` → `404`.
//!
//! ## The control
//!
//! One constructor, `handlers::parity::owner_gate_refusal`, builds every
//! cross-owner refusal on the HTTP surface. It takes no owner parameter,
//! so a refusal built through it is STRUCTURALLY incapable of naming the
//! owner — a future gate cannot reintroduce the leak by copying a
//! neighbouring `json!` literal. The body is the closed vocabulary
//! `{error, code: "NOT_OWNER", caller, <ids the caller supplied>}`. The
//! SAL twins refuse with the bare `errors::msg::CALLER_DOES_NOT_OWN_MEMORY`
//! const, identical on both backends, and `store_err_to_response` renders
//! that const through the SAME constructor. The owner is emitted only to
//! the server-side `ai_memory::authz` trace line, where operators keep
//! full attribution.
//!
//! For invisible rows the sqlite gate now returns
//! `handlers::parity::hidden_row_refusal` — `404 {"error": "not found"}`,
//! byte-identical to the read path and to what postgres already
//! returned. This CONVERGES sqlite onto the standing postgres contract
//! rather than inventing a third behaviour, and it is denial-preserving:
//! every mutation refused before is still refused, just less
//! informatively.
//!
//! ## What this pins — both directions, both backends
//!
//! DENIED (sqlite): update / delete / promote of an invisible cross-owner
//! row mask as `404` and name no owner; update of a VISIBLE
//! (`collective`) cross-owner row refuses `403` carrying the SSOT message,
//! the `NOT_OWNER` code and the caller's OWN id, and nothing else; link
//! create / delete and kg timeline / invalidate refusals name no owner.
//! DENIED (postgres): the pure HTTP rendering of the SAL refusal is
//! leak-free (no live instance needed), and on a live instance the SAL
//! refusal reason is the same bare SSOT const with no principal in it.
//! ALLOWED: the owner's own update / delete still succeeds on both
//! backends.
//! OPERATOR: the `ai_memory::authz` WARN line carries the owner the wire
//! dropped — pinned by the single-test sibling binary
//! `tests/authz_refusal_trace_3426.rs` (one test per binary, because the
//! `tracing` callsite-interest cache is process-global and a parallel
//! sibling with no subscriber can pin the shared callsite to `never`).

#![cfg(feature = "sal")]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// The owning agent whose identity must never appear in a refusal.
const OWNER: &str = "ai:alice-3426";
/// The refused caller.
const INTRUDER: &str = "ai:bob-3426";

fn seed_memory(
    db_path: &std::path::Path,
    owner: &str,
    namespace: &str,
    extra_meta: &Value,
) -> String {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    let now = chrono::Utc::now().to_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();
    let mut metadata = json!({"agent_id": owner});
    if let Some(extra) = extra_meta.as_object()
        && let Some(obj) = metadata.as_object_mut()
    {
        for (k, v) in extra {
            obj.insert(k.clone(), v.clone());
        }
    }
    let mem = Memory {
        id: id.clone(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("seed-{owner}-{}", &id[..8]),
        content: format!("body owned by {owner}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test-3426".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    };
    ai_memory::db::insert(&conn, &mem).expect("db::insert");
    id
}

fn build_router_fixture(db_path: &std::path::Path) -> axum::Router {
    let conn = ai_memory::db::open(db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
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
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, app_state)
}

/// Issue one request against the fixture router and return
/// `(status, body)`. `body` is `Value::Null` for an empty body.
async fn request_as(
    router: &axum::Router,
    method: &str,
    uri: &str,
    caller: &str,
    payload: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-agent-id", caller);
    let body = match payload {
        Some(p) => {
            builder = builder.header("content-type", "application/json");
            Body::from(p.to_string())
        }
        None => Body::empty(),
    };
    let resp = router
        .clone()
        .oneshot(builder.body(body).expect("build request"))
        .await
        .expect("router oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("read body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Render an axum response into `(status, body)` — for the pure
/// `store_err_to_response` rendering the postgres handler branches use.
async fn render(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("read body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The core #3426 invariant, asserted on EVERY refusal in this file:
/// no part of the wire body names the owning agent id, under any key.
fn assert_owner_absent(body: &Value, context: &str) {
    for key in ["owner", "source_owner", "target_owner"] {
        assert!(
            body.get(key).is_none(),
            "#3426 [{context}]: refusal must carry no `{key}` field; body={body}"
        );
    }
    assert!(
        !body.to_string().contains(OWNER),
        "#3426 [{context}]: refusal must not name the owning agent anywhere; body={body}"
    );
}

/// The closed-vocabulary `403` envelope every visible-but-unowned refusal
/// carries: SSOT message, `NOT_OWNER` code, the caller's OWN id.
fn assert_forbidden_envelope(body: &Value, error: &str, context: &str) {
    assert_eq!(
        body["error"].as_str(),
        Some(error),
        "#3426 [{context}]: the refusal carries the SSOT message; body={body}"
    );
    assert_eq!(
        body["code"].as_str(),
        Some(ai_memory::errors::error_codes::NOT_OWNER),
        "#3426 [{context}]: the refusal carries the closed-vocabulary code; body={body}"
    );
    assert_eq!(
        body["caller"].as_str(),
        Some(INTRUDER),
        "#3426 [{context}]: echoing the caller's OWN id discloses nothing; body={body}"
    );
    assert_owner_absent(body, context);
}

fn collective() -> Value {
    json!({"scope": ai_memory::models::MemoryScope::Collective.as_str()})
}

// ---------------------------------------------------------------------
// DENIED — invisible cross-owner row: masked as 404 (sqlite converges
// onto the postgres contract)
// ---------------------------------------------------------------------

#[tokio::test]
async fn put_invisible_cross_owner_row_masks_as_not_found_3426() {
    let tmp = NamedTempFile::new().expect("tempfile");
    // No `scope` key => private (the default posture), so the row is
    // invisible to INTRUDER: the write path must answer exactly what the
    // read path answers.
    let id = seed_memory(tmp.path(), OWNER, "leak-3426/private", &json!({}));
    let router = build_router_fixture(tmp.path());
    let (status, body) = request_as(
        &router,
        "PUT",
        &format!("/api/v1/memories/{id}"),
        INTRUDER,
        Some(json!({"content": "hijacked"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "#3426: an invisible cross-owner row must not be confirmed to exist; body={body}"
    );
    assert_owner_absent(&body, "PUT invisible");

    // Denial-preserving: the row is untouched.
    let conn = ai_memory::db::open(tmp.path()).expect("reopen");
    let after = ai_memory::db::get(&conn, &id).expect("get").expect("row");
    assert_ne!(
        after.content, "hijacked",
        "#3426: refused PUT must not have written"
    );
}

#[tokio::test]
async fn delete_invisible_cross_owner_row_masks_as_not_found_3426() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let id = seed_memory(tmp.path(), OWNER, "leak-3426/private-del", &json!({}));
    let router = build_router_fixture(tmp.path());
    let (status, body) = request_as(
        &router,
        "DELETE",
        &format!("/api/v1/memories/{id}"),
        INTRUDER,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "#3426: invisible cross-owner DELETE masks as not-found; body={body}"
    );
    assert_owner_absent(&body, "DELETE invisible");

    let conn = ai_memory::db::open(tmp.path()).expect("reopen");
    assert!(
        ai_memory::db::get(&conn, &id).expect("get").is_some(),
        "#3426: the refused DELETE must not have removed the row"
    );
}

#[tokio::test]
async fn promote_invisible_cross_owner_row_masks_as_not_found_3426() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let id = seed_memory(tmp.path(), OWNER, "leak-3426/private-promote", &json!({}));
    let router = build_router_fixture(tmp.path());
    let (status, body) = request_as(
        &router,
        "POST",
        &format!("/api/v1/memories/{id}/promote"),
        INTRUDER,
        Some(json!({})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "#3426: invisible cross-owner promote masks as not-found; body={body}"
    );
    assert_owner_absent(&body, "promote invisible");
}

// ---------------------------------------------------------------------
// DENIED — VISIBLE cross-owner row: 403 that names no owner
// ---------------------------------------------------------------------

#[tokio::test]
async fn put_visible_cross_owner_row_refuses_403_without_owner_3426() {
    let tmp = NamedTempFile::new().expect("tempfile");
    // `collective` is world-readable by design, so INTRUDER can already
    // GET this row: masking it as 404 would be a lie. The refusal stays
    // 403 — but it still must not be the channel that discloses the
    // owner.
    let id = seed_memory(tmp.path(), OWNER, "leak-3426/collective", &collective());
    let router = build_router_fixture(tmp.path());
    let (status, body) = request_as(
        &router,
        "PUT",
        &format!("/api/v1/memories/{id}"),
        INTRUDER,
        Some(json!({"content": "hijacked"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#3426: a readable but unowned row refuses 403, not 404; body={body}"
    );
    assert_forbidden_envelope(
        &body,
        ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY,
        "PUT visible",
    );
    assert_eq!(
        body["id"].as_str(),
        Some(id.as_str()),
        "#3426: echoing the id the caller supplied discloses nothing; body={body}"
    );

    let conn = ai_memory::db::open(tmp.path()).expect("reopen");
    let after = ai_memory::db::get(&conn, &id).expect("get").expect("row");
    assert_ne!(
        after.content, "hijacked",
        "#3426: refused PUT must not have written"
    );
}

#[tokio::test]
async fn delete_and_promote_visible_cross_owner_row_refuse_403_without_owner_3426() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let del = seed_memory(tmp.path(), OWNER, "leak-3426/collective-del", &collective());
    let pro = seed_memory(tmp.path(), OWNER, "leak-3426/collective-pro", &collective());
    let router = build_router_fixture(tmp.path());
    let (status, body) = request_as(
        &router,
        "DELETE",
        &format!("/api/v1/memories/{del}"),
        INTRUDER,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "DELETE visible; body={body}");
    assert_forbidden_envelope(
        &body,
        ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY,
        "DELETE visible",
    );
    let (status, body) = request_as(
        &router,
        "POST",
        &format!("/api/v1/memories/{pro}/promote"),
        INTRUDER,
        Some(json!({})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "promote visible; body={body}"
    );
    assert_forbidden_envelope(
        &body,
        ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY,
        "promote visible",
    );
}

// ---------------------------------------------------------------------
// DENIED — POST /api/v1/links + DELETE /api/v1/links owner gates
// ---------------------------------------------------------------------

#[tokio::test]
async fn links_create_cross_owner_refusal_names_no_owner_3426() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let source = seed_memory(tmp.path(), OWNER, "leak-3426/link-src", &collective());
    let target = seed_memory(tmp.path(), OWNER, "leak-3426/link-tgt", &collective());
    let router = build_router_fixture(tmp.path());
    let (status, body) = request_as(
        &router,
        "POST",
        "/api/v1/links",
        INTRUDER,
        Some(json!({
            "source_id": source,
            "target_id": target,
            "relation": "related_to",
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#3426: bob may not link from alice's source row; body={body}"
    );
    assert_forbidden_envelope(
        &body,
        ai_memory::errors::msg::CALLER_NOT_SOURCE_MEMORY_OWNER,
        "POST /links",
    );
    assert_eq!(body["source_id"].as_str(), Some(source.as_str()));
}

#[tokio::test]
async fn links_delete_cross_owner_refusal_names_neither_endpoint_owner_3426() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let source = seed_memory(tmp.path(), OWNER, "leak-3426/unlink-src", &collective());
    let target = seed_memory(tmp.path(), OWNER, "leak-3426/unlink-tgt", &collective());
    let router = build_router_fixture(tmp.path());
    let (created, body) = request_as(
        &router,
        "POST",
        "/api/v1/links",
        OWNER,
        Some(json!({
            "source_id": source,
            "target_id": target,
            "relation": "related_to",
        })),
    )
    .await;
    assert_eq!(
        created,
        StatusCode::CREATED,
        "setup: owner links; body={body}"
    );
    let (status, body) = request_as(
        &router,
        "DELETE",
        "/api/v1/links",
        INTRUDER,
        Some(json!({
            "source_id": source,
            "target_id": target,
            "relation": "related_to",
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#3426: bob owns neither endpoint; body={body}"
    );
    assert_forbidden_envelope(
        &body,
        ai_memory::errors::msg::CALLER_NOT_LINK_ENDPOINT_OWNER,
        "DELETE /links",
    );
    assert_eq!(body["source_id"].as_str(), Some(source.as_str()));
    assert_eq!(body["target_id"].as_str(), Some(target.as_str()));
}

// ---------------------------------------------------------------------
// DENIED — kg timeline / invalidate owner gates
// ---------------------------------------------------------------------

#[tokio::test]
async fn kg_timeline_and_invalidate_refusals_name_no_owner_3426() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let source = seed_memory(tmp.path(), OWNER, "leak-3426/kg-src", &collective());
    let target = seed_memory(tmp.path(), OWNER, "leak-3426/kg-tgt", &collective());
    let router = build_router_fixture(tmp.path());
    let (status, body) = request_as(
        &router,
        "GET",
        &format!("/api/v1/kg/timeline?source_id={source}"),
        INTRUDER,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "kg/timeline; body={body}");
    assert_forbidden_envelope(
        &body,
        ai_memory::errors::msg::CALLER_NOT_SOURCE_MEMORY_OWNER,
        "GET /kg/timeline",
    );
    let (status, body) = request_as(
        &router,
        "POST",
        "/api/v1/kg/invalidate",
        INTRUDER,
        Some(json!({
            "source_id": source,
            "target_id": target,
            "relation": "related_to",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "kg/invalidate; body={body}");
    assert_forbidden_envelope(
        &body,
        ai_memory::errors::msg::CALLER_NOT_SOURCE_MEMORY_OWNER,
        "POST /kg/invalidate",
    );
}

// ---------------------------------------------------------------------
// DENIED — the postgres handler branches render a SAL refusal through
// `store_err_to_response`; that rendering is pure and pinned here with no
// live instance, so the postgres wire shape is asserted on every CI run.
// ---------------------------------------------------------------------

#[tokio::test]
async fn store_err_rendering_of_owner_gate_refusal_is_leak_free_3426() {
    use ai_memory::store::StoreError;
    let (status, body) = render(ai_memory::handlers::store_err_to_response(
        StoreError::PermissionDenied {
            action: "update".to_string(),
            target: "row-3426".to_string(),
            reason: ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY.to_string(),
        },
    ))
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(
        body["error"].as_str(),
        Some(ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY),
        "#3426: byte-identical `error` on both backends; body={body}"
    );
    assert_eq!(
        body["code"].as_str(),
        Some(ai_memory::errors::error_codes::NOT_OWNER),
        "body={body}"
    );
    assert_eq!(body["id"].as_str(), Some("row-3426"), "body={body}");
    assert!(
        !body.to_string().contains("lacks permission"),
        "#3426: the generic Display arm must not render this refusal; body={body}"
    );
    assert_owner_absent(&body, "store_err_to_response memory");

    let (status, body) = render(ai_memory::handlers::store_err_to_response(
        StoreError::PermissionDenied {
            action: "memory_link".to_string(),
            target: "src-3426".to_string(),
            reason: ai_memory::errors::msg::CALLER_NOT_SOURCE_MEMORY_OWNER.to_string(),
        },
    ))
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(
        body["error"].as_str(),
        Some(ai_memory::errors::msg::CALLER_NOT_SOURCE_MEMORY_OWNER),
        "body={body}"
    );
    assert_eq!(body["source_id"].as_str(), Some("src-3426"), "body={body}");
    assert_owner_absent(&body, "store_err_to_response link");
}

// ---------------------------------------------------------------------
// DENIED — the sqlite SAL twin refuses with the bare SSOT reason
// ---------------------------------------------------------------------

#[tokio::test]
async fn sqlite_sal_cross_owner_update_refusal_names_no_owner_3426() {
    use ai_memory::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};
    let tmp = NamedTempFile::new().expect("tempfile");
    let id = seed_memory(tmp.path(), OWNER, "leak-3426/sal-sqlite", &collective());
    let store = ai_memory::store::sqlite::SqliteStore::open(tmp.path()).expect("open");
    let err = store
        .update(
            &CallerContext::for_agent(INTRUDER),
            &id,
            UpdatePatch {
                content: Some("hijacked".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect_err("#3426: a cross-owner update must be refused");
    match err {
        StoreError::PermissionDenied { reason, .. } => {
            assert_eq!(
                reason,
                ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY,
                "#3426: sqlite refuses with the bare SSOT reason"
            );
            assert!(!reason.contains(OWNER), "reason must not name the owner");
        }
        other => panic!("#3426: expected PermissionDenied, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// ALLOWED — the owner's own mutation still succeeds
// ---------------------------------------------------------------------

#[tokio::test]
async fn owner_can_still_update_own_row_3426() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let id = seed_memory(tmp.path(), OWNER, "leak-3426/own", &json!({}));
    let router = build_router_fixture(tmp.path());
    let (status, body) = request_as(
        &router,
        "PUT",
        &format!("/api/v1/memories/{id}"),
        OWNER,
        Some(json!({"content": "owner rewrite"})),
    )
    .await;
    assert!(
        status.is_success(),
        "#3426 ALLOWED: the owner's own update must still succeed; status={status} body={body}"
    );
    let conn = ai_memory::db::open(tmp.path()).expect("reopen");
    let after = ai_memory::db::get(&conn, &id).expect("get").expect("row");
    assert_eq!(
        after.content, "owner rewrite",
        "#3426 ALLOWED: the owner's write must have landed"
    );
}

#[tokio::test]
async fn owner_can_still_delete_and_promote_own_rows_3426() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let del = seed_memory(tmp.path(), OWNER, "leak-3426/own-del", &json!({}));
    let pro = seed_memory(tmp.path(), OWNER, "leak-3426/own-pro", &json!({}));
    let router = build_router_fixture(tmp.path());
    let (status, body) = request_as(
        &router,
        "DELETE",
        &format!("/api/v1/memories/{del}"),
        OWNER,
        None,
    )
    .await;
    assert!(
        status.is_success(),
        "#3426 ALLOWED: the owner's own delete must still succeed; status={status} body={body}"
    );
    let (status, body) = request_as(
        &router,
        "POST",
        &format!("/api/v1/memories/{pro}/promote"),
        OWNER,
        Some(json!({})),
    )
    .await;
    assert!(
        status.is_success(),
        "#3426 ALLOWED: the owner's own promote must still succeed; status={status} body={body}"
    );
}

// ---------------------------------------------------------------------
// DENIED / ALLOWED — postgres SAL twin (live instance)
// ---------------------------------------------------------------------

/// #3426 — the postgres half of the control. `PostgresStore` and
/// `SqliteStore` both refuse a cross-owner mutation with the SAME bare
/// SSOT reason, so the 403 body `store_err_to_response` renders from it
/// carries no principal on either backend.
///
/// Skips with a stderr WARN when `AI_MEMORY_TEST_POSTGRES_URL` is unset,
/// matching the `postgres_owner_gate_1412` convention.
#[cfg(feature = "sal-postgres")]
mod postgres_arm_3426 {
    use super::{INTRUDER, OWNER, assert_owner_absent, render};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};
    use axum::http::StatusCode;

    async fn maybe_open() -> Option<PostgresStore> {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!(
                "test skipped: AI_MEMORY_TEST_POSTGRES_URL not set — \
                 the #3426 postgres refusal-parity pin requires a live instance"
            );
            return None;
        };
        match PostgresStore::connect(&url).await {
            Ok(store) => Some(store),
            Err(e) => {
                eprintln!("test skipped: PostgresStore::connect failed: {e}");
                None
            }
        }
    }

    fn seed(owner: &str, namespace: &str) -> ai_memory::models::Memory {
        let now = chrono::Utc::now().to_rfc3339();
        ai_memory::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: namespace.to_string(),
            title: "3426-refusal-parity".to_string(),
            content: "body".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({
                "agent_id": owner,
                "scope": ai_memory::models::MemoryScope::Collective.as_str(),
            }),
            version: 1,
            ..ai_memory::models::Memory::default()
        }
    }

    #[tokio::test]
    async fn pg_cross_owner_update_refusal_names_no_owner_3426() {
        let Some(store) = maybe_open().await else {
            return;
        };
        let ns = format!("leak-3426-pg/update-{}", uuid::Uuid::new_v4());
        let mem = seed(OWNER, &ns);
        let id = store
            .store(&CallerContext::for_agent(OWNER), &mem)
            .await
            .expect("seed insert");

        let err = store
            .update(
                &CallerContext::for_agent(INTRUDER),
                &id,
                UpdatePatch {
                    content: Some("hijacked".to_string()),
                    ..Default::default()
                },
            )
            .await
            .expect_err("#3426: a cross-owner update must be refused");
        let StoreError::PermissionDenied { ref reason, .. } = err else {
            panic!("#3426: expected PermissionDenied, got {err:?}");
        };
        assert_eq!(
            reason,
            ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY,
            "#3426: postgres refuses with the SAME bare SSOT reason as sqlite"
        );
        assert!(
            !reason.contains(OWNER),
            "#3426: the refusal reason must not name the owner; got {reason:?}"
        );
        // The wire shape the postgres handler branch renders from it.
        let (status, body) = render(ai_memory::handlers::store_err_to_response(err)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
        assert_eq!(
            body["code"].as_str(),
            Some(ai_memory::errors::error_codes::NOT_OWNER),
            "body={body}"
        );
        assert_owner_absent(&body, "pg update");
    }

    #[tokio::test]
    async fn pg_cross_owner_delete_refusal_names_no_owner_3426() {
        let Some(store) = maybe_open().await else {
            return;
        };
        let ns = format!("leak-3426-pg/delete-{}", uuid::Uuid::new_v4());
        let mem = seed(OWNER, &ns);
        let id = store
            .store(&CallerContext::for_agent(OWNER), &mem)
            .await
            .expect("seed insert");
        let err = store
            .delete(&CallerContext::for_agent(INTRUDER), &id)
            .await
            .expect_err("#3426: a cross-owner delete must be refused");
        let StoreError::PermissionDenied { reason, .. } = err else {
            panic!("#3426: expected PermissionDenied, got {err:?}");
        };
        assert_eq!(reason, ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY);
        assert!(!reason.contains(OWNER), "got {reason:?}");
        // Denial-preserving: the owner can still read the row.
        store
            .get(&CallerContext::for_agent(OWNER), &id)
            .await
            .expect("#3426: the refused DELETE must not have removed the row");
    }

    #[tokio::test]
    async fn pg_owner_can_still_update_own_row_3426() {
        let Some(store) = maybe_open().await else {
            return;
        };
        let ctx = CallerContext::for_agent(OWNER);
        let ns = format!("leak-3426-pg/allowed-{}", uuid::Uuid::new_v4());
        let mem = seed(OWNER, &ns);
        let id = store.store(&ctx, &mem).await.expect("seed insert");
        store
            .update(
                &ctx,
                &id,
                UpdatePatch {
                    content: Some("owner rewrite".to_string()),
                    ..Default::default()
                },
            )
            .await
            .expect("#3426 ALLOWED: the owner's own update must still succeed");
        let after = store.get(&ctx, &id).await.expect("owner reads own row");
        assert_eq!(after.content, "owner rewrite");
    }
}
