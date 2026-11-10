// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3226 — HTTP `POST /api/v1/actions/{id}/transition` must bind
//! `claimed_by` to the live lease holder (MCP #3009) and reject an
//! unknown `signal_type` (MCP A6-13). Pre-fix HTTP took `claimed_by`
//! verbatim and coerced unknown signal types to `notify`.
//!
//! #3360 extends the same family: the holder bind used to be OPT-IN on every
//! transition funnel (it ran only inside `if let Some(cb)`), so OMITTING
//! `claimed_by` bypassed it entirely and wrote SQL `NULL` over the recorded
//! owner. Both HTTP local-write lanes — sqlite (`local_transition_via_db`) and postgres
//! (`local_transition_via_store`) — now read the lease unconditionally and
//! defer to the one shared `actions::authorize_claimed_by` control, so the two
//! backends cannot drift on ownership.

#![cfg(feature = "sal")]
#![allow(
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::expect_used,
    clippy::similar_names
)]

use std::path::Path;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::Action;
use ai_memory::store::MemoryStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tempfile::NamedTempFile;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

fn build_sqlite_router(db_path: &Path) -> axum::Router {
    let conn = ai_memory::db::open(db_path).expect("reopen");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("SqliteStore"));
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
        storage_backend: StorageBackend::Sqlite,
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

fn seed_action_with_lease(db_path: &Path, id: &str, holder: &str) {
    let conn = ai_memory::db::open(db_path).expect("seed open");
    let now = chrono::Utc::now().timestamp();
    let action = Action {
        id: id.to_string(),
        namespace: "cov-3226".to_string(),
        kind: "test".to_string(),
        state: ai_memory::models::ActionState::Pending,
        title: "tx".to_string(),
        payload: json!({}),
        priority: 5,
        agent_id: Some("ai:cov".to_string()),
        claimed_by: None,
        vector_clock: json!({}),
        metadata: json!({}),
        created_at: now,
        updated_at: now,
    };
    ai_memory::actions::create(&conn, &action).expect("create action");
    match ai_memory::actions::lease_acquire(&conn, id, holder, now, now + 120)
        .expect("lease_acquire")
    {
        ai_memory::actions::LeaseAcquire::Acquired(_) => {}
        ai_memory::actions::LeaseAcquire::Conflict => panic!("fresh lease must acquire"),
    }
}

/// The `X-Agent-Id` the pre-#8759 cells send when the acting identity is not
/// what they exercise.
const DEFAULT_CALLER: &str = "ai:tester";

async fn post_json(router: axum::Router, uri: &str, body: serde_json::Value) -> StatusCode {
    post_json_as(router, uri, Some(DEFAULT_CALLER), body)
        .await
        .0
}

/// POST `body` as `agent` (`X-Agent-Id`; `None` sends no header, the
/// anonymous posture). Returns the status and the parsed JSON body
/// (`Value::Null` for an empty or non-JSON body).
async fn post_json_as(
    router: axum::Router,
    uri: &str,
    agent: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(agent) = agent {
        req = req.header("x-agent-id", agent);
    }
    let req = req
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    let resp = router.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// HTTP transition with `claimed_by` that is not the live lease holder is 403.
#[tokio::test]
async fn http_transition_claimed_by_not_holder() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("init schema");
    seed_action_with_lease(&db_path, "act-3226", "ai:w1");

    let router = build_sqlite_router(&db_path);
    let status = post_json(
        router,
        "/api/v1/actions/act-3226/transition",
        json!({"to": "claimed", "claimed_by": "ai:w2"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#3226: non-holder claimed_by must be 403"
    );

    // Holder succeeds; control-char claimed_by is 400.
    // #8759 — the holder transitions AS ITSELF (the acting identity is the
    // authenticated `X-Agent-Id`, never the body field).
    let router = build_sqlite_router(&db_path);
    let (ok, _) = post_json_as(
        router,
        "/api/v1/actions/act-3226/transition",
        Some("ai:w1"),
        json!({"to": "claimed", "claimed_by": "ai:w1"}),
    )
    .await;
    assert_eq!(ok, StatusCode::OK, "#3226: lease holder must transition");

    let router = build_sqlite_router(&db_path);
    let bad = post_json(
        router,
        "/api/v1/actions/act-3226/transition",
        json!({"to": "in_progress", "claimed_by": "bad\nid"}),
    )
    .await;
    assert_eq!(
        bad,
        StatusCode::BAD_REQUEST,
        "#3226: control-char claimed_by must be 400"
    );
}

/// #3360 (SECURITY) — an HTTP transition that OMITS `claimed_by` on an action
/// carrying a LIVE lease must be 403, and must leave `actions.claimed_by`
/// intact. Pre-fix it was 200 with `claimed_by: null`.
#[tokio::test]
async fn http_transition_without_claimed_by_on_leased_action_is_refused_3360() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("init schema");
    seed_action_with_lease(&db_path, "act-3360", "ai:alice");

    // The holder claims its own action first, so there IS a recorded owner to
    // erase.
    let router = build_sqlite_router(&db_path);
    let (ok, _) = post_json_as(
        router,
        "/api/v1/actions/act-3360/transition",
        Some("ai:alice"),
        json!({"to": "claimed", "claimed_by": "ai:alice"}),
    )
    .await;
    assert_eq!(ok, StatusCode::OK, "#3360: the holder must transition");

    // DENIED: a second agent simply omits `claimed_by`.
    let router = build_sqlite_router(&db_path);
    let status = post_json(
        router,
        "/api/v1/actions/act-3360/transition",
        json!({"to": "in_progress"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#3360: an unbound transition on a leased action must be 403"
    );

    // The refusal is inert: state AND the recorded owner survive.
    let conn = ai_memory::db::open(&db_path).expect("reopen");
    let after = ai_memory::actions::get(&conn, "act-3360")
        .expect("action_get")
        .expect("action present");
    assert_eq!(after.state, ai_memory::models::ActionState::Claimed);
    assert_eq!(
        after.claimed_by.as_deref(),
        Some("ai:alice"),
        "#3360: the refused transition must not NULL the recorded owner"
    );
    drop(conn);

    // ALLOWED: released lease -> the lease-free flow is unchanged.
    let conn = ai_memory::db::open(&db_path).expect("reopen");
    assert!(
        ai_memory::actions::lease_release(&conn, "act-3360", "ai:alice").expect("release"),
        "the seeded lease must exist"
    );
    drop(conn);
    let router = build_sqlite_router(&db_path);
    let unbound = post_json(
        router,
        "/api/v1/actions/act-3360/transition",
        json!({"to": "in_progress"}),
    )
    .await;
    assert_eq!(
        unbound,
        StatusCode::OK,
        "#3360: a lease-free transition must stay unbound"
    );
}

/// HTTP `POST /signals` rejects an unknown `signal_type` (MCP A6-13 parity).
#[tokio::test]
async fn http_send_signal_rejects_unknown_signal_type() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("init schema");
    let router = build_sqlite_router(&db_path);
    let status = post_json(
        router,
        "/api/v1/signals",
        json!({
            "namespace": "cov-3226",
            "subject": "s",
            "signal_type": "bogus"
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#3226: unknown signal_type must be 400, not coerced to notify"
    );
}

// ---------------------------------------------------------------------------
// #8759 (SECURITY) — the acting identity of a transition is the authenticated
// caller (`X-Agent-Id`, or the synthesized `anonymous:req-*` when absent),
// never the body's `claimed_by`. A `claimed_by` that differs from the caller
// is refused with the named `acting_identity_mismatch` error, on BOTH local
// write lanes (sqlite `local_transition_via_db`, postgres
// `local_transition_via_store`), with and without a live lease, and the
// stored action is left untouched.
// ---------------------------------------------------------------------------

const ALICE_8759: &str = "ai:alice-act";
const BOB_8759: &str = "ai:bob-act";
const MALFORMED_HEADER_8759: &str = "bad id with spaces";
const LEASE_TTL_SECS_8759: i64 = 120;

fn mismatch_8759(caller: &str, claimed: &str) -> String {
    format!(
        "acting_identity_mismatch: caller '{caller}' may only transition an action as itself \
         (claimed_by '{claimed}')"
    )
}

fn error_of(body: &serde_json::Value) -> &str {
    body["error"].as_str().unwrap_or_default()
}

async fn stored_8759(
    store: &Arc<dyn MemoryStore>,
    ctx: &ai_memory::store::CallerContext,
    id: &str,
) -> (ai_memory::models::ActionState, Option<String>) {
    let a = store
        .action_get(ctx, id)
        .await
        .expect("action_get")
        .expect("action present");
    (a.state, a.claimed_by)
}

/// Seed one action in `pending` with ALICE holding a live lease.
async fn seed_8759(store: &Arc<dyn MemoryStore>, ctx: &ai_memory::store::CallerContext) -> String {
    let now = chrono::Utc::now().timestamp();
    let id = format!("act-8759-{}", uuid::Uuid::new_v4());
    let action = Action {
        id: id.clone(),
        namespace: "audit-8759".to_string(),
        kind: "test".to_string(),
        state: ai_memory::models::ActionState::Pending,
        title: "tx".to_string(),
        payload: json!({}),
        priority: 5,
        agent_id: Some(ALICE_8759.to_string()),
        claimed_by: None,
        vector_clock: json!({}),
        metadata: json!({}),
        created_at: now,
        updated_at: now,
    };
    store
        .action_create(ctx, &action)
        .await
        .expect("action_create");
    store
        .lease_acquire(ctx, &id, ALICE_8759, now, now + LEASE_TTL_SECS_8759)
        .await
        .expect("lease_acquire");
    id
}

/// One #8759 table row: (label, `X-Agent-Id`, body `claimed_by`, expected status,
/// expected exact error body when one is pinned).
type Row8759<'a> = (
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    StatusCode,
    Option<String>,
);

/// The shared #8759 table, identical for both backends.
async fn run_8759_table(router: axum::Router, store: Arc<dyn MemoryStore>) {
    use ai_memory::models::ActionState::{Claimed, Done, InProgress};
    let ctx = ai_memory::store::CallerContext::for_agent(ALICE_8759.to_string());
    let id = seed_8759(&store, &ctx).await;
    let uri = format!("/api/v1/actions/{id}/transition");

    // A claims as itself.
    let (st, body) = post_json_as(
        router.clone(),
        &uri,
        Some(ALICE_8759),
        json!({"to": "claimed", "claimed_by": ALICE_8759}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "A claims as itself: {body}");
    let claimed = (Claimed, Some(ALICE_8759.to_string()));
    assert_eq!(stored_8759(&store, &ctx, &id).await, claimed);

    // (header, claimed_by, expected status, expected error) while A's lease
    // is LIVE. Every row is refused and leaves the action unchanged.
    let lease_absent = format!(
        "action {id} is held by lease holder '{ALICE_8759}': a transition on a leased action \
         must supply claimed_by matching the holder"
    );
    let not_holder = format!(
        "claimed_by '{BOB_8759}' is not the live lease holder '{ALICE_8759}' on action {id}"
    );
    let rows: [Row8759<'_>; 5] = [
        (
            "different (B names the holder A)",
            Some(BOB_8759),
            Some(ALICE_8759),
            StatusCode::FORBIDDEN,
            Some(mismatch_8759(BOB_8759, ALICE_8759)),
        ),
        (
            "equal (B as itself, not the holder)",
            Some(BOB_8759),
            Some(BOB_8759),
            StatusCode::FORBIDDEN,
            Some(not_holder),
        ),
        (
            "absent",
            Some(BOB_8759),
            None,
            StatusCode::FORBIDDEN,
            Some(lease_absent),
        ),
        (
            "malformed claimed_by",
            Some(BOB_8759),
            Some("bad\nid"),
            StatusCode::BAD_REQUEST,
            None,
        ),
        (
            "malformed caller header",
            Some(MALFORMED_HEADER_8759),
            Some(ALICE_8759),
            StatusCode::BAD_REQUEST,
            None,
        ),
    ];
    for to in ["in_progress", "done"] {
        for (label, header, claimed_by, want_status, want_err) in &rows {
            let mut req = json!({ "to": to });
            if let Some(cb) = claimed_by {
                req["claimed_by"] = json!(cb);
            }
            let (st, body) = post_json_as(router.clone(), &uri, *header, req).await;
            assert_eq!(st, *want_status, "row `{label}` to {to}: {body}");
            if let Some(want) = want_err {
                assert_eq!(error_of(&body), want, "row `{label}` to {to}");
            }
            assert_eq!(
                stored_8759(&store, &ctx, &id).await,
                claimed,
                "row `{label}` to {to}: the refusal must leave the action unchanged"
            );
        }

        // No header: the caller is a synthesized `anonymous:req-*`, which is
        // not A — refused with the same named error.
        let (st, body) = post_json_as(
            router.clone(),
            &uri,
            None,
            json!({"to": to, "claimed_by": ALICE_8759}),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN, "anonymous to {to}: {body}");
        let err = error_of(&body);
        assert!(
            err.starts_with("acting_identity_mismatch: caller 'anonymous:req-")
                && err.ends_with(&format!(
                    "' may only transition an action as itself (claimed_by '{ALICE_8759}')"
                )),
            "anonymous to {to}: got {err}"
        );
        assert_eq!(stored_8759(&store, &ctx, &id).await, claimed);
    }

    // CONTROL: A (the holder) transitions as itself.
    let (st, body) = post_json_as(
        router.clone(),
        &uri,
        Some(ALICE_8759),
        json!({"to": "in_progress", "claimed_by": ALICE_8759}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "A in_progress: {body}");
    let in_progress = (InProgress, Some(ALICE_8759.to_string()));
    assert_eq!(stored_8759(&store, &ctx, &id).await, in_progress);

    // NO LEASE: the bind is the principal, not the lease. Pre-fix B could
    // stamp A's name on any lease-free action.
    assert!(
        store
            .lease_release(&ctx, &id, ALICE_8759)
            .await
            .expect("lease_release"),
        "the seeded lease must exist"
    );
    let (st, body) = post_json_as(
        router.clone(),
        &uri,
        Some(BOB_8759),
        json!({"to": "done", "claimed_by": ALICE_8759}),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "B as A, no lease: {body}");
    assert_eq!(error_of(&body), mismatch_8759(BOB_8759, ALICE_8759));
    assert_eq!(stored_8759(&store, &ctx, &id).await, in_progress);

    // equal, no lease: accepted, recorded claimant is the caller.
    let (st, body) = post_json_as(
        router,
        &uri,
        Some(BOB_8759),
        json!({"to": "done", "claimed_by": BOB_8759}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "B as itself, no lease: {body}");
    assert_eq!(
        stored_8759(&store, &ctx, &id).await,
        (Done, Some(BOB_8759.to_string()))
    );
}

/// #8759 sqlite cell (`local_transition_via_db`), including the audit's
/// exact replay (B drives A's leased action naming A).
#[tokio::test]
async fn http_transition_acting_identity_table_sqlite_8759() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("init schema");
    let router = build_sqlite_router(&db_path);
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
    run_8759_table(router, store).await;
}

/// #8773 — seed one PENDING `approval` checkpoint created by ALICE.
async fn seed_checkpoint_8773(
    store: &Arc<dyn MemoryStore>,
    ctx: &ai_memory::store::CallerContext,
) -> String {
    let now = chrono::Utc::now().timestamp();
    let cp = ai_memory::models::Checkpoint {
        id: format!("cp-8773-{}", uuid::Uuid::new_v4()),
        namespace: "audit-8773".to_string(),
        title: "approve deploy".to_string(),
        condition_type: ai_memory::models::ConditionType::Approval,
        condition: json!({}),
        state: ai_memory::models::CheckpointState::Pending,
        created_by: ALICE_8759.to_string(),
        resolved_by: None,
        resolution: None,
        resolution_note: None,
        signature: Vec::new(),
        resolver_pubkey: Vec::new(),
        created_at: now,
        deadline_at: None,
        resolved_at: None,
        metadata: json!({}),
    };
    store
        .checkpoint_create(ctx, &cp)
        .await
        .expect("checkpoint_create")
}

async fn stored_checkpoint_8773(
    store: &Arc<dyn MemoryStore>,
    ctx: &ai_memory::store::CallerContext,
    id: &str,
) -> (ai_memory::models::CheckpointState, Option<String>) {
    let cp = store
        .checkpoint_get(ctx, id)
        .await
        .expect("checkpoint_get")
        .expect("checkpoint present");
    (cp.state, cp.resolved_by)
}

/// #8773 HTTP rows, identical for both backends: a body `resolved_by` is only
/// ever COMPARED to the `X-Agent-Id` principal. Different / malformed /
/// anonymous are refused and leave the checkpoint pending; equal and absent
/// resolve as the principal.
async fn run_8773_checkpoint_table(router: axum::Router, store: Arc<dyn MemoryStore>) {
    use ai_memory::models::CheckpointState::{Pending, Rejected, Resolved};
    let ctx = ai_memory::store::CallerContext::for_agent(ALICE_8759.to_string());
    let id = seed_checkpoint_8773(&store, &ctx).await;
    let uri = format!("/api/v1/checkpoints/{id}/resolve");
    let pending = (Pending, None);
    let cp_mismatch = |caller: &str| {
        format!(
            "acting_identity_mismatch: caller '{caller}' may only resolve a checkpoint as itself \
             (resolved_by '{ALICE_8759}')"
        )
    };

    // The audit's exact replay: B resolves A's approval checkpoint naming A.
    let (st, body) = post_json_as(
        router.clone(),
        &uri,
        Some(BOB_8759),
        json!({"state": "resolved", "resolved_by": ALICE_8759}),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "B as A: {body}");
    assert_eq!(error_of(&body), cp_mismatch(BOB_8759));
    assert_eq!(stored_checkpoint_8773(&store, &ctx, &id).await, pending);

    let (st, body) = post_json_as(
        router.clone(),
        &uri,
        Some(BOB_8759),
        json!({"state": "resolved", "resolved_by": "bad\nid"}),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "malformed resolved_by: {body}");
    assert_eq!(stored_checkpoint_8773(&store, &ctx, &id).await, pending);

    let (st, body) = post_json_as(
        router.clone(),
        &uri,
        None,
        json!({"state": "resolved", "resolved_by": ALICE_8759}),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "anonymous as A: {body}");
    let err = error_of(&body);
    assert!(
        err.starts_with("acting_identity_mismatch: caller 'anonymous:req-")
            && err.ends_with(&format!(
                "' may only resolve a checkpoint as itself (resolved_by '{ALICE_8759}')"
            )),
        "anonymous: got {err}"
    );
    assert_eq!(stored_checkpoint_8773(&store, &ctx, &id).await, pending);

    // equal: resolves, recorded as the principal.
    let (st, body) = post_json_as(
        router.clone(),
        &uri,
        Some(ALICE_8759),
        json!({"state": "resolved", "resolved_by": ALICE_8759}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "A as itself: {body}");
    assert_eq!(
        stored_checkpoint_8773(&store, &ctx, &id).await,
        (Resolved, Some(ALICE_8759.to_string()))
    );

    // absent: the pre-existing node-bound posture, recorded as the principal.
    let id2 = seed_checkpoint_8773(&store, &ctx).await;
    let (st, body) = post_json_as(
        router,
        &format!("/api/v1/checkpoints/{id2}/resolve"),
        Some(BOB_8759),
        json!({"state": "rejected"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "absent resolved_by: {body}");
    assert_eq!(
        stored_checkpoint_8773(&store, &ctx, &id2).await,
        (Rejected, Some(BOB_8759.to_string()))
    );
}

/// #8773 sqlite cell, including the audit's exact HTTP replay.
#[tokio::test]
async fn http_checkpoint_resolve_acting_identity_table_sqlite_8773() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("init schema");
    let router = build_sqlite_router(&db_path);
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
    run_8773_checkpoint_table(router, store).await;
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::store::CallerContext;
    use ai_memory::store::postgres::PostgresStore;

    fn postgres_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
    }

    async fn build_pg_router(url: &str) -> (axum::Router, Arc<dyn MemoryStore>) {
        ai_memory::handlers::admin_role::mark_request_authn_configured(true);
        let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
        let db: Db = Arc::new(Mutex::new((
            conn,
            std::path::PathBuf::from(":memory:"),
            ResolvedTtl::default(),
            true,
        )));
        let pg = PostgresStore::connect(url).await.expect("connect postgres");
        let store: Arc<dyn MemoryStore> = Arc::new(pg);
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
            store: Arc::clone(&store),
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
        (ai_memory::build_router(api_key_state, app_state), store)
    }

    /// Live-postgres twin of `http_transition_claimed_by_not_holder`.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
    async fn http_transition_claimed_by_not_holder() {
        let Some(url) = postgres_url() else {
            panic!("AI_MEMORY_TEST_POSTGRES_URL unset — cannot run live-pg #3226 pin");
        };
        let (router, store) = build_pg_router(&url).await;
        let ctx = CallerContext::for_agent("ai:cov".to_string());
        let now = chrono::Utc::now().timestamp();
        let id = format!("act-3226-{}", uuid::Uuid::new_v4());
        let action = Action {
            id: id.clone(),
            namespace: "cov-3226-pg".to_string(),
            kind: "test".to_string(),
            state: ai_memory::models::ActionState::Pending,
            title: "tx".to_string(),
            payload: json!({}),
            priority: 5,
            agent_id: Some("ai:cov".to_string()),
            claimed_by: None,
            vector_clock: json!({}),
            metadata: json!({}),
            created_at: now,
            updated_at: now,
        };
        store
            .action_create(&ctx, &action)
            .await
            .expect("action_create");
        store
            .lease_acquire(&ctx, &id, "ai:w1", now, now + 120)
            .await
            .expect("lease_acquire");

        let status = post_json(
            router,
            &format!("/api/v1/actions/{id}/transition"),
            json!({"to": "claimed", "claimed_by": "ai:w2"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "#3226 pg: non-holder claimed_by must be 403"
        );
    }

    /// #3360 live-postgres twin: an OMITTED `claimed_by` on a leased action is
    /// 403 on the SAL lane too, and the recorded owner survives.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
    async fn http_transition_without_claimed_by_on_leased_action_is_refused_3360() {
        let Some(url) = postgres_url() else {
            panic!("AI_MEMORY_TEST_POSTGRES_URL unset — cannot run live-pg #3360 pin");
        };
        let (router, store) = build_pg_router(&url).await;
        let ctx = CallerContext::for_agent("ai:cov".to_string());
        let now = chrono::Utc::now().timestamp();
        let id = format!("act-3360-{}", uuid::Uuid::new_v4());
        let action = Action {
            id: id.clone(),
            namespace: "cov-3360-pg".to_string(),
            kind: "test".to_string(),
            state: ai_memory::models::ActionState::Pending,
            title: "tx".to_string(),
            payload: json!({}),
            priority: 5,
            agent_id: Some("ai:cov".to_string()),
            claimed_by: None,
            vector_clock: json!({}),
            metadata: json!({}),
            created_at: now,
            updated_at: now,
        };
        store
            .action_create(&ctx, &action)
            .await
            .expect("action_create");
        store
            .lease_acquire(&ctx, &id, "ai:alice", now, now + 120)
            .await
            .expect("lease_acquire");

        // The holder claims its own action first (as itself, #8759).
        let (ok, _) = post_json_as(
            router,
            &format!("/api/v1/actions/{id}/transition"),
            Some("ai:alice"),
            json!({"to": "claimed", "claimed_by": "ai:alice"}),
        )
        .await;
        assert_eq!(ok, StatusCode::OK, "#3360 pg: the holder must transition");

        // DENIED: omit `claimed_by`.
        let (router, _store) = build_pg_router(&url).await;
        let status = post_json(
            router,
            &format!("/api/v1/actions/{id}/transition"),
            json!({"to": "in_progress"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "#3360 pg: an unbound transition on a leased action must be 403"
        );

        let after = store
            .action_get(&ctx, &id)
            .await
            .expect("action_get")
            .expect("action present");
        assert_eq!(after.state, ai_memory::models::ActionState::Claimed);
        assert_eq!(
            after.claimed_by.as_deref(),
            Some("ai:alice"),
            "#3360 pg: the refused transition must not NULL the recorded owner"
        );
    }

    /// #8759 live-postgres twin (`local_transition_via_store`).
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
    async fn http_transition_acting_identity_table_pg_8759() {
        let Some(url) = postgres_url() else {
            panic!("AI_MEMORY_TEST_POSTGRES_URL unset — cannot run live-pg #8759 pin");
        };
        let (router, store) = build_pg_router(&url).await;
        super::run_8759_table(router, store).await;
    }

    /// #8773 pg cell: the same HTTP checkpoint rows through `PostgresStore`.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
    async fn http_checkpoint_resolve_acting_identity_table_pg_8773() {
        let Some(url) = postgres_url() else {
            panic!("AI_MEMORY_TEST_POSTGRES_URL unset — cannot run live-pg #8773 pin");
        };
        let (router, store) = build_pg_router(&url).await;
        super::run_8773_checkpoint_table(router, store).await;
    }
}
