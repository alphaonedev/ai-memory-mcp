// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

//! #2912 item 1 — decisive standalone removal-proof for
//! [`peer_enrolled_in_allowlist`] on BOTH inbound lanes.
//!
//! ## Why the existing 2447/2488 proofs were MASKED
//!
//! `peer_enrolled_in_allowlist` (`src/federation/receive_auth.rs`) is the
//! Layer-2 predicate that refuses an unenrolled / header-absent peer
//! UNCONDITIONALLY — before `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE` is
//! consulted. Its sole production call is inside
//! `layer2_unscoped_peer_authorized`, which both
//! `inbound_write_namespace_authorized` (memories[]) and
//! `inbound_by_id_namespace_authorized` (deletions[]) share.
//!
//! The cert harness previously mapped this control onto
//! `federated_write_outside_peer_scope_refused_2447`. That test uses an
//! ENROLLED, SCOPED peer writing out of scope, so the request is refused by
//! Layer 1 (`peer_declares_namespace_scope`) and never reaches this
//! predicate. Mutating the function to `return true;` therefore left that
//! test GREEN (broken→rc=0) — asserted, not proven.
//!
//! Even a Layer-2 test with the knob at its default (ON) is still masked:
//! after `return true;` the unenrolled peer is treated as enrolled-unscoped,
//! and default-ON Layer 2 still refuses. The request must open the
//! documented hatch (`AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=0`) so
//! that a broken predicate lets the write/delete LAND.
//!
//! ## The only HTTP-reachable unenrolled shape
//!
//! A present-but-unlisted `X-Peer-Id` is refused by the #1056 TOFU envelope
//! (`401 x_peer_id_not_in_allowlist`) BEFORE Layer 2. The shape that
//! actually reaches `peer_enrolled_in_allowlist` is header-absent (or
//! whitespace-only, which `extract_peer_id` collapses to `None`) plus the
//! documented #238 hatch `AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1`. That is
//! the #2497 anonymous-delete grant this control exists to close.
//!
//! Isolation: async `ENV_LOCK` + `set_posture`, copied from
//! `tests/federation_write_ns_scope_2447.rs` /
//! `tests/federation_delete_ns_scope_2488.rs`. Do not invent a parallel
//! env protocol. (#2905 subprocess isolation is for *posture-module*
//! tests; these are federation *lane* tests.)

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// Process-global async mutex — these tests mutate process-wide env vars.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const PEER_ID: &str = "ai:evil";
const VICTIM_NS: &str = "secure/ops";

/// Allowlist IS configured (so we are not on the zero-config faith-based
/// path). `ai:evil` is enrolled with no `allowed_namespaces` — Layer 2
/// would govern that peer IF a header named them. These tests send NO
/// `X-Peer-Id`, so `peer_enrolled_in_allowlist` sees `None`.
const UNSCOPED_ALLOWLIST: &str = r#"{"ai:evil":{"allowed_sender_agent_ids":["ai:evil"]}}"#;

/// RAII posture guard. `clear_posture` at the end of the body does not
/// run when an assertion panics (the #2482 leak). `Drop` runs on unwind.
struct PostureGuard;

impl Drop for PostureGuard {
    fn drop(&mut self) {
        clear_posture();
    }
}

fn build_router_with_db() -> (axum::Router, ai_memory::handlers::Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    let path = std::path::PathBuf::from(":memory:");
    let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        path,
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
        let p = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        std::sync::Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open store"))
    };
    let app_state = ai_memory::handlers::AppState {
        db: db.clone(),
        embedder: std::sync::Arc::new(None),
        vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        federation: std::sync::Arc::new(None),
        tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: std::sync::Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: std::sync::Arc::new(None),
        active_keypair: std::sync::Arc::new(None),
        family_embeddings: std::sync::Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: std::sync::Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: std::sync::Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        recall_scope: std::sync::Arc::new(None),
        deferred_audit_queue: std::sync::Arc::new(None),
        admin_agent_ids: std::sync::Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), db)
}

/// Seed the peer-attestation posture. Always opens the #238 hatch so a
/// header-absent push reaches Layer 2 (without it the envelope refuses
/// `403 peer_id_header_missing` and this control is never consulted).
fn set_posture(allowlist: Option<&str>, require_scope: Option<&str>) {
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
        match allowlist {
            Some(json) => std::env::set_var(
                ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
                json,
            ),
            None => {
                std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
            }
        }
        match require_scope {
            Some(v) => std::env::set_var(
                ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
                v,
            ),
            None => std::env::remove_var(
                ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            ),
        }
        // Belt-and-braces: an earlier test setting the legacy bypass would
        // mask the refusal this file exists to prove.
        std::env::remove_var("AI_MEMORY_FED_SYNC_TRUST_PEER");
    }
}

fn clear_posture() {
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
        std::env::remove_var(REQUIRE_ATTEST_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
}

fn wire_memory(id: &str, namespace: &str, title: &str, content: &str, updated_at: &str) -> Value {
    json!({
        "id": id,
        "tier": "long",
        "namespace": namespace,
        "title": title,
        "content": content,
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "access_count": 0,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": updated_at,
        "metadata": {"agent_id": PEER_ID},
        "reflection_depth": 0,
        "memory_kind": "observation",
    })
}

fn push_body(memories: &[Value]) -> Value {
    json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": memories,
        "dry_run": false,
    })
}

/// POST `/sync/push` with NO `X-Peer-Id`. The request reaches Layer 2 only
/// because `set_posture` opened `AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1`.
async fn push_header_absent(router: &axum::Router, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, report)
}

async fn seed_row(router: &axum::Router, namespace: &str, title: &str) -> String {
    let create = json!({
        "title": title,
        "content": "row the federated delete lane will target",
        "tier": "long",
        "namespace": namespace,
        "tags": [],
        "priority": 5,
        "source": "api",
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json")
        .header("x-agent-id", "ai:victim")
        .body(Body::from(create.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_success(), "seed write must succeed");
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let created: Value = serde_json::from_slice(&bytes).unwrap();
    created["id"].as_str().expect("created id").to_string()
}

async fn count_ns(db: &ai_memory::handlers::Db, ns: &str) -> i64 {
    let guard = db.lock().await;
    guard
        .0
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
            [ns],
            |r| r.get(0),
        )
        .unwrap()
}

async fn row_exists(db: &ai_memory::handlers::Db, id: &str) -> bool {
    let guard = db.lock().await;
    let n: i64 = guard
        .0
        .query_row("SELECT COUNT(*) FROM memories WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .unwrap();
    n == 1
}

// ---------------------------------------------------------------------
// WRITE lane — `inbound_write_namespace_authorized` / memories[].
// Harness MAP guard for `peer_enrolled_in_allowlist`.
// ---------------------------------------------------------------------

#[tokio::test]
async fn unenrolled_peer_refused_on_write_lane_when_scope_hatch_open_2912() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    // Decisive posture: allowlist configured + hatch OPEN. If
    // `peer_enrolled_in_allowlist` is mutated to `return true;`, Layer 2
    // treats the anonymous peer as enrolled-unscoped and the hatch lets
    // the write LAND. Intact, the predicate refuses UNCONDITIONALLY.
    set_posture(Some(UNSCOPED_ALLOWLIST), Some("0"));
    let (router, db) = build_router_with_db();

    let (status, report) = push_header_absent(
        &router,
        &push_body(&[wire_memory(
            &uuid::Uuid::new_v4().to_string(),
            VICTIM_NS,
            "anonymous-write",
            "must not land when peer_enrolled_in_allowlist is intact",
            "2026-07-01T00:00:00+00:00",
        )]),
    )
    .await;
    assert!(
        status.is_success(),
        "#2912: header-absent + TRUST_BODY_AGENT_ID=1 must reach the \
         memories[] loop (per-item skip, batch survives); got {status} {report}"
    );
    assert_eq!(
        count_ns(&db, VICTIM_NS).await,
        0,
        "#2912 WRITE: an anonymous (no x-peer-id) push must NOT land a row \
         on a node that declares a peer allowlist, even with \
         AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=0. That hatch governs \
         only an ENROLLED peer that declared no allowed_namespaces. If this \
         assertion fails after mutating peer_enrolled_in_allowlist to \
         `return true;`, the control is load-bearing; if it stays green, \
         the proof is still MASKED."
    );
}

// ---------------------------------------------------------------------
// BY-ID lane — `inbound_by_id_namespace_authorized` / deletions[].
// Suite-level twin of the MAP guard above.
// ---------------------------------------------------------------------

#[tokio::test]
async fn unenrolled_peer_refused_on_delete_lane_when_scope_hatch_open_2912() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    set_posture(Some(UNSCOPED_ALLOWLIST), Some("0"));
    let (router, db) = build_router_with_db();
    let id = seed_row(&router, VICTIM_NS, "anonymous-delete-target").await;
    assert!(row_exists(&db, &id).await, "seed row must exist");

    let body = json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "deletions": [&id],
        "dry_run": false,
    });
    let (status, report) = push_header_absent(&router, &body).await;
    assert!(
        status.is_success(),
        "#2912: header-absent + TRUST_BODY_AGENT_ID=1 must reach the \
         deletions[] loop; got {status} {report}"
    );
    assert!(
        row_exists(&db, &id).await,
        "#2912 BY-ID: an anonymous (no x-peer-id) push must NOT hard-delete \
         by id on a node that declares a peer allowlist, even with \
         AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=0. This is the #2497 \
         anonymous-delete grant the predicate exists to close. If this \
         assertion fails after mutating peer_enrolled_in_allowlist to \
         `return true;`, the control is load-bearing on this lane too."
    );
}
