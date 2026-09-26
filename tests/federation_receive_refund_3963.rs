// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3963 — the sqlite federation receive path charges the author's quota on
//! the storage-bytes dimension ONLY (`check_and_record_storage_only`, the
//! #1544 vote), so a failed `merge_inbound` must refund storage ONLY — the
//! postgres funnel's `refund_storage_only` mirror. Pre-fix it called
//! `refund_op(QuotaOp::Memory)`, which also decremented
//! `current_memories_today`, a dimension this path never charged: every
//! failed federated merge silently handed the author one free daily write.
//!
//! The cell forces the merge to fail with a `BEFORE INSERT` trigger that
//! RAISEs, and proves non-vacuity with a control push (no trigger) that
//! APPLIES — so the failing push is known to reach `merge_inbound` rather
//! than being skipped by an earlier gate.

#![cfg(feature = "sal")]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;

static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

/// Zero-config receive posture (copied from the #3901 harness): envelope
/// gates relaxed so the memories loop is reached. Restored on Drop.
struct Posture(Vec<(&'static str, Option<std::ffi::OsString>)>);

impl Posture {
    fn zero_config() -> Self {
        use ai_memory::federation::peer_attestation::{
            PEER_ATTESTATION_ENV, TRUST_BODY_AGENT_ID_ENV,
        };
        use ai_memory::federation::receive_auth::{
            FED_QUARANTINE_UNATTRIBUTED_ENV, REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
        };
        use ai_memory::federation::signing::REQUIRE_SIG_ENV;
        let set: [(&'static str, Option<&str>); 8] = [
            (REQUIRE_PUSH_NAMESPACE_SCOPE_ENV, Some("0")),
            (PEER_ATTESTATION_ENV, None),
            (TRUST_BODY_AGENT_ID_ENV, None),
            ("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", Some("0")),
            (REQUIRE_SIG_ENV, Some("0")),
            ("AI_MEMORY_FED_REQUIRE_NONCE", Some("0")),
            ("AI_MEMORY_FED_REQUIRE_WRITE_SIG", None),
            (FED_QUARANTINE_UNATTRIBUTED_ENV, None),
        ];
        let guard = Self(set.iter().map(|(k, _)| (*k, std::env::var_os(k))).collect());
        for (key, value) in set {
            // SAFETY: every caller holds FED_ENV_LOCK; Drop restores before release.
            unsafe {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
        guard
    }
}

impl Drop for Posture {
    fn drop(&mut self) {
        for (key, previous) in &self.0 {
            // SAFETY: the enclosing test still holds FED_ENV_LOCK.
            unsafe {
                match previous {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

/// A production router over sqlite and the connection the funnel writes to.
fn router() -> (axum::Router, Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let p = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open store"));
    let storage_backend = StorageBackend::Sqlite;
    let app_state = AppState {
        db: db.clone(),
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend,
        store: store.clone(),
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
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
    (ai_memory::build_router(api_key_state, app_state), db)
}

fn memory_json(id: &str, ns: &str, title: &str, content: &str, author: &str, ts: &str) -> Value {
    json!({
        "id": id,
        "tier": "long",
        "namespace": ns,
        "title": title,
        "content": content,
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "user",
        "access_count": 0,
        "created_at": ts,
        "updated_at": ts,
        "metadata": {"agent_id": author},
        "reflection_depth": 0,
        "memory_kind": "observation",
    })
}

async fn push(router: &axum::Router, sender: &str, memory: Value) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": sender,
        "sender_clock": {"entries": {}},
        "memories": [memory],
        "dry_run": false,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            sender,
        )
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

#[tokio::test]
async fn failed_federated_merge_refunds_storage_only_3963() {
    let _g = FED_ENV_LOCK.lock().await;
    let _posture = Posture::zero_config();
    let (router, db) = router();
    let author = uniq("ai:q3963");
    let ns = uniq("q3963");
    let now = ai_memory::identity::attest::now_attestable_rfc3339();

    // CONTROL (non-vacuity): with no forced failure the same shape of push
    // APPLIES, so the failing push below is known to reach merge_inbound.
    let (status, report) = push(
        &router,
        &author,
        memory_json(&uniq("m-ok"), &ns, &uniq("t"), "applies", &author, &now),
    )
    .await;
    assert!(status.is_success(), "{status} {report}");
    assert_eq!(report["applied"], 1, "control push must apply: {report}");

    let before = {
        let lock = db.lock().await;
        // The author's OWN local authoring: three charged daily writes.
        for _ in 0..3 {
            ai_memory::quotas::check_and_record(
                &lock.0,
                &author,
                &ns,
                ai_memory::quotas::QuotaOp::Memory { bytes: 10 },
            )
            .expect("local charge");
        }
        lock.0
            .execute_batch(
                "CREATE TRIGGER t3963_force_fail BEFORE INSERT ON memories \
                 BEGIN SELECT RAISE(ABORT, 'forced by #3963 test'); END;",
            )
            .expect("install failing trigger");
        ai_memory::quotas::get_status(&lock.0, &author, &ns).expect("status")
    };
    let (status, report) = push(
        &router,
        &author,
        memory_json(&uniq("m-fail"), &ns, &uniq("t"), "fails", &author, &now),
    )
    .await;
    assert!(status.is_success(), "{status} {report}");
    assert_eq!(
        report["applied"], 0,
        "the forced failure must not apply: {report}"
    );
    assert_eq!(
        report["skipped"], 1,
        "the failed merge is skipped: {report}"
    );
    let after = {
        let lock = db.lock().await;
        ai_memory::quotas::get_status(&lock.0, &author, &ns).expect("status")
    };
    assert_eq!(
        after.current_memories_today, before.current_memories_today,
        "a failed federated merge must not refund a daily write it never charged"
    );
    assert_eq!(
        after.current_storage_bytes, before.current_storage_bytes,
        "the storage-bytes charge is refunded exactly"
    );
}
