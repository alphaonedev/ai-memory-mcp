// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

//! #3075 lane L-PGP, family F1 — the SQLITE half of the federated
//! `archives[]` / `restores[]` lane proof.
//!
//! ## What this file is for
//!
//! #3075 moves these two subcollections from `unsupported_on_postgres` to a
//! real trait-covered apply on a postgres receiver. The whole value of that
//! migration depends on the two backends agreeing, so the postgres twin
//! (`tests/fed_archive_restore_lane_3075_pg.rs`) asserts the SAME four
//! dispositions this file asserts on sqlite:
//!
//! 1. an IN-SCOPE archive APPLIES (the row leaves `memories`, lands in
//!    `archived_memories`, stamped with the shared `sync_push` reason);
//! 2. an IN-SCOPE restore APPLIES (the row comes back);
//! 3. an OUT-OF-SCOPE archive is REFUSED (#2447 by-id gate on the STORED
//!    namespace — the row survives);
//! 4. a FORGET-TOMBSTONED restore is REFUSED (#1848 / G30 — a peer must not be
//!    able to undo a local forget by pushing a restore).
//!
//! Cells 1-3 exercise the HTTP `/sync/push` receive loop, which on sqlite is
//! the long-standing INLINE path (unchanged by #3075) — so they are also the
//! control proving the migration did not move sqlite's behaviour.
//!
//! Cell 4 additionally drives the NEW sqlite SAL methods directly
//! (`apply_remote_archive` / `apply_remote_restore` /
//! `archived_namespace_by_id`), because those are net-new production code that
//! the sqlite receive loop does not reach: without a direct cell the sqlite
//! half of the trait would ship untested while only the pg half was exercised.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// Process-global async mutex — these tests mutate process-wide federation env
/// vars, so they must not race each other.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const PEER_ID: &str = "ai:peer-3075";
const IN_SCOPE_NS: &str = "public/ok";
const VICTIM_NS: &str = "secure/ops";

/// `ai:peer-3075` may push as itself, scoped to `public/**` only.
const SCOPED_ALLOWLIST: &str = r#"{"ai:peer-3075":{"allowed_namespaces":["public/**"],"allowed_sender_agent_ids":["ai:peer-3075"]}}"#;

struct PostureGuard;

impl Drop for PostureGuard {
    fn drop(&mut self) {
        clear_posture();
    }
}

fn set_scoped_posture() {
    // SAFETY: every caller holds ENV_LOCK for the duration.
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            SCOPED_ALLOWLIST,
        );
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
}

fn clear_posture() {
    // SAFETY: every caller holds ENV_LOCK for the duration.
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(REQUIRE_ATTEST_ENV);
        std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
}

fn build_router_with_db() -> (axum::Router, ai_memory::handlers::Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("open sqlite");
    let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
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
        atomise_queue: None,
        recall_scope: std::sync::Arc::new(None),
        deferred_audit_queue: std::sync::Arc::new(None),
        admin_agent_ids: std::sync::Arc::new(Vec::new()),
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
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), db)
}

async fn seed_memory(router: &axum::Router, namespace: &str, title: &str) -> String {
    let create = json!({
        "title": title,
        "content": "row the federated archive/restore lane acts on",
        "namespace": namespace,
        "tier": "long",
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
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let created: Value = serde_json::from_slice(&bytes).unwrap();
    created["id"].as_str().expect("created id").to_string()
}

async fn push(router: &axum::Router, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            PEER_ID,
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, report)
}

/// PRIMARY assertion surface — raw SQL, so no accessor's own error folding can
/// colour the answer.
async fn live_exists(db: &ai_memory::handlers::Db, id: &str) -> bool {
    let lock = db.lock().await;
    lock.0
        .query_row("SELECT COUNT(*) FROM memories WHERE id = ?1", [id], |r| {
            r.get::<_, i64>(0)
        })
        .expect("count live")
        > 0
}

async fn archived_reason(db: &ai_memory::handlers::Db, id: &str) -> Option<String> {
    use rusqlite::OptionalExtension as _;
    let lock = db.lock().await;
    lock.0
        .query_row(
            "SELECT archive_reason FROM archived_memories WHERE id = ?1",
            [id],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()
        .expect("read archive_reason")
        .flatten()
}

async fn write_forget_tombstone(db: &ai_memory::handlers::Db, id: &str, namespace: &str) {
    let lock = db.lock().await;
    lock.0
        .execute(
            "INSERT INTO forget_tombstones (memory_id, namespace, forgotten_at, agent_id, \
             signature) VALUES (?1, ?2, ?3, ?4, NULL)",
            rusqlite::params![id, namespace, "2026-09-05T00:00:00Z", "ai:victim"],
        )
        .expect("seed forget tombstone");
}

/// Cell 1+2 — the ALLOWED half: an in-scope archive APPLIES and its in-scope
/// restore brings the row back. The reason marker is asserted because it is the
/// shared SSOT both backends and both adapters stamp (#3075 /
/// `ARCHIVE_REASON_SYNC_PUSH`); a backend that stamped a different value would
/// make every reason-filtered query and `archive_stats` report disagree across
/// a heterogeneous federation.
#[tokio::test]
async fn federated_archive_then_restore_applies_in_scope_3075() {
    let _g = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_scoped_posture();
    let (router, db) = build_router_with_db();
    let id = seed_memory(&router, IN_SCOPE_NS, "in-scope archive target").await;

    let (status, report) = push(
        &router,
        &json!({
            "sender_agent_id": PEER_ID,
            "sender_clock": {"entries": {}},
            "memories": [],
            "archives": [id],
            "dry_run": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert!(
        !live_exists(&db, &id).await,
        "the in-scope archive must move the live row: {report}"
    );
    assert_eq!(
        archived_reason(&db, &id).await.as_deref(),
        Some(ai_memory::models::field_names::ARCHIVE_REASON_SYNC_PUSH),
        "the federated archive stamps the shared sync_push reason: {report}"
    );
    assert_eq!(report["archived"].as_u64().unwrap_or(0), 1, "{report}");

    let (status, report) = push(
        &router,
        &json!({
            "sender_agent_id": PEER_ID,
            "sender_clock": {"entries": {}},
            "memories": [],
            "restores": [id],
            "dry_run": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert!(
        live_exists(&db, &id).await,
        "the in-scope restore must bring the row back: {report}"
    );
    assert_eq!(report["restored"].as_u64().unwrap_or(0), 1, "{report}");
}

/// Cell 3 — the DENIED half: a peer scoped to `public/**` must not archive a
/// `secure/ops` row. The subject is the row's STORED namespace resolved by id
/// (#2447), never the wire, because `archives[]` carries only an id.
#[tokio::test]
async fn federated_archive_refused_out_of_scope_3075() {
    let _g = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_scoped_posture();
    let (router, db) = build_router_with_db();
    let id = seed_memory(&router, VICTIM_NS, "out-of-scope archive target").await;

    let (status, report) = push(
        &router,
        &json!({
            "sender_agent_id": PEER_ID,
            "sender_clock": {"entries": {}},
            "memories": [],
            "archives": [id],
            "dry_run": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the batch survives: {report}");
    assert!(
        live_exists(&db, &id).await,
        "#2447: a peer scoped to public/** must NOT archive a secure/ops row: {report}"
    );
    assert!(
        archived_reason(&db, &id).await.is_none(),
        "and must not have produced an archive row: {report}"
    );
    assert_eq!(report["archived"].as_u64().unwrap_or(0), 0, "{report}");
}

/// Cell 4 — the SAL surface directly: the new sqlite trait methods, including
/// the #1848 / G30 forget-tombstone refusal that is the whole reason
/// `apply_remote_restore` exists as a method distinct from `archive_restore`
/// (the OPERATOR un-forget path, which must keep round-tripping per #1771).
#[cfg(feature = "sal")]
#[tokio::test]
async fn sqlite_sal_archive_restore_methods_and_g30_gate_3075() {
    use ai_memory::store::MemoryStore as _;

    let _g = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    clear_posture();

    // Driven directly against a `SqliteStore`, with no router: these methods are
    // the SAL surface, and the sqlite RECEIVE loop deliberately does not reach
    // them (it keeps its inline `db::*` path, byte-for-byte unchanged by #3075).
    let id = format!("sal-3075-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let store = ai_memory::store::sqlite::SqliteStore::open(&path).expect("open store");
    let ctx = ai_memory::store::CallerContext::for_agent("ai:victim");
    let mem = ai_memory::models::Memory {
        id: id.clone(),
        namespace: IN_SCOPE_NS.to_string(),
        title: "sal archive/restore target".to_string(),
        content: "row the SAL federated archive/restore acts on".to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-02T00:00:00+00:00".to_string(),
        metadata: json!({"agent_id": "ai:victim"}),
        ..Default::default()
    };
    store.store(&ctx, &mem).await.expect("seed via trait");

    assert!(
        store
            .apply_remote_archive(&ctx, &id)
            .await
            .expect("archive"),
        "a live row archives"
    );
    assert_eq!(
        store
            .archived_namespace_by_id(&ctx, &id)
            .await
            .expect("archived namespace probe")
            .as_deref(),
        Some(IN_SCOPE_NS),
        "the #2447 restores[] probe resolves the ARCHIVE table"
    );
    assert!(
        !store
            .apply_remote_archive(&ctx, "no-such-id-3075")
            .await
            .expect("absent archive"),
        "an absent id is the lane's no-op, never an error"
    );

    // G30: tombstone the id, then prove the federated restore refuses while the
    // operator un-forget path still round-trips.
    {
        let lock_store =
            ai_memory::db::open(std::path::Path::new(&path)).expect("reopen store file");
        lock_store
            .execute(
                "INSERT INTO forget_tombstones (memory_id, namespace, forgotten_at, agent_id, \
                 signature) VALUES (?1, ?2, ?3, ?4, NULL)",
                rusqlite::params![&id, IN_SCOPE_NS, "2026-09-05T00:00:00Z", "ai:victim"],
            )
            .expect("seed forget tombstone");
    }
    assert!(
        !store
            .apply_remote_restore(&ctx, &id)
            .await
            .expect("tombstoned restore"),
        "#1848/G30: a peer must not undo a local forget by pushing a restore"
    );
    assert!(
        store
            .archived_namespace_by_id(&ctx, &id)
            .await
            .expect("still archived")
            .is_some(),
        "the refusal is a no-op: the archived row is neither restored nor destroyed"
    );
}

/// Cell 4b — the HTTP twin of the G30 gate: a tombstoned id pushed on
/// `restores[]` is the lane's no-op, and the tombstone survives.
#[tokio::test]
async fn federated_restore_of_tombstoned_id_is_noop_3075() {
    let _g = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_scoped_posture();
    let (router, db) = build_router_with_db();
    let id = seed_memory(&router, IN_SCOPE_NS, "tombstoned restore target").await;

    let (status, _report) = push(
        &router,
        &json!({
            "sender_agent_id": PEER_ID,
            "sender_clock": {"entries": {}},
            "memories": [],
            "archives": [id],
            "dry_run": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    write_forget_tombstone(&db, &id, IN_SCOPE_NS).await;

    let (status, report) = push(
        &router,
        &json!({
            "sender_agent_id": PEER_ID,
            "sender_clock": {"entries": {}},
            "memories": [],
            "restores": [id],
            "dry_run": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert!(
        !live_exists(&db, &id).await,
        "#1848/G30: the tombstoned row must NOT be resurrected by a peer: {report}"
    );
    assert_eq!(report["restored"].as_u64().unwrap_or(0), 0, "{report}");
}
