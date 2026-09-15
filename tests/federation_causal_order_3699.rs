// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 Consolidation Unit 1 — #3699 (federation out-of-order delivery),
//! 5-agent vote 4d3ea1c5 option (a): the `/sync/push` receive loop applies
//! one body's `memories[]` in CAUSAL order (`updated_at`, `id`) on BOTH
//! backends, and a cross-id `(title, namespace)` merge is counted + WARNed.
//!
//! The shape: the peer still holds source A LIVE (title T). Origin has
//! consolidated A (A is a TOMBSTONE, same id, same title) and then stored a
//! NEW memory W with title T (a live row beside the tombstone at v100). One
//! push body carries both. Delivered W-first, the pre-fix loop folded W into
//! live A (cross-id title merge) and the tombstone then lost by-id to the
//! merged row: A live carrying W's text, no row W — permanent id divergence.
//! In causal order the tombstone lands first (A hidden, by id), so W lands
//! beside it as its own row and both replicas agree: A tombstoned with A's
//! text, W live with W's text and W's id.
//!
//! BOTH arrival orders are pinned (the Conductor's rule: an ordering fix that
//! only pins the order it chose cannot see the other one regress): the
//! W-first body is RED on the pre-fix tree, the tombstone-first body is the
//! control. The cross-push residual (tombstone and W in DIFFERENT pushes) is
//! NOT closed by this and is filed on its own; the merge it produces is
//! observable through `ai_memory_fed_cross_id_title_merge_total`, pinned
//! here on the honest same-title dedup shape.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

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
const PEER_HEADER: &str = "x-peer-id";

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

/// Posture for the memories[] lane: sig gate off, body sender trusted, the
/// peer scoped to its namespace. Restored on Drop (also on panic).
struct Posture([(&'static str, Option<std::ffi::OsString>); 5]);

impl Posture {
    fn new(peer: &str, namespace: &str) -> Self {
        use ai_memory::federation::peer_attestation::{
            PEER_ATTESTATION_ENV, TRUST_BODY_AGENT_ID_ENV,
        };
        use ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV;
        use ai_memory::federation::signing::REQUIRE_SIG_ENV;
        const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
        let keys = [
            PEER_ATTESTATION_ENV,
            REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            REQUIRE_SIG_ENV,
            TRUST_BODY_AGENT_ID_ENV,
            REQUIRE_ATTEST_ENV,
        ];
        let guard = Self(keys.map(|k| (k, std::env::var_os(k))));
        let allowlist = json!({peer: {
            "allowed_sender_agent_ids": [peer],
            "allowed_namespaces": [namespace],
        }});
        // SAFETY: every caller holds FED_ENV_LOCK; Drop restores before release.
        unsafe {
            std::env::set_var(PEER_ATTESTATION_ENV, allowlist.to_string());
            std::env::remove_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
            std::env::set_var(REQUIRE_SIG_ENV, "0");
            std::env::set_var(TRUST_BODY_AGENT_ID_ENV, "1");
            std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        }
        guard
    }
}

impl Drop for Posture {
    fn drop(&mut self) {
        // SAFETY: the enclosing test still holds FED_ENV_LOCK.
        for (key, previous) in &self.0 {
            unsafe {
                match previous {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

enum Backend {
    Sqlite,
    #[cfg(feature = "sal-postgres")]
    Postgres(String),
}

/// A production router over the chosen backend plus the SAL handle the
/// assertions read through.
async fn router(backend: &Backend) -> (axum::Router, Arc<dyn MemoryStore>, Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let (store, storage_backend): (Arc<dyn MemoryStore>, StorageBackend) = match backend {
        Backend::Sqlite => {
            let tmp = tempfile::NamedTempFile::new().expect("tempfile");
            let p = tmp.path().to_path_buf();
            std::mem::forget(tmp);
            (
                Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open store")),
                StorageBackend::Sqlite,
            )
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(url) => (
            Arc::new(
                ai_memory::store::postgres::PostgresStore::connect(url)
                    .await
                    .expect("connect postgres"),
            ),
            StorageBackend::Postgres,
        ),
    };
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
    };
    (ai_memory::build_router(api_key_state, app_state), store, db)
}

fn memory_json(
    id: &str,
    ns: &str,
    title: &str,
    content: &str,
    peer: &str,
    updated_at: &str,
    state: &str,
) -> Value {
    json!({
        "id": id,
        "tier": "long",
        "namespace": ns,
        "title": title,
        "content": content,
        "tags": ["fed-3699"],
        "priority": 5,
        "confidence": 1.0,
        "source": "nhi",
        "access_count": 0,
        "created_at": "2026-09-15T10:00:00.000000Z",
        "updated_at": updated_at,
        "lifecycle_state": state,
        "metadata": {"agent_id": peer}
    })
}

async fn push(router: &axum::Router, peer: &str, memories: Vec<Value>) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "sender_wall_clock": chrono::Utc::now().to_rfc3339(),
        "memories": memories,
        "dry_run": false,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(PEER_HEADER, peer)
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// `(content, lifecycle_state)` of a row by id on the backend the router
/// wrote to, or `None` when no row carries the id.
async fn raw(
    backend: &Backend,
    db: &Db,
    store: &Arc<dyn MemoryStore>,
    id: &str,
) -> Option<(String, String)> {
    match backend {
        Backend::Sqlite => {
            let guard = db.lock().await;
            guard
                .0
                .query_row(
                    "SELECT content, lifecycle_state FROM memories WHERE id = ?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .ok()
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(_) => {
            let pg = store
                .as_any()
                .downcast_ref::<ai_memory::store::postgres::PostgresStore>()
                .expect("postgres store");
            sqlx::query_as::<_, (String, String)>(
                "SELECT content, lifecycle_state FROM memories WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(pg.pool())
            .await
            .expect("query")
        }
    }
}

/// Seed the peer-side LIVE source A directly on the backend (the state
/// before the consolidation push reaches this node).
async fn seed_live_a(
    backend: &Backend,
    db: &Db,
    store: &Arc<dyn MemoryStore>,
    a: &str,
    ns: &str,
    title: &str,
    peer: &str,
) {
    let m: ai_memory::models::Memory = serde_json::from_value(memory_json(
        a,
        ns,
        title,
        "A text",
        peer,
        "2026-09-15T10:00:01.000000Z",
        "open",
    ))
    .expect("memory");
    match backend {
        Backend::Sqlite => {
            let guard = db.lock().await;
            ai_memory::db::insert(&guard.0, &m).expect("seed A");
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(_) => {
            store
                .store(&ai_memory::store::CallerContext::for_agent(peer), &m)
                .await
                .expect("seed A");
        }
    }
}

/// One push body carrying A's tombstone (t2) and the new W (t3 > t2), in the
/// given wire order; both orders must converge to origin's state.
async fn converges_in_order(backend: &Backend, w_first: bool) {
    let peer = uniq("ai:peer-3699");
    let ns = uniq("fed-3699");
    let title = uniq("shared-title");
    let (a, w) = (uniq("a"), uniq("w"));
    let _posture = Posture::new(&peer, &ns);
    let (router, store, db) = router(backend).await;
    seed_live_a(backend, &db, &store, &a, &ns, &title, &peer).await;

    let tombstone = memory_json(
        &a,
        &ns,
        &title,
        "A text",
        &peer,
        "2026-09-15T10:00:02.000000Z",
        "tombstoned",
    );
    let new_w = memory_json(
        &w,
        &ns,
        &title,
        "W text",
        &peer,
        "2026-09-15T10:00:03.000000Z",
        "open",
    );
    let body = if w_first {
        vec![new_w, tombstone]
    } else {
        vec![tombstone, new_w]
    };
    let (status, report) = push(&router, &peer, body).await;
    assert!(status.is_success(), "w_first={w_first}: {status} {report}");
    assert_eq!(
        report["applied"].as_i64(),
        Some(2),
        "both rows applied: {report}"
    );

    assert_eq!(
        raw(backend, &db, &store, &a).await,
        Some(("A text".to_string(), "tombstoned".to_string())),
        "w_first={w_first}: A is the tombstone carrying A's own text"
    );
    assert_eq!(
        raw(backend, &db, &store, &w).await,
        Some(("W text".to_string(), "open".to_string())),
        "w_first={w_first}: W exists under ITS OWN id, live, with W's text"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_w_before_tombstone_in_one_push_converges_3699() {
    let _g = FED_ENV_LOCK.lock().await;
    converges_in_order(&Backend::Sqlite, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_tombstone_before_w_in_one_push_converges_3699() {
    let _g = FED_ENV_LOCK.lock().await;
    converges_in_order(&Backend::Sqlite, false).await;
}

/// The honest same-title dedup (two nodes independently stored title T under
/// different ids, no tombstone anywhere) still merges by title — and is now
/// COUNTED: the cross-id fold is never silent inside the 200.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_cross_id_title_merge_is_counted_3699() {
    let _g = FED_ENV_LOCK.lock().await;
    let backend = Backend::Sqlite;
    let peer = uniq("ai:peer-3699");
    let ns = uniq("fed-3699");
    let title = uniq("independent-title");
    let (a, x) = (uniq("a"), uniq("x"));
    let _posture = Posture::new(&peer, &ns);
    let (router, store, db) = router(&backend).await;
    seed_live_a(&backend, &db, &store, &a, &ns, &title, &peer).await;
    let before = ai_memory::metrics::fed_cross_id_title_merge_count();
    let inbound = memory_json(
        &x,
        &ns,
        &title,
        "X text",
        &peer,
        "2026-09-15T10:00:05.000000Z",
        "open",
    );
    let (status, report) = push(&router, &peer, vec![inbound]).await;
    assert!(status.is_success(), "{status} {report}");
    assert_eq!(
        raw(&backend, &db, &store, &a).await,
        Some(("X text".to_string(), "open".to_string())),
        "the independent same-title store still dedups into the local row"
    );
    assert_eq!(
        raw(&backend, &db, &store, &x).await,
        None,
        "the inbound id is not created here"
    );
    assert_eq!(
        ai_memory::metrics::fed_cross_id_title_merge_count(),
        before + 1,
        "the cross-id title merge is counted (ai_memory_fed_cross_id_title_merge_total)"
    );
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{
        Backend, FED_ENV_LOCK, Posture, converges_in_order, memory_json, push, raw, router,
        seed_live_a, uniq,
    };

    fn pg_backend() -> Option<Backend> {
        match std::env::var("AI_MEMORY_TEST_POSTGRES_URL") {
            Ok(url) if !url.is_empty() => Some(Backend::Postgres(url)),
            _ => {
                eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
                None
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pg_w_before_tombstone_in_one_push_converges_3699() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(backend) = pg_backend() else { return };
        converges_in_order(&backend, true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pg_tombstone_before_w_in_one_push_converges_3699() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(backend) = pg_backend() else { return };
        converges_in_order(&backend, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pg_cross_id_title_merge_is_counted_3699() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(backend) = pg_backend() else { return };
        let peer = uniq("ai:peer-3699");
        let ns = uniq("fed-3699");
        let title = uniq("independent-title");
        let (a, x) = (uniq("a"), uniq("x"));
        let _posture = Posture::new(&peer, &ns);
        let (router, store, db) = router(&backend).await;
        seed_live_a(&backend, &db, &store, &a, &ns, &title, &peer).await;
        let before = ai_memory::metrics::fed_cross_id_title_merge_count();
        let inbound = memory_json(
            &x,
            &ns,
            &title,
            "X text",
            &peer,
            "2026-09-15T10:00:05.000000Z",
            "open",
        );
        let (status, report) = push(&router, &peer, vec![inbound]).await;
        assert!(status.is_success(), "{status} {report}");
        assert_eq!(
            raw(&backend, &db, &store, &a).await,
            Some(("X text".to_string(), "open".to_string()))
        );
        assert_eq!(raw(&backend, &db, &store, &x).await, None);
        assert_eq!(
            ai_memory::metrics::fed_cross_id_title_merge_count(),
            before + 1
        );
    }
}
