// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3901 (SEC, containment) — the #1948 route-OUT dequarantine-on-attest must
//! only ever lift a quarantine on the row the attestation actually covered.
//!
//! Both receive funnels (`merge_inbound` on sqlite and postgres) resolve an
//! inbound row whose id is ABSENT locally through the `(title, namespace)`
//! title-slot upsert, which returns the id of the DIFFERENT local row that
//! holds the slot. Pre-fix the funnel then dequarantined that returned id
//! unconditionally whenever the inbound unit was `agent_attested` — so an
//! attestation over a fresh id `X` un-hid an unrelated local row `Y` that THIS
//! node had quarantined (containment is node-local, item 3 part 5 / #3266).
//!
//! Cells, each on sqlite and (ignored tier, `AI_MEMORY_TEST_POSTGRES_URL`) on
//! live postgres, through the production `/sync/push` router:
//! * cross-id title merge — `Y` stays `quarantined` AND the push still counts
//!   as applied (the pin distinguishes "quarantine preserved" from "the whole
//!   push was refused");
//! * control — the legitimate same-id attested push still dequarantines.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
#[cfg(feature = "sal-postgres")]
use ai_memory::store::CallerContext;
use ai_memory::store::MemoryStore;

static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());
/// Strictly older than any `now_attestable_rfc3339()` so the attested push is
/// the LWW winner of every merge below.
const T_OLD: &str = "2026-01-01T00:00:00.000000Z";

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

/// Zero-config receive posture (the #2863 DO-mesh shape): envelope gates
/// relaxed so the per-write attestation lane is reached; the #1948 route-IN
/// knob OFF so the only lifecycle actor under test is route-OUT. Restored on
/// Drop (also on panic).
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

enum Backend {
    Sqlite,
    #[cfg(feature = "sal-postgres")]
    Postgres(String),
}

/// A production router over the chosen backend, the SAL handle, and the
/// sqlite connection the sqlite funnel writes through.
#[allow(clippy::unused_async)] // the pg arm awaits; the sqlite arm does not
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
        ..Default::default()
    };
    (ai_memory::build_router(api_key_state, app_state), store, db)
}

/// Register `author` and bind a fresh keypair on the backend the receive
/// funnel verifies against, so a signed push lands `agent_attested`.
async fn enroll(
    backend: &Backend,
    db: &Db,
    store: &Arc<dyn MemoryStore>,
    author: &str,
) -> ai_memory::identity::keypair::AgentKeypair {
    let kp = ai_memory::identity::keypair::generate(author).expect("keypair");
    match backend {
        Backend::Sqlite => {
            let lock = db.lock().await;
            ai_memory::db::register_agent(&lock.0, author, "nhi", &[]).expect("register");
            ai_memory::db::bind_agent_pubkey_with_keypair(&lock.0, author, &kp).expect("bind");
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(_) => {
            let ctx = CallerContext::for_agent(author);
            let now = ai_memory::identity::attest::now_attestable_rfc3339();
            store
                .register_agent(
                    &ctx,
                    &ai_memory::models::AgentRegistration {
                        agent_id: author.to_string(),
                        agent_type: "nhi".to_string(),
                        capabilities: Vec::new(),
                        registered_at: now.clone(),
                        last_seen_at: now,
                    },
                )
                .await
                .expect("register");
            let proof = ai_memory::store::prove_possession_via_store(
                store.as_ref(),
                &ctx,
                author,
                kp.private.as_ref().expect("private key"),
            )
            .await
            .expect("prove possession");
            store
                .bind_agent_pubkey(&ctx, author, &kp.public_base64(), proof)
                .await
                .expect("bind");
        }
    }
    let _ = store; // read by the pg arm only
    kp
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

/// A wire row signed by `kp` exactly as the authoring node would sign it.
fn signed_wire(
    kp: &ai_memory::identity::keypair::AgentKeypair,
    id: &str,
    ns: &str,
    title: &str,
    author: &str,
) -> Value {
    let created = ai_memory::identity::attest::now_attestable_rfc3339();
    let mut value = memory_json(id, ns, title, "attested peer text", author, &created);
    let memory: ai_memory::models::Memory = serde_json::from_value(value.clone()).expect("memory");
    let sig = ai_memory::identity::attest::sign_memory_write(kp, &memory, author).expect("sign");
    value["metadata"]["write_signature"] =
        json!(base64::engine::general_purpose::STANDARD.encode(sig));
    value
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

/// Seed a local row and move it to `quarantined` with a raw UPDATE (the
/// route-IN lane's write), keeping `updated_at = T_OLD`.
async fn seed_quarantined(
    backend: &Backend,
    db: &Db,
    store: &Arc<dyn MemoryStore>,
    id: &str,
    ns: &str,
    title: &str,
    author: &str,
) {
    let m: ai_memory::models::Memory =
        serde_json::from_value(memory_json(id, ns, title, "local text", author, T_OLD))
            .expect("memory");
    match backend {
        Backend::Sqlite => {
            let lock = db.lock().await;
            ai_memory::db::insert(&lock.0, &m).expect("seed");
            let n = lock
                .0
                .execute(
                    "UPDATE memories SET lifecycle_state = 'quarantined', updated_at = ?1 \
                     WHERE id = ?2",
                    rusqlite::params![T_OLD, id],
                )
                .expect("quarantine");
            assert_eq!(n, 1);
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(_) => {
            store
                .store(&CallerContext::for_agent(author), &m)
                .await
                .expect("seed");
            let n = sqlx::query(
                "UPDATE memories SET lifecycle_state = 'quarantined', \
                 updated_at = $1::timestamptz WHERE id = $2",
            )
            .bind(T_OLD)
            .bind(id)
            .execute(pg_store(store).pool())
            .await
            .expect("quarantine")
            .rows_affected();
            assert_eq!(n, 1);
        }
    }
    let _ = store; // read by the pg arm only
}

/// `lifecycle_state` of a row by id (`None` when absent).
async fn state(
    backend: &Backend,
    db: &Db,
    store: &Arc<dyn MemoryStore>,
    id: &str,
) -> Option<String> {
    let _ = store; // read by the pg arm only
    match backend {
        Backend::Sqlite => {
            let lock = db.lock().await;
            lock.0
                .query_row(
                    "SELECT lifecycle_state FROM memories WHERE id = ?1",
                    [id],
                    |r| r.get(0),
                )
                .ok()
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(_) => {
            sqlx::query_scalar::<_, String>("SELECT lifecycle_state FROM memories WHERE id = $1")
                .bind(id)
                .fetch_optional(pg_store(store).pool())
                .await
                .expect("query")
        }
    }
}

#[cfg(feature = "sal-postgres")]
fn pg_store(store: &Arc<dyn MemoryStore>) -> &ai_memory::store::postgres::PostgresStore {
    store
        .as_any()
        .downcast_ref::<ai_memory::store::postgres::PostgresStore>()
        .expect("postgres store")
}

/// THE DEFECT (#3901): an attested push of a FRESH id `X` whose
/// `(title, namespace)` collides with a local QUARANTINED row `Y` merges into
/// `Y` via the title slot — and must leave `Y` quarantined. The attestation
/// covered `X`'s unit, never `Y`, nor this node's decision to contain `Y`.
async fn cross_id_title_merge_keeps_other_row_quarantined(backend: &Backend) {
    let _posture = Posture::zero_config();
    let author = uniq("ai:author-3901");
    let ns = uniq("team/q3901");
    let (y, x, title) = (uniq("y"), uniq("x"), uniq("t"));
    let (router, store, db) = router(backend).await;
    let kp = enroll(backend, &db, &store, &author).await;
    seed_quarantined(backend, &db, &store, &y, &ns, &title, &author).await;

    let (status, report) = push(&router, &author, signed_wire(&kp, &x, &ns, &title, &author)).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(
        report["applied"], 1,
        "the attested push must still apply (quarantine preserved, push not refused): {report}"
    );
    assert_eq!(
        state(backend, &db, &store, &x).await,
        None,
        "precondition: the fresh id merged into the title-slot holder, not a new row"
    );
    assert_eq!(
        state(backend, &db, &store, &y).await.as_deref(),
        Some("quarantined"),
        "#3901: an attestation over id {x} must never lift the local quarantine on {y}"
    );
}

/// CONTROL: the legitimate same-id path is unchanged — an attested push of the
/// quarantined row's OWN id still clears the quarantine (#1948 route-OUT).
async fn same_id_attested_push_still_dequarantines(backend: &Backend) {
    let _posture = Posture::zero_config();
    let author = uniq("ai:author-3901");
    let ns = uniq("team/q3901");
    let (y, title) = (uniq("y"), uniq("t"));
    let (router, store, db) = router(backend).await;
    let kp = enroll(backend, &db, &store, &author).await;
    seed_quarantined(backend, &db, &store, &y, &ns, &title, &author).await;

    let (status, report) = push(&router, &author, signed_wire(&kp, &y, &ns, &title, &author)).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(report["applied"], 1, "{report}");
    assert_eq!(
        state(backend, &db, &store, &y).await.as_deref(),
        Some("open"),
        "#1948 route-OUT: an attested push of the row's own id dequarantines it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_cross_id_title_merge_keeps_other_row_quarantined_3901() {
    let _g = FED_ENV_LOCK.lock().await;
    cross_id_title_merge_keeps_other_row_quarantined(&Backend::Sqlite).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_same_id_attested_push_still_dequarantines_3901() {
    let _g = FED_ENV_LOCK.lock().await;
    same_id_attested_push_still_dequarantines(&Backend::Sqlite).await;
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{
        Backend, FED_ENV_LOCK, cross_id_title_merge_keeps_other_row_quarantined,
        same_id_attested_push_still_dequarantines,
    };

    fn pg_backend() -> Backend {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .expect("own PG URL required (AI_MEMORY_TEST_POSTGRES_URL); no soft skip");
        Backend::Postgres(url)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_cross_id_title_merge_keeps_other_row_quarantined_3901() {
        let _g = FED_ENV_LOCK.lock().await;
        cross_id_title_merge_keeps_other_row_quarantined(&pg_backend()).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_same_id_attested_push_still_dequarantines_3901() {
        let _g = FED_ENV_LOCK.lock().await;
        same_id_attested_push_still_dequarantines(&pg_backend()).await;
    }
}
