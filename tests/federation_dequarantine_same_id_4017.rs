// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4017 (SEC, containment) — the #1948 route-OUT dequarantine-on-attest must
//! only lift a quarantine when the STORED row provably IS the attested unit.
//!
//! Pre-fix both receive funnels released a quarantined row whenever the id
//! `merge_inbound` returned equalled the inbound id (#3901 closed only the
//! CROSS-id case). Same id is not proof of same bytes: `merge_inbound` field
//! merges into the existing quarantined row (`merge_memory`), so the stored
//! row can keep the LOCAL content (the inbound loses LWW) or the LOCAL
//! `agent_id` (immutable-to-local) — and the release then un-hid content, or
//! an attribution, the attestation never covered.
//!
//! Cells, each on sqlite and (ignored tier, `AI_MEMORY_TEST_POSTGRES_URL`) on
//! live postgres, through the production `/sync/push` router:
//! * LWW loser — the local quarantined row is NEWER, so its unattested text
//!   survives the merge: it must stay `quarantined` with its local text;
//! * attribution — the inbound wins the text, but the stored `agent_id` stays
//!   the local claimant's: the row is not the signed unit, stays quarantined;
//! * genesis — the quarantined row carries an earlier `created_at`, which the
//!   merge keeps (min): a distinct unit, stays quarantined;
//! * control — the same signed unit (same `created_at`, same author) arriving
//!   newer IS released (`open`), so the fix is not "never release".

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
/// Strictly older than any `now_attestable_rfc3339()`: a local row stamped
/// with it LOSES the LWW tiebreak to the attested push.
const T_OLD: &str = "2026-01-01T00:00:00.000000Z";
/// Far in the future: a local row stamped with it WINS the LWW tiebreak (the
/// receive clamp caps only the INBOUND `updated_at`, never the local one).
const T_FUTURE: &str = "2099-01-01T00:00:00.000000Z";

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

/// A wire row signed by `kp` exactly as the authoring node would sign it,
/// stamped `created_at = updated_at = created`.
fn signed_wire(
    kp: &ai_memory::identity::keypair::AgentKeypair,
    id: &str,
    ns: &str,
    title: &str,
    author: &str,
    created: &str,
) -> Value {
    let mut value = memory_json(id, ns, title, "attested peer text", author, created);
    let memory: ai_memory::models::Memory = serde_json::from_value(value.clone()).expect("memory");
    let sig = ai_memory::identity::attest::sign_memory_write(kp, &memory, author).expect("sign");
    value["metadata"]["write_signature"] =
        json!(base64::engine::general_purpose::STANDARD.encode(sig));
    value
}

/// Seed a local row (`created_at = created`, `agent_id = claimant`, text
/// `"local unattested text"`) and move it to `quarantined` with a raw UPDATE
/// (the route-IN lane's write), stamping `updated_at`.
#[allow(clippy::too_many_arguments)]
async fn seed_quarantined(
    backend: &Backend,
    db: &Db,
    store: &Arc<dyn MemoryStore>,
    id: &str,
    ns: &str,
    title: &str,
    claimant: &str,
    created: &str,
    updated_at: &str,
) {
    let m: ai_memory::models::Memory =
        serde_json::from_value(memory_json(id, ns, title, LOCAL_TEXT, claimant, created))
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
                    rusqlite::params![updated_at, id],
                )
                .expect("quarantine");
            assert_eq!(n, 1);
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(_) => {
            store
                .store(&CallerContext::for_agent(claimant), &m)
                .await
                .expect("seed");
            let n = sqlx::query(
                "UPDATE memories SET lifecycle_state = 'quarantined', \
                 updated_at = $1::timestamptz WHERE id = $2",
            )
            .bind(updated_at)
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

const LOCAL_TEXT: &str = "local unattested text";

/// Raw stored `content` of a row by id (the lifecycle-filtered read paths
/// hide a quarantined row; at-rest encryption is off in this harness).
async fn content(backend: &Backend, db: &Db, store: &Arc<dyn MemoryStore>, id: &str) -> String {
    let _ = store; // read by the pg arm only
    match backend {
        Backend::Sqlite => {
            let lock = db.lock().await;
            lock.0
                .query_row("SELECT content FROM memories WHERE id = ?1", [id], |r| {
                    r.get(0)
                })
                .expect("content")
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(_) => {
            sqlx::query_scalar::<_, String>("SELECT content FROM memories WHERE id = $1")
                .bind(id)
                .fetch_one(pg_store(store).pool())
                .await
                .expect("content")
        }
    }
}

/// THE DEFECT (#4017), LWW loser: the local quarantined row is NEWER than the
/// attested push, so `merge_memory` keeps the LOCAL unattested text. The row
/// the funnel would release is not the row the attestation covered.
async fn lww_loser_keeps_same_id_row_quarantined(backend: &Backend) {
    let _posture = Posture::zero_config();
    let author = uniq("ai:author-4017");
    let ns = uniq("team/q4017");
    let (x, title) = (uniq("x"), uniq("t"));
    let (router, store, db) = router(backend).await;
    let kp = enroll(backend, &db, &store, &author).await;
    let created = ai_memory::identity::attest::now_attestable_rfc3339();
    seed_quarantined(
        backend, &db, &store, &x, &ns, &title, &author, &created, T_FUTURE,
    )
    .await;

    let (status, report) = push(
        &router,
        &author,
        signed_wire(&kp, &x, &ns, &title, &author, &created),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(
        report["applied"], 1,
        "the attested push must still apply (quarantine preserved, push not refused): {report}"
    );
    assert_eq!(
        content(backend, &db, &store, &x).await,
        LOCAL_TEXT,
        "precondition: the local row won LWW, so the stored text is the local one"
    );
    assert_eq!(
        state(backend, &db, &store, &x).await.as_deref(),
        Some("quarantined"),
        "#4017: the stored text was never attested — same id must not release it"
    );
}

/// THE DEFECT (#4017), attribution: the inbound wins the text, but the local
/// row's `agent_id` is immutable-to-local, so the stored row pairs the signed
/// text with an attribution the signature never covered.
async fn foreign_attribution_keeps_same_id_row_quarantined(backend: &Backend) {
    let _posture = Posture::zero_config();
    let author = uniq("ai:author-4017");
    let claimant = uniq("ai:claimant-4017");
    let ns = uniq("team/q4017");
    let (x, title) = (uniq("x"), uniq("t"));
    let (router, store, db) = router(backend).await;
    let kp = enroll(backend, &db, &store, &author).await;
    let created = ai_memory::identity::attest::now_attestable_rfc3339();
    seed_quarantined(
        backend, &db, &store, &x, &ns, &title, &claimant, &created, T_OLD,
    )
    .await;

    let (status, report) = push(
        &router,
        &author,
        signed_wire(&kp, &x, &ns, &title, &author, &created),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(report["applied"], 1, "{report}");
    assert_eq!(
        content(backend, &db, &store, &x).await,
        "attested peer text",
        "precondition: the attested push won the text"
    );
    assert_eq!(
        state(backend, &db, &store, &x).await.as_deref(),
        Some("quarantined"),
        "#4017: the stored row keeps the local claimant as agent_id — not the signed unit"
    );
}

/// THE DEFECT (#4017), genesis: the quarantined row shares the id but carries
/// an EARLIER `created_at`; `created_at` is min-merged, so the stored row
/// keeps the local genesis the signature never covered (a distinct unit).
async fn foreign_genesis_keeps_same_id_row_quarantined(backend: &Backend) {
    let _posture = Posture::zero_config();
    let author = uniq("ai:author-4017");
    let ns = uniq("team/q4017");
    let (x, title) = (uniq("x"), uniq("t"));
    let (router, store, db) = router(backend).await;
    let kp = enroll(backend, &db, &store, &author).await;
    seed_quarantined(backend, &db, &store, &x, &ns, &title, &author, T_OLD, T_OLD).await;

    let created = ai_memory::identity::attest::now_attestable_rfc3339();
    let (status, report) = push(
        &router,
        &author,
        signed_wire(&kp, &x, &ns, &title, &author, &created),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(report["applied"], 1, "{report}");
    assert_eq!(
        state(backend, &db, &store, &x).await.as_deref(),
        Some("quarantined"),
        "#4017: the stored row keeps the local created_at — not the signed unit"
    );
}

/// CONTROL: the same signed unit (same `created_at`, same author) arriving
/// newer than the quarantined copy IS released (#1948 route-OUT unchanged).
async fn attested_unit_still_dequarantines(backend: &Backend) {
    let _posture = Posture::zero_config();
    let author = uniq("ai:author-4017");
    let ns = uniq("team/q4017");
    let (x, title) = (uniq("x"), uniq("t"));
    let (router, store, db) = router(backend).await;
    let kp = enroll(backend, &db, &store, &author).await;
    let created = ai_memory::identity::attest::now_attestable_rfc3339();
    seed_quarantined(
        backend, &db, &store, &x, &ns, &title, &author, &created, T_OLD,
    )
    .await;

    let (status, report) = push(
        &router,
        &author,
        signed_wire(&kp, &x, &ns, &title, &author, &created),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(report["applied"], 1, "{report}");
    assert_eq!(
        state(backend, &db, &store, &x).await.as_deref(),
        Some("open"),
        "#1948 route-OUT: the stored row IS the attested unit, so it is released"
    );
    assert_eq!(
        content(backend, &db, &store, &x).await,
        "attested peer text"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_lww_loser_keeps_same_id_row_quarantined_4017() {
    let _g = FED_ENV_LOCK.lock().await;
    lww_loser_keeps_same_id_row_quarantined(&Backend::Sqlite).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_foreign_attribution_keeps_same_id_row_quarantined_4017() {
    let _g = FED_ENV_LOCK.lock().await;
    foreign_attribution_keeps_same_id_row_quarantined(&Backend::Sqlite).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_foreign_genesis_keeps_same_id_row_quarantined_4017() {
    let _g = FED_ENV_LOCK.lock().await;
    foreign_genesis_keeps_same_id_row_quarantined(&Backend::Sqlite).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_attested_unit_still_dequarantines_4017() {
    let _g = FED_ENV_LOCK.lock().await;
    attested_unit_still_dequarantines(&Backend::Sqlite).await;
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{
        Backend, FED_ENV_LOCK, attested_unit_still_dequarantines,
        foreign_attribution_keeps_same_id_row_quarantined,
        foreign_genesis_keeps_same_id_row_quarantined, lww_loser_keeps_same_id_row_quarantined,
    };

    fn pg_backend() -> Backend {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .expect("own PG URL required (AI_MEMORY_TEST_POSTGRES_URL); no soft skip");
        Backend::Postgres(url)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_lww_loser_keeps_same_id_row_quarantined_4017() {
        let _g = FED_ENV_LOCK.lock().await;
        lww_loser_keeps_same_id_row_quarantined(&pg_backend()).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_foreign_attribution_keeps_same_id_row_quarantined_4017() {
        let _g = FED_ENV_LOCK.lock().await;
        foreign_attribution_keeps_same_id_row_quarantined(&pg_backend()).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_foreign_genesis_keeps_same_id_row_quarantined_4017() {
        let _g = FED_ENV_LOCK.lock().await;
        foreign_genesis_keeps_same_id_row_quarantined(&pg_backend()).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_attested_unit_still_dequarantines_4017() {
        let _g = FED_ENV_LOCK.lock().await;
        attested_unit_still_dequarantines(&pg_backend()).await;
    }
}
