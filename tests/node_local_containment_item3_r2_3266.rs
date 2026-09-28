// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Boids item 3 part 5 (R2) — #3266 / #3750 / #3905, ruling tmux-22
//! (variant B): containment is a NODE-LOCAL overlay.
//!
//! * R2.1 — a LOCAL `contaminated` / `quarantined` row is never replaced by a
//!   peer write (the merge predicate + both upsert CASE arms);
//! * R2.2 — the sqlite same-id receive lane reads via `get_any`, so a hidden
//!   local row reaches the merge (and keeps its `metadata.contamination`);
//! * R2.3 — a WIRE `contaminated` / `quarantined` lifecycle lands `open` and a
//!   wire `metadata.contamination` marker is never adopted, both for a fresh
//!   row and over an existing one — normalised BEFORE the #1948 route-IN
//!   verdict, which therefore still quarantines over an existing row;
//! * R2.5 — the operator release (`operator_dequarantine`) also DECONTAMINATES:
//!   the recorded prior visible state is restored (else `open`), the marker is
//!   removed, and ONE signed `swarm.decontaminate` event binds the released
//!   marker; a row that is neither contaminated nor quarantined is refused
//!   with zero writes and no event; the quarantined release keeps
//!   `memory.dequarantined` unchanged.
//!
//! Every cell runs on sqlite and — with `AI_MEMORY_TEST_POSTGRES_URL` set —
//! on live postgres, through the production `/sync/push` router (receive
//! cells) or the backend release primitive the admin route and CLI call.

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
const MARKER: &str = "contamination";
const T_OLD: &str = "2026-09-15T10:00:01.000000Z";
const T_NEW: &str = "2026-09-15T10:00:05.000000Z";

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

/// Receive posture (the #3699 harness): sig gate off, body sender trusted, the
/// peer scoped to its namespace; the #1948 route-IN knob set explicitly.
/// Restored on Drop (also on panic).
struct Posture([(&'static str, Option<std::ffi::OsString>); 6]);

impl Posture {
    fn new(peer: &str, namespace: &str, quarantine_unattributed: bool) -> Self {
        use ai_memory::federation::peer_attestation::{
            PEER_ATTESTATION_ENV, TRUST_BODY_AGENT_ID_ENV,
        };
        use ai_memory::federation::receive_auth::{
            FED_QUARANTINE_UNATTRIBUTED_ENV, REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
        };
        use ai_memory::federation::signing::REQUIRE_SIG_ENV;
        const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
        let keys = [
            PEER_ATTESTATION_ENV,
            REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            REQUIRE_SIG_ENV,
            TRUST_BODY_AGENT_ID_ENV,
            REQUIRE_ATTEST_ENV,
            FED_QUARANTINE_UNATTRIBUTED_ENV,
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
            if quarantine_unattributed {
                std::env::set_var(FED_QUARANTINE_UNATTRIBUTED_ENV, "1");
            } else {
                std::env::remove_var(FED_QUARANTINE_UNATTRIBUTED_ENV);
            }
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

/// A production router over the chosen backend plus the SAL handle and the
/// sqlite connection the assertions read through.
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

fn memory_json(
    id: &str,
    ns: &str,
    title: &str,
    content: &str,
    peer: &str,
    updated_at: &str,
) -> Value {
    json!({
        "id": id,
        "tier": "long",
        "namespace": ns,
        "title": title,
        "content": content,
        "tags": ["r2-3266"],
        "priority": 5,
        "confidence": 1.0,
        "source": "nhi",
        "access_count": 0,
        "created_at": "2026-09-15T10:00:00.000000Z",
        "updated_at": updated_at,
        "lifecycle_state": "open",
        "metadata": {"agent_id": peer}
    })
}

/// A wire row carrying a node-local overlay state AND a contamination marker
/// (a hand-crafted push — the send lanes never ship a hidden row).
fn tainted_wire(mut row: Value, state: &str) -> Value {
    row["lifecycle_state"] = json!(state);
    row["metadata"][MARKER] = json!({
        "prior_lifecycle_state": "done",
        "contaminated_from": "peer-root",
        "stamped_at": "2026-09-15T10:00:04+00:00",
    });
    row
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

/// `(content, lifecycle_state, metadata, version)` of a row by id.
#[derive(Debug)]
struct Row {
    content: String,
    state: String,
    metadata: Value,
    version: i64,
    updated_at: String,
}

#[allow(unused_variables)] // `store` is read by the pg arm only
async fn row(backend: &Backend, db: &Db, store: &Arc<dyn MemoryStore>, id: &str) -> Option<Row> {
    match backend {
        Backend::Sqlite => {
            let guard = db.lock().await;
            guard
                .0
                .query_row(
                    "SELECT content, lifecycle_state, metadata, version, updated_at \
                     FROM memories WHERE id = ?1",
                    [id],
                    |r| {
                        let meta: String = r.get(2)?;
                        Ok(Row {
                            content: r.get(0)?,
                            state: r.get(1)?,
                            metadata: serde_json::from_str(&meta).unwrap_or(Value::Null),
                            version: r.get(3)?,
                            updated_at: r.get(4)?,
                        })
                    },
                )
                .ok()
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(_) => {
            let pg = pg_store(store);
            sqlx::query_as::<_, (String, String, Value, i64, chrono::DateTime<chrono::Utc>)>(
                "SELECT content, lifecycle_state, metadata, version::bigint, updated_at \
                 FROM memories WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(pg.pool())
            .await
            .expect("query")
            .map(|(content, state, metadata, version, updated_at)| Row {
                content,
                state,
                metadata,
                version,
                updated_at: updated_at.to_rfc3339(),
            })
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

/// Seed a LIVE local row on the backend (`updated_at` = `T_OLD`).
#[allow(unused_variables)] // `store` is read by the pg arm only
async fn seed_open(
    backend: &Backend,
    db: &Db,
    store: &Arc<dyn MemoryStore>,
    id: &str,
    ns: &str,
    title: &str,
    peer: &str,
) {
    let m: ai_memory::models::Memory =
        serde_json::from_value(memory_json(id, ns, title, "local text", peer, T_OLD))
            .expect("memory");
    match backend {
        Backend::Sqlite => {
            let guard = db.lock().await;
            ai_memory::db::insert(&guard.0, &m).expect("seed");
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(_) => {
            store
                .store(&ai_memory::store::CallerContext::for_agent(peer), &m)
                .await
                .expect("seed");
        }
    }
}

/// Move a seeded row into `state` with `metadata` (the raw UPDATE the stamp /
/// route-IN lanes use), keeping `updated_at = T_OLD` so any peer write is
/// strictly newer.
#[allow(unused_variables)] // `store` is read by the pg arm only
async fn force_state(
    backend: &Backend,
    db: &Db,
    store: &Arc<dyn MemoryStore>,
    id: &str,
    state: &str,
    metadata: &Value,
) {
    match backend {
        Backend::Sqlite => {
            let guard = db.lock().await;
            let n = guard
                .0
                .execute(
                    "UPDATE memories SET lifecycle_state = ?1, metadata = ?2, updated_at = ?3 \
                     WHERE id = ?4",
                    rusqlite::params![state, metadata.to_string(), T_OLD, id],
                )
                .expect("force state");
            assert_eq!(n, 1);
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(_) => {
            let n = sqlx::query(
                "UPDATE memories SET lifecycle_state = $1, metadata = $2, \
                 updated_at = $3::timestamptz WHERE id = $4",
            )
            .bind(state)
            .bind(metadata)
            .bind(T_OLD)
            .bind(id)
            .execute(pg_store(store).pool())
            .await
            .expect("force state")
            .rows_affected();
            assert_eq!(n, 1);
        }
    }
}

fn local_marker(prior: &str) -> Value {
    json!({
        "prior_lifecycle_state": prior,
        "contaminated_from": "local-root",
        "stamped_at": "2026-09-15T10:00:01+00:00",
    })
}

// ---------------------------------------------------------------------------
// Receive cells (R2.1 / R2.2 / R2.3)
// ---------------------------------------------------------------------------

/// A LOCAL taint survives a strictly-newer remote CLEAN row for the same id:
/// the row stays `contaminated` and keeps its local marker (the restore
/// anchor); the peer's content still merges (the text converges).
async fn local_taint_survives_remote_clean_row(backend: &Backend) {
    let peer = uniq("ai:peer-r2");
    let ns = uniq("r2-3266");
    let (id, title) = (uniq("a"), uniq("t"));
    let _posture = Posture::new(&peer, &ns, false);
    let (router, store, db) = router(backend).await;
    seed_open(backend, &db, &store, &id, &ns, &title, &peer).await;
    let meta = json!({"agent_id": peer, MARKER: local_marker("active")});
    force_state(backend, &db, &store, &id, "contaminated", &meta).await;

    let clean = memory_json(&id, &ns, &title, "peer text", &peer, T_NEW);
    let (status, report) = push(&router, &peer, vec![clean]).await;
    assert!(status.is_success(), "{status} {report}");
    let got = row(backend, &db, &store, &id).await.expect("row kept");
    assert_eq!(
        got.state, "contaminated",
        "a peer's newer clean row must not clear the local taint: {got:?}"
    );
    assert_eq!(
        got.metadata[MARKER]["prior_lifecycle_state"], "active",
        "the local contamination marker (restore anchor) survives: {got:?}"
    );
    assert_eq!(got.metadata[MARKER]["contaminated_from"], "local-root");
}

/// A REMOTE taint is not adopted for a FRESH row: a wire `contaminated` (and a
/// wire `quarantined`) row lands `open`, with no `contamination` key.
async fn remote_taint_not_adopted_fresh_row(backend: &Backend) {
    let peer = uniq("ai:peer-r2");
    let ns = uniq("r2-3266");
    let _posture = Posture::new(&peer, &ns, false);
    let (router, store, db) = router(backend).await;
    for state in ["contaminated", "quarantined"] {
        let (id, title) = (uniq("f"), uniq("t"));
        let wire = tainted_wire(
            memory_json(&id, &ns, &title, "peer text", &peer, T_NEW),
            state,
        );
        let (status, report) = push(&router, &peer, vec![wire]).await;
        assert!(status.is_success(), "{state}: {status} {report}");
        assert_eq!(report["applied"].as_i64(), Some(1), "{state}: {report}");
        let got = row(backend, &db, &store, &id).await.expect("row landed");
        assert_eq!(got.state, "open", "wire {state} must land open: {got:?}");
        assert!(
            got.metadata.get(MARKER).is_none(),
            "wire {state}: a remote contamination marker is never adopted: {got:?}"
        );
        assert_eq!(got.content, "peer text", "the bytes still converge");
    }
}

/// A REMOTE taint is not adopted over an EXISTING local row: the local row
/// stays `open` with no marker, while the newer peer text still merges.
async fn remote_taint_not_adopted_existing_row(backend: &Backend) {
    let peer = uniq("ai:peer-r2");
    let ns = uniq("r2-3266");
    let _posture = Posture::new(&peer, &ns, false);
    let (router, store, db) = router(backend).await;
    for state in ["contaminated", "quarantined"] {
        let (id, title) = (uniq("e"), uniq("t"));
        seed_open(backend, &db, &store, &id, &ns, &title, &peer).await;
        let wire = tainted_wire(
            memory_json(&id, &ns, &title, "peer text", &peer, T_NEW),
            state,
        );
        let (status, report) = push(&router, &peer, vec![wire]).await;
        assert!(status.is_success(), "{state}: {status} {report}");
        let got = row(backend, &db, &store, &id).await.expect("row kept");
        assert_eq!(
            got.state, "open",
            "wire {state} must not be adopted: {got:?}"
        );
        assert!(
            got.metadata.get(MARKER).is_none(),
            "wire {state}: the peer's marker is never adopted: {got:?}"
        );
        assert_eq!(got.content, "peer text", "the newer peer text still merges");
    }
}

/// #1948 is NOT disabled by R2: with the route-IN knob on, an unattributed
/// (claimed) newer push over an EXISTING live row still quarantines it — the
/// normalisation runs BEFORE the verdict, and the merge keys its refusal on
/// the LOCAL state (spec R2.3).
async fn route_in_quarantine_still_applies_over_existing_row(backend: &Backend) {
    let peer = uniq("ai:peer-r2");
    let ns = uniq("r2-3266");
    let (id, title) = (uniq("q"), uniq("t"));
    let _posture = Posture::new(&peer, &ns, true);
    let (router, store, db) = router(backend).await;
    seed_open(backend, &db, &store, &id, &ns, &title, &peer).await;
    let inbound = memory_json(&id, &ns, &title, "peer text", &peer, T_NEW);
    let (status, report) = push(&router, &peer, vec![inbound]).await;
    assert!(status.is_success(), "{status} {report}");
    let got = row(backend, &db, &store, &id).await.expect("row kept");
    assert_eq!(
        got.state, "quarantined",
        "the #1948 route-IN verdict must still quarantine over an existing row: {got:?}"
    );
}

// ---------------------------------------------------------------------------
// Release cells (R2.5)
// ---------------------------------------------------------------------------

/// `(event_type, payload_hash, timestamp)` of every chain row by `agent_id`.
#[allow(unused_variables)] // `store` is read by the pg arm only
async fn events(
    backend: &Backend,
    db: &Db,
    store: &Arc<dyn MemoryStore>,
    agent_id: &str,
) -> Vec<(String, Vec<u8>, String)> {
    match backend {
        Backend::Sqlite => {
            let guard = db.lock().await;
            let mut stmt = guard
                .0
                .prepare(
                    "SELECT event_type, payload_hash, timestamp FROM signed_events \
                     WHERE agent_id = ?1 ORDER BY sequence",
                )
                .expect("prepare");
            stmt.query_map([agent_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .expect("query")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("rows")
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(_) => {
            sqlx::query_as::<_, (String, Vec<u8>, chrono::DateTime<chrono::Utc>)>(
                "SELECT event_type, payload_hash, timestamp FROM signed_events \
             WHERE agent_id = $1 ORDER BY sequence",
            )
            .bind(agent_id)
            .fetch_all(pg_store(store).pool())
            .await
            .expect("events")
            .into_iter()
            .map(|(t, h, ts)| (t, h, ts.to_rfc3339()))
            .collect()
        }
    }
}

/// The release primitive the admin route and the CLI call, per backend.
#[allow(unused_variables)] // `store` is read by the pg arm only
async fn release(
    backend: &Backend,
    db: &Db,
    store: &Arc<dyn MemoryStore>,
    id: &str,
    operator: &str,
) -> bool {
    match backend {
        Backend::Sqlite => {
            let mut guard = db.lock().await;
            ai_memory::db::operator_dequarantine(&mut guard.0, id, operator).expect("release")
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(_) => store
            .operator_dequarantine(
                &ai_memory::store::CallerContext::for_admin(operator.to_string()),
                id,
            )
            .await
            .expect("release"),
    }
}

/// The canonical `swarm.decontaminate` payload an auditor recomputes from the
/// released marker + the event row (same key order as the writer).
fn expected_decontaminate_payload(
    id: &str,
    restored_to: &str,
    marker: &Value,
    released_by: &str,
    timestamp: &str,
) -> Vec<u8> {
    let canonical = json!({
        "action": "swarm.decontaminate",
        "memory_id": id,
        "restored_to": restored_to,
        "prior_lifecycle_state": marker.get("prior_lifecycle_state"),
        "contaminated_from": marker.get("contaminated_from"),
        "stamped_at": marker.get("stamped_at"),
        "released_by": released_by,
        "timestamp": timestamp,
    });
    ai_memory::signed_events::payload_hash(&serde_json::to_vec(&canonical).expect("payload"))
}

/// Decontaminate restores the recorded prior VISIBLE state (else `open`),
/// removes `metadata.contamination`, and appends ONE signed
/// `swarm.decontaminate` event whose payload binds the released marker.
async fn decontaminate_restores_prior_and_emits_signed_event(backend: &Backend) {
    let peer = uniq("ai:peer-r2");
    let ns = uniq("r2-3266");
    let (router_unused, store, db) = router(backend).await;
    drop(router_unused);
    for (prior, expect) in [("blocked", "blocked"), ("tombstoned", "open")] {
        let (id, title) = (uniq("d"), uniq("t"));
        seed_open(backend, &db, &store, &id, &ns, &title, &peer).await;
        let marker = local_marker(prior);
        let meta = json!({"agent_id": peer, "keep": 1, MARKER: marker});
        force_state(backend, &db, &store, &id, "contaminated", &meta).await;
        let before = row(backend, &db, &store, &id).await.expect("row");
        let operator = uniq("operator");

        assert!(
            release(backend, &db, &store, &id, &operator).await,
            "{prior}: released"
        );
        let got = row(backend, &db, &store, &id).await.expect("row");
        assert_eq!(got.state, expect, "prior {prior} -> {expect}: {got:?}");
        assert!(
            got.metadata.get(MARKER).is_none(),
            "marker removed: {got:?}"
        );
        assert_eq!(got.metadata["keep"], 1, "other metadata untouched: {got:?}");
        assert_eq!(
            got.content, before.content,
            "the durable text is never touched"
        );
        assert_eq!(got.version, before.version + 1);

        let evs = events(backend, &db, &store, &operator).await;
        assert_eq!(evs.len(), 1, "{prior}: exactly one chain row: {evs:?}");
        let (kind, hash, ts) = &evs[0];
        assert_eq!(kind, "swarm.decontaminate");
        assert_eq!(
            *hash,
            expected_decontaminate_payload(&id, expect, &marker, &operator, ts),
            "{prior}: the payload binds prior / contaminated_from / stamped_at"
        );

        // Idempotent: a second release is a no-op with no second event.
        assert!(!release(backend, &db, &store, &id, &operator).await);
        assert_eq!(events(backend, &db, &store, &operator).await.len(), 1);
    }
}

/// A row that is neither contaminated nor quarantined is REFUSED: `false`,
/// zero writes (state / metadata / version / `updated_at` unchanged), no event.
async fn release_of_non_contained_row_is_refused(backend: &Backend) {
    let peer = uniq("ai:peer-r2");
    let ns = uniq("r2-3266");
    let (router_unused, store, db) = router(backend).await;
    drop(router_unused);
    for state in ["open", "done", "tombstoned"] {
        let (id, title) = (uniq("n"), uniq("t"));
        seed_open(backend, &db, &store, &id, &ns, &title, &peer).await;
        // A stale marker on a non-contained row must not be read as a taint.
        let meta = json!({"agent_id": peer, MARKER: local_marker("done")});
        force_state(backend, &db, &store, &id, state, &meta).await;
        let before = row(backend, &db, &store, &id).await.expect("row");
        let operator = uniq("operator");
        assert!(
            !release(backend, &db, &store, &id, &operator).await,
            "{state}: must be refused"
        );
        let after = row(backend, &db, &store, &id).await.expect("row");
        assert_eq!(after.state, before.state, "{state}: zero writes");
        assert_eq!(after.metadata, before.metadata, "{state}: zero writes");
        assert_eq!(after.version, before.version, "{state}: zero writes");
        assert_eq!(after.updated_at, before.updated_at, "{state}: zero writes");
        assert!(
            events(backend, &db, &store, &operator).await.is_empty(),
            "{state}: no event"
        );
    }
    // An absent id is refused the same way.
    let operator = uniq("operator");
    assert!(!release(backend, &db, &store, &uniq("missing"), &operator).await);
    assert!(events(backend, &db, &store, &operator).await.is_empty());
}

/// The QUARANTINED release keeps `memory.dequarantined` unchanged: `open`,
/// the historical payload `kind|id|agent`, and no `swarm.decontaminate`.
async fn quarantined_release_keeps_memory_dequarantined(backend: &Backend) {
    let peer = uniq("ai:peer-r2");
    let ns = uniq("r2-3266");
    let (router_unused, store, db) = router(backend).await;
    drop(router_unused);
    let (id, title) = (uniq("qr"), uniq("t"));
    seed_open(backend, &db, &store, &id, &ns, &title, &peer).await;
    force_state(
        backend,
        &db,
        &store,
        &id,
        "quarantined",
        &json!({"agent_id": peer}),
    )
    .await;
    let operator = uniq("operator");
    assert!(release(backend, &db, &store, &id, &operator).await);
    assert_eq!(
        row(backend, &db, &store, &id).await.expect("row").state,
        "open"
    );
    let evs = events(backend, &db, &store, &operator).await;
    assert_eq!(evs.len(), 1, "{evs:?}");
    assert_eq!(evs[0].0, "memory.dequarantined");
    assert_eq!(
        evs[0].1,
        ai_memory::signed_events::payload_hash(
            format!("memory.dequarantined|{id}|{operator}").as_bytes()
        ),
        "the #2402 payload is byte-unchanged"
    );
}

// ---------------------------------------------------------------------------
// f1 goal4 FB (#3266, GOD ruling on the landing candidate) — the title-slot
// (different-id, same (title, namespace)) newer-wins upsert arm on BOTH
// adapters keeps the LOCAL node-local metadata keys and never adopts a peer's.
// ---------------------------------------------------------------------------

/// f1's `PROBE_TITLE`: a newer peer row with a DIFFERENT id and the SAME title
/// lands on a contaminated local holder. The holder stays contaminated AND
/// keeps its marker (the restore anchor), so a later release restores the
/// recorded prior state (`active`), not the `open` fallback.
async fn title_slot_keeps_local_marker_then_release_restores_prior(backend: &Backend) {
    let peer = uniq("ai:peer-fb");
    let ns = uniq("r2-fb");
    let (id, title) = (uniq("holder"), uniq("t"));
    let _posture = Posture::new(&peer, &ns, false);
    let (router, store, db) = router(backend).await;
    seed_open(backend, &db, &store, &id, &ns, &title, &peer).await;
    let marker = local_marker("active");
    let meta = json!({"agent_id": peer, MARKER: marker});
    force_state(backend, &db, &store, &id, "contaminated", &meta).await;

    let wire = memory_json(&uniq("other-id"), &ns, &title, "peer text", &peer, T_NEW);
    let (status, report) = push(&router, &peer, vec![wire]).await;
    assert!(status.is_success(), "{status} {report}");
    let got = row(backend, &db, &store, &id).await.expect("holder kept");
    assert_eq!(got.state, "contaminated", "{got:?}");
    assert_eq!(
        got.metadata[MARKER], marker,
        "the title-slot newer-wins arm must keep the local marker: {got:?}"
    );
    let operator = uniq("operator");
    assert!(release(backend, &db, &store, &id, &operator).await);
    let released = row(backend, &db, &store, &id).await.expect("row");
    assert_eq!(
        released.state, "active",
        "release restores the recorded prior, not the open fallback: {released:?}"
    );
}

/// Upsert one peer row through the adapter's title-slot newer-wins arm
/// directly (below the receive normalisation).
#[allow(unused_variables)] // `store` is read by the pg arm only
async fn upsert_peer_row(
    backend: &Backend,
    db: &Db,
    store: &Arc<dyn MemoryStore>,
    peer: &str,
    wire: Value,
) {
    let m: ai_memory::models::Memory = serde_json::from_value(wire).expect("memory");
    match backend {
        Backend::Sqlite => {
            let guard = db.lock().await;
            ai_memory::db::insert_if_newer(&guard.0, &m).expect("upsert");
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(_) => {
            store
                .apply_remote_memory(&ai_memory::store::CallerContext::for_agent(peer), &m)
                .await
                .expect("upsert");
        }
    }
}

/// EACH of the four node-local keys (`crdt_merge::NODE_LOCAL_METADATA_KEYS`:
/// `contamination` + the three G7 `contradiction_*`) is kept from the LOCAL
/// holder by the title-slot newer-wins arm, and a peer's value for each is
/// never adopted — on a holder that has them and on one that has none.
async fn title_slot_never_adopts_peer_node_local_keys(backend: &Backend) {
    let peer = uniq("ai:peer-fb");
    let ns = uniq("r2-fb");
    let (_router, store, db) = router(backend).await;
    let local_values = json!({
        "contamination": {"prior_lifecycle_state": "active", "contaminated_from": "local-root"},
        "contradiction_conserved": "local-conserved",
        "contradiction_soft_loser": true,
        "contradiction_winner_id": "local-winner",
    });
    let peer_values = json!({
        "contamination": {"prior_lifecycle_state": "done", "contaminated_from": "peer-root"},
        "contradiction_conserved": "peer-conserved",
        "contradiction_soft_loser": false,
        "contradiction_winner_id": "peer-winner",
    });
    for local_has_keys in [true, false] {
        let (id, title) = (uniq("holder"), uniq("t"));
        seed_open(backend, &db, &store, &id, &ns, &title, &peer).await;
        let mut local_meta = json!({"agent_id": peer});
        if local_has_keys {
            for (k, v) in local_values.as_object().expect("object") {
                local_meta[k] = v.clone();
            }
        }
        force_state(backend, &db, &store, &id, "open", &local_meta).await;
        let mut wire = memory_json(&uniq("other-id"), &ns, &title, "peer text", &peer, T_NEW);
        wire["metadata"] = json!({"agent_id": peer, "peer_note": 1});
        for (k, v) in peer_values.as_object().expect("object") {
            wire["metadata"][k] = v.clone();
        }
        upsert_peer_row(backend, &db, &store, &peer, wire).await;
        let got = row(backend, &db, &store, &id).await.expect("holder kept");
        assert_eq!(
            got.content, "peer text",
            "the newer peer row still wins: {got:?}"
        );
        assert_eq!(
            got.metadata["peer_note"], 1,
            "ordinary keys still merge: {got:?}"
        );
        for key in [
            "contamination",
            "contradiction_conserved",
            "contradiction_soft_loser",
            "contradiction_winner_id",
        ] {
            if local_has_keys {
                assert_eq!(
                    got.metadata.get(key),
                    local_values.get(key),
                    "local {key} must survive: {got:?}"
                );
            } else {
                assert!(
                    got.metadata.get(key).is_none(),
                    "peer {key} must never be adopted: {got:?}"
                );
            }
        }
    }
}

/// The G7 soft-loser down-weight SURVIVES a title-slot peer push, as a RANKING
/// effect (not only key presence): a conserved loser that out-ranks its
/// winner on priority stays BELOW the winner after a newer different-id peer
/// row lands on the loser's slot. Without the fix the key is dropped, the
/// scoring CASE takes its no-penalty arm, and the loser silently wins.
#[allow(unused_variables)] // `store` is read by the pg arm only
async fn soft_loser_rank_survives_title_slot_peer_push(backend: &Backend) {
    let peer = uniq("ai:peer-g7");
    let tok = format!("g7tok{}", uniq("x").replace('-', ""));
    let (loser_ns, winner_ns) = (uniq("g7-loser"), uniq("g7-winner"));
    let _posture = Posture::new(&peer, &loser_ns, false);
    let (router, store, db) = router(backend).await;
    let title = format!("directive {tok}");
    let content = format!("the canonical {tok}");
    let mk = |id: &str, ns: &str, priority: i32, loser: bool| {
        let mut v = memory_json(id, ns, &title, &content, &peer, T_OLD);
        v["priority"] = json!(priority);
        if loser {
            v["metadata"]["contradiction_soft_loser"] = json!(true);
        }
        let m: ai_memory::models::Memory = serde_json::from_value(v).expect("memory");
        m
    };
    let (loser, winner) = (uniq("loser"), uniq("winner"));
    for m in [
        mk(&loser, &loser_ns, 9, true),
        mk(&winner, &winner_ns, 2, false),
    ] {
        match backend {
            Backend::Sqlite => {
                let guard = db.lock().await;
                ai_memory::db::insert(&guard.0, &m).expect("seed");
            }
            #[cfg(feature = "sal-postgres")]
            Backend::Postgres(_) => {
                store
                    .store(&ai_memory::store::CallerContext::for_agent(&peer), &m)
                    .await
                    .expect("seed");
            }
        }
    }
    let ranked = |order: Vec<String>| {
        order
            .into_iter()
            .filter(|id| *id == loser || *id == winner)
            .collect::<Vec<_>>()
    };
    let rank = || async {
        match backend {
            Backend::Sqlite => {
                let guard = db.lock().await;
                let (rows, _) = ai_memory::db::recall(
                    &guard.0,
                    &tok,
                    None,
                    10,
                    None,
                    None,
                    None,
                    ai_memory::SECS_PER_HOUR,
                    ai_memory::SECS_PER_DAY,
                    None,
                    None,
                    false,
                    None,
                    None,
                    None,
                )
                .expect("recall");
                ranked(rows.into_iter().map(|(m, _)| m.id).collect())
            }
            #[cfg(feature = "sal-postgres")]
            Backend::Postgres(_) => {
                let mut f = ai_memory::store::Filter::new();
                f.limit = 10;
                let rows = pg_store(&store)
                    .search_with_source_uri(
                        &ai_memory::store::CallerContext::for_agent(&peer),
                        &tok,
                        &f,
                        None,
                    )
                    .await
                    .expect("search");
                ranked(rows.into_iter().map(|m| m.id).collect())
            }
        }
    };
    assert_eq!(
        rank().await,
        [winner.clone(), loser.clone()],
        "precondition: the down-weight sinks the high-priority loser"
    );
    let wire = memory_json(&uniq("peer-id"), &loser_ns, &title, &content, &peer, T_NEW);
    let (status, report) = push(&router, &peer, vec![wire]).await;
    assert!(status.is_success(), "{status} {report}");
    assert_eq!(
        rank().await,
        [winner.clone(), loser.clone()],
        "a peer push must not restore a demoted soft-loser to full recall weight"
    );
    let held = row(backend, &db, &store, &loser)
        .await
        .expect("loser holder kept");
    assert_eq!(held.metadata["contradiction_soft_loser"], true, "{held:?}");
}

/// f1 goal4 FC (#3266): a caller lifecycle transition that races a raw
/// quarantine never overwrites it. SQLite: a second connection holds the
/// write lock with the row quarantined but uncommitted; the caller's
/// `set_lifecycle_state(open -> active)` blocks (the busy handler is the
/// barrier), the quarantine commits, and the caller must then observe
/// `quarantined` and refuse — the row stays quarantined.
#[test]
fn sqlite_set_lifecycle_state_never_overwrites_a_racing_quarantine_f1_goal4() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static BUSY_SEEN: AtomicBool = AtomicBool::new(false);
    fn busy(_attempt: i32) -> bool {
        BUSY_SEEN.store(true, Ordering::Release);
        std::thread::sleep(std::time::Duration::from_millis(5));
        true
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("fc.db");
    let setup = ai_memory::db::open(&path).expect("open");
    let m: ai_memory::models::Memory = serde_json::from_value(memory_json(
        "fc-row", "fc", "fc title", "body", "ai:fc", T_OLD,
    ))
    .expect("memory");
    ai_memory::db::insert(&setup, &m).expect("seed");
    drop(setup);

    let holder = ai_memory::db::open(&path).expect("holder conn");
    holder.execute_batch("BEGIN IMMEDIATE").expect("write lock");
    holder
        .execute(
            "UPDATE memories SET lifecycle_state = 'quarantined' WHERE id = 'fc-row'",
            [],
        )
        .expect("quarantine (uncommitted)");
    BUSY_SEEN.store(false, Ordering::Release);
    let caller_path = path.clone();
    let caller = std::thread::spawn(move || {
        let conn = ai_memory::db::open(&caller_path).expect("caller conn");
        conn.busy_handler(Some(busy)).expect("busy handler");
        ai_memory::db::set_lifecycle_state(
            &conn,
            "fc-row",
            ai_memory::models::LifecycleState::Active,
        )
        .map_err(|e| e.to_string())
    });
    let end = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !BUSY_SEEN.load(Ordering::Acquire) {
        assert!(std::time::Instant::now() < end, "caller never blocked");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    holder.execute_batch("COMMIT").expect("commit quarantine");
    let outcome = caller.join().expect("caller thread");
    let state: String = holder
        .query_row(
            "SELECT lifecycle_state FROM memories WHERE id = 'fc-row'",
            [],
            |r| r.get(0),
        )
        .expect("state");
    assert_eq!(
        state, "quarantined",
        "a caller transition validated against `open` overwrote a racing quarantine: {outcome:?}"
    );
    assert!(
        outcome.is_err(),
        "quarantined -> active is illegal: the caller must be refused, not silently succeed"
    );
}

macro_rules! sqlite_cells {
    ($($name:ident => $body:ident),* $(,)?) => {$(
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            let _g = FED_ENV_LOCK.lock().await;
            $body(&Backend::Sqlite).await;
        }
    )*};
}

sqlite_cells! {
    sqlite_local_taint_survives_remote_clean_row_3266 => local_taint_survives_remote_clean_row,
    sqlite_remote_taint_not_adopted_fresh_row_3266 => remote_taint_not_adopted_fresh_row,
    sqlite_remote_taint_not_adopted_existing_row_3266 => remote_taint_not_adopted_existing_row,
    sqlite_route_in_quarantine_still_applies_over_existing_row_1948 =>
        route_in_quarantine_still_applies_over_existing_row,
    sqlite_decontaminate_restores_prior_and_emits_signed_event_3266 =>
        decontaminate_restores_prior_and_emits_signed_event,
    sqlite_release_of_non_contained_row_is_refused_3266 => release_of_non_contained_row_is_refused,
    sqlite_quarantined_release_keeps_memory_dequarantined_2402 =>
        quarantined_release_keeps_memory_dequarantined,
    sqlite_title_slot_keeps_local_marker_then_release_restores_prior_f1_goal4 =>
        title_slot_keeps_local_marker_then_release_restores_prior,
    sqlite_title_slot_never_adopts_peer_node_local_keys_f1_goal4 =>
        title_slot_never_adopts_peer_node_local_keys,
    sqlite_soft_loser_rank_survives_title_slot_peer_push_f1_goal4 =>
        soft_loser_rank_survives_title_slot_peer_push,
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{
        Backend, FED_ENV_LOCK, decontaminate_restores_prior_and_emits_signed_event,
        local_taint_survives_remote_clean_row, quarantined_release_keeps_memory_dequarantined,
        release_of_non_contained_row_is_refused, remote_taint_not_adopted_existing_row,
        remote_taint_not_adopted_fresh_row, route_in_quarantine_still_applies_over_existing_row,
        soft_loser_rank_survives_title_slot_peer_push,
        title_slot_keeps_local_marker_then_release_restores_prior,
        title_slot_never_adopts_peer_node_local_keys,
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

    macro_rules! pg_cells {
        ($($name:ident => $body:ident),* $(,)?) => {$(
            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            async fn $name() {
                let _g = FED_ENV_LOCK.lock().await;
                let Some(backend) = pg_backend() else { return };
                $body(&backend).await;
            }
        )*};
    }

    pg_cells! {
        pg_local_taint_survives_remote_clean_row_3266 => local_taint_survives_remote_clean_row,
        pg_remote_taint_not_adopted_fresh_row_3266 => remote_taint_not_adopted_fresh_row,
        pg_remote_taint_not_adopted_existing_row_3266 => remote_taint_not_adopted_existing_row,
        pg_route_in_quarantine_still_applies_over_existing_row_1948 =>
            route_in_quarantine_still_applies_over_existing_row,
        pg_decontaminate_restores_prior_and_emits_signed_event_3266 =>
            decontaminate_restores_prior_and_emits_signed_event,
        pg_release_of_non_contained_row_is_refused_3266 => release_of_non_contained_row_is_refused,
        pg_quarantined_release_keeps_memory_dequarantined_2402 =>
            quarantined_release_keeps_memory_dequarantined,
        pg_title_slot_keeps_local_marker_then_release_restores_prior_f1_goal4 =>
            title_slot_keeps_local_marker_then_release_restores_prior,
        pg_title_slot_never_adopts_peer_node_local_keys_f1_goal4 =>
            title_slot_never_adopts_peer_node_local_keys,
        pg_soft_loser_rank_survives_title_slot_peer_push_f1_goal4 =>
            soft_loser_rank_survives_title_slot_peer_push,
    }
}

/// R2.5 concurrency (f1-review F2 discipline, GOD follow-up): the PG release
/// reads the row `FOR UPDATE`, deletes the marker with an atomic `jsonb -`,
/// and decides the event kind from the state read under the lock. Every
/// interleaving is deterministic: a held row lock plus a `pg_blocking_pids`
/// barrier (the `contaminated_stamp_f1_fixes_pg_item3_3266` pattern).
#[cfg(feature = "sal-postgres")]
mod pg_race {
    use super::{MARKER, local_marker, uniq};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};
    use serde_json::{Value, json};
    use std::sync::Arc;

    async fn connect() -> Option<Arc<PostgresStore>> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        Some(Arc::new(
            PostgresStore::connect(&url)
                .await
                .expect("connect postgres"),
        ))
    }

    /// A contaminated row carrying a `blocked` prior marker.
    async fn seed_contaminated(pg: &PostgresStore) -> String {
        let id = uniq("race");
        sqlx::query(
            "INSERT INTO memories (id, tier, namespace, title, content, source, \
             lifecycle_state, metadata) VALUES ($1, 'long', $2, $3, 'race body', 'test', \
             'contaminated', $4)",
        )
        .bind(&id)
        .bind(uniq("r2-race"))
        .bind(uniq("t"))
        .bind(json!({"agent_id": "ai:race", MARKER: local_marker("blocked")}))
        .execute(pg.pool())
        .await
        .expect("seed");
        id
    }

    async fn row(pg: &PostgresStore, id: &str) -> (String, Value) {
        sqlx::query_as("SELECT lifecycle_state, metadata FROM memories WHERE id = $1")
            .bind(id)
            .fetch_one(pg.pool())
            .await
            .expect("row")
    }

    async fn event_kinds(pg: &PostgresStore, agent: &str) -> Vec<String> {
        sqlx::query_scalar("SELECT event_type FROM signed_events WHERE agent_id = $1")
            .bind(agent)
            .fetch_all(pg.pool())
            .await
            .expect("events")
    }

    async fn wait_blocked_behind(pg: &PostgresStore, holder_pid: i32) {
        let end = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let blocked: i64 = sqlx::query_scalar(
                "WITH w AS (SELECT pid, pg_blocking_pids(pid) AS b FROM pg_stat_activity) \
                 SELECT count(*) FROM w WHERE $1 = ANY(w.b)",
            )
            .bind(holder_pid)
            .fetch_one(pg.pool())
            .await
            .expect("barrier probe");
            if blocked >= 1 {
                return;
            }
            assert!(tokio::time::Instant::now() < end, "barrier not reached");
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    async fn hold_row_lock(
        pg: &PostgresStore,
        id: &str,
    ) -> (sqlx::Transaction<'static, sqlx::Postgres>, i32) {
        let mut tx = pg.pool().begin().await.expect("lock tx");
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .expect("pid");
        sqlx::query("SELECT id FROM memories WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .expect("lock row");
        (tx, pid)
    }

    /// Start the release behind the held lock, run `writer` in the holder's
    /// transaction, commit it, and return the release outcome.
    async fn release_behind(
        pg: &Arc<PostgresStore>,
        id: &str,
        operator: &str,
        writer_sql: &str,
    ) -> bool {
        let (mut lock, holder) = hold_row_lock(pg, id).await;
        let handle = Arc::clone(pg);
        let (rid, op) = (id.to_string(), operator.to_string());
        let release = tokio::spawn(async move {
            handle
                .operator_dequarantine(&CallerContext::for_admin(op), &rid)
                .await
        });
        wait_blocked_behind(pg, holder).await;
        sqlx::query(writer_sql)
            .bind(id)
            .execute(&mut *lock)
            .await
            .expect("concurrent writer");
        lock.commit().await.expect("commit concurrent writer");
        release.await.expect("join").expect("release")
    }

    /// A metadata key committed by a concurrent writer while the release is
    /// blocked on the row lock SURVIVES the release (no lost update).
    #[tokio::test]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_decontaminate_preserves_concurrently_committed_metadata_3266() {
        let Some(pg) = connect().await else { return };
        let id = seed_contaminated(&pg).await;
        let operator = uniq("operator");
        let released = release_behind(
            &pg,
            &id,
            &operator,
            "UPDATE memories SET metadata = jsonb_set(metadata, '{concurrent_committed}', \
             'true'::jsonb), version = version + 1 WHERE id = $1",
        )
        .await;
        assert!(released);
        let (state, meta) = row(&pg, &id).await;
        assert_eq!(state, "blocked", "prior restored: {meta}");
        assert_eq!(
            meta.get("concurrent_committed"),
            Some(&json!(true)),
            "the concurrently committed key must survive the release: {meta}"
        );
        assert!(meta.get(MARKER).is_none(), "marker removed: {meta}");
        assert_eq!(event_kinds(&pg, &operator).await, ["swarm.decontaminate"]);
    }

    /// The event kind follows the state read UNDER THE LOCK: a concurrent
    /// writer that moves the row contaminated -> quarantined before the
    /// release acquires it yields the #2402 `memory.dequarantined` path.
    #[tokio::test]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_release_kind_follows_the_state_read_under_the_lock_3266() {
        let Some(pg) = connect().await else { return };
        let id = seed_contaminated(&pg).await;
        let operator = uniq("operator");
        let released = release_behind(
            &pg,
            &id,
            &operator,
            "UPDATE memories SET lifecycle_state = 'quarantined' WHERE id = $1",
        )
        .await;
        assert!(released, "the locked read sees quarantined and releases it");
        assert_eq!(row(&pg, &id).await.0, "open");
        assert_eq!(event_kinds(&pg, &operator).await, ["memory.dequarantined"]);
    }
}

/// f1 goal4 FA (#3266, GOD ruling on the landing candidate): the PG same-id
/// peer merge reads the row `FOR UPDATE` INSIDE its write transaction, so a
/// local rewind / release that commits while the peer is in flight is never
/// undone by a merge computed from a stale snapshot. f1's interleaving: a
/// SHARE table lock admits the peer's read but holds its write; the local op
/// then queues; `pg_blocking_pids` (transitively) proves both are waiting
/// before the lock is released.
#[cfg(feature = "sal-postgres")]
mod pg_merge_race {
    use super::{
        Backend, FED_ENV_LOCK, MARKER, Posture, T_NEW, force_state, local_marker, memory_json,
        pg_store, push, router, row, seed_open, uniq,
    };
    use ai_memory::store::postgres::PostgresStore;
    use serde_json::json;
    use std::sync::Arc;

    /// Wait until `n` backends are blocked behind `holder_pid` — directly, or
    /// queued behind a waiter that is.
    async fn wait_blocked_behind(pg: &PostgresStore, holder_pid: i32, n: i64) {
        let end = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let blocked: i64 = sqlx::query_scalar(
                "WITH w AS (SELECT pid, pg_blocking_pids(pid) AS b FROM pg_stat_activity \
                 WHERE datname = current_database()) \
                 SELECT count(*) FROM w WHERE $1 = ANY(w.b) OR EXISTS \
                 (SELECT 1 FROM w AS v WHERE v.pid = ANY(w.b) AND $1 = ANY(v.b))",
            )
            .bind(holder_pid)
            .fetch_one(pg.pool())
            .await
            .expect("barrier probe");
            if blocked >= n {
                return;
            }
            assert!(
                tokio::time::Instant::now() < end,
                "barrier not reached: {blocked}/{n}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    async fn merge_race(release_mode: bool) {
        let _g = FED_ENV_LOCK.lock().await;
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let backend = Backend::Postgres(url);
        let peer = uniq("ai:peer-race");
        let ns = uniq("race");
        let (id, title) = (uniq("local"), uniq("title"));
        let _posture = Posture::new(&peer, &ns, false);
        let (router, store, db) = router(&backend).await;
        seed_open(&backend, &db, &store, &id, &ns, &title, &peer).await;
        if release_mode {
            let meta = json!({"agent_id": peer, MARKER: local_marker("active")});
            force_state(&backend, &db, &store, &id, "contaminated", &meta).await;
        }
        let pg = pg_store(&store);
        let mut hold = pg.pool().begin().await.expect("hold tx");
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *hold)
            .await
            .expect("pid");
        sqlx::query("LOCK TABLE memories IN SHARE MODE")
            .execute(&mut *hold)
            .await
            .expect("share lock");
        let wire = memory_json(&id, &ns, &title, "new peer text", &peer, T_NEW);
        let pp = peer.clone();
        let peer_push = tokio::spawn(async move { push(&router, &pp, vec![wire]).await });
        wait_blocked_behind(pg, pid, 1).await;
        let local_store = Arc::clone(&store);
        let (rid, operator) = (id.clone(), uniq("operator"));
        let actor = operator.clone();
        let local = tokio::spawn(async move {
            let ctx = ai_memory::store::CallerContext::for_admin(actor);
            if release_mode {
                assert!(
                    local_store
                        .operator_dequarantine(&ctx, &rid)
                        .await
                        .expect("release")
                );
            } else {
                let r = local_store
                    .swarm_rewind(&ctx, &rid, 5, "memory", &[], false)
                    .await
                    .expect("rewind");
                assert!(r.root_contaminated, "{r:?}");
            }
        });
        wait_blocked_behind(pg, pid, 2).await;
        hold.commit().await.expect("release share lock");
        local.await.expect("local op");
        let (status, report) = peer_push.await.expect("peer push");
        assert!(status.is_success(), "{status} {report}");
        let got = row(&backend, &db, &store, &id).await.expect("row");
        let kinds: Vec<String> =
            sqlx::query_scalar("SELECT event_type FROM signed_events WHERE agent_id = $1")
                .bind(&operator)
                .fetch_all(pg.pool())
                .await
                .expect("events");
        if release_mode {
            assert_eq!(kinds, ["swarm.decontaminate"]);
            assert_eq!(
                got.state, "active",
                "a peer merge must not re-taint a locally released row: {got:?}"
            );
            assert!(got.metadata.get(MARKER).is_none(), "{got:?}");
        } else {
            assert_eq!(kinds, ["swarm.rewind"]);
            assert_eq!(
                got.state, "contaminated",
                "a peer merge must not clear a committed local rewind: {got:?}"
            );
            assert!(got.metadata.get(MARKER).is_some(), "{got:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_peer_merge_must_not_undo_release_f1_goal4() {
        merge_race(true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_peer_merge_must_not_undo_rewind_f1_goal4() {
        merge_race(false).await;
    }
}

/// f1 goal4 FC (#3266), postgres: a caller lifecycle transition
/// (`update` with a lifecycle target → `apply_lifecycle_patch`) and a racing
/// quarantine never lose the quarantine. The competing writer attempts its
/// quarantine AFTER the patch has read the row and BEFORE the patch writes
/// (f2r's window): with the read locked in the write transaction the
/// quarantine waits for the patch and lands after it; with an unlocked read
/// (the pre-fix pool SELECT, or `FOR UPDATE` on the pool — f2r's trap) and no
/// CAS, the patch overwrites a committed quarantine.
///
/// Deterministic interleaving (no sleeps): H holds `embed_skip` in SHARE mode,
/// so the caller's main update M (a content edit) stalls in the
/// `memories_embed_skip_clear` trigger while holding the row lock; S queues a
/// SHARE lock on `memories` behind M; H commits → M commits → S is granted;
/// the patch P reads the row, and its UPDATE queues behind S; Q then runs
/// `SELECT … FOR UPDATE` (compatible with S) — it blocks on P's row lock iff
/// P's read is locked — and queues its quarantine UPDATE behind S; S commits.
#[cfg(feature = "sal-postgres")]
mod pg_fc_race {
    use super::{T_OLD, uniq};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore, UpdatePatch};
    use std::sync::Arc;

    async fn blocked_behind(pg: &PostgresStore, holder_pid: i32) -> i64 {
        sqlx::query_scalar(
            "WITH w AS (SELECT pid, pg_blocking_pids(pid) AS b FROM pg_stat_activity \
             WHERE datname = current_database()) \
             SELECT count(*) FROM w WHERE $1 = ANY(w.b) OR EXISTS \
             (SELECT 1 FROM w AS v WHERE v.pid = ANY(w.b) AND $1 = ANY(v.b))",
        )
        .bind(holder_pid)
        .fetch_one(pg.pool())
        .await
        .expect("barrier probe")
    }

    async fn wait_blocked(pg: &PostgresStore, holder_pid: i32, n: i64) {
        let end = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        while blocked_behind(pg, holder_pid).await < n {
            assert!(tokio::time::Instant::now() < end, "barrier not reached");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    async fn locked_tx(pg: &PostgresStore) -> (sqlx::Transaction<'static, sqlx::Postgres>, i32) {
        let mut tx = pg.pool().begin().await.expect("tx");
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .expect("pid");
        (tx, pid)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_lifecycle_patch_never_overwrites_a_racing_quarantine_f1_goal4() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let pg = Arc::new(PostgresStore::connect(&url).await.expect("connect"));
        let owner = uniq("ai:fc-owner");
        let ctx = CallerContext::for_agent(owner.clone());
        let seed_row: ai_memory::models::Memory = serde_json::from_value(super::memory_json(
            &uniq("fc"),
            &uniq("fc-ns"),
            &uniq("t"),
            "body",
            &owner,
            T_OLD,
        ))
        .expect("memory");
        let id = pg.store(&ctx, &seed_row).await.expect("seed");

        // H: stall M inside its own row lock.
        let (mut holder, h_pid) = locked_tx(&pg).await;
        sqlx::query("LOCK TABLE embed_skip IN SHARE MODE")
            .execute(&mut *holder)
            .await
            .expect("H lock");
        let (store, rid, caller_ctx) = (Arc::clone(&pg), id.clone(), ctx.clone());
        let caller = tokio::spawn(async move {
            let patch = UpdatePatch {
                content: Some("edited by caller".to_string()),
                lifecycle_state: Some(ai_memory::models::LifecycleState::Active),
                ..UpdatePatch::default()
            };
            store.update(&caller_ctx, &rid, patch).await
        });
        wait_blocked(&pg, h_pid, 1).await;
        // S: a SHARE lock on `memories`, queued behind M's ROW EXCLUSIVE.
        let (mut share, s_pid) = locked_tx(&pg).await;
        let s_task = tokio::spawn(async move {
            sqlx::query("LOCK TABLE memories IN SHARE MODE")
                .execute(&mut *share)
                .await
                .expect("S lock");
            share
        });
        wait_blocked(&pg, h_pid, 2).await;
        holder.commit().await.expect("H release");
        let share = s_task.await.expect("S join");
        // P has read the row; its UPDATE waits on S.
        wait_blocked(&pg, s_pid, 1).await;
        // Q: lock the row (compatible with S), then quarantine (waits on S).
        let (mut quarantiner, _q_pid) = locked_tx(&pg).await;
        let qid = id.clone();
        let q_task = tokio::spawn(async move {
            sqlx::query("SELECT id FROM memories WHERE id = $1 FOR UPDATE")
                .bind(&qid)
                .fetch_one(&mut *quarantiner)
                .await
                .expect("Q lock");
            sqlx::query("UPDATE memories SET lifecycle_state = 'quarantined' WHERE id = $1")
                .bind(&qid)
                .execute(&mut *quarantiner)
                .await
                .expect("Q quarantine");
            quarantiner.commit().await.expect("Q commit");
        });
        wait_blocked(&pg, s_pid, 2).await;
        share.commit().await.expect("S release");
        q_task.await.expect("Q join");
        let outcome = caller.await.expect("caller join");
        let state: String =
            sqlx::query_scalar("SELECT lifecycle_state FROM memories WHERE id = $1")
                .bind(&id)
                .fetch_one(pg.pool())
                .await
                .expect("state");
        assert_eq!(
            state, "quarantined",
            "a caller transition overwrote a racing quarantine (outcome {outcome:?})"
        );
    }
}
