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
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{
        Backend, FED_ENV_LOCK, decontaminate_restores_prior_and_emits_signed_event,
        local_taint_survives_remote_clean_row, quarantined_release_keeps_memory_dequarantined,
        release_of_non_contained_row_is_refused, remote_taint_not_adopted_existing_row,
        remote_taint_not_adopted_fresh_row, route_in_quarantine_still_applies_over_existing_row,
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
