// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar-3 (#1709) / #224 Task 3a.1 — CRDT-lite sync-state merge
//! receive-path regression.
//!
//! The federation `/sync/push` receiver now folds the sender's full
//! vector clock (`sender_clock.entries`) into its own persisted
//! `sync_state` via pointwise max (`db::sync_state_merge`), so the
//! receiver's returned `receiver_clock` reflects EVERY peer the sender
//! has transitively observed — not just this push's per-peer
//! observation. The merge is monotonic: an older incoming timestamp for
//! a peer the receiver already tracks at a newer value must NOT regress
//! the stored entry.
//!
//! These tests drive the real Axum `sync_push` handler end-to-end
//! (zero-config TOFU + `REQUIRE_SIG=0` + `TRUST_BODY_AGENT_ID=1` so the
//! push flows past the security gates to the reconciliation step) and
//! assert on the `receiver_clock` echoed in the response. No schema /
//! wire change: `sender_clock.entries` was already on the wire and
//! `sync_state` was already per-peer.

#![allow(clippy::too_many_lines)]
#![allow(clippy::await_holding_lock)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn setup_router() -> axum::Router {
    setup_router_with_path().0
}

fn setup_router_with_path() -> (axum::Router, std::path::PathBuf) {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    std::mem::forget(db_tmp);
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
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
        storage_backend: StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store: Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"),
        ),
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    (ai_memory::build_router(api_key_state, app_state), db_path)
}

/// Stable receiver identity. The HTTP `/sync/push` path resolves the
/// receiver's own `local_agent_id` (the `sync_state.agent_id` the merge
/// persists against) from the `X-Agent-Id` header; without it every
/// request would synthesize a fresh `anonymous:req-<uuid>` and the two
/// pushes would land on DIFFERENT `sync_state` rows. Pinning it lets the
/// monotonic-merge regression observe a single accumulating clock.
const RECEIVER_AGENT_ID: &str = "ai:receiver-node";

async fn post_sync_push(router: &axum::Router, body: Value, peer_id: &str) -> (StatusCode, Value) {
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header("x-agent-id", RECEIVER_AGENT_ID)
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            peer_id,
        )
        .body(Body::from(body_bytes))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Relax the federation security gates so a zero-config push flows all
/// the way to the sync-state reconciliation step. Returns nothing; the
/// caller must clear these in a teardown.
fn relax_fed_gates() {
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
        // #1801→#1954 — the per-write CONTENT and per-signal AUTHOR signature
        // defaults flipped strict at v1.0.0; this zero-config merge test pushes
        // UNSIGNED bodies to reach the reconciliation step, so opt back into the
        // permissive accept-and-flag posture (`=0` escape hatch) — the test
        // exercises sync-state merge semantics, not the content-attestation gate.
        std::env::set_var(
            ai_memory::federation::receive_auth::REQUIRE_WRITE_SIG_ENV,
            "0",
        );
        std::env::set_var(
            ai_memory::federation::receive_auth::REQUIRE_SIGNAL_SIG_ENV,
            "0",
        );
    }
}

fn clear_fed_gates() {
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_WRITE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_SIGNAL_SIG_ENV);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn sync_push_merges_sender_clock_into_receiver_clock_1709() {
    let _g = env_lock();
    relax_fed_gates();
    let router = setup_router();

    // The sender carries a clock describing peers it has observed —
    // including a transitive peer the receiver has never talked to.
    let body = json!({
        "sender_agent_id": "ai:sender",
        "sender_clock": {"entries": {
            "ai:sender": "2026-03-01T00:00:00Z",
            "ai:transitive-peer": "2026-02-01T00:00:00Z",
        }},
        "memories": [],
        "dry_run": false,
    });
    let (status, resp) = post_sync_push(&router, body, "ai:sender").await;
    clear_fed_gates();

    assert_eq!(status, StatusCode::OK, "push must succeed; resp={resp}");
    let clock = &resp["receiver_clock"]["entries"];
    // Every peer the sender's clock carried is now persisted on the
    // receiver — including the transitive peer it had never seen.
    assert_eq!(
        clock["ai:sender"].as_str(),
        Some("2026-03-01T00:00:00Z"),
        "sender's own entry must land in receiver clock; resp={resp}"
    );
    assert_eq!(
        clock["ai:transitive-peer"].as_str(),
        Some("2026-02-01T00:00:00Z"),
        "transitive peer must be merged into receiver clock; resp={resp}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sync_push_older_sender_timestamp_does_not_regress_receiver_clock_1709() {
    let _g = env_lock();
    relax_fed_gates();
    let router = setup_router();

    // First push advances "ai:peer" to a NEWER timestamp.
    let first = json!({
        "sender_agent_id": "ai:sender",
        "sender_clock": {"entries": {"ai:peer": "2026-05-01T00:00:00Z"}},
        "memories": [],
        "dry_run": false,
    });
    let (s1, r1) = post_sync_push(&router, first, "ai:sender").await;
    assert_eq!(s1, StatusCode::OK, "first push must succeed; r1={r1}");
    assert_eq!(
        r1["receiver_clock"]["entries"]["ai:peer"].as_str(),
        Some("2026-05-01T00:00:00Z")
    );

    // Second push carries an OLDER timestamp for the same peer — the
    // monotonic pointwise-max merge must NOT regress the stored value.
    let second = json!({
        "sender_agent_id": "ai:sender",
        "sender_clock": {"entries": {"ai:peer": "2026-01-01T00:00:00Z"}},
        "memories": [],
        "dry_run": false,
    });
    let (s2, r2) = post_sync_push(&router, second, "ai:sender").await;
    clear_fed_gates();

    assert_eq!(s2, StatusCode::OK, "second push must succeed; r2={r2}");
    assert_eq!(
        r2["receiver_clock"]["entries"]["ai:peer"].as_str(),
        Some("2026-05-01T00:00:00Z"),
        "older incoming timestamp must NOT regress the receiver clock; r2={r2}"
    );
}

/// Build a `/sync/push`-shaped memory object with the given id, tags,
/// priority, and `updated_at`. Carries a stable `(title, namespace)` so the
/// two pushes converge on the SAME row by id.
fn push_memory(id: &str, tags: &[&str], priority: i64, updated_at: &str) -> Value {
    json!({
        "id": id,
        "tier": "long",
        "namespace": "fed-merge-ns",
        "title": "fed-merge-title",
        "content": "c",
        "tags": tags,
        "priority": priority,
        "confidence": 1.0,
        "source": "user",
        "access_count": 0,
        "created_at": "2026-06-16T00:00:00+00:00",
        "updated_at": updated_at,
        "metadata": {"agent_id": "original-owner"},
        "version": 1,
    })
}

/// v0.8.0 Pillar-3 (#1709 / #224) — a `/sync/push` of a divergent same-`id`
/// memory FIELD-MERGES (tags union, priority max) instead of LWW-clobbering.
/// This pins the wired `db::merge_inbound` reconciliation path end-to-end
/// through the real Axum receiver.
#[tokio::test(flavor = "current_thread")]
async fn sync_push_divergent_same_id_memory_field_merges_1709() {
    let _g = env_lock();
    relax_fed_gates();
    let (router, db_path) = setup_router_with_path();

    let mem_id = "fed-merge-mem-1709";
    // First push: tags=[a], priority=3.
    let first = json!({
        "sender_agent_id": "ai:sender",
        "sender_clock": {"entries": {"ai:sender": "2026-06-16T00:00:00Z"}},
        "memories": [push_memory(mem_id, &["a"], 3, "2026-06-16T00:00:00+00:00")],
        "dry_run": false,
    });
    let (s1, r1) = post_sync_push(&router, first, "ai:sender").await;
    assert_eq!(s1, StatusCode::OK, "first push must succeed; r1={r1}");

    // Second push: SAME id, NEWER, divergent tags=[b], priority=5, and a
    // peer trying to rewrite the immutable agent_id.
    let mut diverged = push_memory(mem_id, &["b"], 5, "2026-06-16T09:00:00+00:00");
    diverged["metadata"] = json!({"agent_id": "peer-impostor"});
    let second = json!({
        "sender_agent_id": "ai:sender",
        "sender_clock": {"entries": {"ai:sender": "2026-06-16T09:00:00Z"}},
        "memories": [diverged],
        "dry_run": false,
    });
    let (s2, r2) = post_sync_push(&router, second, "ai:sender").await;
    clear_fed_gates();
    assert_eq!(s2, StatusCode::OK, "second push must succeed; r2={r2}");

    // Read the persisted row back and assert the #224 CRDT-lite field-merge
    // (was LWW-clobber pre-Pillar-3 wiring): tags union {a,b}, priority
    // max=5, agent_id immutable (original survives the peer's rewrite).
    let conn = ai_memory::db::open(&db_path).expect("reopen db for read-back");
    let got = ai_memory::db::get(&conn, mem_id)
        .expect("db::get ok")
        .expect("merged memory present");
    let mut tags = got.tags.clone();
    tags.sort();
    assert_eq!(
        tags,
        vec!["a", "b"],
        "tags union — both peers' tags survive the field-merge"
    );
    assert_eq!(got.priority, 5, "priority is max(3, 5)");
    assert_eq!(
        got.metadata["agent_id"],
        json!("original-owner"),
        "agent_id is immutable — the peer's rewrite is rejected by merge_memory"
    );
}
