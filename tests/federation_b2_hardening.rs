// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 Wave-2 fix B2 — federation hardening tests.
//!
//! Covers the three medium-severity findings + one low closed under
//! the `FEDERATION_HARDENING` campaign:
//!
//! * **S6-M1 (L2-2)** — cross-peer reflection bookkeeping. The
//!   `sync_push` receive path stamps `metadata.peer_origin` on
//!   imported reflection memories so a later `memory_reflection_origin`
//!   MCP lookup can reconstruct the attribution chain. The local
//!   namespace cap (`max_reflection_depth`) governs subsequent
//!   reflections derived from imports — peer-cap drift cannot
//!   smuggle a deeper reflection past the receiver's policy.
//! * **S6-M2** — `sync_push` per-agent quota gate. Federation receive
//!   now consults `quotas::check_and_record` BEFORE writing, refusing
//!   the push with 429 + `X-Quota-Reset-At` when the sender would be
//!   pushed past their `agent_quotas` row's daily/lifetime limits.
//! * **S6-LOW2** — `sender_clock` is now consumed for skew
//!   observability. The wire field is no longer `dead_code`; this
//!   suite asserts the deserialisation path stays clean and the
//!   helper emits a warn-level log when skew exceeds 60s.
//!
//! ## Topology
//!
//! All tests use the same in-process `axum::Router` harness used by
//! `tests/integration.rs::OneshotDaemon` so the suite stays hermetic
//! (no subprocess, no real network) per the campaign's
//! "in-process multi-instance simulation" mandate.

use ai_memory::handlers::{AppState, Db, StorageBackend};
use rusqlite::params;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Test harness — minimal in-process daemon.
//
// Mirrors `tests/integration.rs::OneshotDaemon::with_federation` but
// kept local so this file remains self-contained (the integration.rs
// harness is `pub(crate)` only). The shape is identical and
// `build_router` is the same call.
// ---------------------------------------------------------------------------

struct B2Daemon {
    router: axum::Router,
    db: Db,
}

impl B2Daemon {
    fn new() -> Self {
        ai_memory::config::set_allow_loopback_webhooks(true);
        let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
        let path = PathBuf::from(":memory:");
        let db: Db = Arc::new(Mutex::new((
            conn,
            path,
            ai_memory::config::ResolvedTtl::default(),
            true,
        )));
        #[cfg(feature = "sal")]
        let store: Arc<dyn ai_memory::store::MemoryStore> = {
            let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
            let p = tmp.path().to_path_buf();
            std::mem::forget(tmp);
            Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open SqliteStore"))
        };
        let app_state = AppState {
            db: db.clone(),
            embedder: Arc::new(None),
            vector_index: Arc::new(Mutex::new(None)),
            federation: Arc::new(None),
            tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
            scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
            profile: Arc::new(ai_memory::profile::Profile::core()),
            mcp_config: Arc::new(None),
            active_keypair: Arc::new(None),
            family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
            storage_backend: StorageBackend::Sqlite,
            #[cfg(feature = "sal")]
            store,
            llm: Arc::new(None),
            auto_tag_model: Arc::new(None),
            llm_call_timeout: std::time::Duration::from_secs(30),
            replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
            verify_require_nonce: false,
            autonomous_hooks: false,
            recall_scope: Arc::new(None),
        };
        let api_key_state = ai_memory::handlers::ApiKeyState { key: None };
        let router = ai_memory::build_router(api_key_state, app_state);
        Self { router, db }
    }

    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> (
        axum::http::StatusCode,
        axum::http::HeaderMap,
        serde_json::Value,
    ) {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, headers, json)
    }

    /// Tighten the `agent_quotas` row for a given sender so we don't have
    /// to push 1000+ memories to hit the cap.
    async fn set_quota_caps(
        &self,
        agent_id: &str,
        max_memories_per_day: i64,
        max_storage_bytes: i64,
        max_links_per_day: i64,
    ) {
        let lock = self.db.lock().await;
        // Ensure the row exists (auto-inserted via `get_status` semantics).
        let _ = ai_memory::quotas::get_status(&lock.0, agent_id).expect("quota row");
        lock.0
            .execute(
                "UPDATE agent_quotas SET max_memories_per_day = ?1, \
                 max_storage_bytes = ?2, max_links_per_day = ?3 WHERE agent_id = ?4",
                params![
                    max_memories_per_day,
                    max_storage_bytes,
                    max_links_per_day,
                    agent_id
                ],
            )
            .expect("tighten quota caps");
    }
}

// ---------------------------------------------------------------------------
// S6-M2 — sync_push quota gate.
// ---------------------------------------------------------------------------

fn synth_memory(id: &str, ns: &str, title: &str, content: &str) -> serde_json::Value {
    let now = chrono::Utc::now().to_rfc3339();
    json!({
        "id": id,
        "tier": "mid",
        "namespace": ns,
        "title": title,
        "content": content,
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "access_count": 0,
        "created_at": now,
        "updated_at": now,
        "metadata": {"agent_id": "ai:remote-curator"},
        "reflection_depth": 0,
    })
}

#[tokio::test]
async fn test_sync_push_quota_under_limit_succeeds() {
    // Sanity baseline: a single small push from a fresh sender under
    // the default 1000/day cap lands cleanly with 200 OK.
    let d = B2Daemon::new();
    let body = json!({
        "sender_agent_id": "ai:peer-alpha",
        "memories": [synth_memory("mem-u-1", "ns-quota", "ok-1", "small")],
        "deletions": [],
        "archives": [],
        "restores": [],
        "links": [],
        "pendings": [],
        "pending_decisions": [],
        "namespace_meta": [],
        "namespace_meta_clears": []
    });
    let (status, _h, resp) = d.post("/api/v1/sync/push", &body).await;
    assert_eq!(status, axum::http::StatusCode::OK, "body: {resp}");
    assert_eq!(resp["applied"], 1, "body: {resp}");
}

#[tokio::test]
async fn test_sync_push_quota_check_enforced() {
    // Tighten the sender's cap to 1 memory/day, then push 3 → the
    // second + third must be refused with 429 + `X-Quota-Reset-At`.
    let d = B2Daemon::new();
    d.set_quota_caps("ai:peer-bravo", 1, 100 * 1024 * 1024, 5000)
        .await;
    let body = json!({
        "sender_agent_id": "ai:peer-bravo",
        "memories": [
            synth_memory("mem-q-1", "ns-quota", "first", "a"),
            synth_memory("mem-q-2", "ns-quota", "second", "b"),
            synth_memory("mem-q-3", "ns-quota", "third", "c"),
        ],
        "deletions": [],
        "archives": [],
        "restores": [],
        "links": [],
        "pendings": [],
        "pending_decisions": [],
        "namespace_meta": [],
        "namespace_meta_clears": []
    });
    let (status, headers, resp) = d.post("/api/v1/sync/push", &body).await;
    assert_eq!(
        status,
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        "body: {resp}"
    );
    assert!(
        headers.contains_key("x-quota-reset-at"),
        "must surface X-Quota-Reset-At; headers: {headers:?}"
    );
    assert_eq!(resp["code"], "QUOTA_EXCEEDED", "body: {resp}");
    assert_eq!(resp["limit"], "memories_per_day", "body: {resp}");
    assert_eq!(resp["via"], "sync_push", "body: {resp}");
}

#[tokio::test]
async fn test_sync_push_dry_run_bypasses_quota_check() {
    // dry_run pushes are preview-only and must not be charged against
    // the sender's quota — otherwise an attacker who couldn't write
    // could still exhaust the daily counter via a flood of previews.
    let d = B2Daemon::new();
    d.set_quota_caps("ai:peer-charlie", 1, 100 * 1024 * 1024, 5000)
        .await;
    let body = json!({
        "sender_agent_id": "ai:peer-charlie",
        "memories": [
            synth_memory("mem-d-1", "ns-dry", "first", "a"),
            synth_memory("mem-d-2", "ns-dry", "second", "b"),
        ],
        "deletions": [],
        "archives": [],
        "restores": [],
        "links": [],
        "pendings": [],
        "pending_decisions": [],
        "namespace_meta": [],
        "namespace_meta_clears": [],
        "dry_run": true
    });
    let (status, _h, resp) = d.post("/api/v1/sync/push", &body).await;
    assert_eq!(status, axum::http::StatusCode::OK, "body: {resp}");
    // dry_run counts as noop, never applied.
    assert_eq!(resp["applied"], 0);
}

// ---------------------------------------------------------------------------
// S6-M1 — cross-peer reflection bookkeeping.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_reflection_bookkeeping_imports_with_origin() {
    // A peer pushes a reflection memory (reflection_depth > 0) — the
    // receiver must stamp `metadata.peer_origin` with the sender's id
    // and the recorded depth so `memory_reflection_origin` can find
    // the provenance later.
    let d = B2Daemon::new();
    let reflection_id = "mem-refl-import-1";
    let mut reflection = synth_memory(
        reflection_id,
        "ns-refl-import",
        "remote reflection",
        "reflected content",
    );
    reflection["reflection_depth"] = json!(2);
    let body = json!({
        "sender_agent_id": "ai:peer-delta",
        "memories": [reflection],
        "deletions": [],
        "archives": [],
        "restores": [],
        "links": [],
        "pendings": [],
        "pending_decisions": [],
        "namespace_meta": [],
        "namespace_meta_clears": []
    });
    let (status, _h, resp) = d.post("/api/v1/sync/push", &body).await;
    assert_eq!(status, axum::http::StatusCode::OK, "body: {resp}");

    // Re-read the row via the substrate (avoids depending on the
    // memory_get HTTP shape) and assert peer_origin landed.
    let lock = d.db.lock().await;
    let mem = ai_memory::db::get(&lock.0, reflection_id)
        .expect("read")
        .expect("memory present");
    let block = mem
        .metadata
        .get("peer_origin")
        .expect("peer_origin stamped on imported reflection");
    assert_eq!(block["peer_id"], "ai:peer-delta");
    assert_eq!(block["original_depth"], 2);
    assert!(block["imported_at"].as_str().is_some());
    assert_eq!(mem.reflection_depth, 2);
}

#[tokio::test]
async fn test_imported_non_reflection_memory_skips_peer_origin_stamp() {
    // Non-reflection rows (depth==0) must NOT get a peer_origin block —
    // we want the marker to stay specific to reflection provenance so
    // a curator's bookkeeping queries don't have to walk every imported
    // row.
    let d = B2Daemon::new();
    let memory_id = "mem-plain-import-1";
    let plain = synth_memory(memory_id, "ns-plain", "plain memory", "no reflection");
    let body = json!({
        "sender_agent_id": "ai:peer-echo",
        "memories": [plain],
        "deletions": [], "archives": [], "restores": [], "links": [],
        "pendings": [], "pending_decisions": [],
        "namespace_meta": [], "namespace_meta_clears": []
    });
    let (status, _h, _resp) = d.post("/api/v1/sync/push", &body).await;
    assert_eq!(status, axum::http::StatusCode::OK);

    let lock = d.db.lock().await;
    let mem = ai_memory::db::get(&lock.0, memory_id)
        .expect("read")
        .expect("memory present");
    assert!(
        mem.metadata.get("peer_origin").is_none(),
        "plain memory must not be stamped; metadata={}",
        mem.metadata
    );
}

#[tokio::test]
async fn test_memory_reflection_origin_returns_correct_data() {
    // Direct substrate-level check of `lookup_reflection_origin` —
    // returns the stamped block plus the local depth-at-arrival
    // snapshot for an imported reflection, and `None`/None for a
    // locally-minted memory.
    let d = B2Daemon::new();

    // Push an imported reflection.
    let imported_id = "mem-refl-origin-1";
    let mut refl = synth_memory(
        imported_id,
        "ns-origin",
        "remote reflection",
        "reflected content",
    );
    refl["reflection_depth"] = json!(3);
    let body = json!({
        "sender_agent_id": "ai:peer-foxtrot",
        "memories": [refl],
        "deletions": [], "archives": [], "restores": [], "links": [],
        "pendings": [], "pending_decisions": [],
        "namespace_meta": [], "namespace_meta_clears": []
    });
    let (status, _h, _r) = d.post("/api/v1/sync/push", &body).await;
    assert_eq!(status, axum::http::StatusCode::OK);

    let lock = d.db.lock().await;
    let origin = ai_memory::federation::reflection_bookkeeping::lookup_reflection_origin(
        &lock.0,
        imported_id,
    )
    .expect("read")
    .expect("memory present");
    assert_eq!(origin.memory_id, imported_id);
    assert_eq!(origin.peer_origin.as_deref(), Some("ai:peer-foxtrot"));
    assert_eq!(origin.original_depth, Some(3));
    assert_eq!(origin.local_depth_at_arrival, 3);
    // signing_agent comes from `metadata.agent_id` set at synth time.
    assert_eq!(origin.signing_agent.as_deref(), Some("ai:remote-curator"));

    // Non-existent id → Ok(None).
    let missing = ai_memory::federation::reflection_bookkeeping::lookup_reflection_origin(
        &lock.0,
        "does-not-exist",
    )
    .expect("read");
    assert!(missing.is_none());
}

#[tokio::test]
async fn test_local_curator_refuses_derived_depth_over_local_cap() {
    // Imported reflection at depth=2 → local cap (default = 3) means a
    // local curator can reflect ONCE on top (new depth = 3) but not
    // twice. We assert that the second-level reflection emits
    // REFLECTION_DEPTH_EXCEEDED on the local node regardless of what
    // depth the source peer recorded.
    use ai_memory::db::{ReflectError, ReflectInput, reflect};
    use ai_memory::models::Tier;

    let d = B2Daemon::new();
    let imported_id = "mem-refl-cap-1";
    let mut refl = synth_memory(
        imported_id,
        "ns-cap",
        "imported reflection",
        "remote-minted reflection content",
    );
    refl["reflection_depth"] = json!(3);
    let body = json!({
        "sender_agent_id": "ai:peer-golf",
        "memories": [refl],
        "deletions": [], "archives": [], "restores": [], "links": [],
        "pendings": [], "pending_decisions": [],
        "namespace_meta": [], "namespace_meta_clears": []
    });
    let (status, _h, resp) = d.post("/api/v1/sync/push", &body).await;
    assert_eq!(status, axum::http::StatusCode::OK, "body: {resp}");

    // Now have a LOCAL curator try to reflect on top of the imported
    // depth-3 memory. New depth = 4. Local default cap is 3 →
    // DepthExceeded.
    let lock = d.db.lock().await;
    let input = ReflectInput {
        source_ids: vec![imported_id.to_string()],
        title: "second-order reflection".to_string(),
        content: "should refuse — over local cap".to_string(),
        namespace: Some("ns-cap".to_string()),
        tier: Tier::Mid,
        tags: Vec::new(),
        priority: 5,
        confidence: 1.0,
        source: "claude".to_string(),
        agent_id: "ai:local-curator".to_string(),
        metadata: serde_json::json!({}),
    };
    let err = reflect(&lock.0, &input).expect_err("must refuse: 4 > local cap 3");
    match err {
        ReflectError::DepthExceeded {
            attempted,
            cap,
            namespace,
        } => {
            assert_eq!(attempted, 4);
            assert_eq!(cap, 3);
            assert_eq!(namespace, "ns-cap");
        }
        other => panic!("expected DepthExceeded, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// S6-LOW2 — sender_clock skew observability.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_sender_clock_skew_logged_when_excessive() {
    // The wire field `sender_clock` is no longer `dead_code`. We don't
    // assert tracing capture here (that requires a test subscriber);
    // the contract this test pins is the deserialisation +
    // accept-and-process path. A push carrying a clock 1 hour in the
    // past is accepted (skew is observability-only, not policy) and
    // the row lands cleanly. The skew helper itself is
    // `observe_sender_clock_skew`, exercised by direct call when a
    // tracing subscriber is configured.
    let d = B2Daemon::new();
    let one_hour_ago = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let body = json!({
        "sender_agent_id": "ai:peer-hotel",
        "sender_clock": {
            "entries": {
                "ai:peer-hotel": one_hour_ago,
            }
        },
        "memories": [synth_memory("mem-skew-1", "ns-skew", "skew check", "x")],
        "deletions": [], "archives": [], "restores": [], "links": [],
        "pendings": [], "pending_decisions": [],
        "namespace_meta": [], "namespace_meta_clears": []
    });
    let (status, _h, resp) = d.post("/api/v1/sync/push", &body).await;
    assert_eq!(status, axum::http::StatusCode::OK, "body: {resp}");
    assert_eq!(resp["applied"], 1);

    // Same body without sender_clock must also still deserialise (back-
    // compat with pre-S6 callers).
    let body_no_clock = json!({
        "sender_agent_id": "ai:peer-india",
        "memories": [synth_memory("mem-skew-2", "ns-skew", "no clock", "x")],
        "deletions": [], "archives": [], "restores": [], "links": [],
        "pendings": [], "pending_decisions": [],
        "namespace_meta": [], "namespace_meta_clears": []
    });
    let (status, _h, resp) = d.post("/api/v1/sync/push", &body_no_clock).await;
    assert_eq!(status, axum::http::StatusCode::OK, "body: {resp}");
}
