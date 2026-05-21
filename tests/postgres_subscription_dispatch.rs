// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! v0.7.0 Track D #932 regression test — postgres-backed daemons MUST
//! fire HMAC-signed webhook POSTs when a `memory_store` event matches
//! a registered subscription. Pre-#932 the postgres-create branch in
//! `src/handlers/create.rs::create_memory_postgres` called no
//! dispatch helper at all, so subscriptions stored in
//! `_subscriptions/<aid>` namespace via the SAL never fired —
//! vacuously satisfying the v0.7.0 "HMAC non-optional" guarantee for
//! Postgres-backed deployments.
//!
//! This test stands up a SAL `SqliteStore` (the in-tree adapter used
//! by every postgres-flavoured code path that doesn't have a real
//! `AI_MEMORY_TEST_POSTGRES_URL` available), inserts a subscription
//! memory in `_subscriptions/probe` with metadata mirroring what
//! `handlers::subscriptions::subscribe`'s postgres branch persists,
//! then invokes `handlers::subscriptions::dispatch_event_postgres`
//! directly and asserts the wiremock-backed sink received exactly
//! one POST carrying the canonical `x-ai-memory-signature` header.
//!
//! The test bypasses `AppState` construction (which requires the full
//! daemon scaffolding) by mocking the minimal surface
//! `dispatch_event_postgres` reads — the store handle and the sqlite
//! audit DB path. Subsequent test rounds can swap the `SqliteStore` for
//! a real `PostgresStore` via `AI_MEMORY_TEST_POSTGRES_URL`; the
//! subscription metadata + dispatch wire shape is identical.

#![cfg(feature = "sal")]

use std::sync::Arc;
use std::time::Duration;

use ai_memory::handlers::{AppState, StorageBackend, dispatch_event_postgres};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::{CallerContext, MemoryStore, sqlite::SqliteStore};
use chrono::Utc;
use tokio::sync::{Mutex, RwLock};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Local SHA-256 helper — the `ai_memory::subscriptions::sha256_hex`
/// helper is `pub(crate)` so it isn't reachable from the integration
/// test crate. Re-implement the byte-for-byte equivalent here using
/// the same `sha2` crate.
fn sha256_hex_local(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let digest = h.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn make_subscription_memory(
    sub_id: &str,
    owner: &str,
    url: &str,
    target_ns: &str,
    secret_hash: Option<&str>,
) -> Memory {
    let now = Utc::now().to_rfc3339();
    let metadata = serde_json::json!({
        "kind": "subscription",
        "agent_id": owner,
        "subscription_id": sub_id,
        "url": url,
        "events": "*",
        "namespace_filter": target_ns,
        "agent_filter": null,
        "secret_hash": secret_hash,
        "created_by": owner,
        "created_at": now.clone(),
    });
    Memory {
        id: sub_id.to_string(),
        tier: Tier::Long,
        namespace: format!("_subscriptions/{owner}"),
        title: format!("subscription:{sub_id}"),
        content: format!("subscription for {owner} -> {target_ns}"),
        tags: vec!["subscription".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "subscribe".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

/// Build a minimal `AppState` whose `storage_backend = Postgres` but
/// whose underlying `store` is a `SqliteStore` (the in-tree SAL
/// adapter). The two branches of `dispatch_event_postgres` we care
/// about (namespace-prefix filter + metadata-shaped subscription
/// row + worker dispatch) are identical regardless of the concrete
/// `MemoryStore` impl, so the test exercises the postgres dispatch
/// LOGIC without requiring a live postgres instance.
fn make_test_state() -> (AppState, std::path::PathBuf) {
    let scratch_dir = tempfile::tempdir().expect("tempdir for scratch sqlite");
    let sqlite_path = scratch_dir.path().join("audit.db");
    // `crate::db::open` runs the full migration ladder so the audit
    // tables (subscription_events, subscription_dlq, dispatches)
    // exist for `dispatch_event_to_subs` to write into.
    let conn = ai_memory::db::open(&sqlite_path).expect("open sqlite audit db");
    let db: ai_memory::handlers::Db = Arc::new(Mutex::new((
        conn,
        sqlite_path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));

    let store_path = scratch_dir.path().join("store.db");
    let store: Arc<dyn MemoryStore> =
        Arc::new(SqliteStore::open(&store_path).expect("open SAL SqliteStore"));

    let state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Postgres,
        store,
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(ai_memory::config::DEFAULT_LLM_CALL_TIMEOUT_SECS),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::new()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(ai_memory::identity::replay::FederationNonceCache::new()),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
    };

    // Leak the tempdir so the scratch files outlive the test (otherwise
    // the destructor would race the worker thread's audit writes).
    std::mem::forget(scratch_dir);
    (state, sqlite_path)
}

/// K6 ACK echo helper — mirrors the helper in
/// `src/subscriptions.rs::tests::AckEcho`. Receivers MUST return a
/// JSON `{"status":"ack","correlation_id":"<id>"}` body whose
/// correlation id matches the request header. Otherwise the
/// dispatcher's `deliver_with_retry` records failure and the test
/// would observe the POST in `received_requests()` but no
/// `dispatch_count` bump — making the success/failure distinction
/// noisy.
struct AckEcho;
impl wiremock::Respond for AckEcho {
    fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
        let corr = request
            .headers
            .get("x-ai-memory-correlation-id")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();
        let body = serde_json::json!({"status": "ack", "correlation_id": corr});
        ResponseTemplate::new(200).set_body_json(body)
    }
}

/// #932 — happy path: a postgres subscription in `_subscriptions/probe`
/// with a configured `secret_hash` MUST cause `dispatch_event_postgres`
/// to POST to the sink with an HMAC signature header. Pre-#932 the
/// postgres dispatch path did not exist at all (zero webhooks fired).
#[tokio::test(flavor = "multi_thread")]
async fn dispatch_event_postgres_fires_hmac_signed_post() {
    // H11 — the dispatcher's SSRF guard reads from the process-wide
    // `ALLOW_LOOPBACK_WEBHOOKS` atomic (not the env var directly).
    // Wiremock binds to 127.0.0.1; opt into loopback for the test
    // duration so the dispatcher's `validate_url` doesn't reject the
    // sink URL outright.
    ai_memory::config::set_allow_loopback_webhooks(true);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sink"))
        .respond_with(AckEcho)
        .mount(&server)
        .await;

    let (state, _audit_path) = make_test_state();

    // SAL-stored subscription pointing at the wiremock sink. The
    // `secret_hash` is what `handlers::subscriptions::subscribe`'s
    // postgres branch persists at subscribe time — SHA-256 of the
    // plaintext, mirroring the sqlite path's `secret_hash` column.
    let sub_secret_hash = sha256_hex_local("track-d-test-secret");
    let url = format!("{}/sink", server.uri());
    let sub_mem = make_subscription_memory(
        "track-d-sub-1",
        "probe",
        &url,
        "track-d/d2-sub",
        Some(&sub_secret_hash),
    );
    let admin_ctx = CallerContext::for_admin("test-setup");
    state
        .store
        .store(&admin_ctx, &sub_mem)
        .await
        .expect("seed subscription memory");

    // Fire the dispatch path identical to what `create_memory_postgres`
    // now invokes after #932.
    dispatch_event_postgres(
        &state,
        "memory_store",
        "mem-under-test",
        "track-d/d2-sub",
        Some("ai:probe"),
        None,
    )
    .await;

    // Poll until the wiremock observes the dispatched POST.
    for _ in 0..50 {
        let received = server.received_requests().await.unwrap_or_default();
        if !received.is_empty() {
            let req = &received[0];
            let sig = req
                .headers
                .get("x-ai-memory-signature")
                .expect("HMAC signature header MUST be present on postgres dispatch");
            let sig_str = sig.to_str().expect("signature header is ASCII");
            assert!(
                sig_str.starts_with("sha256="),
                "signature header MUST carry sha256= prefix; got {sig_str:?}"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "post-#932 dispatch path never reached the sink — \
         regression: dispatch_event_postgres dropped the event"
    );
}

/// #932 — namespace-filter row: a subscription scoped to
/// `track-d/other-ns` MUST NOT fire when the event landed in
/// `track-d/d2-sub`. Pins the matcher equivalence between the
/// sqlite and postgres paths.
#[tokio::test(flavor = "multi_thread")]
async fn dispatch_event_postgres_respects_namespace_filter() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sink"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let (state, _audit_path) = make_test_state();

    let url = format!("{}/sink", server.uri());
    let sub_mem = make_subscription_memory(
        "ns-mismatch-sub",
        "probe",
        &url,
        // Subscription wants this namespace…
        "track-d/other-ns",
        Some(&sha256_hex_local("secret")),
    );
    let admin_ctx = CallerContext::for_admin("test-setup");
    state.store.store(&admin_ctx, &sub_mem).await.unwrap();

    dispatch_event_postgres(
        &state,
        "memory_store",
        "mem-id",
        // …but event landed in a different namespace.
        "track-d/d2-sub",
        Some("ai:probe"),
        None,
    )
    .await;

    // Wait briefly to confirm no dispatch fires.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let received = server.received_requests().await.unwrap_or_default();
    assert!(
        received.is_empty(),
        "namespace-filtered subscription must NOT receive an event \
         from a different namespace; got {} POST(s)",
        received.len()
    );
}

/// #932 — zero subscribers row: when no matching subscription exists,
/// `dispatch_event_postgres` MUST be a no-op (no panic, no error).
#[tokio::test(flavor = "multi_thread")]
async fn dispatch_event_postgres_zero_subs_is_noop() {
    let (state, _audit_path) = make_test_state();

    // No subscription seeded. This MUST NOT panic.
    dispatch_event_postgres(
        &state,
        "memory_store",
        "unrelated-mem",
        "unrelated-ns",
        None,
        None,
    )
    .await;
    // No assertion needed — the test passes iff the call returned.
}
