// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2168 (SEC, data-integrity) — federation inbound embedding-model
//! fingerprint gate.
//!
//! The #1566 / #1579 B1 embed-ship receive path stored a peer-shipped
//! vector verbatim once it passed the DIMENSION + finiteness/L2-norm
//! (#1584) gates — but it never compared the shipped `model` against the
//! receiver's own embedder identity. A same-dimension vector produced by
//! a DIFFERENT embedding model (or the same model under a different
//! prefix scheme) lives in a different coordinate space: stored verbatim
//! it silently poisons the receiver's cosine recall (a numerically-valid
//! but semantically-meaningless score — no error, no WARN, no counter).
//!
//! This suite pins the fix end-to-end through the production router:
//!
//! 1. **Foreign model → deferred re-embed** — a same-dim vector whose
//!    `model` fingerprint differs from the receiver's is NOT stored
//!    verbatim; the row still lands (CRDT-safe) and is re-embedded under
//!    the LOCAL model. The foreign vector NEVER reaches the stored
//!    embedding (CORE INVARIANT: degrade, never corrupt).
//! 2. **Matching model → stored verbatim** — no #1566 perf regression.
//! 3. **Bare-id matching model → stored verbatim** — the fingerprint is
//!    prose-tolerant (`"nomic-embed-text"` matches
//!    `"nomic-embed-text (768-dim, remote)"`).
//! 4. **#1584 still applies under a matching fingerprint** — a
//!    non-normalized matching-space vector is stored L2-normalized.
//!
//! The sqlite funnel (`federation_receive::sync_push`) is exercised
//! directly here; the postgres funnel (`sync_push_via_store`) is its
//! cross-backend twin (identical gate, `sal-postgres` build).

#![allow(clippy::too_many_lines)]
// The env_lock guard is intentionally held across .await points (same
// discipline as tests/federation_1566_embed_ship.rs).
#![allow(clippy::await_holding_lock)]
#![allow(clippy::needless_update)]
#![allow(clippy::cast_precision_loss)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::embeddings::Embedder;
use ai_memory::federation::ShippedEmbedding;
use ai_memory::federation::signing::REQUIRE_SIG_ENV;
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};

const SENDER_ID: &str = "ai:peer-2168";
/// The mock ollama fill returned by the receiver's LOCAL re-embed — a
/// distinctive value the foreign shipped vector never carries, so the
/// stored embedding unambiguously reveals which path wrote it.
const LOCAL_REEMBED_FILL: f32 = 0.5;

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex as StdMutex, OnceLock};
    static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn mock_ollama_embed(dim: usize, fill: f32, delay: Duration) -> MockServer {
    let server = MockServer::start().await;
    let vector: Vec<f32> = vec![fill; dim];
    Mock::given(method("POST"))
        .and(path("/api/embed"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"embeddings": [vector]}))
                .set_delay(delay),
        )
        .mount(&server)
        .await;
    server
}

async fn embed_calls(server: &MockServer) -> usize {
    server.received_requests().await.map_or(0, |reqs| {
        reqs.iter().filter(|r| r.url.path() == "/api/embed").count()
    })
}

struct Receiver {
    router: axum::Router,
    db: Db,
    _db_tmp: tempfile::NamedTempFile,
}

fn build_receiver(embedder: Option<Embedder>) -> Receiver {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));

    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let app_state = AppState {
        db: db.clone(),
        embedder: Arc::new(embedder),
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
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    Receiver {
        router,
        db,
        _db_tmp: db_tmp,
    }
}

/// A remote (Ollama) embedder pinned to `nomic-embed-text` (768-dim,
/// nomic prefix scheme) backed by the mock server.
fn build_nomic_embedder(base_url: &str) -> Embedder {
    let client =
        ai_memory::llm::OllamaClient::new_with_url_no_health_check(base_url, "nomic-embed-text")
            .expect("mock ollama client");
    Embedder::new_ollama(Arc::new(client))
}

fn sample_memory(id: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: "fed-2168".to_string(),
        title: format!("fingerprint-gate probe {id}"),
        content: "foreign-embedding-model receive-gate regression body (#2168)".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "user".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": SENDER_ID}),
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

fn push_body(mems: &[Memory], shipped: &[ShippedEmbedding]) -> Value {
    json!({
        "sender_agent_id": SENDER_ID,
        "sender_clock": {"entries": {}},
        "memories": mems,
        "embeddings": shipped,
        "dry_run": false,
    })
}

async fn post_push(router: &axum::Router, body_bytes: Vec<u8>) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            SENDER_ID,
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

async fn stored_embedding(db: &Db, id: &str) -> Option<Vec<f32>> {
    let lock = db.lock().await;
    ai_memory::db::get_embedding(&lock.0, id).expect("get_embedding")
}

async fn wait_for_embedding(db: &Db, id: &str, budget: Duration) -> Option<Vec<f32>> {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(v) = stored_embedding(db, id).await {
            return Some(v);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn unit_norm_fill(dim: usize) -> Vec<f32> {
    vec![1.0_f32 / (dim as f32).sqrt(); dim]
}

// ---------------------------------------------------------------------------
// 1. Foreign model, SAME dim → deferred local re-embed; foreign vector
//    NEVER stored. The core #2168 invariant.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn foreign_model_shipped_vector_not_stored_verbatim_deferred_2168() {
    let _g = env_lock();
    // SAFETY: env mutation under env_lock for the test's duration.
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
    }
    // Receiver runs nomic-768; its local re-embed returns the distinctive
    // LOCAL_REEMBED_FILL vector.
    let ollama = mock_ollama_embed(768, LOCAL_REEMBED_FILL, Duration::ZERO).await;
    let embedder = build_nomic_embedder(&ollama.uri());
    let dim = embedder.dim();
    let rx = build_receiver(Some(embedder));

    let mem = sample_memory("foreign-model-1");
    // A SAME-DIMENSION (768) unit-norm vector produced by a DIFFERENT
    // model (granite-768). Passes the dim + #1584 norm gates; fails the
    // #2168 fingerprint gate. The fill (1/sqrt(768) ≈ 0.036) is distinct
    // from LOCAL_REEMBED_FILL so we can prove which path wrote storage.
    let foreign_vec = unit_norm_fill(dim);
    let shipped = vec![ShippedEmbedding::new(
        mem.id.clone(),
        "granite-embedding (768-dim, remote)".to_string(),
        foreign_vec.clone(),
    )];
    let body = push_body(std::slice::from_ref(&mem), &shipped);
    let (status, v) = post_push(&rx.router, serde_json::to_vec(&body).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "push must be acked: {v}");
    // CRDT-safe: the row still lands even though its foreign vector is
    // refused.
    assert_eq!(v["applied"], 1, "row must land (CRDT convergence): {v}");

    // Give the detached `tokio::spawn` a scheduling slice before we
    // poll. macos-fed CI (2026-08-26, 77e35229) timed the 10s budget
    // out on this cell while the empty-model twin in the same binary
    // passed; local default-features reproduce is 0.33s. The mock
    // delay is ZERO — this is scheduler slop, not embed latency.
    tokio::task::yield_now().await;
    let stored = wait_for_embedding(&rx.db, &mem.id, Duration::from_secs(30))
        .await
        .expect("deferred local re-embed must populate the row");
    assert_eq!(stored.len(), dim, "stored vector is receiver-dim");

    // INVARIANT: the stored embedding is the LOCAL re-embed, never the
    // foreign shipped vector. `set_embedding` is called ONLY by the
    // deferred path here (the gate routed the foreign vector to
    // `deferred_embed`, so it never reached `set_embedding` / the HNSW
    // insert), so storage can only ever hold the local re-embed.
    assert!(
        (stored[0] - LOCAL_REEMBED_FILL).abs() < 1e-6,
        "stored[0] must be the LOCAL re-embed fill, got {}",
        stored[0]
    );
    assert_ne!(
        stored, foreign_vec,
        "the foreign-fingerprint vector must NEVER be stored verbatim (#2168 CORE INVARIANT)"
    );
    assert!(
        embed_calls(&ollama).await >= 1,
        "fingerprint mismatch must trigger the deferred local re-embed"
    );

    unsafe {
        std::env::remove_var(REQUIRE_SIG_ENV);
    }
}

// ---------------------------------------------------------------------------
// 1b. Empty/degenerate model string, SAME dim → deferred local re-embed;
//     the empty-string wire value NEVER short-circuits into a false MATCH
//     (#2176, [#2168 Fable audit] regression-hardening follow-up).
//
//     `embedding_space_fingerprint("")` canonicalises to `"#none"`, which
//     can never equal the receiver's own fingerprint (its `id` half is
//     always non-empty — `model_description()` always names a real model),
//     so the only accepting path is exact equality with the receiver's
//     derived fingerprint. This pins that degenerate-wire-value disposition
//     as a regression proof rather than leaving it to code-reading: a
//     future refactor that special-cases an absent/empty model string as
//     "legacy sender, accept" would be caught here.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn empty_model_string_shipped_vector_not_stored_verbatim_deferred_2176() {
    let _g = env_lock();
    // SAFETY: env mutation under env_lock for the test's duration.
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
    }
    // Receiver runs nomic-768; its local re-embed returns the distinctive
    // LOCAL_REEMBED_FILL vector.
    let ollama = mock_ollama_embed(768, LOCAL_REEMBED_FILL, Duration::ZERO).await;
    let embedder = build_nomic_embedder(&ollama.uri());
    let dim = embedder.dim();
    let rx = build_receiver(Some(embedder));

    let mem = sample_memory("empty-model-1");
    // A SAME-DIMENSION (768) unit-norm vector shipped with an EMPTY
    // `model` string — the degenerate/absent-fingerprint wire value.
    // Passes the dim + #1584 norm gates; must still fail the #2168
    // fingerprint gate (fingerprint("") = "#none" != the receiver's
    // non-empty nomic fingerprint).
    let empty_model_vec = unit_norm_fill(dim);
    let shipped = vec![ShippedEmbedding::new(
        mem.id.clone(),
        String::new(),
        empty_model_vec.clone(),
    )];
    let body = push_body(std::slice::from_ref(&mem), &shipped);
    let (status, v) = post_push(&rx.router, serde_json::to_vec(&body).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "push must be acked: {v}");
    // CRDT-safe: the row still lands even though its degenerate-model
    // vector is refused.
    assert_eq!(v["applied"], 1, "row must land (CRDT convergence): {v}");

    // Give the detached `tokio::spawn` a scheduling slice before we
    // poll. macos-fed CI (2026-08-26, 77e35229) timed the 10s budget
    // out on this cell while the empty-model twin in the same binary
    // passed; local default-features reproduce is 0.33s. The mock
    // delay is ZERO — this is scheduler slop, not embed latency.
    tokio::task::yield_now().await;
    let stored = wait_for_embedding(&rx.db, &mem.id, Duration::from_secs(30))
        .await
        .expect("deferred local re-embed must populate the row");
    assert_eq!(stored.len(), dim, "stored vector is receiver-dim");

    // INVARIANT: the stored embedding is the LOCAL re-embed, never the
    // empty-model shipped vector.
    assert!(
        (stored[0] - LOCAL_REEMBED_FILL).abs() < 1e-6,
        "stored[0] must be the LOCAL re-embed fill, got {}",
        stored[0]
    );
    assert_ne!(
        stored, empty_model_vec,
        "an empty-model-string shipped vector must NEVER be stored verbatim (#2176/#2168)"
    );
    assert!(
        embed_calls(&ollama).await >= 1,
        "empty-model fingerprint mismatch must trigger the deferred local re-embed"
    );

    unsafe {
        std::env::remove_var(REQUIRE_SIG_ENV);
    }
}

// ---------------------------------------------------------------------------
// 2. Matching model → stored verbatim (no #1566 perf regression).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn matching_model_shipped_vector_stored_verbatim_2168() {
    let _g = env_lock();
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
    }
    let ollama = mock_ollama_embed(768, LOCAL_REEMBED_FILL, Duration::ZERO).await;
    let embedder = build_nomic_embedder(&ollama.uri());
    let dim = embedder.dim();
    // A well-behaved peer on the SAME model ships its model_description().
    let model_desc = embedder.model_description();
    let rx = build_receiver(Some(embedder));

    let mem = sample_memory("matching-model-1");
    let shipped_vec = unit_norm_fill(dim);
    let shipped = vec![ShippedEmbedding::new(
        mem.id.clone(),
        model_desc.clone(),
        shipped_vec.clone(),
    )];
    let body = push_body(std::slice::from_ref(&mem), &shipped);
    let (status, v) = post_push(&rx.router, serde_json::to_vec(&body).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "push acked: {v}");
    assert_eq!(v["applied"], 1, "{v}");

    // Stored verbatim, synchronously with the ack.
    let stored = stored_embedding(&rx.db, &mem.id)
        .await
        .expect("matching-fingerprint vector must be stored");
    assert_eq!(
        stored, shipped_vec,
        "a matching-fingerprint vector must be stored verbatim (no #1566 regression)"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        embed_calls(&ollama).await,
        0,
        "a matching-fingerprint shipped vector must produce ZERO receiver-side embeds"
    );

    unsafe {
        std::env::remove_var(REQUIRE_SIG_ENV);
    }
}

// ---------------------------------------------------------------------------
// 3. Bare-id matching model → stored verbatim (prose-tolerant parse):
//    the same model + same dim is accepted whether the wire carries the
//    display prose or the bare id token.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn same_model_bare_id_accepted_2168() {
    let _g = env_lock();
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
    }
    let ollama = mock_ollama_embed(768, LOCAL_REEMBED_FILL, Duration::ZERO).await;
    let embedder = build_nomic_embedder(&ollama.uri());
    let dim = embedder.dim();
    let rx = build_receiver(Some(embedder));

    let mem = sample_memory("bare-id-1");
    let shipped_vec = unit_norm_fill(dim);
    // Bare model id (no " (…dim, …)" prose) — same fingerprint as the
    // receiver's `nomic-embed-text` embedder.
    let shipped = vec![ShippedEmbedding::new(
        mem.id.clone(),
        "nomic-embed-text".to_string(),
        shipped_vec.clone(),
    )];
    let body = push_body(std::slice::from_ref(&mem), &shipped);
    let (status, v) = post_push(&rx.router, serde_json::to_vec(&body).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "push acked: {v}");
    assert_eq!(v["applied"], 1, "{v}");

    let stored = stored_embedding(&rx.db, &mem.id)
        .await
        .expect("bare-id matching-fingerprint vector must be stored");
    assert_eq!(
        stored, shipped_vec,
        "bare-id same-model vector stored verbatim"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(embed_calls(&ollama).await, 0, "no receiver-side re-embed");

    unsafe {
        std::env::remove_var(REQUIRE_SIG_ENV);
    }
}

// ---------------------------------------------------------------------------
// 4. #1584 finiteness/norm still applies under a MATCHING fingerprint —
//    the fingerprint gate does not bypass the value-domain sanitizer.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn matching_fingerprint_non_normalized_still_normalized_1584_2168() {
    let _g = env_lock();
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
    }
    let ollama = mock_ollama_embed(768, LOCAL_REEMBED_FILL, Duration::ZERO).await;
    let embedder = build_nomic_embedder(&ollama.uri());
    let dim = embedder.dim();
    let model_desc = embedder.model_description();
    let rx = build_receiver(Some(embedder));

    let mem = sample_memory("matching-bignorm-1");
    // Matching fingerprint, but a finite HIGH-magnitude (non-unit-norm)
    // vector — #1584 must still L2-normalize it before storage.
    let shipped = vec![ShippedEmbedding::new(
        mem.id.clone(),
        model_desc.clone(),
        vec![5.0_f32; dim],
    )];
    let body = push_body(std::slice::from_ref(&mem), &shipped);
    let (status, v) = post_push(&rx.router, serde_json::to_vec(&body).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "push acked: {v}");
    assert_eq!(v["applied"], 1, "{v}");

    let stored = stored_embedding(&rx.db, &mem.id)
        .await
        .expect("finite matching-fingerprint vector stored");
    let norm: f32 = stored.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!(
        (norm - 1.0).abs() < 1e-4,
        "#1584 must still L2-normalize an accepted (matching-space) vector; got norm {norm}"
    );
    let expected = 1.0_f32 / (dim as f32).sqrt();
    assert!(
        (stored[0] - expected).abs() < 1e-4,
        "normalization must preserve direction"
    );
    assert_eq!(
        embed_calls(&ollama).await,
        0,
        "a finite matching-fingerprint vector must NOT trigger a re-embed"
    );

    unsafe {
        std::env::remove_var(REQUIRE_SIG_ENV);
    }
}
