// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1566 / #1579 B1 — embed-once-replicate-vector + ack-after-commit.
//!
//! Pre-fix, the federation receiver embedded every applied row
//! synchronously (~1s/row via ollama) WHILE HOLDING the DB lock,
//! inside the sender's quorum-ack window — the mechanism behind the
//! `deadline_exceeded` → DLQ cascade (#1578's 62k-row event) and the
//! up-to-9× duplicate embedding across the fleet. This suite pins the
//! new contract end-to-end through the production router
//! (`ai_memory::build_router` + `tower::ServiceExt::oneshot`, the
//! #922-test pattern):
//!
//! 1. **Wire tolerance** — a `/sync/push` body WITHOUT the new
//!    `embeddings` field (the pre-#1566 / older-peer shape) is
//!    accepted unchanged, and `ShippedEmbedding` round-trips through
//!    serde.
//! 2. **Ship-the-vector** — a dim-matching shipped vector is stored
//!    directly on the receiver with ZERO local embed calls.
//! 3. **Dim-mismatch fallback** — a mismatched vector is ignored and
//!    the row is embedded by the deferred background path instead.
//! 4. **Ack-after-commit** — a receiver whose embedder is SLOW
//!    (mock ollama with a per-call delay) still acks the push well
//!    inside the deadline; the embeddings land in the background.
//! 5. **Signature covers the vector** — the `embeddings` array rides
//!    inside the Ed25519-signed body bytes, so tampering with one
//!    vector element invalidates `X-Memory-Sig` (401).

#![allow(clippy::too_many_lines)]
// The env_lock guard is intentionally held across .await points so no
// other test can observe intermediate `AI_MEMORY_FED_REQUIRE_*` state
// (same discipline as tests/federation_nonce_replay_922.rs).
#![allow(clippy::await_holding_lock)]
// `..Memory::default()` in the fixture keeps compiling when Memory
// gains fields (the same posture as tests/federation_inbound_verify.rs).
#![allow(clippy::needless_update)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::Mutex;
use tower::ServiceExt as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::embeddings::Embedder;
use ai_memory::federation::ShippedEmbedding;
use ai_memory::federation::signing::{
    NONCE_HEADER, REQUIRE_NONCE_ENV, REQUIRE_SIG_ENV, SIGNATURE_HEADER, sign_body_with_nonce_header,
};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::keypair as kp_mod;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};

const SENDER_ID: &str = "ai:peer-1566";

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex as StdMutex, OnceLock};
    static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Stand up a wiremock ollama that answers `/api/embed` with a fixed
/// `dim`-length vector after `delay`. Returns the server (keep it
/// alive for the test's duration).
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

/// Build a receiver `AppState` + production router, optionally wired
/// with a mock-ollama embedder (768-dim nomic shape). Mirrors the
/// #922 test fixture.
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
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    Receiver {
        router,
        db,
        _db_tmp: db_tmp,
    }
}

fn build_ollama_embedder(base_url: &str) -> Embedder {
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
        namespace: "fed-1566".to_string(),
        title: format!("embed-ship probe {id}"),
        content: "embed-once-replicate-vector regression body (#1566/#1579 B1)".to_string(),
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

fn push_body(mems: &[Memory], shipped: Option<&[ShippedEmbedding]>) -> Value {
    let mut body = json!({
        "sender_agent_id": SENDER_ID,
        "sender_clock": {"entries": {}},
        "memories": mems,
        "dry_run": false,
    });
    if let Some(ship) = shipped {
        body["embeddings"] = json!(ship);
    }
    body
}

async fn post_push(
    router: &axum::Router,
    body_bytes: Vec<u8>,
    sig: Option<&str>,
    nonce: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            SENDER_ID,
        );
    if let Some(sig) = sig {
        builder = builder.header(SIGNATURE_HEADER, sig);
    }
    if let Some(nonce) = nonce {
        builder = builder.header(NONCE_HEADER, nonce);
    }
    let req = builder.body(Body::from(body_bytes)).unwrap();
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

/// Poll until the row has an embedding or the budget elapses.
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

// ---------------------------------------------------------------------------
// 1. Wire tolerance — serde round trips, with AND without the field.
// ---------------------------------------------------------------------------

#[test]
fn shipped_embedding_serde_round_trip() {
    let se = ShippedEmbedding::new(
        "mem-rt".to_string(),
        "nomic-embed-text-v1.5 (768-dim, Ollama)".to_string(),
        vec![0.25_f32, -1.5, 3.0],
    );
    assert_eq!(se.dim, 3, "dim is derived from the vector length");
    let wire = serde_json::to_value(&se).expect("serialize");
    let back: ShippedEmbedding = serde_json::from_value(wire).expect("deserialize");
    assert_eq!(back.memory_id, "mem-rt");
    assert_eq!(back.model, se.model);
    assert_eq!(back.dim, 3);
    assert_eq!(back.vector, vec![0.25_f32, -1.5, 3.0]);
}

#[test]
fn sync_push_body_decodes_with_and_without_embeddings_field() {
    // Older-peer shape: no `embeddings` key at all → empty vec.
    let old: ai_memory::handlers::SyncPushBody = serde_json::from_value(json!({
        "sender_agent_id": SENDER_ID,
        "memories": [],
    }))
    .expect("pre-#1566 body must decode unchanged");
    assert!(
        old.embeddings.is_empty(),
        "absent field must default to empty (tolerant decode)"
    );

    // New shape: field present → parsed.
    let new: ai_memory::handlers::SyncPushBody = serde_json::from_value(json!({
        "sender_agent_id": SENDER_ID,
        "memories": [],
        "embeddings": [
            {"memory_id": "m1", "model": "test-model-768", "dim": 2, "vector": [1.0, 2.0]}
        ],
    }))
    .expect("post-#1566 body must decode");
    assert_eq!(new.embeddings.len(), 1);
    assert_eq!(new.embeddings[0].memory_id, "m1");
    assert_eq!(new.embeddings[0].vector, vec![1.0_f32, 2.0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn push_without_embeddings_field_is_accepted_old_peer_shape() {
    let _g = env_lock();
    // SAFETY: env mutation under env_lock; restored semantics by every
    // test in this file setting the vars it needs explicitly.
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
    }
    let rx = build_receiver(None);
    let mem = sample_memory("old-shape-1");
    let body = push_body(std::slice::from_ref(&mem), None);
    let (status, v) = post_push(&rx.router, serde_json::to_vec(&body).unwrap(), None, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "old-peer body must be accepted: {v}"
    );
    assert_eq!(v["applied"], 1, "row applied: {v}");
}

// ---------------------------------------------------------------------------
// 2. Ship-the-vector — dim match → stored directly, zero local embeds.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn shipped_vector_stored_directly_without_receiver_embed() {
    let _g = env_lock();
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
    }
    let ollama = mock_ollama_embed(768, 0.5, Duration::ZERO).await;
    let embedder = build_ollama_embedder(&ollama.uri());
    let dim = embedder.dim();
    let rx = build_receiver(Some(embedder));

    let mem = sample_memory("ship-direct-1");
    // A distinctive UNIT-NORM fill (≠ the mock server's 0.5) so the
    // assertion below can tell a verbatim-stored shipped vector from a
    // (buggy) receiver-side re-embed. #1584: the fill is 1/sqrt(dim) so
    // the vector is already L2-normalized and `sanitize_shipped_vector`
    // stores it byte-for-byte (a well-behaved peer ships normalized
    // vectors). A non-normalized fill is covered by
    // `non_normalized_shipped_vector_is_stored_normalized_1584`.
    let shipped_vec: Vec<f32> = vec![1.0_f32 / (dim as f32).sqrt(); dim];
    let shipped = vec![ShippedEmbedding::new(
        mem.id.clone(),
        "sender-model".to_string(),
        shipped_vec.clone(),
    )];
    let body = push_body(std::slice::from_ref(&mem), Some(&shipped));
    let (status, v) = post_push(&rx.router, serde_json::to_vec(&body).unwrap(), None, None).await;
    assert_eq!(status, StatusCode::OK, "push must be acked: {v}");
    assert_eq!(v["applied"], 1, "row applied: {v}");

    // The shipped vector is stored verbatim, synchronously with the ack.
    let stored = stored_embedding(&rx.db, &mem.id)
        .await
        .expect("shipped vector must be stored");
    assert_eq!(
        stored, shipped_vec,
        "receiver must store the SHIPPED vector, not a re-embed"
    );

    // Give any (buggy) background embed a beat to fire, then assert
    // the receiver's embedder was never called — the whole point of
    // embed-once-replicate-vector.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        embed_calls(&ollama).await,
        0,
        "dim-matching shipped vector must produce ZERO receiver-side embed calls"
    );
}

// ---------------------------------------------------------------------------
// 3. Dim-mismatch fallback — shipped vector ignored, deferred embed runs.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn dim_mismatch_falls_back_to_deferred_local_embed() {
    let _g = env_lock();
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
    }
    let ollama = mock_ollama_embed(768, 0.25, Duration::ZERO).await;
    let embedder = build_ollama_embedder(&ollama.uri());
    let dim = embedder.dim();
    let rx = build_receiver(Some(embedder));

    let mem = sample_memory("dim-mismatch-1");
    // 384-dim vector against a 768-dim receiver → mismatch.
    let shipped = vec![ShippedEmbedding::new(
        mem.id.clone(),
        "sender-minilm-384".to_string(),
        vec![0.9_f32; 384],
    )];
    let body = push_body(std::slice::from_ref(&mem), Some(&shipped));
    let (status, v) = post_push(&rx.router, serde_json::to_vec(&body).unwrap(), None, None).await;
    assert_eq!(status, StatusCode::OK, "push must be acked: {v}");
    assert_eq!(v["applied"], 1, "row applied despite dim mismatch: {v}");

    // The deferred background embed must land the receiver-dim vector.
    let stored = wait_for_embedding(&rx.db, &mem.id, Duration::from_secs(10))
        .await
        .expect("deferred embed must populate the row");
    assert_eq!(
        stored.len(),
        dim,
        "stored vector must be the receiver's local embed (receiver dim), \
         not the mismatched shipped one"
    );
    assert!(
        embed_calls(&ollama).await >= 1,
        "dim mismatch must trigger exactly the deferred local embed path"
    );
}

// ---------------------------------------------------------------------------
// 4. Ack-after-commit — slow embedder must NOT delay the quorum ack.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn slow_embedder_does_not_delay_sync_push_ack() {
    let _g = env_lock();
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
    }
    // 2s per embed call — the pre-#1566 inline loop would have spent
    // 2 rows × 2s = 4s INSIDE this request (and inside the sender's
    // quorum window, which defaults to 2s).
    let ollama = mock_ollama_embed(768, 0.75, Duration::from_secs(2)).await;
    let embedder = build_ollama_embedder(&ollama.uri());
    let rx = build_receiver(Some(embedder));

    let mems = vec![sample_memory("slow-embed-1"), sample_memory("slow-embed-2")];
    let body = push_body(&mems, None);

    let started = Instant::now();
    let (status, v) = post_push(&rx.router, serde_json::to_vec(&body).unwrap(), None, None).await;
    let elapsed = started.elapsed();
    assert_eq!(status, StatusCode::OK, "push must be acked: {v}");
    assert_eq!(v["applied"], 2, "both rows applied: {v}");
    assert!(
        elapsed < Duration::from_millis(1500),
        "ack must NOT wait on the embedder (2 rows × 2s embed); took {elapsed:?}"
    );

    // The background path must still converge both rows.
    for mem in &mems {
        let stored = wait_for_embedding(&rx.db, &mem.id, Duration::from_secs(15))
            .await
            .unwrap_or_else(|| panic!("background embed must land for {}", mem.id));
        assert_eq!(stored.len(), 768);
    }
}

// ---------------------------------------------------------------------------
// 5. Signature covers the vector — tampering with a shipped vector
//    element invalidates X-Memory-Sig.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn signature_covers_shipped_vector_tamper_yields_401() {
    let _g = env_lock();
    let key_tmp = TempDir::new().expect("key tempdir");
    // SAFETY: env mutation under env_lock for the test's duration.
    unsafe {
        std::env::set_var("AI_MEMORY_KEY_DIR", key_tmp.path());
        std::env::set_var(REQUIRE_SIG_ENV, "1");
        std::env::set_var(REQUIRE_NONCE_ENV, "1");
    }

    // Receiver enrols the sender's public key (the #922 fixture shape).
    let sender = kp_mod::generate(SENDER_ID).expect("generate sender keypair");
    let sender_pub_only = kp_mod::AgentKeypair {
        agent_id: sender.agent_id.clone(),
        public: sender.public,
        private: None,
    };
    kp_mod::save_public_only(&sender_pub_only, key_tmp.path()).expect("enrol sender pubkey");

    let rx = build_receiver(None);
    let mem = sample_memory("sig-vector-1");
    // 42.5 is exactly representable in f32 so it serialises as the
    // literal "42.5" (no f32→f64 mantissa tail) — the tamper step
    // below string-replaces it in the wire bytes.
    let marker = 42.5_f32;
    let mut vector = vec![0.0_f32; 4];
    vector[0] = marker;
    let shipped = vec![ShippedEmbedding::new(
        mem.id.clone(),
        "sender-model".to_string(),
        vector,
    )];
    let body = push_body(std::slice::from_ref(&mem), Some(&shipped));
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let priv_key = sender.private.as_ref().expect("sender private key");

    // (a) Valid signature over the embeddings-carrying body → accepted.
    let nonce1 = uuid::Uuid::new_v4().to_string();
    let sig1 = sign_body_with_nonce_header(priv_key, &body_bytes, &nonce1);
    let (status, v) = post_push(&rx.router, body_bytes.clone(), Some(&sig1), Some(&nonce1)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "signed embeddings-carrying push must verify + apply: {v}"
    );
    assert_eq!(v["applied"], 1, "{v}");

    // (b) Tamper ONE vector element in the wire bytes, keep the (now
    // stale) signature with a FRESH nonce — the receiver must refuse.
    // A fresh nonce isolates the failure to the SIGNATURE arm (a
    // replayed nonce would 401 regardless of the body bytes).
    let tampered = String::from_utf8(body_bytes.clone())
        .unwrap()
        .replace("42.5", "43.5")
        .into_bytes();
    assert_ne!(tampered, body_bytes, "tamper must change the wire bytes");
    let nonce2 = uuid::Uuid::new_v4().to_string();
    let sig2 = sign_body_with_nonce_header(priv_key, &body_bytes, &nonce2);
    let (status, v) = post_push(&rx.router, tampered, Some(&sig2), Some(&nonce2)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a tampered shipped vector must invalidate X-Memory-Sig: {v}"
    );

    unsafe {
        std::env::remove_var(REQUIRE_SIG_ENV);
        std::env::remove_var(REQUIRE_NONCE_ENV);
        std::env::remove_var("AI_MEMORY_KEY_DIR");
    }
}

// ---------------------------------------------------------------------------
// 6. #1584 (SEC) — value-domain validation of shipped vectors.
//    The dim gate is necessary but not sufficient: a dim-matching
//    vector with NaN/±Inf components or a non-unit norm would poison
//    cosine ranking if stored verbatim. `sanitize_shipped_vector`
//    rejects non-finite vectors (→ local re-embed) and L2-normalizes
//    the rest.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn nan_shipped_vector_rejected_at_json_wire_boundary_1584() {
    // #1584 — non-finite f32 components (NaN / ±Inf) cannot cross the
    // JSON federation wire at all: serde_json serializes them to `null`,
    // and the strict `Vec<f32>` deserializer on `/sync/push` rejects
    // `null` with a 400 ("invalid type: null, expected f32"). This test
    // pins that the JSON transport itself blocks the NaN-injection
    // vector. The `federation::sanitize_shipped_vector` finite check
    // (unit-tested in src/federation/mod.rs) + the
    // `Embedder::cosine_similarity` finite guard are the defense-in-depth
    // layer for any NON-JSON path (a future binary wire format, a
    // direct-call ingest) that could carry a non-finite component past
    // serde.
    let _g = env_lock();
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
    }
    let ollama = mock_ollama_embed(768, 0.5, Duration::ZERO).await;
    let embedder = build_ollama_embedder(&ollama.uri());
    let dim = embedder.dim();
    let rx = build_receiver(Some(embedder));

    let mem = sample_memory("ship-nan-1584");
    let mut poisoned = vec![0.1_f32; dim];
    poisoned[7] = f32::NAN;
    let shipped = vec![ShippedEmbedding::new(
        mem.id.clone(),
        "malicious-peer".to_string(),
        poisoned,
    )];
    let body = push_body(std::slice::from_ref(&mem), Some(&shipped));
    let (status, v) = post_push(&rx.router, serde_json::to_vec(&body).unwrap(), None, None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#1584: a NaN shipped-vector component must be rejected at the \
         JSON deserialization boundary, not stored: {v}"
    );

    unsafe {
        std::env::remove_var(REQUIRE_SIG_ENV);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn non_normalized_shipped_vector_is_stored_normalized_1584() {
    let _g = env_lock();
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
    }
    let ollama = mock_ollama_embed(768, 0.5, Duration::ZERO).await;
    let embedder = build_ollama_embedder(&ollama.uri());
    let dim = embedder.dim();
    let rx = build_receiver(Some(embedder));

    let mem = sample_memory("ship-bignorm-1584");
    // A finite but HIGH-magnitude vector (norm = sqrt(dim)*5 ≫ 1). Pre-#1584
    // this stored verbatim and would inflate its dot product against
    // every query (the cheapest ranking-manipulation primitive).
    let shipped_vec: Vec<f32> = vec![5.0_f32; dim];
    let shipped = vec![ShippedEmbedding::new(
        mem.id.clone(),
        "non-normalized-peer".to_string(),
        shipped_vec,
    )];
    let body = push_body(std::slice::from_ref(&mem), Some(&shipped));
    let (status, v) = post_push(&rx.router, serde_json::to_vec(&body).unwrap(), None, None).await;
    assert_eq!(status, StatusCode::OK, "push acked: {v}");
    assert_eq!(v["applied"], 1, "row applied: {v}");

    // Stored synchronously with the ack (finite → no local embed), but
    // L2-NORMALIZED, not verbatim.
    let stored = stored_embedding(&rx.db, &mem.id)
        .await
        .expect("finite shipped vector stored");
    let norm: f32 = stored.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!(
        (norm - 1.0).abs() < 1e-4,
        "#1584: a non-normalized shipped vector must be stored L2-normalized; got norm {norm}"
    );
    // Direction preserved: every component equal ⇒ each is 1/sqrt(dim).
    let expected = 1.0_f32 / (dim as f32).sqrt();
    assert!(
        (stored[0] - expected).abs() < 1e-4,
        "#1584: normalization must preserve direction"
    );
    assert_eq!(
        embed_calls(&ollama).await,
        0,
        "#1584: a finite (normalizable) shipped vector must NOT trigger a re-embed"
    );

    unsafe {
        std::env::remove_var(REQUIRE_SIG_ENV);
    }
}
