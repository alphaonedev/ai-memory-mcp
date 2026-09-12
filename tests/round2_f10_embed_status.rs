// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::manual_let_else, clippy::map_unwrap_or)]
//! v0.7.0 Round-2 F10 — embedder skip / fail surfaces `embed_status`
//! in the HTTP store response.
//!
//! Pre-F10 behaviour: a memory whose content blew past the embedder's
//! token budget still committed at the row level (correct — embeddings
//! are an enhancement layer, not a write-path gate) but the HTTP
//! response was indistinguishable from a normal 201 even though the
//! row would silently miss every semantic-recall query until a
//! re-index. F10 surfaces the skip/fail outcome on the response by
//! consuming Fix-Agent α's `embeddings::EmbedStatus` enum +
//! `Embedder::embed_with_status` producer.
//!
//! ## Wire shape
//!
//! Non-`Indexed` outcomes add an `embed_status` (and an
//! `embed_status_reason`) field to the 201 response body:
//!
//! ```json
//! { "id": "...", "embed_status": "skipped", "embed_status_reason": "..." }
//! ```
//!
//! The `Indexed` (success) path intentionally does NOT add the field
//! so the response shape is unchanged for the common case.
//!
//! ## Local-model availability
//!
//! The `Embedder::new_local()` constructor pulls the MiniLM model from
//! HuggingFace Hub. On CI workers without a pre-warmed cache + no
//! network this fails; we follow α's F6 pattern and `return` cleanly
//! so the suite stays green on offline workers. The contract is still
//! pinned at the lower layer by α's `embed_status_*` unit tests in
//! `src/embeddings.rs` and by the F9/F7 sister tests above.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::embeddings::{EmbedStatus, Embedder};
use ai_memory::handlers::{ApiKeyState, AppState, Db};

/// #1751 — pin this test binary (and any spawned `ai-memory` child, which
/// inherits the process env) to the explicit permissive agent-attestation
/// opt-out. The v0.9 store-path default is REQUIRED and would reject this
/// suite's unsigned store fixtures; the required default itself is pinned
/// in `tests/agent_attestation_integrity.rs` + `tests/config_precedence.rs`.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for
    // the process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}
fn build_router_with_embedder(embedder: Option<Embedder>) -> (axum::Router, NamedTempFile) {
    permissive_attestation_for_tests();
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(embedder),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),

        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

async fn post(router: &axum::Router, body: Value) -> (StatusCode, Value) {
    // #907/#910 — auto-derive X-Agent-Id from body.agent_id so the
    // spoof-match check + SAL visibility filter both see the same
    // caller. Otherwise the post 403s on the spoof guard.
    let body_agent_id = body
        .get("agent_id")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json");
    if let Some(aid) = body_agent_id.as_deref() {
        req = req.header("x-agent-id", aid);
    }
    let req = req
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

#[tokio::test]
async fn http_oversized_content_surfaces_skipped_embed_status() {
    // F10 acceptance: content >64KB returns 201 (row committed) AND
    // `embed_status: "skipped"` so the caller can tell semantic
    // recall will miss this row until a re-index.
    let local = match Embedder::new_local() {
        Ok(e) => e,
        Err(_) => {
            // Offline CI worker — see the module-level note. Skip
            // cleanly; α's `embed_status_*` unit tests cover the
            // lower-layer contract, and the F9/F7 sister tests cover
            // the rest of the HTTP path.
            return;
        }
    };
    let (router, _keep) = build_router_with_embedder(Some(local));

    // The HTTP store path validates `content.len() <= MAX_CONTENT_SIZE`
    // (= 65536 = EMBED_MAX_BYTES) before the handler ever sees the body.
    // To exercise the embedder-skip branch we need:
    //   * a content that PASSES the validator (≤ 65536 bytes), AND
    //   * a concatenated `"{title} {content}"` that EXCEEDS the
    //     embedder cap (> 65536 bytes).
    // Title + space adds 19 bytes; content at 65530 bytes makes the
    // embedded text 65530 + 1 + 18 = 65549 > 65536 → Skipped.
    let title = "oversized embedder";
    let content = "x".repeat(65_530);
    let body = json!({
        "tier": "long",
        "namespace": "round2-f10",
        "title": title,
        "content": content,
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "metadata": {},
        "agent_id": "round2-f10-agent",
    });
    let (status, payload) = post(&router, body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "F10: row must still commit at 201 even when the embedder skips (got {status})"
    );
    let embed_status = payload.get("embed_status").and_then(|v| v.as_str()).expect(
        "F10: response must include `embed_status` field on non-Indexed outcomes \
             (got payload without that field)",
    );
    assert!(
        embed_status == "skipped" || embed_status == "failed",
        "F10: oversized-content branch should map to `skipped` or `failed` (got {embed_status:?})"
    );
    assert!(
        payload.get("id").and_then(|v| v.as_str()).is_some(),
        "F10: skip-branch response must still carry the row `id` so the caller can \
         re-index later"
    );
    // The reason field carries the human-facing detail (e.g. "content
    // 71680 bytes exceeds embed cap 65536 bytes"). Best-effort assert
    // that it is populated for the skip path.
    if embed_status == "skipped" {
        assert!(
            payload
                .get("embed_status_reason")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "F10: skip path should populate `embed_status_reason`"
        );
    }
}

#[tokio::test]
async fn http_empty_content_surfaces_skipped_embed_status() {
    // α's `embed_with_status` reports `Skipped("empty content")` on
    // empty input. We can't actually POST a memory with empty content
    // (validate::validate_create rejects it), so we use a single-char
    // title and content that, after concat, the embedder still treats
    // as legitimate input — the empty-content branch is exercised at
    // the lower layer by α's unit tests. Here we just pin that an
    // available embedder + a normal-size body produces an `Indexed`
    // outcome (no `embed_status` field surfaced).
    let local = match Embedder::new_local() {
        Ok(e) => e,
        Err(_) => return,
    };
    let (router, _keep) = build_router_with_embedder(Some(local));

    let body = json!({
        "tier": "long",
        "namespace": "round2-f10",
        "title": "small body",
        "content": "small enough to embed cleanly",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "metadata": {},
        "agent_id": "round2-f10-agent-ok",
    });
    let (status, payload) = post(&router, body).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(
        payload.get("embed_status").is_none(),
        "F10: success path must NOT include `embed_status` (got {payload})"
    );
}

#[tokio::test]
async fn http_keyword_only_node_does_not_surface_embed_status() {
    // Negative pin: a keyword-only deployment (embedder=None)
    // intentionally reports `Indexed` so we don't leak the
    // configuration outcome into every response. This branch runs
    // without the local model so it never has to skip on offline CI.
    let (router, _keep) = build_router_with_embedder(None);

    let body = json!({
        "tier": "long",
        "namespace": "round2-f10",
        "title": "keyword-only probe",
        "content": "keyword-only deployment must stay silent on embed_status",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "metadata": {},
        "agent_id": "round2-f10-keyword-agent",
    });
    let (status, payload) = post(&router, body).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(
        payload.get("embed_status").is_none(),
        "F10: keyword-only nodes (embedder=None) must not surface embed_status \
         (got {payload})"
    );
    // And a final shape probe: even on the keyword path the response
    // still carries the canonical `id`. Belt-and-braces against a
    // future change that reorganises the response builder.
    assert!(payload.get("id").and_then(|v| v.as_str()).is_some());
}

#[derive(Clone, Default)]
struct RedactionLog3648(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for RedactionLog3648 {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// #3648: provider echoes must never reach create HTTP responses or logs.
#[tokio::test(flavor = "multi_thread")]
async fn http_provider_echo_is_redacted_3648() {
    use ai_memory::llm::OllamaClient;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SECRET: &str = "provider-echo-credential-3648";
    let logs = RedactionLog3648::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    for ollama in [false, true] {
        for (status, malformed_json) in [(401, false), (200, false), (200, true)] {
            let server = MockServer::start().await;
            let body = if malformed_json {
                format!("{{{SECRET}")
            } else {
                json!({"error": SECRET}).to_string()
            };
            Mock::given(method("POST"))
                .and(path(if ollama { "/api/embed" } else { "/embeddings" }))
                .respond_with(ResponseTemplate::new(status).set_body_string(body))
                .mount(&server)
                .await;
            let client = if ollama {
                OllamaClient::new_with_url_no_health_check(&server.uri(), "test").unwrap()
            } else {
                OllamaClient::new_openai_compatible(&server.uri(), "test", "test-key").unwrap()
            };
            let embedder = Embedder::new_remote(Arc::new(client), "test".to_string(), 4);
            let (router, _db) = build_router_with_embedder(Some(embedder));
            let (code, payload) = post(&router, json!({
            "title": "redaction regression", "content": "ordinary memory", "agent_id": "test-agent"
        })).await;
            assert_eq!(code, StatusCode::CREATED, "{payload}");
            assert_eq!(payload["embed_status"], "failed", "{payload}");
            let reason = payload["embed_status_reason"].as_str().unwrap();
            assert!(!reason.contains(SECRET), "provider echo leaked: {reason}");
            assert!(reason.len() < 256, "failure metadata must be bounded");
            let provider = if ollama {
                "ollama"
            } else {
                "openai_compatible"
            };
            assert!(
                reason.contains(provider),
                "must retain safe provider identity: {reason}"
            );
        }
    }
    let rendered = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        rendered.contains("embed_with_status: embedder failed"),
        "must capture failure logs"
    );
    assert!(
        !rendered.contains(SECRET),
        "provider echo leaked to logs: {rendered}"
    );
}

// #3648: local failures remain actionable for operators while wire metadata is bounded.
#[test]
fn local_embedder_cause_is_operator_only_3648() {
    use candle_core::{DType, Device};
    use candle_nn::VarBuilder;
    use candle_transformers::models::bert::{BertModel, Config};
    use tokenizers::{Tokenizer, models::wordlevel::WordLevel};

    let config = Config {
        vocab_size: 1,
        hidden_size: 2,
        num_hidden_layers: 0,
        num_attention_heads: 1,
        intermediate_size: 2,
        max_position_embeddings: 2,
        type_vocab_size: 1,
        ..Config::default()
    };
    let device = Device::Cpu;
    let model = BertModel::load(VarBuilder::zeros(DType::F32, &device), &config).unwrap();
    // An empty vocabulary cannot encode input: no model downloads or network needed.
    let embedder = Embedder::Local {
        model: Arc::new(model),
        tokenizer: Arc::new(Tokenizer::new(WordLevel::default())),
        device,
    };
    let cause = embedder.embed("local failure").unwrap_err();
    let logs = RedactionLog3648::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    let (vector, status) = tracing::subscriber::with_default(subscriber, || {
        embedder.embed_with_status("local failure")
    });
    assert!(vector.is_none());
    assert_eq!(status, EmbedStatus::Failed("embedding_failed".to_string()));
    let rendered = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        rendered.contains(&format!("{cause:#}")),
        "operator log must retain the complete local error chain: {rendered}"
    );
}
