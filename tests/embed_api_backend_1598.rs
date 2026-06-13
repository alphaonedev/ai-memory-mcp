// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1598 — wire-level integration coverage for the API-wired embedding
//! backend (W5a of the API-embeddings train).
//!
//! The in-module unit tests under `src/embeddings.rs::tests::*1598*`
//! pin the constructor surface (dynamic dim, truthful description,
//! degraded-latch against a dead endpoint). What they CANNOT reach is
//! the real HTTP wire: the OpenAI-compatible `/embeddings` + Bearer
//! request shape, the `data[0].embedding` response parse, the
//! degraded-flag round-trip across a live 401 → 200 sequence, and the
//! nomic task-prefix injection as it actually lands in the request
//! body. These tests stand up an in-process `wiremock` server speaking
//! the OpenAI-compatible embeddings wire shape (the same pattern as
//! `src/llm.rs::wiremock_tests`) and drive the production
//! [`Embedder`] against it.
//!
//! Covered #1598 additions:
//! - `Embedder::new_remote` + `embed()` end-to-end over the
//!   OpenAI-compatible wire (Bearer header, request body, response
//!   vector parse, `dim()`, `model_description()`).
//! - degraded-flag truthfulness (#1594): a live 401 latches
//!   `is_degraded() == true`; the next 2xx clears it.
//! - `Embedder::from_resolved` boot ladder: API backend → remote
//!   embedder (keyed and keyless), keyword tier → `None`,
//!   unknown-model-without-dim → loud `Err` naming the
//!   `[embeddings].dim` escape hatch.
//! - nomic task-prefix gating over the wire (#1520 / #1598): a
//!   `nomic-embed` family model id sends `search_document:` /
//!   `search_query:` prefixed inputs per role; a non-nomic model id
//!   sends the input verbatim.
//!
//! The `OllamaClient` embed path is blocking (`reqwest::blocking`-style
//! `block_on_local`) while wiremock is async, so every client call runs
//! under `tokio::task::spawn_blocking` (the `src/llm.rs` wiremock-test
//! convention).

use std::sync::Arc;

use ai_memory::config::{EmbeddingModel, ResolvedEmbeddings};
use ai_memory::embeddings::Embedder;
use ai_memory::llm::OllamaClient;
use serde_json::json;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// OpenAI-compatible embeddings response carrying one vector.
fn openai_embedding_response(vector: &[f32]) -> serde_json::Value {
    json!({ "data": [ { "embedding": vector } ] })
}

// ---------------------------------------------------------------------------
// 1a. Happy path: new_remote → embed() returns the mock vector; the
//     degraded flag stays false; dim() reports the constructed dim.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::float_cmp)] // exactly-representable literals round-trip losslessly
async fn happy_path_remote_embed_returns_mock_vector_1598() {
    let server = MockServer::start().await;
    // Bearer header + model id are part of the matcher: a request that
    // drops either gets a wiremock 404 and the test fails loudly.
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("authorization", "Bearer test-key-1598"))
        .and(body_partial_json(json!({ "model": "fake-embed-model" })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(openai_embedding_response(&[0.25, -0.5, 0.75, 1.0])),
        )
        .mount(&server)
        .await;

    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        let client = OllamaClient::new_openai_compatible(&uri, "fake-embed-model", "test-key-1598")
            .expect("OpenAI-compatible client construction is probe-free and must succeed");
        let embedder = Embedder::new_remote(Arc::new(client), "fake-embed-model".to_string(), 4);

        assert_eq!(embedder.dim(), 4, "dim() must report the constructed dim");
        assert_eq!(
            embedder.model_description(),
            "fake-embed-model (4-dim, remote)",
            "remote variant must report its live model + dim truthfully (#1598)",
        );

        let v = embedder
            .embed("hello over the wire")
            .expect("embed against the mock /embeddings endpoint must succeed");
        assert_eq!(
            v,
            vec![0.25, -0.5, 0.75, 1.0],
            "embed() must return the data[0].embedding vector verbatim",
        );
        assert!(
            !embedder.is_degraded(),
            "a successful embed must leave the degraded flag false (#1594)",
        );
    })
    .await
    .expect("blocking embed task must not panic");
}

// ---------------------------------------------------------------------------
// 1b. 401 auth rejection latches degraded; the next success clears it.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn auth_rejection_latches_degraded_then_success_clears_1598() {
    let server = MockServer::start().await;
    // First call: 401 (mounted FIRST so it wins dispatch, consumed once).
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({ "error": "invalid api key" })),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    // Every later call: 200 with a vector.
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(openai_embedding_response(&[0.5, 0.5])),
        )
        .mount(&server)
        .await;

    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        let client = OllamaClient::new_openai_compatible(&uri, "fake-embed-model", "bad-key")
            .expect("client construction must succeed");
        let embedder = Embedder::new_remote(Arc::new(client), "fake-embed-model".to_string(), 2);

        let err = embedder
            .embed("first call hits the 401")
            .expect_err("a 401 from the endpoint must surface as an embed error");
        assert!(
            err.to_string().contains("401"),
            "the error must carry the HTTP status: {err}",
        );
        assert!(
            embedder.is_degraded(),
            "a failed remote embed must latch is_degraded() == true (#1594)",
        );

        embedder
            .embed("second call succeeds")
            .expect("the follow-up 200 must succeed");
        assert!(
            !embedder.is_degraded(),
            "the next successful embed must clear the degraded latch (#1594)",
        );
    })
    .await
    .expect("blocking embed task must not panic");
}

// ---------------------------------------------------------------------------
// 1c-i. from_resolved: API-backend ResolvedEmbeddings → Some(remote
//       embedder) wired with the resolved Bearer key + dim.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn from_resolved_api_backend_builds_keyed_remote_embedder_1598() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("authorization", "Bearer sk-or-resolved-1598"))
        .and(body_partial_json(
            json!({ "model": "google/gemini-embedding-2" }),
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(openai_embedding_response(&[0.125; 8])),
        )
        .mount(&server)
        .await;

    let resolved = ResolvedEmbeddings::from_parts(
        "openrouter".to_string(),
        server.uri(),
        "google/gemini-embedding-2".to_string(),
        Some(8),
        Some("sk-or-resolved-1598".to_string()),
    );
    tokio::task::spawn_blocking(move || {
        let embedder = Embedder::from_resolved(&resolved, Some(EmbeddingModel::NomicEmbedV15))
            .expect("API-backend from_resolved must not error")
            .expect("API-backend from_resolved must yield Some(embedder)");
        assert_eq!(
            embedder.dim(),
            8,
            "from_resolved must carry the resolved embedding_dim into the embedder",
        );
        let v = embedder
            .embed("resolved boot-ladder embed")
            .expect("embed via the resolved remote embedder must succeed");
        assert_eq!(v.len(), 8, "vector length must match the resolved dim");
        assert!(!embedder.is_degraded());
    })
    .await
    .expect("blocking embed task must not panic");
}

// ---------------------------------------------------------------------------
// 1c-ii. from_resolved: keyless self-hosted endpoint (HF TEI / vLLM
//        posture) — no resolved key still yields a working embedder
//        (empty Bearer value the server ignores).
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn from_resolved_keyless_api_backend_embeds_1598() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(openai_embedding_response(&[1.0, 2.0, 3.0])),
        )
        .mount(&server)
        .await;

    let resolved = ResolvedEmbeddings::from_parts(
        "openai-compatible".to_string(),
        server.uri(),
        "ibm-granite/granite-embedding-125m-english".to_string(),
        Some(3),
        None, // keyless: legitimate for self-hosted TEI / vLLM (#1598)
    );
    tokio::task::spawn_blocking(move || {
        let embedder = Embedder::from_resolved(&resolved, Some(EmbeddingModel::MiniLmL6V2))
            .expect("keyless API-backend from_resolved must not error")
            .expect("keyless API-backend from_resolved must yield Some(embedder)");
        let v = embedder
            .embed("keyless endpoint embed")
            .expect("keyless embed must succeed against an auth-ignoring endpoint");
        assert_eq!(v.len(), 3);
    })
    .await
    .expect("blocking embed task must not panic");
}

// ---------------------------------------------------------------------------
// 1c-iii. from_resolved: keyword tier (tier_model None) → Ok(None).
// ---------------------------------------------------------------------------
#[test]
fn from_resolved_keyword_tier_returns_none_1598() {
    let resolved = ResolvedEmbeddings::from_parts(
        "openrouter".to_string(),
        "http://127.0.0.1:9".to_string(),
        "google/gemini-embedding-2".to_string(),
        Some(3072),
        Some("never-used".to_string()),
    );
    let built = Embedder::from_resolved(&resolved, None)
        .expect("keyword tier must be Ok, not an error (embeddings disabled by preset)");
    assert!(
        built.is_none(),
        "tier_model = None (keyword tier) must yield Ok(None) — no embedder, no client built",
    );
}

// ---------------------------------------------------------------------------
// 1c-iv. from_resolved: API backend + unknown model + no dim override →
//        loud Err naming the [embeddings].dim escape hatch (fail-closed,
//        never a silent wrong-dim embedder).
// ---------------------------------------------------------------------------
#[test]
fn from_resolved_unknown_model_without_dim_errs_naming_escape_hatch_1598() {
    let resolved = ResolvedEmbeddings::from_parts(
        "openai-compatible".to_string(),
        "http://127.0.0.1:9".to_string(),
        "model-not-in-known-dims-table-1598".to_string(),
        None, // no [embeddings].dim override, not in KNOWN_EMBEDDING_DIMS
        None,
    );
    // `expect_err` needs `T: Debug` and `Embedder` deliberately has no
    // `Debug` impl (it carries a live client), so unwrap via match.
    let Err(err) = Embedder::from_resolved(&resolved, Some(EmbeddingModel::NomicEmbedV15)) else {
        panic!("an API-backend model with no known dim must fail closed")
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("[embeddings].dim"),
        "the error must name the [embeddings].dim escape hatch: {msg}",
    );
    assert!(
        msg.contains("AI_MEMORY_EMBED_MODEL"),
        "the error must name the model-override env var: {msg}",
    );
    assert!(
        msg.contains("model-not-in-known-dims-table-1598"),
        "the error must name the offending model id: {msg}",
    );
}

// ---------------------------------------------------------------------------
// 1d-i. nomic-prefix gating over the wire: a nomic-embed family model
//       must send role-prefixed inputs (search_document: / search_query:).
//       Assertion is structural: ONLY the prefixed bodies have mocks, so
//       an unprefixed request 404s and the embed call errors.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::float_cmp)] // exactly-representable literals round-trip losslessly
async fn nomic_model_sends_role_prefixed_input_over_the_wire_1598() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(body_partial_json(
            json!({ "input": "search_document: corpus text" }),
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(openai_embedding_response(&[1.0, 0.0])),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(body_partial_json(
            json!({ "input": "search_query: corpus text" }),
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(openai_embedding_response(&[0.0, 1.0])),
        )
        .mount(&server)
        .await;

    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        // HF-id spelling: the #1598 CONTAINS-match must gate the same as
        // the Ollama tag form.
        let client =
            OllamaClient::new_openai_compatible(&uri, "nomic-ai/nomic-embed-text-v1.5", "k")
                .expect("client construction must succeed");
        let embedder = Embedder::new_remote(
            Arc::new(client),
            "nomic-ai/nomic-embed-text-v1.5".to_string(),
            2,
        );

        let doc = embedder
            .embed("corpus text")
            .expect("Document-role embed must send the search_document: prefix");
        assert_eq!(
            doc,
            vec![1.0, 0.0],
            "Document role must hit the search_document: mock"
        );

        let query = embedder
            .embed_query("corpus text")
            .expect("Query-role embed must send the search_query: prefix");
        assert_eq!(
            query,
            vec![0.0, 1.0],
            "Query role must hit the search_query: mock"
        );
    })
    .await
    .expect("blocking embed task must not panic");
}

// ---------------------------------------------------------------------------
// 1d-ii. A non-nomic (gemini-style) model id must NOT be prefixed: only
//        the verbatim-input body has a mock, so an injected prefix 404s.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn gemini_style_model_input_is_not_prefixed_1598() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(body_partial_json(json!({ "input": "plain text" })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(openai_embedding_response(&[0.5, 0.5, 0.5])),
        )
        .mount(&server)
        .await;

    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        let client = OllamaClient::new_openai_compatible(&uri, "gemini-embedding-2", "k")
            .expect("client construction must succeed");
        let embedder = Embedder::new_remote(Arc::new(client), "gemini-embedding-2".to_string(), 3);

        embedder
            .embed("plain text")
            .expect("Document-role embed of a non-nomic model must send the input verbatim");
        embedder
            .embed_query("plain text")
            .expect("Query-role embed of a non-nomic model must send the input verbatim");
    })
    .await
    .expect("blocking embed task must not panic");
}

// ---------------------------------------------------------------------------
// 5. #1598 fleet follow-up — requested output dimensionality
//    (`[embeddings].dim` → wire `dimensions` param for
//    Matryoshka-capable API models).
// ---------------------------------------------------------------------------

/// When `requested_dim` is set on the resolved view, the
/// OpenAI-compatible embed payload MUST carry `"dimensions": <dim>`
/// — the mock only answers a body containing it, so a dropped param
/// fails structurally.
#[tokio::test(flavor = "multi_thread")]
async fn requested_dim_sends_wire_dimensions_param_1598() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(body_partial_json(json!({
            "model": "google/gemini-embedding-2",
            "dimensions": 768
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(openai_embedding_response(&[0.5; 768])),
        )
        .mount(&server)
        .await;

    let resolved = ResolvedEmbeddings::from_parts(
        "openrouter".to_string(),
        server.uri(),
        "google/gemini-embedding-2".to_string(),
        Some(768),
        Some("sk-or-dims-1598".to_string()),
    )
    .with_requested_dim(Some(768));
    tokio::task::spawn_blocking(move || {
        let embedder = Embedder::from_resolved(&resolved, Some(EmbeddingModel::NomicEmbedV15))
            .expect("from_resolved with requested_dim must not error")
            .expect("from_resolved with requested_dim must yield Some(embedder)");
        let v = embedder
            .embed("matryoshka requested-dim embed")
            .expect("embed must succeed when the wire carries dimensions");
        assert_eq!(v.len(), 768, "vector must come back at the requested dim");
    })
    .await
    .expect("blocking embed task must not panic");
}

/// Without `requested_dim`, the payload MUST NOT carry a `dimensions`
/// key — a table-derived dim describes the model's native output and
/// must never be re-requested on the wire. The mock 422s any body
/// containing the key.
#[tokio::test(flavor = "multi_thread")]
async fn table_dim_does_not_send_wire_dimensions_param_1598() {
    let server = MockServer::start().await;
    // Reject any request that carries "dimensions".
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(body_partial_json(json!({ "dimensions": 8 })))
        .respond_with(ResponseTemplate::new(422))
        .mount(&server)
        .await;
    // Accept the plain shape.
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(openai_embedding_response(&[0.25; 8])),
        )
        .mount(&server)
        .await;

    let resolved = ResolvedEmbeddings::from_parts(
        "openrouter".to_string(),
        server.uri(),
        "google/gemini-embedding-2".to_string(),
        Some(8), // dim known (as if table-derived) but NOT requested
        Some("sk-or-nodims-1598".to_string()),
    );
    assert_eq!(
        resolved.requested_dim, None,
        "from_parts must not populate requested_dim implicitly",
    );
    tokio::task::spawn_blocking(move || {
        let embedder = Embedder::from_resolved(&resolved, Some(EmbeddingModel::NomicEmbedV15))
            .expect("from_resolved without requested_dim must not error")
            .expect("from_resolved without requested_dim must yield Some(embedder)");
        let v = embedder
            .embed("native-dim embed")
            .expect("embed without a dimensions param must succeed");
        assert_eq!(v.len(), 8);
    })
    .await
    .expect("blocking embed task must not panic");
}
