// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3742 (WP-EGRESS #6053) — LLM / embedding request URLs are joined onto
//! the configured base URL's PATH, never appended after its query string.
//!
//! Every OpenAI-compatible and Ollama request URL used to be built as
//! `format!("{base_url}/<path>")`. A base URL that carries a query string —
//! Azure OpenAI's `?api-version=2024-02-01` is the common real case — had
//! the path appended AFTER the query: `…/v1?api-version=2024-02-01/models`.
//! The request went to the wrong resource and the query value was corrupted.
//!
//! These cells drive the PUBLIC client against a mock that only answers the
//! CORRECT join (`/v1/models?api-version=…`, `/v1/embeddings?api-version=…`,
//! `/ollama/api/tags?x=1`): on the pre-fix tree the request hits an
//! unmatched route (404) and the probe reports not-available / the embed
//! fails, so each cell is RED on the base and GREEN on the tip. A no-query
//! control proves the join is unchanged for the common shape.

use ai_memory::llm::OllamaClient;
use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const API_VERSION: &str = "2024-02-01";

async fn azure_shaped_server() -> MockServer {
    let server = MockServer::start().await;
    // Only the CORRECT join answers; everything else is wiremock's 404.
    Mock::given(method("GET"))
        .and(path("/openai/deployments/x/models"))
        .and(query_param("api-version", API_VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/openai/deployments/x/embeddings"))
        .and(query_param("api-version", API_VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"index": 0, "embedding": [0.1, 0.2, 0.3]}]
        })))
        .mount(&server)
        .await;
    server
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_compatible_probe_keeps_base_query_before_the_path_3742() {
    let server = azure_shaped_server().await;
    let base = format!(
        "{}/openai/deployments/x?api-version={API_VERSION}",
        server.uri()
    );
    let client = OllamaClient::new_openai_compatible(&base, "m", "k").expect("client");
    assert!(
        client.is_available_async().await,
        "#3742: the health probe must GET <base path>/models?api-version=…, not \
         <base>?api-version=…/models; received: {:?}",
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_compatible_embed_keeps_base_query_before_the_path_3742() {
    let server = azure_shaped_server().await;
    let base = format!(
        "{}/openai/deployments/x?api-version={API_VERSION}",
        server.uri()
    );
    let client = OllamaClient::new_openai_compatible(&base, "m", "k").expect("client");
    let vec = client
        .embed_text_async("hello", "m")
        .await
        .expect("#3742: the embed POST must reach <base path>/embeddings?api-version=…");
    assert_eq!(vec.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ollama_probe_keeps_base_query_before_the_path_3742() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ollama/api/tags"))
        .and(query_param("x", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    let base = format!("{}/ollama?x=1", server.uri());
    let client = OllamaClient::new_with_url_no_health_check(&base, "m").expect("client");
    assert!(
        client.is_available_async().await,
        "#3742: the Ollama tags probe must GET <base path>/api/tags?x=1"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_query_control_join_is_unchanged_3742() {
    // Control: the common no-query shape (with and without a trailing slash)
    // still probes `<base>/models` — the join is byte-identical there.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;
    for base in [
        format!("{}/v1", server.uri()),
        format!("{}/v1/", server.uri()),
    ] {
        let client = OllamaClient::new_openai_compatible(&base, "m", "k").expect("client");
        assert!(
            client.is_available_async().await,
            "control: {base} must probe /v1/models"
        );
    }
}
