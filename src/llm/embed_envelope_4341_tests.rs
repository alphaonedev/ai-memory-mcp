// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4341 — a malformed embedding envelope must FAIL, never succeed.
//!
//! Both embed parsers used to build the vector with
//! `filter_map(|v| v.as_f64().map(|f| f as f32))`, which silently DROPPED a
//! non-numeric element (returning a vector shorter than the model's
//! dimension) and saturated an out-of-f32-range number to +/-inf, then
//! called `note_success()`. Each cell here drives the real client against a
//! wiremock endpoint and asserts on the behaviour: the call errors as an
//! `invalid_response` and the failure counts toward the circuit breaker.
//! Control cells pin that a valid vector still succeeds.

use super::{CIRCUIT_BREAKER_THRESHOLD, OllamaClient, parse_openai_embeddings_batch};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OLLAMA_EMBED_PATH: &str = "/api/embed";

/// A finite JSON number whose `as f32` cast saturates to +inf.
const OUT_OF_F32_RANGE: f64 = 1e300;

fn mixed_vector() -> Value {
    json!([0.1, "not-a-number", 0.3])
}

fn null_vector() -> Value {
    json!([0.1, null, 0.3])
}

fn out_of_range_vector() -> Value {
    json!([0.1, OUT_OF_F32_RANGE, 0.3])
}

fn ollama_body(vector: &Value) -> Value {
    json!({ "embeddings": [vector] })
}

fn openai_body(vector: &Value) -> Value {
    json!({ "data": [{ "index": 0, "embedding": vector }] })
}

async fn serve(route: &str, body: Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    server
}

fn ollama_client(server: &MockServer) -> OllamaClient {
    OllamaClient::new_for_tests_without_probe(&server.uri(), "test-model").unwrap()
}

fn openai_client(server: &MockServer) -> OllamaClient {
    OllamaClient::new_openai_compatible(&server.uri(), "test-model", "fake-key").unwrap()
}

/// Every call must error as `invalid_response`, and `THRESHOLD` of them
/// must open the breaker (a success would have reset the counter).
async fn assert_single_rejected_and_counted(client: &OllamaClient, label: &str) {
    for i in 0..CIRCUIT_BREAKER_THRESHOLD {
        let err = client
            .embed_text_async("hello", "m")
            .await
            .expect_err(&format!(
                "{label}: malformed envelope must error (call {i})"
            ));
        assert!(
            format!("{err:#}").contains("invalid_response"),
            "{label}: expected invalid_response, got: {err:#}"
        );
    }
    assert!(
        client.circuit_breaker_open(),
        "{label}: malformed envelopes must count toward the breaker"
    );
}

async fn assert_batch_rejected_and_counted(client: &OllamaClient, label: &str) {
    for i in 0..CIRCUIT_BREAKER_THRESHOLD {
        let err = client
            .embed_texts_one_request(&["hello"], "m")
            .await
            .expect_err(&format!("{label}: malformed batch must error (call {i})"));
        assert!(
            format!("{err:#}").contains("invalid_response"),
            "{label}: expected invalid_response, got: {err:#}"
        );
    }
    assert!(
        client.circuit_breaker_open(),
        "{label}: malformed batch envelopes must count toward the breaker"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ollama_single_non_numeric_element_is_rejected_4341() {
    for (label, vector) in [("mixed", mixed_vector()), ("null", null_vector())] {
        let server = serve(OLLAMA_EMBED_PATH, ollama_body(&vector)).await;
        assert_single_rejected_and_counted(&ollama_client(&server), label).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ollama_single_out_of_range_element_is_rejected_4341() {
    let server = serve(OLLAMA_EMBED_PATH, ollama_body(&out_of_range_vector())).await;
    assert_single_rejected_and_counted(&ollama_client(&server), "ollama out-of-range").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn openai_single_non_numeric_element_is_rejected_4341() {
    for (label, vector) in [("mixed", mixed_vector()), ("null", null_vector())] {
        let server = serve(super::OPENAI_COMPAT_EMBEDDINGS_PATH, openai_body(&vector)).await;
        assert_single_rejected_and_counted(&openai_client(&server), label).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn openai_single_out_of_range_element_is_rejected_4341() {
    let server = serve(
        super::OPENAI_COMPAT_EMBEDDINGS_PATH,
        openai_body(&out_of_range_vector()),
    )
    .await;
    assert_single_rejected_and_counted(&openai_client(&server), "openai out-of-range").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn openai_batch_non_numeric_and_out_of_range_are_rejected_4341() {
    for (label, vector) in [
        ("batch mixed", mixed_vector()),
        ("batch null", null_vector()),
        ("batch out-of-range", out_of_range_vector()),
    ] {
        let server = serve(super::OPENAI_COMPAT_EMBEDDINGS_PATH, openai_body(&vector)).await;
        assert_batch_rejected_and_counted(&openai_client(&server), label).await;
    }
}

#[test]
fn batch_parser_rejects_malformed_elements_4341() {
    for vector in [mixed_vector(), null_vector(), out_of_range_vector()] {
        assert!(
            parse_openai_embeddings_batch(&openai_body(&vector), 1).is_err(),
            "batch parser must refuse {vector}"
        );
    }
    let ok = parse_openai_embeddings_batch(&openai_body(&json!([0.1, -2.5, 3])), 1)
        .expect("valid vector parses");
    assert_eq!(ok, vec![vec![0.1_f32, -2.5, 3.0]]);
}

#[tokio::test(flavor = "multi_thread")]
async fn valid_vectors_still_succeed_on_every_arm_4341() {
    let valid = json!([0.25, -0.5, 1]);
    let expected = vec![0.25_f32, -0.5, 1.0];

    let server = serve(OLLAMA_EMBED_PATH, ollama_body(&valid)).await;
    let client = ollama_client(&server);
    assert_eq!(client.embed_text_async("hi", "m").await.unwrap(), expected);
    assert!(!client.circuit_breaker_open());

    let server = serve(super::OPENAI_COMPAT_EMBEDDINGS_PATH, openai_body(&valid)).await;
    let client = openai_client(&server);
    assert_eq!(client.embed_text_async("hi", "m").await.unwrap(), expected);
    assert_eq!(
        client.embed_texts_one_request(&["hi"], "m").await.unwrap(),
        vec![expected]
    );
    assert!(!client.circuit_breaker_open());
}
