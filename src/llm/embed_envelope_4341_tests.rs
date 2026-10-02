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
//!
//! The counting cells pin that every bad-envelope arm of the embed path
//! calls `note_failure()` EXACTLY once: a double count would open the
//! breaker after two bad envelopes instead of `CIRCUIT_BREAKER_THRESHOLD`.

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
    OllamaClient::new_with_url_no_health_check(&server.uri(), "test-model").unwrap()
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

/// The breaker's consecutive-failure count, read through the parent's
/// private state (child module).
fn fails(client: &OllamaClient) -> u32 {
    client
        .breaker
        .lock()
        .map(|b| b.consecutive_failures)
        .unwrap_or(u32::MAX)
}

/// Which request a bad envelope is driven through.
#[derive(Clone, Copy, Debug)]
enum Arm {
    OllamaSingle,
    OpenAiSingle,
    OpenAiBatch,
}

/// Every bad-envelope arm of the embed path, one body each.
fn bad_envelope_arms() -> Vec<(&'static str, Arm, Value)> {
    let not_json = Value::String("not-json".to_owned());
    vec![
        ("ollama missing embeddings[0]", Arm::OllamaSingle, json!({})),
        (
            "ollama empty vector",
            Arm::OllamaSingle,
            ollama_body(&json!([])),
        ),
        (
            "ollama non-numeric",
            Arm::OllamaSingle,
            ollama_body(&mixed_vector()),
        ),
        (
            "ollama non-finite",
            Arm::OllamaSingle,
            ollama_body(&out_of_range_vector()),
        ),
        ("ollama invalid json", Arm::OllamaSingle, not_json.clone()),
        (
            "openai missing data[0].embedding",
            Arm::OpenAiSingle,
            json!({}),
        ),
        (
            "openai empty vector",
            Arm::OpenAiSingle,
            openai_body(&json!([])),
        ),
        (
            "openai non-numeric",
            Arm::OpenAiSingle,
            openai_body(&mixed_vector()),
        ),
        (
            "openai non-finite",
            Arm::OpenAiSingle,
            openai_body(&out_of_range_vector()),
        ),
        ("openai invalid json", Arm::OpenAiSingle, not_json.clone()),
        ("batch missing data", Arm::OpenAiBatch, json!({})),
        (
            "batch empty vector",
            Arm::OpenAiBatch,
            openai_body(&json!([])),
        ),
        (
            "batch non-numeric",
            Arm::OpenAiBatch,
            openai_body(&null_vector()),
        ),
        (
            "batch non-finite",
            Arm::OpenAiBatch,
            openai_body(&out_of_range_vector()),
        ),
        ("batch invalid json", Arm::OpenAiBatch, not_json),
    ]
}

/// Serve `body` for `arm`; a JSON string value is served as a RAW
/// (non-JSON) body so the invalid-JSON arm is reachable.
async fn serve_arm(arm: Arm, body: &Value) -> (MockServer, OllamaClient) {
    let route = match arm {
        Arm::OllamaSingle => OLLAMA_EMBED_PATH,
        Arm::OpenAiSingle | Arm::OpenAiBatch => super::OPENAI_COMPAT_EMBEDDINGS_PATH,
    };
    let server = MockServer::start().await;
    let template = match body {
        Value::String(raw) => ResponseTemplate::new(200).set_body_string(raw.clone()),
        other => ResponseTemplate::new(200).set_body_json(other),
    };
    Mock::given(method("POST"))
        .and(path(route))
        .respond_with(template)
        .mount(&server)
        .await;
    let client = match arm {
        Arm::OllamaSingle => ollama_client(&server),
        Arm::OpenAiSingle | Arm::OpenAiBatch => openai_client(&server),
    };
    (server, client)
}

async fn drive(client: &OllamaClient, arm: Arm) -> anyhow::Result<()> {
    match arm {
        Arm::OllamaSingle | Arm::OpenAiSingle => {
            client.embed_text_async("hello", "m").await.map(|_| ())
        }
        Arm::OpenAiBatch => client
            .embed_texts_one_request(&["hello"], "m")
            .await
            .map(|_| ()),
    }
}

/// #4341 — each bad-envelope arm, driven once, counts exactly ONE failure.
#[tokio::test(flavor = "multi_thread")]
async fn envelope_arms_count_exactly_once_4341() {
    let mut wrong = Vec::new();
    for (label, arm, body) in bad_envelope_arms() {
        let (_server, client) = serve_arm(arm, &body).await;
        let result = drive(&client, arm).await;
        let count = fails(&client);
        if result.is_ok() || count != 1 {
            wrong.push(format!("{label}: ok={} fails={count}", result.is_ok()));
        }
    }
    assert!(
        wrong.is_empty(),
        "arms not counted exactly once: {wrong:#?}"
    );
}

/// #4341 — the breaker opens on the THIRD bad envelope, not the second,
/// on every arm; the fourth call fast-fails without reaching the wire.
#[tokio::test(flavor = "multi_thread")]
async fn envelope_breaker_opens_on_third_not_second_4341() {
    assert_eq!(
        CIRCUIT_BREAKER_THRESHOLD, 3,
        "cell is written for threshold 3"
    );
    let mut wrong = Vec::new();
    for (label, arm, body) in bad_envelope_arms() {
        let (server, client) = serve_arm(arm, &body).await;
        for _ in 0..2 {
            let _ = drive(&client, arm).await;
        }
        if client.circuit_breaker_open() {
            wrong.push(format!("{label}: open after 2 (fails={})", fails(&client)));
            continue;
        }
        let _ = drive(&client, arm).await;
        if !client.circuit_breaker_open() {
            wrong.push(format!(
                "{label}: closed after 3 (fails={})",
                fails(&client)
            ));
            continue;
        }
        let fourth = drive(&client, arm).await;
        let fast_failed = fourth
            .as_ref()
            .err()
            .is_some_and(|e| e.to_string().contains("circuit breaker open"));
        let requests = server.received_requests().await.map_or(0, |r| r.len());
        if !fast_failed || requests != 3 {
            wrong.push(format!(
                "{label}: fourth fast_failed={fast_failed} requests={requests}"
            ));
        }
    }
    assert!(wrong.is_empty(), "breaker threshold drift: {wrong:#?}");
}

/// #4341 — the batched path's per-text fallback counts one failure per
/// REQUEST (batch arm + per-text arm), and the batch error keeps the
/// parser's specific cause under `invalid_response` (ERRORS-15).
#[tokio::test(flavor = "multi_thread")]
async fn batch_fallback_counts_per_request_and_keeps_cause_4341() {
    let (_server, client) = serve_arm(Arm::OpenAiBatch, &openai_body(&mixed_vector())).await;
    let batch_err = drive(&client, Arm::OpenAiBatch)
        .await
        .expect_err("malformed batch must error");
    let rendered = format!("{batch_err:#}");
    assert!(
        rendered.contains("invalid_response") && rendered.contains("Non-numeric or non-finite"),
        "batch error must keep classification AND parser cause: {rendered}"
    );
    assert_eq!(fails(&client), 1);

    let (_server, client) = serve_arm(Arm::OpenAiBatch, &openai_body(&mixed_vector())).await;
    client
        .embed_texts_async(&["hello"], "m")
        .await
        .expect_err("malformed batch and per-text fallback must error");
    assert_eq!(
        fails(&client),
        2,
        "one failure for the batch, one for the per-text retry"
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
