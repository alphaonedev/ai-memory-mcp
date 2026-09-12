// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! Provider bodies must not escape through error formatting or logs (#3648).
use ai_memory::llm::{OllamaClient, ToolDef};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Clone, Copy)]
enum Operation {
    Chat,
    Tools,
    Override,
    Embed,
    Batch,
}

const HTTP_ERRORS: [(u16, bool); 2] = [(401, false), (500, false)];
const MALFORMED_RESPONSES: [(u16, bool); 2] = [(200, false), (200, true)];

async fn assert_redacted(operation: Operation, cases: &[(u16, bool)]) {
    const SECRET: &str = "provider-echo-credential-3648";
    for ollama in [false, true] {
        for &(status, malformed_json) in cases {
            let server = MockServer::start().await;
            let embedding = matches!(operation, Operation::Embed | Operation::Batch);
            let endpoint = match (ollama, embedding) {
                (true, true) => "/api/embed",
                (true, false) => "/api/chat",
                (false, true) => "/embeddings",
                (false, false) => "/chat/completions",
            };
            let body = if malformed_json {
                format!("{{{SECRET}")
            } else {
                json!({"error": SECRET}).to_string()
            };
            Mock::given(method("POST"))
                .and(path(endpoint))
                .respond_with(ResponseTemplate::new(status).set_body_string(body))
                .mount(&server)
                .await;
            let client = if ollama {
                OllamaClient::new_with_url_no_health_check(&server.uri(), "test").unwrap()
            } else {
                OllamaClient::new_openai_compatible(&server.uri(), "test", "test-key").unwrap()
            };
            let error = match operation {
                Operation::Chat => client.generate_async("input", None).await.unwrap_err(),
                Operation::Tools => client
                    .generate_with_tools_async(
                        "input",
                        None,
                        &[ToolDef::new("test", "test", json!({"type": "object"}))],
                    )
                    .await
                    .unwrap_err(),
                Operation::Override => client
                    .generate_with_model_override_async("input", None, Some("override"))
                    .await
                    .unwrap_err(),
                Operation::Embed => client.embed_text_async("input", "test").await.unwrap_err(),
                Operation::Batch => client
                    .embed_texts_async(&["one", "two"], "test")
                    .await
                    .unwrap_err(),
            };
            for rendered in [
                format!("{error}"),
                format!("{error:#}"),
                format!("{error:?}"),
            ] {
                assert!(
                    !rendered.contains(SECRET),
                    "provider echo leaked: {rendered}"
                );
                assert!(rendered.len() < 512, "error must be bounded: {rendered}");
            }
            let diagnostic = format!("{error:#}");
            if status == 401 {
                assert!(
                    diagnostic.contains("http_status=401"),
                    "must preserve a safe status code: {diagnostic}"
                );
            }
            if status == 200 {
                assert!(
                    diagnostic.contains("invalid_response"),
                    "must classify malformed responses: {diagnostic}"
                );
            }
            assert!(!server.received_requests().await.unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn chat_echo_redaction_3648() {
    assert_redacted(Operation::Chat, &HTTP_ERRORS).await;
}
#[tokio::test]
async fn tools_echo_redaction_3648() {
    assert_redacted(Operation::Tools, &HTTP_ERRORS).await;
}
#[tokio::test]
async fn override_echo_redaction_3648() {
    assert_redacted(Operation::Override, &HTTP_ERRORS).await;
}
#[tokio::test]
async fn embed_echo_redaction_3648() {
    assert_redacted(Operation::Embed, &HTTP_ERRORS).await;
}
#[tokio::test]
async fn batch_echo_redaction_3648() {
    assert_redacted(Operation::Batch, &HTTP_ERRORS).await;
}

#[tokio::test]
async fn chat_malformed_echo_redaction_3648() {
    assert_redacted(Operation::Chat, &MALFORMED_RESPONSES).await;
}

#[tokio::test]
async fn tools_malformed_echo_redaction_3648() {
    assert_redacted(Operation::Tools, &MALFORMED_RESPONSES).await;
}

#[tokio::test]
async fn override_malformed_echo_redaction_3648() {
    assert_redacted(Operation::Override, &MALFORMED_RESPONSES).await;
}

#[tokio::test]
async fn embed_malformed_echo_redaction_3648() {
    assert_redacted(Operation::Embed, &MALFORMED_RESPONSES).await;
}

#[tokio::test]
async fn batch_malformed_echo_redaction_3648() {
    assert_redacted(Operation::Batch, &MALFORMED_RESPONSES).await;
}
