// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4047 — every invalid-envelope arm of the LLM client feeds the circuit
//! breaker (child module of `llm` so the parent stays under its QUAL-10 ceiling).

use super::*;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn call(client: &OllamaClient, variant: u8) -> Result<()> {
    match variant {
        0 => client.generate_async("test", None).await.map(|_| ()),
        1 => client
            .generate_with_tools_async("test", None, &[ToolDef::new("test", "test", json!({}))])
            .await
            .map(|_| ()),
        2 => client
            .generate_with_model_override_async("test", None, Some("other"))
            .await
            .map(|_| ()),
        3 => client
            .generate_with_body_async(&json!({}))
            .await
            .map(|_| ()),
        4 => client.embed_text_async("test", "test").await.map(|_| ()),
        _ => client
            .embed_texts_async(&["test"], "test")
            .await
            .map(|_| ()),
    }
}

fn client(server: &MockServer, openai: bool) -> OllamaClient {
    if openai {
        OllamaClient::new_openai_compatible(&server.uri(), "test", "test-key").unwrap()
    } else {
        OllamaClient::new_with_url_no_health_check(&server.uri(), "test").unwrap()
    }
}

async fn respond(server: &MockServer, status: u16, body: Value) {
    server.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn issue_4047_invalid_envelopes_open_breaker() {
    let mut failures = Vec::new();
    for openai in [false, true] {
        for variant in 0..6 {
            if variant == 3 && openai {
                continue;
            }
            for body in [
                json!({}),
                json!({"message": {"content": 42}, "choices": [{"message": {"content": 42}}], "response": 42, "embeddings": 42, "data": 42}),
            ] {
                let server = MockServer::start().await;
                respond(&server, 200, body).await;
                let client = client(&server, openai);
                for attempt in 0..4 {
                    let error = call(&client, variant).await.unwrap_err();
                    if attempt == 3 && !error.to_string().contains("circuit breaker open") {
                        failures.push(format!(
                            "openai={openai}, variant={variant}: fourth request returned {error}"
                        ));
                    }
                }
                let count = server.received_requests().await.unwrap().len();
                if count != 3 {
                    failures.push(format!(
                        "openai={openai}, variant={variant}: requests={count}"
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn issue_4047_success_resets_and_http_status_policy_is_preserved() {
    for openai in [false, true] {
        let server = MockServer::start().await;
        let client = client(&server, openai);
        respond(&server, 200, json!({})).await;
        for _ in 0..2 {
            assert!(client.generate_async("test", None).await.is_err());
        }
        let message = json!({"content": "valid response"});
        let body = if openai {
            json!({"choices": [{"message": message}]})
        } else {
            json!({"message": message})
        };
        respond(&server, 200, body).await;
        assert_eq!(
            client.generate_async("test", None).await.unwrap(),
            "valid response"
        );
        respond(&server, 500, json!({})).await;
        for _ in 0..3 {
            assert!(client.generate_async("test", None).await.is_err());
        }
        assert!(
            client
                .generate_async("test", None)
                .await
                .unwrap_err()
                .to_string()
                .contains("circuit breaker open")
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
        let client =
            super::OllamaClient::new_with_url_no_health_check(&server.uri(), "test").unwrap();
        respond(&server, 400, json!({})).await;
        for _ in 0..4 {
            assert!(client.generate_async("test", None).await.is_err());
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 4);
    }
}

#[tokio::test]
async fn issue_4047_tool_calls_without_text_are_successful() {
    for openai in [false, true] {
        let server = MockServer::start().await;
        let client = client(&server, openai);
        let message = json!({"tool_calls": [{"function": {"name": "test", "arguments": "{}"}}]});
        let body = if openai {
            json!({"choices": [{"message": message}]})
        } else {
            json!({"message": message})
        };
        respond(&server, 200, body).await;
        for _ in 0..4 {
            assert!(matches!(
                client
                    .generate_with_tools_async(
                        "test",
                        None,
                        &[ToolDef::new("test", "test", json!({}))]
                    )
                    .await
                    .unwrap(),
                ChatOutcome::ToolCalls(_)
            ));
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 4);
    }
}
