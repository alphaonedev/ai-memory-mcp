// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4046 — an empty or whitespace-only LLM summary is refused before it can
//! replace consolidation sources (child module of `llm`, QUAL-10 ceiling).

use super::*;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn issue_4046_whitespace_summary_is_refused() {
    for openai in [false, true] {
        let server = MockServer::start().await;
        let message = json!({"content": " \n\t"});
        let body = if openai {
            json!({"choices": [{"message": message}]})
        } else {
            json!({"message": message})
        };
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        let client = if openai {
            OllamaClient::new_openai_compatible(&server.uri(), "test", "test-key").unwrap()
        } else {
            OllamaClient::new_with_url_no_health_check(&server.uri(), "test").unwrap()
        };
        assert!(
            client
                .summarize_memories_async(&[("title".into(), "body".into())])
                .await
                .is_err()
        );
    }
}
