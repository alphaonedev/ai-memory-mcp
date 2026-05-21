// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// v0.7.0 Posture-1a (issue #1068 Layer 3) — LLM client TLS handshake
// through the mobile rustls stack.
//
// reqwest's `rustls-tls` feature pulls in `rustls` + `webpki-roots`
// + `ring` (or `aws-lc-rs` post a v0.7.x bump). The mobile risk is:
//
//   1. `ring`'s assembly fallbacks on ARM64 — known to silently
//      go scalar on iOS in some XCode versions, which still passes
//      tests but at 100x latency.
//   2. iOS App Transport Security (ATS) rejecting non-pinned TLS
//      connections. Defaults block plaintext HTTP; an app embedding
//      ai-memory must declare ATS exceptions or use HTTPS only.
//   3. Android Network Security Configuration blocking cleartext to
//      arbitrary domains on API 28+.
//
// These tests use a `wiremock`-stubbed local HTTP server (NOT HTTPS,
// since rustls cert provisioning on a CI emulator is its own can of
// worms). The ATS-bypass is the consuming app's responsibility; the
// test here proves the reqwest stack itself initialises + completes
// a request on mobile rust.

use std::time::Duration;

#[tokio::test(flavor = "current_thread")]
async fn reqwest_basic_get_on_mobile_runtime() {
    // Skip when wiremock isn't available (debug-builds-only feature).
    // The smoke is "does the reqwest client even compile + run on
    // mobile?" — a real LLM hit goes through a wiremock stub set up
    // by the harness in non-#[cfg(test)] paths.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client builds on mobile");

    // Hit a known-stable localhost URL via wiremock to round-trip
    // through the actual reqwest + rustls dispatch. If wiremock
    // isn't present (light variant of this test), fall back to a
    // simple builder validation.
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/health"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let url = format!("{}/health", server.uri());
    let resp = client
        .get(&url)
        .send()
        .await
        .expect("GET /health round-trips on mobile reqwest stack");
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().await.expect("body text");
    assert_eq!(body, "ok");
}

#[tokio::test(flavor = "current_thread")]
async fn reqwest_openai_compatible_chat_stub_round_trip() {
    // Exercises the same wire shape ai-memory's llm.rs uses for the
    // OpenAI-compatible provider path (xAI, OpenAI, Anthropic-via-
    // shim, etc.). The stub replies "ok"; the test asserts the
    // response parses cleanly.
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/chat/completions"))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{
                    "message": { "content": "ok", "role": "assistant" },
                    "index": 0,
                    "finish_reason": "stop"
                }],
                "model": "stub",
                "object": "chat.completion"
            })),
        )
        .mount(&server)
        .await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("{}/v1/chat/completions", server.uri());
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "model": "stub",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .expect("OpenAI-compat POST round-trip");
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["choices"][0]["message"]["content"], "ok");
}

// TODO #1068 Layer 3 follow-up:
//   - HTTPS handshake to a real wiremock-with-rustls listener
//     (validates rustls cert chain processing on mobile)
//   - HTTP/2 ALPN negotiation on iOS (App Transport Security
//     enforces HTTP/2-or-better on iOS 13+)
//   - Connection pool eviction under iOS background suspension
//   - DNS resolution timeout under Android's NetworkSecurityConfig
//     blocking
