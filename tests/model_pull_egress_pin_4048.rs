// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Model pulls must retain the inference client's admitted address and redirect policy.

use ai_memory::{
    egress::{EgressClass, InferenceEgressMode, admit_inference_target},
    llm::OllamaClient,
};
use serde_json::json;
use std::net::{SocketAddr, TcpListener};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn admitted_client(url: &str, addr: SocketAddr, embed: bool) -> OllamaClient {
    let class = if embed {
        EgressClass::InferenceEmbedding
    } else {
        EgressClass::InferenceLlm
    };
    let mut pin = admit_inference_target(InferenceEgressMode::InternalOnly, class, url)
        .expect("loopback admission")
        .expect("internal-only pin");
    assert!(
        pin.addrs.contains(&addr),
        "fixture address must be admitted"
    );
    // Model the address set seen at boot, before DNS starts returning the
    // other loopback address. Both listeners remain live for the entire probe.
    pin.addrs = vec![addr];
    OllamaClient::new_with_url_no_health_check_pinned(&pin, "missing").expect("pinned client")
}

async fn pull(client: &OllamaClient, embed: bool) -> anyhow::Result<()> {
    if embed {
        client.ensure_embed_model_async("missing").await
    } else {
        client.ensure_model_async().await
    }
}

async fn mount_tags(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(server)
        .await;
}

async fn pin_probe(embed: bool) {
    let mut escaped = 0;
    for pinned_v6 in [true, false] {
        let listener = TcpListener::bind(if pinned_v6 { "[::1]:0" } else { "127.0.0.1:0" })
            .expect("admitted listener");
        let addr = listener.local_addr().unwrap();
        let other_listener =
            TcpListener::bind((if pinned_v6 { "127.0.0.1" } else { "::1" }, addr.port()))
                .expect("unadmitted listener on same port");
        let admitted = MockServer::builder().listener(listener).start().await;
        let other = MockServer::builder().listener(other_listener).start().await;
        mount_tags(&admitted).await;
        for server in [&admitted, &other] {
            Mock::given(method("POST"))
                .and(path("/api/pull"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({"status": "success"})),
                )
                .mount(server)
                .await;
        }
        let client = admitted_client(&format!("http://localhost:{}", addr.port()), addr, embed);
        assert!(client.is_available_async().await, "admitted health control");
        let result = pull(&client, embed).await;
        let good = admitted.received_requests().await.unwrap();
        let bad = other.received_requests().await.unwrap();
        let tags = good.iter().filter(|r| r.url.path() == "/api/tags").count();
        let pulls = good.iter().filter(|r| r.url.path() == "/api/pull").count();
        println!(
            "PIN embed={embed} pinned_v6={pinned_v6} result_ok={} admitted_tags={tags} admitted_pull={pulls} unpinned_pull={}",
            result.is_ok(),
            bad.len()
        );
        assert!(result.is_ok(), "model pull must succeed: {result:?}");
        assert_eq!(tags, 2, "both health and listing use the admitted server");
        assert_eq!(pulls + bad.len(), 1, "exactly one model pull");
        escaped += bad.len();
    }
    assert_eq!(escaped, 0, "model pull escaped the admitted address pin");
}

async fn redirect_probe(embed: bool) {
    let admitted = MockServer::start().await;
    let other = MockServer::start().await;
    mount_tags(&admitted).await;
    Mock::given(method("POST"))
        .and(path("/api/pull"))
        .respond_with(ResponseTemplate::new(307).insert_header("Location", other.uri()))
        .mount(&admitted)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&other)
        .await;
    let client = admitted_client(&admitted.uri(), *admitted.address(), embed);
    let result = pull(&client, embed).await;
    let redirected = other.received_requests().await.unwrap().len();
    println!(
        "REDIRECT embed={embed} result_ok={} redirected={redirected}",
        result.is_ok()
    );
    assert_eq!(redirected, 0, "model pull followed an unadmitted redirect");
    assert!(result.is_err(), "redirect must fail closed");
}

#[tokio::test]
async fn llm_pull_keeps_admitted_address_4048() {
    pin_probe(false).await;
}

#[tokio::test]
async fn embedding_pull_keeps_admitted_address_4048() {
    pin_probe(true).await;
}

#[tokio::test]
async fn llm_pull_refuses_redirect_4048() {
    redirect_probe(false).await;
}

#[tokio::test]
async fn embedding_pull_refuses_redirect_4048() {
    redirect_probe(true).await;
}
