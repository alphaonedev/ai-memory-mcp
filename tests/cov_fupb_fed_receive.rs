// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! FUPB coverage — `src/federation/receive.rs` catchup-GET error arms.
//!
//! `tests/federation_catchup_api_key.rs` exercises the 200-OK + api-key
//! header arms of the catchup loop. This file drives the COMPLEMENTARY
//! failure arms via the public `catchup_once_for_tests` probe:
//!   - non-2xx peer response → `log_catchup_http_skip` (the
//!     `Ok(r) if !success` branch).
//!   - unreachable peer (dead address) → `log_catchup_unreachable`
//!     (the `Err(e)` branch).
//!   - 200 with a non-JSON body → `log_catchup_unparseable_body`.
//!   - 200 with a JSON body that has no `memories` array → the
//!     `None => continue` arm.
//!   - 200 with a non-empty `memories` array → `log_catchup_pull_ok`
//!     with a positive row count.
//!
//! These run the request through `sync_since_url` (no `since` cursor →
//! the `None` arm) so the URL builder is exercised on every case.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ai_memory::federation::{FederationConfig, PeerEndpoint, catchup_once_for_tests};
use ai_memory::replication::QuorumPolicy;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use tokio::net::TcpListener;

#[derive(Clone)]
enum PeerBehaviour {
    /// Respond 503 — drives the non-2xx HTTP-skip arm.
    ServerError,
    /// 200 but a non-JSON body — drives the unparseable-body arm.
    NonJsonBody,
    /// 200 with a JSON object missing the `memories` key.
    NoMemoriesKey,
    /// 200 with a non-empty `memories` array (pull-ok positive count).
    WithMemories,
}

#[derive(Clone)]
struct MockState {
    hits: Arc<AtomicUsize>,
    behaviour: PeerBehaviour,
}

async fn since_handler(State(state): State<MockState>) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    state.hits.fetch_add(1, Ordering::Relaxed);
    match state.behaviour {
        PeerBehaviour::ServerError => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"error": "down"})),
        )
            .into_response(),
        PeerBehaviour::NonJsonBody => (StatusCode::OK, "this is not json at all").into_response(),
        PeerBehaviour::NoMemoriesKey => (
            StatusCode::OK,
            axum::Json(serde_json::json!({"not_memories": true})),
        )
            .into_response(),
        PeerBehaviour::WithMemories => {
            let mem = serde_json::json!({
                "id": "11111111-1111-4111-8111-111111111111",
                "tier": "long",
                "namespace": "fed-cov",
                "title": "catchup row",
                "content": "from peer",
                "tags": [],
                "priority": 5,
                "confidence": 1.0,
                "source": "federation",
                "metadata": {},
                "access_count": 0,
                "created_at": "2026-06-01T00:00:00Z",
                "updated_at": "2026-06-01T00:00:00Z",
            });
            (
                StatusCode::OK,
                axum::Json(serde_json::json!({"memories": [mem]})),
            )
                .into_response()
        }
    }
}

async fn spawn_peer(behaviour: PeerBehaviour) -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let state = MockState {
        hits: hits.clone(),
        behaviour,
    };
    let app = Router::new()
        .route("/api/v1/sync/since", get(since_handler))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), hits)
}

fn build_cfg(peer_url: &str) -> FederationConfig {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("build reqwest client");
    FederationConfig {
        policy: QuorumPolicy::new(2, 1, Duration::from_secs(2), Duration::from_secs(30)).unwrap(),
        peers: vec![PeerEndpoint {
            id: "peer-cov".to_string(),
            sync_push_url: format!("{peer_url}/api/v1/sync/push"),
        }],
        client,
        sender_agent_id: "ai:fed-receive-cov".to_string(),
        api_key: None,
        signing_key: None,
        #[cfg(feature = "sal")]
        dlq_sink: None,
    }
}

#[tokio::test]
async fn catchup_non_2xx_response_skips_tick() {
    let (peer_url, hits) = spawn_peer(PeerBehaviour::ServerError).await;
    let cfg = build_cfg(&peer_url);
    // No panic; the handler hits the `Ok(r) if !success` HTTP-skip arm.
    catchup_once_for_tests(&cfg).await;
    assert_eq!(hits.load(Ordering::Relaxed), 1, "peer must be hit once");
}

#[tokio::test]
async fn catchup_unreachable_peer_is_swallowed() {
    // Reserve a port then drop the listener so the connect fails fast —
    // drives the `Err(e)` unreachable arm without a long timeout wait.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let cfg = build_cfg(&format!("http://{addr}"));
    // Must return without panicking; the unreachable arm logs + continues.
    catchup_once_for_tests(&cfg).await;
}

#[tokio::test]
async fn catchup_non_json_body_is_swallowed() {
    let (peer_url, hits) = spawn_peer(PeerBehaviour::NonJsonBody).await;
    let cfg = build_cfg(&peer_url);
    catchup_once_for_tests(&cfg).await;
    assert_eq!(hits.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn catchup_body_without_memories_key_continues() {
    let (peer_url, hits) = spawn_peer(PeerBehaviour::NoMemoriesKey).await;
    let cfg = build_cfg(&peer_url);
    catchup_once_for_tests(&cfg).await;
    assert_eq!(hits.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn catchup_with_memories_logs_pull_ok() {
    let (peer_url, hits) = spawn_peer(PeerBehaviour::WithMemories).await;
    let cfg = build_cfg(&peer_url);
    catchup_once_for_tests(&cfg).await;
    assert_eq!(hits.load(Ordering::Relaxed), 1);
}

/// Two configured peers: a healthy one + a dead one. The catchup loop
/// must visit BOTH (the per-peer `continue` does not abort the loop) —
/// exercises the multi-peer iteration in `catchup_once_for_tests`.
#[tokio::test]
async fn catchup_visits_every_peer_despite_one_failing() {
    let (good_url, good_hits) = spawn_peer(PeerBehaviour::WithMemories).await;
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let cfg = FederationConfig {
        policy: QuorumPolicy::new(2, 1, Duration::from_secs(2), Duration::from_secs(30)).unwrap(),
        peers: vec![
            PeerEndpoint {
                id: "peer-dead".to_string(),
                sync_push_url: format!("http://{dead_addr}/api/v1/sync/push"),
            },
            PeerEndpoint {
                id: "peer-good".to_string(),
                sync_push_url: format!("{good_url}/api/v1/sync/push"),
            },
        ],
        client,
        sender_agent_id: "ai:fed-receive-cov".to_string(),
        api_key: None,
        signing_key: None,
        #[cfg(feature = "sal")]
        dlq_sink: None,
    };
    catchup_once_for_tests(&cfg).await;
    assert_eq!(
        good_hits.load(Ordering::Relaxed),
        1,
        "the healthy peer must still be visited after the dead peer's connect error"
    );
}
