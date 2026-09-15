// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3705 — a RECORDING TLS receiver for the dispatch suites.
//!
//! "Only encrypted data in transit" refuses every `http://` webhook target,
//! loopback included, so the `wiremock::MockServer` fixtures the dispatch
//! suites inherited from the base can no longer be a target: the dispatcher
//! refuses them before a byte is sent. This is the drop-in replacement in
//! the shape those suites already use — `uri()`, `received_requests()`,
//! a `Recorded` request carrying `url` / `headers` / `body` — served over
//! TLS with the per-binary [`super::tls::TestTls`] leaf, which the test
//! installs as the dispatcher's operator root
//! (`ai_memory::subscriptions::install_dispatch_root_certificate`). No
//! verification bypass anywhere: the dispatcher verifies the receiver the
//! way it would verify an operator's `[subscriptions] ca_cert`.
//!
//! Loopback is still the SSRF guard's call
//! (`ai_memory::config::set_allow_loopback_webhooks(true)`): that opt-in is
//! an SSRF control, not a plaintext permit.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use tokio::sync::Mutex;

use super::tls::TestTls;

/// One request the receiver saw — the fields the suites read off a
/// `wiremock::Request`.
#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: Method,
    /// Absolute URL of the request as received (`https://127.0.0.1:<port>/…`).
    pub url: reqwest::Url,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// How the receiver answers: `status`, an optional JSON body, an optional
/// delay before answering (the `ResponseTemplate` knobs the suites use).
#[derive(Clone, Debug)]
pub struct Respond {
    pub status: u16,
    pub body_json: Option<serde_json::Value>,
    pub delay: Option<Duration>,
}

impl Respond {
    #[must_use]
    pub fn ok() -> Self {
        Self {
            status: 200,
            body_json: None,
            delay: None,
        }
    }

    #[must_use]
    pub fn status(status: u16) -> Self {
        Self {
            status,
            body_json: None,
            delay: None,
        }
    }

    #[must_use]
    pub fn json(mut self, body: serde_json::Value) -> Self {
        self.body_json = Some(body);
        self
    }

    #[must_use]
    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}

/// The receiver: an in-process axum server over TLS on an ephemeral
/// loopback port, recording every request.
pub struct TlsReceiver {
    port: u16,
    recorded: Arc<Mutex<Vec<Recorded>>>,
    handle: axum_server::Handle<std::net::SocketAddr>,
}

/// A responder computed from the request (the `wiremock::Respond` shape the
/// K6 ACK-echo fixtures use).
pub type Responder = Arc<dyn Fn(&Recorded) -> Respond + Send + Sync>;

/// The correlation id a dispatch carried: the `x-ai-memory-correlation-id`
/// header when present, else the JSON body's `correlation_id`, else
/// `"missing"` (so a mismatch is a visible non-ack, never a silent one).
#[must_use]
pub fn correlation_id_of(req: &Recorded) -> String {
    if let Some(h) = req
        .headers
        .get("x-ai-memory-correlation-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    {
        return h.to_string();
    }
    serde_json::from_slice::<serde_json::Value>(&req.body)
        .ok()
        .and_then(|v| {
            v.get("correlation_id")
                .and_then(|c| c.as_str().map(str::to_string))
        })
        .unwrap_or_else(|| "missing".to_string())
}

/// The K6 ACK contract: `200 {"status":"ack","correlation_id":"<echoed>"}`
/// with the correlation id read back from the request — the shape
/// `deliver_with_retry` counts as a delivery.
#[must_use]
pub fn ack_echo() -> Responder {
    Arc::new(|req: &Recorded| {
        Respond::ok()
            .json(serde_json::json!({"status": "ack", "correlation_id": correlation_id_of(req)}))
    })
}

/// [`ack_echo`] that holds the response for `delay` first (a slow receiver).
#[must_use]
pub fn ack_echo_slow(delay: Duration) -> Responder {
    Arc::new(move |req: &Recorded| {
        Respond::ok()
            .json(serde_json::json!({"status": "ack", "correlation_id": correlation_id_of(req)}))
            .delay(delay)
    })
}

impl TlsReceiver {
    /// Start a receiver that answers every request with `respond`.
    pub async fn start(tls: &TestTls, respond: Respond) -> Self {
        Self::start_with(tls, Arc::new(move |_| respond.clone())).await
    }

    /// Start a receiver whose answer is computed per request.
    pub async fn start_with(tls: &TestTls, responder: Responder) -> Self {
        let recorded: Arc<Mutex<Vec<Recorded>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = recorded.clone();
        let app = axum::Router::new().fallback(
            move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
                let sink = sink.clone();
                let responder = responder.clone();
                async move {
                    // `uri` is the request-target (path + query); the suites
                    // read `req.url.path()` and `req.url`'s origin, so
                    // rebuild an absolute URL from the Host header.
                    let host = headers
                        .get(axum::http::header::HOST)
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("127.0.0.1");
                    let url = reqwest::Url::parse(&format!("https://{host}{uri}"))
                        .expect("absolute request URL");
                    let recorded = Recorded {
                        method,
                        url,
                        headers,
                        body: body.to_vec(),
                    };
                    let respond = responder(&recorded);
                    sink.lock().await.push(recorded);
                    if let Some(delay) = respond.delay {
                        tokio::time::sleep(delay).await;
                    }
                    let status = StatusCode::from_u16(respond.status).expect("valid status");
                    match respond.body_json {
                        Some(json) => (status, axum::Json(json)).into_response(),
                        None => status.into_response(),
                    }
                }
            },
        );
        let (port, handle) = tls.serve_router(app).await;
        Self {
            port,
            recorded,
            handle,
        }
    }

    /// `https://127.0.0.1:<port>` — the origin a subscription URL is built on.
    #[must_use]
    pub fn uri(&self) -> String {
        TestTls::base_url(self.port)
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Every request received so far, in arrival order. `Option` so the
    /// call site reads exactly as `wiremock::MockServer::received_requests`
    /// did (`.await.unwrap_or_default()`); it is always `Some`.
    pub async fn received_requests(&self) -> Option<Vec<Recorded>> {
        Some(self.recorded.lock().await.clone())
    }

    /// Number of requests received so far.
    pub async fn received_count(&self) -> usize {
        self.recorded.lock().await.len()
    }
}

impl Drop for TlsReceiver {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

use axum::response::IntoResponse as _;

/// The per-binary leaf, installed as the dispatcher's operator root the
/// first time this is called in a process. Returns the leaf so the caller
/// can start receivers with it.
pub fn dispatch_tls(scratch_dir: &std::path::Path) -> &'static TestTls {
    let tls = super::tls::shared(scratch_dir);
    ai_memory::subscriptions::install_dispatch_root_certificate(tls.cert_pem.as_bytes())
        .expect("install the fixture leaf as the dispatcher root (#3705)");
    tls
}
