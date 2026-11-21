// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9666 measurement pin: what `mtls_agent_binding::bind_request` does with
//! every `X-Agent-Id` form when a client certificate is bound to an agent.
//!
//! `bind_request` reads the claimed header itself (first value, lossy UTF-8)
//! rather than through `caller_identity::header_agent_id`. Routing it through
//! the funnel would answer the duplicate and non-UTF-8 forms with the funnel's
//! 400 instead of the 200 / 403 below, a status a client sees, so the change
//! waits for the #9666 decision and the site stays allow-listed in the
//! ratchet. This table pins the behaviour as measured, so the decision is
//! taken on it and any change to it is red.

use ai_memory::mtls_agent_binding::{
    AGENT_ID_CERTIFICATE_MISMATCH, AgentBindingMode, ClientCertAgentBinding, bind_request,
};
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode};

const CERT_AGENT: &str = "ai:alice";
const OTHER_AGENT: &str = "ai:mallory";
const ROUTE: &str = "/api/v1/memories";
const BODY_LIMIT: usize = 64 * 1024;

/// What the request looks like after `bind_request`.
#[derive(Debug, PartialEq)]
enum Outcome {
    /// Passed on; the request now carries exactly these header values.
    Passed(Vec<Vec<u8>>),
    /// Refused with this status and body.
    Refused(StatusCode, serde_json::Value),
}

fn mismatch_body() -> serde_json::Value {
    serde_json::json!({
        "code": AGENT_ID_CERTIFICATE_MISMATCH,
        "error": "agent_id_certificate_mismatch: the claimed agent id disagrees with the \
                  agent id bound to the presented client certificate (\"ai:alice\")",
    })
}

async fn run(values: &[&[u8]]) -> Outcome {
    let mut req = Request::builder()
        .uri(ROUTE)
        .body(Body::empty())
        .expect("request");
    req.extensions_mut().insert(ClientCertAgentBinding::new(
        Some(CERT_AGENT.to_owned()),
        AgentBindingMode::Enforce,
    ));
    for v in values {
        req.headers_mut().append(
            ai_memory::HEADER_AGENT_ID,
            HeaderValue::from_bytes(v).expect("legal header bytes"),
        );
    }
    match bind_request(&mut req) {
        Ok(()) => Outcome::Passed(
            req.headers()
                .get_all(ai_memory::HEADER_AGENT_ID)
                .iter()
                .map(|v| v.as_bytes().to_vec())
                .collect(),
        ),
        Err(resp) => {
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), BODY_LIMIT)
                .await
                .expect("refusal body");
            Outcome::Refused(
                status,
                serde_json::from_slice(&bytes).expect("refusal body is JSON"),
            )
        }
    }
}

#[tokio::test]
async fn bind_request_header_forms_are_pinned_as_measured_9666() {
    let bound = || Outcome::Passed(vec![CERT_AGENT.as_bytes().to_vec()]);
    let refused = || Outcome::Refused(StatusCode::FORBIDDEN, mismatch_body());
    let rows: &[(&str, &[&[u8]], Outcome)] = &[
        ("absent", &[], bound()),
        ("empty", &[b""], bound()),
        ("the certificate's agent", &[CERT_AGENT.as_bytes()], bound()),
        ("another agent", &[OTHER_AGENT.as_bytes()], refused()),
        // First value is the certificate's agent: passed, and the insert
        // drops the second value, so no later layer sees it.
        (
            "duplicate, certificate's agent first",
            &[CERT_AGENT.as_bytes(), OTHER_AGENT.as_bytes()],
            bound(),
        ),
        (
            "duplicate, other agent first",
            &[OTHER_AGENT.as_bytes(), CERT_AGENT.as_bytes()],
            refused(),
        ),
        ("non-utf8", &[b"ai:\xffx"], refused()),
    ];
    for (name, values, want) in rows {
        assert_eq!(&run(values).await, want, "{name}");
    }
}
