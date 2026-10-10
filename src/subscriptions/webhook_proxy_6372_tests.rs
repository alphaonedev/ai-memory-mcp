// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6372 (WP-EGRESS #6053) — the webhook dispatch client must not honour a
//! process-wide `HTTPS_PROXY` / `ALL_PROXY`.
//!
//! `send()` pins the guard-validated addresses with `Client::builder()
//! .resolve(host, addr)`, but a system proxy resolves the host at the proxy
//! and receives the signed event body and the HMAC headers, so the pin (and
//! the SSRF guard behind it) is bypassed. The cell runs the dispatch in a
//! clean child process (`spawn_test_child`) whose environment carries an
//! `HTTPS_PROXY` aimed at a probe listener owned by the parent; the probe
//! must see ZERO connections and the delivery must reach the receiver.

#![cfg(unix)]

use super::*;

const PROXY_PORT_ENV: &str = "AI_MEMORY_TEST_6372_PROXY_PORT";
const CHILD_TEST: &str = "subscriptions::webhook_proxy_6372_tests::dispatch_ignores_proxy_env_6372";

/// Child half: deliver one signed event to a TLS receiver with
/// `HTTPS_PROXY` set to the parent's probe port (inherited from the env the
/// parent passes). Returns after asserting the delivery was acked.
fn deliver_with_proxy_env() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("child runtime");
    let url = rt.block_on(async {
        let pki = crate::test_support::tls_test_pki();
        let ca_pem = std::fs::read(&pki.ca_pem).expect("read the test CA");
        install_dispatch_root_certificate(&ca_pem).expect("install the test CA");
        let app = axum::Router::new().fallback(|headers: axum::http::HeaderMap| async move {
            let corr = headers
                .get("x-ai-memory-correlation-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            axum::Json(serde_json::json!({"status": "ack", "correlation_id": corr}))
        });
        format!("{}/hook", crate::test_support::spawn_tls_mock(app).await)
    });
    let res = std::thread::spawn(move || send(&url, "{}", "1700000000", None, "corr-6372", true))
        .join()
        .expect("dispatch thread");
    assert_eq!(
        res,
        Ok(()),
        "#6372: the delivery reaches the receiver directly"
    );
}

/// The proxy variable spellings reqwest reads for an `https://` target. Each
/// is exercised ALONE (a single-variable cell is what pins `.no_proxy()`
/// unconditionally: a guard that only looked at `HTTPS_PROXY` would pass the
/// all-four cell), and then all together.
const PROXY_ENV_SETS: &[&[&str]] = &[
    &["HTTPS_PROXY"],
    &["https_proxy"],
    &["ALL_PROXY"],
    &["all_proxy"],
    &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"],
];

#[test]
fn dispatch_ignores_proxy_env_6372() {
    if std::env::var(PROXY_PORT_ENV).is_ok() {
        deliver_with_proxy_env();
        return;
    }
    for names in PROXY_ENV_SETS {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the proxy probe");
        probe.set_nonblocking(true).expect("non-blocking probe");
        let port = probe
            .local_addr()
            .expect("probe address")
            .port()
            .to_string();
        let proxy = format!("http://127.0.0.1:{port}");
        let mut env: Vec<(&str, &str)> = vec![(PROXY_PORT_ENV, port.as_str())];
        env.extend(names.iter().map(|n| (*n, proxy.as_str())));
        let out = crate::test_support::spawn_test_child(CHILD_TEST, &env);
        assert!(
            probe.accept().is_err(),
            "#6372: the proxy probe must receive zero CONNECTs with {names:?} set"
        );
        assert!(
            out.status.success(),
            "#6372: the child delivery must succeed with {names:?} set.\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
