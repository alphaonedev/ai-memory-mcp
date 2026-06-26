// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `ai_memory::tls`. Exercises the on-disk PEM /
//! allowlist load paths end-to-end, including the operator-friendly error
//! messages around missing-file and empty-allowlist failure modes.
//!
//! Fixtures live under `tests/fixtures/tls/` and are regenerated via
//! `tests/fixtures/tls/regenerate.sh`. The cert/key files are produced
//! by `examples/gen_tls_fixtures.rs` (rcgen 0.14.7); the allowlist `.txt`
//! files are hand-authored.

use ai_memory::tls;
use std::path::PathBuf;

fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(rel)
}

#[tokio::test]
async fn test_load_rustls_config_with_valid_pem() {
    let cert = fixture("valid_cert.pem");
    let key = fixture("valid_key_pkcs8.pem");
    // Install ring as the default provider — required by rustls 0.23 the
    // first time a config is built. Ignored if already installed; the
    // config builder is what actually exercises the production path.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = tls::load_rustls_config(&cert, &key)
        .await
        .expect("load_rustls_config with rcgen-generated leaf cert + PKCS#8 key");
    // The returned RustlsConfig is opaque; if the ?-cascade above
    // returned Ok, every parser branch and the from_pem builder ran
    // successfully — that's the production path under test here.
    drop(config);
}

#[tokio::test]
async fn test_load_rustls_config_missing_cert_file_error_mentions_path() {
    let cert = fixture("does_not_exist.pem");
    let key = fixture("valid_key_pkcs8.pem");
    let err = tls::load_rustls_config(&cert, &key)
        .await
        .expect_err("missing cert file must error");
    let msg = err.to_string();
    assert!(
        msg.contains("failed to read TLS cert"),
        "expected operator-friendly cert read error, got: {msg}"
    );
    // The path must appear in the error so the operator can debug — this
    // is the whole reason the production code uses `with_context`.
    assert!(
        msg.contains("does_not_exist.pem")
            || err
                .chain()
                .any(|c| c.to_string().contains("does_not_exist.pem")),
        "expected path in error chain, got: {msg}"
    );
}

#[tokio::test]
async fn test_load_mtls_rustls_config_empty_allowlist_bails() {
    let cert = fixture("valid_cert.pem");
    let key = fixture("valid_key_pkcs8.pem");
    let allowlist = fixture("allowlist_empty.txt");
    let _ = rustls::crypto::ring::default_provider().install_default();
    let err = tls::load_mtls_rustls_config(&cert, &key, &allowlist)
        .await
        .expect_err("empty allowlist must refuse to start");
    let msg = err.to_string();
    assert!(
        msg.contains("empty"),
        "expected 'empty allowlist' error, got: {msg}"
    );
    assert!(
        msg.contains("refuse to start"),
        "expected 'refuse to start' wording, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// R-10 (#1798 Grok full-spectrum review) — TLS serve + graceful-shutdown
// integration. The config-load paths above are covered; the acceptor
// handshake is covered by tests/mtls_nodelay_acceptor.rs; and the NON-TLS
// serve+shutdown seam is covered by
// `daemon_runtime::tests::test_serve_http_with_shutdown_future_serves_then_stops`.
// The remaining untested seam is the TLS branch of `serve()`: that
// `axum_server::Handle::graceful_shutdown(..)` actually drains and stops the
// `axum_server::bind().acceptor(serve_rustls_acceptor).handle().serve()` loop
// after a real TLS request. This test reproduces that exact production bind
// chain (daemon_runtime.rs serve() TLS arm) over a minimal router and asserts
// it serves, then stops gracefully on the shutdown signal.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_serve_tls_graceful_shutdown_serves_then_stops() {
    use axum::routing::get;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;

    // Under feature graphs where BOTH `ring` and `aws-lc-rs` are present
    // (e.g. coverage's `--features sal,sal-postgres`), rustls cannot
    // auto-select a process CryptoProvider — pin ring explicitly, as the
    // production serve() path and the sibling mTLS tests do. Idempotent.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Production server TLS config from the committed fixtures (the plain-TLS
    // `--tls-cert`/`--tls-key` path, no client-auth).
    let tls_config =
        tls::load_rustls_config(&fixture("valid_cert.pem"), &fixture("valid_key_pkcs8.pem"))
            .await
            .expect("server rustls config from committed fixtures");

    // Bind a free loopback port.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let socket_addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let app = axum::Router::new().route("/api/v1/health", get(|| async { "ok" }));

    // EXACT serve() TLS arm: an `axum_server::Handle` whose graceful_shutdown
    // is triggered by a spawned signal listener (here a `Notify` standing in
    // for ctrl_c / SIGTERM), then `bind().acceptor(serve_rustls_acceptor).
    // handle().serve()`.
    let handle = axum_server::Handle::new();
    let handle_clone = handle.clone();
    let shutdown = Arc::new(Notify::new());
    let shutdown_clone = shutdown.clone();
    let grace = Duration::from_secs(5);
    tokio::spawn(async move {
        shutdown_clone.notified().await;
        handle_clone.graceful_shutdown(Some(grace));
    });

    let serve = tokio::spawn(async move {
        axum_server::bind(socket_addr)
            .acceptor(tls::serve_rustls_acceptor(&tls_config))
            .handle(handle)
            .serve(app.into_make_service())
            .await
    });

    // A real HTTPS client (reqwest's rustls backend) that accepts the
    // self-signed fixture cert. Poll until the listener is up, then assert a
    // 200 from the TLS-served /health.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    let url = format!("https://127.0.0.1:{port}/api/v1/health");
    let mut served = false;
    for _ in 0..60 {
        if let Ok(resp) = client.get(&url).send().await {
            assert_eq!(resp.status(), reqwest::StatusCode::OK);
            served = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        served,
        "TLS server must answer /health over HTTPS before shutdown"
    );

    // Signal graceful shutdown — the serve future MUST return Ok within the
    // grace window (this is the seam R-10 names: Handle::graceful_shutdown
    // actually stopping the rustls serve loop).
    shutdown.notify_one();
    let joined = tokio::time::timeout(Duration::from_secs(10), serve)
        .await
        .expect("TLS serve task must finish within the grace+timeout window")
        .expect("TLS serve task must not panic");
    assert!(joined.is_ok(), "TLS serve returned an error: {joined:?}");

    // After graceful shutdown the port no longer accepts new TLS connections.
    let after = client.get(&url).send().await;
    assert!(
        after.is_err(),
        "server must stop accepting new connections after graceful shutdown"
    );
}
