// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6401 (WP-EGRESS #6053, #4075) — an end-to-end TLS receiver for a webhook
//! whose `https://` URL names NO port.
//!
//! The #4075 cells assert the pinned `SocketAddr` ports; nothing proved a
//! real TLS handshake and a signed POST land on the scheme default. The
//! connector keeps the pinned override's port when the URI omits one, so the
//! delivery goes to TCP 443. This cell serves the in-process test PKI (a
//! self-signed CA minted per run under the test `TMPDIR`) on port 443 and
//! delivers `https://localhost/hook` to it: it must arrive, signed, once.
//!
//! Port 443 is privileged on most Linux hosts. A host that cannot bind it
//! FAILS this cell (it used to skip silently, which let a connector regression
//! pass green, mutant N20). CI lowers `net.ipv4.ip_unprivileged_port_start`
//! on its Linux jobs; a developer host that genuinely cannot bind 443 sets
//! `AI_MEMORY_TEST_SKIP_443_BIND=1`, which skips the TLS leg and says so.

use super::*;

const IMPLICIT_PORT_URL: &str = "https://localhost/hook";

/// Explicit opt-out for hosts that cannot bind the privileged port 443.
const SKIP_443_ENV: &str = "AI_MEMORY_TEST_SKIP_443_BIND";

/// #6401 — turn the outcome of the 443 bind into a listener. A failed bind is
/// a test FAILURE unless `opt_out` is set; the opt-out returns `None` after an
/// explicit stderr line. Pure so the policy is itself tested.
fn listener_or_loud_failure(
    bound: std::io::Result<std::net::TcpListener>,
    opt_out: bool,
) -> Option<std::net::TcpListener> {
    match bound {
        Ok(l) => Some(l),
        Err(e) if opt_out => {
            eprintln!("#6401: cannot bind port 443 ({e}); {SKIP_443_ENV} set, TLS leg skipped");
            None
        }
        Err(e) => panic!(
            "#6401: cannot bind the wildcard port 443 ({e}); the TLS default-port leg must run. \
             On Linux run `sudo sysctl -w net.ipv4.ip_unprivileged_port_start=0` (CI does); set \
             {SKIP_443_ENV}=1 only on a host that cannot bind it"
        ),
    }
}

fn bind_443() -> std::io::Result<std::net::TcpListener> {
    // Dual-stack wildcard first: `localhost` pins both `::1` and `127.0.0.1`.
    std::net::TcpListener::bind("[::]:443").or_else(|_| std::net::TcpListener::bind("0.0.0.0:443"))
}

#[test]
#[should_panic(expected = "#6401: cannot bind the wildcard port 443")]
fn failed_443_bind_fails_loudly_without_opt_out_6401() {
    let denied = Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    let _ = listener_or_loud_failure(denied, false);
}

#[test]
fn failed_443_bind_is_skipped_only_with_explicit_opt_out_6401() {
    let denied = Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    assert!(listener_or_loud_failure(denied, true).is_none());
    let free = std::net::TcpListener::bind("127.0.0.1:0");
    assert!(listener_or_loud_failure(free, false).is_some());
}

#[test]
fn https_url_without_port_delivers_to_443_over_tls_6401() {
    // The pin leg runs everywhere.
    let (_host, addrs) = validate_url_dns_with(IMPLICIT_PORT_URL, true)
        .unwrap_or_else(|e| panic!("{IMPLICIT_PORT_URL} is an accepted loopback shape: {e}"));
    assert!(
        addrs.iter().all(|a| a.port() == 443),
        "#6401: pinned ports must be the https default 443, got {addrs:?}"
    );

    let opt_out = std::env::var_os(SKIP_443_ENV).is_some_and(|v| v == "1");
    let Some(listener) = listener_or_loud_failure(bind_443(), opt_out) else {
        return;
    };
    listener
        .set_nonblocking(true)
        .expect("non-blocking listener");

    let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let sink = received.clone();
    rt.block_on(async move {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = crate::test_support::tls_test_pki();
        let ca_pem = std::fs::read(&pki.ca_pem).expect("read the test CA");
        install_dispatch_root_certificate(&ca_pem).expect("install the test CA");
        let config = crate::tls::load_rustls_config(&pki.leaf_pem, &pki.leaf_key_pem)
            .await
            .expect("test leaf TLS config");
        let acceptor = crate::tls::serve_rustls_acceptor(&config);
        let app = axum::Router::new().fallback(
            move |uri: axum::http::Uri, headers: axum::http::HeaderMap, body: String| {
                let sink = sink.clone();
                async move {
                    let corr = headers
                        .get("x-ai-memory-correlation-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    if let Ok(mut g) = sink.lock() {
                        g.push((uri.path().to_string(), body));
                    }
                    axum::Json(serde_json::json!({"status": "ack", "correlation_id": corr}))
                }
            },
        );
        tokio::spawn(async move {
            let _ = axum_server::from_tcp(listener)
                .expect("axum_server from_tcp")
                .acceptor(acceptor)
                .serve(app.into_make_service())
                .await;
        });
    });
    let res = std::thread::spawn(|| {
        send(
            IMPLICIT_PORT_URL,
            "{\"e\":1}",
            "1700000000",
            None,
            "corr-6401",
            true,
        )
    })
    .join()
    .expect("dispatch thread");
    assert_eq!(
        res,
        Ok(()),
        "#6401: delivery to https://localhost (443) acks; pins {addrs:?}"
    );
    // `send` returning Ok is exactly the branch `deliver_with_retry` maps to
    // `success: true`, i.e. NO `subscription_dlq` row and no retry ladder.
    let got = received.lock().expect("receiver log").clone();
    assert_eq!(
        got,
        vec![("/hook".to_string(), "{\"e\":1}".to_string())],
        "#6401: exactly one POST reached the 443 receiver"
    );
}
