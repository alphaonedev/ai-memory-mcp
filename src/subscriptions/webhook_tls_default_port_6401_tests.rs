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
//! Port 443 is privileged on most Linux hosts; where the process may not bind
//! it (or something else owns it) the cell says so on stderr and asserts only
//! the pin, the end-to-end leg then runs on hosts that allow the bind (macOS
//! dev nodes, root CI).

use super::*;

const IMPLICIT_PORT_URL: &str = "https://localhost/hook";

#[test]
fn https_url_without_port_delivers_to_443_over_tls_6401() {
    // The pin leg runs everywhere.
    let (_host, addrs) = validate_url_dns_with(IMPLICIT_PORT_URL, true)
        .unwrap_or_else(|e| panic!("{IMPLICIT_PORT_URL} is an accepted loopback shape: {e}"));
    assert!(
        addrs.iter().all(|a| a.port() == 443),
        "#6401: pinned ports must be the https default 443, got {addrs:?}"
    );

    // Dual-stack wildcard first: `localhost` pins both `::1` and `127.0.0.1`.
    let bound = std::net::TcpListener::bind("[::]:443")
        .or_else(|_| std::net::TcpListener::bind("0.0.0.0:443"));
    let listener = match bound {
        Ok(l) => l,
        Err(e) => {
            eprintln!("#6401: cannot bind the wildcard port 443 here ({e}); TLS leg not exercised");
            return;
        }
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
    let got = received.lock().expect("receiver log").clone();
    assert_eq!(
        got,
        vec![("/hook".to_string(), "{\"e\":1}".to_string())],
        "#6401: exactly one POST reached the 443 receiver"
    );
}
