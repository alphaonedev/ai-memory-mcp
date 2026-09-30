// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4075 — DNS pins carry the scheme default port the client will dial.

use super::*;

/// #4075 — the addresses the SSRF guard returns are installed verbatim
/// as reqwest per-host pins, so their PORT must be the port the client
/// will connect to: the scheme default (443) for an implicit-port
/// `https://` hostname, the explicit port when one is given. Pre-fix
/// every implicit-port target resolved (and was pinned) to :80.
#[test]
fn dns_pins_use_scheme_default_port_4075() {
    let ports = |url: &str| -> Vec<u16> {
        let (_, addrs) = validate_url_dns_resolved(url, true)
            .unwrap_or_else(|e| panic!("{url} must pass the loopback-allowed guard: {e}"));
        assert!(!addrs.is_empty(), "{url} must resolve");
        addrs.iter().map(std::net::SocketAddr::port).collect()
    };
    for url in [
        "https://localhost/hook",
        "https://LOCALHOST/hook",
        "HTTPS://localhost",
        "https://127.0.0.1/hook",
        "https://[::1]/hook",
    ] {
        assert!(
            ports(url).iter().all(|p| *p == 443),
            "#4075: implicit-port {url} must pin :443, got {:?}",
            ports(url)
        );
    }
    // Controls: an explicit port wins; plaintext loopback keeps :80.
    assert!(ports("https://localhost:8443/h").iter().all(|p| *p == 8443));
    assert!(ports("https://[::1]:8443/h").iter().all(|p| *p == 8443));
    assert!(ports("http://localhost/h").iter().all(|p| *p == 80));
    // A scheme with no known default is refused, never guessed.
    assert!(validate_url_dns_resolved("ftp://localhost/h", true).is_err());
}

/// #4075 — the single scheme default-port table both pinning lanes use.
#[test]
fn default_port_table_4075() {
    assert_eq!(default_port_for_scheme("https"), Some(443));
    assert_eq!(default_port_for_scheme("http"), Some(80));
    assert_eq!(default_port_for_scheme("gopher"), None);
    assert_eq!(
        host_port_with_default_port("example.com", 443),
        "example.com:443"
    );
}

/// #4075 — the premise of the fix, pinned against the LOCKED reqwest /
/// hyper-util: for a URL with no explicit port, the connector dials the
/// PIN's port, not the scheme default. So a pin resolved with the wrong
/// default port (the pre-fix `:80` for https) redirects the connection.
/// Proven on plaintext loopback (no TLS needed): the URL says implicit
/// :80, the pin says an ephemeral port, and the request lands on the
/// ephemeral listener.
#[test]
fn locked_connector_dials_the_pin_port_for_implicit_port_urls_4075() {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let pinned = listener.local_addr().expect("local addr");
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf);
        sock.write_all(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .expect("write response");
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .no_proxy()
        .resolve("pin-probe-4075.invalid", pinned)
        .build()
        .expect("client");
    let resp = client
        .get("http://pin-probe-4075.invalid/")
        .send()
        .expect("#4075: the implicit-port request must reach the PINNED port");
    assert_eq!(resp.status().as_u16(), 204);
    server.join().expect("server thread");
}
