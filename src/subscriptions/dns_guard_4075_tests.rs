// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4075 (WP-EGRESS #6053) — the webhook DNS pin resolves an implicit-port
//! `https://` hostname on the SCHEME's default port (443), not on 80.
//!
//! `validate_url_dns_with` appended `:80` to every authority that omits a
//! port, so for `https://hostname/...` the pinned `SocketAddr`s carried port
//! 80. The locked connector (reqwest 0.12.28 / hyper-util 0.1.20) replaces
//! an override's port only when the URI port is explicit or the override
//! port is 0, so the TLS connection was made to TCP 80: the most common
//! webhook shape (public HTTPS hostname, default port) failed delivery
//! against a normal :443 receiver, retried through the ladder and landed in
//! the DLQ. Hermetic: `localhost` and the loopback literals resolve through
//! the hosts file, no network.

use super::*;

fn pinned_ports(url: &str) -> Vec<u16> {
    let (_host, addrs) = validate_url_dns_with(url, true)
        .unwrap_or_else(|e| panic!("{url} is an accepted loopback shape: {e}"));
    assert!(!addrs.is_empty(), "{url}: at least one address is pinned");
    addrs.iter().map(std::net::SocketAddr::port).collect()
}

#[test]
fn implicit_port_https_hostname_pins_443_4075() {
    // `localhost` is the one hostname every hosts file resolves (no network).
    for url in ["https://localhost/hook", "https://LOCALHOST/hook"] {
        let ports = pinned_ports(url);
        assert!(
            ports.iter().all(|&p| p == 443),
            "#4075: {url} must pin the scheme default 443, got {ports:?}"
        );
    }
}

#[test]
fn implicit_port_https_literals_pin_443_4075() {
    for url in ["https://127.0.0.1/hook", "https://[::1]/hook"] {
        let ports = pinned_ports(url);
        assert!(
            ports.iter().all(|&p| p == 443),
            "#4075: {url} must pin the scheme default 443, got {ports:?}"
        );
    }
}

#[test]
fn explicit_port_and_http_default_are_unchanged_4075() {
    // Controls: an explicit port is kept verbatim; the DNS guard is scheme-
    // agnostic by design (the syntactic guard owns the https-only rule), so
    // a plaintext http:// target still resolves on 80.
    for (url, port) in [
        ("https://localhost:8443/hook", 8443),
        ("https://127.0.0.1:8443/hook", 8443),
        ("https://[::1]:8443/hook", 8443),
        ("http://localhost/hook", 80),
        ("http://127.0.0.1/hook", 80),
    ] {
        let ports = pinned_ports(url);
        assert!(
            ports.iter().all(|&p| p == port),
            "control: {url} must pin {port}, got {ports:?}"
        );
    }
}
