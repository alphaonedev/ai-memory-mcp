// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4075 (WP-EGRESS #6053), inference lane — the `internal-only` resolve-
//! then-pin resolves an implicit-port `https://` target on the scheme's
//! default port (443), not on 80.
//!
//! `egress::resolve_inference_authority` shared the webhook guard's `:80`
//! default-port helper, so a pinned `https://host/v1` client carried port-80
//! overrides and the connector (which keeps an override's port unless the
//! URI port is explicit or the override port is 0) opened TLS to TCP 80.
//! Hermetic: loopback names and literals resolve through the hosts file.

use ai_memory::egress::{EgressClass, InferenceEgressMode, admit_inference_target};

fn pinned_ports(url: &str) -> Vec<u16> {
    let pin = admit_inference_target(
        InferenceEgressMode::InternalOnly,
        EgressClass::InferenceLlm,
        url,
    )
    .unwrap_or_else(|d| panic!("{url} is an internal target: {d:?}"))
    .expect("internal-only always pins on admit");
    assert!(
        !pin.addrs.is_empty(),
        "{url}: at least one address is pinned"
    );
    pin.addrs.iter().map(std::net::SocketAddr::port).collect()
}

#[test]
fn implicit_port_https_target_pins_443_4075() {
    for url in [
        "https://localhost/v1",
        "https://127.0.0.1/v1",
        "https://[::1]/v1",
    ] {
        let ports = pinned_ports(url);
        assert!(
            ports.iter().all(|&p| p == 443),
            "#4075: {url} must pin the scheme default 443, got {ports:?}"
        );
    }
}

#[test]
fn explicit_port_and_loopback_http_are_unchanged_4075() {
    // Controls: an explicit port is kept; loopback plaintext http (the
    // pinned allowed-path control of #3823) resolves on 80.
    for (url, port) in [
        ("https://localhost:8443/v1", 8443),
        ("https://127.0.0.1:11434/v1", 11434),
        ("http://127.0.0.1/v1", 80),
        ("http://localhost/v1", 80),
    ] {
        let ports = pinned_ports(url);
        assert!(
            ports.iter().all(|&p| p == port),
            "control: {url} must pin {port}, got {ports:?}"
        );
    }
}
