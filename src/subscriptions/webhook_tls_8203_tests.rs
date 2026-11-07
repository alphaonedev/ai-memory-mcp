// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6401 scheme-default regression and #6866 IDN admission pins.

use super::*;

const HTTPS_PORT: u16 = 443;
const IMPLICIT_URL: &str = "https://localhost/hook";
const UNICODE_URL: &str = "https://bücher.example/hook";
const PUNYCODE_URL: &str = "https://xn--bcher-kva.example/hook";

#[test]
fn implicit_https_default_port_6401() {
    let (host, addresses) = validate_url_dns_resolved(IMPLICIT_URL, true)
        .expect("loopback resolver must succeed");
    assert_eq!(host, "localhost");
    assert!(!addresses.is_empty());
    let ports: Vec<_> = addresses.iter().map(std::net::SocketAddr::port).collect();
    assert!(
        ports.iter().all(|port| *port == HTTPS_PORT),
        "#6401 prerequisite: implicit HTTPS must pin 443, got {ports:?}"
    );
}

#[test]
fn explicit_https_port_control_6401() {
    for (url, port) in [
        ("https://localhost:443/hook", HTTPS_PORT),
        ("https://localhost:8443/hook", 8443),
        ("http://localhost/hook", 80),
    ] {
        let (_, addresses) = validate_url_dns_resolved(url, true)
            .expect("loopback resolver must succeed");
        assert!(!addresses.is_empty());
        assert!(addresses.iter().all(|address| address.port() == port));
    }
}

#[test]
fn idn_admission_only_6866() {
    for url in [UNICODE_URL, PUNYCODE_URL] {
        validate_url_with(url, false).expect("IDN admission accepts both spellings");
    }
}
