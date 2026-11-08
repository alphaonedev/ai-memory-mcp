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
    let (host, addresses) =
        validate_url_dns_resolved(IMPLICIT_URL, true).expect("loopback resolver must succeed");
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
        let (_, addresses) =
            validate_url_dns_resolved(url, true).expect("loopback resolver must succeed");
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

#[path = "webhook_tls_receiver_6401_tests.rs"]
pub(super) mod receiver;

const PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const PUNYCODE_HOST: &str = "xn--bcher-kva.example";

struct PublicAnswer;

impl Drop for PublicAnswer {
    fn drop(&mut self) {
        super::webhook_ssrf_8203_tests::DNS_ANSWER.with_borrow_mut(|answer| *answer = None);
    }
}

fn public_answer(url: &str) -> (String, Vec<std::net::SocketAddr>) {
    use super::webhook_ssrf_8203_tests::DNS_ANSWER;
    let host = url
        .strip_prefix("https://")
        .and_then(|rest| rest.strip_suffix("/hook"))
        .expect("IDN fixture authority");
    DNS_ANSWER.with_borrow_mut(|answer| {
        assert!(
            answer
                .replace((
                    format!("{host}:{HTTPS_PORT}"),
                    Ok(std::net::SocketAddr::new(PUBLIC_IP.into(), HTTPS_PORT)),
                ))
                .is_none()
        );
    });
    let _reset = PublicAnswer;
    let result = validate_url_dns_with(url, false);
    assert!(DNS_ANSWER.with_borrow_mut(Option::take).is_none());
    result.expect("injected public address must be admitted")
}

#[test]
fn punycode_idn_public_dns_pins_443_6866() {
    let (host, addresses) = public_answer(PUNYCODE_URL);
    assert_eq!(host, PUNYCODE_HOST);
    assert_eq!(
        addresses,
        vec![std::net::SocketAddr::new(PUBLIC_IP.into(), HTTPS_PORT)]
    );
}

#[test]
fn unicode_idn_public_dns_answer_6866() {
    // #6371 owns the Unicode/client pin-key difference. This cell exercises
    // the real guard's public-address admission without normalizing its input.
    let (_, addresses) = public_answer(UNICODE_URL);
    assert_eq!(
        addresses,
        vec![std::net::SocketAddr::new(PUBLIC_IP.into(), HTTPS_PORT)]
    );
}

#[test]
fn inference_http_default_helper_is_unchanged_6401() {
    assert_eq!(
        host_port_with_default_http_port("localhost"),
        "localhost:80"
    );
}

#[test]
fn guard_rejects_zero_port_8649() {
    for host in ["localhost", "127.0.0.1", "[::1]"] {
        let url = format!("https://{host}:0/hook");
        assert!(validate_url_dns_resolved(&url, true).is_err(), "{url}");
    }
}

#[test]
fn guard_rejects_empty_port_8649() {
    for host in ["localhost", "127.0.0.1", "[::1]"] {
        let url = format!("https://{host}:/hook");
        assert!(validate_url_dns_resolved(&url, true).is_err(), "{url}");
    }
}

#[test]
fn guard_rejects_overflow_port_8649() {
    for host in ["localhost", "127.0.0.1", "[::1]"] {
        let url = format!("https://{host}:65536/hook");
        assert!(validate_url_dns_resolved(&url, true).is_err(), "{url}");
    }
}

#[test]
fn normalizer_rejects_zero_port_8649() {
    assert_invalid_normalized_port("0");
}

#[test]
fn normalizer_rejects_empty_port_8649() {
    assert_invalid_normalized_port("");
}

#[test]
fn normalizer_rejects_overflow_port_8649() {
    assert_invalid_normalized_port("65536");
}

fn assert_invalid_normalized_port(port: &str) {
    for host in ["localhost", "127.0.0.1", "[::1]"] {
        for scheme in ["https", "http"] {
            let authority = format!("{host}:{port}");
            assert!(
                normalize_webhook_host_port(&authority, scheme).is_err(),
                "{authority}"
            );
        }
    }
}

#[test]
fn normalizer_preserves_valid_ports_and_host_spelling_8649() {
    for host in [
        "localhost",
        "127.0.0.1",
        "[::1]",
        "bücher.example",
        PUNYCODE_HOST,
    ] {
        for (scheme, default) in [("https", HTTPS_PORT), ("http", 80)] {
            assert_eq!(
                normalize_webhook_host_port(host, scheme).expect("scheme default"),
                format!("{host}:{default}")
            );
            for port in [1, HTTPS_PORT, 8443, u16::MAX] {
                let authority = format!("{host}:{port}");
                assert_eq!(
                    normalize_webhook_host_port(&authority, scheme).expect("explicit port"),
                    authority
                );
            }
        }
    }
}
