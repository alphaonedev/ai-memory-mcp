// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6401 scheme-default regression and #6866 IDN admission pins.

use super::*;

const HTTPS_PORT: u16 = 443;
const IMPLICIT_URL: &str = "https://localhost/hook";
const UNICODE_URL: &str = "https://bücher.example/hook";
const PUNYCODE_URL: &str = "https://xn--bcher-kva.example/hook";
const INVALID_PORTS: [&str; 4] = ["0", "", "65536", "+0"];
const PORT_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];
const URL_SCHEMES: [&str; 2] = ["https", "http"];
const INVALID_PORT_ERROR: &str = "webhook URL has an invalid explicit port";
const PORT_CHILD: &str = "AI_MEMORY_TEST_INVALID_PORT_8649_CHILD";
const DNS_FAIL_OPEN: &str = "AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL";
const LARGE_HOST_CHARS: usize = 100_000;
const LARGE_INPUT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

#[test]
fn implicit_https_default_port_6401() {
    let (host, addresses) =
        validate_url_dns_resolved(IMPLICIT_URL, true).expect("loopback resolver must succeed");
    assert_eq!(host, "localhost");
    assert!(
        !addresses.is_empty(),
        "#6401: implicit HTTPS must resolve addresses"
    );
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
        assert!(!addresses.is_empty(), "#6401: {url} must resolve addresses");
        assert!(
            addresses.iter().all(|address| address.port() == port),
            "#6401: {url} must retain expected port {port}: {addresses:?}"
        );
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
                .is_none(),
            "#8649: IDN fixture must not replace an outstanding resolver answer"
        );
    });
    let _reset = PublicAnswer;
    let result = validate_url_dns_with(url, false);
    assert!(
        DNS_ANSWER.with_borrow_mut(Option::take).is_none(),
        "#8649: shared resolver must consume the injected IDN answer"
    );
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
    assert_dispatch_port_refused("guard_rejects_zero_port_8649", INVALID_PORTS[0]);
}

#[test]
fn guard_rejects_empty_port_8649() {
    assert_dispatch_port_refused("guard_rejects_empty_port_8649", INVALID_PORTS[1]);
}

#[test]
fn guard_rejects_overflow_port_8649() {
    assert_dispatch_port_refused("guard_rejects_overflow_port_8649", INVALID_PORTS[2]);
}

#[test]
fn guard_rejects_plus_zero_port_8649() {
    assert_dispatch_port_refused("guard_rejects_plus_zero_port_8649", INVALID_PORTS[3]);
}

fn run_invalid_port_children(test_name: &str) -> bool {
    if std::env::var(PORT_CHILD).as_deref() == Ok(test_name) {
        return false;
    }
    let module = module_path!().split_once("::").expect("crate module").1;
    let filter = format!("{module}::{test_name}");
    for override_value in [None, Some("1")] {
        let mut command = crate::spawn_audit::audited_command(
            std::env::current_exe().expect("lib test binary"),
            "webhook_tls_8203_tests::run_invalid_port_children",
        );
        command
            .args(["--exact", &filter, "--nocapture", "--test-threads=1"])
            .env_clear()
            .env(PORT_CHILD, test_name)
            .env("TMPDIR", std::env::temp_dir())
            .env("AI_MEMORY_NO_CONFIG", "1")
            .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)));
        if let Some(value) = override_value {
            command.env(DNS_FAIL_OPEN, value);
        }
        let output = command.output().expect("isolated invalid-port child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "#8649: {test_name} with DNS override {override_value:?}: {stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("1 passed") && !stdout.contains("0 passed"),
            "#8649: exact invalid-port child must execute one test: {stdout}"
        );
    }
    true
}

fn assert_dispatch_port_refused(test_name: &str, port: &str) {
    assert_invalid_url_ports(test_name, &[port], |url, allow_loopback| {
        validate_url_dns_resolved(url, allow_loopback).map(|_| ())
    });
}

fn assert_invalid_url_ports(
    test_name: &str,
    ports: &[&str],
    validate: fn(&str, bool) -> Result<()>,
) {
    if run_invalid_port_children(test_name) {
        return;
    }
    for port in ports {
        for host in PORT_HOSTS {
            for scheme in URL_SCHEMES {
                let url = format!("{scheme}://{host}:{port}/hook");
                let error = validate(&url, true).expect_err("#8649: invalid explicit port");
                assert_eq!(error.to_string(), INVALID_PORT_ERROR, "#8649: {url}");
            }
        }
    }
}

#[test]
fn registration_rejects_invalid_ports_8649() {
    assert_invalid_url_ports(
        "registration_rejects_invalid_ports_8649",
        &INVALID_PORTS,
        validate_url_with,
    );
}

#[test]
fn large_invalid_authorities_have_bounded_validation_8649() {
    if run_invalid_port_children("large_invalid_authorities_have_bounded_validation_8649") {
        return;
    }
    let started = std::time::Instant::now();
    for unit in ["a", "é"] {
        let host = unit.repeat(LARGE_HOST_CHARS);
        for scheme in URL_SCHEMES {
            let url = format!("{scheme}://{host}:{}/hook", INVALID_PORTS[0]);
            let registration = validate_url_with(&url, true).expect_err("invalid large authority");
            let dispatch =
                validate_url_dns_resolved(&url, true).expect_err("invalid large authority");
            assert_eq!(
                registration.to_string(),
                INVALID_PORT_ERROR,
                "registration {scheme}"
            );
            assert_eq!(
                dispatch.to_string(),
                INVALID_PORT_ERROR,
                "dispatch {scheme}"
            );
        }
    }
    assert!(
        started.elapsed() < LARGE_INPUT_DEADLINE,
        "#8649: 100K+ authority validation exceeded {LARGE_INPUT_DEADLINE:?}"
    );
}

#[test]
fn normalizer_rejects_zero_port_8649() {
    assert_invalid_normalized_port(INVALID_PORTS[0]);
}

#[test]
fn normalizer_rejects_empty_port_8649() {
    assert_invalid_normalized_port(INVALID_PORTS[1]);
}

#[test]
fn normalizer_rejects_overflow_port_8649() {
    assert_invalid_normalized_port(INVALID_PORTS[2]);
}

#[test]
fn normalizer_rejects_plus_zero_port_8649() {
    assert_invalid_normalized_port(INVALID_PORTS[3]);
}

fn assert_invalid_normalized_port(port: &str) {
    for host in PORT_HOSTS {
        for scheme in URL_SCHEMES {
            let authority = format!("{host}:{port}");
            let error = normalize_webhook_host_port(&authority, scheme)
                .expect_err("#8649: invalid normalized port");
            assert_eq!(
                error.to_string(),
                INVALID_PORT_ERROR,
                "#8649: {scheme} authority {authority}"
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
