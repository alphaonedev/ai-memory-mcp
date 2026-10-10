// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6371 (WP-EGRESS #6053) — the webhook SSRF guards and the HTTP client
//! must read the SAME host out of a webhook URL.
//!
//! The guards carved the host out of the raw string by hand while `send()`
//! handed the string to reqwest, whose WHATWG parser ends the authority at a
//! backslash and normalizes legacy IPv4 spellings. `https://127.0.0.1\@8.8.8.8/x`
//! read as the public `8.8.8.8` to the guard and as loopback to the client.
//! Hermetic: every host below is an IP literal (no resolver round-trip).

use super::*;

/// Shapes the old hand parse and reqwest read differently. The CLIENT's host
/// is a loopback / private / link-local address in every one of them.
const DIFFERENTIAL_TARGETS_6371: &[&str] = &[
    "https://127.0.0.1\\@8.8.8.8/hook",
    "https://127.0.0.1:8443\\@8.8.8.8/hook",
    "https://169.254.169.254\\@8.8.8.8/latest/meta-data/",
    "https://169.254.169.254:443\\@8.8.8.8/latest",
    "https://[::1]\\@8.8.8.8/hook",
    "https://[fd00::1]\\@8.8.8.8/hook",
    "https://localhost\\@8.8.8.8/hook",
    "https://10.0.0.5\\@8.8.8.8/hook",
    "https://2130706433/hook",
    "https://0x7f.0.0.1/hook",
    "https://127.1/hook",
    "https://0177.0.0.1/hook",
    "https://2852039166/latest",
];

#[test]
fn syntactic_guard_refuses_what_the_client_would_send_internally_6371() {
    for url in DIFFERENTIAL_TARGETS_6371 {
        let res = validate_url_with(url, false);
        assert!(
            res.is_err(),
            "#6371: the syntactic guard must refuse {url}, whose client host is internal"
        );
    }
}

#[test]
fn dns_guard_refuses_what_the_client_would_send_internally_6371() {
    for url in DIFFERENTIAL_TARGETS_6371 {
        let res = validate_url_dns_with(url, false);
        assert!(
            res.is_err(),
            "#6371: the DNS guard must refuse {url}, whose client host is internal; got {res:?}"
        );
    }
}

#[test]
fn guard_and_client_agree_on_the_host_6371() {
    // `8.8.8.8\@169.254.169.254` is a PUBLIC target to the client (the
    // backslash ends the authority at 8.8.8.8). The guard must judge, and
    // pin, the host the client connects to, not the text after the `@`.
    let url = "https://8.8.8.8\\@169.254.169.254/hook";
    assert_eq!(
        reqwest::Url::parse(url)
            .ok()
            .as_ref()
            .and_then(reqwest::Url::host_str),
        Some("8.8.8.8"),
        "premise: the client's host"
    );
    validate_url_with(url, false).expect("#6371: the syntactic guard judges the client's host");
    let (host, addrs) =
        validate_url_dns_with(url, false).expect("#6371: the DNS guard judges the client's host");
    assert_eq!(
        host, "8.8.8.8",
        "#6371: the pinned host is the client's host"
    );
    assert!(
        addrs
            .iter()
            .all(|a| a.ip().to_string() == "8.8.8.8" && a.port() == 443),
        "#6371: the pin is the client's address on the scheme default port: {addrs:?}"
    );
}

#[test]
fn plain_listener_gets_no_connection_from_send_6371() {
    // End to end with the production-default posture (loopback webhooks
    // OFF): the guards clear `8.8.8.8`, the pre-fix client connects to the
    // loopback listener named before the backslash.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    listener
        .set_nonblocking(true)
        .expect("non-blocking listener");
    let port = listener.local_addr().expect("listener address").port();
    let url = format!("https://127.0.0.1:{port}\\@8.8.8.8/hook");
    let res = send(&url, "{}", "1700000000", None, "corr-6371", false);
    assert_eq!(
        res,
        Err(dlq_reason::SSRF_REJECTED.to_string()),
        "#6371: refused by the guard, never attempted"
    );
    assert!(
        listener.accept().is_err(),
        "#6371: no connection may reach the loopback listener"
    );
}

/// #6687 — the deprecated IPv4-compatible `::/96` form wraps an IPv4 address
/// exactly like `::ffff:`; both guards must read the wrapped address.
#[test]
fn ipv4_compatible_ipv6_literals_are_unwrapped_by_both_guards_6687() {
    for url in [
        "https://[::127.0.0.1]/hook",
        "https://[::7f00:1]/hook",
        "https://[::10.0.0.1]/hook",
        "https://[::169.254.169.254]/latest",
        "https://[::192.168.1.1]/hook",
    ] {
        assert!(
            validate_url_with(url, false).is_err(),
            "#6687: the syntactic guard must refuse {url}"
        );
        assert!(
            validate_url_dns_with(url, false).is_err(),
            "#6687: the DNS guard must refuse {url}"
        );
    }
    // The wrapped loopback is loopback: allowed only with the opt-in.
    assert!(validate_url_with("https://[::127.0.0.1]/hook", true).is_ok());
    assert!(is_loopback_normalized("::127.0.0.1".parse().expect("ip")));
    assert_eq!(
        normalize_ip("::10.0.0.1".parse().expect("ip")),
        "10.0.0.1".parse::<IpAddr>().expect("ip")
    );
    // `::` and `::1` keep their IPv6 identity (no wrap to 0.0.0.0 / 0.0.0.1).
    assert_eq!(
        normalize_ip("::1".parse().expect("ip")),
        "::1".parse::<IpAddr>().expect("ip")
    );
    assert_eq!(
        normalize_ip("::".parse().expect("ip")),
        "::".parse::<IpAddr>().expect("ip")
    );
}
