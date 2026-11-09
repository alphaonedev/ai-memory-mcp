// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Regression pins for #8655 / #3744: the webhook guards read the same host
//! and port as the client URL parser. Moved out of `subscriptions.rs` so the
//! parent stays under its QUAL-10 ceiling (submodule-over-bump).

use super::{WebhookAuthority, validate_url_dns_with, validate_url_with};

#[test]
fn registration_parser_parity_8655() {
    for host in ["10.0.0.1", "127.0.0.1", "[fd00::1]", "[::1]"] {
        let url = format!("https://{host}{}@public.example/hook", char::from(92));
        let parsed = reqwest::Url::parse(&url).expect("synthetic URL parses");
        assert_eq!(parsed.host_str(), Some(host), "connection host oracle");
        let error = validate_url_with(&url, false)
            .expect_err("#8655: registration must check the connection host");
        assert!(
            error.to_string().contains(host),
            "refusal names the parsed host"
        );
    }
}

#[test]
fn dns_pin_parser_parity_8655() {
    let url = format!("https://127.0.0.2{}@127.0.0.1/hook", char::from(92));
    let parsed = reqwest::Url::parse(&url).expect("synthetic URL parses");
    let (host, addresses) = validate_url_dns_with(&url, true).expect("opted-in loopback");
    assert_eq!(
        Some(host.as_str()),
        parsed.host_str(),
        "#8655: DNS pin key parity"
    );
    assert!(!addresses.is_empty(), "pin has addresses");
    assert!(
        addresses.iter().all(|a| a.ip().to_string() == "127.0.0.2"),
        "only the canonical connection host may be resolved"
    );
    assert!(
        addresses.iter().all(|a| a.port() == 443),
        "HTTPS default port"
    );
}

#[test]
fn dns_private_target_parser_parity_8655() {
    let url = format!("https://10.0.0.1{}@127.0.0.1/hook", char::from(92));
    let error = validate_url_dns_with(&url, true)
        .expect_err("#8655: loopback opt-in cannot hide a private target");
    assert!(
        error.to_string().contains("private"),
        "address-class refusal"
    );
}

#[test]
fn malformed_authority_refused_8655() {
    for url in [
        "https://",
        "https://[",
        "file:///hook",
        "custom:/hook",
        "https://example.invalid:0/",
    ] {
        assert!(
            validate_url_with(url, true).is_err(),
            "invalid registration authority"
        );
        assert!(
            validate_url_dns_with(url, true).is_err(),
            "invalid DNS authority"
        );
    }
}

#[test]
fn parse_error_keeps_own_display_and_source_8655() {
    let url = "https://[";
    let error = WebhookAuthority::parse(url).expect_err("invalid authority");
    assert_eq!(
        error.to_string(),
        format!(
            "invalid webhook URL: {}",
            crate::url_display::url_origin(url)
        ),
        "#8655: caller-facing text is owned by the validation boundary"
    );
    let expected = reqwest::Url::parse(url).expect_err("invalid URL");
    assert_eq!(
        error.chain().nth(1).expect("parser cause").to_string(),
        expected.to_string(),
        "#8655: the original parser cause remains available"
    );
}

#[test]
fn parsed_authority_preserves_userinfo_controls_3744() {
    for (suffix, expected_host, expected_port) in [
        ("example.com/hook", "example.com", 443),
        ("a:b@example.com:8443/hook?x=1", "example.com", 8443),
        ("a@b@example.com/", "example.com", 443),
        ("a:b@[fd00::1]:443", "[fd00::1]", 443),
        ("example.com?x=@y", "example.com", 443),
        ("example.com/p@th", "example.com", 443),
    ] {
        let authority = WebhookAuthority::parse(&format!("https://{suffix}"))
            .expect("valid existing userinfo control");
        assert_eq!(authority.host, expected_host, "#3744: canonical host");
        assert_eq!(authority.port.get(), expected_port, "#3744: canonical port");
    }
}
