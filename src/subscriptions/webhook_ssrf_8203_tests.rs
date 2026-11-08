// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Regression pins for #8203: compatible IPv6, dispatch DNS pins and proxies.

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};

const PRIVATE_IPV4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const METADATA_IPV4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

type DnsAnswer = (String, std::io::Result<SocketAddr>);

thread_local! {
    // Only the current synchronous send thread can consume this one-shot answer.
    // The normal guard still validates its address before the client is built.
    pub(super) static DNS_ANSWER: RefCell<Option<DnsAnswer>> = const { RefCell::new(None) };
}

pub(super) fn resolve(target: &str) -> std::io::Result<Vec<SocketAddr>> {
    if let Some((expected, address)) = DNS_ANSWER.with_borrow_mut(Option::take) {
        assert_eq!(target, expected, "#6860: resolve the actual webhook host");
        return address.map(|address| vec![address]);
    }
    target.to_socket_addrs().map(Iterator::collect)
}

#[test]
fn resolver_error_is_refused_8203() {
    const RESOLVER_TARGET: &str = "resolver-error.invalid:443";
    const WEBHOOK_URL: &str = "https://resolver-error.invalid:443/hook";
    if crate::test_support::run_env_isolated_child_or_spawn_scrubbing(
        "subscriptions::webhook_ssrf_8203_tests::resolver_error_is_refused_8203",
        &["AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL"],
    ) {
        return;
    }
    DNS_ANSWER.with_borrow_mut(|answer| {
        assert!(
            answer
                .replace((
                    RESOLVER_TARGET.to_owned(),
                    Err(std::io::ErrorKind::TimedOut.into()),
                ))
                .is_none()
        );
    });
    let result = super::validate_url_dns_with(WEBHOOK_URL, false);
    assert!(
        DNS_ANSWER.with_borrow_mut(Option::take).is_none(),
        "#8203: the guard must consume the injected resolver error"
    );
    assert!(
        result.is_err(),
        "#8203: resolver errors must fail closed: {result:?}"
    );
}

#[test]
fn compatible_and_mapped_private_addresses_are_refused_8203() {
    for address in [
        PRIVATE_IPV4.to_ipv6_compatible(),
        PRIVATE_IPV4.to_ipv6_mapped(),
    ] {
        let ip = IpAddr::V6(address);
        assert_eq!(super::normalize_ip(ip), IpAddr::V4(PRIVATE_IPV4));
        assert!(super::is_private(ip), "#8203: private address {address}");
        let url = format!("https://[{address}]/hook");
        assert!(super::validate_url_with(&url, false).is_err());
        assert!(super::validate_url_dns_with(&url, false).is_err());
    }
}

#[test]
fn ipv4_compatible_literals_are_refused_by_both_guards_6687() {
    for (host, expected) in [
        ("::127.0.0.1", Ipv4Addr::LOCALHOST),
        ("::7f00:1", Ipv4Addr::LOCALHOST),
        ("::a00:1", PRIVATE_IPV4),
        ("::169.254.169.254", METADATA_IPV4),
    ] {
        let url = format!("https://[{host}]/hook");
        let ip: IpAddr = host.parse().expect("compatible IPv6 fixture");
        assert_eq!(
            super::normalize_ip(ip),
            IpAddr::V4(expected),
            "#6687: compatible address must normalize to IPv4: {host}"
        );
        assert!(
            super::validate_url_with(&url, false).is_err(),
            "#6687: syntactic guard must refuse {host}"
        );
        assert!(
            super::validate_url_dns_with(&url, false).is_err(),
            "#6687: DNS guard must refuse {host}"
        );
    }
}

#[test]
fn compatible_normalization_preserves_ipv6_special_addresses_6687() {
    for host in ["::", "::1"] {
        let ip: IpAddr = host.parse().expect("IPv6 special address");
        assert_eq!(super::normalize_ip(ip), ip, "#6687: retain {host}");
        let url = format!("https://[{host}]/hook");
        assert!(super::validate_url_with(&url, false).is_err());
        assert!(super::validate_url_dns_with(&url, false).is_err());
    }
    for host in ["::127.0.0.1", "::7f00:1", "::1"] {
        let url = format!("https://[{host}]/hook");
        assert!(super::validate_url_with(&url, true).is_ok());
        assert!(super::validate_url_dns_with(&url, true).is_ok());
    }
    let public: IpAddr = "::8.8.8.8".parse().expect("public compatible address");
    assert_eq!(
        super::normalize_ip(public),
        "8.8.8.8".parse::<IpAddr>().expect("public IPv4")
    );
    assert!(super::validate_url_with("https://[::8.8.8.8]/", false).is_ok());
    assert!(super::validate_url_dns_with("https://[::8.8.8.8]/", false).is_ok());
}

#[test]
fn compatible_addresses_share_internal_egress_classification_6687() {
    use crate::egress::{EgressClass, EgressDecision, InferenceEgressMode};
    for (host, allowed) in [
        ("::127.0.0.1", true),
        ("::a00:1", true),
        ("::169.254.169.254", false),
        ("::8.8.8.8", false),
        ("::", false),
        ("::1", true),
    ] {
        let address = SocketAddr::new(host.parse().expect("IP fixture"), 443);
        let decision = crate::egress::evaluate_inference_egress_resolved(
            InferenceEgressMode::InternalOnly,
            EgressClass::InferenceLlm,
            "https://inference.example.test/",
            &[address],
        );
        assert_eq!(
            matches!(decision, EgressDecision::Allow),
            allowed,
            "#6687: shared internal classifier for {host}: {decision:?}"
        );
    }
}

#[cfg(unix)]
mod dispatch {
    use super::DNS_ANSWER;
    use std::net::{SocketAddr, TcpListener, TcpStream};

    const CHILD_ROLE: &str = "AI_MEMORY_TEST_WEBHOOK_8203_CHILD";
    const BODY: &str = "{\"event\":\"dns-pin-8203\"}";
    const CORRELATION: &str = "webhook-pin-8203";
    const TIMESTAMP: &str = "1700000000";
    const SIGNATURE: &str = "test-signature-8203";
    const PIN_HOSTS: [&str; 2] = ["pin-test.invalid", "pin-test.invalid."];

    fn assert_child_succeeded(output: &std::process::Output) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "#8203: isolated webhook child:\n{stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("1 passed") && !stdout.contains("0 passed"),
            "#8203: exact child must execute one test: {stdout}"
        );
    }

    async fn assert_pinned_delivery(host: &str) {
        use axum::{Json, body::Bytes, extract::State, http::HeaderMap};
        use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

        async fn receive(
            State(sender): State<UnboundedSender<(HeaderMap, Bytes)>>,
            headers: HeaderMap,
            body: Bytes,
        ) -> Json<serde_json::Value> {
            let correlation = headers["x-ai-memory-correlation-id"]
                .to_str()
                .expect("correlation header")
                .to_string();
            sender
                .send((headers, body))
                .expect("record webhook request");
            Json(serde_json::json!({"status": "ack", "correlation_id": correlation}))
        }

        let pki = crate::test_support::tls_test_pki();
        crate::subscriptions::install_dispatch_root_certificate(
            &std::fs::read(&pki.ca_pem).expect("test CA"),
        )
        .expect("trust the existing test PKI");
        let (sender, mut received) = unbounded_channel();
        let app = axum::Router::new().fallback(receive).with_state(sender);
        let base = crate::test_support::spawn_tls_mock(app).await;
        let address: SocketAddr = base
            .strip_prefix("https://")
            .expect("TLS mock scheme")
            .parse()
            .expect("TLS mock address");
        let target = format!("{host}:{}", address.port());
        let url = format!("https://{target}/hook");
        let result = tokio::task::spawn_blocking(move || {
            DNS_ANSWER.with_borrow_mut(|answer| {
                assert!(answer.replace((target, Ok(address))).is_none());
            });
            let result =
                crate::subscriptions::send(&url, BODY, TIMESTAMP, Some(SIGNATURE), CORRELATION);
            assert!(
                DNS_ANSWER.with_borrow_mut(Option::take).is_none(),
                "#6860: send must consume the guarded DNS answer"
            );
            result
        })
        .await
        .expect("join synchronous send");
        assert_eq!(result, Ok(()), "#8203: pinned TLS receiver must ACK {host}");
        let (headers, body) = received
            .try_recv()
            .expect("one POST reached pinned receiver");
        assert_eq!(body.as_ref(), BODY.as_bytes());
        assert_eq!(headers["x-ai-memory-correlation-id"], CORRELATION);
        assert_eq!(headers[crate::HEADER_AI_MEMORY_TIMESTAMP], TIMESTAMP);
        assert_eq!(
            headers[crate::HEADER_AI_MEMORY_SIGNATURE],
            format!("sha256={SIGNATURE}")
        );
        assert!(received.try_recv().is_err(), "exactly one POST per send");
    }

    fn exercise_pinned_hosts() {
        // Only the isolated child changes this process-wide test posture.
        crate::config::set_allow_loopback_webhooks(true);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("receiver runtime");
        runtime.block_on(async {
            for host in PIN_HOSTS {
                assert_pinned_delivery(host).await;
            }
        });
    }

    #[test]
    fn send_uses_guarded_dns_answer_6860() {
        if std::env::var_os(CHILD_ROLE).is_none() {
            let output = crate::test_support::spawn_test_child(
                "subscriptions::webhook_ssrf_8203_tests::dispatch::send_uses_guarded_dns_answer_6860",
                &[(CHILD_ROLE, "1"), ("NO_PROXY", ""), ("no_proxy", "")],
            );
            assert_child_succeeded(&output);
            return;
        }
        exercise_pinned_hosts();
    }

    #[test]
    fn send_ignores_environment_proxies_6372() {
        if std::env::var_os(CHILD_ROLE).is_none() {
            let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve proxy address");
            let address = reservation.local_addr().expect("proxy address");
            drop(reservation);
            assert!(
                TcpStream::connect(address).is_err(),
                "proxy must be unreachable"
            );
            let proxy = format!("http://{address}");
            for key in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
                let output = crate::test_support::spawn_test_child(
                    "subscriptions::webhook_ssrf_8203_tests::dispatch::send_ignores_environment_proxies_6372",
                    &[
                        (CHILD_ROLE, "1"),
                        ("NO_PROXY", ""),
                        ("no_proxy", ""),
                        (key, &proxy),
                    ],
                );
                assert_child_succeeded(&output);
            }
            return;
        }
        exercise_pinned_hosts();
    }
}
