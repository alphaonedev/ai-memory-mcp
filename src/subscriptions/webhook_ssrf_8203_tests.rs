// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Regression pins for #8203: compatible IPv6, dispatch DNS pins and proxies.

use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

thread_local! {
    // Only the current synchronous send thread can consume this one-shot answer.
    // The normal guard still validates its address before the client is built.
    static DNS_ANSWER: RefCell<Option<(String, SocketAddr)>> = const { RefCell::new(None) };
}

pub(super) fn resolve(target: &str) -> std::io::Result<Vec<SocketAddr>> {
    if let Some((expected, address)) = DNS_ANSWER.with_borrow_mut(Option::take) {
        assert_eq!(target, expected, "#6860: resolve the actual webhook host");
        return Ok(vec![address]);
    }
    target.to_socket_addrs().map(Iterator::collect)
}

#[test]
fn ipv4_compatible_literals_are_refused_by_both_guards_6687() {
    for host in ["::127.0.0.1", "::7f00:1", "::10.0.0.1", "::169.254.169.254"] {
        let url = format!("https://[{host}]/hook");
        let ip: IpAddr = host.parse().expect("compatible IPv6 fixture");
        assert!(
            matches!(super::normalize_ip(ip), IpAddr::V4(_)),
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
        ("::10.0.0.1", true),
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
    use std::time::{Duration, Instant};

    const CHILD_ROLE: &str = "AI_MEMORY_TEST_WEBHOOK_8203_CHILD";
    const CHILD_TIMEOUT: Duration = Duration::from_secs(120);
    const CHILD_POLL: Duration = Duration::from_millis(20);
    const BODY: &str = "{\"event\":\"dns-pin-8203\"}";
    const CORRELATION: &str = "webhook-pin-8203";
    const TIMESTAMP: &str = "1700000000";
    const SIGNATURE: &str = "test-signature-8203";
    const PIN_HOSTS: [&str; 2] = ["pin-test.invalid", "pin-test.invalid."];

    fn run_child(test_name: &str, environment: &[(&str, &str)]) {
        let directory = tempfile::tempdir_in(std::env::temp_dir()).expect("child scratch");
        let stdout_path = directory.path().join("stdout");
        let stderr_path = directory.path().join("stderr");
        let mut command = crate::spawn_audit::audited_command(
            std::env::current_exe().expect("current lib test binary"),
            "webhook_ssrf_8203_tests::run_child",
        );
        // The crate name is not part of libtest's exact test path.
        let module = module_path!().split_once("::").expect("crate module").1;
        let filter = format!("{module}::{test_name}");
        command
            .args(["--exact", &filter, "--nocapture", "--test-threads=1"])
            .env_clear()
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("TMPDIR", std::env::temp_dir())
            .env(CHILD_ROLE, "1")
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
            .envs(environment.iter().copied())
            .stdout(std::fs::File::create(&stdout_path).expect("child stdout"))
            .stderr(std::fs::File::create(&stderr_path).expect("child stderr"));
        let mut child = command.spawn().expect("spawn isolated webhook test");
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll webhook child") {
                break status;
            }
            if started.elapsed() >= CHILD_TIMEOUT {
                child.kill().expect("kill timed-out child");
                child.wait().expect("reap timed-out child");
                panic!("#8203: isolated webhook child exceeded {CHILD_TIMEOUT:?}");
            }
            std::thread::sleep(CHILD_POLL);
        };
        let stdout = std::fs::read_to_string(stdout_path).expect("read child stdout");
        let stderr = std::fs::read_to_string(stderr_path).expect("read child stderr");
        assert!(
            status.success(),
            "#8203: child {filter}:\n{stdout}\n{stderr}"
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
                assert!(answer.replace((target, address)).is_none());
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
            run_child("send_uses_guarded_dns_answer_6860", &[]);
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
                run_child("send_ignores_environment_proxies_6372", &[(key, &proxy)]);
            }
            return;
        }
        exercise_pinned_hosts();
    }
}
