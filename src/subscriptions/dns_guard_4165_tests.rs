// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4165 (WP-EGRESS #6053) — the DNS-resolved SSRF guard's refusal is split
//! into a TERMINAL class (the stored URL names a forbidden address, or a host
//! that can never resolve) and a RETRYABLE class (the resolver failed), so a
//! verdict that no later attempt can change is dead-lettered on the first
//! attempt instead of sleeping the whole backoff ladder (~6.2 s of a bounded
//! dispatch worker per event) for the same answer three more times.
//!
//! Child module of `subscriptions` so the cells can drive the PRIVATE retry
//! ladder (`deliver_with_retry`) and the private guard directly (the parent
//! stays under its QUAL-10 ceiling).

use super::dns_guard::DnsGuardRefusal;
use super::*;

/// A host the guard refuses DETERMINISTICALLY without a resolver round-trip:
/// a 70-octet DNS label violates RFC 1035 §2.3.4 (the hermetic construction
/// `test_validate_url_dns_fails_closed_on_dns_failure_1053` uses). The
/// syntactic guard passes it (not loopback, not an IP literal), so `send`
/// reaches the DNS guard, whose verdict is a pure function of the URL.
fn shape_refused_url() -> String {
    format!("https://{}.fxf1-test./hook", "a".repeat(70))
}

#[test]
fn ladder_stops_after_one_attempt_for_a_deterministic_dns_refusal_4165() {
    let _env_guard = super::tests::SSRF_ENV_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let url = shape_refused_url();
    let started = std::time::Instant::now();
    let outcome = deliver_with_retry(&url, "{}", "2026-10-09T00:00:00Z", None, "corr-4165");
    assert!(!outcome.success);
    assert_eq!(
        outcome.attempts, 1,
        "#4165: a DNS-guard verdict that is a pure function of the stored URL must \
         dead-letter on the FIRST attempt, not retry through the ladder; last_error={}",
        outcome.last_error
    );
    assert!(
        refusal_is_terminal(&outcome.last_error),
        "#4165: the recorded reason must be the terminal class: {}",
        outcome.last_error
    );
    assert_eq!(outcome.last_error, dlq_reason::DNS_SSRF_FORBIDDEN_ADDRESS);
    // The ladder's first backoff alone is 200 ms; a terminal refusal returns
    // without sleeping at all.
    assert!(
        started.elapsed() < RETRY_BACKOFFS[0],
        "#4165: no backoff sleep for a terminal refusal ({:?})",
        started.elapsed()
    );
}

#[test]
fn address_class_refusals_are_terminal_4165() {
    // The issue's cell: a hook at the cloud-metadata address. The DNS guard
    // resolves the literal itself and refuses it for its ADDRESS CLASS — a
    // verdict no retry can change — so it lands as the terminal reason.
    // (The syntactic guard refuses the same literal one line earlier in
    // `send` under `ssrf_rejected`; this pins the DNS guard's OWN class for
    // the hostname-resolves-to-metadata shape it alone can see.)
    for (url, allow_loopback) in [
        ("https://169.254.169.254/latest/meta-data/", false),
        ("https://10.0.0.1/hook", false),
        ("https://[fd00::1]/hook", false),
        ("https://127.0.0.1/hook", false),
        ("https://[::ffff:10.0.0.1]/hook", true),
    ] {
        let refusal = validate_url_dns_with(url, allow_loopback)
            .expect_err("the DNS guard refuses the forbidden class");
        assert!(
            matches!(refusal, DnsGuardRefusal::ForbiddenAddress(_)),
            "#4165: {url} is an address-class refusal, got {refusal:?}"
        );
        assert_eq!(refusal.dlq_reason(), dlq_reason::DNS_SSRF_FORBIDDEN_ADDRESS);
        assert!(
            refusal_is_terminal(refusal.dlq_reason()),
            "#4165: {url} must be terminal"
        );
    }
    // A host that can never name an address (RFC 1035 shape) is terminal too.
    let shape = validate_url_dns_with(&shape_refused_url(), false)
        .expect_err("the shape check refuses a 70-octet label");
    assert!(matches!(shape, DnsGuardRefusal::ForbiddenAddress(_)));
    assert!(
        shape.to_string().contains("RFC 1035"),
        "the message still names the shape verdict: {shape}"
    );
    // Presence control: the opted-in loopback shape is admitted.
    assert!(validate_url_dns_with("https://127.0.0.1/hook", true).is_ok());
}

#[test]
fn resolver_failure_class_stays_retryable_4165() {
    // The RETRYABLE class is the ladder's default; its token must never be
    // treated as terminal, and the two tokens must be distinct closed-vocab
    // values (the stored `last_error` is what the subscriber reads back).
    let transient = DnsGuardRefusal::ResolutionFailed("resolver timed out".to_string());
    assert_eq!(transient.dlq_reason(), dlq_reason::DNS_RESOLUTION_FAILED);
    assert!(!refusal_is_terminal(transient.dlq_reason()));
    assert!(!refusal_is_terminal(dlq_reason::DNS_RESOLUTION_FAILED));
    assert_ne!(
        dlq_reason::DNS_RESOLUTION_FAILED,
        dlq_reason::DNS_SSRF_FORBIDDEN_ADDRESS
    );
    assert_eq!(transient.to_string(), "resolver timed out");
    // The syntactic guard's reason stays terminal (the #3790 contract).
    assert!(refusal_is_terminal(dlq_reason::SSRF_REJECTED));
}
