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
    // The ladder's first backoff alone is 200 ms; a terminal refusal returns
    // without sleeping at all.
    assert!(
        started.elapsed() < RETRY_BACKOFFS[0],
        "#4165: no backoff sleep for a terminal refusal ({:?})",
        started.elapsed()
    );
}
