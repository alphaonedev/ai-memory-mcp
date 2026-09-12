// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2032 M2 `tls_bind_guard` unit tests (cleartext off-host bind posture),
//! plus the #3200 R3 `asi-hard` arm. Mounted from `daemon_runtime.rs` via
//! `#[path]` (the `daemon_runtime_shutdown_tests.rs` precedent) so the
//! parent stays under its QUAL-10 ceiling; `tls_bind_guard` is private, so
//! the tests must stay a child module of `daemon_runtime`.

use super::*;
use crate::security_profile::SecurityPosture;

const STANDARD: SecurityPosture = SecurityPosture::Standard;
const ASI_HARD: SecurityPosture = SecurityPosture::AsiHard;

/// In-process TLS present => silent on any host (nothing to warn about).
#[test]
fn tls_bind_guard_tls_present_silent_2032_m2() {
    assert_eq!(
        tls_bind_guard(true, "0.0.0.0", false, false, STANDARD).unwrap(),
        None
    );
    // TLS present satisfies REQUIRE_TLS too.
    assert_eq!(
        tls_bind_guard(true, "0.0.0.0", false, true, STANDARD).unwrap(),
        None
    );
}

/// Plaintext loopback bind is exempt (same-host reverse-proxy default).
#[test]
fn tls_bind_guard_plaintext_loopback_silent_2032_m2() {
    for host in ["127.0.0.1", "::1", "localhost", "[::1]", "0:0:0:0:0:0:0:1"] {
        assert_eq!(
            tls_bind_guard(false, host, false, false, STANDARD).unwrap(),
            None,
            "plaintext loopback {host} must be silent"
        );
    }
}

/// Plaintext non-loopback bind WITHOUT the ack emits the hard M2 WARN
/// (permitted, not refused, this release) naming the escape hatches.
#[test]
fn tls_bind_guard_plaintext_nonloopback_warns_2032_m2() {
    let warning = tls_bind_guard(false, "0.0.0.0", false, false, STANDARD)
        .unwrap()
        .expect("plaintext non-loopback bind must WARN, not bind silently");
    assert!(
        warning.contains("CLEARTEXT")
            && warning.contains("AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK")
            && warning.contains("AI_MEMORY_REQUIRE_TLS"),
        "M2 WARN must name cleartext + both escape hatches: {warning}"
    );
}

/// The upstream-TLS acknowledgement silences the non-loopback WARN.
#[test]
fn tls_bind_guard_plaintext_nonloopback_acked_silent_2032_m2() {
    assert_eq!(
        tls_bind_guard(false, "0.0.0.0", true, false, STANDARD).unwrap(),
        None,
        "AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK must silence the M2 WARN"
    );
}

/// REQUIRE_TLS with no in-process TLS is refused (fail-closed-now) on any
/// host, INCLUDING loopback — the operator demanded TLS everywhere.
#[test]
fn tls_bind_guard_require_tls_refuses_plaintext_2032_m2() {
    for host in ["0.0.0.0", "127.0.0.1"] {
        let err = tls_bind_guard(false, host, false, true, STANDARD)
            .expect_err("REQUIRE_TLS + plaintext MUST be refused");
        assert!(
            err.contains("AI_MEMORY_REQUIRE_TLS") && err.contains("in-process TLS"),
            "refusal must name the knob for {host}: {err}"
        );
    }
    // Even the ack does not override an explicit REQUIRE_TLS demand.
    assert!(tls_bind_guard(false, "0.0.0.0", true, true, STANDARD).is_err());
}

/// #3200 R3 — under `asi-hard` a plaintext NON-loopback bind is REFUSED
/// outright, and the acknowledgement hatch does not open it.
#[test]
fn tls_bind_guard_asi_hard_refuses_nonloopback_plaintext_3200() {
    for ack in [false, true] {
        let err = tls_bind_guard(false, "0.0.0.0", ack, false, ASI_HARD)
            .expect_err("asi-hard + plaintext non-loopback MUST be refused");
        assert!(
            err.contains("asi-hard") && err.contains("CLEARTEXT"),
            "refusal must name the posture and the exposure (ack={ack}): {err}"
        );
    }
}

/// #3200 R3 — under `asi-hard` the loopback exemption stays (same-host
/// TLS-terminating proxy), and in-process TLS binds anywhere.
#[test]
fn tls_bind_guard_asi_hard_keeps_loopback_exemption_3200() {
    for host in ["127.0.0.1", "::1", "localhost"] {
        assert_eq!(
            tls_bind_guard(false, host, false, false, ASI_HARD).unwrap(),
            None,
            "asi-hard must keep the loopback plaintext exemption for {host}"
        );
    }
    assert_eq!(
        tls_bind_guard(true, "0.0.0.0", false, false, ASI_HARD).unwrap(),
        None,
        "in-process TLS satisfies asi-hard on any host"
    );
}
