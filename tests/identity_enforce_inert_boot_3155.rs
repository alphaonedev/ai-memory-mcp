// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3155 (v1.0.0, security) — `AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY=enforce`
//! must not be SILENTLY inert when no per-agent keys are enrolled.
//!
//! `enforce_for_request` returns `None` on an empty enrolled map in EVERY mode,
//! and that is deliberate: the #1985 unsatisfiable-default trap means an
//! `enforce` posture which refused every named caller when nobody COULD be
//! key-attested would brick the deployment. The defect is not the inertness,
//! it is that an operator who DELIBERATELY selected `enforce` got no signal at
//! all — no boot WARN, no readiness flag — so a deployment could believe it was
//! refusing spoofed `X-Agent-Id` headers while serving every one of them `200`.
//!
//! This file pins BOTH halves of the contract:
//!
//! 1. the request-path behaviour is UNCHANGED (an empty enrolled map is still
//!    inert in every mode) — a documented default is never silently tightened;
//! 2. boot now produces a verdict for exactly the silently-disarmed
//!    combination, which the daemon renders as a WARN by default and as a
//!    refusal under `asi-hard`.
//!
//! Removal proof: making `inert_enforce_boot_reason` return `None`
//! unconditionally reds `enforce_with_zero_enrolled_keys_is_reported_at_boot_3155`.

use std::collections::HashMap;

use ai_memory::config::{ENV_HTTP_ATTESTED_IDENTITY, HttpIdentityMode};
use ai_memory::handlers::identity_binding::{enforce_for_request, inert_enforce_boot_reason};

#[test]
fn enforce_with_zero_enrolled_keys_is_reported_at_boot_3155() {
    let reason = inert_enforce_boot_reason(HttpIdentityMode::Enforce, 0).expect(
        "an `enforce` posture with zero enrolled per-agent keys is a DISARMED security \
         control and must produce a boot verdict",
    );
    assert!(
        reason.contains(ENV_HTTP_ATTESTED_IDENTITY),
        "the verdict must name the knob the operator set, got: {reason}"
    );
    assert!(
        reason.contains("INERT"),
        "the verdict must say plainly that the control is not armed, got: {reason}"
    );
    assert!(
        reason.contains("advisory"),
        "the verdict must offer the honest alternative posture, got: {reason}"
    );
}

#[test]
fn a_single_enrolled_key_arms_the_gate_and_silences_the_verdict_3155() {
    assert!(
        inert_enforce_boot_reason(HttpIdentityMode::Enforce, 1).is_none(),
        "one enrolled per-agent key is enough to ARM enforcement, so there is nothing \
         to warn about"
    );
    assert!(inert_enforce_boot_reason(HttpIdentityMode::Enforce, 4096).is_none());
}

#[test]
fn only_the_enforce_posture_produces_a_verdict_3155() {
    // `advisory` (the v1.0.0 default) and `off` are documented as inert with an
    // empty map; warning there would be noise on every single-operator
    // deployment, which is exactly what #1985 kept out.
    for mode in [HttpIdentityMode::Off, HttpIdentityMode::Advisory] {
        for enrolled in [0usize, 1, 7] {
            assert!(
                inert_enforce_boot_reason(mode, enrolled).is_none(),
                "{mode:?} with {enrolled} enrolled keys must produce no boot verdict"
            );
        }
    }
}

/// The documented request-path contract is NOT changed by #3155. This is the
/// "never silently tighten a documented default" half: the fix adds a boot
/// SIGNAL, it does not start refusing requests that were served before.
#[test]
fn an_empty_enrolled_map_stays_inert_on_the_request_path_3155() {
    let enrolled: HashMap<String, String> = HashMap::new();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-agent-id", "boss".parse().expect("header value"));
    headers.insert(
        "x-api-key",
        "shared-transport-key".parse().expect("header value"),
    );

    for mode in [
        HttpIdentityMode::Off,
        HttpIdentityMode::Advisory,
        HttpIdentityMode::Enforce,
    ] {
        assert!(
            enforce_for_request(&enrolled, mode, &headers, "boss", "/api/v1/export").is_none(),
            "{mode:?} with an EMPTY enrolled map must still serve the request — the \
             #1985 unsatisfiable-default trap is deliberate, and #3155 adds a boot \
             signal rather than changing this"
        );
    }
}

/// With a key enrolled, `enforce` does bite — so the boot verdict is scoped to
/// the genuinely-disarmed case and not merely describing a control that never
/// works.
#[test]
fn enforce_refuses_a_claimed_caller_once_a_key_is_enrolled_3155() {
    let mut enrolled: HashMap<String, String> = HashMap::new();
    // sha256 of some other agent's enrolled token -> that agent. The caller
    // below presents nothing that hashes to it, so it stays `Claimed`.
    enrolled.insert("0".repeat(64), "someone-else".to_string());

    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-agent-id", "boss".parse().expect("header value"));

    assert!(
        enforce_for_request(
            &enrolled,
            HttpIdentityMode::Enforce,
            &headers,
            "boss",
            "/api/v1/export",
        )
        .is_some(),
        "with at least one enrolled key, `enforce` must refuse a merely-claimed \
         principal — which is why the zero-key case is worth a boot verdict"
    );
    assert!(
        inert_enforce_boot_reason(HttpIdentityMode::Enforce, enrolled.len()).is_none(),
        "and that armed state must NOT be reported as inert"
    );
}
