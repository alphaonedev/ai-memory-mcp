// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3155 (v1.0.0, security) — `AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY=enforce`
//! must not be SILENTLY inert when no per-agent keys are enrolled.
//!
//! `enforce_for_request` (the per-handler gate) returns `None` on an empty
//! enrolled map in EVERY mode. #3155 made the `enforce` + zero-keys posture
//! visible at boot. Since #9341 B-1 (3-agent vote (71472661)) the authority
//! funnel refuses every unproven NAMED caller in that posture, so the boot
//! verdict says so instead of calling the posture inert.
//!
//! This file pins:
//!
//! 1. the per-handler gate stays inert on an empty map (the funnel refusal is
//!    pinned in `tests/http_idor_closure_2125_2096.rs`);
//! 2. boot produces a verdict for exactly the `enforce` + zero-keys
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
        reason.contains("attested_identity_required"),
        "#9341 B-1: the verdict must say named callers are refused, got: {reason}"
    );
    assert!(
        !reason.contains("INERT"),
        "#9341 B-1: the funnel refuses named callers with zero keys; the verdict \
         must not call the posture inert, got: {reason}"
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

/// The PER-HANDLER gate (`enforce_for_request`) stays inert with an empty
/// map. The named-caller refusal for this posture lives in the authority
/// funnel since #9341 B-1 (3-agent vote (71472661)) and is pinned route by
/// route in `tests/http_idor_closure_2125_2096.rs`
/// `zero_enrollment_enforce_refuses_named_and_serves_anonymous_on_every_route_9341`.
#[test]
fn an_empty_enrolled_map_keeps_the_per_handler_gate_inert_3155() {
    let enrolled = ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty();
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
    let mut seed: HashMap<String, String> = HashMap::new();
    // sha256 of some other agent's enrolled token -> that agent. The caller
    // below presents nothing that hashes to it, so it stays `Claimed`.
    seed.insert("0".repeat(64), "someone-else".to_string());
    let enrolled = ai_memory::handlers::identity_binding::EnrolledAgentKeys::from_map(seed);

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
