// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3822 (5-agent vote 4d3ea1c5) — builder pin for the `internal-only`
//! inference-egress posture: the `InternalOnly` reqwest client MUST be built
//! with (a) `resolve_to_addrs` pinned to the admitted addresses, (b)
//! redirects DISABLED (`redirect::Policy::none()` — a redirect could reach
//! an un-pinned address), and (c) `.no_proxy()` (A3 — a pin binds an address
//! the daemon connects to directly; a proxy would defeat it).
//!
//! reqwest's `ClientBuilder` exposes NO config getters, so the builder
//! configuration cannot be read back off a built `Client`, and a behavioural
//! `no_proxy` proof would require setting `HTTP(S)_PROXY` in the environment
//! — which the #3822 pin contract forbids ("assert on the builder config,
//! not on env"; no `set_var`). This is therefore a SOURCE-STRUCTURAL pin
//! (the `record_stop_structural_b7` precedent): it asserts on the exact
//! builder-config code that IS the client's configuration.
//!
//! Load-bearing: the single composition point is
//! `OllamaClient::apply_internal_egress_pin`; every `*_pinned` constructor
//! routes through it (the two base constructors call it directly, the other
//! four delegate to those), so pinning the helper pins every `InternalOnly`
//! client. The specificity control asserts the NON-pinned constructors do
//! NOT carry the pin (it is unique to the `InternalOnly` path, not global).

use std::path::Path;

fn llm_src() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/llm.rs");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Extract the body of a `fn <name>(` … matching-brace region.
fn fn_body(src: &str, sig_prefix: &str) -> String {
    let start = src
        .find(sig_prefix)
        .unwrap_or_else(|| panic!("fn not found: {sig_prefix}"));
    // Find the opening brace of the body.
    let brace = src[start..]
        .find('{')
        .map(|i| start + i)
        .expect("fn body brace");
    let bytes = src.as_bytes();
    let mut depth = 0i32;
    let mut end = brace;
    for (i, &b) in bytes.iter().enumerate().skip(brace) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    src[brace..end].to_string()
}

#[test]
fn internal_egress_pin_builder_carries_resolve_none_redirect_and_no_proxy_3822() {
    let src = llm_src();
    let body = fn_body(&src, "fn apply_internal_egress_pin(");

    assert!(
        body.contains(".resolve_to_addrs("),
        "InternalOnly client must pin DNS via resolve_to_addrs; body:\n{body}"
    );
    assert!(
        body.contains(".redirect(reqwest::redirect::Policy::none())"),
        "InternalOnly client must DISABLE redirects (Policy::none); body:\n{body}"
    );
    assert!(
        body.contains(".no_proxy()"),
        "InternalOnly client must build with no_proxy (A3); body:\n{body}"
    );
}

#[test]
fn every_pinned_constructor_routes_through_the_pin_helper_3822() {
    let src = llm_src();
    // The two base constructors call the helper directly.
    for base in [
        "fn new_openai_compatible_pinned(",
        "fn new_with_url_no_health_check_pinned(",
    ] {
        let body = fn_body(&src, base);
        assert!(
            body.contains("apply_internal_egress_pin("),
            "{base} must apply the pin directly"
        );
    }
    // The remaining pinned constructors delegate to a base pinned ctor, so
    // the pin applies transitively. Assert each delegates to a `*_pinned`.
    for deleg in [
        "fn new_with_url_async_pinned(",
        "fn new_with_url_pinned(",
        "fn build_from_resolved_pinned(",
        "fn build_from_resolved_async_pinned(",
    ] {
        let body = fn_body(&src, deleg);
        assert!(
            body.contains("_pinned("),
            "{deleg} must delegate to a *_pinned constructor (transitive pin)"
        );
    }
}

#[test]
fn non_pinned_constructors_do_not_carry_the_pin_3822() {
    // Specificity control: the pin (no_proxy + Policy::none) is UNIQUE to the
    // InternalOnly path. The byte-identical-legacy non-pinned constructors
    // must NOT have gained it (a global no_proxy/none would change every
    // client, which #3822 does not do).
    let src = llm_src();
    for base in [
        "fn new_openai_compatible(",
        "fn new_with_url_no_health_check(",
    ] {
        let body = fn_body(&src, base);
        assert!(
            !body.contains(".no_proxy()"),
            "{base} (non-pinned) must NOT carry .no_proxy() — the pin is InternalOnly-only"
        );
    }
}
