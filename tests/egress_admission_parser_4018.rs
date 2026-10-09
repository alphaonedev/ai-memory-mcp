// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4018 (WP-EGRESS #6053) — the inference-egress admission gate reads the
//! target host with the SAME parser the HTTP client connects with.
//!
//! The admission check (`loopback-only` / `internal-only`) extracted the host
//! from the configured base URL with a hand-rolled authority parser; the
//! request is then built and sent by reqwest, whose WHATWG `url::Url` parser
//! can name a DIFFERENT host for the same string. The hand-rolled parser
//! bounded the authority at the first `/`, `?` or `#` and took the text after
//! the LAST `@`; `url::Url` also ends the authority of a special scheme at a
//! BACKSLASH. So for `https://evil.example\@127.0.0.1/v1` the gate admitted
//! `127.0.0.1` (loopback) while reqwest connected to `evil.example`: memory
//! content left the host with the gate reporting compliance.
//!
//! Invariant pinned here, on every shape of the table: the admitted host
//! EQUALS the host `reqwest::Url` would connect to, or the URL is REFUSED.
//! Each adversarial row has a presence control (the same host spelled
//! unambiguously is admitted), so a green cannot come from a gate that
//! refuses everything.

use ai_memory::egress::{
    EgressClass, EgressDecision, InferenceEgressMode, admit_inference_target, admitted_host,
    evaluate_inference_egress, target_is_loopback,
};

/// The host reqwest will connect to for `url` (the client's own parser).
fn client_host(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
}

/// Shapes where the pre-fix authority parser and `url::Url` disagree. The
/// second element is the host the CLIENT contacts.
const DISAGREEING: &[(&str, &str)] = &[
    // backslash ends the authority for a special scheme: the "userinfo" is
    // the real host, the "host" is path text.
    ("https://evil.example\\@127.0.0.1/v1", "evil.example"),
    ("https://evil.example\\@10.0.0.1/v1", "evil.example"),
    ("https://evil.example\\@localhost/v1", "evil.example"),
    // the mirror image: the real host is an attacker name, the "host" the
    // hand-rolled parser read was the loopback literal in the path.
    ("https://evil.example\\127.0.0.1/v1", "evil.example"),
];

#[test]
fn loopback_only_refuses_every_shape_whose_client_host_is_not_loopback_4018() {
    for (url, contacted) in DISAGREEING {
        assert_eq!(
            client_host(url).as_deref(),
            Some(*contacted),
            "fixture: reqwest parses {url} to host {contacted}"
        );
        assert!(
            !target_is_loopback(url),
            "#4018: {url} is contacted at {contacted}, which is not loopback — the \
             loopback predicate must read the client's host"
        );
        let d = evaluate_inference_egress(
            InferenceEgressMode::LoopbackOnly,
            EgressClass::InferenceLlm,
            url,
        );
        assert!(
            d.is_refused(),
            "#4018: loopback-only must refuse {url}: reqwest contacts {contacted}; got {d:?}"
        );
    }
    // presence control: the loopback host spelled unambiguously is admitted.
    assert_eq!(
        evaluate_inference_egress(
            InferenceEgressMode::LoopbackOnly,
            EgressClass::InferenceLlm,
            "https://127.0.0.1/v1",
        ),
        EgressDecision::Allow
    );
}

#[test]
fn internal_only_admitted_host_is_the_client_host_or_refused_4018() {
    for (url, contacted) in DISAGREEING {
        match admit_inference_target(
            InferenceEgressMode::InternalOnly,
            EgressClass::InferenceLlm,
            url,
        ) {
            // Refused (fail closed) — acceptable: nothing is contacted.
            Err(_) => {}
            // Admitted — then the pinned host MUST be what reqwest contacts.
            Ok(Some(pin)) => assert_eq!(
                pin.host.to_ascii_lowercase(),
                *contacted,
                "#4018: {url} admitted a host reqwest never connects to"
            ),
            Ok(None) => panic!("internal-only always pins on admit: {url}"),
        }
    }
    // presence control: an unambiguous loopback literal is admitted AND pinned
    // on the host reqwest contacts.
    let pin = admit_inference_target(
        InferenceEgressMode::InternalOnly,
        EgressClass::InferenceLlm,
        "https://127.0.0.1:9/v1",
    )
    .expect("loopback literal is internal")
    .expect("internal-only pins");
    assert_eq!(pin.host, "127.0.0.1");
    assert_eq!(
        client_host("https://127.0.0.1:9/v1").as_deref(),
        Some("127.0.0.1")
    );
}

#[test]
fn admitted_host_is_the_client_host_for_every_shape_4018() {
    // The exported predicate the gate reads its host through equals the
    // client's host (bracket-stripped for IPv6, the `resolve_to_addrs` key)
    // on the adversarial table AND on ordinary shapes.
    for (url, contacted) in DISAGREEING {
        assert_eq!(admitted_host(url).as_deref(), Some(*contacted), "{url}");
    }
    for (url, host) in [
        ("https://api.openai.com/v1", "api.openai.com"),
        ("https://svc:pw@API.Example:8443/v1?k=v#f", "api.example"),
        ("http://[::1]:11434", "::1"),
        ("http://127.0.0.1:11434/", "127.0.0.1"),
    ] {
        assert_eq!(admitted_host(url).as_deref(), Some(host), "{url}");
    }
    for url in ["localhost:11434", "ftp://127.0.0.1/v1", "", "https://"] {
        assert_eq!(
            admitted_host(url),
            None,
            "{url}: no http(s) host to agree on"
        );
    }
}

#[test]
fn scheme_less_and_non_http_targets_are_not_loopback_4018() {
    // reqwest refuses to send to a scheme-less or non-http(s) URL at all, so
    // the gate must not admit what the client can never contact (fail
    // closed): there is no host to agree on.
    for url in ["localhost:11434", "ftp://127.0.0.1/v1", "127.0.0.1:11434"] {
        assert!(
            !target_is_loopback(url),
            "#4018: {url} has no http(s) host reqwest would contact — not loopback"
        );
        assert!(
            evaluate_inference_egress(
                InferenceEgressMode::LoopbackOnly,
                EgressClass::InferenceLlm,
                url
            )
            .is_refused(),
            "#4018: loopback-only must refuse {url}"
        );
    }
    // presence controls: the same targets with an http(s) scheme ARE loopback.
    for url in ["http://localhost:11434", "http://127.0.0.1:11434"] {
        assert!(target_is_loopback(url), "control: {url} is loopback");
    }
}
