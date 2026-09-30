// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4083 — the module docs match the enforced SSRF policy and signing contract.

use super::*;

/// The `//!` module documentation of this file, joined.
fn module_docs_4083() -> String {
    include_str!("../subscriptions.rs")
        .lines()
        .take_while(|l| l.starts_with("//") || l.is_empty())
        .filter_map(|l| l.strip_prefix("//!"))
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// #4083 — the module docs are the receiver-facing signing contract. A
/// receiver that follows them must compute the bytes the dispatcher
/// signs. This test implements the DOCUMENTED recipe independently (the
/// `hmac` + `sha2` crates, not the in-tree signer) and checks it against
/// the shipped conformance vector, then pins the load-bearing phrases of
/// the docs so a regression back to "over the raw JSON body" goes red.
#[test]
fn documented_signature_recipe_verifies_the_shipped_vector_4083() {
    use hmac::{Hmac, Mac};
    let fx: serde_json::Value =
        serde_json::from_str(include_str!("../../sdk/fixtures/webhook_hmac_vector.json"))
            .expect("webhook fixture is valid JSON");
    let f = |k: &str| fx[k].as_str().expect("fixture field is a string");
    // key = the 32-byte SHA-256 digest of the plaintext secret.
    let key = Sha256::digest(f("secret").as_bytes());
    // message = "<timestamp>.<body>".
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("hmac accepts any key length");
    mac.update(f("timestamp").as_bytes());
    mac.update(b".");
    mac.update(f("body").as_bytes());
    let hex: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(format!("sha256={hex}"), f("signature_header"));
    // The body-only recipe the pre-#4083 docs described does NOT verify.
    let mut body_only = Hmac::<Sha256>::new_from_slice(&key).expect("hmac key");
    body_only.update(f("body").as_bytes());
    let body_only_hex: String = body_only
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_ne!(format!("sha256={body_only_hex}"), f("signature_header"));

    let docs = module_docs_4083();
    assert!(
        docs.contains("\"<timestamp>.<body>\"") && docs.contains("X-Ai-Memory-Timestamp"),
        "#4083: the module docs must state the canonical signed bytes"
    );
    assert!(
        !docs.contains("over the raw JSON body"),
        "#4083: the module docs must not claim a body-only signature"
    );
}

/// #4083 — the docs must describe the private-address policy the code
/// enforces: no private-network override exists, only a loopback opt-in.
/// The behavioural half: a private literal is refused even with the
/// loopback opt-in on, at registration and at dispatch.
#[test]
fn documented_private_network_policy_matches_the_guards_4083() {
    let docs = module_docs_4083();
    assert!(
        !docs.contains("allow_private_networks"),
        "#4083: the docs must not advertise a private-network override"
    );
    assert!(
        docs.contains("refused UNCONDITIONALLY"),
        "#4083: the docs must say private targets are refused unconditionally"
    );
    assert!(docs.contains("allow_loopback_webhooks"));
    for url in [
        "https://10.0.0.1/h",
        "https://192.168.1.1/h",
        "https://[fd00::1]/h",
    ] {
        assert!(validate_url_with(url, true).is_err(), "{url} registration");
        assert!(validate_url_dns_with(url, true).is_err(), "{url} dispatch");
    }
}
