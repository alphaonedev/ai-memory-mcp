// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7786 — regression: the wake-hub docs in `src/lib.rs`, `src/wake_hub/mod.rs`
//! and `docs/reference/ARCHITECTURE_REFERENCE.md` must describe the live
//! identity state (the hub wires the scoped `a2a-hub/join/v1` delegation
//! verifier when an allowlist is configured; `DenyAllVerifier` is the fallback
//! otherwise and in tests, and the `HubDeps::default()` value), not the
//! pre-#3468 "refuses every hello until the delegation lands".

/// The stale clause the three sites carried before the fix.
const STALE_CLAUSE: &str = "lands in #3468";

/// The same clause with the issue number written as a markdown link.
const STALE_CLAUSE_LINKED: &str = "lands in [#3468]";

/// The fallback verifier both rustdoc sites must name.
const FALLBACK_VERIFIER: &str = "DenyAllVerifier";

/// Marker opening the crate-level `wake_hub` module doc paragraph.
const LIB_DOC_MARKER: &str = "Identity verification is a trait boundary";

/// Marker opening the `HubDeps` doc paragraph.
const HUBDEPS_DOC_MARKER: &str = "Both default to the";

fn read(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} must exist ({}): {e}", rel, path.display()))
}

/// The text from `marker` to the next blank doc line or item, joined on one line.
fn paragraph_after(text: &str, marker: &str) -> String {
    let at = text
        .find(marker)
        .unwrap_or_else(|| panic!("marker {marker:?} missing"));
    let mut out = String::new();
    for line in text[at..].lines() {
        let body = line.trim_start_matches('/').trim();
        if body.is_empty() || (!out.is_empty() && line.trim_start().starts_with("#[")) {
            break;
        }
        out.push_str(body);
        out.push(' ');
        if body.ends_with('.') {
            break;
        }
    }
    out
}

#[test]
fn no_site_says_the_delegation_lands_in_3468() {
    for rel in [
        "src/lib.rs",
        "src/wake_hub/mod.rs",
        "docs/reference/ARCHITECTURE_REFERENCE.md",
    ] {
        let text = read(rel);
        assert!(
            !text.contains(STALE_CLAUSE),
            "{rel} still contains the stale clause {STALE_CLAUSE:?}"
        );
        // A doc comment can wrap the clause across lines; collapse it first.
        let collapsed = text
            .lines()
            .map(|l| {
                l.trim_start()
                    .trim_start_matches('/')
                    .trim_start_matches('!')
            })
            .flat_map(str::split_whitespace)
            .collect::<Vec<_>>()
            .join(" ");
        let collapsed = collapsed.replace("[ ", "[");
        for stale in [STALE_CLAUSE, STALE_CLAUSE_LINKED] {
            assert!(
                !collapsed.contains(stale),
                "{rel} still contains the line-broken stale clause {stale:?}"
            );
        }
    }
}

#[test]
fn lib_wake_hub_doc_names_scoped_verifier_and_fallback() {
    let para = paragraph_after(&read("src/lib.rs"), LIB_DOC_MARKER);
    assert!(para.contains(FALLBACK_VERIFIER), "lib.rs doc: {para}");
    assert!(para.contains("scoped"), "lib.rs doc: {para}");
    assert!(para.contains("fallback"), "lib.rs doc: {para}");
}

#[test]
fn hubdeps_doc_names_scoped_verifier_and_fallback() {
    let para = paragraph_after(&read("src/wake_hub/mod.rs"), HUBDEPS_DOC_MARKER);
    assert!(para.contains(FALLBACK_VERIFIER), "HubDeps doc: {para}");
    assert!(para.contains("scoped"), "HubDeps doc: {para}");
    assert!(para.contains("fallback"), "HubDeps doc: {para}");
}
