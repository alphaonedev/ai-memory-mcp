// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7791 — regression: the docs in `src/wake_hub/identity.rs` must say that
//! `DenyAllVerifier` is the live no-allowlist fallback (posture `deny-all`,
//! `src/cli/wake_hub.rs`) as well as the test fallback, and must not call it
//! only "the test fallback".

/// The phrase that wrongly narrowed the verifier to tests.
const STALE_PHRASE: &str = "test fallback";

/// The phrase that names the live no-allowlist case.
const LIVE_PHRASE: &str = "no allowlist";

/// The verifier the live phrase must be attached to.
const FALLBACK_VERIFIER: &str = "DenyAllVerifier";

/// The doc paragraphs of `src/wake_hub/identity.rs`, each collapsed to one
/// line with the `//!` / `///` prefixes stripped and whitespace squeezed.
fn doc_paragraphs() -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/wake_hub/identity.rs");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "src/wake_hub/identity.rs must exist ({}): {e}",
            path.display()
        )
    });
    let mut paragraphs = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let body = trimmed
            .strip_prefix("//!")
            .or_else(|| trimmed.strip_prefix("///"));
        match body {
            Some(b) if !b.trim().is_empty() => current.push(b),
            _ => {
                if !current.is_empty() {
                    paragraphs.push(current.join(" "));
                    current.clear();
                }
            }
        }
    }
    if !current.is_empty() {
        paragraphs.push(current.join(" "));
    }
    paragraphs
        .into_iter()
        .map(|p| p.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

#[test]
fn identity_docs_name_the_no_allowlist_fallback_not_only_tests_7791() {
    let paragraphs = doc_paragraphs();
    for p in &paragraphs {
        assert!(
            !p.contains(STALE_PHRASE),
            "src/wake_hub/identity.rs still calls the verifier only a {STALE_PHRASE:?}: {p}"
        );
    }
    let naming = paragraphs
        .iter()
        .filter(|p| p.contains(FALLBACK_VERIFIER) && p.contains(LIVE_PHRASE))
        .count();
    assert!(
        naming >= 1,
        "src/wake_hub/identity.rs must name {FALLBACK_VERIFIER} as the {LIVE_PHRASE:?} fallback in one paragraph"
    );
    let posture = paragraphs
        .iter()
        .any(|p| p.contains(FALLBACK_VERIFIER) && p.contains("deny-all"));
    assert!(
        posture,
        "src/wake_hub/identity.rs must tie {FALLBACK_VERIFIER} to the `deny-all` posture"
    );
}

/// #7784 review r3 LOW-B: the `IdentityNotConfigured` refusal text is logged
/// only when the scoped verifier is NOT wired (no allowlist, posture
/// `deny-all`), so it must not claim that the live hub wires it.
#[test]
fn identity_not_configured_text_names_the_deny_all_posture_7791() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/wake_hub/identity.rs");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "src/wake_hub/identity.rs must exist ({}): {e}",
            path.display()
        )
    });
    // Join the string-literal `\` line continuations before collapsing.
    let mut joined = String::new();
    let mut skip_leading = false;
    for line in text.lines() {
        let piece = if skip_leading {
            line.trim_start()
        } else {
            line
        };
        if let Some(head) = piece.strip_suffix('\\') {
            joined.push_str(head);
            skip_leading = true;
        } else {
            joined.push_str(piece);
            joined.push('\n');
            skip_leading = false;
        }
    }
    let collapsed = joined
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("[ ", "[")
        .replace(" ]", "]");
    assert!(
        !collapsed.contains("live hub wires the scoped"),
        "src/wake_hub/identity.rs IdentityNotConfigured text still claims the live hub wires the scoped verifier"
    );
    for needle in [
        "posture deny-all",
        "until an allowlist arms the scoped a2a-hub/join/v1 delegation verifier",
    ] {
        assert!(
            collapsed.contains(needle),
            "src/wake_hub/identity.rs IdentityNotConfigured text must contain {needle:?}"
        );
    }
}
