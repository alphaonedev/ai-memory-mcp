// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Red guard for `CodeQL` `rust/cleartext-logging` assertion-message leaks in
//! `#[cfg(test)]` modules of `src/` files (#6588, #6589, #6591, #6592, #6606;
//! same defect class as #6098, refs #6163 #6351).
//!
//! Each alerted assertion keeps its condition; only the failure message must
//! stop interpolating the value `CodeQL` tracks as sensitive. This guard reads
//! the source text, locates the named test function inside the file's
//! `#[cfg(test)]` region, and fails while that function body still carries a
//! forbidden interpolation.

use std::path::Path;

/// Read a repo source file relative to the crate root.
fn read_src(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Body of test fn `name` in `rel`: from its `fn name(` signature up to the
/// next `#[test]` attribute (or end of file). The signature must sit after the
/// first `#[cfg(test)]` so a production fn of the same name never satisfies it.
fn test_fn_body(rel: &str, name: &str) -> String {
    let src = read_src(rel);
    let cfg_test = src
        .find("#[cfg(test)]")
        .unwrap_or_else(|| panic!("{rel}: no #[cfg(test)] region"));
    let sig = format!("fn {name}(");
    let start = src[cfg_test..].find(&sig).map_or_else(
        || panic!("{rel}: test fn `{name}` not found in #[cfg(test)] region"),
        |off| cfg_test + off,
    );
    let rest = &src[start..];
    let end = rest.find("#[test]").unwrap_or(rest.len());
    rest[..end].to_string()
}

/// Fail with a list of `(file, fn, forbidden)` cells whose body still carries
/// the forbidden interpolation.
fn assert_cells_clean(cells: &[(&str, &str, &str)]) {
    let leaking: Vec<String> = cells
        .iter()
        .filter(|(rel, name, forbidden)| test_fn_body(rel, name).contains(forbidden))
        .map(|(rel, name, forbidden)| format!("{rel}::{name} still interpolates `{forbidden}`"))
        .collect();
    assert!(
        leaking.is_empty(),
        "cleartext assertion-message sites remain:\n  {}",
        leaking.join("\n  ")
    );
}

/// #6588 — alerts 128/129/130: the token Debug-rendering test must not echo
/// the rendering it asserts is redacted.
#[test]
fn capability_token_debug_messages_6588() {
    assert_cells_clean(&[(
        "src/governance/capability.rs",
        "token_debug_redacts_bearer_bytes",
        "{rendered}",
    )]);
}

/// #6589 — alert 179: the per-alias env-var preference test must not echo the
/// returned / expected env-var name lists.
#[test]
fn llm_alias_env_var_messages_6589() {
    assert_cells_clean(&[
        (
            "src/llm.rs",
            "alias_api_key_env_vars_per_alias_pins_1067",
            "{got:?}",
        ),
        (
            "src/llm.rs",
            "alias_api_key_env_vars_per_alias_pins_1067",
            "{expected:?}",
        ),
    ]);
}

/// #6591 — alert 133: the owner-clear result must not be Debug-dumped.
#[test]
fn namespace_owner_clear_messages_6591() {
    assert_cells_clean(&[(
        "src/mcp/tools/namespace.rs",
        "clear_standard_owner_gate_1777",
        "{ok:?}",
    )]);
}

/// #6592 — alerts 148/149/150/151: verifier results and the parsed cert count
/// must not reach the assertion messages.
#[test]
fn tls_verifier_messages_6592() {
    assert_cells_clean(&[
        ("src/tls.rs", "test_pem_iter_certs_chain", "got {}"),
        (
            "src/tls.rs",
            "test_verifier_accepts_allowlisted_fp",
            "{result:?}",
        ),
        (
            "src/tls.rs",
            "pin_verifier_accepts_matching_fingerprint",
            "{res:?}",
        ),
        (
            "src/tls.rs",
            "pin_verifier_acceptany_policy_passes_unpinned_host",
            "{res:?}",
        ),
    ]);
}

/// #6606 — alert 131: the anonymous HTTP fallback id must not be echoed.
#[test]
fn identity_anonymous_req_messages_6606() {
    assert_cells_clean(&[(
        "src/identity/mod.rs",
        "resolve_http_fallback_is_anonymous_req",
        "{id}",
    )]);
}
