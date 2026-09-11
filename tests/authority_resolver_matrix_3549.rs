// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3549 — the resolver's DENIED / ALLOWED matrix, cell by cell, over
//! `identity::authority::Authority::{resolve_mcp_in, resolve_http}` and the pure
//! `http_admin_binding_admitted` arm. Lives under `tests/` (not in the crate)
//! because the MCP cells steer the caller principal through the #3523
//! thread-local seam, which `src/` may never arm.

use ai_memory::config::HttpIdentityMode;
use ai_memory::identity::authority::{
    Admin, Authority, AuthorityError, Binding, HttpAuthorityInputs, Surface,
    http_admin_binding_admitted,
};
use ai_memory::identity::test_agent_id::AgentIdOverride;
const CALLER: &str = "ai:alice";
const ADMIN: &str = "ai:operator";

fn allow(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|s| (*s).to_string()).collect()
}

fn http(
    header: Option<&'static str>,
    key_bound: Option<&'static str>,
    mode: HttpIdentityMode,
    keys: bool,
    allowlist: &[String],
    trusted: bool,
) -> Result<Authority, AuthorityError> {
    Authority::resolve_http(HttpAuthorityInputs {
        header_agent_id: header,
        key_bound_principal: key_bound,
        identity_mode: mode,
        enrolled_keys_present: keys,
        admin_allowlist: allowlist,
        header_trusted: trusted,
    })
}

// ----- MCP stdio matrix ------------------------------------------------

/// ALLOWED — configured identity: `Env` binding, reads enforced.
#[test]
fn mcp_configured_identity_binds_env_and_enforces_reads_3549() {
    let _seam = AgentIdOverride::set(CALLER);
    let a = Authority::resolve_mcp_in(None, &[]).expect("resolves");
    assert_eq!(a.surface(), Surface::McpStdio);
    assert_eq!(a.principal(), CALLER);
    assert_eq!(a.binding(), Binding::Env);
    assert_eq!(a.read_caller(), Some(CALLER));
    assert_eq!(a.admin(), Admin::None);
    assert!(!a.is_anonymous());
}

/// ALLOWED — no configured identity: the single trust domain (F13).
/// Writes carry a durable stamp; reads are trust-all.
#[test]
fn mcp_unset_identity_is_the_local_operator_trust_domain_3549() {
    let _seam = AgentIdOverride::unset();
    let a = Authority::resolve_mcp_in(Some("claude-code"), &[]).expect("resolves");
    assert_eq!(a.binding(), Binding::LocalOperator);
    assert_eq!(a.read_caller(), None, "F13: trust-all reads when unset");
    assert!(!a.principal().is_empty());
    assert!(
        ai_memory::validate::validate_agent_id_shape(a.principal()).is_ok(),
        "the durable stamp is a valid owner id: {}",
        a.principal()
    );
    assert!(a.principal().starts_with("ai:claude-code@") || a.principal().starts_with("host:"));
}

/// DENIED — an EMPTY configured identity is configuration, not absence.
#[test]
fn mcp_empty_configured_identity_is_refused_3549() {
    let _seam = AgentIdOverride::set("");
    let err = Authority::resolve_mcp_in(None, &[]).expect_err("must refuse");
    assert!(matches!(err, AuthorityError::ConfiguredIdentityInvalid(_)));
    assert!(err.to_string().contains("AI_MEMORY_AGENT_ID"), "{err}");
}

/// DENIED — a shape-invalid configured identity is refused, never
/// collapsed into the trust-all posture.
#[test]
fn mcp_malformed_configured_identity_is_refused_3549() {
    let _seam = AgentIdOverride::set("bad id with spaces");
    let err = Authority::resolve_mcp_in(None, &[]).expect_err("must refuse");
    assert!(matches!(err, AuthorityError::ConfiguredIdentityInvalid(_)));
}

/// ALLOWED (admin) — the configured identity is on the allowlist.
#[test]
fn mcp_allowlisted_configured_identity_is_enrolled_admin_3549() {
    let _seam = AgentIdOverride::set(ADMIN);
    let a = Authority::resolve_mcp_in(None, &allow(&[ADMIN])).expect("resolves");
    assert_eq!(a.admin(), Admin::Enrolled);
    assert!(a.is_admin());
}

/// DENIED (admin) — an empty allowlist admits nobody, even a configured
/// identity.
#[test]
fn mcp_empty_allowlist_admits_no_admin_3549() {
    let _seam = AgentIdOverride::set(ADMIN);
    let a = Authority::resolve_mcp_in(None, &[]).expect("resolves");
    assert_eq!(a.admin(), Admin::None);
}

// ----- HTTP matrix -----------------------------------------------------

/// ALLOWED — a valid asserted identity with the shared key is `Claimed`.
#[test]
fn http_asserted_identity_is_claimed_3549() {
    let a = http(
        Some(CALLER),
        None,
        HttpIdentityMode::Advisory,
        false,
        &[],
        true,
    )
    .expect("resolves");
    assert_eq!(a.surface(), Surface::Http);
    assert_eq!(a.principal(), CALLER);
    assert_eq!(a.binding(), Binding::Claimed);
    assert_eq!(a.read_caller(), Some(CALLER));
    assert_eq!(a.admin(), Admin::None);
}

/// ALLOWED — the presented per-agent key is enrolled for the asserted
/// identity: `ApiKey`.
#[test]
fn http_enrolled_per_agent_key_binds_api_key_3549() {
    let a = http(
        Some(CALLER),
        Some(CALLER),
        HttpIdentityMode::Enforce,
        true,
        &[],
        true,
    )
    .expect("resolves");
    assert_eq!(a.binding(), Binding::ApiKey);
    assert!(a.binding().is_key_bound());
}

/// A per-agent key enrolled for ANOTHER principal does not bind this
/// one (the middleware corrects / refuses the header first; the resolver
/// never upgrades on a mismatch).
#[test]
fn http_foreign_per_agent_key_does_not_bind_3549() {
    let a = http(
        Some(CALLER),
        Some("ai:bob"),
        HttpIdentityMode::Enforce,
        true,
        &[],
        true,
    )
    .expect("resolves");
    assert_eq!(a.binding(), Binding::Claimed);
}

/// ALLOWED — no asserted identity mints the per-request anonymous id:
/// reads as `Some(anonymous)` (sees only non-private rows), never admin.
#[test]
fn http_no_identity_is_anonymous_and_never_admin_3549() {
    let anon_allow = allow(&["anonymous:req-abcdef12"]);
    for header in [None, Some("")] {
        let a = http(
            header,
            None,
            HttpIdentityMode::Off,
            false,
            &anon_allow,
            true,
        )
        .expect("resolves");
        assert!(a.is_anonymous(), "{}", a.principal());
        assert!(
            a.principal()
                .starts_with(ai_memory::identity::sentinels::ANONYMOUS_REQ_PREFIX)
        );
        assert_eq!(a.read_caller(), Some(a.principal()));
        assert_eq!(a.binding(), Binding::Claimed);
        assert_eq!(a.admin(), Admin::None, "anonymous can never be admin");
    }
}

/// DENIED — a malformed asserted identity is refused, not anonymised.
#[test]
fn http_malformed_asserted_identity_is_refused_3549() {
    let err = http(
        Some("bad id with spaces"),
        None,
        HttpIdentityMode::Advisory,
        false,
        &[],
        true,
    )
    .expect_err("must refuse");
    assert!(matches!(err, AuthorityError::HeaderIdentityInvalid(_)));
    assert!(err.to_string().starts_with("invalid agent_id:"), "{err}");
}

/// DENIED — a RESERVED name (`daemon`) is refused with the #977 reason.
#[test]
fn http_reserved_asserted_identity_is_refused_3549() {
    let err = http(
        Some("daemon"),
        None,
        HttpIdentityMode::Advisory,
        false,
        &[],
        true,
    )
    .expect_err("must refuse");
    assert!(
        err.to_string().contains("reserved for internal use"),
        "{err}"
    );
}

/// ADMIN matrix — one rule: allowlisted AND header trusted AND the #2044
/// binding gate admits.
#[test]
fn http_admin_requires_allowlist_trust_and_binding_3549() {
    let admins = allow(&[ADMIN]);
    // ALLOWED: allowlisted + trusted + gate inert (no keys enrolled).
    let a = http(
        Some(ADMIN),
        None,
        HttpIdentityMode::Enforce,
        false,
        &admins,
        true,
    )
    .unwrap();
    assert_eq!(a.admin(), Admin::Enrolled);
    // DENIED: header not trusted (keyless deployment, hatch off — #1570).
    let a = http(
        Some(ADMIN),
        None,
        HttpIdentityMode::Off,
        false,
        &admins,
        false,
    )
    .unwrap();
    assert_eq!(a.admin(), Admin::None);
    // DENIED: enforce + keys enrolled + merely claimed (#2044 M1).
    let a = http(
        Some(ADMIN),
        None,
        HttpIdentityMode::Enforce,
        true,
        &admins,
        true,
    )
    .unwrap();
    assert_eq!(a.admin(), Admin::None);
    // ALLOWED: enforce + keys enrolled + key-bound to the admin id.
    let a = http(
        Some(ADMIN),
        Some(ADMIN),
        HttpIdentityMode::Enforce,
        true,
        &admins,
        true,
    )
    .unwrap();
    assert_eq!(a.admin(), Admin::Enrolled);
    // ALLOWED (advisory soak): keys enrolled, merely claimed, advisory.
    let a = http(
        Some(ADMIN),
        None,
        HttpIdentityMode::Advisory,
        true,
        &admins,
        true,
    )
    .unwrap();
    assert_eq!(a.admin(), Admin::Enrolled);
    // DENIED: not allowlisted at all.
    let a = http(
        Some(CALLER),
        Some(CALLER),
        HttpIdentityMode::Off,
        true,
        &admins,
        true,
    )
    .unwrap();
    assert_eq!(a.admin(), Admin::None);
}

/// The pure admission arm, cell by cell.
#[test]
fn http_admin_binding_admitted_matrix_3549() {
    use HttpIdentityMode as M;
    // Inert without enrolled keys, in every mode and binding.
    for mode in [M::Off, M::Advisory, M::Enforce] {
        assert!(http_admin_binding_admitted(mode, Binding::Claimed, false));
    }
    // Key-bound always admits.
    assert!(http_admin_binding_admitted(
        M::Enforce,
        Binding::ApiKey,
        true
    ));
    assert!(http_admin_binding_admitted(
        M::Enforce,
        Binding::Attested,
        true
    ));
    // Claimed under keys: off/advisory admit, enforce refuses.
    assert!(http_admin_binding_admitted(M::Off, Binding::Claimed, true));
    assert!(http_admin_binding_admitted(
        M::Advisory,
        Binding::Claimed,
        true
    ));
    assert!(!http_admin_binding_admitted(
        M::Enforce,
        Binding::Claimed,
        true
    ));
}

/// The wire tags are stable (audit surfaces key on them).
#[test]
fn tags_are_stable_3549() {
    assert_eq!(Surface::McpStdio.as_str(), "mcp_stdio");
    assert_eq!(Surface::Http.as_str(), "http");
    assert_eq!(Binding::Env.as_str(), "env");
    assert_eq!(Binding::LocalOperator.as_str(), "local_operator");
    assert_eq!(Binding::Claimed.as_str(), "claimed");
    assert_eq!(Binding::ApiKey.as_str(), "api_key");
    assert_eq!(Binding::Attested.as_str(), "attested");
}
