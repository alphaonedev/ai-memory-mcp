// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3578: the hub authority domain is not a wire caller identity.
//!
//! These shared-resolver pins cover HTTP header/body claims and MCP explicit
//! claims in both caller postures. They do not stand in for the lane's handler
//! credential and backend zero-mutation tests. TEST-02: each refused boundary
//! has an allowed ordinary-principal control; no process environment mutation.

use ai_memory::identity::{
    hub_delegation::A2A_HUB_SCOPE, resolve_agent_id, resolve_governance_subject,
    resolve_http_agent_id, test_agent_id::AgentIdOverride,
};
use ai_memory::validate::{RESERVED_AGENT_IDS, validate_agent_id, validate_agent_id_shape};

const HUB_CLAIMS: &[&str] = &[
    A2A_HUB_SCOPE,
    "a2a-hub/",
    "a2a-hub/join/v1",
    "a2a-hub/other/future-scope",
    "a2a-hub//join",
];
const CALLER: &str = "ai:alice";

#[test]
fn hub_domain_is_reserved_at_wire_boundary_3578() {
    assert!(RESERVED_AGENT_IDS.contains(&A2A_HUB_SCOPE));
    for &claim in HUB_CLAIMS {
        // The refusal must be the authority-domain reservation, not an
        // accidental shape rejection; internal shape-only callers still work.
        validate_agent_id_shape(claim).expect("valid shape");
        let err = validate_agent_id(claim).expect_err("hub domain is not a principal");
        assert!(err.to_string().contains("reserved for internal use"));
    }
    validate_agent_id(CALLER).expect("ordinary principal");
}

#[test]
fn hub_reservation_does_not_expand_to_substring_matches_3578() {
    for principal in [
        CALLER,
        "a2a-hub-agent",
        "a2a-hub2/join/v1",
        "ai:a2a-hub",
        "team/a2a-hub/join/v1",
        "spiffe://a2a-hub.example/agent",
        "daemon/agent",
    ] {
        validate_agent_id(principal).expect("ordinary grammar unchanged");
        assert_eq!(
            resolve_http_agent_id(Some(principal), Some(principal)).expect("matching caller"),
            principal
        );
    }
}

#[test]
fn http_refuses_hub_domain_in_header_and_body_3578() {
    for &claim in HUB_CLAIMS {
        for (body, header) in [
            (None, Some(claim)),
            (Some(claim), None),
            (Some(claim), Some(claim)),
            (Some(claim), Some(CALLER)),
            (Some(CALLER), Some(claim)),
        ] {
            let err = resolve_http_agent_id(body, header).expect_err("hub domain refused");
            assert!(err.to_string().contains("reserved for internal use"));
        }
    }
    assert_eq!(
        resolve_http_agent_id(Some(CALLER), Some(CALLER)).expect("ordinary caller"),
        CALLER
    );
}

#[test]
fn http_body_claim_cannot_replace_independent_caller_3578() {
    let err = resolve_http_agent_id(Some("ai:forged"), Some(CALLER))
        .expect_err("body cannot replace the header caller");
    assert!(err.to_string().contains("agent_id_body_header_mismatch"));
    assert_eq!(
        resolve_http_agent_id(None, Some(CALLER)).expect("header caller"),
        CALLER
    );
}

#[test]
fn mcp_refuses_explicit_hub_domain_without_enforced_caller_3578() {
    let _caller = AgentIdOverride::unset();
    for &claim in HUB_CLAIMS {
        for result in [
            resolve_agent_id(Some(claim), None),
            resolve_governance_subject(Some(claim), None, "notify"),
        ] {
            let err = result.expect_err("hub domain refused in single-operator posture");
            assert!(err.to_string().contains("reserved for internal use"));
        }
    }
    assert_eq!(
        resolve_governance_subject(Some(CALLER), None, "notify").expect("explicit caller"),
        CALLER
    );
}

#[test]
fn mcp_refuses_explicit_hub_domain_with_enforced_caller_3578() {
    let _caller = AgentIdOverride::set(CALLER);
    for &claim in HUB_CLAIMS {
        let err = resolve_governance_subject(Some(claim), None, "notify")
            .expect_err("hub domain refused before caller comparison");
        assert!(err.to_string().contains("reserved for internal use"));
    }
    for explicit in [None, Some(CALLER)] {
        assert_eq!(
            resolve_governance_subject(explicit, None, "notify").expect("independent caller"),
            CALLER
        );
    }
    let err = resolve_governance_subject(Some("ai:forged"), None, "notify")
        .expect_err("explicit claim cannot replace the caller");
    assert!(err.to_string().contains("agent_id mismatch"));
}

#[test]
fn mcp_explicit_hub_domain_is_refused_even_when_operator_value_agrees_3578() {
    // The existing internal-bootstrap shape-only env path is distinct from
    // the wire boundary. Agreement with it must not waive wire validation.
    for &claim in HUB_CLAIMS {
        let _caller = AgentIdOverride::set(claim);
        let err = resolve_governance_subject(Some(claim), None, "notify")
            .expect_err("matching operator value cannot bless a wire hub claim");
        assert!(err.to_string().contains("reserved for internal use"));
    }
}
