// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #977 — wire-side reserved-agent-id reject regression test.
//!
//! Pre-#977 a wire caller setting `X-Agent-Id: daemon` (or the same via
//! MCP-tool `agent_id` field, or HTTP body `agent_id` field) passed
//! [`ai_memory::validate::validate_agent_id`] and reached
//! `CallerContext.principal == "daemon"`. Nine downstream cross-tenant
//! ownership gates carve out `caller == "daemon"` as the internal-admin
//! path (`src/handlers/parity.rs::require_caller_owns_memory`,
//! `src/handlers/links.rs`, `src/handlers/kg.rs`,
//! `src/handlers/hook_subscribers.rs`, `src/mcp/tools/namespace.rs`), so
//! the wire caller could spoof the internal sentinel and bypass every
//! such gate — a critical cross-tenant write authorisation bypass.
//!
//! Sister `"system"` sentinel: `src/handlers/hook_subscribers.rs:412`,
//! `:577`, `:699` treat `recorded_owner == "system"` as legacy-unowned,
//! and the unowned-claim rewrite branch lets the claiming caller silently
//! own the row. A wire spoof of `X-Agent-Id: system` exploited the same
//! shape.
//!
//! Both are closed via the [`validate_agent_id`] reserved-name reject;
//! this file pins:
//!
//! 1. Every reserved name is rejected by the validator.
//! 2. The error message cites the reserved-name reason (so log-triage
//!    can distinguish from generic shape rejections).
//! 3. [`resolve_http_agent_id`] surfaces the validator error for both
//!    the `X-Agent-Id` header path AND the body-refinement path.
//! 4. Sibling forms that share a SUBSTRING with reserved names (e.g.
//!    `"daemon-1"`, `"ai:daemon-impostor"`, `"system-admin"`) continue
//!    to pass — the reject is exact-string only.
//! 5. Internal `CallerContext::for_admin(...)` constructions still
//!    succeed — they bypass the validator by design.

use ai_memory::identity::resolve_http_agent_id;
#[cfg(feature = "sal")]
use ai_memory::store::CallerContext;
use ai_memory::validate::validate_agent_id;

const RESERVED_NAMES: &[&str] = &[
    "daemon",
    "system",
    "federation-catchup",
    "subscription-dispatch",
    "ai:http-internal",
    "ai:migrate",
    "export-internal",
    "governance-internal",
];

#[test]
fn validator_rejects_every_reserved_name_977() {
    for &reserved in RESERVED_NAMES {
        let r = validate_agent_id(reserved);
        assert!(
            r.is_err(),
            "validate_agent_id({reserved:?}) MUST be Err per #977",
        );
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains("reserved for internal use"),
            "reserved-name reject must surface the dedicated reason for triage; got: {msg}",
        );
    }
}

#[test]
fn http_header_spoof_of_daemon_is_rejected_977() {
    // The pre-#977 bypass: `X-Agent-Id: daemon` → resolver accepts →
    // CallerContext.principal == "daemon" → every cross-tenant ownership
    // gate's `caller == "daemon"` carve-out fires → caller bypasses
    // ownership checks.
    let r = resolve_http_agent_id(None, Some("daemon"));
    assert!(
        r.is_err(),
        "resolve_http_agent_id MUST reject X-Agent-Id: daemon per #977",
    );
    let msg = r.unwrap_err().to_string();
    assert!(
        msg.contains("reserved for internal use"),
        "header reject must surface reserved-name reason; got: {msg}",
    );
}

#[test]
fn http_header_spoof_of_system_is_rejected_977() {
    // The sister bypass: `X-Agent-Id: system` → resolver accepts →
    // hook_subscribers unowned-claim rewrite branch lets the caller
    // silently claim ownership of legacy-unowned rows.
    let r = resolve_http_agent_id(None, Some("system"));
    assert!(
        r.is_err(),
        "resolve_http_agent_id MUST reject X-Agent-Id: system per #977",
    );
}

#[test]
fn http_body_spoof_of_every_reserved_name_is_rejected_977() {
    // Defence-in-depth: even with no header (anonymous fallback path),
    // a body-supplied `agent_id` claim of a reserved name MUST be
    // rejected. The body path is the federation receiver's entry point
    // when `AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1`.
    for &reserved in RESERVED_NAMES {
        let r = resolve_http_agent_id(Some(reserved), None);
        assert!(
            r.is_err(),
            "resolve_http_agent_id(body={reserved:?}, header=None) MUST be Err per #977",
        );
    }
}

#[test]
fn http_body_and_header_both_reserved_is_rejected_977() {
    // Belt-and-suspenders: even if both body and header agree on a
    // reserved name, the resolver MUST reject — the validator runs
    // on both arms before the mismatch check.
    for &reserved in RESERVED_NAMES {
        let r = resolve_http_agent_id(Some(reserved), Some(reserved));
        assert!(
            r.is_err(),
            "resolve_http_agent_id(body={reserved:?}, header={reserved:?}) MUST be Err per #977",
        );
    }
}

#[test]
fn sibling_forms_sharing_substring_with_reserved_still_pass_977() {
    // Operators sometimes use distinctive prefixes/suffixes that share
    // a substring with a reserved name. The reject is exact-string
    // only; these MUST continue to pass.
    let legitimate = [
        "daemon-1",
        "system-admin",
        "ai:daemon-impostor",
        "federation-catchup-v2",
        "subscription-dispatch-replica",
        "ai:http-internal-shadow",
        "export-internal-tester",
        "governance-internal-audit",
        "host:daemon",              // colon-prefixed
        "spiffe://daemon.example/", // SPIFFE-style
    ];
    for id in legitimate {
        assert!(
            validate_agent_id(id).is_ok(),
            "sibling form '{id}' that shares a substring with a reserved name MUST still pass after #977",
        );
        // The resolver path agrees with the validator.
        assert!(
            resolve_http_agent_id(None, Some(id)).is_ok(),
            "resolve_http_agent_id(header={id:?}) MUST still accept the sibling form after #977",
        );
    }
}

#[cfg(feature = "sal")]
#[test]
fn internal_for_admin_constructions_still_work_977() {
    // Internal callers construct CallerContext directly via
    // for_admin(...) — they bypass the validator by design. This is
    // the load-bearing property that makes the wire-side reject safe:
    // closing the spoof on the wire does NOT close the legitimate
    // internal path that uses the same string sentinels.
    //
    // Gated on `feature = "sal"` because `CallerContext` lives in the
    // SAL boundary module (`ai_memory::store`).
    for &reserved in RESERVED_NAMES {
        let ctx = CallerContext::for_admin(reserved);
        // The agent_id lands verbatim — for_admin does not validate.
        assert_eq!(
            ctx.agent_id, reserved,
            "for_admin({reserved:?}) MUST still construct a CallerContext with the literal \
             agent_id — this is the internal path the gates carve out",
        );
        // The admin-bypass posture is set so downstream gates know
        // this is the legitimate internal path.
        assert!(
            ctx.bypass_visibility,
            "for_admin({reserved:?}) MUST set bypass_visibility=true",
        );
    }
}
