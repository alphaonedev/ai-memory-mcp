// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Reserved caller-identity sentinels — the SSOT for every internal /
//! system principal string the substrate compares against, stamps on
//! rows, or carves out of cross-tenant ownership gates (#1558
//! identity-sentinel remediation).
//!
//! Scattering these as inline literals is a security hazard, not a
//! style nit: the cross-tenant ownership gates exempt callers whose
//! principal EQUALS one of these strings, so a one-character drift
//! between the site that CONSTRUCTS a privileged
//! [`crate::store::CallerContext`] and the gate that COMPARES against
//! it silently changes an authz decision. The wire-side rejection list
//! [`crate::validate::RESERVED_AGENT_IDS`] is built from these consts,
//! keeping the "reject wire callers claiming internal names" property
//! mechanically in sync with the construction sites.
//!
//! Note the deliberate distinction from
//! [`crate::identity::keypair::DAEMON_KEYPAIR_LABEL`]: that const is a
//! key-file LABEL (which file on disk holds the daemon's Ed25519
//! signing key); [`DAEMON_PRINCIPAL`] here is a CALLER IDENTITY. They
//! share the string `"daemon"` today but govern different mechanisms,
//! so each is named for its own semantic.

/// Privileged internal daemon principal. Internal admin/system paths
/// construct `CallerContext::for_admin(DAEMON_PRINCIPAL)` directly;
/// the cross-tenant ownership gates (`handlers/{parity,links,kg,
/// hook_subscribers}.rs`, `mcp/tools/namespace.rs`) exempt callers
/// with this exact principal.
pub const DAEMON_PRINCIPAL: &str = "daemon";

/// Resolve-failure sentinel: stamped as the caller when HTTP/MCP
/// agent-id resolution ERRORS (invalid header/param shape). Ownership
/// gates treat it as "not an owner of anything"; it must never match a
/// stored `metadata.agent_id`.
pub const ANONYMOUS_INVALID: &str = "anonymous:invalid";

/// Legacy unowned-marker / system principal stamped on legacy-rewrite
/// rows by `handlers/hook_subscribers.rs`; also matched as the
/// unowned-marker sentinel in cross-tenant gates.
pub const SYSTEM_PRINCIPAL: &str = "system";

/// Internal federation catch-up principal (`src/federation/receive.rs`).
pub const FEDERATION_CATCHUP: &str = "federation-catchup";

/// Internal subscription approval-dispatch principal
/// (`src/handlers/subscriptions.rs::dispatch_approval_requested`).
pub const SUBSCRIPTION_DISPATCH: &str = "subscription-dispatch";

/// Internal HTTP-daemon maintenance principal used by
/// `CallerContext::for_admin` paths in `handlers/{http,power,
/// hook_subscribers}.rs`.
pub const AI_HTTP_INTERNAL: &str = "ai:http-internal";

/// Internal store-migration principal (`src/migrate.rs`).
pub const AI_MIGRATE: &str = "ai:migrate";

/// Internal export-path principal (`src/store/postgres.rs::export_*`).
pub const EXPORT_INTERNAL: &str = "export-internal";

/// Internal governance-maintenance principal
/// (`src/store/postgres.rs::governance_*`).
pub const GOVERNANCE_INTERNAL: &str = "governance-internal";

/// Default agent id stamped by the HTTP daemon surface when acting as
/// itself (NOT a privileged carve-out — unlike [`AI_HTTP_INTERNAL`]).
pub const AI_HTTP: &str = "ai:http";

/// Agent id the curator daemon writes with.
pub const AI_CURATOR: &str = "ai:curator";

/// Prefix for per-request synthesized anonymous HTTP principals
/// (`anonymous:req-<uuid8>` — see
/// [`crate::identity::anonymous_request_id`], the one synthesis
/// helper every fallback path must route through; #1560).
pub const ANONYMOUS_REQ_PREFIX: &str = "anonymous:req-";

#[cfg(test)]
mod tests {
    use super::*;

    /// The reserved-name rejection list must carry every privileged
    /// principal const above — a const added here without a matching
    /// `RESERVED_AGENT_IDS` entry would let a wire caller claim it.
    #[test]
    fn reserved_agent_ids_cover_all_privileged_sentinels() {
        for s in [
            DAEMON_PRINCIPAL,
            SYSTEM_PRINCIPAL,
            FEDERATION_CATCHUP,
            SUBSCRIPTION_DISPATCH,
            AI_HTTP_INTERNAL,
            AI_MIGRATE,
            EXPORT_INTERNAL,
            GOVERNANCE_INTERNAL,
        ] {
            assert!(
                crate::validate::RESERVED_AGENT_IDS.contains(&s),
                "privileged sentinel `{s}` missing from RESERVED_AGENT_IDS"
            );
        }
    }
}
