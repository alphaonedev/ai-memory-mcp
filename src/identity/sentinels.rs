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

/// Internal embedding-backfill sweep principal (#1579 A4 —
/// `src/daemon_runtime.rs` serve-boot sweep over
/// [`crate::store::MemoryStore::list_unembedded`]). The sweep is an
/// operator-level maintenance path: it must see and re-embed EVERY
/// row regardless of `metadata.scope`, so it runs under
/// `CallerContext::for_admin(EMBEDDING_BACKFILL)`.
pub const EMBEDDING_BACKFILL: &str = "embedding-backfill";

/// Default agent id stamped by the HTTP daemon surface when acting as
/// itself (NOT a privileged carve-out — unlike [`AI_HTTP_INTERNAL`]).
pub const AI_HTTP: &str = "ai:http";

/// Agent id the curator daemon writes with.
pub const AI_CURATOR: &str = "ai:curator";

/// #1727 (v0.8.0) — principal label for an admin/operator CLI context
/// (`bypass_visibility`) when the operator did not supply an explicit
/// `--agent-id`. Used by the CLI-only `ai-memory undo-edit` operator
/// tool. A label only — the bypass authority comes from
/// [`crate::store::CallerContext::for_admin`], not from this string.
pub const AI_OPERATOR: &str = "ai:operator";

/// v1.0.0 #3469 (EPIC #3466) — the identity a SUBSTRATE-originated
/// wake is stamped with on the `ai-memory wake-hub` plane.
///
/// A wake produced by [`crate::wake_sink`] from the `agent_notified`
/// bus is NOT stamped with the notifying agent's id: no hub session
/// ever authenticated that agent for that frame, so putting its id on
/// the frame's `from` would be a claim the hub never checked. The real
/// sender rides in the wake METADATA, where it is plainly metadata.
///
/// Because the name is a [`crate::validate::RESERVED_AGENT_IDS`]
/// member, no wire caller can register or claim it, so "may wake any
/// agent on this host" stays an operator grant to one unclaimable name
/// rather than something an agent can talk its way into. It is NOT a
/// privileged store principal: nothing constructs a `CallerContext`
/// with it and no cross-tenant ownership gate exempts it.
pub const WAKE_HUB_PRODUCER: &str = "wake-hub-producer";

/// Prefix for per-request synthesized anonymous HTTP principals
/// (`anonymous:req-<uuid8>` — see
/// [`crate::identity::anonymous_request_id`], the one synthesis
/// helper every fallback path must route through; #1560).
pub const ANONYMOUS_REQ_PREFIX: &str = "anonymous:req-";

/// Prefix marking an NHI (AI) agent identity (`ai:<client>@<host>:…`,
/// `ai:claude-code@…`, the operator-set `AI_MEMORY_AGENT_ID=ai:…`
/// forms). The id-shape ladder in [`crate::identity::resolve_agent_id`]
/// synthesizes ids under this prefix from `initialize.clientInfo.name`;
/// #1600 derives the default `memory_update` `edit_source` from it
/// ([`crate::models::EditSource::default_for_agent_id`]).
pub const AI_AGENT_ID_PREFIX: &str = "ai:";

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
            EMBEDDING_BACKFILL,
            WAKE_HUB_PRODUCER,
        ] {
            assert!(
                crate::validate::RESERVED_AGENT_IDS.contains(&s),
                "privileged sentinel `{s}` missing from RESERVED_AGENT_IDS"
            );
        }
    }
}
